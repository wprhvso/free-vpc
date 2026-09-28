const std = @import("std");
const Config = @import("config.zig").Config;
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const FrameQueue = @import("frame_queue.zig").FrameQueue;

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: u32,
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

const sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

fn getMilliTimestamp() i64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return (ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000);
}

const RemoteConnection = struct {
    fd: i32,
    io: std.Io,
    allocator: std.mem.Allocator,
    file: std.Io.File = undefined,
    file_reader: std.Io.File.Reader = undefined,
    file_writer: std.Io.File.Writer = undefined,
    tls_client: ?std.crypto.tls.Client = null,
    tls_raw_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    tls_raw_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,

    read_buf: [16384]u8 = undefined,
    read_pos: usize = 0,
    read_len: usize = 0,

    pub fn init(fd: i32, host: []const u8, io: std.Io, allocator: std.mem.Allocator) !*RemoteConnection {
        const conn = try allocator.create(RemoteConnection);
        conn.* = .{
            .fd = fd,
            .io = io,
            .allocator = allocator,
        };

        if (Config.client.is_tls) {
            conn.file = .{ .handle = fd, .flags = .{ .nonblocking = false } };
            conn.file_reader = conn.file.readerStreaming(io, &conn.tls_raw_read_buf);
            conn.file_writer = conn.file.writerStreaming(io, &conn.tls_raw_write_buf);

            var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
            _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

            var ts: std.posix.timespec = undefined;
            _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
            const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

            conn.tls_client = std.crypto.tls.Client.init(
                &conn.file_reader.interface,
                &conn.file_writer.interface,
                .{
                    .host = .{ .explicit = host },
                    .ca = .no_verification,
                    .write_buffer = &conn.tls_write_buf,
                    .read_buffer = &conn.tls_read_buf,
                    .entropy = &entropy,
                    .realtime_now = now,
                    .allow_truncation_attacks = true,
                },
            ) catch |err| {
                conn.close();
                return err;
            };
        }
        return conn;
    }

    pub fn readRaw(self: *RemoteConnection, buffer: []u8) !usize {
        if (Config.client.is_tls) {
            return self.tls_client.?.reader.readSliceShort(buffer);
        } else {
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(buffer.ptr), buffer.len);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) return error.ConnectionClosed;
            return @intCast(signed);
        }
    }

    pub fn readChunk(self: *RemoteConnection, dest: []u8) !usize {
        if (self.read_pos < self.read_len) {
            const avail = @min(dest.len, self.read_len - self.read_pos);
            @memcpy(dest[0..avail], self.read_buf[self.read_pos .. self.read_pos + avail]);
            self.read_pos += avail;
            return avail;
        }
        return self.readRaw(dest);
    }

    pub fn readExact(self: *RemoteConnection, dest: []u8) !void {
        var total: usize = 0;
        while (total < dest.len) {
            const n = try self.readChunk(dest[total..]);
            total += n;
        }
    }

    pub fn readHeadersFast(self: *RemoteConnection, out_buf: []u8, leftover: *[]const u8) ![]const u8 {
        var total: usize = 0;
        if (self.read_pos < self.read_len) {
            const avail = self.read_len - self.read_pos;
            @memcpy(out_buf[0..avail], self.read_buf[self.read_pos..self.read_len]);
            total += avail;
            self.read_pos = 0;
            self.read_len = 0;
        }

        while (total < out_buf.len) {
            if (std.mem.indexOf(u8, out_buf[0..total], "\r\n\r\n")) |idx| {
                const hdr_end = idx + 4;
                leftover.* = out_buf[hdr_end..total];
                return out_buf[0..hdr_end];
            }
            const n = try self.readRaw(out_buf[total..]);
            total += n;
        }
        return error.HeadersTooLong;
    }

    pub fn writeAll(self: *RemoteConnection, bytes: []const u8) !void {
        if (Config.client.is_tls) {
            try self.tls_client.?.writer.writeAll(bytes);
            try self.tls_client.?.writer.flush();
            try self.file_writer.interface.flush();
        } else {
            var index: usize = 0;
            while (index < bytes.len) {
                const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(bytes.ptr + index), bytes.len - index);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) return error.WriteFailed;
                index += @intCast(signed);
            }
        }
    }

    pub fn close(self: *RemoteConnection) void {
        if (Config.client.is_tls) {
            if (self.tls_client) |*tc| tc.end() catch {};
            self.tls_client = null;
        }
        if (self.fd >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
            self.fd = -1;
        }
        self.allocator.destroy(self);
    }
};

const StreamContext = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 0,
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: futex.Mutex = .{},
};

const ConnectWaiter = struct {
    event: futex.Event = .{},
    success: bool = false,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    remote_addr: sockaddr_in,
    upstream_queue: FrameQueue,
    local_streams: std.AutoHashMap(u32, *StreamContext),
    streams_mutex: futex.Mutex = .{},
    connect_waiters: std.AutoHashMap(u32, *ConnectWaiter),
    waiters_mutex: futex.Mutex = .{},
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Client {
        const uq = FrameQueue.init(allocator, Config.common.queue_capacity) catch unreachable;

        var octets: [4]u8 = .{ 127, 0, 0, 1 };
        if (!protocol.resolveDnsA(Config.client.remote_host, &octets)) {
            std.debug.print("\x1b[31m[CLIENT ERROR]\x1b[0m Cannot resolve {s}\n", .{Config.client.remote_host});
        } else {
            std.debug.print("\x1b[32m[DNS]\x1b[0m {s} -> {d}.{d}.{d}.{d}\n", .{ Config.client.remote_host, octets[0], octets[1], octets[2], octets[3] });
        }

        const r_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.client.remote_port),
            .addr = @as(u32, @bitCast(octets)),
        };

        return .{
            .allocator = allocator,
            .io = io,
            .remote_addr = r_addr,
            .upstream_queue = uq,
            .local_streams = std.AutoHashMap(u32, *StreamContext).init(allocator),
            .connect_waiters = std.AutoHashMap(u32, *ConnectWaiter).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.upstream_queue.deinit(self.allocator);
        self.local_streams.deinit();
        self.connect_waiters.deinit();
    }

    fn connectRemote(self: *Client) !*RemoteConnection {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const fd: i32 = @intCast(rc);
        errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

        protocol.setNoDelay(fd);

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&self.remote_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) return error.ConnectFailed;

        return RemoteConnection.init(fd, Config.client.remote_host, self.io, self.allocator);
    }

    pub fn start(self: *Client) !void {
        std.debug.print("\x1b[32m[INIT]\x1b[0m Spawning 6 PUSH and 6 PULL Keep-Alive workers...\n", .{});

        for (0..Config.client.push_workers) |w_id| {
            const th = try std.Thread.spawn(.{}, pushWorkerThread, .{ self, w_id });
            th.detach();
        }

        for (0..Config.client.pull_workers) |w_id| {
            const th = try std.Thread.spawn(.{}, pullWorkerThread, .{ self, w_id });
            th.detach();
        }

        try self.socksListener();
    }

    fn pushWorkerThread(self: *Client, id: usize) void {
        const send_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch return;
        defer self.allocator.free(send_buf);
        var header_scratch: [1024]u8 = undefined;
        var conn: ?*RemoteConnection = null;

        while (true) {
            while (conn == null) {
                conn = self.connectRemote() catch |err| {
                    std.debug.print("\x1b[31m[PUSH #{d}]\x1b[0m Connection to Cloudflare failed: {s}\n", .{ id, @errorName(err) });
                    _ = futex.Futex.wait(&self.next_stream_id, 0, 500);
                    continue;
                };
                std.debug.print("\x1b[32m[PUSH #{d}]\x1b[0m Connected to Cloudflare\n", .{id});
            }

            _ = self.upstream_queue.waitData(null);

            const batch_len = self.upstream_queue.drainBatch(send_buf);
            if (batch_len == 0) continue;

            std.debug.print("\x1b[35m[PUSH #{d}]\x1b[0m Sending {d} bytes to Cloudflare ({s})...\n", .{ id, batch_len, Config.common.push_path });

            const req_hdrs = std.fmt.bufPrint(&header_scratch,
                "POST {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "User-Agent: {s}\r\n" ++
                "{s}: {s}\r\n" ++
                "Content-Type: application/octet-stream\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: keep-alive\r\n\r\n",
                .{ Config.common.push_path, Config.client.remote_host, Config.client.user_agent, Config.common.token_header, Config.common.token, batch_len }
            ) catch unreachable;

            const send_ok = blk: {
                conn.?.writeAll(req_hdrs) catch break :blk false;
                conn.?.writeAll(send_buf[0..batch_len]) catch break :blk false;
                break :blk true;
            };

            if (!send_ok) {
                std.debug.print("\x1b[31m[PUSH #{d}]\x1b[0m Socket write failed!\n", .{id});
                conn.?.close();
                conn = null;
                continue;
            }

            var resp_hdr_buf: [2048]u8 = undefined;
            var leftover: []const u8 = undefined;
            const hdrs = conn.?.readHeadersFast(&resp_hdr_buf, &leftover) catch |err| {
                std.debug.print("\x1b[31m[PUSH #{d}]\x1b[0m Read response error: {s}\n", .{ id, @errorName(err) });
                conn.?.close();
                conn = null;
                continue;
            };

            const first_line = hdrs[0 .. std.mem.indexOf(u8, hdrs, "\r\n") orelse hdrs.len];
            std.debug.print("\x1b[35m[PUSH #{d}]\x1b[0m Cloudflare response: {s}\n", .{ id, first_line });
        }
    }

    fn pullWorkerThread(self: *Client, id: usize) void {
        const pull_req = std.fmt.comptimePrint(
            "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: {s}\r\n" ++
            "{s}: {s}\r\n" ++
            "Content-Length: 0\r\n" ++
            "Connection: keep-alive\r\n\r\n",
            .{ Config.common.pull_path, Config.client.remote_host, Config.client.user_agent, Config.common.token_header, Config.common.token }
        );

        const resp_body_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch return;
        defer self.allocator.free(resp_body_buf);
        var header_buf: [4096]u8 = undefined;
        var conn: ?*RemoteConnection = null;

        while (true) {
            while (conn == null) {
                conn = self.connectRemote() catch |err| {
                    std.debug.print("\x1b[31m[PULL #{d}]\x1b[0m Connection to Cloudflare failed: {s}\n", .{ id, @errorName(err) });
                    _ = futex.Futex.wait(&self.next_stream_id, 0, 500);
                    continue;
                };
                std.debug.print("\x1b[32m[PULL #{d}]\x1b[0m Long-Poll worker connected (10s hold)\n", .{id});
            }

            if (conn.?.writeAll(pull_req)) |_| {} else |_| {
                conn.?.close();
                conn = null;
                continue;
            }

            var leftover: []const u8 = undefined;
            const hdrs = conn.?.readHeadersFast(&header_buf, &leftover) catch |err| {
                std.debug.print("\x1b[31m[PULL #{d}]\x1b[0m Read response error: {s}\n", .{ id, @errorName(err) });
                conn.?.close();
                conn = null;
                continue;
            };

            const first_line = hdrs[0 .. std.mem.indexOf(u8, hdrs, "\r\n") orelse hdrs.len];
            var content_len: usize = 0;
            var is_close = false;
            const status_200 = std.mem.indexOf(u8, hdrs, "200 OK") != null;

            var h_it = std.mem.splitSequence(u8, hdrs, "\r\n");
            while (h_it.next()) |line| {
                if (line.len == 0) break;
                if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \t"), 10) catch 0;
                } else if (std.ascii.startsWithIgnoreCase(line, "connection:")) {
                    if (std.mem.indexOf(u8, line, "close") != null) is_close = true;
                }
            }

            std.debug.print("\x1b[34m[PULL #{d}]\x1b[0m Cloudflare response: {s} (len={d})\n", .{ id, first_line, content_len });

            if (status_200 and content_len > 0) {
                const body_slice = resp_body_buf[0..content_len];
                if (leftover.len > 0) {
                    const from_leftover = @min(leftover.len, content_len);
                    @memcpy(body_slice[0..from_leftover], leftover[0..from_leftover]);
                    if (content_len > from_leftover) {
                        conn.?.readExact(body_slice[from_leftover..content_len]) catch {
                            conn.?.close();
                            conn = null;
                            continue;
                        };
                    }
                } else {
                    conn.?.readExact(body_slice) catch {
                        conn.?.close();
                        conn = null;
                        continue;
                    };
                }
                self.dispatchFrames(body_slice);
            }

            if (is_close) {
                conn.?.close();
                conn = null;
            }
        }
    }

    fn dispatchFrames(self: *Client, bytes: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= bytes.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(bytes[offset..].ptr));
            if (hdr.magic != 0xCF01) break;
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > bytes.len) break;
            const payload = bytes[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .connect_ok => {
                    self.waiters_mutex.lock();
                    if (self.connect_waiters.get(hdr.stream_id)) |w| {
                        w.success = true;
                        w.event.set();
                    }
                    self.waiters_mutex.unlock();
                },
                .data => self.handleDownstreamData(hdr.stream_id, hdr.seq_id, payload),
                .close => self.closeLocalStream(hdr.stream_id),
                else => {},
            }
        }
    }

    fn handleDownstreamData(self: *Client, stream_id: u32, seq_id: u32, payload: []const u8) void {
        self.streams_mutex.lock();
        const ctx_opt = self.local_streams.get(stream_id);
        self.streams_mutex.unlock();

        if (ctx_opt) |ctx| {
            ctx.mutex.lock();
            defer ctx.mutex.unlock();

            if (seq_id == ctx.expected_seq) {
                ctx.stream.writeAll(payload) catch {
                    self.closeLocalStream(stream_id);
                    return;
                };
                ctx.expected_seq +%= 1;

                while (ctx.reorder_queue.fetchRemove(ctx.expected_seq)) |entry| {
                    defer self.allocator.free(entry.value);
                    ctx.stream.writeAll(entry.value) catch {
                        self.closeLocalStream(stream_id);
                        return;
                    };
                    ctx.expected_seq +%= 1;
                }
            } else if (seq_id > ctx.expected_seq) {
                if (ctx.reorder_queue.count() < Config.server.reorder_limit) {
                    const copy = self.allocator.alloc(u8, payload.len) catch return;
                    @memcpy(copy, payload);
                    ctx.reorder_queue.put(seq_id, copy) catch {
                        self.allocator.free(copy);
                    };
                }
            }
        }
    }

    pub fn closeLocalStream(self: *Client, stream_id: u32) void {
        self.waiters_mutex.lock();
        if (self.connect_waiters.get(stream_id)) |w| {
            w.success = false;
            w.event.set();
        }
        self.waiters_mutex.unlock();

        self.streams_mutex.lock();
        const removed = self.local_streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const ctx = entry.value;
            ctx.stream.shutdown();
            ctx.stream.close();
            var q_it = ctx.reorder_queue.iterator();
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            ctx.reorder_queue.deinit();
            self.allocator.destroy(ctx);

            _ = self.upstream_queue.push(stream_id, 0, .close, "");
        }
    }

    fn socksListener(self: *Client) !void {
        const listen_fd = try listenOn(Config.client.socks_host, Config.client.socks_port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        std.debug.print("\x1b[32m[SOCKS5]\x1b[0m Ready on {s}:{d}\n", .{ Config.client.socks_host, Config.client.socks_port });

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            protocol.setNoDelay(client_fd);

            const stream = protocol.SocketStream{ .handle = client_fd };
            const th = std.Thread.spawn(.{}, handleSocks, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
        }
    }

    fn handleSocks(self: *Client, stream: protocol.SocketStream) void {
        var greeting_hdr: [2]u8 = undefined;
        if (!protocol.readExactStream(stream, &greeting_hdr)) {
            stream.close();
            return;
        }

        if (greeting_hdr[0] != 5) {
            std.debug.print("\x1b[33m[SOCKS]\x1b[0m Rejecting non-socks5 (ver {d})\n", .{greeting_hdr[0]});
            stream.close();
            return;
        }

        const nmethods = greeting_hdr[1];
        var methods_buf: [256]u8 = undefined;
        if (nmethods == 0 or !protocol.readExactStream(stream, methods_buf[0..nmethods])) {
            stream.close();
            return;
        }

        stream.writeAll(&[_]u8{ 5, 0 }) catch { stream.close(); return; };

        var req_hdr: [4]u8 = undefined;
        if (!protocol.readExactStream(stream, &req_hdr)) {
            stream.close();
            return;
        }

        if (req_hdr[0] != 5 or req_hdr[1] != 1) {
            std.debug.print("\x1b[33m[SOCKS]\x1b[0m Unsupported command {d}\n", .{req_hdr[1]});
            _ = stream.writeAll(&[_]u8{ 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            stream.close();
            return;
        }

        const atyp = req_hdr[3];
        var addr_buf: [256]u8 = undefined;
        var addr_len: u8 = 0;
        var target_type: u8 = 0;

        if (atyp == 1) {
            target_type = 1;
            addr_len = 4;
            if (!protocol.readExactStream(stream, addr_buf[0..4])) {
                stream.close();
                return;
            }
        } else if (atyp == 3) {
            target_type = 2;
            var dlen: [1]u8 = undefined;
            if (!protocol.readExactStream(stream, &dlen)) {
                stream.close();
                return;
            }
            addr_len = dlen[0];
            if (addr_len == 0 or !protocol.readExactStream(stream, addr_buf[0..addr_len])) {
                stream.close();
                return;
            }
        } else {
            std.debug.print("\x1b[33m[SOCKS]\x1b[0m Unsupported atyp {d}\n", .{atyp});
            _ = stream.writeAll(&[_]u8{ 5, 8, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            stream.close();
            return;
        }

        var port_buf: [2]u8 = undefined;
        if (!protocol.readExactStream(stream, &port_buf)) {
            stream.close();
            return;
        }
        const target_port = std.mem.readInt(u16, &port_buf, .big);
        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        if (target_type == 1) {
            std.debug.print("\x1b[36m[SOCKS]\x1b[0m Stream #{d} -> {d}.{d}.{d}.{d}:{d}\n", .{
                stream_id, addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3], target_port,
            });
        } else {
            std.debug.print("\x1b[36m[SOCKS]\x1b[0m Stream #{d} -> {s}:{d}\n", .{
                stream_id, addr_buf[0..addr_len], target_port,
            });
        }

        var payload_buf: [300]u8 = undefined;
        @memcpy(payload_buf[0..2], &port_buf);
        payload_buf[2] = target_type;
        payload_buf[3] = addr_len;
        @memcpy(payload_buf[4 .. 4 + addr_len], addr_buf[0..addr_len]);
        const conn_payload = payload_buf[0 .. 4 + addr_len];

        var waiter = ConnectWaiter{};

        self.waiters_mutex.lock();
        self.connect_waiters.put(stream_id, &waiter) catch unreachable;
        self.waiters_mutex.unlock();

        const ctx = self.allocator.create(StreamContext) catch unreachable;
        ctx.* = .{
            .stream = stream,
            .expected_seq = 0,
            .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
        };

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, ctx) catch unreachable;
        self.streams_mutex.unlock();

        var seq: u32 = 0;
        while (!self.upstream_queue.push(stream_id, seq, .connect, conn_payload)) {
            futex.Futex.wait(&self.next_stream_id, 0, 1);
        }
        seq += 1;

        const start_ms = getMilliTimestamp();
        const ok = waiter.event.wait(Config.client.connect_timeout_ms) and waiter.success;
        const dur = getMilliTimestamp() - start_ms;

        self.waiters_mutex.lock();
        _ = self.connect_waiters.remove(stream_id);
        self.waiters_mutex.unlock();

        if (!ok) {
            std.debug.print("\x1b[31m[SOCKS]\x1b[0m Stream #{d} connect FAILED after {d}ms\n", .{ stream_id, dur });
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            self.closeLocalStream(stream_id);
            return;
        }

        std.debug.print("\x1b[32m[SOCKS]\x1b[0m Stream #{d} CONNECTED in {d}ms\n", .{ stream_id, dur });
        stream.writeAll(&[_]u8{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {
            self.closeLocalStream(stream_id);
            return;
        };

        var data_buf: [16384]u8 = undefined;
        while (true) {
            const rd = stream.read(&data_buf) catch 0;
            if (rd == 0) {
                self.closeLocalStream(stream_id);
                return;
            }
            while (!self.upstream_queue.push(stream_id, seq, .data, data_buf[0..rd])) {
                futex.Futex.wait(&self.next_stream_id, 0, 1);
            }
            seq +%= 1;
        }
    }
};

fn listenOn(host: []const u8, port: u16) !i32 {
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    const fd: i32 = @intCast(rc);
    const one: c_int = 1;
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

    var octets: [4]u8 = .{ 127, 0, 0, 1 };
    _ = protocol.parseIp4(host, &octets);

    const addr = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };
    _ = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
    _ = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), 128);
    return fd;
}
