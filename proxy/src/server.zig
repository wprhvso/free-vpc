const std = @import("std");
const protocol = @import("protocol.zig");

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: u32,
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

const sockaddr_in6 = extern struct {
    family: u16 = 10,
    port: u16,
    flowinfo: u32 = 0,
    addr: [16]u8,
    scope_id: u32 = 0,
};

const sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        while (self.state.swap(2, .acquire) != 0) {
            _ = std.os.linux.syscall4(.futex, @intFromPtr(&self.state.raw), 0, 2, 0);
        }
    }

    pub fn unlock(self: *Mutex) void {
        if (self.state.swap(0, .release) == 2) {
            _ = std.os.linux.syscall3(.futex, @intFromPtr(&self.state.raw), 1, 1);
        }
    }
};

const Semaphore = struct {
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn post(self: *Semaphore) void {
        _ = self.count.fetchAdd(1, .release);
        _ = std.os.linux.syscall3(.futex, @intFromPtr(&self.count.raw), 1, 1);
    }

    pub fn wait(self: *Semaphore) void {
        while (true) {
            var c = self.count.load(.acquire);
            while (c > 0) {
                if (self.count.cmpxchgWeak(c, c - 1, .acquire, .monotonic)) |actual| {
                    c = actual;
                } else return;
            }
            _ = std.os.linux.syscall4(.futex, @intFromPtr(&self.count.raw), 0, 0, 0);
        }
    }
};

fn sleepMs(ms: u64) void {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    const ts = timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.syscall2(.nanosleep, @intFromPtr(&ts), 0);
}

fn getTimeMs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return (@as(i64, ts.sec) * 1000) + @divTrunc(ts.nsec, 1_000_000);
}

fn parseIp4(s: []const u8, out: *[4]u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return false;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return false;
        i += 1;
    }
    return (i == 4);
}

fn getDnsServerIp() [4]u8 {
    const default_dns: [4]u8 = .{ 1, 1, 1, 1 };
    const fd_rc = std.os.linux.syscall2(.open, @intFromPtr("/etc/resolv.conf"), 0);
    if (@as(isize, @bitCast(fd_rc)) < 0) return default_dns;
    const fd: i32 = @intCast(fd_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

    var buf: [1024]u8 = undefined;
    const rd = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&buf), buf.len);
    const signed: isize = @bitCast(rd);
    if (signed <= 0) return default_dns;
    const content = buf[0..@intCast(signed)];

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "nameserver")) {
            const rest = std.mem.trim(u8, trimmed["nameserver".len..], " \t");
            var ip: [4]u8 = undefined;
            if (parseIp4(rest, &ip)) {
                return ip;
            }
        }
    }
    return default_dns;
}

fn resolveDnsA(domain: []const u8, out_ip: *[4]u8) bool {
    const sock_rc = std.os.linux.syscall3(.socket, 2, 2, 0);
    if (@as(isize, @bitCast(sock_rc)) < 0) return false;
    const sock: i32 = @intCast(sock_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));

    const timeout = extern struct { sec: i64 = 2, usec: i64 = 0 }{};
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, sock))), 1, 20, @intFromPtr(&timeout), @sizeOf(@TypeOf(timeout)));

    const dns_ip = getDnsServerIp();
    const dns_server = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @as(u32, @bitCast(dns_ip)),
    };

    const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&dns_server), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(conn_rc)) < 0) return false;

    var query_buf: [512]u8 = undefined;
    query_buf[0] = 0x24;
    query_buf[1] = 0x68;
    query_buf[2] = 0x01;
    query_buf[3] = 0x00;
    query_buf[4] = 0x00;
    query_buf[5] = 0x01;
    query_buf[6] = 0x00;
    query_buf[7] = 0x00;
    query_buf[8] = 0x00;
    query_buf[9] = 0x00;
    query_buf[10] = 0x00;
    query_buf[11] = 0x00;

    var q_idx: usize = 12;
    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 63) return false;
        if (q_idx + 1 + part.len >= query_buf.len - 5) return false;
        query_buf[q_idx] = @intCast(part.len);
        q_idx += 1;
        @memcpy(query_buf[q_idx .. q_idx + part.len], part);
        q_idx += part.len;
    }
    query_buf[q_idx] = 0;
    q_idx += 1;

    query_buf[q_idx] = 0x00;
    query_buf[q_idx + 1] = 0x01;
    query_buf[q_idx + 2] = 0x00;
    query_buf[q_idx + 3] = 0x01;
    q_idx += 4;

    const write_rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&query_buf), q_idx);
    if (@as(isize, @bitCast(write_rc)) <= 0) return false;

    var resp_buf: [512]u8 = undefined;
    const read_rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&resp_buf), resp_buf.len);
    const read_len: isize = @bitCast(read_rc);
    if (read_len < 12) return false;

    const r_len: usize = @intCast(read_len);
    if (resp_buf[0] != 0x24 or resp_buf[1] != 0x68) return false;
    const ancount = std.mem.readInt(u16, resp_buf[6..8], .big);
    if (ancount == 0) return false;

    var r_idx = q_idx;
    var a_i: usize = 0;
    while (a_i < ancount and r_idx + 12 <= r_len) : (a_i += 1) {
        if ((resp_buf[r_idx] & 0xc0) == 0xc0) {
            r_idx += 2;
        } else {
            while (r_idx < r_len and resp_buf[r_idx] != 0) : (r_idx += 1) {}
            r_idx += 1;
        }

        if (r_idx + 10 > r_len) return false;
        const qtype = std.mem.readInt(u16, resp_buf[r_idx..][0..2], .big);
        const rdlength = std.mem.readInt(u16, resp_buf[r_idx + 8 ..][0..2], .big);
        r_idx += 10;

        if (r_idx + rdlength > r_len) return false;
        if (qtype == 1 and rdlength == 4) {
            @memcpy(out_ip, resp_buf[r_idx .. r_idx + 4]);
            return true;
        }
        r_idx += rdlength;
    }

    return false;
}

fn listenOn(host: []const u8, port: u16) !i32 {
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

    const one: c_int = 1;
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

    var octets: [4]u8 = .{ 127, 0, 0, 1 };
    _ = parseIp4(host, &octets);

    const addr = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };

    const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(bind_rc)) < 0) return error.BindFailed;

    const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), 128);
    if (@as(isize, @bitCast(listen_rc)) < 0) return error.ListenFailed;

    return fd;
}

const RingBuffer = struct {
    data: []u8,
    read_index: usize = 0,
    write_index: usize = 0,
    count: usize = 0,
    mutex: Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !RingBuffer {
        return .{
            .data = try allocator.alloc(u8, capacity),
            .read_index = 0,
            .write_index = 0,
            .count = 0,
        };
    }

    pub fn deinit(self: *RingBuffer, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn push(self: *RingBuffer, bytes: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count + bytes.len > self.data.len) return false;

        const first = @min(bytes.len, self.data.len - self.write_index);
        @memcpy(self.data[self.write_index .. self.write_index + first], bytes[0..first]);

        const second = bytes.len - first;
        if (second > 0) {
            @memcpy(self.data[0..second], bytes[first..]);
        }

        self.write_index = (self.write_index + bytes.len) % self.data.len;
        self.count += bytes.len;
        return true;
    }

    pub fn drainAtMost(self: *RingBuffer, dest: []u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const to_read = @min(self.count, dest.len);
        if (to_read == 0) return 0;

        const first = @min(to_read, self.data.len - self.read_index);
        @memcpy(dest[0..first], self.data[self.read_index .. self.read_index + first]);

        const second = to_read - first;
        if (second > 0) {
            @memcpy(dest[first..to_read], self.data[0..second]);
        }

        self.read_index = (self.read_index + to_read) % self.data.len;
        self.count -= to_read;
        return to_read;
    }
};

// Состояние каждого стрима с очередью переупорядочивания (Reorder Buffer)
const StreamState = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 1,
    close_pending: bool = false,
    close_seq: u32 = 0,
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: Mutex = .{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    buffer_capacity: usize,
    token: []const u8,
    rqlite_url: []const u8,
    downstream_ring: RingBuffer,
    downstream_sem: Semaphore = .{},
    active_stream_fd: std.atomic.Value(i32) = std.atomic.Value(i32).init(-1),
    active_stream_gen: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    streams: std.AutoHashMap(u32, *StreamState),
    streams_mutex: Mutex = .{},
    log_listeners: std.ArrayList(protocol.SocketStream),
    log_mutex: Mutex = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        buf_mb: usize,
        token: []const u8,
        rqlite_url: []const u8,
    ) Server {
        const ring = RingBuffer.init(allocator, buf_mb * 1024 * 1024) catch unreachable;
        return .{
            .allocator = allocator,
            .io = io,
            .host = host,
            .port = port,
            .buffer_capacity = buf_mb * 1024 * 1024,
            .token = token,
            .rqlite_url = rqlite_url,
            .downstream_ring = ring,
            .streams = std.AutoHashMap(u32, *StreamState).init(allocator),
            .log_listeners = std.ArrayList(protocol.SocketStream).empty,
        };
    }

    pub fn deinit(self: *Server) void {
        self.downstream_ring.deinit(self.allocator);

        self.streams_mutex.lock();
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            state.stream.shutdown();
            state.stream.close();
            var q_it = state.reorder_queue.iterator();
            while (q_it.next()) |q_entry| {
                self.allocator.free(q_entry.value_ptr.*);
            }
            state.reorder_queue.deinit();
            self.allocator.destroy(state);
        }
        self.streams.deinit();
        self.streams_mutex.unlock();

        self.log_mutex.lock();
        self.log_listeners.deinit(self.allocator);
        self.log_mutex.unlock();
    }

    pub fn logEvent(self: *Server, json: []const u8) void {
        self.broadcastLiveLog(json);
        self.sendToDownstream(0, 0, .log, json);
        self.storeLogInRqlite(json);
    }

    fn broadcastLiveLog(self: *Server, json: []const u8) void {
        self.log_mutex.lock();
        defer self.log_mutex.unlock();

        var i: usize = 0;
        while (i < self.log_listeners.items.len) {
            const stream = self.log_listeners.items[i];
            var chunk_hdr: [32]u8 = undefined;
            const full_len = 6 + json.len + 2;
            const hdr = std.fmt.bufPrint(&chunk_hdr, "{x}\r\n", .{full_len}) catch continue;

            const ok = blk: {
                stream.writeAll(hdr) catch break :blk false;
                stream.writeAll("data: ") catch break :blk false;
                stream.writeAll(json) catch break :blk false;
                stream.writeAll("\n\n\r\n") catch break :blk false;
                break :blk true;
            };

            if (!ok) {
                stream.close();
                _ = self.log_listeners.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn storeLogInRqlite(self: *Server, json: []const u8) void {
        _ = self;
        _ = json;
    }

    pub fn sendToDownstream(self: *Server, stream_id: u32, seq_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
        var static_buf: [4096]u8 = undefined;
        const total = @sizeOf(protocol.Header) + payload.len;

        var full_frame: []u8 = undefined;
        var dyn_buf: ?[]u8 = null;
        defer if (dyn_buf) |b| self.allocator.free(b);

        if (total <= static_buf.len) {
            full_frame = static_buf[0..total];
        } else {
            dyn_buf = self.allocator.alloc(u8, total) catch return;
            full_frame = dyn_buf.?;
        }

        const n = protocol.writeFrame(full_frame, stream_id, seq_id, cmd, payload) catch return;

        var retry: usize = 0;
        while (!self.downstream_ring.push(full_frame[0..n])) {
            sleepMs(2);
            retry += 1;
            if (retry > 500) {
                std.debug.print("\x1b[31m[BUFFER WARN]\x1b[0m Downstream ring buffer full, dropped frame cmd={s}\n", .{@tagName(cmd)});
                return;
            }
        }
        self.downstream_sem.post();
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const state = entry.value;
            std.debug.print("\x1b[33m[PROXY CLOSE]\x1b[0m Stream #{d} closed\n", .{stream_id});
            state.stream.shutdown();
            state.stream.close();

            var q_it = state.reorder_queue.iterator();
            while (q_it.next()) |q_entry| {
                self.allocator.free(q_entry.value_ptr.*);
            }
            state.reorder_queue.deinit();
            self.allocator.destroy(state);

            self.sendToDownstream(stream_id, 0, .close, "");
        }
    }

    pub fn start(self: *Server) !void {
        const ping_thread = try std.Thread.spawn(.{}, serverHeartbeatWorker, .{self});
        ping_thread.detach();

        const listen_fd = try listenOn(self.host, self.port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        std.debug.print("\x1b[32m[SERVER READY]\x1b[0m Listening on http://{s}:{d}\n", .{ self.host, self.port });

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn serverHeartbeatWorker(self: *Server) void {
        var ping_payload: [4096]u8 = undefined;
        @memset(&ping_payload, 0);

        while (true) {
            sleepMs(1000);
            if (self.active_stream_fd.load(.acquire) < 0) continue;

            std.mem.writeInt(i64, ping_payload[0..8], getTimeMs(), .little);

            self.sendToDownstream(0, 0, .ping, &ping_payload);
        }
    }

    fn readHeaders(stream: protocol.SocketStream, buf: []u8) ![]const u8 {
        var total: usize = 0;
        while (total < buf.len) {
            var b: [1]u8 = undefined;
            const n = try stream.read(&b);
            if (n == 0) return error.ConnectionClosed;
            buf[total] = b[0];
            total += 1;
            if (total >= 4 and std.mem.eql(u8, buf[total - 4 .. total], "\r\n\r\n")) {
                return buf[0..total];
            }
        }
        return error.HeadersTooLong;
    }

    fn readExact(stream: protocol.SocketStream, buf: []u8) !void {
        var total: usize = 0;
        while (total < buf.len) {
            const n = try stream.read(buf[total..]);
            if (n == 0) return error.ConnectionClosed;
            total += n;
        }
    }

    fn handleConnection(self: *Server, stream: protocol.SocketStream) void {
        var header_buf: [8192]u8 = undefined;

        while (true) {
            const headers = readHeaders(stream, &header_buf) catch {
                stream.close();
                return;
            };

            const first_line_end = std.mem.indexOf(u8, headers, "\r\n") orelse headers.len;
            const req_line = headers[0..first_line_end];

            std.debug.print("\x1b[36m[HTTP]\x1b[0m Inbound: {s}\n", .{req_line});

            if (std.mem.startsWith(u8, req_line, "GET /health") or std.mem.startsWith(u8, req_line, "GET / ")) {
                const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
                stream.writeAll(resp) catch return;
                continue;
            }

            if (std.mem.startsWith(u8, req_line, "GET /stream")) {
                std.debug.print("\x1b[32m[STREAM]\x1b[0m Downstream client subscribed! Initializing tunnel...\n", .{});

                const gen = self.active_stream_gen.fetchAdd(1, .monotonic) + 1;
                const old_fd = self.active_stream_fd.swap(stream.handle, .release);
                if (old_fd >= 0) {
                    _ = std.os.linux.syscall2(.shutdown, @as(usize, @bitCast(@as(isize, old_fd))), 2);
                }

                const sse_headers =
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: application/octet-stream\r\n" ++
                    "Cache-Control: no-cache, no-transform, private\r\n" ++
                    "X-Accel-Buffering: no\r\n" ++
                    "Connection: keep-alive\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\n";

                stream.writeAll(sse_headers) catch {
                    stream.close();
                    _ = self.active_stream_fd.cmpxchgStrong(stream.handle, -1, .release, .monotonic);
                    return;
                };

                // БЕЗОПАСНЫЙ 4KB BURST: Прямое заполнение буфера без @memcpy
                var burst_buf: [4096]u8 = undefined;
                @memset(&burst_buf, 0);

                const hdr_ptr: *protocol.Header = @ptrCast(@alignCast(&burst_buf));
                hdr_ptr.* = .{
                    .stream_id = 0,
                    .seq_id = 0,
                    .cmd = .ping,
                    .reserved = 0,
                    .payload_len = @intCast(burst_buf.len - @sizeOf(protocol.Header)),
                };

                var burst_hdr: [32]u8 = undefined;
                const b_hdr = std.fmt.bufPrint(&burst_hdr, "{x}\r\n", .{burst_buf.len}) catch "";
                stream.writeAll(b_hdr) catch return;
                stream.writeAll(&burst_buf) catch return;
                stream.writeAll("\r\n") catch return;
                std.debug.print("\x1b[32m[STREAM]\x1b[0m 4KB Preamble burst sent successfully!\n", .{});

                var ts_bytes: [8]u8 = undefined;
                std.mem.writeInt(i64, &ts_bytes, getTimeMs(), .little);
                self.sendToDownstream(0, 0, .ping, &ts_bytes);

                var drain_buf: [65536]u8 = undefined;
                var chunk_hdr: [32]u8 = undefined;

                while (true) {
                    self.downstream_sem.wait();

                    if (self.active_stream_gen.load(.acquire) != gen) {
                        std.debug.print("\x1b[33m[STREAM]\x1b[0m Connection superseded by a new client, exiting worker.\n", .{});
                        break;
                    }

                    const n = self.downstream_ring.drainAtMost(&drain_buf);
                    if (n == 0) continue;

                    const frame = drain_buf[0..n];
                    const ch_hdr = std.fmt.bufPrint(&chunk_hdr, "{x}\r\n", .{frame.len}) catch break;

                    stream.writeAll(ch_hdr) catch break;
                    stream.writeAll(frame) catch break;
                    stream.writeAll("\r\n") catch break;
                }

                _ = self.active_stream_fd.cmpxchgStrong(stream.handle, -1, .release, .monotonic);
                stream.close();
                std.debug.print("\x1b[33m[STREAM]\x1b[0m Downstream connection closed.\n", .{});
                return;
            }

            if (std.mem.startsWith(u8, req_line, "GET /logs/stream")) {
                if (!self.validateToken(req_line)) {
                    std.debug.print("\x1b[31m[AUTH]\x1b[0m Logs access denied: invalid token\n", .{});
                    stream.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                    stream.close();
                    return;
                }

                const sse_headers =
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: text/event-stream\r\n" ++
                    "Cache-Control: no-cache\r\n" ++
                    "Connection: keep-alive\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\n";

                stream.writeAll(sse_headers) catch {
                    stream.close();
                    return;
                };

                self.log_mutex.lock();
                self.log_listeners.append(self.allocator, stream) catch {
                    self.log_mutex.unlock();
                    stream.close();
                    return;
                };
                self.log_mutex.unlock();
                std.debug.print("\x1b[32m[LOGS]\x1b[0m New live log viewer connected\n", .{});
                return;
            }

            if (std.mem.startsWith(u8, req_line, "POST /push")) {
                var content_len: usize = 0;
                if (findHeader(headers, "content-length:")) |val| {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, val, " \t"), 10) catch 0;
                }

                if (content_len == 0) {
                    stream.writeAll("HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n") catch return;
                    continue;
                }

                const body = self.allocator.alloc(u8, content_len) catch return;
                defer self.allocator.free(body);

                readExact(stream, body) catch {
                    stream.close();
                    return;
                };

                self.processPushBody(body);

                stream.writeAll("HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n") catch return;
                continue;
            }

            stream.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch return;
            stream.close();
            return;
        }
    }

    fn validateToken(self: *Server, req_line: []const u8) bool {
        if (std.mem.indexOf(u8, req_line, "token=")) |idx| {
            const query_val = req_line[idx + 6 ..];
            const end_idx = std.mem.indexOfAny(u8, query_val, " &\r\n") orelse query_val.len;
            return std.mem.eql(u8, query_val[0..end_idx], self.token);
        }
        return false;
    }

    fn findHeader(headers: []const u8, lower_name: []const u8) ?[]const u8 {
        var it = std.mem.splitSequence(u8, headers, "\r\n");
        _ = it.next();
        while (it.next()) |line| {
            if (line.len < lower_name.len) continue;
            var is_match = true;
            for (lower_name, 0..) |c, i| {
                if (std.ascii.toLower(line[i]) != c) {
                    is_match = false;
                    break;
                }
            }
            if (is_match) {
                return line[lower_name.len..];
            }
        }
        return null;
    }

    fn processPushBody(self: *Server, body: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= body.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(body[offset..].ptr));
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > body.len) break;
            const payload = body[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .connect => {
                    self.handleConnect(hdr.stream_id, payload);
                },
                .data => {
                    self.handleOrderedData(hdr.stream_id, hdr.seq_id, payload);
                },
                .close => {
                    self.handleOrderedClose(hdr.stream_id, hdr.seq_id);
                },
                .log => {
                    self.logEvent(payload);
                },
                else => {},
            }
        }
    }

    // Обработка входящих данных с гарантией строгого порядка (Reorder Buffer)
    fn handleOrderedData(self: *Server, stream_id: u32, seq_id: u32, payload: []const u8) void {
        self.streams_mutex.lock();
        const state_opt = self.streams.get(stream_id);
        self.streams_mutex.unlock();

        if (state_opt) |state| {
            state.mutex.lock();
            defer state.mutex.unlock();

            if (seq_id == state.expected_seq) {
                // 1. Пришел ожидаемый пакет — пишем в сокет
                state.stream.writeAll(payload) catch {
                    self.closeStream(stream_id);
                    return;
                };
                state.expected_seq +%= 1;

                // 2. Каскадный сброс: выгребаем накопившиеся пакеты из очереди
                while (state.reorder_queue.fetchRemove(state.expected_seq)) |entry| {
                    const queued_payload = entry.value;
                    defer self.allocator.free(queued_payload);

                    state.stream.writeAll(queued_payload) catch {
                        self.closeStream(stream_id);
                        return;
                    };
                    state.expected_seq +%= 1;
                }

                // 3. Если ожидалось закрытие и очередь опустела
                if (state.close_pending and state.expected_seq >= state.close_seq) {
                    self.closeStream(stream_id);
                }
            } else if (seq_id > state.expected_seq) {
                // Пакет обогнал очередь — сохраняем в буфер
                if (state.reorder_queue.count() < 256) {
                    const copy = self.allocator.alloc(u8, payload.len) catch return;
                    @memcpy(copy, payload);
                    state.reorder_queue.put(seq_id, copy) catch {
                        self.allocator.free(copy);
                    };
                }
            }
        }
    }

    fn handleOrderedClose(self: *Server, stream_id: u32, seq_id: u32) void {
        self.streams_mutex.lock();
        const state_opt = self.streams.get(stream_id);
        self.streams_mutex.unlock();

        if (state_opt) |state| {
            state.mutex.lock();
            defer state.mutex.unlock();

            if (seq_id <= state.expected_seq and state.reorder_queue.count() == 0) {
                self.closeStream(stream_id);
            } else {
                state.close_pending = true;
                state.close_seq = seq_id;
            }
        }
    }

    fn handleConnect(self: *Server, stream_id: u32, payload: []const u8) void {
        if (payload.len < 4) {
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        }

        const port = std.mem.readInt(u16, payload[0..2], .big);
        const atyp = payload[2];
        const addr_len = payload[3];
        if (payload.len < 4 + addr_len) {
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        }

        const addr_data = payload[4 .. 4 + addr_len];

        if (atyp == 1 and addr_len == 4) {
            const octets = addr_data[0..4].*;
            std.debug.print("\x1b[34m[PROXY]\x1b[0m Stream #{d} -> {d}.{d}.{d}.{d}:{d}\n", .{
                stream_id, octets[0], octets[1], octets[2], octets[3], port,
            });
            self.connectTcpIpv4(stream_id, octets, port);
        } else if (atyp == 4 and addr_len == 16) {
            std.debug.print("\x1b[34m[PROXY]\x1b[0m Stream #{d} -> [IPv6]:{d}\n", .{ stream_id, port });
            const sock_rc = std.os.linux.syscall3(.socket, 10, 1, 0);
            if (@as(isize, @bitCast(sock_rc)) < 0) {
                self.sendToDownstream(stream_id, 0, .close, "");
                return;
            }
            const sock: i32 = @intCast(sock_rc);

            const target_addr = sockaddr_in6{
                .family = 10,
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = addr_data[0..16].*,
                .scope_id = 0,
            };

            const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in6));
            if (@as(isize, @bitCast(conn_rc)) < 0) {
                _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
                self.sendToDownstream(stream_id, 0, .close, "");
                return;
            }

            const target_conn = protocol.SocketStream{ .handle = sock };

            const state = self.allocator.create(StreamState) catch {
                target_conn.close();
                self.sendToDownstream(stream_id, 0, .close, "");
                return;
            };
            state.* = .{
                .stream = target_conn,
                .expected_seq = 1,
                .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
            };

            self.streams_mutex.lock();
            self.streams.put(stream_id, state) catch {
                self.streams_mutex.unlock();
                state.reorder_queue.deinit();
                self.allocator.destroy(state);
                target_conn.close();
                self.sendToDownstream(stream_id, 0, .close, "");
                return;
            };
            self.streams_mutex.unlock();

            self.sendToDownstream(stream_id, 0, .connect_ok, "");

            const thread = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn }) catch {
                self.closeStream(stream_id);
                return;
            };
            thread.detach();
        } else if (atyp == 2) {
            std.debug.print("\x1b[34m[PROXY]\x1b[0m Stream #{d} -> {s}:{d}\n", .{ stream_id, addr_data, port });
            var octets: [4]u8 = .{ 0, 0, 0, 0 };
            if (parseIp4(addr_data, &octets)) {
                self.connectTcpIpv4(stream_id, octets, port);
            } else if (resolveDnsA(addr_data, &octets)) {
                self.connectTcpIpv4(stream_id, octets, port);
            } else {
                std.debug.print("\x1b[31m[PROXY ERROR]\x1b[0m Stream #{d}: DNS resolve failed for {s}\n", .{ stream_id, addr_data });
                self.sendToDownstream(stream_id, 0, .close, "");
            }
        } else {
            self.sendToDownstream(stream_id, 0, .close, "");
        }
    }

    fn connectTcpIpv4(self: *Server, stream_id: u32, octets: [4]u8, port: u16) void {
        const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) {
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        }
        const sock: i32 = @intCast(sock_rc);

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        }

        const target_conn = protocol.SocketStream{ .handle = sock };

        const state = self.allocator.create(StreamState) catch {
            target_conn.close();
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        };
        state.* = .{
            .stream = target_conn,
            .expected_seq = 1,
            .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
        };

        self.streams_mutex.lock();
        self.streams.put(stream_id, state) catch {
            self.streams_mutex.unlock();
            state.reorder_queue.deinit();
            self.allocator.destroy(state);
            target_conn.close();
            self.sendToDownstream(stream_id, 0, .close, "");
            return;
        };
        self.streams_mutex.unlock();

        self.sendToDownstream(stream_id, 0, .connect_ok, "");
        std.debug.print("\x1b[32m[PROXY OK]\x1b[0m Stream #{d} connected successfully\n", .{stream_id});

        const thread = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn }) catch {
            self.closeStream(stream_id);
            return;
        };
        thread.detach();
    }

    fn targetReaderWorker(self: *Server, stream_id: u32, target_stream: protocol.SocketStream) void {
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) {
                self.closeStream(stream_id);
                return;
            }
            self.sendToDownstream(stream_id, 0, .data, buf[0..n]);
        }
    }
};
