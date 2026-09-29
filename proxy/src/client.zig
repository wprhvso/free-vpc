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

fn getMilliTimestamp() u64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return @intCast((ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000));
}

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

fn clientLog(level: []const u8, component: []const u8, event: []const u8, stream_id: u32, data_json: []const u8) void {
    var scratch: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&scratch,
        "{{\"ts\":{d},\"node\":\"client\",\"component\":\"{s}\",\"level\":\"{s}\",\"event\":\"{s}\",\"stream_id\":{d},\"data\":{s}}}\n",
        .{ getMilliTimestamp(), component, level, event, stream_id, data_json }
    ) catch return;
    _ = std.os.linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
}

const DirectSocketWriter = struct {
    fd: i32,
    raw_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    writer: std.Io.Writer = undefined,

    pub fn setup(self: *DirectSocketWriter, fd: i32) void {
        self.fd = fd;
        self.writer = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .drain = drain,
                .flush = flush,
            },
            .end = 0,
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        try flush(w);
        var total: usize = 0;
        for (data[0 .. data.len - 1]) |buf| {
            try writeSyscall(w, buf);
            total += buf.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try writeSyscall(w, last);
            total += last.len;
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *DirectSocketWriter = @alignCast(@fieldParentPtr("writer", w));
        if (w.end > 0) {
            var index: usize = 0;
            while (index < w.end) {
                const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(w.buffer.ptr + index), w.end - index);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) return error.WriteFailed;
                index += @intCast(signed);
            }
            w.end = 0;
        }
    }

    fn writeSyscall(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
        const self: *DirectSocketWriter = @alignCast(@fieldParentPtr("writer", w));
        var index: usize = 0;
        while (index < bytes.len) {
            const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(bytes.ptr + index), bytes.len - index);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) return error.WriteFailed;
            index += @intCast(signed);
        }
    }
};

const DirectSocketReader = struct {
    fd: i32,
    raw_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    reader: std.Io.Reader = undefined,

    pub fn setup(self: *DirectSocketReader, fd: i32) void {
        self.fd = fd;
        self.reader = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .stream = stream,
                .readVec = readVec,
            },
            .seek = 0,
            .end = 0,
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        var bufs: [1][]u8 = .{""};
        return readVec(r, &bufs);
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const self: *DirectSocketReader = @alignCast(@fieldParentPtr("reader", r));

        if (data.len > 0 and data[0].len > 0) {
            const dest = data[0];
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(dest.ptr), dest.len);
            const signed: isize = @bitCast(rc);
            if (signed < 0) return error.ReadFailed;
            if (signed == 0) return error.EndOfStream;
            return @intCast(signed);
        }

        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        }

        const avail = r.buffer.len - r.end;
        if (avail == 0) return 0;

        const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(r.buffer.ptr + r.end), avail);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.ReadFailed;
        if (signed == 0) return error.EndOfStream;

        r.end += @intCast(signed);
        return 0;
    }
};

const RemoteConnection = struct {
    fd: i32,
    allocator: std.mem.Allocator,
    direct_reader: DirectSocketReader = undefined,
    direct_writer: DirectSocketWriter = undefined,
    tls_client: ?std.crypto.tls.Client = null,
    tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,

    pub fn init(fd: i32, host: []const u8, allocator: std.mem.Allocator) !*RemoteConnection {
        const conn = try allocator.create(RemoteConnection);
        conn.* = .{
            .fd = fd,
            .allocator = allocator,
        };

        if (Config.client.is_tls) {
            conn.direct_reader.setup(fd);
            conn.direct_writer.setup(fd);

            var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
            _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

            var ts: std.posix.timespec = undefined;
            _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
            const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

            conn.tls_client = std.crypto.tls.Client.init(
                &conn.direct_reader.reader,
                &conn.direct_writer.writer,
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

    pub fn readByte(self: *RemoteConnection) !u8 {
        if (Config.client.is_tls) {
            const slice = try self.tls_client.?.reader.peekGreedy(1);
            if (slice.len == 0) return error.ConnectionClosed;
            const b = slice[0];
            self.tls_client.?.reader.toss(1);
            return b;
        } else {
            var b: [1]u8 = undefined;
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(&b), 1);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) return error.ConnectionClosed;
            return b[0];
        }
    }

    pub fn readExact(self: *RemoteConnection, dest: []u8) !void {
        var total: usize = 0;
        while (total < dest.len) {
            if (Config.client.is_tls) {
                const avail = self.tls_client.?.reader.buffered();
                if (avail.len > 0) {
                    const copy_len = @min(dest.len - total, avail.len);
                    @memcpy(dest[total .. total + copy_len], avail[0..copy_len]);
                    self.tls_client.?.reader.toss(copy_len);
                    total += copy_len;
                    continue;
                }
                const b = try self.readByte();
                dest[total] = b;
                total += 1;
            } else {
                const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(dest.ptr + total), dest.len - total);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) return error.ConnectionClosed;
                total += @intCast(signed);
            }
        }
    }

    pub fn readHeadersFast(self: *RemoteConnection, out_buf: []u8) ![]const u8 {
        var total: usize = 0;
        while (total < out_buf.len) {
            const b = try self.readByte();
            out_buf[total] = b;
            total += 1;
            if (total >= 4 and std.mem.eql(u8, out_buf[total - 4 .. total], "\r\n\r\n")) {
                return out_buf[0..total];
            }
        }
        return error.HeadersTooLong;
    }

    pub fn readChunkHeader(self: *RemoteConnection) !usize {
        var line_buf: [64]u8 = undefined;
        var idx: usize = 0;
        while (idx < line_buf.len) {
            const b = try self.readByte();
            if (b == '\n' and idx > 0 and line_buf[idx - 1] == '\r') {
                var hex_part = std.mem.trim(u8, line_buf[0 .. idx - 1], " \t");
                if (std.mem.indexOfScalar(u8, hex_part, ';')) |semi| {
                    hex_part = hex_part[0..semi];
                }
                return std.fmt.parseInt(usize, hex_part, 16);
            }
            line_buf[idx] = b;
            idx += 1;
        }
        return error.InvalidChunk;
    }

    pub fn skipCrLf(self: *RemoteConnection) !void {
        _ = try self.readByte();
        _ = try self.readByte();
    }

    pub fn writeAll(self: *RemoteConnection, bytes: []const u8) !void {
        if (Config.client.is_tls) {
            try self.tls_client.?.writer.writeAll(bytes);
            try self.tls_client.?.writer.flush();
            try self.direct_writer.writer.flush();
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

const PoolSocket = struct {
    id: usize,
    conn: ?*RemoteConnection = null,
    created_at: u64 = 0,
    in_use: bool = false,
    mutex: futex.Mutex = .{},
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
    pool: [Config.client.pool_size]PoolSocket = undefined,
    gen_counter: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Client {
        const uq = FrameQueue.init(allocator, Config.common.queue_capacity) catch unreachable;

        var octets: [4]u8 = .{ 127, 0, 0, 1 };
        _ = protocol.resolveDnsA(Config.client.remote_host, &octets);

        const r_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.client.remote_port),
            .addr = @as(u32, @bitCast(octets)),
        };

        var c = Client{
            .allocator = allocator,
            .io = io,
            .remote_addr = r_addr,
            .upstream_queue = uq,
            .local_streams = std.AutoHashMap(u32, *StreamContext).init(allocator),
            .connect_waiters = std.AutoHashMap(u32, *ConnectWaiter).init(allocator),
        };

        for (0..Config.client.pool_size) |i| {
            c.pool[i] = .{
                .id = i,
            };
        }

        return c;
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

        return RemoteConnection.init(fd, Config.client.remote_host, self.allocator);
    }

    pub fn start(self: *Client) !void {
        clientLog("info", "init", "starting", 0, "{\"msg\":\"initializing client pool\"}");

        for (0..Config.client.pool_size) |i| {
            const th = try std.Thread.spawn(.{}, poolWorkerLoop, .{ self, i });
            th.detach();
        }

        const rot_th = try std.Thread.spawn(.{}, poolRotationThread, .{self});
        rot_th.detach();

        const trigger_th = try std.Thread.spawn(.{}, batonPulseThread, .{self});
        trigger_th.detach();

        try self.socksListener();
    }

    fn poolRotationThread(self: *Client) void {
        const step = Config.client.socket_ttl_ms / Config.client.pool_size;
        while (true) {
            sleepMs(step);
            const now = getMilliTimestamp();
            for (0..Config.client.pool_size) |i| {
                const s = &self.pool[i];
                s.mutex.lock();
                if (s.conn != null and !s.in_use and s.created_at > 0 and (now >= s.created_at + Config.client.socket_ttl_ms)) {
                    s.conn.?.close();
                    s.conn = null;
                    const age = now - s.created_at;
                    s.created_at = 0;
                    var rot_data: [64]u8 = undefined;
                    const rot_slice = std.fmt.bufPrint(&rot_data, "{{\"idx\":{d},\"age_ms\":{d}}}", .{ i, age }) catch "{}";
                    clientLog("debug", "pool", "socket_rotated", 0, rot_slice);
                }
                s.mutex.unlock();
            }
        }
    }

    fn batonPulseThread(self: *Client) void {
        while (true) {
            _ = self.upstream_queue.waitData(Config.client.idle_interval_ms);
            self.executeBatonRound();
        }
    }

    fn acquireAvailableSocket(self: *Client) ?*PoolSocket {
        for (0..Config.client.pool_size) |i| {
            const s = &self.pool[i];
            s.mutex.lock();
            if (!s.in_use) {
                s.in_use = true;
                if (s.conn == null) {
                    s.conn = self.connectRemote() catch {
                        s.in_use = false;
                        s.mutex.unlock();
                        var err_data: [64]u8 = undefined;
                        const err_slice = std.fmt.bufPrint(&err_data, "{{\"idx\":{d},\"error\":\"on_demand_connect_failed\"}}", .{i}) catch "{}";
                        clientLog("error", "pool", "socket_connect_failed", 0, err_slice);
                        continue;
                    };
                    s.created_at = getMilliTimestamp();
                    var conn_data: [64]u8 = undefined;
                    const conn_slice = std.fmt.bufPrint(&conn_data, "{{\"idx\":{d},\"on_demand\":true}}", .{i}) catch "{}";
                    clientLog("debug", "pool", "socket_connected", 0, conn_slice);
                }
                s.mutex.unlock();
                return s;
            }
            s.mutex.unlock();
        }
        clientLog("warn", "pool", "pool_exhausted", 0, "{}");
        return null;
    }

    fn executeBatonRound(self: *Client) void {
        const target_sock = self.acquireAvailableSocket() orelse return;

        const th = std.Thread.spawn(.{}, executeBatonRequest, .{ self, target_sock }) catch {
            target_sock.mutex.lock();
            target_sock.in_use = false;
            target_sock.mutex.unlock();
            return;
        };
        th.detach();
    }

    fn executeBatonRequest(self: *Client, ps: *PoolSocket) void {
        defer {
            ps.mutex.lock();
            ps.in_use = false;
            ps.mutex.unlock();
        }

        const send_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch return;
        defer self.allocator.free(send_buf);

        const batch_len = self.upstream_queue.drainBatch(send_buf);
        const gen = self.gen_counter.fetchAdd(1, .monotonic);

        var req_hdr: [1024]u8 = undefined;
        const hdrs = std.fmt.bufPrint(&req_hdr,
            "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: {s}\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "{s}: {s}\r\n" ++
            "X-Gen: {d}\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: keep-alive\r\n\r\n",
            .{ Config.common.pipe_path, Config.client.remote_host, Config.client.user_agent, Config.common.token_header, Config.common.token, gen, batch_len }
        ) catch unreachable;

        var req_log: [128]u8 = undefined;
        const req_slice = std.fmt.bufPrint(&req_log, "{{\"idx\":{d},\"gen\":{d},\"bytes\":{d}}}", .{ ps.id, gen, batch_len }) catch "{}";
        clientLog("info", "baton", "request_sent", 0, req_slice);

        const start_time = getMilliTimestamp();
        var conn = ps.conn.?;
        const send_ok = blk: {
            conn.writeAll(hdrs) catch break :blk false;
            if (batch_len > 0) {
                conn.writeAll(send_buf[0..batch_len]) catch break :blk false;
            }
            break :blk true;
        };

        if (!send_ok) {
            clientLog("error", "baton", "write_failed", 0, req_slice);
            conn.close();
            ps.conn = null;
            return;
        }

        var resp_hdr_buf: [2048]u8 = undefined;
        const resp_hdrs = conn.readHeadersFast(&resp_hdr_buf) catch {
            clientLog("error", "baton", "headers_read_failed", 0, req_slice);
            conn.close();
            ps.conn = null;
            return;
        };

        const rtt = getMilliTimestamp() - start_time;
        const first_line = resp_hdrs[0 .. std.mem.indexOf(u8, resp_hdrs, "\r\n") orelse resp_hdrs.len];
        var resp_log: [256]u8 = undefined;
        const resp_slice = std.fmt.bufPrint(&resp_log, "{{\"idx\":{d},\"gen\":{d},\"status\":\"{s}\",\"rtt_ms\":{d}}}", .{ ps.id, gen, first_line, rtt }) catch "{}";
        clientLog("info", "baton", "response_headers", 0, resp_slice);

        const chunk_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch return;
        defer self.allocator.free(chunk_buf);

        while (true) {
            const chunk_len = conn.readChunkHeader() catch {
                conn.close();
                ps.conn = null;
                break;
            };

            if (chunk_len == 0) {
                conn.skipCrLf() catch {};
                var end_log: [64]u8 = undefined;
                const end_slice = std.fmt.bufPrint(&end_log, "{{\"idx\":{d},\"gen\":{d}}}", .{ ps.id, gen }) catch "{}";
                clientLog("debug", "baton", "stream_ended", 0, end_slice);
                break;
            }

            var read_chunk = chunk_buf;
            var dyn_chunk: ?[]u8 = null;
            defer if (dyn_chunk) |b| self.allocator.free(b);

            if (chunk_len > chunk_buf.len) {
                dyn_chunk = self.allocator.alloc(u8, chunk_len) catch null;
                if (dyn_chunk == null) {
                    conn.close();
                    ps.conn = null;
                    break;
                }
                read_chunk = dyn_chunk.?;
            }

            conn.readExact(read_chunk[0..chunk_len]) catch {
                conn.close();
                ps.conn = null;
                break;
            };
            conn.skipCrLf() catch {
                conn.close();
                ps.conn = null;
                break;
            };

            self.dispatchFrames(read_chunk[0..chunk_len]);
        }
    }

    fn poolWorkerLoop(self: *Client, id: usize) void {
        const s = &self.pool[id];
        const initial_delay = id * (Config.client.socket_ttl_ms / Config.client.pool_size);
        if (initial_delay > 0) {
            sleepMs(initial_delay);
        }

        s.mutex.lock();
        if (s.conn == null and !s.in_use) {
            s.conn = self.connectRemote() catch null;
            if (s.conn != null) {
                s.created_at = getMilliTimestamp();
                var conn_data: [64]u8 = undefined;
                const conn_slice = std.fmt.bufPrint(&conn_data, "{{\"idx\":{d}}}", .{id}) catch "{}";
                clientLog("debug", "pool", "socket_connected", 0, conn_slice);
            } else {
                var err_data: [64]u8 = undefined;
                const err_slice = std.fmt.bufPrint(&err_data, "{{\"idx\":{d},\"error\":\"connect_failed\"}}", .{id}) catch "{}";
                clientLog("error", "pool", "socket_connect_failed", 0, err_slice);
            }
        }
        s.mutex.unlock();
    }

    fn dispatchFrames(self: *Client, bytes: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= bytes.len) {
            var hdr: protocol.Header = undefined;
            @memcpy(std.mem.asBytes(&hdr), bytes[offset .. offset + @sizeOf(protocol.Header)]);

            if (hdr.magic != 0xCF01) break;
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > bytes.len) break;
            const payload = bytes[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .log => {
                    _ = std.os.linux.syscall3(.write, 1, @intFromPtr(payload.ptr), payload.len);
                    _ = std.os.linux.syscall3(.write, 1, @intFromPtr("\n"), 1);
                },
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
                if (ctx.reorder_queue.count() < Config.client.reorder_limit) {
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
            clientLog("info", "socks", "stream_closed", stream_id, "{}");
        }
    }

    fn socksListener(self: *Client) !void {
        const listen_fd = try listenOn(Config.client.socks_host, Config.client.socks_port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        clientLog("info", "socks", "ready", 0, "{\"host\":\"127.0.0.1\",\"port\":1080}");

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
        clientLog("info", "socks", "accept", 0, "{}");

        var greeting_hdr: [2]u8 = undefined;
        if (!protocol.readExactStream(stream, &greeting_hdr)) {
            clientLog("warn", "socks", "handshake_read_failed", 0, "{}");
            stream.close();
            return;
        }

        if (greeting_hdr[0] != 5) {
            clientLog("warn", "socks", "unsupported_version", 0, "{}");
            stream.close();
            return;
        }

        const nmethods = greeting_hdr[1];
        var methods_buf: [256]u8 = undefined;
        if (nmethods == 0 or !protocol.readExactStream(stream, methods_buf[0..nmethods])) {
            clientLog("warn", "socks", "methods_read_failed", 0, "{}");
            stream.close();
            return;
        }

        stream.writeAll(&[_]u8{ 5, 0 }) catch {
            stream.close();
            return;
        };

        var req_hdr: [4]u8 = undefined;
        if (!protocol.readExactStream(stream, &req_hdr)) {
            clientLog("warn", "socks", "req_hdr_read_failed", 0, "{}");
            stream.close();
            return;
        }

        if (req_hdr[0] != 5 or req_hdr[1] != 1) {
            clientLog("warn", "socks", "unsupported_command", 0, "{}");
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

        var req_log: [256]u8 = undefined;
        const req_slice = if (target_type == 1)
            std.fmt.bufPrint(&req_log, "{{\"target\":\"{d}.{d}.{d}.{d}\",\"port\":{d}}}", .{ addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3], target_port }) catch "{}"
        else
            std.fmt.bufPrint(&req_log, "{{\"target\":\"{s}\",\"port\":{d}}}", .{ addr_buf[0..addr_len], target_port }) catch "{}";
        clientLog("info", "socks", "cmd_connect", stream_id, req_slice);

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
            var fail_log: [128]u8 = undefined;
            const fail_slice = std.fmt.bufPrint(&fail_log, "{{\"dur_ms\":{d},\"error\":\"timeout_or_rejected\"}}", .{dur}) catch "{}";
            clientLog("error", "socks", "connect_failed", stream_id, fail_slice);
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            self.closeLocalStream(stream_id);
            return;
        }

        var ok_log: [128]u8 = undefined;
        const ok_slice = std.fmt.bufPrint(&ok_log, "{{\"dur_ms\":{d}}}", .{dur}) catch "{}";
        clientLog("info", "socks", "connect_established", stream_id, ok_slice);

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
