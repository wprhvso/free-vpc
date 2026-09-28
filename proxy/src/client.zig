const std = @import("std");
const protocol = @import("protocol.zig");

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

const ConnectWaiter = struct {
    status: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
};

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

const DirectStream = struct {
    fd: i32,

    pub fn read(self: DirectStream, buffer: []u8) !usize {
        const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(buffer.ptr), buffer.len);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.ReadFailed;
        return @intCast(signed);
    }

    pub fn readExact(self: DirectStream, buffer: []u8) !void {
        var total: usize = 0;
        while (total < buffer.len) {
            const n = try self.read(buffer[total..]);
            if (n == 0) return error.ConnectionClosed;
            total += n;
        }
    }

    pub fn readLine(self: DirectStream, buffer: []u8) !usize {
        var i: usize = 0;
        while (i < buffer.len) {
            var b: [1]u8 = undefined;
            const n = try self.read(&b);
            if (n == 0) return error.ConnectionClosed;
            if (b[0] == '\n') {
                if (i > 0 and buffer[i - 1] == '\r') {
                    return i - 1;
                }
                return i;
            }
            buffer[i] = b[0];
            i += 1;
        }
        return error.LineTooLong;
    }

    pub fn writeAll(self: DirectStream, bytes: []const u8) !void {
        var index: usize = 0;
        while (index < bytes.len) {
            const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(bytes.ptr + index), bytes.len - index);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) return error.WriteFailed;
            index += @intCast(signed);
        }
    }

    pub fn close(self: DirectStream) void {
        _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    remote_url: []const u8,
    remote_host_hdr: []const u8,
    remote_addr: sockaddr_in,
    socks_addr: ?[]const u8,
    forward_rule: ?[]const u8,
    num_workers: usize,
    max_chunk_size: usize,
    ring: RingBuffer,
    workers_free: []bool,
    pool_mutex: Mutex = .{},
    local_streams: std.AutoHashMap(u32, protocol.SocketStream),
    streams_mutex: Mutex = .{},
    connect_waiters: std.AutoHashMap(u32, *ConnectWaiter),
    waiters_mutex: Mutex = .{},
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        remote_url: []const u8,
        socks_addr: ?[]const u8,
        forward_rule: ?[]const u8,
        num_workers: usize,
        max_body_mb: usize,
        buf_mb: usize,
    ) Client {
        const ring = RingBuffer.init(allocator, buf_mb * 1024 * 1024) catch unreachable;
        const workers_free = allocator.alloc(bool, num_workers) catch unreachable;
        @memset(workers_free, true);

        var host_part: []const u8 = remote_url;
        var port: u16 = 80;

        if (std.mem.startsWith(u8, host_part, "http://")) {
            host_part = host_part["http://".len..];
            port = 80;
        } else if (std.mem.startsWith(u8, host_part, "https://")) {
            host_part = host_part["https://".len..];
            port = 443;
        }

        if (std.mem.indexOfScalar(u8, host_part, '/')) |slash| {
            host_part = host_part[0..slash];
        }

        const host_header = allocator.dupe(u8, host_part) catch unreachable;

        if (std.mem.indexOfScalar(u8, host_part, ':')) |colon| {
            port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch port;
            host_part = host_part[0..colon];
        }

        var octets: [4]u8 = .{ 127, 0, 0, 1 };
        _ = parseIp4(host_part, &octets);

        const remote_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        return .{
            .allocator = allocator,
            .io = io,
            .remote_url = remote_url,
            .remote_host_hdr = host_header,
            .remote_addr = remote_addr,
            .socks_addr = socks_addr,
            .forward_rule = forward_rule,
            .num_workers = num_workers,
            .max_chunk_size = max_body_mb * 1024 * 1024,
            .ring = ring,
            .workers_free = workers_free,
            .local_streams = std.AutoHashMap(u32, protocol.SocketStream).init(allocator),
            .connect_waiters = std.AutoHashMap(u32, *ConnectWaiter).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.ring.deinit(self.allocator);
        self.allocator.free(self.workers_free);
        self.allocator.free(self.remote_host_hdr);

        self.streams_mutex.lock();
        var it = self.local_streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.shutdown();
            entry.value_ptr.close();
        }
        self.local_streams.deinit();
        self.streams_mutex.unlock();

        self.waiters_mutex.lock();
        self.connect_waiters.deinit();
        self.waiters_mutex.unlock();
    }

    fn connectRemoteTcp(self: *Client) !DirectStream {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const fd: i32 = @intCast(rc);
        errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 6, 1, @intFromPtr(&one), @sizeOf(c_int));

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&self.remote_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) return error.ConnectFailed;

        return DirectStream{ .fd = fd };
    }

    pub fn sendToUpstream(self: *Client, stream_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
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

        const n = protocol.writeFrame(full_frame, stream_id, cmd, payload) catch return;

        while (!self.ring.push(full_frame[0..n])) {
            sleepMs(2);
        }
    }

    pub fn closeLocalStream(self: *Client, stream_id: u32) void {
        self.waiters_mutex.lock();
        if (self.connect_waiters.get(stream_id)) |waiter| {
            waiter.status.store(2, .release);
        }
        self.waiters_mutex.unlock();

        self.streams_mutex.lock();
        const removed = self.local_streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const stream = entry.value;
            stream.shutdown();
            stream.close();
            self.sendToUpstream(stream_id, .close, "");
        }
    }

    pub fn start(self: *Client) !void {
        const sse_thread = try std.Thread.spawn(.{}, downstreamSseWorker, .{self});
        sse_thread.detach();

        for (0..self.num_workers) |w_idx| {
            const push_thread = try std.Thread.spawn(.{}, upstreamWorkerThread, .{ self, w_idx });
            push_thread.detach();
        }

        if (self.forward_rule) |fwd| {
            const fwd_thread = try std.Thread.spawn(.{}, forwardListener, .{ self, fwd });
            fwd_thread.detach();
        }

        if (self.socks_addr) |socks| {
            try self.socksListener(socks);
        } else {
            while (true) {
                sleepMs(1000);
            }
        }
    }

    fn upstreamWorkerThread(self: *Client, worker_id: usize) void {
        const chunk_buf = self.allocator.alloc(u8, self.max_chunk_size) catch return;
        defer self.allocator.free(chunk_buf);

        var seed: u64 = @as(u64, @intCast(worker_id)) ^ 0xdeadbeef;
        _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&seed), @sizeOf(u64), 0);
        var prng = std.Random.DefaultPrng.init(seed);        

        var opt_conn: ?DirectStream = null;
        defer if (opt_conn) |c| c.close();

        while (true) {
            const should_run = self.acquireRandomWorkerSlot(worker_id, prng.random());
            if (!should_run) {
                sleepMs(2);
                continue;
            }

            const bytes_read = self.ring.drainAtMost(chunk_buf);
            if (bytes_read == 0) {
                self.releaseWorkerSlot(worker_id);
                sleepMs(2);
                continue;
            }

            const payload = chunk_buf[0..bytes_read];

            if (opt_conn == null) {
                opt_conn = self.connectRemoteTcp() catch {
                    self.releaseWorkerSlot(worker_id);
                    sleepMs(50);
                    continue;
                };
            }

            var conn = opt_conn.?;

            var req_hdr: [256]u8 = undefined;
            const hdr_text = std.fmt.bufPrint(&req_hdr,
                "POST /push HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: keep-alive\r\n\r\n",
                .{ self.remote_host_hdr, payload.len }
            ) catch {
                self.releaseWorkerSlot(worker_id);
                continue;
            };

            conn.writeAll(hdr_text) catch {
                conn.close();
                opt_conn = null;
                self.releaseWorkerSlot(worker_id);
                sleepMs(10);
                continue;
            };

            conn.writeAll(payload) catch {
                conn.close();
                opt_conn = null;
                self.releaseWorkerSlot(worker_id);
                sleepMs(10);
                continue;
            };

            var resp_buf: [256]u8 = undefined;
            const n = conn.read(&resp_buf) catch 0;
            if (n == 0) {
                conn.close();
                opt_conn = null;
            }

            self.releaseWorkerSlot(worker_id);
        }
    }

    fn acquireRandomWorkerSlot(self: *Client, worker_id: usize, rand: std.Random) bool {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        var free_count: usize = 0;
        var free_indices: [64]usize = undefined;

        for (self.workers_free, 0..) |is_free, idx| {
            if (is_free and free_count < free_indices.len) {
                free_indices[free_count] = idx;
                free_count += 1;
            }
        }

        if (free_count == 0) return false;

        const picked_idx = free_indices[rand.uintLessThan(usize, free_count)];
        if (picked_idx == worker_id) {
            self.workers_free[worker_id] = false;
            return true;
        }

        return false;
    }

    fn releaseWorkerSlot(self: *Client, worker_id: usize) void {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();
        self.workers_free[worker_id] = true;
    }

    fn downstreamSseWorker(self: *Client) void {
        while (true) {
            var conn = self.connectRemoteTcp() catch {
                sleepMs(200);
                continue;
            };
            defer conn.close();

            var req_hdr: [256]u8 = undefined;
            const hdr_text = std.fmt.bufPrint(&req_hdr,
                "GET /stream HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Accept: text/event-stream\r\n" ++
                "Cache-Control: no-cache\r\n" ++
                "Connection: keep-alive\r\n\r\n",
                .{ self.remote_host_hdr }
            ) catch return;

            conn.writeAll(hdr_text) catch continue;

            while (true) {
                var line_buf: [256]u8 = undefined;
                const line_len = conn.readLine(&line_buf) catch break;
                if (line_len == 0) break;
            }

            var chunk_hdr_buf: [32]u8 = undefined;
            var frame_scratch: [65536]u8 = undefined;

            while (true) {
                const hex_line_len = conn.readLine(&chunk_hdr_buf) catch break;
                if (hex_line_len == 0) continue;

                const chunk_size = std.fmt.parseInt(usize, std.mem.trim(u8, chunk_hdr_buf[0..hex_line_len], " \t\r"), 16) catch break;
                if (chunk_size == 0) break;

                var target_buf: []u8 = frame_scratch[0..chunk_size];
                var dyn_alloc: ?[]u8 = null;
                defer if (dyn_alloc) |b| self.allocator.free(b);

                if (chunk_size > frame_scratch.len) {
                    dyn_alloc = self.allocator.alloc(u8, chunk_size) catch break;
                    target_buf = dyn_alloc.?;
                }

                conn.readExact(target_buf) catch break;

                var crlf: [2]u8 = undefined;
                conn.readExact(&crlf) catch break;

                self.dispatchFrames(target_buf);
            }

            sleepMs(50);
        }
    }

    fn dispatchFrames(self: *Client, bytes: []const u8) void {
        var offset: usize = 0;

        while (offset + @sizeOf(protocol.Header) <= bytes.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(bytes[offset..].ptr));
            const frame_len = @sizeOf(protocol.Header) + hdr.payload_len;

            if (offset + frame_len > bytes.len) break;

            const payload = bytes[offset + @sizeOf(protocol.Header) .. offset + frame_len];
            offset += frame_len;

            switch (hdr.cmd) {
                .connect_ok => {
                    self.waiters_mutex.lock();
                    if (self.connect_waiters.get(hdr.stream_id)) |waiter| {
                        waiter.status.store(1, .release);
                    }
                    self.waiters_mutex.unlock();
                },
                .data => {
                    self.streams_mutex.lock();
                    const s_opt = self.local_streams.get(hdr.stream_id);
                    self.streams_mutex.unlock();
                    if (s_opt) |local_stream| {
                        local_stream.writeAll(payload) catch {
                            self.closeLocalStream(hdr.stream_id);
                        };
                    }
                },
                .close => {
                    self.closeLocalStream(hdr.stream_id);
                },
                else => {},
            }
        }
    }

    fn readExactStream(stream: protocol.SocketStream, buf: []u8) bool {
        var total: usize = 0;
        while (total < buf.len) {
            const n = stream.read(buf[total..]) catch 0;
            if (n == 0) return false;
            total += n;
        }
        return true;
    }

    fn socksListener(self: *Client, socks_str: []const u8) !void {
        var port: u16 = 1080;
        var host = socks_str;

        if (std.mem.indexOfScalar(u8, socks_str, ':')) |colon| {
            host = socks_str[0..colon];
            port = std.fmt.parseInt(u16, socks_str[colon + 1 ..], 10) catch 1080;
        }

        const listen_fd = try listenOn(host, port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const thread = try std.Thread.spawn(.{}, handleSocksConnection, .{ self, stream });
            thread.detach();
        }
    }

    fn handleSocksConnection(self: *Client, stream: protocol.SocketStream) void {
        var hand_buf: [2]u8 = undefined;
        if (!readExactStream(stream, &hand_buf)) {
            stream.shutdown();
            stream.close();
            return;
        }

        if (hand_buf[0] != 5) {
            if (hand_buf[0] == 'G' or hand_buf[0] == 'P' or hand_buf[0] == 'H') {
                const msg = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nThis is a SOCKS5 proxy port. Use: curl -x socks5h://127.0.0.1:1080 <url>\r\n";
                _ = stream.writeAll(msg) catch {};
            }
            stream.shutdown();
            stream.close();
            return;
        }

        const nmethods = hand_buf[1];
        var methods_buf: [256]u8 = undefined;
        if (nmethods == 0 or !readExactStream(stream, methods_buf[0..nmethods])) {
            stream.shutdown();
            stream.close();
            return;
        }

        _ = stream.writeAll(&[_]u8{ 5, 0 }) catch {
            stream.shutdown();
            stream.close();
            return;
        };

        var req_buf: [4]u8 = undefined;
        if (!readExactStream(stream, &req_buf)) {
            stream.shutdown();
            stream.close();
            return;
        }

        if (req_buf[0] != 5 or req_buf[1] != 1) {
            _ = stream.writeAll(&[_]u8{ 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            stream.shutdown();
            stream.close();
            return;
        }

        const atyp = req_buf[3];
        var addr_buf: [256]u8 = undefined;
        var addr_len: u8 = 0;

        if (atyp == 1) {
            addr_len = 4;
            if (!readExactStream(stream, addr_buf[0..4])) {
                stream.shutdown();
                stream.close();
                return;
            }
        } else if (atyp == 3) {
            var domain_len_buf: [1]u8 = undefined;
            if (!readExactStream(stream, &domain_len_buf)) {
                stream.shutdown();
                stream.close();
                return;
            }
            addr_len = domain_len_buf[0];
            if (addr_len == 0 or !readExactStream(stream, addr_buf[0..addr_len])) {
                stream.shutdown();
                stream.close();
                return;
            }
        } else if (atyp == 4) {
            addr_len = 16;
            if (!readExactStream(stream, addr_buf[0..16])) {
                stream.shutdown();
                stream.close();
                return;
            }
        } else {
            _ = stream.writeAll(&[_]u8{ 5, 8, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            stream.shutdown();
            stream.close();
            return;
        }

        var port_buf: [2]u8 = undefined;
        if (!readExactStream(stream, &port_buf)) {
            stream.shutdown();
            stream.close();
            return;
        }

        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        var payload_buf: [300]u8 = undefined;
        @memcpy(payload_buf[0..2], &port_buf);
        payload_buf[2] = if (atyp == 3) 2 else atyp;
        payload_buf[3] = addr_len;
        @memcpy(payload_buf[4 .. 4 + addr_len], addr_buf[0..addr_len]);
        const conn_payload = payload_buf[0 .. 4 + addr_len];

        var waiter = ConnectWaiter{};

        self.waiters_mutex.lock();
        self.connect_waiters.put(stream_id, &waiter) catch {
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.waiters_mutex.unlock();

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, stream) catch {
            self.streams_mutex.unlock();
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        self.sendToUpstream(stream_id, .connect, conn_payload);

        var waited_ms: usize = 0;
        while (waiter.status.load(.acquire) == 0 and waited_ms < 15000) : (waited_ms += 10) {
            sleepMs(10);
        }

        self.waiters_mutex.lock();
        _ = self.connect_waiters.remove(stream_id);
        self.waiters_mutex.unlock();

        const connected = (waiter.status.load(.acquire) == 1);

        if (!connected) {
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            self.closeLocalStream(stream_id);
            return;
        }

        const success_reply = [_]u8{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        _ = stream.writeAll(&success_reply) catch {
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
            self.sendToUpstream(stream_id, .data, data_buf[0..rd]);
        }
    }

    fn forwardListener(self: *Client, fwd_rule: []const u8) void {
        var it = std.mem.splitScalar(u8, fwd_rule, ':');
        const l_port_str = it.next() orelse return;
        const r_host = it.next() orelse return;
        const r_port_str = it.next() orelse return;

        const l_port = std.fmt.parseInt(u16, l_port_str, 10) catch return;
        const r_port = std.fmt.parseInt(u16, r_port_str, 10) catch return;

        const listen_fd = listenOn("127.0.0.1", l_port) catch return;
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const thread = std.Thread.spawn(.{}, handleForwardConnection, .{ self, stream, r_host, r_port }) catch {
                stream.shutdown();
                stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn handleForwardConnection(self: *Client, stream: protocol.SocketStream, r_host: []const u8, r_port: u16) void {
        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        var payload_buf: [300]u8 = undefined;
        std.mem.writeInt(u16, payload_buf[0..2], r_port, .big);

        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        var total_payload_len: usize = 0;

        if (parseIp4(r_host, &octets)) {
            payload_buf[2] = 1;
            payload_buf[3] = 4;
            @memcpy(payload_buf[4..8], &octets);
            total_payload_len = 8;
        } else {
            payload_buf[2] = 2;
            payload_buf[3] = @intCast(r_host.len);
            @memcpy(payload_buf[4 .. 4 + r_host.len], r_host);
            total_payload_len = 4 + r_host.len;
        }

        const conn_payload = payload_buf[0..total_payload_len];
        var waiter = ConnectWaiter{};

        self.waiters_mutex.lock();
        self.connect_waiters.put(stream_id, &waiter) catch {
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.waiters_mutex.unlock();

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, stream) catch {
            self.streams_mutex.unlock();
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        self.sendToUpstream(stream_id, .connect, conn_payload);

        var waited_ms: usize = 0;
        while (waiter.status.load(.acquire) == 0 and waited_ms < 15000) : (waited_ms += 10) {
            sleepMs(10);
        }

        self.waiters_mutex.lock();
        _ = self.connect_waiters.remove(stream_id);
        self.waiters_mutex.unlock();

        const connected = (waiter.status.load(.acquire) == 1);

        if (!connected) {
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            sleepMs(50);
            self.closeLocalStream(stream_id);
            return;
        }

        var data_buf: [16384]u8 = undefined;
        while (true) {
            const rd = stream.read(&data_buf) catch 0;
            if (rd == 0) {
                self.closeLocalStream(stream_id);
                return;
            }
            self.sendToUpstream(stream_id, .data, data_buf[0..rd]);
        }
    }
};
