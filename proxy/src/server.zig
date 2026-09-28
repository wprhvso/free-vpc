const std = @import("std");
const protocol = @import("protocol.zig");

pub const ServerOptions = struct {
    host: []const u8 = "0.0.0.0",
    port: u16 = 8022,
    sync_path: []const u8 = "/api/v1/sync",
    chunk_kb: usize = 64,
    buf_mb: usize = 32,
    hold_ms: u64 = 2000,
    target_conn_timeout_ms: u64 = 3000,
    reorder_limit: usize = 512,
    token: []const u8 = "default_secret",
    token_header: []const u8 = "X-Auth-Token",
    stream_idle_sec: u64 = 300,
    log_level: []const u8 = "info",
};

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

    pub fn timedWait(self: *Semaphore, timeout_ms: u64) bool {
        const timespec = extern struct {
            sec: i64,
            nsec: i64,
        };
        const ts = timespec{
            .sec = @intCast(timeout_ms / 1000),
            .nsec = @intCast((timeout_ms % 1000) * 1_000_000),
        };

        var c = self.count.load(.acquire);
        while (c > 0) {
            if (self.count.cmpxchgWeak(c, c - 1, .acquire, .monotonic)) |actual| {
                c = actual;
            } else return true;
        }

        const rc = std.os.linux.syscall4(.futex, @intFromPtr(&self.count.raw), 0, 0, @intFromPtr(&ts));
        const signed: isize = @bitCast(rc);
        _ = signed;

        c = self.count.load(.acquire);
        while (c > 0) {
            if (self.count.cmpxchgWeak(c, c - 1, .acquire, .monotonic)) |actual| {
                c = actual;
            } else return true;
        }
        return false;
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

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    for (needle, 0..) |c, i| {
        if (std.ascii.toLower(haystack[i]) != std.ascii.toLower(c)) return false;
    }
    return true;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(c)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
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
            if (parseIp4(rest, &ip)) return ip;
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

    var octets: [4]u8 = .{ 0, 0, 0, 0 };
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

const StreamState = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 1,
    downstream_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    close_pending: bool = false,
    close_seq: u32 = 0,
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: Mutex = .{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: ServerOptions,
    downstream_ring: RingBuffer,
    downstream_sem: Semaphore = .{},
    streams: std.AutoHashMap(u32, *StreamState),
    streams_mutex: Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, opts: ServerOptions) Server {
        const ring = RingBuffer.init(allocator, opts.buf_mb * 1024 * 1024) catch unreachable;
        return .{
            .allocator = allocator,
            .io = io,
            .opts = opts,
            .downstream_ring = ring,
            .streams = std.AutoHashMap(u32, *StreamState).init(allocator),
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
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            state.reorder_queue.deinit();
            self.allocator.destroy(state);
        }
        self.streams.deinit();
        self.streams_mutex.unlock();
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

        while (!self.downstream_ring.push(full_frame[0..n])) {
            sleepMs(1);
        }
        self.downstream_sem.post();
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const state = entry.value;
            state.stream.shutdown();
            state.stream.close();

            var q_it = state.reorder_queue.iterator();
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            state.reorder_queue.deinit();
            self.allocator.destroy(state);

            self.sendToDownstream(stream_id, 0, .close, "");
        }
    }

    pub fn start(self: *Server) !void {
        const listen_fd = try listenOn(self.opts.host, self.opts.port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const th = std.Thread.spawn(.{}, handleHttpConnection, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
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

    fn handleHttpConnection(self: *Server, stream: protocol.SocketStream) void {
        var header_buf: [4096]u8 = undefined;
        const max_drain = self.opts.chunk_kb * 1024;
        const drain_buf = self.allocator.alloc(u8, max_drain) catch {
            stream.close();
            return;
        };
        defer self.allocator.free(drain_buf);

        while (true) {
            const headers = readHeaders(stream, &header_buf) catch {
                stream.close();
                return;
            };

            const first_line_end = std.mem.indexOf(u8, headers, "\r\n") orelse headers.len;
            const req_line = headers[0..first_line_end];

            if (std.mem.startsWith(u8, req_line, "GET /health") or std.mem.startsWith(u8, req_line, "GET / ")) {
                const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
                stream.writeAll(resp) catch return;
                continue;
            }

            var path_matches = false;
            var is_post = false;

            if (std.mem.startsWith(u8, req_line, "POST ")) {
                is_post = true;
                const path_part = req_line[5..];
                if (std.mem.indexOfScalar(u8, path_part, ' ')) |sp| {
                    if (std.mem.eql(u8, path_part[0..sp], self.opts.sync_path)) {
                        path_matches = true;
                    }
                }
            }

            if (!is_post or !path_matches) {
                stream.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                stream.close();
                return;
            }

            var auth_valid = false;
            var content_len: usize = 0;
            var is_keep_alive = true;

            var h_it = std.mem.splitSequence(u8, headers, "\r\n");
            _ = h_it.next();
            while (h_it.next()) |line| {
                if (line.len == 0) break;
                if (startsWithIgnoreCase(line, "content-length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \t"), 10) catch 0;
                } else if (startsWithIgnoreCase(line, "connection:")) {
                    if (containsIgnoreCase(line, "close")) {
                        is_keep_alive = false;
                    }
                } else if (line.len >= self.opts.token_header.len + 1 and startsWithIgnoreCase(line, self.opts.token_header)) {
                    const val = std.mem.trim(u8, line[self.opts.token_header.len + 1 ..], " \t");
                    if (std.mem.eql(u8, val, self.opts.token)) {
                        auth_valid = true;
                    }
                }
            }

            if (!auth_valid and self.opts.token.len > 0) {
                stream.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                stream.close();
                return;
            }

            if (content_len > 0) {
                const body = self.allocator.alloc(u8, content_len) catch {
                    stream.close();
                    return;
                };
                defer self.allocator.free(body);

                readExact(stream, body) catch {
                    stream.close();
                    return;
                };

                self.processUpstreamBody(body);
            }

            var drained_n = self.downstream_ring.drainAtMost(drain_buf);
            if (drained_n == 0 and self.opts.hold_ms > 0) {
                if (self.downstream_sem.timedWait(self.opts.hold_ms)) {
                    drained_n = self.downstream_ring.drainAtMost(drain_buf);
                }
            }

            var resp_hdr: [256]u8 = undefined;
            if (drained_n > 0) {
                const hdr_text = std.fmt.bufPrint(&resp_hdr,
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: application/octet-stream\r\n" ++
                    "Content-Length: {d}\r\n" ++
                    "Connection: {s}\r\n\r\n",
                    .{ drained_n, if (is_keep_alive) "keep-alive" else "close" }
                ) catch {
                    stream.close();
                    return;
                };

                stream.writeAll(hdr_text) catch { stream.close(); return; };
                stream.writeAll(drain_buf[0..drained_n]) catch { stream.close(); return; };
            } else {
                const hdr_text = std.fmt.bufPrint(&resp_hdr,
                    "HTTP/1.1 204 No Content\r\n" ++
                    "Connection: {s}\r\n\r\n",
                    .{ if (is_keep_alive) "keep-alive" else "close" }
                ) catch {
                    stream.close();
                    return;
                };
                stream.writeAll(hdr_text) catch { stream.close(); return; };
            }

            if (!is_keep_alive) {
                stream.close();
                return;
            }
        }
    }

    fn processUpstreamBody(self: *Server, body: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= body.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(body[offset..].ptr));
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > body.len) break;
            const payload = body[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .connect => self.handleConnect(hdr.stream_id, payload),
                .data => self.handleOrderedData(hdr.stream_id, hdr.seq_id, payload),
                .close => self.handleOrderedClose(hdr.stream_id, hdr.seq_id),
                else => {},
            }
        }
    }

    fn handleOrderedData(self: *Server, stream_id: u32, seq_id: u32, payload: []const u8) void {
        self.streams_mutex.lock();
        const state_opt = self.streams.get(stream_id);
        self.streams_mutex.unlock();

        if (state_opt) |state| {
            state.mutex.lock();
            defer state.mutex.unlock();

            if (seq_id == state.expected_seq) {
                state.stream.writeAll(payload) catch {
                    self.closeStream(stream_id);
                    return;
                };
                state.expected_seq +%= 1;

                while (state.reorder_queue.fetchRemove(state.expected_seq)) |entry| {
                    const q_payload = entry.value;
                    defer self.allocator.free(q_payload);

                    state.stream.writeAll(q_payload) catch {
                        self.closeStream(stream_id);
                        return;
                    };
                    state.expected_seq +%= 1;
                }

                if (state.close_pending and state.expected_seq >= state.close_seq) {
                    self.closeStream(stream_id);
                }
            } else if (seq_id > state.expected_seq) {
                if (state.reorder_queue.count() < self.opts.reorder_limit) {
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
            self.connectTcpIpv4(stream_id, octets, port);
        } else if (atyp == 4 and addr_len == 16) {
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

            const th = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn, state }) catch {
                self.closeStream(stream_id);
                return;
            };
            th.detach();
        } else if (atyp == 2) {
            var octets: [4]u8 = .{ 0, 0, 0, 0 };
            if (parseIp4(addr_data, &octets) or resolveDnsA(addr_data, &octets)) {
                self.connectTcpIpv4(stream_id, octets, port);
            } else {
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

        const th = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn, state }) catch {
            self.closeStream(stream_id);
            return;
        };
        th.detach();
    }

    fn targetReaderWorker(self: *Server, stream_id: u32, target_stream: protocol.SocketStream, state: *StreamState) void {
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) {
                self.closeStream(stream_id);
                return;
            }
            const s_seq = state.downstream_seq.fetchAdd(1, .monotonic);
            self.sendToDownstream(stream_id, s_seq, .data, buf[0..n]);
        }
    }
};
