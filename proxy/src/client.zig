const std = @import("std");
const protocol = @import("protocol.zig");

pub const ClientOptions = struct {
    remote_url: []const u8 = "https://ssh.unsafie.com",
    sync_path: []const u8 = "/api/v1/sync",
    socks_addr: ?[]const u8 = "127.0.0.1:1080",
    forward_rule: ?[]const u8 = null,
    num_workers: usize = 8,
    chunk_kb: usize = 64,
    buf_mb: usize = 32,
    timeout_req_ms: u64 = 2500,
    timeout_conn_ms: u64 = 3000,
    reorder_limit: usize = 512,
    token: []const u8 = "default_secret",
    token_header: []const u8 = "X-Auth-Token",
    user_agent: []const u8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    name: []const u8 = "client-default",
    log_level: []const u8 = "info",
};

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
    query_buf[0] = 0x56;
    query_buf[1] = 0x78;
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
    if (resp_buf[0] != 0x56 or resp_buf[1] != 0x78) return false;
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

const RemoteConnection = struct {
    fd: i32,
    is_tls: bool,
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

    pub fn init(fd: i32, is_tls: bool, host: []const u8, io: std.Io, allocator: std.mem.Allocator) !*RemoteConnection {
        const conn = try allocator.create(RemoteConnection);
        conn.* = .{
            .fd = fd,
            .is_tls = is_tls,
            .io = io,
            .allocator = allocator,
        };

        if (is_tls) {
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

    pub fn read(self: *RemoteConnection, buffer: []u8) !usize {
        if (self.is_tls) {
            return self.tls_client.?.reader.readSliceShort(buffer) catch |err| return err;
        } else {
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(buffer.ptr), buffer.len);
            const signed: isize = @bitCast(rc);
            if (signed < 0) return error.ReadFailed;
            return @intCast(signed);
        }
    }

    pub fn readExact(self: *RemoteConnection, buffer: []u8) !void {
        var total: usize = 0;
        while (total < buffer.len) {
            const n = try self.read(buffer[total..]);
            if (n == 0) return error.ConnectionClosed;
            total += n;
        }
    }

    pub fn readHeaders(self: *RemoteConnection, buffer: []u8) ![]const u8 {
        var total: usize = 0;
        while (total < buffer.len) {
            var b: [1]u8 = undefined;
            const n = try self.read(&b);
            if (n == 0) return error.ConnectionClosed;
            buffer[total] = b[0];
            total += 1;
            if (total >= 4 and std.mem.eql(u8, buffer[total - 4 .. total], "\r\n\r\n")) {
                return buffer[0..total];
            }
        }
        return error.HeadersTooLong;
    }

    pub fn writeAll(self: *RemoteConnection, bytes: []const u8) !void {
        if (self.is_tls) {
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
        if (self.is_tls) {
            if (self.tls_client) |*tc| tc.end() catch {};
            self.tls_client = null;
        }
        if (self.fd >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
            self.fd = -1;
        }
        const alloc = self.allocator;
        alloc.destroy(self);
    }
};

const StreamContext = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 0,
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: Mutex = .{},
};

const ConnectWaiter = struct {
    status: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: ClientOptions,
    remote_host_hdr: []const u8,
    remote_addr: sockaddr_in,
    is_tls: bool,
    ring: RingBuffer,
    workers_sem: Semaphore = .{},
    local_streams: std.AutoHashMap(u32, *StreamContext),
    streams_mutex: Mutex = .{},
    connect_waiters: std.AutoHashMap(u32, *ConnectWaiter),
    waiters_mutex: Mutex = .{},
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, opts: ClientOptions) Client {
        const ring = RingBuffer.init(allocator, opts.buf_mb * 1024 * 1024) catch unreachable;

        var host_part: []const u8 = opts.remote_url;
        var port: u16 = 80;
        var is_tls = false;

        if (std.mem.startsWith(u8, host_part, "http://")) {
            host_part = host_part["http://".len..];
            port = 80;
            is_tls = false;
        } else if (std.mem.startsWith(u8, host_part, "https://")) {
            host_part = host_part["https://".len..];
            port = 443;
            is_tls = true;
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
        if (!parseIp4(host_part, &octets)) {
            _ = resolveDnsA(host_part, &octets);
        }

        const remote_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        return .{
            .allocator = allocator,
            .io = io,
            .opts = opts,
            .remote_host_hdr = host_header,
            .remote_addr = remote_addr,
            .is_tls = is_tls,
            .ring = ring,
            .local_streams = std.AutoHashMap(u32, *StreamContext).init(allocator),
            .connect_waiters = std.AutoHashMap(u32, *ConnectWaiter).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.ring.deinit(self.allocator);
        self.allocator.free(self.remote_host_hdr);

        self.streams_mutex.lock();
        var it = self.local_streams.iterator();
        while (it.next()) |entry| {
            const ctx = entry.value_ptr.*;
            ctx.stream.shutdown();
            ctx.stream.close();
            var q_it = ctx.reorder_queue.iterator();
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            ctx.reorder_queue.deinit();
            self.allocator.destroy(ctx);
        }
        self.local_streams.deinit();
        self.streams_mutex.unlock();

        self.waiters_mutex.lock();
        self.connect_waiters.deinit();
        self.waiters_mutex.unlock();
    }

    fn connectRemote(self: *Client) !*RemoteConnection {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const fd: i32 = @intCast(rc);
        errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 6, 1, @intFromPtr(&one), @sizeOf(c_int));

        const rcv_timeout = extern struct {
            sec: i64,
            usec: i64 = 0,
        }{
            .sec = @intCast(self.opts.timeout_req_ms / 1000),
            .usec = @intCast((self.opts.timeout_req_ms % 1000) * 1000),
        };
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 20, @intFromPtr(&rcv_timeout), @sizeOf(@TypeOf(rcv_timeout)));
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 21, @intFromPtr(&rcv_timeout), @sizeOf(@TypeOf(rcv_timeout)));

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&self.remote_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) return error.ConnectFailed;

        return RemoteConnection.init(fd, self.is_tls, self.remote_host_hdr, self.io, self.allocator);
    }

    pub fn sendToUpstream(self: *Client, stream_id: u32, seq_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
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

        while (!self.ring.push(full_frame[0..n])) {
            sleepMs(1);
        }
        self.workers_sem.post();
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
            const ctx = entry.value;
            ctx.stream.shutdown();
            ctx.stream.close();
            var q_it = ctx.reorder_queue.iterator();
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            ctx.reorder_queue.deinit();
            self.allocator.destroy(ctx);
            self.sendToUpstream(stream_id, 0, .close, "");
        }
    }

    pub fn start(self: *Client) !void {
        for (0..self.opts.num_workers) |w_idx| {
            const th = try std.Thread.spawn(.{}, duplexWorkerThread, .{ self, w_idx });
            th.detach();
        }

        if (self.opts.forward_rule) |fwd| {
            const fwd_th = try std.Thread.spawn(.{}, forwardListener, .{ self, fwd });
            fwd_th.detach();
        }

        if (self.opts.socks_addr) |socks| {
            try self.socksListener(socks);
        } else {
            while (true) sleepMs(1000);
        }
    }

    fn duplexWorkerThread(self: *Client, worker_id: usize) void {
        _ = worker_id;
        const max_chunk = self.opts.chunk_kb * 1024;
        const send_buf = self.allocator.alloc(u8, max_chunk) catch return;
        defer self.allocator.free(send_buf);

        const resp_body_buf = self.allocator.alloc(u8, max_chunk + 16384) catch return;
        defer self.allocator.free(resp_body_buf);

        var header_buf: [4096]u8 = undefined;
        var conn: ?*RemoteConnection = null;

        while (true) {
            if (conn == null) {
                conn = self.connectRemote() catch {
                    sleepMs(50);
                    continue;
                };
            }

            const to_send_len = self.ring.drainAtMost(send_buf);
            const req_body = send_buf[0..to_send_len];

            var req_hdr_scratch: [1024]u8 = undefined;
            const hdr_text = std.fmt.bufPrint(&req_hdr_scratch,
                "POST {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "User-Agent: {s}\r\n" ++
                "{s}: {s}\r\n" ++
                "Content-Type: application/octet-stream\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: keep-alive\r\n\r\n",
                .{ self.opts.sync_path, self.remote_host_hdr, self.opts.user_agent, self.opts.token_header, self.opts.token, req_body.len }
            ) catch {
                if (conn) |c| { c.close(); conn = null; }
                continue;
            };

            const write_res = blk: {
                conn.?.writeAll(hdr_text) catch break :blk false;
                if (req_body.len > 0) {
                    conn.?.writeAll(req_body) catch break :blk false;
                }
                break :blk true;
            };

            if (!write_res) {
                if (req_body.len > 0) {
                    _ = self.ring.push(req_body);
                    self.workers_sem.post();
                }
                if (conn) |c| { c.close(); conn = null; }
                sleepMs(20);
                continue;
            }

            const hdrs = conn.?.readHeaders(&header_buf) catch {
                if (req_body.len > 0) {
                    _ = self.ring.push(req_body);
                    self.workers_sem.post();
                }
                if (conn) |c| { c.close(); conn = null; }
                sleepMs(20);
                continue;
            };

            var content_len: usize = 0;
            var is_close = false;

            var h_it = std.mem.splitSequence(u8, hdrs, "\r\n");
            _ = h_it.next();
            while (h_it.next()) |line| {
                if (line.len == 0) break;
                if (startsWithIgnoreCase(line, "content-length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \t"), 10) catch 0;
                } else if (startsWithIgnoreCase(line, "connection:")) {
                    if (containsIgnoreCase(line, "close")) {
                        is_close = true;
                    }
                }
            }

            if (content_len > 0) {
                var target_resp = resp_body_buf;
                var dyn_resp: ?[]u8 = null;
                defer if (dyn_resp) |b| self.allocator.free(b);

                if (content_len > resp_body_buf.len) {
                    dyn_resp = self.allocator.alloc(u8, content_len) catch null;
                    if (dyn_resp == null) {
                        if (conn) |c| { c.close(); conn = null; }
                        continue;
                    }
                    target_resp = dyn_resp.?;
                }

                const r_slice = target_resp[0..content_len];
                conn.?.readExact(r_slice) catch {
                    if (conn) |c| { c.close(); conn = null; }
                    continue;
                };

                self.dispatchFrames(r_slice);
            }

            if (is_close) {
                if (conn) |c| { c.close(); conn = null; }
            }

            if (self.ring.count > 0) {
                self.workers_sem.post();
            } else if (content_len == 0) {
                sleepMs(5);
            }
        }
    }

    fn dispatchFrames(self: *Client, bytes: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= bytes.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(bytes[offset..].ptr));
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > bytes.len) break;
            const payload = bytes[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .connect_ok => {
                    self.waiters_mutex.lock();
                    if (self.connect_waiters.get(hdr.stream_id)) |waiter| {
                        waiter.status.store(1, .release);
                    }
                    self.waiters_mutex.unlock();
                },
                .data => {
                    self.handleDownstreamData(hdr.stream_id, hdr.seq_id, payload);
                },
                .close => {
                    self.closeLocalStream(hdr.stream_id);
                },
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
                    const q_payload = entry.value;
                    defer self.allocator.free(q_payload);

                    ctx.stream.writeAll(q_payload) catch {
                        self.closeLocalStream(stream_id);
                        return;
                    };
                    ctx.expected_seq +%= 1;
                }
            } else if (seq_id > ctx.expected_seq) {
                if (ctx.reorder_queue.count() < self.opts.reorder_limit) {
                    const copy = self.allocator.alloc(u8, payload.len) catch return;
                    @memcpy(copy, payload);
                    ctx.reorder_queue.put(seq_id, copy) catch {
                        self.allocator.free(copy);
                    };
                }
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
            const th = std.Thread.spawn(.{}, handleSocksConnection, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
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

        const ctx = self.allocator.create(StreamContext) catch {
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        ctx.* = .{
            .stream = stream,
            .expected_seq = 0,
            .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
        };

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, ctx) catch {
            self.streams_mutex.unlock();
            self.allocator.destroy(ctx);
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        var seq: u32 = 0;
        self.sendToUpstream(stream_id, seq, .connect, conn_payload);
        seq += 1;

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
            sleepMs(20);
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
                self.sendToUpstream(stream_id, seq, .close, "");
                self.closeLocalStream(stream_id);
                return;
            }
            self.sendToUpstream(stream_id, seq, .data, data_buf[0..rd]);
            seq +%= 1;
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
            const th = std.Thread.spawn(.{}, handleForwardConnection, .{ self, stream, r_host, r_port }) catch {
                stream.shutdown();
                stream.close();
                continue;
            };
            th.detach();
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

        const ctx = self.allocator.create(StreamContext) catch {
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        ctx.* = .{
            .stream = stream,
            .expected_seq = 0,
            .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
        };

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, ctx) catch {
            self.streams_mutex.unlock();
            self.allocator.destroy(ctx);
            self.waiters_mutex.lock();
            _ = self.connect_waiters.remove(stream_id);
            self.waiters_mutex.unlock();
            stream.shutdown();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        var seq: u32 = 0;
        self.sendToUpstream(stream_id, seq, .connect, conn_payload);
        seq += 1;

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
            sleepMs(20);
            self.closeLocalStream(stream_id);
            return;
        }

        var data_buf: [16384]u8 = undefined;
        while (true) {
            const rd = stream.read(&data_buf) catch 0;
            if (rd == 0) {
                self.sendToUpstream(stream_id, seq, .close, "");
                self.closeLocalStream(stream_id);
                return;
            }
            self.sendToUpstream(stream_id, seq, .data, data_buf[0..rd]);
            seq +%= 1;
        }
    }
};
