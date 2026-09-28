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

    pub fn readLine(self: *RemoteConnection, buffer: []u8) !usize {
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

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    remote_url: []const u8,
    remote_host_hdr: []const u8,
    remote_addr: sockaddr_in,
    is_tls: bool,
    socks_addr: ?[]const u8,
    forward_rule: ?[]const u8,
    num_workers: usize,
    max_chunk_size: usize,
    name: []const u8,
    token: []const u8,
    ring: RingBuffer,
    workers_sem: Semaphore = .{},
    local_streams: std.AutoHashMap(u32, protocol.SocketStream),
    streams_mutex: Mutex = .{},
    connect_waiters: std.AutoHashMap(u32, *ConnectWaiter),
    waiters_mutex: Mutex = .{},
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    last_ping_ts: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    tunnel_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active_sse_fd: std.atomic.Value(i32) = std.atomic.Value(i32).init(-1),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        remote_url: []const u8,
        socks_addr: ?[]const u8,
        forward_rule: ?[]const u8,
        num_workers: usize,
        max_body_mb: usize,
        buf_mb: usize,
        name: []const u8,
        token: []const u8,
    ) Client {
        const ring = RingBuffer.init(allocator, buf_mb * 1024 * 1024) catch unreachable;

        var host_part: []const u8 = remote_url;
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
            std.debug.print("\x1b[36m[DNS]\x1b[0m Resolving {s}...\n", .{host_part});
            if (!resolveDnsA(host_part, &octets)) {
                std.debug.print("\x1b[31m[DNS ERROR]\x1b[0m Unable to resolve {s}, defaulting to 127.0.0.1\n", .{host_part});
            } else {
                std.debug.print("\x1b[32m[DNS]\x1b[0m Resolved {s} -> {d}.{d}.{d}.{d}\n", .{ host_part, octets[0], octets[1], octets[2], octets[3] });
            }
        }

        const remote_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        std.debug.print("\x1b[35m[CONFIG]\x1b[0m Remote target: {d}.{d}.{d}.{d}:{d} (Host: '{s}', TLS: {})\n", .{
            octets[0], octets[1], octets[2], octets[3], port, host_header, is_tls,
        });

        return .{
            .allocator = allocator,
            .io = io,
            .remote_url = remote_url,
            .remote_host_hdr = host_header,
            .remote_addr = remote_addr,
            .is_tls = is_tls,
            .socks_addr = socks_addr,
            .forward_rule = forward_rule,
            .num_workers = num_workers,
            .max_chunk_size = max_body_mb * 1024 * 1024,
            .name = name,
            .token = token,
            .ring = ring,
            .local_streams = std.AutoHashMap(u32, protocol.SocketStream).init(allocator),
            .connect_waiters = std.AutoHashMap(u32, *ConnectWaiter).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.ring.deinit(self.allocator);
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

    pub fn emitLog(self: *Client, lvl: []const u8, evt: []const u8, sid: u32, target: []const u8, msg: []const u8) void {
        var log_buf: [1024]u8 = undefined;
        const now = getTimeMs();
        const json = std.fmt.bufPrint(&log_buf, "{{\"ts\":{d},\"src\":\"client\",\"name\":\"{s}\",\"lvl\":\"{s}\",\"evt\":\"{s}\",\"sid\":{d},\"target\":\"{s}\",\"msg\":\"{s}\"}}", .{
            now, self.name, lvl, evt, sid, target, msg,
        }) catch return;

        std.debug.print("\x1b[36m[{s}]\x1b[0m ({d}) {s}: {s}\n", .{ evt, sid, target, msg });
        self.sendToUpstream(0, 0, .log, json);
    }

    fn connectRemote(self: *Client) !*RemoteConnection {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const fd: i32 = @intCast(rc);
        errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 6, 1, @intFromPtr(&one), @sizeOf(c_int));

        const rcv_timeout = extern struct { sec: i64 = 10, usec: i64 = 0 }{};
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 20, @intFromPtr(&rcv_timeout), @sizeOf(@TypeOf(rcv_timeout)));

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&self.remote_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) return error.ConnectFailed;

        return RemoteConnection.init(fd, self.is_tls, self.remote_host_hdr, self.io, self.allocator);
    }

    // Каждый фрейм отправляется с указанием stream_id и seq_id
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

        var retry: usize = 0;
        while (!self.ring.push(full_frame[0..n])) {
            sleepMs(2);
            retry += 1;
            if (retry > 1000) {
                std.debug.print("\x1b[31m[BUFFER OVERFLOW]\x1b[0m Upstream ring buffer full, dropped frame stream={d} cmd={s}\n", .{ stream_id, @tagName(cmd) });
                return;
            }
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
            const stream = entry.value;
            stream.shutdown();
            stream.close();
            self.sendToUpstream(stream_id, 0, .close, "");
        }
    }

    pub fn start(self: *Client) !void {
        const sse_thread = try std.Thread.spawn(.{}, downstreamSseWorker, .{self});
        sse_thread.detach();

        const watchdog_thread = try std.Thread.spawn(.{}, downstreamWatchdogWorker, .{self});
        watchdog_thread.detach();

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

    fn downstreamWatchdogWorker(self: *Client) void {
        while (true) {
            sleepMs(1000);
            if (!self.tunnel_ready.load(.acquire)) continue;

            const now = getTimeMs();
            const last = self.last_ping_ts.load(.acquire);
            if (last > 0 and (now - last) > 6000) {
                const diff = now - last;
                std.debug.print("\x1b[33m[WATCHDOG WARN]\x1b[0m Downstream stalled! No heartbeat for {d}ms (>6000ms). Forcing reconnect...\x1b[0m\n", .{diff});

                const active_fd = self.active_sse_fd.load(.acquire);
                if (active_fd >= 0) {
                    _ = std.os.linux.syscall2(.shutdown, @as(usize, @bitCast(@as(isize, active_fd))), 2);
                }
                self.tunnel_ready.store(false, .release);
            }
        }
    }

    fn upstreamWorkerThread(self: *Client, worker_id: usize) void {
        const chunk_buf = self.allocator.alloc(u8, self.max_chunk_size) catch return;
        defer self.allocator.free(chunk_buf);

        while (true) {
            self.workers_sem.wait();

            const bytes_read = self.ring.drainAtMost(chunk_buf);
            if (bytes_read == 0) continue;

            const payload = chunk_buf[0..bytes_read];

            var conn = self.connectRemote() catch |err| {
                std.debug.print("\x1b[31m[PUSH ERROR]\x1b[0m Worker #{d} failed to connect upstream: {s}\n", .{ worker_id, @errorName(err) });
                sleepMs(100);
                continue;
            };
            defer conn.close();

            var req_hdr: [256]u8 = undefined;
            const hdr_text = std.fmt.bufPrint(&req_hdr,
                "POST /push HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: close\r\n\r\n",
                .{ self.remote_host_hdr, payload.len }
            ) catch continue;

            conn.writeAll(hdr_text) catch continue;
            conn.writeAll(payload) catch continue;

            var resp_buf: [512]u8 = undefined;
            const n = conn.read(&resp_buf) catch 0;
            if (n > 0) {
                const resp = resp_buf[0..n];
                if (std.mem.startsWith(u8, resp, "HTTP/1.1 4") or std.mem.startsWith(u8, resp, "HTTP/1.1 5")) {
                    const first_line = resp[0 .. std.mem.indexOf(u8, resp, "\r\n") orelse resp.len];
                    std.debug.print("\x1b[31m[PUSH ERROR]\x1b[0m Upstream rejected: {s}\n", .{first_line});
                }
            }

            if (self.ring.count > 0) {
                self.workers_sem.post();
            }
        }
    }

    fn downstreamSseWorker(self: *Client) void {
        var header_buf: [8192]u8 = undefined;

        while (true) {
            std.debug.print("\x1b[36m[SSE]\x1b[0m Connecting to downstream stream ({s})...\n", .{self.remote_host_hdr});
            var conn = self.connectRemote() catch |err| {
                std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Connect failed ({s}). Retrying in 1s...\n", .{@errorName(err)});
                sleepMs(1000);
                continue;
            };
            self.active_sse_fd.store(conn.fd, .release);

            const teardown = struct {
                fn run(c: *Client, rc: *RemoteConnection) void {
                    c.active_sse_fd.store(-1, .release);
                    c.tunnel_ready.store(false, .release);
                    rc.close();
                }
            };
            defer teardown.run(self, conn);

            var req_hdr: [512]u8 = undefined;
            const hdr_text = std.fmt.bufPrint(&req_hdr,
                "GET /stream HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Accept: text/event-stream\r\n" ++
                "Cache-Control: no-cache\r\n" ++
                "X-Client-Name: {s}\r\n" ++
                "Connection: keep-alive\r\n\r\n",
                .{ self.remote_host_hdr, self.name }
            ) catch return;

            conn.writeAll(hdr_text) catch |err| {
                std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Failed sending GET /stream ({s}). Retrying...\n", .{@errorName(err)});
                sleepMs(1000);
                continue;
            };

            const hdrs = conn.readHeaders(&header_buf) catch |err| {
                std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Failed reading response headers ({s}). Retrying in 1s...\n", .{@errorName(err)});
                sleepMs(1000);
                continue;
            };

            const first_line = hdrs[0 .. std.mem.indexOf(u8, hdrs, "\r\n") orelse hdrs.len];
            if (!std.mem.containsAtLeast(u8, first_line, 1, " 200 ")) {
                std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Remote server rejected stream! Status: '{s}'\n", .{first_line});
                sleepMs(2000);
                continue;
            }

            std.debug.print("\x1b[32m[SSE OK]\x1b[0m Downstream tunnel established (HTTP 200). Listening for frames...\n", .{});
            self.tunnel_ready.store(true, .release);
            self.last_ping_ts.store(getTimeMs(), .release);

            var chunk_hdr_buf: [32]u8 = undefined;
            var frame_scratch: [65536]u8 = undefined;

            while (true) {
                const hex_line_len = conn.readLine(&chunk_hdr_buf) catch |err| {
                    std.debug.print("\x1b[33m[SSE WARN]\x1b[0m Read line interrupted or timed out: {s}\n", .{@errorName(err)});
                    break;
                };
                if (hex_line_len == 0) continue;

                const trimmed_hex = std.mem.trim(u8, chunk_hdr_buf[0..hex_line_len], " \t\r");
                const chunk_size = std.fmt.parseInt(usize, trimmed_hex, 16) catch |err| {
                    std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Invalid chunk size hex '{s}': {s}\n", .{ trimmed_hex, @errorName(err) });
                    break;
                };
                if (chunk_size == 0) {
                    std.debug.print("\x1b[33m[SSE]\x1b[0m Remote sent clean EOF chunk (0)\n", .{});
                    break;
                }

                var target_buf: []u8 = frame_scratch[0..chunk_size];
                var dyn_alloc: ?[]u8 = null;
                defer if (dyn_alloc) |b| self.allocator.free(b);

                if (chunk_size > frame_scratch.len) {
                    dyn_alloc = self.allocator.alloc(u8, chunk_size) catch |err| {
                        std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m OOM allocating {d} bytes: {s}\n", .{ chunk_size, @errorName(err) });
                        break;
                    };
                    target_buf = dyn_alloc.?;
                }

                conn.readExact(target_buf) catch |err| {
                    std.debug.print("\x1b[31m[SSE ERROR]\x1b[0m Incomplete chunk body read: {s}\n", .{@errorName(err)});
                    break;
                };

                var crlf: [2]u8 = undefined;
                conn.readExact(&crlf) catch break;

                self.dispatchFrames(target_buf);
            }

            self.tunnel_ready.store(false, .release);
            std.debug.print("\x1b[33m[SSE]\x1b[0m Downstream connection lost. Reconnecting in 500ms...\n", .{});
            sleepMs(500);
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
                .ping => {
                    const now = getTimeMs();
                    self.last_ping_ts.store(now, .release);
                    if (payload.len >= 8) {
                        const srv_ts = std.mem.readInt(i64, payload[0..8], .little);
                        if (srv_ts > 0) {
                            const rtt = now - srv_ts;
                            std.debug.print("\x1b[32m[HEALTH]\x1b[0m Heartbeat received | Server RTT: {d}ms\n", .{rtt});
                        }
                    }
                },
                .log => {
                    std.debug.print("\x1b[36m[SERVER-LOG]\x1b[0m {s}\n", .{payload});
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

        std.debug.print("\x1b[32m[SOCKS]\x1b[0m SOCKS5 proxy listening on {s}:{d}\n", .{ host, port });

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const thread = std.Thread.spawn(.{}, handleSocksConnection, .{ self, stream }) catch {
                stream.close();
                continue;
            };
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

        const target_port = std.mem.readInt(u16, &port_buf, .big);
        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        if (atyp == 1) {
            std.debug.print("\x1b[36m[SOCKS]\x1b[0m Stream #{d} -> {d}.{d}.{d}.{d}:{d}\n", .{ stream_id, addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3], target_port });
        } else if (atyp == 3) {
            std.debug.print("\x1b[36m[SOCKS]\x1b[0m Stream #{d} -> {s}:{d}\n", .{ stream_id, addr_buf[0..addr_len], target_port });
        }

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

        // Счётчик порядковых номеров пакетов внутри этого стрима
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
            std.debug.print("\x1b[31m[SOCKS ERROR]\x1b[0m Stream #{d} connect timed out or rejected\n", .{stream_id});
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            sleepMs(50);
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
            seq += 1;
        }
    }

    fn forwardListener(self: *Client, fwd_rule: []const u8) void {
        var it = std.mem.splitScalar(u8, fwd_rule, ':');
        const l_port_str = it.next() orelse return;
        const r_host = it.next() orelse return;
        const r_port_str = it.next() orelse return;

        const l_port = std.fmt.parseInt(u16, l_port_str, 10) catch return;
        const r_port = std.fmt.parseInt(u16, r_port_str, 10) catch return;

        const listen_fd = listenOn("127.0.0.1", l_port) catch {
            std.debug.print("\x1b[31m[FWD ERROR]\x1b[0m Cannot bind to 127.0.0.1:{d}\n", .{l_port});
            return;
        };
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        std.debug.print("\x1b[32m[FWD]\x1b[0m Forwarding 127.0.0.1:{d} -> {s}:{d}\n", .{ l_port, r_host, r_port });

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
            std.debug.print("\x1b[31m[FWD ERROR]\x1b[0m Stream #{d} connect to {s}:{d} rejected or timed out\n", .{ stream_id, r_host, r_port });
            _ = stream.writeAll(&[_]u8{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
            sleepMs(50);
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
            seq += 1;
        }
    }
};
