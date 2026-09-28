const std = @import("std");

pub const Cmd = enum(u8) {
    connect = 1,
    connect_ok = 2,
    data = 3,
    close = 4,
    _,
};

pub const Header = extern struct {
    magic: u16 = 0xCF01,
    payload_len: u16,
    stream_id: u32,
    seq_id: u32,
    cmd: Cmd,
    reserved: u8 = 0,
    pad: u16 = 0,
};

pub fn setNoDelay(fd: i32) void {
    const one: c_int = 1;
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 6, 1, @intFromPtr(&one), @sizeOf(c_int));
}

pub const SocketStream = struct {
    handle: i32,

    pub fn read(self: SocketStream, buffer: []u8) !usize {
        const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.handle))), @intFromPtr(buffer.ptr), buffer.len);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.ReadFailed;
        return @intCast(signed);
    }

    pub fn writeAll(self: SocketStream, bytes: []const u8) !void {
        var index: usize = 0;
        while (index < bytes.len) {
            const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.handle))), @intFromPtr(bytes.ptr + index), bytes.len - index);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) return error.WriteFailed;
            index += @intCast(signed);
        }
    }

    pub fn close(self: SocketStream) void {
        _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.handle))));
    }

    pub fn shutdown(self: SocketStream) void {
        _ = std.os.linux.syscall2(.shutdown, @as(usize, @bitCast(@as(isize, self.handle))), 2);
    }
};

pub fn readExactStream(stream: SocketStream, dest: []u8) bool {
    var total: usize = 0;
    while (total < dest.len) {
        const n = stream.read(dest[total..]) catch return false;
        if (n == 0) return false;
        total += n;
    }
    return true;
}

pub fn parseIp4(s: []const u8, out: *[4]u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |p| {
        if (i >= 4) return false;
        out[i] = std.fmt.parseInt(u8, p, 10) catch return false;
        i += 1;
    }
    return i == 4;
}

pub fn getDnsServerIp() [4]u8 {
    const default_dns: [4]u8 = .{ 1, 1, 1, 1 };
    const fd_rc = std.os.linux.syscall2(.open, @intFromPtr("/etc/resolv.conf"), 0);
    if (@as(isize, @bitCast(fd_rc)) < 0) return default_dns;
    const fd: i32 = @intCast(fd_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

    var buf: [1024]u8 = undefined;
    const rd = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&buf), buf.len);
    const signed: isize = @bitCast(rd);
    if (signed <= 0) return default_dns;

    var it = std.mem.splitScalar(u8, buf[0..@intCast(signed)], '\n');
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

pub fn resolveDnsA(domain: []const u8, out_ip: *[4]u8) bool {
    if (parseIp4(domain, out_ip)) return true;

    const sock_rc = std.os.linux.syscall3(.socket, 2, 2, 0); // AF_INET, SOCK_DGRAM
    if (@as(isize, @bitCast(sock_rc)) < 0) return false;
    const sock: i32 = @intCast(sock_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));

    const timeout = extern struct { sec: i64 = 2, usec: i64 = 0 }{};
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, sock))), 1, 20, @intFromPtr(&timeout), @sizeOf(@TypeOf(timeout)));

    const dns_ip = getDnsServerIp();
    const sockaddr_in = extern struct {
        family: u16 = 2,
        port: u16,
        addr: u32,
        zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const dns_server = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @as(u32, @bitCast(dns_ip)),
    };

    const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&dns_server), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(conn_rc)) < 0) return false;

    var query_buf: [512]u8 = undefined;
    query_buf[0] = 0x12; query_buf[1] = 0x34;
    query_buf[2] = 0x01; query_buf[3] = 0x00;
    query_buf[4] = 0x00; query_buf[5] = 0x01;
    query_buf[6] = 0x00; query_buf[7] = 0x00;
    query_buf[8] = 0x00; query_buf[9] = 0x00;
    query_buf[10] = 0x00; query_buf[11] = 0x00;

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
    query_buf[q_idx] = 0; q_idx += 1;
    query_buf[q_idx] = 0x00; query_buf[q_idx + 1] = 0x01;
    query_buf[q_idx + 2] = 0x00; query_buf[q_idx + 3] = 0x01;
    q_idx += 4;

    const write_rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&query_buf), q_idx);
    if (@as(isize, @bitCast(write_rc)) <= 0) return false;

    var resp_buf: [512]u8 = undefined;
    const read_rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&resp_buf), resp_buf.len);
    const read_len: isize = @bitCast(read_rc);
    if (read_len < 12) return false;

    const r_len: usize = @intCast(read_len);
    if (resp_buf[0] != 0x12 or resp_buf[1] != 0x34) return false;
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
