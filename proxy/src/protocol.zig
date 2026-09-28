const std = @import("std");

pub const Cmd = enum(u8) {
    connect = 1,
    connect_ok = 2,
    data = 3,
    close = 4,
    ping = 5,
    pong = 6,
    log = 7,
    _,
};

pub const Header = extern struct {
    stream_id: u32,
    seq_id: u32,
    cmd: Cmd,
    reserved: u8 = 0,
    payload_len: u16,
};

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

pub fn writeFrame(dest: []u8, stream_id: u32, seq_id: u32, cmd: Cmd, payload: []const u8) !usize {
    const total = @sizeOf(Header) + payload.len;
    if (dest.len < total) return error.BufferTooSmall;
    if (payload.len > std.math.maxInt(u16)) return error.PayloadTooLarge;

    const hdr: *Header = @ptrCast(@alignCast(dest.ptr));
    hdr.* = .{
        .stream_id = stream_id,
        .seq_id = seq_id,
        .cmd = cmd,
        .reserved = 0,
        .payload_len = @intCast(payload.len),
    };

    if (payload.len > 0) {
        @memcpy(dest[@sizeOf(Header)..total], payload);
    }

    return total;
}
