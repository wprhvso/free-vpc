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
