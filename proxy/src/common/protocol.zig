const std = @import("std");

pub const Cmd = enum(u8) {
    connect      = 0x01,
    connect_ok   = 0x02,
    connect_fail = 0x03,
    data         = 0x04,
    fin          = 0x05,
    rst          = 0x06,
    ping         = 0x07,
    pong         = 0x08,
    log          = 0x09,
    _,
};

pub const FrameHeader = extern struct {
    magic: u16 = 0x5455, // "TU"
    cmd: Cmd,
    flags: u8 = 0,
    stream_id: u32,
    seq: u32,
    payload_len: u16,
    reserved: u16 = 0,

    pub fn serialize(self: FrameHeader, out: *[16]u8) void {
        std.mem.writeInt(u16, out[0..2], self.magic, .big);
        out[2] = @intFromEnum(self.cmd);
        out[3] = self.flags;
        std.mem.writeInt(u32, out[4..8], self.stream_id, .big);
        std.mem.writeInt(u32, out[8..12], self.seq, .big);
        std.mem.writeInt(u16, out[12..14], self.payload_len, .big);
        std.mem.writeInt(u16, out[14..16], self.reserved, .big);
    }

    pub fn deserialize(buf: *const [16]u8) FrameHeader {
        return .{
            .magic = std.mem.readInt(u16, buf[0..2], .big),
            .cmd = @enumFromInt(buf[2]),
            .flags = buf[3],
            .stream_id = std.mem.readInt(u32, buf[4..8], .big),
            .seq = std.mem.readInt(u32, buf[8..12], .big),
            .payload_len = std.mem.readInt(u16, buf[12..14], .big),
            .reserved = std.mem.readInt(u16, buf[14..16], .big),
        };
    }
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
        if (self.handle >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.handle))));
        }
    }

    pub fn shutdown(self: SocketStream) void {
        if (self.handle >= 0) {
            _ = std.os.linux.syscall2(.shutdown, @as(usize, @bitCast(@as(isize, self.handle))), 2);
        }
    }
};
