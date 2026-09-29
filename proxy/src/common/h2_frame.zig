const std = @import("std");

pub const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FrameType = struct {
    pub const DATA: u8 = 0x00;
    pub const HEADERS: u8 = 0x01;
    pub const RST_STREAM: u8 = 0x03;
    pub const SETTINGS: u8 = 0x04;
    pub const PING: u8 = 0x06;
    pub const GOAWAY: u8 = 0x07;
    pub const WINDOW_UPDATE: u8 = 0x08;
};

pub const Flags = struct {
    pub const NONE: u8 = 0x00;
    pub const ACK: u8 = 0x01;
    pub const END_STREAM: u8 = 0x01;
    pub const END_HEADERS: u8 = 0x04;
};

pub const H2Header = struct {
    length: u24,
    frame_type: u8,
    flags: u8,
    stream_id: u31,

    pub fn serialize(self: H2Header, out: *[9]u8) void {
        out[0] = @intCast((self.length >> 16) & 0xFF);
        out[1] = @intCast((self.length >> 8) & 0xFF);
        out[2] = @intCast(self.length & 0xFF);
        out[3] = self.frame_type;
        out[4] = self.flags;
        out[5] = @intCast((self.stream_id >> 24) & 0x7F);
        out[6] = @intCast((self.stream_id >> 16) & 0xFF);
        out[7] = @intCast((self.stream_id >> 8) & 0xFF);
        out[8] = @intCast(self.stream_id & 0xFF);
    }

    pub fn deserialize(buf: *const [9]u8) H2Header {
        const len = (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2];
        const sid = (@as(u31, buf[5] & 0x7F) << 24) | (@as(u31, buf[6]) << 16) | (@as(u31, buf[7]) << 8) | buf[8];
        return .{
            .length = len,
            .frame_type = buf[3],
            .flags = buf[4],
            .stream_id = sid,
        };
    }
};

// Точные Chrome HTTP/2 фреймы
pub const CHROME_SETTINGS = [_]u8{
    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65536
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
    0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 6291456
    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 262144
};

pub const CHROME_WINDOW_UPDATE = [_]u8{
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xee, 0xef, 0x01,             // Increment: 15663105 bytes
};
