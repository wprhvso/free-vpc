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

pub const FrameHeader = struct {
    length: u24,
    frame_type: u8,
    flags: u8,
    stream_id: u31,

    pub fn serialize(self: FrameHeader, out: *[9]u8) void {
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

    pub fn deserialize(buf: *const [9]u8) FrameHeader {
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

/// Генерация статического HPACK блока для вызова gRPC (RFC 7541) без сторонних библиотек
pub fn encodeClientGrpcHeaders(dest: []u8, host: []const u8, path: []const u8) usize {
    var idx: usize = 0;
    // :method: POST (Indexed index 3)
    dest[idx] = 0x83; idx += 1;
    // :scheme: https (Indexed index 7)
    dest[idx] = 0x87; idx += 1;
    // :path (Literal without indexing, new name)
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 5; idx += 1;
    @memcpy(dest[idx .. idx + 5], ":path"); idx += 5;
    dest[idx] = @intCast(path.len); idx += 1;
    @memcpy(dest[idx .. idx + path.len], path); idx += path.len;
    // :authority
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 10; idx += 1;
    @memcpy(dest[idx .. idx + 10], ":authority"); idx += 10;
    dest[idx] = @intCast(host.len); idx += 1;
    @memcpy(dest[idx .. idx + host.len], host); idx += host.len;
    // content-type: application/grpc
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 12; idx += 1;
    @memcpy(dest[idx .. idx + 12], "content-type"); idx += 12;
    dest[idx] = 16; idx += 1;
    @memcpy(dest[idx .. idx + 16], "application/grpc"); idx += 16;
    // te: trailers
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 2; idx += 1;
    @memcpy(dest[idx .. idx + 2], "te"); idx += 2;
    dest[idx] = 8; idx += 1;
    @memcpy(dest[idx .. idx + 8], "trailers"); idx += 8;
    return idx;
}

/// Генерация ответа сервера gRPC 200 OK
pub fn encodeServerGrpcHeaders(dest: []u8) usize {
    var idx: usize = 0;
    // :status: 200 (Indexed index 8)
    dest[idx] = 0x88; idx += 1;
    // content-type: application/grpc
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 12; idx += 1;
    @memcpy(dest[idx .. idx + 12], "content-type"); idx += 12;
    dest[idx] = 16; idx += 1;
    @memcpy(dest[idx .. idx + 16], "application/grpc"); idx += 16;
    return idx;
}

// --- Внутренний протокол туннелирования (12 байт заголовок) ---
pub const TunnelCmd = enum(u8) {
    connect = 1,
    connect_ok = 2,
    connect_fail = 3,
    data = 4,
    close = 5,
    _,
};

pub const TunnelHeader = extern struct {
    magic: u16 = 0x5650, // "VP"
    cmd: TunnelCmd,
    reserved: u8 = 0,
    stream_id: u32,
    payload_len: u32,
};

pub fn writeH2Frame(writer: anytype, header: FrameHeader, payload: []const u8) !void {
    var hdr_buf: [9]u8 = undefined;
    header.serialize(&hdr_buf);
    try writer.writeAll(&hdr_buf);
    if (payload.len > 0) {
        try writer.writeAll(payload);
    }
}
