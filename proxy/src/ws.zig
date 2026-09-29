const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

pub const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute Sec-WebSocket-Accept given a Sec-WebSocket-Key
pub fn computeAcceptKey(key: []const u8, out_buf: *[28]u8) void {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(WS_GUID);
    const digest = sha.finalResult();
    _ = std.base64.standard.Encoder.encode(out_buf, &digest);
}

/// Serialize a WebSocket frame.
/// If `mask_key` is provided (4 bytes), frame is masked (client -> server).
/// If `mask_key` is null, frame is unmasked (server -> client).
pub fn writeFrame(writer: anytype, opcode: Opcode, payload: []const u8, mask_key: ?[4]u8) !void {
    var hdr_buf: [14]u8 = undefined;
    var hdr_len: usize = 2;

    hdr_buf[0] = 0x80 | @as(u8, @intFromEnum(opcode)); // FIN = 1

    const mask_bit: u8 = if (mask_key != null) 0x80 else 0x00;

    if (payload.len <= 125) {
        hdr_buf[1] = mask_bit | @as(u8, @intCast(payload.len));
    } else if (payload.len <= 65535) {
        hdr_buf[1] = mask_bit | 126;
        std.mem.writeInt(u16, hdr_buf[2..4], @intCast(payload.len), .big);
        hdr_len = 4;
    } else {
        hdr_buf[1] = mask_bit | 127;
        std.mem.writeInt(u64, hdr_buf[2..10], @intCast(payload.len), .big);
        hdr_len = 10;
    }

    if (mask_key) |m| {
        @memcpy(hdr_buf[hdr_len .. hdr_len + 4], &m);
        hdr_len += 4;
    }

    try writer.writeAll(hdr_buf[0..hdr_len]);

    if (payload.len > 0) {
        if (mask_key) |m| {
            var temp_buf: [4096]u8 = undefined;
            var offset: usize = 0;
            while (offset < payload.len) {
                const chunk_len = @min(temp_buf.len, payload.len - offset);
                for (0..chunk_len) |i| {
                    temp_buf[i] = payload[offset + i] ^ m[(offset + i) % 4];
                }
                try writer.writeAll(temp_buf[0..chunk_len]);
                offset += chunk_len;
            }
        } else {
            try writer.writeAll(payload);
        }
    }
}

/// Apply in-place XOR unmask
pub fn applyMask(data: []u8, mask: [4]u8) void {
    for (data, 0..) |*b, i| {
        b.* ^= mask[i % 4];
    }
}
