const std = @import("std");

/// Генерация статического HEADERS для GET /api/v2/events?s=SESSION
pub fn encodeDownstreamGet(dest: []u8, host: []const u8, path: []const u8) usize {
    var idx: usize = 0;
    // :method: GET (Index 2)
    dest[idx] = 0x82; idx += 1;
    // :scheme: https (Index 7)
    dest[idx] = 0x87; idx += 1;
    // :path (Literal without indexing, name index 4)
    dest[idx] = 0x04; idx += 1;
    dest[idx] = @intCast(path.len); idx += 1;
    @memcpy(dest[idx .. idx + path.len], path); idx += path.len;
    // :authority (Literal without indexing, name index 1)
    dest[idx] = 0x01; idx += 1;
    dest[idx] = @intCast(host.len); idx += 1;
    @memcpy(dest[idx .. idx + host.len], host); idx += host.len;
    // accept: application/octet-stream
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 6; idx += 1;
    @memcpy(dest[idx .. idx + 6], "accept"); idx += 6;
    dest[idx] = 24; idx += 1;
    @memcpy(dest[idx .. idx + 24], "application/octet-stream"); idx += 24;
    return idx;
}

/// Генерация статического HEADERS для POST /api/v2/telemetry
pub fn encodeUpstreamPost(dest: []u8, host: []const u8, session_id: []const u8, content_len: usize) usize {
    var idx: usize = 0;
    // :method: POST (Index 3)
    dest[idx] = 0x83; idx += 1;
    // :scheme: https (Index 7)
    dest[idx] = 0x87; idx += 1;
    // :path: /api/v2/telemetry
    const path = "/api/v2/telemetry";
    dest[idx] = 0x04; idx += 1;
    dest[idx] = @intCast(path.len); idx += 1;
    @memcpy(dest[idx .. idx + path.len], path); idx += path.len;
    // :authority
    dest[idx] = 0x01; idx += 1;
    dest[idx] = @intCast(host.len); idx += 1;
    @memcpy(dest[idx .. idx + host.len], host); idx += host.len;
    // content-type: application/octet-stream
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 12; idx += 1;
    @memcpy(dest[idx .. idx + 12], "content-type"); idx += 12;
    dest[idx] = 24; idx += 1;
    @memcpy(dest[idx .. idx + 24], "application/octet-stream"); idx += 24;
    // x-session-id
    dest[idx] = 0x00; idx += 1;
    dest[idx] = 12; idx += 1;
    @memcpy(dest[idx .. idx + 12], "x-session-id"); idx += 12;
    dest[idx] = @intCast(session_id.len); idx += 1;
    @memcpy(dest[idx .. idx + session_id.len], session_id); idx += session_id.len;
    // content-length (Name Index 28 -> 0x0F, 0x0D)
    var len_buf: [16]u8 = undefined;
    const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{content_len}) catch "0";
    dest[idx] = 0x0f; idx += 1;
    dest[idx] = 0x0d; idx += 1;
    dest[idx] = @intCast(len_str.len); idx += 1;
    @memcpy(dest[idx .. idx + len_str.len], len_str); idx += len_str.len;
    return idx;
}

pub fn decodeStatus(data: []const u8) ?u16 {
    var i: usize = 0;
    while (i < data.len) {
        const b = data[i];
        if ((b & 0x80) != 0) {
            const idx = b & 0x7F;
            i += 1;
            if (idx == 8) return 200;
            if (idx == 9) return 204;
        } else {
            i += 1;
            if (i >= data.len) return null;
            const vlen = data[i] & 0x7F;
            i += 1 + vlen;
        }
    }
    return null;
}
