const std = @import("std");

pub const Cmd = enum(u8) {
    connect = 1,
    connect_ok = 2,
    data = 3,
    close = 4,
    ping = 5,
    pong = 6,
    _,
};

pub fn writeFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: u32, cmd: Cmd, payload: []const u8) !void {
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], stream_id, .little);
    hdr[4] = @intFromEnum(cmd);
    hdr[5] = 0;
    std.mem.writeInt(u16, hdr[6..8], @intCast(payload.len), .little);
    try list.appendSlice(allocator, &hdr);
    if (payload.len > 0) {
        try list.appendSlice(allocator, payload);
    }
}
