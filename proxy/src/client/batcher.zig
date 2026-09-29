const std = @import("std");
const sync = @import("../common/sync.zig");
const protocol = @import("../common/protocol.zig");
const stream_mgr = @import("stream_manager.zig");
const pool = @import("pool.zig");

pub fn flushStream(ctx: *stream_mgr.StreamContext) !void {
    ctx.buf_mutex.lock();
    defer ctx.buf_mutex.unlock();

    if (ctx.accumulated_len == 0) return;

    var frame_buf: [4096 + 16]u8 = undefined;
    const seq = ctx.next_upstream_seq.fetchAdd(1, .monotonic);

    const fh = protocol.FrameHeader{
        .magic = 0x5455,
        .cmd = .data,
        .flags = 0,
        .stream_id = ctx.stream_id,
        .seq = seq,
        .payload_len = @intCast(ctx.accumulated_len),
    };
    fh.serialize(frame_buf[0..16]);
    @memcpy(frame_buf[16 .. 16 + ctx.accumulated_len], ctx.accumulated_buf[0..ctx.accumulated_len]);

    const total = 16 + ctx.accumulated_len;
    ctx.accumulated_len = 0;

    if (pool.global_pool) |p| {
        try p.postBatch(frame_buf[0..total]);
    }
}

pub fn tickerLoop() void {
    while (true) {
        sync.sleepMs(1);
        const now = sync.getMonotonicNs();

        if (stream_mgr.global_manager) |mgr| {
            mgr.mutex.lock();
            var it = mgr.streams.valueIterator();
            while (it.next()) |ctx_ptr| {
                const ctx = ctx_ptr.*;
                if (ctx.accumulated_len > 0 and (now - ctx.first_byte_time) >= 5_000_000) {
                    flushStream(ctx) catch {};
                }
            }
            mgr.mutex.unlock();
        }
    }
}
