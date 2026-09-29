const std = @import("std");
const h2 = @import("../common/h2_frame.zig");
const logger = @import("../common/logger.zig");
const protocol = @import("../common/protocol.zig");
const H2Connection = @import("h2_conn.zig").H2Connection;
const stream_mgr = @import("stream_manager.zig");
const hpack = @import("../common/static_hpack.zig");

pub fn downstreamLoop(conn: *H2Connection, allocator: std.mem.Allocator) void {
    var hdr_buf: [9]u8 = undefined;
    var accum: [128 * 1024]u8 = undefined;
    var accum_len: usize = 0;

    while (true) {
        conn.readExact(&hdr_buf) catch |err| {
            logger.json(.err, "downstream", "h2_read_hdr_failed", null, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            break;
        };
        const frame = h2.H2Header.deserialize(&hdr_buf);

        var payload: []u8 = &[_]u8{};
        if (frame.length > 0) {
            payload = allocator.alloc(u8, frame.length) catch break;
            conn.readExact(payload) catch |err| {
                allocator.free(payload);
                logger.json(.err, "downstream", "h2_read_payload_failed", null, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                break;
            };
        }
        defer if (payload.len > 0) allocator.free(payload);

        switch (frame.frame_type) {
            h2.FrameType.HEADERS => {
                const status = hpack.decodeStatus(payload) orelse 0;
                logger.json(.info, "downstream", "h2_headers", null, null, "{{\"status\":{d},\"sid\":{d}}}", .{ status, frame.stream_id });
            },
            h2.FrameType.DATA => {
                if (frame.stream_id == 1 and payload.len > 0) {
                    if (accum_len + payload.len > accum.len) {
                        logger.json(.err, "downstream", "accum_overflow_reset", null, null, "{{}}", .{});
                        accum_len = 0;
                    }
                    @memcpy(accum[accum_len .. accum_len + payload.len], payload);
                    accum_len += payload.len;

                    var cursor: usize = 0;
                    while (cursor + 16 <= accum_len) {
                        var fh_bytes: [16]u8 = undefined;
                        @memcpy(&fh_bytes, accum[cursor .. cursor + 16]);
                        const fh = protocol.FrameHeader.deserialize(&fh_bytes);

                        if (fh.magic != 0x5455) {
                            cursor += 1;
                            continue;
                        }

                        const total_frame_len = 16 + @as(usize, fh.payload_len);
                        if (cursor + total_frame_len > accum_len) {
                            break; // ждем хвост фрейма
                        }

                        const data_payload = accum[cursor + 16 .. cursor + total_frame_len];
                        cursor += total_frame_len;

                        logger.json(.debug, "downstream", "tunnel_frame_rx", fh.stream_id, fh.seq, "{{\"cmd\":\"{s}\",\"len\":{d}}}", .{ @tagName(fh.cmd), fh.payload_len });

                        if (fh.cmd == .log) {
                            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(data_payload.ptr), data_payload.len);
                            _ = std.os.linux.syscall3(.write, 2, @intFromPtr("\n"), 1);
                        } else if (stream_mgr.global_manager) |mgr| {
                            if (mgr.get(fh.stream_id)) |s| {
                                switch (fh.cmd) {
                                    .connect_ok => {
                                        logger.json(.info, "downstream", "connect_ok", fh.stream_id, null, "{{}}", .{});
                                        s.connect_success = true;
                                        s.connected_event.set();
                                    },
                                    .connect_fail => {
                                        logger.json(.warn, "downstream", "connect_fail", fh.stream_id, null, "{{}}", .{});
                                        s.connect_success = false;
                                        s.connected_event.set();
                                    },
                                    .data => {
                                        s.client_stream.writeAll(data_payload) catch {};
                                    },
                                    .fin, .rst => {
                                        logger.json(.info, "downstream", "remote_close", fh.stream_id, null, "{{}}", .{});
                                        s.active.store(false, .release);
                                        s.client_stream.close();
                                    },
                                    else => {},
                                }
                            } else {
                                logger.json(.warn, "downstream", "stream_not_found", fh.stream_id, null, "{{\"cmd\":\"{s}\"}}", .{@tagName(fh.cmd)});
                            }
                        }
                    }

                    if (cursor > 0) {
                        const remaining = accum_len - cursor;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, accum[0..remaining], accum[cursor..accum_len]);
                        }
                        accum_len = remaining;
                    }
                }
            },
            h2.FrameType.PING => {
                if ((frame.flags & h2.Flags.ACK) == 0) {
                    conn.sendH2Frame(.{ .length = 8, .frame_type = h2.FrameType.PING, .flags = h2.Flags.ACK, .stream_id = 0 }, payload) catch {};
                }
            },
            h2.FrameType.SETTINGS => {
                if ((frame.flags & h2.Flags.ACK) == 0) {
                    conn.sendH2Frame(.{ .length = 0, .frame_type = h2.FrameType.SETTINGS, .flags = h2.Flags.ACK, .stream_id = 0 }, "") catch {};
                }
            },
            else => {},
        }
    }
}
