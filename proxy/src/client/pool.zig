const std = @import("std");
const H2Connection = @import("h2_conn.zig").H2Connection;
const h2 = @import("../common/h2_frame.zig");
const hpack = @import("../common/static_hpack.zig");
const downstream = @import("downstream.zig");
const logger = @import("../common/logger.zig");

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    session_id: [32]u8,
    sockets: [6]H2Connection = undefined,
    round_robin: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !*ConnectionPool {
        const pool = try allocator.create(ConnectionPool);
        pool.* = .{
            .allocator = allocator,
            .host = host,
            .port = port,
            .session_id = undefined,
        };
        @memset(&pool.session_id, 'a');

        for (0..6) |i| {
            pool.sockets[i] = H2Connection.init(i);
        }
        return pool;
    }

    pub fn start(self: *ConnectionPool) !void {
        // 1. Подключаем Conn #0 (Master Downstream)
        try self.sockets[0].connect(self.host, self.port);

        var hpack_buf: [512]u8 = undefined;
        var path_buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/api/v2/events?s={s}", .{self.session_id});
        const hlen = hpack.encodeDownstreamGet(&hpack_buf, self.host, path);

        try self.sockets[0].sendH2Frame(.{
            .length = @intCast(hlen),
            .frame_type = h2.FrameType.HEADERS,
            .flags = h2.Flags.END_HEADERS | h2.Flags.END_STREAM,
            .stream_id = 1,
        }, hpack_buf[0..hlen]);

        const th = try std.Thread.spawn(.{}, downstream.downstreamLoop, .{ &self.sockets[0], self.allocator });
        th.detach();

        // 2. Подключаем Conn #1..#5 (Upstream Workers)
        for (1..6) |i| {
            try self.sockets[i].connect(self.host, self.port);
            const w_th = try std.Thread.spawn(.{}, upstreamWorkerLoop, .{ &self.sockets[i], self.allocator });
            w_th.detach();
        }
        logger.json(.info, "pool", "all_6_sockets_ready", null, null, "{{}}", .{});
    }

    pub fn postBatch(self: *ConnectionPool, data: []const u8) !void {
        const idx = (self.round_robin.fetchAdd(1, .monotonic) % 5) + 1; // 1..5
        const conn = &self.sockets[idx];

        conn.write_mutex.lock();
        defer conn.write_mutex.unlock();

        const sid = conn.next_stream_id;
        conn.next_stream_id += 2;

        logger.json(.debug, "pool", "tx_post_start", null, null, "{{\"conn_idx\":{d},\"h2_sid\":{d},\"bytes\":{d}}}", .{ idx, sid, data.len });

        var hpack_buf: [512]u8 = undefined;
        const hlen = hpack.encodeUpstreamPost(&hpack_buf, self.host, &self.session_id, data.len);

        var h_buf: [9]u8 = undefined;
        const h_hdr = h2.H2Header{
            .length = @intCast(hlen),
            .frame_type = h2.FrameType.HEADERS,
            .flags = h2.Flags.END_HEADERS,
            .stream_id = sid,
        };
        h_hdr.serialize(&h_buf);

        const d_hdr = h2.H2Header{
            .length = @intCast(data.len),
            .frame_type = h2.FrameType.DATA,
            .flags = h2.Flags.END_STREAM,
            .stream_id = sid,
        };
        var d_buf: [9]u8 = undefined;
        d_hdr.serialize(&d_buf);

        if (conn.tls_inst) |*t| {
            t.writer.writeAll(&h_buf) catch |err| {
                logger.json(.err, "pool", "tx_post_hdr_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            t.writer.writeAll(hpack_buf[0..hlen]) catch |err| {
                logger.json(.err, "pool", "tx_post_hpack_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            t.writer.writeAll(&d_buf) catch |err| {
                logger.json(.err, "pool", "tx_post_dhdr_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            t.writer.writeAll(data) catch |err| {
                logger.json(.err, "pool", "tx_post_data_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            t.writer.flush() catch |err| {
                logger.json(.err, "pool", "tx_post_flush_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            conn.direct_writer.writer.flush() catch |err| {
                logger.json(.err, "pool", "tx_post_sock_flush_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                return err;
            };
            logger.json(.debug, "pool", "tx_post_ok", null, null, "{{\"conn_idx\":{d},\"h2_sid\":{d}}}", .{ idx, sid });
        } else {
            logger.json(.err, "pool", "tx_post_no_tls", null, null, "{{\"conn_idx\":{d}}}", .{idx});
            return error.NotConnected;
        }
    }
};

fn upstreamWorkerLoop(conn: *H2Connection, allocator: std.mem.Allocator) void {
    var hdr_buf: [9]u8 = undefined;
    while (true) {
        conn.readExact(&hdr_buf) catch |err| {
            logger.json(.warn, "pool", "worker_h2_read_err", null, null, "{{\"conn_idx\":{d},\"error\":\"{s}\"}}", .{ conn.idx, @errorName(err) });
            break;
        };
        const frame = h2.H2Header.deserialize(&hdr_buf);

        if (frame.length > 0) {
            const payload = allocator.alloc(u8, frame.length) catch break;
            defer allocator.free(payload);
            conn.readExact(payload) catch break;

            if (frame.frame_type == h2.FrameType.PING and (frame.flags & h2.Flags.ACK) == 0) {
                conn.sendH2Frame(.{ .length = 8, .frame_type = h2.FrameType.PING, .flags = h2.Flags.ACK, .stream_id = 0 }, payload) catch {};
            } else if (frame.frame_type == h2.FrameType.SETTINGS and (frame.flags & h2.Flags.ACK) == 0) {
                conn.sendH2Frame(.{ .length = 0, .frame_type = h2.FrameType.SETTINGS, .flags = h2.Flags.ACK, .stream_id = 0 }, "") catch {};
            }
        } else {
            if (frame.frame_type == h2.FrameType.SETTINGS and (frame.flags & h2.Flags.ACK) == 0) {
                conn.sendH2Frame(.{ .length = 0, .frame_type = h2.FrameType.SETTINGS, .flags = h2.Flags.ACK, .stream_id = 0 }, "") catch {};
            }
        }
    }
}

pub var global_pool: ?*ConnectionPool = null;
