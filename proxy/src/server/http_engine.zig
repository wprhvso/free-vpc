const std = @import("std");
const protocol = @import("../common/protocol.zig");
const logger = @import("../common/logger.zig");
const Session = @import("session.zig").Session;
const session_mod = @import("session.zig");
const target_conn = @import("target_conn.zig");

pub fn handleConnection(allocator: std.mem.Allocator, stream: protocol.SocketStream) void {
    defer stream.close();

    while (true) {
        var hdr_buf: [4096]u8 = undefined;
        var hdr_len: usize = 0;

        while (hdr_len < hdr_buf.len) {
            const n = stream.read(hdr_buf[hdr_len .. hdr_len + 1]) catch return;
            if (n == 0) return;
            hdr_len += 1;
            if (hdr_len >= 4 and std.mem.eql(u8, hdr_buf[hdr_len - 4 .. hdr_len], "\r\n\r\n")) {
                break;
            }
        }

        const headers = hdr_buf[0..hdr_len];
        if (std.mem.startsWith(u8, headers, "GET /api/v2/events")) {
            var sid: [32]u8 = undefined;
            @memset(&sid, '0');
            if (std.mem.indexOf(u8, headers, "?s=")) |pos| {
                const start = pos + 3;
                if (start + 32 <= headers.len) {
                    @memcpy(&sid, headers[start .. start + 32]);
                }
            }

            if (session_mod.global_session == null) {
                session_mod.global_session = Session.init(allocator, &sid) catch return;
            }
            const sess = session_mod.global_session.?;

            const DOWNSTREAM_HDR =
                "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: application/octet-stream\r\n" ++
                "Cache-Control: no-cache, no-store, no-transform\r\n" ++
                "X-Accel-Buffering: no\r\n" ++
                "Connection: keep-alive\r\n" ++
                "Transfer-Encoding: chunked\r\n\r\n";

            stream.writeAll(DOWNSTREAM_HDR) catch return;
            sess.attachDownstream(stream);

            while (true) {
                @import("../common/sync.zig").sleepMs(15000);
                sess.sendDownstreamFrame(.ping, 0, "") catch break;
            }
            return;
        } else if (std.mem.startsWith(u8, headers, "POST /api/v2/telemetry")) {
            var cl: usize = 0;
            var lines = std.mem.splitSequence(u8, headers, "\r\n");
            while (lines.next()) |line| {
                if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                    const val = std.mem.trim(u8, line["content-length:".len..], " ");
                    cl = std.fmt.parseInt(usize, val, 10) catch 0;
                }
            }

            if (cl < 16) {
                logger.json(.warn, "engine", "post_body_too_short", null, null, "{{\"cl\":{d}}}", .{cl});
                return;
            }

            const body = allocator.alloc(u8, cl) catch return;
            defer allocator.free(body);

            var total: usize = 0;
            while (total < cl) {
                const n = stream.read(body[total..]) catch return;
                if (n == 0) return;
                total += n;
            }

            stream.writeAll("HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n") catch return;

            if (session_mod.global_session) |sess| {
                var raw_hdr: [16]u8 = undefined;
                @memcpy(&raw_hdr, body[0..16]);
                const fh = protocol.FrameHeader.deserialize(&raw_hdr);
                const payload = body[16..];

                logger.json(.debug, "engine", "rx_tunnel_cmd", fh.stream_id, fh.seq, "{{\"cmd\":\"{s}\",\"len\":{d}}}", .{ @tagName(fh.cmd), fh.payload_len });

                switch (fh.cmd) {
                    .connect => target_conn.handleConnect(sess, fh.stream_id, payload),
                    .data => {
                        sess.streams_mutex.lock();
                        const s_opt = sess.streams.get(fh.stream_id);
                        if (s_opt) |entry| {
                            if (entry.active.load(.acquire)) {
                                entry.reassembler.push(fh.seq, payload) catch {};
                            }
                        } else {
                            logger.json(.warn, "engine", "data_orphan_stream", fh.stream_id, fh.seq, "{{}}", .{});
                        }
                        sess.streams_mutex.unlock();
                    },
                    .rst, .fin => {
                        sess.streams_mutex.lock();
                        const removed = sess.streams.fetchRemove(fh.stream_id);
                        sess.streams_mutex.unlock();
                        if (removed) |kv| {
                            kv.value.active.store(false, .release);
                            kv.value.target_stream.close();
                        }
                    },
                    else => {},
                }
            } else {
                logger.json(.err, "engine", "post_no_session", null, null, "{{}}", .{});
            }
        } else {
            stream.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
            return;
        }
    }
}
