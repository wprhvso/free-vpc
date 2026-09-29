const std = @import("std");
const net = @import("../common/net.zig");
const sync = @import("../common/sync.zig");
const protocol = @import("../common/protocol.zig");
const logger = @import("../common/logger.zig");
const stream_mgr = @import("stream_manager.zig");
const pool = @import("pool.zig");

pub fn startListener(allocator: std.mem.Allocator, host: []const u8, port: u16) !void {
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
    const listen_fd: i32 = @intCast(rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

    net.setReuseAddr(listen_fd);
    net.setNoDelay(listen_fd);

    var octets: [4]u8 = undefined;
    _ = net.parseIp4(host, &octets);

    const addr = net.sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };

    _ = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(net.sockaddr_in));
    _ = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);

    logger.json(.info, "socks5", "listening", null, null, "{{\"host\":\"{s}\",\"port\":{d}}}", .{ host, port });

    while (true) {
        var client_addr: net.sockaddr = undefined;
        var client_len: u32 = @sizeOf(net.sockaddr);
        const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
        if (@as(isize, @bitCast(accept_rc)) < 0) continue;
        const client_fd: i32 = @intCast(accept_rc);

        net.setNoDelay(client_fd);
        const stream = protocol.SocketStream{ .handle = client_fd };

        const th = std.Thread.spawn(.{}, handleSocksClient, .{ allocator, stream }) catch {
            stream.close();
            continue;
        };
        th.detach();
    }
}

fn handleSocksClient(allocator: std.mem.Allocator, stream: protocol.SocketStream) void {
    defer stream.close();

    var buf: [512]u8 = undefined;
    var rd = stream.read(&buf) catch return;
    if (rd < 3 or buf[0] != 5) return;
    stream.writeAll("\x05\x00") catch return; // No auth

    rd = stream.read(&buf) catch return;
    if (rd < 7 or buf[0] != 5 or buf[1] != 1) return; // Only CONNECT

    const ctx = stream_mgr.global_manager.?.createStream(allocator, stream) catch return;
    defer {
        logger.json(.debug, "socks5", "client_cleanup", ctx.stream_id, null, "{{}}", .{});
        _ = stream_mgr.global_manager.?.remove(ctx.stream_id);
    }

    logger.json(.info, "socks5", "client_connect_req", ctx.stream_id, null, "{{}}", .{});

    const target_payload = buf[3..rd];
    var frame_buf: [512]u8 = undefined;
    const fh = protocol.FrameHeader{
        .magic = 0x5455,
        .cmd = .connect,
        .flags = 0,
        .stream_id = ctx.stream_id,
        .seq = ctx.next_upstream_seq.fetchAdd(1, .monotonic),
        .payload_len = @intCast(target_payload.len),
    };
    fh.serialize(frame_buf[0..16]);
    @memcpy(frame_buf[16 .. 16 + target_payload.len], target_payload);

    pool.global_pool.?.postBatch(frame_buf[0 .. 16 + target_payload.len]) catch |err| {
        logger.json(.err, "socks5", "post_connect_fail", ctx.stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
        return;
    };

    logger.json(.debug, "socks5", "waiting_connect_ok", ctx.stream_id, null, "{{}}", .{});

    if (!ctx.connected_event.wait(10000) or !ctx.connect_success) {
        logger.json(.warn, "socks5", "connect_timeout_or_fail", ctx.stream_id, null, "{{\"ok\":{any}}}", .{ctx.connect_success});
        _ = stream.writeAll("\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
        return;
    }

    logger.json(.info, "socks5", "connect_handshake_done", ctx.stream_id, null, "{{}}", .{});
    _ = stream.writeAll("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") catch return;

    var data_buf: [4096]u8 = undefined;
    while (ctx.active.load(.acquire)) {
        const n = stream.read(&data_buf) catch 0;
        if (n == 0) break;

        var upload_buf: [4096 + 16]u8 = undefined;
        const seq = ctx.next_upstream_seq.fetchAdd(1, .monotonic);
        const data_fh = protocol.FrameHeader{
            .magic = 0x5455,
            .cmd = .data,
            .flags = 0,
            .stream_id = ctx.stream_id,
            .seq = seq,
            .payload_len = @intCast(n),
        };
        data_fh.serialize(upload_buf[0..16]);
        @memcpy(upload_buf[16 .. 16 + n], data_buf[0..n]);

        pool.global_pool.?.postBatch(upload_buf[0 .. 16 + n]) catch |err| {
            logger.json(.err, "socks5", "post_data_fail", ctx.stream_id, seq, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            break;
        };
    }
}
