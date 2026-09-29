const std = @import("std");
const net = @import("../common/net.zig");
const protocol = @import("../common/protocol.zig");
const logger = @import("../common/logger.zig");
const Session = @import("session.zig").Session;
const Reassembler = @import("reassembler.zig").Reassembler;

pub fn handleConnect(session: *Session, stream_id: u32, payload: []const u8) void {
    logger.json(.info, "target", "handle_connect_start", stream_id, null, "{{\"len\":{d}}}", .{payload.len});
    const payload_copy = session.allocator.dupe(u8, payload) catch return;
    const th = std.Thread.spawn(.{}, connectWorker, .{ session, stream_id, payload_copy }) catch {
        session.allocator.free(payload_copy);
        session.sendDownstreamFrame(.connect_fail, stream_id, "\x01") catch {};
        return;
    };
    th.detach();
}

fn connectWorker(session: *Session, stream_id: u32, payload: []u8) void {
    defer session.allocator.free(payload);

    if (payload.len < 5) {
        logger.json(.err, "target", "payload_too_short", stream_id, null, "{{}}", .{});
        session.sendDownstreamFrame(.connect_fail, stream_id, "\x01") catch {};
        return;
    }

    const atyp = payload[0];
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var port: u16 = 0;

    if (atyp == 1) { // IPv4
        if (payload.len < 7) {
            session.sendDownstreamFrame(.connect_fail, stream_id, "\x01") catch {};
            return;
        }
        @memcpy(&octets, payload[1..5]);
        port = std.mem.readInt(u16, payload[5..7], .big);
    } else if (atyp == 3) { // Domain
        const dlen = payload[1];
        if (payload.len < 2 + dlen + 2) {
            session.sendDownstreamFrame(.connect_fail, stream_id, "\x01") catch {};
            return;
        }
        const domain = payload[2 .. 2 + dlen];
        port = std.mem.readInt(u16, payload[2 + dlen ..][0..2], .big);
        if (!net.resolveDnsA(domain, &octets)) {
            logger.json(.err, "target", "dns_resolve_failed", stream_id, null, "{{\"domain\":\"{s}\"}}", .{domain});
            session.sendDownstreamFrame(.connect_fail, stream_id, "\x04") catch {};
            return;
        }
    } else {
        session.sendDownstreamFrame(.connect_fail, stream_id, "\x08") catch {};
        return;
    }

    const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    if (@as(isize, @bitCast(sock_rc)) < 0) {
        session.sendDownstreamFrame(.connect_fail, stream_id, "\x01") catch {};
        return;
    }
    const target_fd: i32 = @intCast(sock_rc);
    net.setNoDelay(target_fd);
    net.setSocketTimeout(target_fd, 120);

    const addr = net.sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };

    const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, target_fd))), @intFromPtr(&addr), @sizeOf(net.sockaddr_in));
    if (@as(isize, @bitCast(conn_rc)) < 0) {
        _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, target_fd))));
        logger.json(.err, "target", "tcp_connect_failed", stream_id, null, "{{\"port\":{d}}}", .{port});
        session.sendDownstreamFrame(.connect_fail, stream_id, "\x05") catch {};
        return;
    }

    logger.json(.info, "target", "connected", stream_id, null, "{{\"port\":{d}}}", .{port});

    const target_stream = protocol.SocketStream{ .handle = target_fd };
    const entry = session.allocator.create(Session.StreamEntry) catch {
        target_stream.close();
        return;
    };
    entry.* = .{
        .id = stream_id,
        .target_stream = target_stream,
        .reassembler = Reassembler.init(stream_id, target_stream),
    };

    session.streams_mutex.lock();
    session.streams.put(stream_id, entry) catch {
        session.streams_mutex.unlock();
        target_stream.close();
        session.allocator.destroy(entry);
        return;
    };
    session.streams_mutex.unlock();

    logger.json(.info, "target", "sending_connect_ok", stream_id, null, "{{}}", .{});
    session.sendDownstreamFrame(.connect_ok, stream_id, "") catch |err| {
        logger.json(.err, "target", "send_connect_ok_err", stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
    };

    var buf: [4096]u8 = undefined;
    while (entry.active.load(.acquire)) {
        const rd = target_stream.read(&buf) catch break;
        if (rd == 0) break;
        session.sendDownstreamFrame(.data, stream_id, buf[0..rd]) catch break;
    }

    session.streams_mutex.lock();
    _ = session.streams.remove(stream_id);
    session.streams_mutex.unlock();

    entry.active.store(false, .release);
    target_stream.close();
    session.sendDownstreamFrame(.fin, stream_id, "") catch {};
    session.allocator.destroy(entry);
    logger.json(.info, "target", "closed", stream_id, null, "{{}}", .{});
}
