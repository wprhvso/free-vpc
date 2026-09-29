const std = @import("std");
const net = @import("common/net.zig");
const logger = @import("common/logger.zig");
const protocol = @import("common/protocol.zig");
const http_engine = @import("server/http_engine.zig");
const session_mod = @import("server/session.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    logger.setRole(.server);
    logger.setHook(session_mod.serverLogHook);

    const port: u16 = 8023;
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0); // AF_INET, SOCK_STREAM
    if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
    const listen_fd: i32 = @intCast(rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

    net.setReuseAddr(listen_fd);
    net.setNoDelay(listen_fd);

    const addr = net.sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0, // 0.0.0.0
    };

    const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(net.sockaddr_in));
    if (@as(isize, @bitCast(bind_rc)) < 0) return error.BindFailed;

    const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);
    if (@as(isize, @bitCast(listen_rc)) < 0) return error.ListenFailed;

    logger.json(.info, "lifecycle", "server_started", null, null, "{{\"bind\":\"0.0.0.0:{d}\"}}", .{port});

    while (true) {
        var client_addr: net.sockaddr = undefined;
        var client_len: u32 = @sizeOf(net.sockaddr);
        const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
        if (@as(isize, @bitCast(accept_rc)) < 0) continue;
        const client_fd: i32 = @intCast(accept_rc);

        net.setNoDelay(client_fd);
        const stream = protocol.SocketStream{ .handle = client_fd };

        const th = std.Thread.spawn(.{}, http_engine.handleConnection, .{ allocator, stream }) catch {
            stream.close();
            continue;
        };
        th.detach();
    }
}
