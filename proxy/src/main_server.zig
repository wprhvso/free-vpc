const std = @import("std");
const Server = @import("server.zig").Server;
const Config = @import("config.zig").Config;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    std.debug.print("\x1b[32m[START]\x1b[0m cf-proxy-server (bind: {s}:{d}, hold: {d}ms)\n", .{
        Config.server.bind_host, Config.server.bind_port, Config.server.hold_timeout_ms,
    });

    var server = Server.init(allocator, io);
    defer server.deinit();
    try server.start();
}
