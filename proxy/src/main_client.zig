const std = @import("std");
const Client = @import("client.zig").Client;
const Config = @import("config.zig").Config;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    std.debug.print("\x1b[32m[START]\x1b[0m cf-proxy-client (target: {s}:{d}, socks: {s}:{d}, workers: 6 PUSH / 6 PULL)\n", .{
        Config.client.remote_host, Config.client.remote_port, Config.client.socks_host, Config.client.socks_port,
    });

    var client = Client.init(allocator, io);
    defer client.deinit();
    try client.start();
}
