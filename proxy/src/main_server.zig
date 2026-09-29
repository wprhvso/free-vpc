const std = @import("std");
const Server = @import("server.zig").Server;
const logger = @import("logger.zig");

pub fn main(init: std.process.Init) !void {
    logger.setRole(.server);
    const allocator = init.gpa;
    var server = Server.init(allocator);
    defer server.deinit();
    try server.start();
}
