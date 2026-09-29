const std = @import("std");
const Client = @import("client.zig").Client;
const logger = @import("logger.zig");

pub fn main(init: std.process.Init) !void {
    logger.setRole(.client);
    const allocator = init.gpa;
    var client = Client.init(allocator);
    defer client.deinit();
    try client.start();
}
