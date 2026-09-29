const std = @import("std");
const Client = @import("client.zig").Client;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var client = Client.init(allocator);
    defer client.deinit();
    try client.start();
}
