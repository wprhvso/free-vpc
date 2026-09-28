const std = @import("std");
const Client = @import("client.zig").Client;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var client = Client.init(allocator, io);
    defer client.deinit();
    try client.start();
}
