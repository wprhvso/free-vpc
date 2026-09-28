const std = @import("std");
const Server = @import("server.zig").Server;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var server = Server.init(allocator, io);
    defer server.deinit();
    try server.start();
}
