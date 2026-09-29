const std = @import("std");
const Server = @import("server.zig").Server;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var server = Server.init(allocator);
    defer server.deinit();
    try server.start();
}
