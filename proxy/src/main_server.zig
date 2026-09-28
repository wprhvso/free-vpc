const std = @import("std");
const Server = @import("server.zig").Server;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var host: []const u8 = "127.0.0.1";
    var port: u16 = 8022;
    var buf_mb: usize = 16;
    var token: []const u8 = "default_secret";
    var rqlite_url: []const u8 = "http://127.0.0.1:4001";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--host")) {
            if (i + 1 < args.len) {
                i += 1;
                host = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                i += 1;
                port = std.fmt.parseInt(u16, args[i], 10) catch 8022;
            }
        } else if (std.mem.eql(u8, arg, "-b")) {
            if (i + 1 < args.len) {
                i += 1;
                buf_mb = std.fmt.parseInt(usize, args[i], 10) catch 16;
            }
        } else if (std.mem.eql(u8, arg, "--token")) {
            if (i + 1 < args.len) {
                i += 1;
                token = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--rqlite")) {
            if (i + 1 < args.len) {
                i += 1;
                rqlite_url = args[i];
            }
        }
    }

    std.debug.print("Starting cf-proxy-server on {s}:{d} (buffer: {d}MB, rqlite: {s})...\n", .{
        host, port, buf_mb, rqlite_url,
    });

    var server = Server.init(allocator, io, host, port, buf_mb, token, rqlite_url);
    defer server.deinit();
    try server.start();
}
