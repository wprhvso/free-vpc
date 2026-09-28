const std = @import("std");
const Client = @import("client.zig").Client;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var remote_url: []const u8 = "https://ssh.unsafie.com";
    var socks_addr: ?[]const u8 = "127.0.0.1:1080";
    var forward_rule: ?[]const u8 = null;
    var num_workers: usize = 8;
    var max_body_mb: usize = 1;
    var buf_mb: usize = 16;
    var name: []const u8 = "client-default";
    var token: []const u8 = "default_secret";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--remote")) {
            if (i + 1 < args.len) {
                i += 1;
                remote_url = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--socks")) {
            if (i + 1 < args.len) {
                i += 1;
                socks_addr = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--forward")) {
            if (i + 1 < args.len) {
                i += 1;
                forward_rule = args[i];
            }
        } else if (std.mem.eql(u8, arg, "-n")) {
            if (i + 1 < args.len) {
                i += 1;
                num_workers = std.fmt.parseInt(usize, args[i], 10) catch 8;
            }
        } else if (std.mem.eql(u8, arg, "-s")) {
            if (i + 1 < args.len) {
                i += 1;
                max_body_mb = std.fmt.parseInt(usize, args[i], 10) catch 1;
            }
        } else if (std.mem.eql(u8, arg, "-b")) {
            if (i + 1 < args.len) {
                i += 1;
                buf_mb = std.fmt.parseInt(usize, args[i], 10) catch 16;
            }
        } else if (std.mem.eql(u8, arg, "--name")) {
            if (i + 1 < args.len) {
                i += 1;
                name = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--token")) {
            if (i + 1 < args.len) {
                i += 1;
                token = args[i];
            }
        }
    }

    std.debug.print("Starting cf-proxy-client [{s}] (remote: {s}, workers: {d}, buffer: {d}MB)...\n", .{
        name, remote_url, num_workers, buf_mb,
    });

    var client = Client.init(allocator, io, remote_url, socks_addr, forward_rule, num_workers, max_body_mb, buf_mb, name, token);
    defer client.deinit();
    try client.start();
}
