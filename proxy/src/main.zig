const std = @import("std");
const Server = @import("server.zig").Server;
const Client = @import("client.zig").Client;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        printUsage();
        return;
    }

    const mode = args[1];

    if (std.mem.eql(u8, mode, "server")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8022;
        var buf_mb: usize = 16;

        var i: usize = 2;
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
            }
        }

        std.debug.print("Starting cf-proxy server on {s}:{d} (buffer: {d}MB)...\n", .{ host, port, buf_mb });
        var server = Server.init(allocator, io, host, port, buf_mb);
        defer server.deinit();
        try server.start();
    } else if (std.mem.eql(u8, mode, "client")) {
        var remote_url: []const u8 = "https://ssh.unsafie.com";
        var socks_addr: ?[]const u8 = "127.0.0.1:1080";
        var forward_rule: ?[]const u8 = null;
        var num_workers: usize = 8;
        var max_body_mb: usize = 1;
        var buf_mb: usize = 16;

        var i: usize = 2;
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
            }
        }

        std.debug.print("Starting cf-proxy client (remote: {s}, workers: {d}, max_body: {d}MB, buffer: {d}MB)...\n", .{
            remote_url, num_workers, max_body_mb, buf_mb,
        });

        var client = Client.init(allocator, io, remote_url, socks_addr, forward_rule, num_workers, max_body_mb, buf_mb);
        defer client.deinit();
        try client.start();
    } else {
        printUsage();
    }
}

fn printUsage() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  cf-proxy server [--host 127.0.0.1] [--port 8022] [-b <buffer_mb>]\n", .{});
    std.debug.print("  cf-proxy client --remote <url> [--socks 127.0.0.1:1080] [--forward <local:host:remote>] [-n <workers>] [-s <max_post_mb>] [-b <buffer_mb>]\n", .{});
}
