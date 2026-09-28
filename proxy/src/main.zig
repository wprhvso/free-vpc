const std = @import("std");
const Server = @import("server.zig").Server;
const Client = @import("client.zig").Client;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    const mode = args.next() orelse {
        printUsage();
        return;
    };

    if (std.mem.eql(u8, mode, "server")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8022;

        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--host")) {
                host = args.next() orelse host;
            } else if (std.mem.eql(u8, arg, "--port")) {
                const port_str = args.next() orelse "8022";
                port = std.fmt.parseInt(u16, port_str, 10) catch 8022;
            }
        }

        std.debug.print("Starting cf-proxy server on {s}:{d}...\n", .{ host, port });
        var server = Server.init(allocator, host, port);
        defer server.deinit();
        try server.start();
    } else if (std.mem.eql(u8, mode, "client")) {
        var remote_url: []const u8 = "https://ssh.unsafie.com";
        var socks_addr: ?[]const u8 = "127.0.0.1:1080";
        var forward_rule: ?[]const u8 = null;

        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--remote")) {
                remote_url = args.next() orelse remote_url;
            } else if (std.mem.eql(u8, arg, "--socks")) {
                socks_addr = args.next();
            } else if (std.mem.eql(u8, arg, "--forward")) {
                forward_rule = args.next();
            }
        }

        std.debug.print("Starting cf-proxy client (remote: {s})...\n", .{remote_url});
        if (socks_addr) |s| {
            std.debug.print("SOCKS5 proxy listening on {s}\n", .{s});
        }
        if (forward_rule) |f| {
            std.debug.print("Forwarding rule: {s}\n", .{f});
        }

        var client = Client.init(allocator, remote_url, socks_addr, forward_rule);
        defer client.deinit();
        try client.start();
    } else {
        printUsage();
    }
}

fn printUsage() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  cf-proxy server [--host 127.0.0.1] [--port 8022]\n", .{});
    std.debug.print("  cf-proxy client --remote <url> [--socks 127.0.0.1:1080] [--forward <local_port:host:remote_port>]\n", .{});
}
