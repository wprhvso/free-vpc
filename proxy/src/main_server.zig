const std = @import("std");
const Server = @import("server.zig").Server;
const ServerOptions = @import("server.zig").ServerOptions;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var opts = ServerOptions{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--host")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.host = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.port = std.fmt.parseInt(u16, args[i], 10) catch 8022;
            }
        } else if (std.mem.eql(u8, arg, "--path")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.sync_path = args[i];
            }
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--chunk-kb")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.chunk_kb = std.fmt.parseInt(usize, args[i], 10) catch 64;
            }
        } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--buf-mb")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.buf_mb = std.fmt.parseInt(usize, args[i], 10) catch 32;
            }
        } else if (std.mem.eql(u8, arg, "--hold-ms")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.hold_ms = std.fmt.parseInt(u64, args[i], 10) catch 2000;
            }
        } else if (std.mem.eql(u8, arg, "--target-conn-timeout-ms")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.target_conn_timeout_ms = std.fmt.parseInt(u64, args[i], 10) catch 3000;
            }
        } else if (std.mem.eql(u8, arg, "--reorder-limit")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.reorder_limit = std.fmt.parseInt(usize, args[i], 10) catch 512;
            }
        } else if (std.mem.eql(u8, arg, "--token")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.token = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--token-header")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.token_header = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--stream-idle-sec")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.stream_idle_sec = std.fmt.parseInt(u64, args[i], 10) catch 300;
            }
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.log_level = args[i];
            }
        }
    }

    var server = Server.init(allocator, io, opts);
    defer server.deinit();
    try server.start();
}
