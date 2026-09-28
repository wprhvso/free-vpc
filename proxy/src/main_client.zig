const std = @import("std");
const Client = @import("client.zig").Client;
const ClientOptions = @import("client.zig").ClientOptions;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var opts = ClientOptions{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--remote")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.remote_url = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--path")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.sync_path = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--socks")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.socks_addr = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--forward")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.forward_rule = args[i];
            }
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--workers")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.num_workers = std.fmt.parseInt(usize, args[i], 10) catch 8;
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
        } else if (std.mem.eql(u8, arg, "--timeout-req-ms")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.timeout_req_ms = std.fmt.parseInt(u64, args[i], 10) catch 2500;
            }
        } else if (std.mem.eql(u8, arg, "--timeout-conn-ms")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.timeout_conn_ms = std.fmt.parseInt(u64, args[i], 10) catch 3000;
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
        } else if (std.mem.eql(u8, arg, "--user-agent")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.user_agent = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--name")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.name = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            if (i + 1 < args.len) {
                i += 1;
                opts.log_level = args[i];
            }
        }
    }

    std.debug.print("\x1b[32m[START]\x1b[0m cf-proxy-client [{s}] (remote: {s}{s}, workers: {d}, buffer: {d}MB, timeout: {d}ms)\n", .{
        opts.name, opts.remote_url, opts.sync_path, opts.num_workers, opts.buf_mb, opts.timeout_req_ms,
    });

    var client = Client.init(allocator, io, opts);
    defer client.deinit();
    try client.start();
}
