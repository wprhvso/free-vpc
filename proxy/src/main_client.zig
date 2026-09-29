const std = @import("std");
const logger = @import("common/logger.zig");
const pool = @import("client/pool.zig");
const stream_mgr = @import("client/stream_manager.zig");
const batcher = @import("client/batcher.zig");
const socks5 = @import("client/socks5.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    logger.setRole(.client);

    const remote_host = "ssh.unsafie.com";
    const remote_port: u16 = 443;
    const socks_host = "127.0.0.1";
    const socks_port: u16 = 1080;

    var sm = stream_mgr.StreamManager.init(allocator);
    defer sm.streams.deinit();
    stream_mgr.global_manager = &sm;

    var p = try pool.ConnectionPool.init(allocator, remote_host, remote_port);
    defer allocator.destroy(p);
    pool.global_pool = p;
    
    try p.start();

    const ticker_th = try std.Thread.spawn(.{}, batcher.tickerLoop, .{});
    ticker_th.detach();

    try socks5.startListener(allocator, socks_host, socks_port);
}
