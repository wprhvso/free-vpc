const std = @import("std");

pub const Config = struct {
    pub const remote_host: []const u8 = "ssh.unsafie.com";
    pub const remote_port: u16 = 443;
    pub const grpc_path: []const u8 = "/tunnel.v1.Tunnel/Pipe";

    pub const socks_host: []const u8 = "127.0.0.1";
    pub const socks_port: u16 = 1080;

    pub const server_bind_host: []const u8 = "0.0.0.0";
    pub const server_bind_port: u16 = 8022;

    pub const max_chunk_payload: usize = 14 * 1024; // 14KB
    pub const window_update_threshold: u32 = 32 * 1024; // 32KB
};
