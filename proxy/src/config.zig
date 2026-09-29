const std = @import("std");

pub const Config = struct {
    pub const common = struct {
        pub const pipe_path: []const u8 = "/pipe";
        pub const token_header: []const u8 = "X-Telemetry-Auth";
        pub const token: []const u8 = "secret_production_cf_token_884129";

        pub const max_payload_len: usize = 32 * 1024;
        pub const http_chunk_size: usize = 64 * 1024;
        pub const queue_capacity: usize = 16 * 1024 * 1024;
    };

    pub const client = struct {
        pub const remote_host: []const u8 = "ssh.unsafie.com";
        pub const remote_port: u16 = 443;
        pub const is_tls: bool = true;

        pub const socks_host: []const u8 = "127.0.0.1";
        pub const socks_port: u16 = 1080;

        pub const pool_size: usize = 6;
        pub const socket_ttl_ms: u64 = 10_000;
        pub const idle_interval_ms: u64 = 1_000;

        pub const user_agent: []const u8 = "curl/8.21.0";
        pub const connect_timeout_ms: u64 = 8_000;
        pub const reorder_limit: usize = 512;
    };

    pub const server = struct {
        pub const bind_host: []const u8 = "0.0.0.0";
        pub const bind_port: u16 = 8022;

        pub const target_conn_timeout_ms: u64 = 5_000;
        pub const reorder_limit: usize = 512;
    };
};
