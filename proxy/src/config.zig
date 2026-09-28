const std = @import("std");

pub const Config = struct {
    pub const common = struct {
        pub const token_header: []const u8 = "X-Telemetry-Auth";
        pub const token: []const u8 = "secret_production_cf_token_884129";

        pub const push_path: []const u8 = "/v2/telemetry/events";
        pub const pull_path: []const u8 = "/v2/telemetry/updates";

        pub const max_payload_len: usize = 32 * 1024;
        pub const http_chunk_size: usize = 128 * 1024;
        pub const queue_capacity: usize = 16 * 1024 * 1024;
    };

    pub const client = struct {
        pub const remote_host: []const u8 = "ssh.unsafie.com";
        pub const remote_port: u16 = 443;
        pub const is_tls: bool = true;

        pub const socks_host: []const u8 = "127.0.0.1";
        pub const socks_port: u16 = 1080;

        pub const push_workers: usize = 6;
        pub const pull_workers: usize = 6;

        pub const user_agent: []const u8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
        pub const connect_timeout_ms: u64 = 8_000;
    };

    pub const server = struct {
        pub const bind_host: []const u8 = "0.0.0.0";
        pub const bind_port: u16 = 8022;

        pub const hold_timeout_ms: u64 = 10_000;
        pub const target_conn_timeout_ms: u64 = 5_000;
        pub const reorder_limit: usize = 512;
    };
};
