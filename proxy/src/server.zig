const std = @import("std");
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const Config = @import("config.zig").Config;
const logger = @import("logger.zig");
const ws = @import("ws.zig");

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: u32,
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

const sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

const ServerStream = struct {
    id: u32,
    target_stream: protocol.SocketStream,
    active: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
};

var global_server_instance: ?*Server = null;

fn serverLogHook(line: []const u8) void {
    if (global_server_instance) |s| {
        s.broadcastPacket(.log, 0, line) catch {};
    }
}

pub const Server = struct {
    allocator: std.mem.Allocator,
    ws_clients_mutex: futex.Mutex = .{},
    ws_clients: std.ArrayListUnmanaged(protocol.SocketStream),
    streams_mutex: futex.Mutex = .{},
    streams: std.AutoHashMap(u32, *ServerStream),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator) Server {
        return .{
            .allocator = allocator,
            .ws_clients = .empty,
            .streams = std.AutoHashMap(u32, *ServerStream).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        global_server_instance = null;
        logger.setHook(null);
        self.ws_clients.deinit(self.allocator);
        self.streams.deinit();
    }

    pub fn start(self: *Server) !void {
        global_server_instance = self;
        logger.setHook(serverLogHook);

        logger.json(.info, "lifecycle", "starting", "{{\"bind_host\":\"{s}\",\"bind_port\":{d}}}", .{
            Config.server_bind_host, Config.server_bind_port,
        });

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) {
            logger.json(.err, "tcp", "socket_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(rc))});
            return error.SocketFailed;
        }
        const listen_fd: i32 = @intCast(rc);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, listen_fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        _ = protocol.parseIp4(Config.server_bind_host, &octets);

        const addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.server_bind_port),
            .addr = @as(u32, @bitCast(octets)),
        };
        const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(bind_rc)) < 0) {
            logger.json(.err, "tcp", "bind_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(bind_rc))});
            return error.BindFailed;
        }

        const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);
        if (@as(isize, @bitCast(listen_rc)) < 0) {
            logger.json(.err, "tcp", "listen_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(listen_rc))});
            return error.ListenFailed;
        }

        logger.json(.info, "tcp", "listen_ok", "{{\"host\":\"{s}\",\"port\":{d}}}", .{
            Config.server_bind_host, Config.server_bind_port,
        });

        while (self.running.load(.acquire)) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            logger.json(.info, "tcp", "accepted", "{{\"fd\":{d}}}", .{client_fd});
            protocol.setNoDelay(client_fd);
            const stream = protocol.SocketStream{ .handle = client_fd };

            const th = std.Thread.spawn(.{}, handleWsClientWrapper, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
        }
    }

    fn handleWsClientWrapper(self: *Server, stream: protocol.SocketStream) void {
        self.handleWsClient(stream) catch |err| {
            logger.json(.warn, "ws", "client_disconnected", "{{\"error\":\"{s}\",\"fd\":{d}}}", .{ @errorName(err), stream.handle });
        };
        self.removeWsClient(stream);
        stream.close();
    }

    fn removeWsClient(self: *Server, stream: protocol.SocketStream) void {
        self.ws_clients_mutex.lock();
        defer self.ws_clients_mutex.unlock();
        for (self.ws_clients.items, 0..) |s, i| {
            if (s.handle == stream.handle) {
                _ = self.ws_clients.swapRemove(i);
                break;
            }
        }
    }

    fn handleWsClient(self: *Server, stream: protocol.SocketStream) !void {
        // 1. Read HTTP/1.1 Upgrade handshake
        var hdr_buf: [4096]u8 = undefined;
        var hdr_len: usize = 0;
        var ws_key: ?[]const u8 = null;

        while (hdr_len < hdr_buf.len) {
            const b = stream.read(hdr_buf[hdr_len .. hdr_len + 1]) catch return error.ReadFailed;
            if (b == 0) return error.ConnectionClosed;
            hdr_len += 1;
            if (hdr_len >= 4 and std.mem.eql(u8, hdr_buf[hdr_len - 4 .. hdr_len], "\r\n\r\n")) {
                break;
            }
        }

        const headers_str = hdr_buf[0..hdr_len];
        var lines = std.mem.splitSequence(u8, headers_str, "\r\n");
        while (lines.next()) |line| {
            if (std.ascii.startsWithIgnoreCase(line, "Sec-WebSocket-Key:")) {
                ws_key = std.mem.trim(u8, line["Sec-WebSocket-Key:".len..], " \t");
            }
        }

        const key = ws_key orelse {
            logger.json(.err, "ws", "missing_ws_key", "{{}}", .{});
            try stream.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return error.InvalidHandshake;
        };

        var accept_key: [28]u8 = undefined;
        ws.computeAcceptKey(key, &accept_key);

        var resp_buf: [512]u8 = undefined;
        const resp = try std.fmt.bufPrint(&resp_buf,
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
            .{accept_key},
        );

        try stream.writeAll(resp);
        logger.json(.info, "ws", "handshake_ok", "{{\"fd\":{d}}}", .{stream.handle});

        self.ws_clients_mutex.lock();
        try self.ws_clients.append(self.allocator, stream);
        self.ws_clients_mutex.unlock();

        // 2. Read WebSocket frames
        while (self.running.load(.acquire)) {
            var hdr: [2]u8 = undefined;
            if (!protocol.readExactStream(stream, &hdr)) break;

            const opcode: ws.Opcode = @enumFromInt(@as(u4, @intCast(hdr[0] & 0x0F)));
            const is_masked = (hdr[1] & 0x80) != 0;
            var payload_len: u64 = hdr[1] & 0x7F;

            if (payload_len == 126) {
                var ext: [2]u8 = undefined;
                if (!protocol.readExactStream(stream, &ext)) break;
                payload_len = std.mem.readInt(u16, &ext, .big);
            } else if (payload_len == 127) {
                var ext: [8]u8 = undefined;
                if (!protocol.readExactStream(stream, &ext)) break;
                payload_len = std.mem.readInt(u64, &ext, .big);
            }

            var mask: [4]u8 = .{ 0, 0, 0, 0 };
            if (is_masked) {
                if (!protocol.readExactStream(stream, &mask)) break;
            }

            if (payload_len > 1024 * 1024) {
                logger.json(.err, "ws", "payload_too_large", "{{\"len\":{d}}}", .{payload_len});
                break;
            }

            const p_len: usize = @intCast(payload_len);
            const payload = try self.allocator.alloc(u8, p_len);
            defer self.allocator.free(payload);

            if (!protocol.readExactStream(stream, payload)) break;
            if (is_masked) {
                ws.applyMask(payload, mask);
            }

            switch (opcode) {
                .binary => {
                    self.handleIncomingPacket(stream, payload);
                },
                .ping => {
                    // Send pong
                    var pong_writer = SocketStreamWriter{ .stream = stream };
                    try ws.writeFrame(&pong_writer, .pong, payload, null);
                },
                .close => break,
                else => {},
            }
        }
    }

    pub fn broadcastPacket(self: *Server, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
        self.ws_clients_mutex.lock();
        defer self.ws_clients_mutex.unlock();
        if (self.ws_clients.items.len == 0) return;

        // Broadcast to first client (or active client)
        const client = self.ws_clients.items[0];
        try self.sendTunnelPacket(client, cmd, stream_id, payload);
    }

    pub fn sendTunnelPacket(self: *Server, client_stream: protocol.SocketStream, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
        _ = self;
        var frame_buf: [Config.max_chunk_payload + 64]u8 = undefined;
        const th = protocol.TunnelHeader{
            .magic = 0x5650,
            .cmd = cmd,
            .reserved = 0,
            .stream_id = stream_id,
            .payload_len = @intCast(payload.len),
        };
        @memcpy(frame_buf[0..@sizeOf(protocol.TunnelHeader)], std.mem.asBytes(&th));
        if (payload.len > 0) {
            @memcpy(frame_buf[@sizeOf(protocol.TunnelHeader) .. @sizeOf(protocol.TunnelHeader) + payload.len], payload);
        }

        const total_len = @sizeOf(protocol.TunnelHeader) + payload.len;
        var w = SocketStreamWriter{ .stream = client_stream };
        try ws.writeFrame(&w, .binary, frame_buf[0..total_len], null);
    }

    fn handleIncomingPacket(self: *Server, client_stream: protocol.SocketStream, data: []const u8) void {
        if (data.len < @sizeOf(protocol.TunnelHeader)) return;
        var th: protocol.TunnelHeader = undefined;
        @memcpy(std.mem.asBytes(&th), data[0..@sizeOf(protocol.TunnelHeader)]);

        if (th.magic != 0x5650) {
            logger.json(.err, "tunnel_rx", "invalid_magic", "{{\"magic\":{d}}}", .{th.magic});
            return;
        }

        const payload = data[@sizeOf(protocol.TunnelHeader) .. @sizeOf(protocol.TunnelHeader) + th.payload_len];

        switch (th.cmd) {
            .connect => self.handleConnect(client_stream, th.stream_id, payload),
            .data => {
                self.streams_mutex.lock();
                const s_opt = self.streams.get(th.stream_id);
                self.streams_mutex.unlock();
                if (s_opt) |s| {
                    s.target_stream.writeAll(payload) catch {
                        self.closeStream(client_stream, th.stream_id);
                    };
                } else {
                    logger.json(.warn, "tunnel_rx", "orphan_stream", "{{\"stream_id\":{d}}}", .{th.stream_id});
                }
            },
            .close => {
                logger.json(.info, "stream", "remote_close", "{{\"stream_id\":{d}}}", .{th.stream_id});
                self.closeStream(client_stream, th.stream_id);
            },
            else => {},
        }
    }

    fn handleConnect(self: *Server, client_stream: protocol.SocketStream, stream_id: u32, payload: []const u8) void {
        const payload_copy = self.allocator.dupe(u8, payload) catch {
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        };

        const th = std.Thread.spawn(.{}, connectWorker, .{ self, client_stream, stream_id, payload_copy }) catch {
            self.allocator.free(payload_copy);
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        };
        th.detach();
    }

    fn connectWorker(self: *Server, client_stream: protocol.SocketStream, stream_id: u32, payload: []u8) void {
        defer self.allocator.free(payload);

        if (payload.len < 5) {
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        }

        const atyp = payload[0];
        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        var port: u16 = 0;

        if (atyp == 1) {
            if (payload.len < 7) {
                self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
                return;
            }
            @memcpy(&octets, payload[1..5]);
            port = std.mem.readInt(u16, payload[5..7], .big);
        } else if (atyp == 3) {
            const dlen = payload[1];
            if (payload.len < 2 + dlen + 2) {
                self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
                return;
            }
            const domain = payload[2 .. 2 + dlen];
            port = std.mem.readInt(u16, payload[2 + dlen ..][0..2], .big);

            logger.json(.debug, "dns", "resolve_start", "{{\"stream_id\":{d},\"domain\":\"{s}\"}}", .{ stream_id, domain });
            if (!protocol.resolveDnsA(domain, &octets)) {
                logger.json(.err, "dns", "resolve_failed", "{{\"stream_id\":{d},\"domain\":\"{s}\"}}", .{ stream_id, domain });
                self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
                return;
            }
            logger.json(.info, "dns", "resolve_ok", "{{\"stream_id\":{d},\"domain\":\"{s}\",\"ip\":\"{d}.{d}.{d}.{d}\"}}", .{
                stream_id, domain, octets[0], octets[1], octets[2], octets[3],
            });
        } else {
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        }

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) {
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        }
        const target_fd: i32 = @intCast(rc);
        protocol.setNoDelay(target_fd);

        const timeval = extern struct { sec: i64, usec: i64 };
        const tv = timeval{ .sec = 5, .usec = 0 };
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, target_fd))), 1, 20, @intFromPtr(&tv), @sizeOf(timeval));
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, target_fd))), 1, 21, @intFromPtr(&tv), @sizeOf(timeval));

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        logger.json(.debug, "tcp", "connect_start", "{{\"stream_id\":{d},\"fd\":{d},\"port\":{d}}}", .{ stream_id, target_fd, port });
        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, target_fd))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            logger.json(.err, "tcp", "connect_failed", "{{\"stream_id\":{d},\"rc\":{d}}}", .{ stream_id, @as(isize, @bitCast(conn_rc)) });
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, target_fd))));
            self.sendTunnelPacket(client_stream, .connect_fail, stream_id, "") catch {};
            return;
        }

        logger.json(.info, "stream", "connect_ok", "{{\"stream_id\":{d},\"fd\":{d}}}", .{ stream_id, target_fd });

        const target_stream = protocol.SocketStream{ .handle = target_fd };
        const s = self.allocator.create(ServerStream) catch return;
        s.* = .{
            .id = stream_id,
            .target_stream = target_stream,
        };

        self.streams_mutex.lock();
        self.streams.put(stream_id, s) catch {
            self.streams_mutex.unlock();
            target_stream.close();
            return;
        };
        self.streams_mutex.unlock();

        self.sendTunnelPacket(client_stream, .connect_ok, stream_id, "") catch {};

        var buf: [Config.max_chunk_payload]u8 = undefined;
        while (s.active.load(.acquire)) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) break;
            self.sendTunnelPacket(client_stream, .data, stream_id, buf[0..n]) catch break;
        }

        self.closeStream(client_stream, stream_id);
    }

    pub fn closeStream(self: *Server, client_stream: protocol.SocketStream, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const s = entry.value;
            if (s.active.swap(false, .acq_rel)) {
                logger.json(.info, "stream", "closing", "{{\"stream_id\":{d}}}", .{stream_id});
                s.target_stream.shutdown();
                s.target_stream.close();
                self.sendTunnelPacket(client_stream, .close, stream_id, "") catch {};
                self.allocator.destroy(s);
            }
        }
    }
};

const SocketStreamWriter = struct {
    stream: protocol.SocketStream,

    pub fn writeAll(self: *SocketStreamWriter, bytes: []const u8) !void {
        try self.stream.writeAll(bytes);
    }
};
