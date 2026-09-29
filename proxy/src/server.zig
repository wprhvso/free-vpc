const std = @import("std");
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const Config = @import("config.zig").Config;

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

pub const Server = struct {
    allocator: std.mem.Allocator,
    h2_stream: ?protocol.SocketStream = null,
    h2_stream_id: u32 = 1,
    write_mutex: futex.Mutex = .{},
    streams_mutex: futex.Mutex = .{},
    streams: std.AutoHashMap(u32, *ServerStream),
    accumulated_window: u32 = 0,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator) Server {
        return .{
            .allocator = allocator,
            .streams = std.AutoHashMap(u32, *ServerStream).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.streams.deinit();
    }

    pub fn start(self: *Server) !void {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
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
        _ = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
        _ = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);

        _ = std.os.linux.syscall3(.write, 1, @intFromPtr("[SERVER] Listening for Nginx H2C on 127.0.0.1:8023...\n"), 55);

        while (self.running.load(.acquire)) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            protocol.setNoDelay(client_fd);
            const stream = protocol.SocketStream{ .handle = client_fd };

            var preface_buf: [24]u8 = undefined;
            if (!protocol.readExactStream(stream, &preface_buf)) {
                stream.close();
                continue;
            }

            self.h2_stream = stream;

            try self.sendH2Frame(.{
                .length = 0,
                .frame_type = protocol.FrameType.SETTINGS,
                .flags = protocol.Flags.NONE,
                .stream_id = 0,
            }, "");

            self.h2ServerLoop(stream);
        }
    }

    pub fn sendH2Frame(self: *Server, hdr: protocol.FrameHeader, payload: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();

        if (self.h2_stream) |s| {
            var h_buf: [9]u8 = undefined;
            hdr.serialize(&h_buf);
            try s.writeAll(&h_buf);
            if (payload.len > 0) {
                try s.writeAll(payload);
            }
        }
    }

    pub fn sendTunnelPacket(self: *Server, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
        var frame_buf: [Config.max_chunk_payload + 64]u8 = undefined;

        const tunnel_len: u32 = @intCast(@sizeOf(protocol.TunnelHeader) + payload.len);
        frame_buf[0] = 0;
        std.mem.writeInt(u32, frame_buf[1..][0..4], tunnel_len, .big);

        const th = protocol.TunnelHeader{
            .magic = 0x5650,
            .cmd = cmd,
            .reserved = 0,
            .stream_id = stream_id,
            .payload_len = @intCast(payload.len),
        };
        @memcpy(frame_buf[5 .. 5 + @sizeOf(protocol.TunnelHeader)], std.mem.asBytes(&th));

        if (payload.len > 0) {
            @memcpy(frame_buf[5 + @sizeOf(protocol.TunnelHeader) .. 5 + tunnel_len], payload);
        }

        const total_data_len = 5 + tunnel_len;

        try self.sendH2Frame(.{
            .length = @intCast(total_data_len),
            .frame_type = protocol.FrameType.DATA,
            .flags = protocol.Flags.NONE,
            .stream_id = @intCast(self.h2_stream_id),
        }, frame_buf[0..total_data_len]);
    }

    fn h2ServerLoop(self: *Server, stream: protocol.SocketStream) void {
        defer stream.close();
        var hdr_buf: [9]u8 = undefined;

        while (self.running.load(.acquire)) {
            if (!protocol.readExactStream(stream, &hdr_buf)) break;
            const frame = protocol.FrameHeader.deserialize(&hdr_buf);

            const payload = self.allocator.alloc(u8, frame.length) catch break;
            defer self.allocator.free(payload);
            if (!protocol.readExactStream(stream, payload)) break;

            switch (frame.frame_type) {
                protocol.FrameType.HEADERS => {
                    self.h2_stream_id = frame.stream_id;
                    var resp_buf: [64]u8 = undefined;
                    const r_len = protocol.encodeServerGrpcHeaders(&resp_buf);
                    self.sendH2Frame(.{
                        .length = @intCast(r_len),
                        .frame_type = protocol.FrameType.HEADERS,
                        .flags = protocol.Flags.END_HEADERS,
                        .stream_id = frame.stream_id,
                    }, resp_buf[0..r_len]) catch break;
                },
                protocol.FrameType.DATA => {
                    self.h2_stream_id = frame.stream_id;
                    self.handleIncomingData(payload);

                    self.accumulated_window += frame.length;
                    if (self.accumulated_window >= Config.window_update_threshold) {
                        self.sendWindowUpdate(0, self.accumulated_window) catch {};
                        self.sendWindowUpdate(frame.stream_id, self.accumulated_window) catch {};
                        self.accumulated_window = 0;
                    }
                },
                protocol.FrameType.SETTINGS => {
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        self.sendH2Frame(.{
                            .length = 0,
                            .frame_type = protocol.FrameType.SETTINGS,
                            .flags = protocol.Flags.ACK,
                            .stream_id = 0,
                        }, "") catch {};
                    }
                },
                protocol.FrameType.PING => {
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        self.sendH2Frame(.{
                            .length = 8,
                            .frame_type = protocol.FrameType.PING,
                            .flags = protocol.Flags.ACK,
                            .stream_id = 0,
                        }, payload) catch {};
                    }
                },
                else => {},
            }
        }
    }

    fn sendWindowUpdate(self: *Server, stream_id: u31, increment: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, increment & 0x7FFFFFFF, .big);
        try self.sendH2Frame(.{
            .length = 4,
            .frame_type = protocol.FrameType.WINDOW_UPDATE,
            .flags = protocol.Flags.NONE,
            .stream_id = stream_id,
        }, &buf);
    }

    fn handleIncomingData(self: *Server, data: []const u8) void {
        var offset: usize = 0;
        while (offset + 5 + @sizeOf(protocol.TunnelHeader) <= data.len) {
            const grpc_len = std.mem.readInt(u32, data[offset + 1 ..][0..4], .big);
            offset += 5;

            if (offset + grpc_len > data.len) break;

            var th: protocol.TunnelHeader = undefined;
            @memcpy(std.mem.asBytes(&th), data[offset .. offset + @sizeOf(protocol.TunnelHeader)]);
            offset += @sizeOf(protocol.TunnelHeader);

            if (th.magic != 0x5650) break;
            const payload = data[offset .. offset + th.payload_len];
            offset += th.payload_len;

            switch (th.cmd) {
                .connect => self.handleConnect(th.stream_id, payload),
                .data => {
                    self.streams_mutex.lock();
                    const s_opt = self.streams.get(th.stream_id);
                    self.streams_mutex.unlock();
                    if (s_opt) |s| {
                        s.target_stream.writeAll(payload) catch {
                            self.closeStream(th.stream_id);
                        };
                    }
                },
                .close => self.closeStream(th.stream_id),
                else => {},
            }
        }
    }

    fn handleConnect(self: *Server, stream_id: u32, payload: []const u8) void {
        const th = std.Thread.spawn(.{}, connectWorker, .{ self, stream_id, payload }) catch {
            self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
            return;
        };
        th.detach();
    }

    fn connectWorker(self: *Server, stream_id: u32, payload: []const u8) void {
        if (payload.len < 5) {
            self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
            return;
        }

        const atyp = payload[0];
        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        var port: u16 = 0;

        if (atyp == 1) {
            if (payload.len < 7) {
                self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
                return;
            }
            @memcpy(&octets, payload[1..5]);
            port = std.mem.readInt(u16, payload[5..7], .big);
        } else if (atyp == 3) {
            const dlen = payload[1];
            if (payload.len < 2 + dlen + 2) {
                self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
                return;
            }
            const domain = payload[2 .. 2 + dlen];
            port = std.mem.readInt(u16, payload[2 + dlen ..][0..2], .big);

            if (!protocol.resolveDnsA(domain, &octets)) {
                self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
                return;
            }
        } else {
            self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
            return;
        }

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) {
            self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
            return;
        }
        const target_fd: i32 = @intCast(rc);
        protocol.setNoDelay(target_fd);

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, target_fd))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, target_fd))));
            self.sendTunnelPacket(.connect_fail, stream_id, "") catch {};
            return;
        }

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

        self.sendTunnelPacket(.connect_ok, stream_id, "") catch {};

        var buf: [Config.max_chunk_payload]u8 = undefined;
        while (s.active.load(.acquire)) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) break;
            self.sendTunnelPacket(.data, stream_id, buf[0..n]) catch break;
        }

        self.closeStream(stream_id);
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const s = entry.value;
            if (s.active.swap(false, .acq_rel)) {
                s.target_stream.shutdown();
                s.target_stream.close();
                self.sendTunnelPacket(.close, stream_id, "") catch {};
            }
        }
    }
};
