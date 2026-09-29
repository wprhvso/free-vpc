const std = @import("std");
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const Config = @import("config.zig").Config;
const logger = @import("logger.zig");
const TlsClient = @import("tls_client.zig");

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

fn sliceToHex(bytes: []const u8, out: []u8) []const u8 {
    const hex_digits = "0123456789abcdef";
    var i: usize = 0;
    while (i < bytes.len and i * 2 + 2 <= out.len) : (i += 1) {
        out[i * 2] = hex_digits[bytes[i] >> 4];
        out[i * 2 + 1] = hex_digits[bytes[i] & 0x0f];
    }
    return out[0 .. i * 2];
}

const DirectSocketWriter = struct {
    fd: i32,
    raw_buf: [TlsClient.min_buffer_len]u8 = undefined,
    writer: std.Io.Writer = undefined,

    pub fn setup(self: *DirectSocketWriter, fd: i32) void {
        self.fd = fd;
        self.writer = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .drain = drain,
                .flush = flush,
            },
            .end = 0,
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        try flush(w);
        if (data.len == 0) return 0;
        var total: usize = 0;
        for (data[0 .. data.len - 1]) |buf| {
            try writeSyscall(w, buf);
            total += buf.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try writeSyscall(w, last);
            total += last.len;
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *DirectSocketWriter = @alignCast(@fieldParentPtr("writer", w));
        if (w.end > 0) {
            var index: usize = 0;
            while (index < w.end) {
                const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(w.buffer.ptr + index), w.end - index);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) {
                    logger.json(.err, "direct_writer", "flush_failed", "{{\"fd\":{d},\"rc\":{d}}}", .{ self.fd, signed });
                    return error.WriteFailed;
                }
                index += @intCast(signed);
            }
            w.end = 0;
        }
    }

    fn writeSyscall(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
        const self: *DirectSocketWriter = @alignCast(@fieldParentPtr("writer", w));
        var index: usize = 0;
        while (index < bytes.len) {
            const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(bytes.ptr + index), bytes.len - index);
            const signed: isize = @bitCast(rc);
            if (signed <= 0) {
                logger.json(.err, "direct_writer", "write_failed", "{{\"fd\":{d},\"rc\":{d}}}", .{ self.fd, signed });
                return error.WriteFailed;
            }
            index += @intCast(signed);
        }
    }
};

const DirectSocketReader = struct {
    fd: i32,
    raw_buf: [TlsClient.min_buffer_len]u8 = undefined,
    reader: std.Io.Reader = undefined,

    pub fn setup(self: *DirectSocketReader, fd: i32) void {
        self.fd = fd;
        self.reader = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .stream = stream,
                .readVec = readVec,
            },
            .seek = 0,
            .end = 0,
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        var bufs: [1][]u8 = .{""};
        return readVec(r, &bufs);
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const self: *DirectSocketReader = @alignCast(@fieldParentPtr("reader", r));

        if (data.len > 0 and data[0].len > 0) {
            const dest = data[0];
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(dest.ptr), dest.len);
            const signed: isize = @bitCast(rc);
            if (signed < 0) {
                logger.json(.err, "direct_reader", "read_vec_failed", "{{\"fd\":{d},\"rc\":{d}}}", .{ self.fd, signed });
                return error.ReadFailed;
            }
            if (signed == 0) return error.EndOfStream;
            return @intCast(signed);
        }

        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        } else if (r.seek > 0) {
            const remaining = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..remaining], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = remaining;
        }

        const avail = r.buffer.len - r.end;
        if (avail == 0) return 0;

        const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(r.buffer.ptr + r.end), avail);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            logger.json(.err, "direct_reader", "buffer_fill_failed", "{{\"fd\":{d},\"rc\":{d}}}", .{ self.fd, signed });
            return error.ReadFailed;
        }
        if (signed == 0) return error.EndOfStream;

        r.end += @intCast(signed);
        return 0;
    }
};

const RemoteConnection = struct {
    fd: i32,
    direct_reader: DirectSocketReader = undefined,
    direct_writer: DirectSocketWriter = undefined,
    tls_client: ?TlsClient = null,
    tls_read_buf: [TlsClient.min_buffer_len]u8 = undefined,
    tls_write_buf: [TlsClient.min_buffer_len]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, fd: i32, host: []const u8) !*RemoteConnection {
        const conn = try allocator.create(RemoteConnection);
        errdefer allocator.destroy(conn);

        conn.fd = fd;
        conn.tls_client = null;
        conn.direct_reader.setup(fd);
        conn.direct_writer.setup(fd);

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

        var ts: std.posix.timespec = undefined;
        _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
        const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

        logger.json(.debug, "tls", "handshake_start", "{{\"host\":\"{s}\",\"fd\":{d}}}", .{ host, fd });

        conn.tls_client = TlsClient.init(
            &conn.direct_reader.reader,
            &conn.direct_writer.writer,
            .{
                .host = .{ .explicit = host },
                .ca = .no_verification,
                .write_buffer = &conn.tls_write_buf,
                .read_buffer = &conn.tls_read_buf,
                .entropy = &entropy,
                .realtime_now = now,
                .allow_truncation_attacks = true,
            },
        ) catch |err| {
            logger.json(.err, "tls", "handshake_failed", "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            return err;
        };

        logger.json(.info, "tls", "handshake_ok", "{{\"host\":\"{s}\"}}", .{host});
        return conn;
    }

    pub fn readExact(self: *RemoteConnection, dest: []u8) !void {
        var total: usize = 0;
        while (total < dest.len) {
            const avail = self.tls_client.?.reader.buffered();
            if (avail.len > 0) {
                const copy_len = @min(dest.len - total, avail.len);
                @memcpy(dest[total .. total + copy_len], avail[0..copy_len]);
                self.tls_client.?.reader.toss(copy_len);
                total += copy_len;
            } else {
                const slice = try self.tls_client.?.reader.peekGreedy(1);
                if (slice.len == 0) return error.ConnectionClosed;
                const copy_len = @min(dest.len - total, slice.len);
                @memcpy(dest[total .. total + copy_len], slice[0..copy_len]);
                self.tls_client.?.reader.toss(copy_len);
                total += copy_len;
            }
        }
    }

    pub fn close(self: *RemoteConnection) void {
        if (self.tls_client) |*tc| tc.end() catch {};
        self.tls_client = null;
        if (self.fd >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
            logger.json(.debug, "tls", "socket_closed", "{{\"fd\":{d}}}", .{self.fd});
            self.fd = -1;
        }
    }
};

const ClientStream = struct {
    id: u32,
    stream: protocol.SocketStream,
    connected_event: futex.Event = .{},
    connect_success: bool = false,
    active: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    remote_conn: ?*RemoteConnection = null,
    write_mutex: futex.Mutex = .{},
    streams_mutex: futex.Mutex = .{},
    streams: std.AutoHashMap(u32, *ClientStream),
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    accumulated_window: u32 = 0,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    rx_buf: [64 * 1024]u8 = undefined,
    rx_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Client {
        return .{
            .allocator = allocator,
            .streams = std.AutoHashMap(u32, *ClientStream).init(allocator),
            .rx_len = 0,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.remote_conn) |c| {
            c.close();
            self.allocator.destroy(c);
            self.remote_conn = null;
        }
        self.streams.deinit();
    }

    pub fn start(self: *Client) !void {
        logger.json(.info, "lifecycle", "starting", "{{\"remote_host\":\"{s}\",\"remote_port\":{d}}}", .{ Config.remote_host, Config.remote_port });
        try self.connectH2();

        const reader_th = try std.Thread.spawn(.{}, h2ReaderLoop, .{self});
        reader_th.detach();

        const ping_th = try std.Thread.spawn(.{}, keepAliveLoop, .{self});
        ping_th.detach();

        try self.startSocksListener();
    }

    fn connectH2(self: *Client) !void {
        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        logger.json(.debug, "dns", "resolve_start", "{{\"host\":\"{s}\"}}", .{Config.remote_host});
        if (!protocol.resolveDnsA(Config.remote_host, &octets)) {
            logger.json(.err, "dns", "resolve_failed", "{{\"host\":\"{s}\"}}", .{Config.remote_host});
            return error.DnsFailed;
        }
        logger.json(.info, "dns", "resolve_ok", "{{\"host\":\"{s}\",\"ip\":\"{d}.{d}.{d}.{d}\"}}", .{
            Config.remote_host, octets[0], octets[1], octets[2], octets[3],
        });

        const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) {
            logger.json(.err, "tcp", "socket_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(sock_rc))});
            return error.SocketFailed;
        }
        const fd: i32 = @intCast(sock_rc);

        protocol.setNoDelay(fd);

        const r_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.remote_port),
            .addr = @as(u32, @bitCast(octets)),
        };

        logger.json(.debug, "tcp", "connect_start", "{{\"fd\":{d},\"port\":{d}}}", .{ fd, Config.remote_port });
        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&r_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            logger.json(.err, "tcp", "connect_failed", "{{\"fd\":{d},\"rc\":{d}}}", .{ fd, @as(isize, @bitCast(conn_rc)) });
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));
            return error.ConnectFailed;
        }
        logger.json(.info, "tcp", "connect_ok", "{{\"fd\":{d}}}", .{fd});

        self.remote_conn = try RemoteConnection.init(self.allocator, fd, Config.remote_host);

        logger.json(.debug, "h2_tx", "send_preface", "{{\"len\":{d}}}", .{protocol.PREFACE.len});
        try self.writeTlsRaw(protocol.PREFACE);

        try self.sendH2Frame(.{
            .length = 0,
            .frame_type = protocol.FrameType.SETTINGS,
            .flags = protocol.Flags.NONE,
            .stream_id = 0,
        }, "");

        var hpack_buf: [256]u8 = undefined;
        const hpack_len = protocol.encodeClientGrpcHeaders(&hpack_buf, Config.remote_host, Config.grpc_path);
        logger.json(.debug, "h2_tx", "send_client_headers", "{{\"stream_id\":1,\"hpack_len\":{d},\"path\":\"{s}\"}}", .{ hpack_len, Config.grpc_path });

        try self.sendH2Frame(.{
            .length = @intCast(hpack_len),
            .frame_type = protocol.FrameType.HEADERS,
            .flags = protocol.Flags.END_HEADERS,
            .stream_id = 1,
        }, hpack_buf[0..hpack_len]);

        logger.json(.info, "h2_session", "tunnel_ready", "{{\"stream_id\":1}}", .{});
    }

    fn writeTlsRaw(self: *Client, bytes: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        try self.remote_conn.?.tls_client.?.writer.writeAll(bytes);
        try self.remote_conn.?.tls_client.?.writer.flush();
        try self.remote_conn.?.direct_writer.writer.flush();
    }

    pub fn sendH2Frame(self: *Client, hdr: protocol.FrameHeader, payload: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();

        if (!self.running.load(.acquire) or self.remote_conn == null) {
            return error.NotConnected;
        }

        var h_buf: [9]u8 = undefined;
        hdr.serialize(&h_buf);

        logger.json(.debug, "h2_tx", "frame", "{{\"type\":{d},\"flags\":{d},\"stream_id\":{d},\"len\":{d}}}", .{
            hdr.frame_type, hdr.flags, hdr.stream_id, hdr.length,
        });

        const conn = self.remote_conn orelse return error.NotConnected;
        if (conn.tls_client) |*tls_cl| {
            try tls_cl.writer.writeAll(&h_buf);
            if (payload.len > 0) {
                try tls_cl.writer.writeAll(payload);
            }
            try tls_cl.writer.flush();
            try conn.direct_writer.writer.flush();
        } else {
            return error.NotConnected;
        }
    }

    pub fn sendTunnelPacket(self: *Client, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
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

        logger.json(.debug, "tunnel_tx", "packet", "{{\"cmd\":{d},\"stream_id\":{d},\"payload_len\":{d},\"total_data_len\":{d}}}", .{
            @intFromEnum(cmd), stream_id, payload.len, total_data_len,
        });

        try self.sendH2Frame(.{
            .length = @intCast(total_data_len),
            .frame_type = protocol.FrameType.DATA,
            .flags = protocol.Flags.NONE,
            .stream_id = 1,
        }, frame_buf[0..total_data_len]);
    }

    fn h2ReaderLoop(self: *Client) void {
        var hdr_buf: [9]u8 = undefined;
        logger.json(.info, "h2_rx", "reader_loop_started", "{{}}", .{});

        while (self.running.load(.acquire)) {
            self.remote_conn.?.readExact(&hdr_buf) catch |err| {
                logger.json(.err, "h2_rx", "read_header_error", "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                break;
            };
            const frame = protocol.FrameHeader.deserialize(&hdr_buf);

            logger.json(.debug, "h2_rx", "frame_header", "{{\"type\":{d},\"flags\":{d},\"stream_id\":{d},\"length\":{d}}}", .{
                frame.frame_type, frame.flags, frame.stream_id, frame.length,
            });

            const payload = self.allocator.alloc(u8, frame.length) catch |err| {
                logger.json(.err, "h2_rx", "alloc_payload_error", "{{\"error\":\"{s}\",\"len\":{d}}}", .{ @errorName(err), frame.length });
                break;
            };
            defer self.allocator.free(payload);
            self.remote_conn.?.readExact(payload) catch |err| {
                logger.json(.err, "h2_rx", "read_payload_error", "{{\"error\":\"{s}\",\"expected\":{d}}}", .{ @errorName(err), frame.length });
                break;
            };

            switch (frame.frame_type) {
                protocol.FrameType.HEADERS => {
                    var hex_buf: [64]u8 = undefined;
                    const preview_len = @min(payload.len, 16);
                    const hex_str = sliceToHex(payload[0..preview_len], &hex_buf);
                    logger.json(.warn, "h2_rx", "headers_received", "{{\"stream_id\":{d},\"len\":{d},\"flags\":{d},\"preview_hex\":\"{s}\"}}", .{
                        frame.stream_id, frame.length, frame.flags, hex_str,
                    });
                },
                protocol.FrameType.DATA => {
                    logger.json(.debug, "h2_rx", "data_received", "{{\"stream_id\":{d},\"len\":{d}}}", .{ frame.stream_id, frame.length });
                    self.handleIncomingData(payload);

                    self.accumulated_window += frame.length;
                    if (self.accumulated_window >= Config.window_update_threshold) {
                        logger.json(.debug, "h2_tx", "window_update", "{{\"window\":{d}}}", .{self.accumulated_window});
                        self.sendWindowUpdate(0, self.accumulated_window) catch {};
                        self.sendWindowUpdate(1, self.accumulated_window) catch {};
                        self.accumulated_window = 0;
                    }
                },
                protocol.FrameType.SETTINGS => {
                    logger.json(.debug, "h2_rx", "settings", "{{\"flags\":{d},\"len\":{d}}}", .{ frame.flags, frame.length });
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        logger.json(.debug, "h2_tx", "settings_ack", "{{}}", .{});
                        self.sendH2Frame(.{
                            .length = 0,
                            .frame_type = protocol.FrameType.SETTINGS,
                            .flags = protocol.Flags.ACK,
                            .stream_id = 0,
                        }, "") catch {};
                    }
                },
                protocol.FrameType.PING => {
                    logger.json(.debug, "h2_rx", "ping", "{{\"flags\":{d}}}", .{frame.flags});
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        logger.json(.debug, "h2_tx", "ping_ack", "{{}}", .{});
                        self.sendH2Frame(.{
                            .length = 8,
                            .frame_type = protocol.FrameType.PING,
                            .flags = protocol.Flags.ACK,
                            .stream_id = 0,
                        }, payload) catch {};
                    }
                },
                protocol.FrameType.WINDOW_UPDATE => {
                    const inc = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF else 0;
                                        logger.json(.debug, "h2_rx", "window_update_received", "{{\"stream_id\":{d},\"increment\":{d}}}", .{ frame.stream_id, inc });
                },
                protocol.FrameType.RST_STREAM => {
                    const error_code = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                    logger.json(.err, "h2_rx", "rst_stream", "{{\"stream_id\":{d},\"error_code\":{d}}}", .{ frame.stream_id, error_code });
                    break;
                },
                protocol.FrameType.GOAWAY => {
                    const last_id = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                    const error_code = if (payload.len >= 8) std.mem.readInt(u32, payload[4..8], .big) else 0;
                    logger.json(.err, "h2_rx", "goaway", "{{\"last_stream_id\":{d},\"error_code\":{d},\"payload_len\":{d}}}", .{
                        last_id, error_code, payload.len,
                    });
                    break;
                },
                else => {
                    logger.json(.debug, "h2_rx", "unhandled_frame", "{{\"type\":{d},\"len\":{d}}}", .{ frame.frame_type, frame.length });
                },
            }
        }

        logger.json(.err, "h2_session", "reader_loop_terminated", "{{}}", .{});
        self.running.store(false, .release);

        self.streams_mutex.lock();
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            if (s.active.swap(false, .acq_rel)) {
                s.stream.close();
                s.connected_event.set();
            }
        }
        self.streams_mutex.unlock();
    }

    fn sendWindowUpdate(self: *Client, stream_id: u31, increment: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, increment & 0x7FFFFFFF, .big);
        try self.sendH2Frame(.{
            .length = 4,
            .frame_type = protocol.FrameType.WINDOW_UPDATE,
            .flags = protocol.Flags.NONE,
            .stream_id = stream_id,
        }, &buf);
    }

    fn handleIncomingData(self: *Client, data: []const u8) void {
        if (self.rx_len + data.len > self.rx_buf.len) {
            logger.json(.err, "tunnel_rx", "rx_buffer_overflow", "{{\"rx_len\":{d},\"incoming\":{d}}}", .{ self.rx_len, data.len });
            self.rx_len = 0;
            return;
        }

        @memcpy(self.rx_buf[self.rx_len .. self.rx_len + data.len], data);
        self.rx_len += data.len;

        var offset: usize = 0;
        while (offset + 5 <= self.rx_len) {
            const grpc_len = std.mem.readInt(u32, self.rx_buf[offset + 1 ..][0..4], .big);
            const total_msg_len = 5 + grpc_len;
            if (offset + total_msg_len > self.rx_len) {
                logger.json(.debug, "tunnel_rx", "partial_grpc_buffered", "{{\"grpc_len\":{d},\"avail\":{d}}}", .{ grpc_len, self.rx_len - offset });
                break;
            }

            if (grpc_len < @sizeOf(protocol.TunnelHeader)) {
                logger.json(.err, "tunnel_rx", "malformed_grpc_len", "{{\"grpc_len\":{d}}}", .{grpc_len});
                offset += total_msg_len;
                continue;
            }

            var th: protocol.TunnelHeader = undefined;
            @memcpy(std.mem.asBytes(&th), self.rx_buf[offset + 5 .. offset + 5 + @sizeOf(protocol.TunnelHeader)]);

            if (th.magic != 0x5650) {
                logger.json(.err, "tunnel_rx", "invalid_magic", "{{\"magic\":{d}}}", .{th.magic});
                offset += total_msg_len;
                continue;
            }

            const payload = self.rx_buf[offset + 5 + @sizeOf(protocol.TunnelHeader) .. offset + 5 + @sizeOf(protocol.TunnelHeader) + th.payload_len];
            offset += total_msg_len;

            logger.json(.debug, "tunnel_rx", "packet", "{{\"cmd\":{d},\"stream_id\":{d},\"payload_len\":{d}}}", .{
                @intFromEnum(th.cmd), th.stream_id, th.payload_len,
            });

            self.streams_mutex.lock();
            const s_opt = self.streams.get(th.stream_id);
            self.streams_mutex.unlock();

            if (th.cmd == .log) {
                _ = std.os.linux.syscall3(.write, 2, @intFromPtr(payload.ptr), payload.len);
                const nl: [1]u8 = .{10};
                _ = std.os.linux.syscall3(.write, 2, @intFromPtr(&nl), 1);
            } else if (s_opt) |s| {
                switch (th.cmd) {
                    .connect_ok => {
                        logger.json(.info, "stream", "connect_ok", "{{\"stream_id\":{d}}}", .{th.stream_id});
                        s.connect_success = true;
                        s.connected_event.set();
                    },
                    .connect_fail => {
                        logger.json(.warn, "stream", "connect_fail", "{{\"stream_id\":{d}}}", .{th.stream_id});
                        s.connect_success = false;
                        s.connected_event.set();
                    },
                    .data => {
                        logger.json(.debug, "stream", "data_rx", "{{\"stream_id\":{d},\"len\":{d}}}", .{ th.stream_id, payload.len });
                        s.stream.writeAll(payload) catch |err| {
                            logger.json(.err, "stream", "write_local_error", "{{\"stream_id\":{d},\"error\":\"{s}\"}}", .{ th.stream_id, @errorName(err) });
                            self.closeStream(s.id);
                        };
                    },
                    .close => {
                        logger.json(.info, "stream", "remote_close", "{{\"stream_id\":{d}}}", .{th.stream_id});
                        self.closeStream(s.id);
                    },
                    else => {
                        logger.json(.warn, "stream", "unknown_cmd", "{{\"stream_id\":{d},\"cmd\":{d}}}", .{ th.stream_id, @intFromEnum(th.cmd) });
                    },
                }
            } else {
                logger.json(.warn, "tunnel_rx", "orphan_stream", "{{\"stream_id\":{d},\"cmd\":{d}}}", .{ th.stream_id, @intFromEnum(th.cmd) });
            }
        }

        if (offset > 0) {
            const remaining = self.rx_len - offset;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.rx_buf[0..remaining], self.rx_buf[offset .. self.rx_len]);
            }
            self.rx_len = remaining;
        }
    }

    pub fn closeStream(self: *Client, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const s = entry.value;
            if (s.active.swap(false, .acq_rel)) {
                logger.json(.info, "stream", "closing", "{{\"stream_id\":{d}}}", .{stream_id});
                s.stream.shutdown();
                s.stream.close();
                self.sendTunnelPacket(.close, stream_id, "") catch {};
            }
        }
    }

    fn keepAliveLoop(self: *Client) void {
        while (self.running.load(.acquire)) {
            sleepMs(20_000);
            if (!self.running.load(.acquire)) break;
            logger.json(.debug, "h2_tx", "ping_keepalive", "{{}}", .{});
            self.sendH2Frame(.{
                .length = 8,
                .frame_type = protocol.FrameType.PING,
                .flags = protocol.Flags.NONE,
                .stream_id = 0,
            }, "\x00\x00\x00\x00\x00\x00\x00\x00") catch |err| {
                logger.json(.err, "h2_tx", "ping_failed", "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                break;
            };
        }
    }

    fn startSocksListener(self: *Client) !void {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) {
            logger.json(.err, "socks5", "socket_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(rc))});
            return error.SocketFailed;
        }
        const listen_fd: i32 = @intCast(rc);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, listen_fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

        var octets: [4]u8 = .{ 127, 0, 0, 1 };
        _ = protocol.parseIp4(Config.socks_host, &octets);

        const addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.socks_port),
            .addr = @as(u32, @bitCast(octets)),
        };
        const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(bind_rc)) < 0) {
            logger.json(.err, "socks5", "bind_failed", "{{\"port\":{d},\"rc\":{d}}}", .{ Config.socks_port, @as(isize, @bitCast(bind_rc)) });
            return error.BindFailed;
        }

        const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);
        if (@as(isize, @bitCast(listen_rc)) < 0) {
            logger.json(.err, "socks5", "listen_failed", "{{\"rc\":{d}}}", .{@as(isize, @bitCast(listen_rc))});
            return error.ListenFailed;
        }

        logger.json(.info, "socks5", "listening", "{{\"host\":\"{s}\",\"port\":{d}}}", .{ Config.socks_host, Config.socks_port });

        while (self.running.load(.acquire)) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            logger.json(.info, "socks5", "accepted_client", "{{\"fd\":{d}}}", .{client_fd});
            protocol.setNoDelay(client_fd);

            const stream = protocol.SocketStream{ .handle = client_fd };
            const th = std.Thread.spawn(.{}, handleSocksClient, .{ self, stream }) catch |err| {
                logger.json(.err, "socks5", "spawn_client_handler_failed", "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                stream.close();
                continue;
            };
            th.detach();
        }

        logger.json(.warn, "socks5", "listener_stopped", "{{}}", .{});
    }

    fn handleSocksClient(self: *Client, stream: protocol.SocketStream) void {
        defer stream.close();

        var buf: [512]u8 = undefined;
        var rd = stream.read(&buf) catch |err| {
            logger.json(.err, "socks5", "read_auth_error", "{{\"fd\":{d},\"error\":\"{s}\"}}", .{ stream.handle, @errorName(err) });
            return;
        };

        if (rd < 3 or buf[0] != 5) {
            logger.json(.warn, "socks5", "invalid_auth_packet", "{{\"fd\":{d},\"bytes\":{d}}}", .{ stream.handle, rd });
            return;
        }

        stream.writeAll("\x05\x00") catch |err| {
            logger.json(.err, "socks5", "write_auth_reply_error", "{{\"fd\":{d},\"error\":\"{s}\"}}", .{ stream.handle, @errorName(err) });
            return;
        };

        rd = stream.read(&buf) catch |err| {
            logger.json(.err, "socks5", "read_req_error", "{{\"fd\":{d},\"error\":\"{s}\"}}", .{ stream.handle, @errorName(err) });
            return;
        };

        if (rd < 7 or buf[0] != 5 or buf[1] != 1) {
            logger.json(.warn, "socks5", "unsupported_req", "{{\"fd\":{d},\"cmd\":{d}}}", .{ stream.handle, if (rd > 1) buf[1] else 0 });
            _ = stream.writeAll("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            return;
        }

        const sid = self.next_stream_id.fetchAdd(1, .monotonic);
        const s = self.allocator.create(ClientStream) catch |err| {
            logger.json(.err, "socks5", "alloc_stream_failed", "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            return;
        };
        s.* = .{
            .id = sid,
            .stream = stream,
        };

        self.streams_mutex.lock();
        self.streams.put(sid, s) catch |err| {
            self.streams_mutex.unlock();
            logger.json(.err, "socks5", "put_stream_failed", "{{\"stream_id\":{d},\"error\":\"{s}\"}}", .{ sid, @errorName(err) });
            return;
        };
        self.streams_mutex.unlock();

        const conn_payload = buf[3..rd];
        logger.json(.info, "stream", "request_connect", "{{\"stream_id\":{d},\"payload_len\":{d}}}", .{ sid, conn_payload.len });

        self.sendTunnelPacket(.connect, sid, conn_payload) catch |err| {
            logger.json(.err, "stream", "send_tunnel_connect_failed", "{{\"stream_id\":{d},\"error\":\"{s}\"}}", .{ sid, @errorName(err) });
            self.closeStream(sid);
            return;
        };

        logger.json(.debug, "stream", "waiting_remote_ack", "{{\"stream_id\":{d}}}", .{sid});
        const wait_ok = s.connected_event.wait(8000);

        if (!wait_ok or !s.connect_success) {
            logger.json(.err, "stream", "connect_failed_or_timeout", "{{\"stream_id\":{d},\"wait_ok\":{s},\"success\":{s}}}", .{
                sid,
                if (wait_ok) "true" else "false",
                if (s.connect_success) "true" else "false",
            });
            _ = stream.writeAll("\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            self.closeStream(sid);
            return;
        }

        logger.json(.info, "stream", "connect_success_replying_socks", "{{\"stream_id\":{d}}}", .{sid});
        stream.writeAll("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") catch |err| {
            logger.json(.err, "socks5", "write_success_reply_failed", "{{\"stream_id\":{d},\"error\":\"{s}\"}}", .{ sid, @errorName(err) });
            self.closeStream(sid);
            return;
        };

        var data_buf: [Config.max_chunk_payload]u8 = undefined;
        while (s.active.load(.acquire)) {
            const bytes_read = stream.read(&data_buf) catch 0;
            if (bytes_read == 0) {
                logger.json(.info, "stream", "local_client_eof", "{{\"stream_id\":{d}}}", .{sid});
                break;
            }
            logger.json(.debug, "stream", "local_data_fwd", "{{\"stream_id\":{d},\"bytes\":{d}}}", .{ sid, bytes_read });
            self.sendTunnelPacket(.data, sid, data_buf[0..bytes_read]) catch |err| {
                logger.json(.err, "stream", "fwd_tunnel_data_error", "{{\"stream_id\":{d},\"error\":\"{s}\"}}", .{ sid, @errorName(err) });
                break;
            };
        }

        self.closeStream(sid);
    }
};

fn sleepMs(ms: u64) void {
    const timespec = extern struct { sec: i64, nsec: i64 };
    const ts = timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.syscall2(.nanosleep, @intFromPtr(&ts), 0);
}
