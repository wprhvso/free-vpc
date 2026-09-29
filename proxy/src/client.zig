const BufferWriter = struct {
    buf: []u8,
    pos: usize,

    pub fn writeAll(self: *BufferWriter, bytes: []const u8) !void {
        if (self.pos + bytes.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
};
const std = @import("std");
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const Config = @import("config.zig").Config;
const logger = @import("logger.zig");
const TlsClient = @import("tls_client.zig");
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

const POOL_SIZE = 6;

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
        var index: usize = 0;
        if (w.end > 0) {
            while (index < w.end) {
                const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(w.buffer.ptr + index), w.end - index);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) return error.WriteFailed;
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
            if (signed <= 0) return error.WriteFailed;
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
        _ = r;
        _ = w;
        _ = limit;
        return 0;
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const self: *DirectSocketReader = @alignCast(@fieldParentPtr("reader", r));
        if (data.len > 0 and data[0].len > 0) {
            const dest = data[0];
            const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(dest.ptr), dest.len);
            const signed: isize = @bitCast(rc);
            if (signed < 0) return error.ReadFailed;
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
        if (signed < 0) return error.ReadFailed;
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

        conn.tls_client = try TlsClient.init(
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
        );

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
        self.tls_client = null;
        if (self.fd >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
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
    conn_idx: usize = 0,
};

const PoolConn = struct {
    idx: usize,
    remote_conn: ?*RemoteConnection = null,
    write_mutex: futex.Mutex = .{},
    is_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    accumulated_window: u32 = 0,
    rx_buf: [64 * 1024]u8 = undefined,
    rx_len: usize = 0,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    pool: [POOL_SIZE]PoolConn = undefined,
    round_robin: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    streams_mutex: futex.Mutex = .{},
    streams: std.AutoHashMap(u32, *ClientStream),
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator) Client {
        var c = Client{
            .allocator = allocator,
            .streams = std.AutoHashMap(u32, *ClientStream).init(allocator),
        };
        for (0..POOL_SIZE) |i| {
            c.pool[i] = .{
                .idx = i,
                .remote_conn = null,
            };
        }
        return c;
    }

    pub fn deinit(self: *Client) void {
        self.running.store(false, .release);
        for (0..POOL_SIZE) |i| {
            if (self.pool[i].remote_conn) |conn| {
                conn.close();
                self.allocator.destroy(conn);
                self.pool[i].remote_conn = null;
            }
        }
        self.streams.deinit();
    }

    pub fn start(self: *Client) !void {
        logger.json(.info, "lifecycle", "starting", "{{\"remote_host\":\"{s}\",\"pool_size\":{d}}}", .{ Config.remote_host, POOL_SIZE });

        for (0..POOL_SIZE) |i| {
            const th = try std.Thread.spawn(.{}, connWorkerLoop, .{ self, i });
            th.detach();
        }

        // Ждем пока хотя бы один сокет реально подтвердит статус 200 от Cloudflare
        var ready = false;
        for (0..100) |_| {
            for (0..POOL_SIZE) |i| {
                if (self.pool[i].is_ready.load(.acquire)) {
                    ready = true;
                    break;
                }
            }
            if (ready) break;
            sleepMs(100);
        }

        try self.startSocksListener();
    }

    fn connWorkerLoop(self: *Client, idx: usize) void {
        const p = &self.pool[idx];
        while (self.running.load(.acquire)) {
            logger.json(.info, "pool", "connecting_socket", "{{\"idx\":{d}}}", .{idx});
            self.connectH2Ws(p) catch |err| {
                logger.json(.err, "pool", "connect_failed", "{{\"idx\":{d},\"error\":\"{s}\"}}", .{ idx, @errorName(err) });
                sleepMs(2000);
                continue;
            };

            // Читаем поток HTTP/2 (is_ready выставится внутри h2ReaderLoop ТОЛЬКО после получения :status 200)
            self.h2ReaderLoop(p);

            p.is_ready.store(false, .release);
            p.write_mutex.lock();
            if (p.remote_conn) |conn| {
                conn.close();
                self.allocator.destroy(conn);
                p.remote_conn = null;
            }
            p.write_mutex.unlock();
            sleepMs(1000);
        }
    }

    fn connectH2Ws(self: *Client, p: *PoolConn) !void {
        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        if (!protocol.resolveDnsA(Config.remote_host, &octets)) return error.DnsFailed;

        const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) return error.SocketFailed;
        const fd: i32 = @intCast(sock_rc);

        protocol.setNoDelay(fd);

        const r_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.remote_port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&r_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));
            return error.ConnectFailed;
        }

        const conn = try RemoteConnection.init(self.allocator, fd, Config.remote_host);

        p.write_mutex.lock();
        p.remote_conn = conn;
        p.rx_len = 0;
        p.accumulated_window = 0;
        p.write_mutex.unlock();

        // 1. Send Preface
        try self.writeTlsRaw(p, protocol.PREFACE);

        // 2. Send SETTINGS (enable_connect_protocol = 1)
        const settings_payload = "\x00\x08\x00\x00\x00\x01"; // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1
        try self.sendH2Frame(p, .{
            .length = settings_payload.len,
            .frame_type = protocol.FrameType.SETTINGS,
            .flags = protocol.Flags.NONE,
            .stream_id = 0,
        }, settings_payload);

        // 3. Send Extended CONNECT for WebSocket (RFC 8441)
        var hpack_buf: [256]u8 = undefined;
        const hpack_len = protocol.encodeClientWsHeaders(&hpack_buf, Config.remote_host, "/tunnel");
        try self.sendH2Frame(p, .{
            .length = @intCast(hpack_len),
            .frame_type = protocol.FrameType.HEADERS,
            .flags = protocol.Flags.END_HEADERS,
            .stream_id = 1,
        }, hpack_buf[0..hpack_len]);

        logger.json(.info, "pool", "handshake_sent", "{{\"idx\":{d}}}", .{p.idx});
    }

    fn writeTlsRaw(self: *Client, p: *PoolConn, bytes: []const u8) !void {
        _ = self;
        p.write_mutex.lock();
        defer p.write_mutex.unlock();
        if (p.remote_conn) |conn| {
            if (conn.tls_client) |*tls_cl| {
                try tls_cl.writer.writeAll(bytes);
                try tls_cl.writer.flush();
                try conn.direct_writer.writer.flush();
            }
        }
    }

    pub fn sendH2Frame(self: *Client, p: *PoolConn, hdr: protocol.FrameHeader, payload: []const u8) !void {
        _ = self;
        p.write_mutex.lock();
        defer p.write_mutex.unlock();

        if (p.remote_conn == null) return error.NotConnected;
        const conn = p.remote_conn orelse return error.NotConnected;

        var h_buf: [9]u8 = undefined;
        hdr.serialize(&h_buf);

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

    pub fn sendTunnelPacket(self: *Client, p: *PoolConn, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
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

        // Wrap into WebSocket Binary Frame (Client must mask!)
        var ws_buf: [Config.max_chunk_payload + 128]u8 = undefined;
        var bw = BufferWriter{ .buf = &ws_buf, .pos = 0 };
        const mask = [4]u8{ 0x1A, 0x2B, 0x3C, 0x4D };
        try ws.writeFrame(&bw, .binary, frame_buf[0..total_len], mask);

        const ws_bytes = ws_buf[0..bw.pos];

        // Send over H2 stream 1
        try self.sendH2Frame(p, .{
            .length = @intCast(ws_bytes.len),
            .frame_type = protocol.FrameType.DATA,
            .flags = protocol.Flags.NONE,
            .stream_id = 1,
        }, ws_bytes);
    }

    fn h2ReaderLoop(self: *Client, p: *PoolConn) void {
        var hdr_buf: [9]u8 = undefined;

        while (self.running.load(.acquire)) {
            p.remote_conn.?.readExact(&hdr_buf) catch break;
            const frame = protocol.FrameHeader.deserialize(&hdr_buf);

            const payload = self.allocator.alloc(u8, frame.length) catch break;
            defer self.allocator.free(payload);
            p.remote_conn.?.readExact(payload) catch break;

            switch (frame.frame_type) {
                protocol.FrameType.HEADERS => {
                    if (frame.stream_id == 1) {
                        const status = protocol.decodeHpackStatus(payload);
                        if (status) |st| {
                            logger.json(.info, "h2", "handshake_status", "{{\"idx\":{d},\"status\":{d}}}", .{ p.idx, st });
                            if (st == 200) {
                                p.is_ready.store(true, .release);
                                logger.json(.info, "pool", "socket_ready", "{{\"idx\":{d}}}", .{p.idx});
                            } else {
                                logger.json(.err, "pool", "handshake_failed", "{{\"idx\":{d},\"status\":{d}}}", .{ p.idx, st });
                                break;
                            }
                        } else {
                            logger.json(.warn, "h2", "headers_without_status", "{{\"idx\":{d}}}", .{p.idx});
                        }
                    }
                },
                protocol.FrameType.DATA => {
                    self.handleIncomingWsData(p, payload);

                    p.accumulated_window += frame.length;
                    if (p.accumulated_window >= Config.window_update_threshold) {
                        var buf: [4]u8 = undefined;
                        std.mem.writeInt(u32, &buf, p.accumulated_window & 0x7FFFFFFF, .big);
                        self.sendH2Frame(p, .{ .length = 4, .frame_type = protocol.FrameType.WINDOW_UPDATE, .flags = protocol.Flags.NONE, .stream_id = 0 }, &buf) catch {};
                        self.sendH2Frame(p, .{ .length = 4, .frame_type = protocol.FrameType.WINDOW_UPDATE, .flags = protocol.Flags.NONE, .stream_id = 1 }, &buf) catch {};
                        p.accumulated_window = 0;
                    }
                },
                protocol.FrameType.SETTINGS => {
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        self.sendH2Frame(p, .{ .length = 0, .frame_type = protocol.FrameType.SETTINGS, .flags = protocol.Flags.ACK, .stream_id = 0 }, "") catch {};
                    }
                },
                protocol.FrameType.PING => {
                    if ((frame.flags & protocol.Flags.ACK) == 0) {
                        self.sendH2Frame(p, .{ .length = 8, .frame_type = protocol.FrameType.PING, .flags = protocol.Flags.ACK, .stream_id = 0 }, payload) catch {};
                    }
                },
                protocol.FrameType.WINDOW_UPDATE => {},
                protocol.FrameType.RST_STREAM => {
                    logger.json(.err, "h2", "rst_stream", "{{\"idx\":{d},\"stream_id\":{d}}}", .{ p.idx, frame.stream_id });
                    break;
                },
                protocol.FrameType.GOAWAY => {
                    logger.json(.err, "h2", "goaway", "{{\"idx\":{d}}}", .{p.idx});
                    break;
                },
                else => {},
            }
        }
    }

    fn handleIncomingWsData(self: *Client, p: *PoolConn, data: []const u8) void {
        if (p.rx_len + data.len > p.rx_buf.len) {
            p.rx_len = 0;
            return;
        }
        @memcpy(p.rx_buf[p.rx_len .. p.rx_len + data.len], data);
        p.rx_len += data.len;

        var offset: usize = 0;
        while (offset + 2 <= p.rx_len) {
            const b0 = p.rx_buf[offset];
            const b1 = p.rx_buf[offset + 1];
            const opcode: ws.Opcode = @enumFromInt(@as(u4, @intCast(b0 & 0x0F)));
            const is_masked = (b1 & 0x80) != 0;
            var payload_len: u64 = b1 & 0x7F;
            var hdr_size: usize = 2;

            if (payload_len == 126) {
                if (offset + 4 > p.rx_len) break;
                payload_len = std.mem.readInt(u16, p.rx_buf[offset + 2 ..][0..2], .big);
                hdr_size = 4;
            } else if (payload_len == 127) {
                if (offset + 10 > p.rx_len) break;
                payload_len = std.mem.readInt(u64, p.rx_buf[offset + 2 ..][0..8], .big);
                hdr_size = 10;
            }

            var mask: [4]u8 = .{ 0, 0, 0, 0 };
            if (is_masked) {
                if (offset + hdr_size + 4 > p.rx_len) break;
                @memcpy(&mask, p.rx_buf[offset + hdr_size .. offset + hdr_size + 4]);
                hdr_size += 4;
            }

            const total_frame_len = hdr_size + payload_len;
            if (offset + total_frame_len > p.rx_len) break;

            const frame_payload = p.rx_buf[offset + hdr_size .. offset + total_frame_len];
            if (is_masked) {
                ws.applyMask(frame_payload, mask);
            }
            offset += total_frame_len;

            switch (opcode) {
                .binary => self.handleTunnelPacket(p, frame_payload),
                .ping => {
                    var ws_buf: [128]u8 = undefined;
                    var bw = BufferWriter{ .buf = &ws_buf, .pos = 0 };
                    const m = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
                    ws.writeFrame(&bw, .pong, frame_payload, m) catch {};
                    const written = ws_buf[0..bw.pos];
                    self.sendH2Frame(p, .{ .length = @intCast(written.len), .frame_type = protocol.FrameType.DATA, .flags = protocol.Flags.NONE, .stream_id = 1 }, written) catch {};
                },
                .close => break,
                else => {},
            }
        }

        if (offset > 0) {
            const remaining = p.rx_len - offset;
            if (remaining > 0) {
                std.mem.copyForwards(u8, p.rx_buf[0..remaining], p.rx_buf[offset .. p.rx_len]);
            }
            p.rx_len = remaining;
        }
    }

    fn handleTunnelPacket(self: *Client, p: *PoolConn, data: []const u8) void {
        _ = p;
        if (data.len < @sizeOf(protocol.TunnelHeader)) return;
        var th: protocol.TunnelHeader = undefined;
        @memcpy(std.mem.asBytes(&th), data[0..@sizeOf(protocol.TunnelHeader)]);

        if (th.magic != 0x5650) return;
        const payload = data[@sizeOf(protocol.TunnelHeader) .. @sizeOf(protocol.TunnelHeader) + th.payload_len];

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
                    s.stream.writeAll(payload) catch {
                        self.closeStream(s.id);
                    };
                },
                .close => {
                    self.closeStream(s.id);
                },
                else => {},
            }
        }
    }

    pub fn closeStream(self: *Client, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const s = entry.value;
            if (s.active.swap(false, .acq_rel)) {
                s.stream.shutdown();
                s.stream.close();
                const p = &self.pool[s.conn_idx];
                self.sendTunnelPacket(p, .close, stream_id, "") catch {};
            }
        }
    }

    fn getNextReadyConn(self: *Client) ?*PoolConn {
        for (0..POOL_SIZE) |_| {
            const idx = self.round_robin.fetchAdd(1, .monotonic) % POOL_SIZE;
            if (self.pool[idx].is_ready.load(.acquire)) {
                return &self.pool[idx];
            }
        }
        return null;
    }

    fn startSocksListener(self: *Client) !void {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const listen_fd: i32 = @intCast(rc);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        const one: c_int = 1;
        _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, listen_fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        _ = protocol.parseIp4(Config.socks_host, &octets);

        const addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, Config.socks_port),
            .addr = @as(u32, @bitCast(octets)),
        };
        const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(bind_rc)) < 0) return error.BindFailed;

        const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);
        if (@as(isize, @bitCast(listen_rc)) < 0) return error.ListenFailed;

        logger.json(.info, "socks5", "listening", "{{\"host\":\"{s}\",\"port\":{d}}}", .{ Config.socks_host, Config.socks_port });

        while (self.running.load(.acquire)) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            protocol.setNoDelay(client_fd);
            const stream = protocol.SocketStream{ .handle = client_fd };

            const th = std.Thread.spawn(.{}, handleSocksClient, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
        }
    }

    fn handleSocksClient(self: *Client, stream: protocol.SocketStream) void {
        defer stream.close();

        var buf: [512]u8 = undefined;
        var rd = stream.read(&buf) catch return;
        if (rd < 3 or buf[0] != 5) return;
        stream.writeAll("\x05\x00") catch return;

        rd = stream.read(&buf) catch return;
        if (rd < 7 or buf[0] != 5 or buf[1] != 1) {
            _ = stream.writeAll("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            return;
        }

        const p = self.getNextReadyConn() orelse {
            logger.json(.err, "pool", "no_ready_sockets", "{{}}", .{});
            _ = stream.writeAll("\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            return;
        };

        const sid = self.next_stream_id.fetchAdd(1, .monotonic);
        const s = self.allocator.create(ClientStream) catch return;
        s.* = .{
            .id = sid,
            .stream = stream,
            .conn_idx = p.idx,
        };

        self.streams_mutex.lock();
        self.streams.put(sid, s) catch {
            self.streams_mutex.unlock();
            return;
        };
        self.streams_mutex.unlock();

        const conn_payload = buf[3..rd];
        self.sendTunnelPacket(p, .connect, sid, conn_payload) catch {
            self.closeStream(sid);
            return;
        };

        if (!s.connected_event.wait(8000) or !s.connect_success) {
            _ = stream.writeAll("\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            self.closeStream(sid);
            return;
        }

        stream.writeAll("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") catch return;

        var data_buf: [Config.max_chunk_payload]u8 = undefined;
        while (s.active.load(.acquire)) {
            const bytes_read = stream.read(&data_buf) catch 0;
            if (bytes_read == 0) break;
            self.sendTunnelPacket(p, .data, sid, data_buf[0..bytes_read]) catch break;
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
