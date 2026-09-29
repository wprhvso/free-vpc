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

const DirectSocketWriter = struct {
    fd: i32,
    raw_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
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
    raw_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
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
            if (signed < 0) return error.ReadFailed;
            if (signed == 0) return error.EndOfStream;
            return @intCast(signed);
        }

        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
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
    tls_client: ?std.crypto.tls.Client = null,
    tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,

    pub fn init(fd: i32, host: []const u8) !RemoteConnection {
        var conn = RemoteConnection{ .fd = fd };
        conn.direct_reader.setup(fd);
        conn.direct_writer.setup(fd);

        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

        var ts: std.posix.timespec = undefined;
        _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
        const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

        conn.tls_client = try std.crypto.tls.Client.init(
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

    pub fn readByte(self: *RemoteConnection) !u8 {
        const slice = try self.tls_client.?.reader.peekGreedy(1);
        if (slice.len == 0) return error.ConnectionClosed;
        const b = slice[0];
        self.tls_client.?.reader.toss(1);
        return b;
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
                continue;
            }
            const b = try self.readByte();
            dest[total] = b;
            total += 1;
        }
    }

    pub fn close(self: *RemoteConnection) void {
        if (self.tls_client) |*tc| tc.end() catch {};
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
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    remote_conn: ?RemoteConnection = null,
    write_mutex: futex.Mutex = .{},
    streams_mutex: futex.Mutex = .{},
    streams: std.AutoHashMap(u32, *ClientStream),
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    accumulated_window: u32 = 0,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator) Client {
        return .{
            .allocator = allocator,
            .streams = std.AutoHashMap(u32, *ClientStream).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.remote_conn) |*c| c.close();
        self.streams.deinit();
    }

    pub fn start(self: *Client) !void {
        _ = std.os.linux.syscall3(.write, 1, @intFromPtr("[CLIENT] Establishing HTTP/2 gRPC tunnel to Cloudflare...\n"), 58);
        try self.connectH2();

        const reader_th = try std.Thread.spawn(.{}, h2ReaderLoop, .{self});
        reader_th.detach();

        const ping_th = try std.Thread.spawn(.{}, keepAliveLoop, .{self});
        ping_th.detach();

        try self.startSocksListener();
    }

    fn connectH2(self: *Client) !void {
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

        self.remote_conn = try RemoteConnection.init(fd, Config.remote_host);

        // 1. Отправляем Client Preface
        try self.writeTlsRaw(protocol.PREFACE);

        // 2. Отправляем начальный пустой SETTINGS (Stream 0)
        try self.sendH2Frame(.{
            .length = 0,
            .frame_type = protocol.FrameType.SETTINGS,
            .flags = protocol.Flags.NONE,
            .stream_id = 0,
        }, "");

        // 3. Отправляем gRPC HEADERS (Stream 1)
        var hpack_buf: [256]u8 = undefined;
        const hpack_len = protocol.encodeClientGrpcHeaders(&hpack_buf, Config.remote_host, Config.grpc_path);
        try self.sendH2Frame(.{
            .length = @intCast(hpack_len),
            .frame_type = protocol.FrameType.HEADERS,
            .flags = protocol.Flags.END_HEADERS,
            .stream_id = 1,
        }, hpack_buf[0..hpack_len]);

        _ = std.os.linux.syscall3(.write, 1, @intFromPtr("[CLIENT] HTTP/2 gRPC bidi-stream established!\n"), 46);
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

        var h_buf: [9]u8 = undefined;
        hdr.serialize(&h_buf);
        try self.remote_conn.?.tls_client.?.writer.writeAll(&h_buf);
        if (payload.len > 0) {
            try self.remote_conn.?.tls_client.?.writer.writeAll(payload);
        }
        try self.remote_conn.?.tls_client.?.writer.flush();
        try self.remote_conn.?.direct_writer.writer.flush();
    }

    pub fn sendTunnelPacket(self: *Client, cmd: protocol.TunnelCmd, stream_id: u32, payload: []const u8) !void {
        var frame_buf: [Config.max_chunk_payload + 64]u8 = undefined;

        const tunnel_len: u32 = @intCast(@sizeOf(protocol.TunnelHeader) + payload.len);
        frame_buf[0] = 0; // gRPC uncompressed
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
            .stream_id = 1,
        }, frame_buf[0..total_data_len]);
    }

    fn h2ReaderLoop(self: *Client) void {
        var hdr_buf: [9]u8 = undefined;

        while (self.running.load(.acquire)) {
            self.remote_conn.?.readExact(&hdr_buf) catch break;
            const frame = protocol.FrameHeader.deserialize(&hdr_buf);

            const payload = self.allocator.alloc(u8, frame.length) catch break;
            defer self.allocator.free(payload);
            self.remote_conn.?.readExact(payload) catch break;

            switch (frame.frame_type) {
                protocol.FrameType.DATA => {
                    self.handleIncomingData(payload);

                    // Flow Control: пополняем окно каждые 32 КБ
                    self.accumulated_window += frame.length;
                    if (self.accumulated_window >= Config.window_update_threshold) {
                        self.sendWindowUpdate(0, self.accumulated_window) catch {};
                        self.sendWindowUpdate(1, self.accumulated_window) catch {};
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
                protocol.FrameType.GOAWAY, protocol.FrameType.RST_STREAM => break,
                else => {},
            }
        }
        self.running.store(false, .release);
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

            self.streams_mutex.lock();
            const s_opt = self.streams.get(th.stream_id);
            self.streams_mutex.unlock();

            if (s_opt) |s| {
                switch (th.cmd) {
                    .connect_ok => {
                        s.connect_success = true;
                        s.connected_event.set();
                    },
                    .connect_fail => {
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
                self.sendTunnelPacket(.close, stream_id, "") catch {};
            }
        }
    }

    fn keepAliveLoop(self: *Client) void {
        while (self.running.load(.acquire)) {
            sleepMs(20_000);
            if (!self.running.load(.acquire)) break;
            self.sendH2Frame(.{
                .length = 8,
                .frame_type = protocol.FrameType.PING,
                .flags = protocol.Flags.NONE,
                .stream_id = 0,
            }, "\x00\x00\x00\x00\x00\x00\x00\x00") catch break;
        }
    }

    fn startSocksListener(self: *Client) !void {
        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
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
        _ = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
        _ = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, listen_fd))), 128);

        _ = std.os.linux.syscall3(.write, 1, @intFromPtr("[SOCKS5] Ready on 127.0.0.1:1080\n"), 33);

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
        stream.writeAll("\x05\x00") catch return; // No authentication required

        rd = stream.read(&buf) catch return;
        if (rd < 7 or buf[0] != 5 or buf[1] != 1) { // CONNECT command
            _ = stream.writeAll("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00") catch {};
            return;
        }

        const sid = self.next_stream_id.fetchAdd(1, .monotonic);
        const s = self.allocator.create(ClientStream) catch return;
        s.* = .{
            .id = sid,
            .stream = stream,
        };

        self.streams_mutex.lock();
        self.streams.put(sid, s) catch {
            self.streams_mutex.unlock();
            return;
        };
        self.streams_mutex.unlock();

        const conn_payload = buf[3..rd]; // atyp + host + port
        self.sendTunnelPacket(.connect, sid, conn_payload) catch {
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
            self.sendTunnelPacket(.data, sid, data_buf[0..bytes_read]) catch break;
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
