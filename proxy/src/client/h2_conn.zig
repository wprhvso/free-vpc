const std = @import("std");
const net = @import("../common/net.zig");
const sync = @import("../common/sync.zig");
const h2 = @import("../common/h2_frame.zig");
const logger = @import("../common/logger.zig");
const hpack = @import("../common/static_hpack.zig");
const TlsClient = @import("../common/tls_client.zig");

pub const DirectSocketWriter = struct {
    fd: i32,
    raw_buf: [TlsClient.min_buffer_len]u8 = undefined,
    writer: std.Io.Writer = undefined,

    pub fn setup(self: *DirectSocketWriter, fd: i32) void {
        self.fd = fd;
        self.writer = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .drain = sockDrain,
                .flush = sockFlush,
            },
        };
    }

    fn sockDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        try sockFlush(w);
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

    fn sockFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
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

pub const DirectSocketReader = struct {
    fd: i32,
    raw_buf: [TlsClient.min_buffer_len]u8 = undefined,
    reader: std.Io.Reader = undefined,

    pub fn setup(self: *DirectSocketReader, fd: i32) void {
        self.fd = fd;
        self.reader = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .stream = sockStream,
                .readVec = sockReadVec,
            },
            .seek = 0,
            .end = 0,
        };
    }

    fn sockStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = r; _ = w; _ = limit;
        return 0;
    }

    fn sockReadVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
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

pub const H2Connection = struct {
    idx: usize,
    fd: i32 = -1,
    direct_reader: DirectSocketReader = undefined,
    direct_writer: DirectSocketWriter = undefined,
    tls_inst: ?TlsClient = null,
    tls_read_buf: [TlsClient.min_buffer_len]u8 = undefined,
    tls_write_buf: [TlsClient.min_buffer_len]u8 = undefined,
    write_mutex: sync.Mutex = .{},
    next_stream_id: u31 = 1,
    is_ready: sync.Event = .{},

    pub fn init(idx: usize) H2Connection {
        return .{
            .idx = idx,
        };
    }

    pub fn connect(self: *H2Connection, host: []const u8, port: u16) !void {
        var octets: [4]u8 = undefined;
        if (!net.resolveDnsA(host, &octets)) return error.DnsFailed;

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
        const sock_fd: i32 = @intCast(rc);

        net.setNoDelay(sock_fd);
        net.setSocketTimeout(sock_fd, 60); // 60 секунд таймаут

        const r_addr = net.sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock_fd))), @intFromPtr(&r_addr), @sizeOf(net.sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock_fd))));
            return error.ConnectFailed;
        }

        self.fd = sock_fd;
        self.direct_reader.setup(sock_fd);
        self.direct_writer.setup(sock_fd);

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

        var ts: std.posix.timespec = undefined;
        _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
        const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

        self.tls_inst = try TlsClient.init(
            &self.direct_reader.reader,
            &self.direct_writer.writer,
            .{
                .host = .{ .explicit = host },
                .ca = .no_verification,
                .write_buffer = &self.tls_write_buf,
                .read_buffer = &self.tls_read_buf,
                .entropy = &entropy,
                .realtime_now = now,
                .allow_truncation_attacks = true,
            },
        );

        // 1. Send Preface
        try self.writeRaw(h2.PREFACE);
        // 2. Send Chrome Settings & Window Update
        try self.writeRaw(&h2.CHROME_SETTINGS);
        try self.writeRaw(&h2.CHROME_WINDOW_UPDATE);

        self.is_ready.set();
        logger.json(.info, "h2_conn", "connected", null, null, "{{\"idx\":{d}}}", .{self.idx});
    }

    pub fn writeRaw(self: *H2Connection, bytes: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.tls_inst) |*t| {
            try t.writer.writeAll(bytes);
            try t.writer.flush();
            try self.direct_writer.writer.flush();
        }
    }

    pub fn sendH2Frame(self: *H2Connection, hdr: h2.H2Header, payload: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.tls_inst) |*t| {
            var h_buf: [9]u8 = undefined;
            hdr.serialize(&h_buf);
            try t.writer.writeAll(&h_buf);
            if (payload.len > 0) try t.writer.writeAll(payload);
            try t.writer.flush();
            try self.direct_writer.writer.flush();
        }
    }

    pub fn readExact(self: *H2Connection, dest: []u8) !void {
        var total: usize = 0;
        while (total < dest.len) {
            const avail = self.tls_inst.?.reader.buffered();
            if (avail.len > 0) {
                const copy_len = @min(dest.len - total, avail.len);
                @memcpy(dest[total .. total + copy_len], avail[0..copy_len]);
                self.tls_inst.?.reader.toss(copy_len);
                total += copy_len;
            } else {
                _ = self.tls_inst.?.reader.peekGreedy(1) catch |err| {
                    return err;
                };
                const new_avail = self.tls_inst.?.reader.buffered();
                if (new_avail.len == 0) {
                    if (self.tls_inst.?.eof()) {
                        return error.ConnectionClosed;
                    }
                    // Это был TLS 1.3 NewSessionTicket! Не умираем, читаем дальше!
                    continue;
                }
                const copy_len = @min(dest.len - total, new_avail.len);
                @memcpy(dest[total .. total + copy_len], new_avail[0..copy_len]);
                self.tls_inst.?.reader.toss(copy_len);
                total += copy_len;
            }
        }
    }

    pub fn close(self: *H2Connection) void {
        self.is_ready.reset();
        self.tls_inst = null;
        if (self.fd >= 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, self.fd))));
            self.fd = -1;
        }
    }
};
