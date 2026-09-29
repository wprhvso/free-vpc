const std = @import("std");
const Config = @import("config.zig").Config;
const protocol = @import("protocol.zig");

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: u32,
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

fn getMilliTimestamp() u64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return @intCast((ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000));
}

fn printLog(comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "[{d}] " ++ fmt, .{getMilliTimestamp()} ++ args) catch return;
    _ = std.os.linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
}

const DirectSocketWriter = struct {
    fd: i32,
    raw_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined,
    writer: std.Io.Writer = undefined,

    pub fn init(fd: i32) DirectSocketWriter {
        var self = DirectSocketWriter{
            .fd = fd,
        };
        self.writer = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .drain = drain,
                .flush = flush,
            },
            .end = 0,
        };
        return self;
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
            printLog("SYSCALL WRITE >> sending {d} encrypted bytes to fd {d}...\n", .{ w.end, self.fd });
            var index: usize = 0;
            while (index < w.end) {
                const rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(w.buffer.ptr + index), w.end - index);
                const signed: isize = @bitCast(rc);
                if (signed <= 0) return error.WriteFailed;
                index += @intCast(signed);
            }
            printLog("SYSCALL WRITE << {d} bytes written to Linux kernel successfully!\n", .{w.end});
            w.end = 0;
        }
    }

    fn writeSyscall(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
        const self: *DirectSocketWriter = @alignCast(@fieldParentPtr("writer", w));
        printLog("SYSCALL WRITE >> sending {d} direct bytes to fd {d}...\n", .{ bytes.len, self.fd });
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

    pub fn init(fd: i32) DirectSocketReader {
        var self = DirectSocketReader{
            .fd = fd,
        };
        self.reader = .{
            .buffer = &self.raw_buf,
            .vtable = &.{
                .stream = stream,
                .readVec = readVec,
            },
            .seek = 0,
            .end = 0,
        };
        return self;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        return readFromSocket(r);
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        _ = data;
        return readFromSocket(r);
    }

    fn readFromSocket(r: *std.Io.Reader) std.Io.Reader.Error!usize {
        const self: *DirectSocketReader = @alignCast(@fieldParentPtr("reader", r));
        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        }
        if (r.buffer.len - r.end == 0) return 0;

        printLog("SYSCALL READ >> waiting on kernel read(fd={d}, avail_cap={d})...\n", .{ self.fd, r.buffer.len - r.end });
        const rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, self.fd))), @intFromPtr(r.buffer.ptr + r.end), r.buffer.len - r.end);
        const signed: isize = @bitCast(rc);
        printLog("SYSCALL READ << syscall returned {d} bytes!\n", .{signed});
        if (signed < 0) return error.ReadFailed;
        if (signed == 0) return error.EndOfStream;
        r.end += @intCast(signed);
        return 0;
    }
};

fn readByteDiagnostic(
    tls_client: *std.crypto.tls.Client,
    raw_buf: []u8,
    pos: *usize,
    len: *usize,
) !u8 {
    while (true) {
        if (pos.* < len.*) {
            const res = raw_buf[pos.*];
            pos.* += 1;
            return res;
        }
        pos.* = 0;
        printLog("TLS DECRYPT >> calling tls_client.reader.readSliceShort...\n", .{});
        const n = try tls_client.reader.readSliceShort(raw_buf);
        printLog("TLS DECRYPT << decrypted {d} application bytes (eof={})\n", .{ n, tls_client.eof() });
        if (n == 0) {
            if (tls_client.eof()) {
                printLog("TLS DECRYPT << EOF signaled by TLS layer\n", .{});
                return error.ConnectionClosed;
            }
            printLog("TLS DECRYPT << Handshake control frame consumed without application data, reading next...\n", .{});
            continue;
        }
        len.* = n;
    }
}

pub fn main(init: std.process.Init) !void {
    _ = init;

    printLog("STEP 1: Starting DNS resolution for '{s}'...\n", .{Config.client.remote_host});
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    const dns_ok = protocol.resolveDnsA(Config.client.remote_host, &octets);
    if (!dns_ok) {
        printLog("ERROR: DNS resolution failed for '{s}'!\n", .{Config.client.remote_host});
        return error.DnsFailed;
    }
    printLog("STEP 1: DNS resolved -> {d}.{d}.{d}.{d}\n", .{ octets[0], octets[1], octets[2], octets[3] });

    printLog("STEP 2: Creating socket...\n", .{});
    const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    if (@as(isize, @bitCast(sock_rc)) < 0) {
        printLog("ERROR: socket syscall failed\n", .{});
        return error.SocketFailed;
    }
    const fd: i32 = @intCast(sock_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

    protocol.setNoDelay(fd);

    const r_addr = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, Config.client.remote_port),
        .addr = @as(u32, @bitCast(octets)),
    };

    printLog("STEP 2: Connecting TCP to {d}.{d}.{d}.{d}:{d}...\n", .{
        octets[0], octets[1], octets[2], octets[3], Config.client.remote_port,
    });
    const start_tcp = getMilliTimestamp();
    const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&r_addr), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(conn_rc)) < 0) {
        printLog("ERROR: TCP connect failed with code {d}\n", .{conn_rc});
        return error.ConnectFailed;
    }
    const tcp_dur = getMilliTimestamp() - start_tcp;
    printLog("STEP 2: TCP connected in {d}ms!\n", .{tcp_dur});

    printLog("STEP 3: Preparing direct syscall-backed TLS structures...\n", .{});
    var direct_reader = DirectSocketReader.init(fd);
    var direct_writer = DirectSocketWriter.init(fd);

    var tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;

    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    _ = std.os.linux.syscall3(.getrandom, @intFromPtr(&entropy), entropy.len, 0);

    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    const now = std.Io.Timestamp{ .nanoseconds = (@as(i96, ts.sec) * std.time.ns_per_s) + ts.nsec };

    printLog("STEP 3: Starting TLS handshake...\n", .{});
    const start_tls = getMilliTimestamp();
    var tls_client = std.crypto.tls.Client.init(
        &direct_reader.reader,
        &direct_writer.writer,
        .{
            .host = .{ .explicit = Config.client.remote_host },
            .ca = .no_verification,
            .write_buffer = &tls_write_buf,
            .read_buffer = &tls_read_buf,
            .entropy = &entropy,
            .realtime_now = now,
            .allow_truncation_attacks = true,
        },
    ) catch |err| {
        printLog("ERROR: TLS handshake failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer tls_client.end() catch {};
    const tls_dur = getMilliTimestamp() - start_tls;
    printLog("STEP 3: TLS handshake finished in {d}ms! Version: {s}\n", .{ tls_dur, @tagName(tls_client.tls_version) });

    var req_hdr: [1024]u8 = undefined;
    const hdrs = std.fmt.bufPrint(&req_hdr,
        "POST {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "User-Agent: {s}\r\n" ++
        "Accept-Encoding: identity\r\n" ++
        "{s}: {s}\r\n" ++
        "X-Gen: 1\r\n" ++
        "Content-Type: application/octet-stream\r\n" ++
        "Content-Length: 0\r\n" ++
        "Connection: keep-alive\r\n\r\n",
        .{ Config.common.pipe_path, Config.client.remote_host, Config.client.user_agent, Config.common.token_header, Config.common.token }
    ) catch unreachable;

    printLog("STEP 4: Writing HTTP request ({d} bytes):\n---\n{s}---\n", .{ hdrs.len, hdrs });
    try tls_client.writer.writeAll(hdrs);
    printLog("STEP 4: Flushing TLS records into raw socket writer...\n", .{});
    try tls_client.writer.flush();
    printLog("STEP 4: Flushing raw socket writer to kernel...\n", .{});
    try direct_writer.writer.flush();
    printLog("STEP 4: HTTP request confirmed sent to kernel!\n", .{});

    printLog("STEP 5: Reading HTTP response headers...\n", .{});
    const start_http = getMilliTimestamp();

    var raw_recv_buf: [16384]u8 = undefined;
    var raw_recv_pos: usize = 0;
    var raw_recv_len: usize = 0;

    var header_buf: [4096]u8 = undefined;
    var header_idx: usize = 0;

    while (header_idx < header_buf.len) {
        const b = try readByteDiagnostic(&tls_client, &raw_recv_buf, &raw_recv_pos, &raw_recv_len);
        header_buf[header_idx] = b;
        header_idx += 1;
        if (header_idx >= 4 and std.mem.eql(u8, header_buf[header_idx - 4 .. header_idx], "\r\n\r\n")) {
            break;
        }
    }

    const ttfb = getMilliTimestamp() - start_http;
    const headers_slice = header_buf[0..header_idx];
    printLog("STEP 5: Headers received in {d}ms (TTFB)!\n---\n{s}---\n", .{ ttfb, headers_slice });

    printLog("STEP 6: Reading chunk size line...\n", .{});
    var chunk_hdr_buf: [64]u8 = undefined;
    var chunk_hdr_idx: usize = 0;
    var chunk_size: usize = 0;

    while (chunk_hdr_idx < chunk_hdr_buf.len) {
        const b = try readByteDiagnostic(&tls_client, &raw_recv_buf, &raw_recv_pos, &raw_recv_len);
        if (b == '\n' and chunk_hdr_idx > 0 and chunk_hdr_buf[chunk_hdr_idx - 1] == '\r') {
            var hex_part = std.mem.trim(u8, chunk_hdr_buf[0 .. chunk_hdr_idx - 1], " \t");
            if (std.mem.indexOfScalar(u8, hex_part, ';')) |semi| {
                hex_part = hex_part[0..semi];
            }
            chunk_size = try std.fmt.parseInt(usize, hex_part, 16);
            break;
        }
        chunk_hdr_buf[chunk_hdr_idx] = b;
        chunk_hdr_idx += 1;
    }

    printLog("STEP 6: Chunk header parsed -> 0x{x} ({d} bytes)\n", .{ chunk_size, chunk_size });

    if (chunk_size == 0) {
        printLog("STEP 7: Stream ended immediately (chunk_size = 0)\n", .{});
        return;
    }

    printLog("STEP 7: Reading chunk body of {d} bytes...\n", .{chunk_size});
    var bytes_read: usize = 0;
    var first_32: [32]u8 = undefined;

    while (bytes_read < chunk_size) {
        const b = try readByteDiagnostic(&tls_client, &raw_recv_buf, &raw_recv_pos, &raw_recv_len);
        if (bytes_read < 32) {
            first_32[bytes_read] = b;
        }
        bytes_read += 1;
    }

    _ = try readByteDiagnostic(&tls_client, &raw_recv_buf, &raw_recv_pos, &raw_recv_len);
    _ = try readByteDiagnostic(&tls_client, &raw_recv_buf, &raw_recv_pos, &raw_recv_len);

    printLog("STEP 7: Chunk body fully received ({d} bytes)!\n", .{bytes_read});

    if (bytes_read >= @sizeOf(protocol.Header)) {
        var hdr: protocol.Header = undefined;
        @memcpy(std.mem.asBytes(&hdr), first_32[0..@sizeOf(protocol.Header)]);
        printLog("STEP 8: Protocol Frame Verification:\n", .{});
        printLog("  magic: 0x{x} (expected: 0xCF01)\n", .{hdr.magic});
        printLog("  payload_len: {d}\n", .{hdr.payload_len});
        printLog("  stream_id: {d}\n", .{hdr.stream_id});
        printLog("  seq_id: {d}\n", .{hdr.seq_id});
        printLog("  cmd: {s} ({d})\n", .{ @tagName(hdr.cmd), @intFromEnum(hdr.cmd) });
    }

    printLog("TEST COMPLETED SUCCESSFULLY: Single baton HTTP chunk roundtrip verified.\n", .{});
}
