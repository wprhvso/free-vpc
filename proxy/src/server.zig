const std = @import("std");
const protocol = @import("protocol.zig");

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: u32,
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

const sockaddr_in6 = extern struct {
    family: u16 = 10,
    port: u16,
    flowinfo: u32 = 0,
    addr: [16]u8,
    scope_id: u32 = 0,
};

const sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        while (self.state.swap(2, .acquire) != 0) {
            _ = std.os.linux.syscall4(.futex, @intFromPtr(&self.state.raw), 0, 2, 0);
        }
    }

    pub fn unlock(self: *Mutex) void {
        if (self.state.swap(0, .release) == 2) {
            _ = std.os.linux.syscall3(.futex, @intFromPtr(&self.state.raw), 1, 1);
        }
    }
};

fn sleepMs(ms: u64) void {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    const ts = timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.syscall2(.nanosleep, @intFromPtr(&ts), 0);
}

fn parseIp4(s: []const u8, out: *[4]u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return false;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return false;
        i += 1;
    }
    return (i == 4);
}

fn resolveDnsA(domain: []const u8, out_ip: *[4]u8) bool {
    const sock_rc = std.os.linux.syscall3(.socket, 2, 2, 0);
    if (@as(isize, @bitCast(sock_rc)) < 0) return false;
    const sock: i32 = @intCast(sock_rc);
    defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));

    const timeout = extern struct { sec: i64 = 2, usec: i64 = 0 }{};
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, sock))), 1, 20, @intFromPtr(&timeout), @sizeOf(@TypeOf(timeout)));

    const dns_server = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @as(u32, @bitCast([4]u8{ 77, 88, 8, 8 })),
    };

    const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&dns_server), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(conn_rc)) < 0) return false;

    var query_buf: [512]u8 = undefined;
    query_buf[0] = 0x12;
    query_buf[1] = 0x34;
    query_buf[2] = 0x01;
    query_buf[3] = 0x00;
    query_buf[4] = 0x00;
    query_buf[5] = 0x01;
    query_buf[6] = 0x00;
    query_buf[7] = 0x00;
    query_buf[8] = 0x00;
    query_buf[9] = 0x00;
    query_buf[10] = 0x00;
    query_buf[11] = 0x00;

    var q_idx: usize = 12;
    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 63) return false;
        if (q_idx + 1 + part.len >= query_buf.len - 5) return false;
        query_buf[q_idx] = @intCast(part.len);
        q_idx += 1;
        @memcpy(query_buf[q_idx .. q_idx + part.len], part);
        q_idx += part.len;
    }
    query_buf[q_idx] = 0;
    q_idx += 1;

    query_buf[q_idx] = 0x00;
    query_buf[q_idx + 1] = 0x01;
    query_buf[q_idx + 2] = 0x00;
    query_buf[q_idx + 3] = 0x01;
    q_idx += 4;

    const write_rc = std.os.linux.syscall3(.write, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&query_buf), q_idx);
    if (@as(isize, @bitCast(write_rc)) <= 0) return false;

    var resp_buf: [512]u8 = undefined;
    const read_rc = std.os.linux.syscall3(.read, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&resp_buf), resp_buf.len);
    const read_len: isize = @bitCast(read_rc);
    if (read_len < 12) return false;

    const r_len: usize = @intCast(read_len);
    if (resp_buf[0] != 0x12 or resp_buf[1] != 0x34) return false;
    const ancount = std.mem.readInt(u16, resp_buf[6..8], .big);
    if (ancount == 0) return false;

    var r_idx = q_idx;
    var a_i: usize = 0;
    while (a_i < ancount and r_idx + 12 <= r_len) : (a_i += 1) {
        if ((resp_buf[r_idx] & 0xc0) == 0xc0) {
            r_idx += 2;
        } else {
            while (r_idx < r_len and resp_buf[r_idx] != 0) : (r_idx += 1) {}
            r_idx += 1;
        }

        if (r_idx + 10 > r_len) return false;
        const qtype = std.mem.readInt(u16, resp_buf[r_idx..][0..2], .big);
        const rdlength = std.mem.readInt(u16, resp_buf[r_idx + 8 ..][0..2], .big);
        r_idx += 10;

        if (r_idx + rdlength > r_len) return false;
        if (qtype == 1 and rdlength == 4) {
            @memcpy(out_ip, resp_buf[r_idx .. r_idx + 4]);
            return true;
        }
        r_idx += rdlength;
    }

    return false;
}

fn listenOn(host: []const u8, port: u16) !i32 {
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    if (@as(isize, @bitCast(rc)) < 0) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));

    const one: c_int = 1;
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

    var octets: [4]u8 = .{ 127, 0, 0, 1 };
    _ = parseIp4(host, &octets);

    const addr = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };

    const bind_rc = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
    if (@as(isize, @bitCast(bind_rc)) < 0) return error.BindFailed;

    const listen_rc = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), 128);
    if (@as(isize, @bitCast(listen_rc)) < 0) return error.ListenFailed;

    return fd;
}

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    buffer_capacity: usize,
    downstream_sink: ?protocol.SocketStream = null,
    sink_mutex: Mutex = .{},
    downstream_backup: std.ArrayList(u8) = .empty,
    backup_mutex: Mutex = .{},
    streams: std.AutoHashMap(u32, protocol.SocketStream),
    streams_mutex: Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, buf_mb: usize) Server {
        return .{
            .allocator = allocator,
            .io = io,
            .host = host,
            .port = port,
            .buffer_capacity = buf_mb * 1024 * 1024,
            .downstream_backup = .empty,
            .streams = std.AutoHashMap(u32, protocol.SocketStream).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.sink_mutex.lock();
        if (self.downstream_sink) |sink| {
            sink.shutdown();
            sink.close();
            self.downstream_sink = null;
        }
        self.sink_mutex.unlock();

        self.backup_mutex.lock();
        self.downstream_backup.deinit(self.allocator);
        self.backup_mutex.unlock();

        self.streams_mutex.lock();
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.shutdown();
            entry.value_ptr.close();
        }
        self.streams.deinit();
        self.streams_mutex.unlock();
    }

    pub fn sendDownstreamDirect(self: *Server, frame: []const u8) void {
        self.sink_mutex.lock();
        if (self.downstream_sink) |sink| {
            var chunk_hdr: [32]u8 = undefined;
            const hdr = std.fmt.bufPrint(&chunk_hdr, "{x}\r\n", .{frame.len}) catch {
                self.sink_mutex.unlock();
                return;
            };

            sink.writeAll(hdr) catch {
                self.downstream_sink = null;
                self.sink_mutex.unlock();
                self.bufferBackup(frame);
                return;
            };

            sink.writeAll(frame) catch {
                self.downstream_sink = null;
                self.sink_mutex.unlock();
                self.bufferBackup(frame);
                return;
            };

            sink.writeAll("\r\n") catch {
                self.downstream_sink = null;
                self.sink_mutex.unlock();
                return;
            };

            self.sink_mutex.unlock();
        } else {
            self.sink_mutex.unlock();
            self.bufferBackup(frame);
        }
    }

    fn bufferBackup(self: *Server, frame: []const u8) void {
        self.backup_mutex.lock();
        defer self.backup_mutex.unlock();
        if (self.downstream_backup.items.len + frame.len <= self.buffer_capacity) {
            self.downstream_backup.appendSlice(self.allocator, frame) catch {};
        }
    }

    pub fn sendToDownstream(self: *Server, stream_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
        var static_buf: [4096]u8 = undefined;
        const total = @sizeOf(protocol.Header) + payload.len;

        if (total <= static_buf.len) {
            const n = protocol.writeFrame(&static_buf, stream_id, cmd, payload) catch return;
            self.sendDownstreamDirect(static_buf[0..n]);
        } else {
            const dyn_buf = self.allocator.alloc(u8, total) catch return;
            defer self.allocator.free(dyn_buf);
            const n = protocol.writeFrame(dyn_buf, stream_id, cmd, payload) catch return;
            self.sendDownstreamDirect(dyn_buf[0..n]);
        }
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const stream = entry.value;
            stream.shutdown();
            stream.close();
            self.sendToDownstream(stream_id, .close, "");
        }
    }

    pub fn start(self: *Server) !void {
        const listen_fd = try listenOn(self.host, self.port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);
            const stream = protocol.SocketStream{ .handle = client_fd };
            const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, stream });
            thread.detach();
        }
    }

    fn handleConnection(self: *Server, stream: protocol.SocketStream) void {
        var read_buf: [8192]u8 = undefined;

        while (true) {
            var total_read: usize = 0;
            var header_end: ?usize = null;

            while (total_read < read_buf.len) {
                const n = stream.read(read_buf[total_read..]) catch 0;
                if (n == 0) {
                    stream.close();
                    return;
                }
                total_read += n;

                if (std.mem.indexOf(u8, read_buf[0..total_read], "\r\n\r\n")) |idx| {
                    header_end = idx;
                    break;
                }
            }

            const h_end = header_end orelse {
                stream.close();
                return;
            };

            const headers = read_buf[0..h_end];
            const body_start = h_end + 4;
            const initial_body_len = total_read - body_start;

            const first_line_end = std.mem.indexOf(u8, headers, "\r\n") orelse headers.len;
            const req_line = headers[0..first_line_end];

            if (std.mem.startsWith(u8, req_line, "GET /health") or std.mem.startsWith(u8, req_line, "GET / ")) {
                const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
                _ = stream.writeAll(resp) catch return;
                continue;
            }

            if (std.mem.startsWith(u8, req_line, "GET /stream")) {
                const sse_headers =
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: text/event-stream\r\n" ++
                    "Cache-Control: no-cache, no-transform, private\r\n" ++
                    "X-Accel-Buffering: no\r\n" ++
                    "Connection: keep-alive\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\n";

                stream.writeAll(sse_headers) catch {
                    stream.close();
                    return;
                };

                self.sink_mutex.lock();
                if (self.downstream_sink) |old_sink| {
                    old_sink.shutdown();
                    old_sink.close();
                }
                self.downstream_sink = stream;
                self.sink_mutex.unlock();

                self.backup_mutex.lock();
                if (self.downstream_backup.items.len > 0) {
                    const saved = self.downstream_backup.toOwnedSlice(self.allocator) catch null;
                    self.backup_mutex.unlock();
                    if (saved) |buf| {
                        defer self.allocator.free(buf);
                        self.sendDownstreamDirect(buf);
                    }
                } else {
                    self.backup_mutex.unlock();
                }

                return;
            }

            if (std.mem.startsWith(u8, req_line, "POST /push")) {
                var content_len: usize = 0;
                if (findHeader(headers, "content-length:")) |val| {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, val, " \t"), 10) catch 0;
                }

                if (content_len == 0) {
                    const resp = "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
                    _ = stream.writeAll(resp) catch return;
                    continue;
                }

                var body = self.allocator.alloc(u8, content_len) catch return;
                defer self.allocator.free(body);

                if (initial_body_len > 0) {
                    const to_copy = @min(initial_body_len, content_len);
                    @memcpy(body[0..to_copy], read_buf[body_start .. body_start + to_copy]);
                }

                var current_body_len = @min(initial_body_len, content_len);
                while (current_body_len < content_len) {
                    const n = stream.read(body[current_body_len..]) catch 0;
                    if (n == 0) {
                        stream.close();
                        return;
                    }
                    current_body_len += n;
                }

                self.processPushBody(body);

                const resp = "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
                _ = stream.writeAll(resp) catch return;
                continue;
            }

            const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            _ = stream.writeAll(not_found) catch return;
            stream.close();
            return;
        }
    }

    fn findHeader(headers: []const u8, lower_name: []const u8) ?[]const u8 {
        var it = std.mem.splitSequence(u8, headers, "\r\n");
        _ = it.next();
        while (it.next()) |line| {
            if (line.len < lower_name.len) continue;
            var is_match = true;
            for (lower_name, 0..) |c, i| {
                if (std.ascii.toLower(line[i]) != c) {
                    is_match = false;
                    break;
                }
            }
            if (is_match) {
                return line[lower_name.len..];
            }
        }
        return null;
    }

    fn processPushBody(self: *Server, body: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= body.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(body[offset..].ptr));
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > body.len) break;
            const payload = body[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            switch (hdr.cmd) {
                .connect => {
                    self.handleConnect(hdr.stream_id, payload);
                },
                .data => {
                    self.streams_mutex.lock();
                    const s_opt = self.streams.get(hdr.stream_id);
                    self.streams_mutex.unlock();
                    if (s_opt) |target_stream| {
                        target_stream.writeAll(payload) catch {
                            self.closeStream(hdr.stream_id);
                        };
                    }
                },
                .close => {
                    self.closeStream(hdr.stream_id);
                },
                .ping => {
                    self.sendToDownstream(hdr.stream_id, .pong, "");
                },
                else => {},
            }
        }
    }

    fn handleConnect(self: *Server, stream_id: u32, payload: []const u8) void {
        if (payload.len < 4) {
            self.sendToDownstream(stream_id, .close, "");
            return;
        }

        const port = std.mem.readInt(u16, payload[0..2], .big);
        const atyp = payload[2];
        const addr_len = payload[3];
        if (payload.len < 4 + addr_len) {
            self.sendToDownstream(stream_id, .close, "");
            return;
        }

        const addr_data = payload[4 .. 4 + addr_len];

        if (atyp == 1 and addr_len == 4) {
            self.connectTcpIpv4(stream_id, addr_data[0..4].*, port);
        } else if (atyp == 4 and addr_len == 16) {
            const sock_rc = std.os.linux.syscall3(.socket, 10, 1, 0);
            if (@as(isize, @bitCast(sock_rc)) < 0) {
                self.sendToDownstream(stream_id, .close, "");
                return;
            }
            const sock: i32 = @intCast(sock_rc);

            const target_addr = sockaddr_in6{
                .family = 10,
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = addr_data[0..16].*,
                .scope_id = 0,
            };

            const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in6));
            if (@as(isize, @bitCast(conn_rc)) < 0) {
                _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
                self.sendToDownstream(stream_id, .close, "");
                return;
            }

            const target_conn = protocol.SocketStream{ .handle = sock };

            self.streams_mutex.lock();
            self.streams.put(stream_id, target_conn) catch {
                self.streams_mutex.unlock();
                target_conn.close();
                self.sendToDownstream(stream_id, .close, "");
                return;
            };
            self.streams_mutex.unlock();

            self.sendToDownstream(stream_id, .connect_ok, "");

            const thread = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn }) catch {
                self.closeStream(stream_id);
                return;
            };
            thread.detach();
        } else if (atyp == 2) {
            var octets: [4]u8 = .{ 0, 0, 0, 0 };
            if (parseIp4(addr_data, &octets)) {
                self.connectTcpIpv4(stream_id, octets, port);
            } else if (resolveDnsA(addr_data, &octets)) {
                self.connectTcpIpv4(stream_id, octets, port);
            } else {
                self.sendToDownstream(stream_id, .close, "");
            }
        } else {
            self.sendToDownstream(stream_id, .close, "");
        }
    }

    fn connectTcpIpv4(self: *Server, stream_id: u32, octets: [4]u8, port: u16) void {
        const sock_rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) {
            self.sendToDownstream(stream_id, .close, "");
            return;
        }
        const sock: i32 = @intCast(sock_rc);

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
            self.sendToDownstream(stream_id, .close, "");
            return;
        }

        const target_conn = protocol.SocketStream{ .handle = sock };

        self.streams_mutex.lock();
        self.streams.put(stream_id, target_conn) catch {
            self.streams_mutex.unlock();
            target_conn.close();
            self.sendToDownstream(stream_id, .close, "");
            return;
        };
        self.streams_mutex.unlock();

        self.sendToDownstream(stream_id, .connect_ok, "");

        const thread = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn }) catch {
            self.closeStream(stream_id);
            return;
        };
        thread.detach();
    }

    fn targetReaderWorker(self: *Server, stream_id: u32, target_stream: protocol.SocketStream) void {
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) {
                self.closeStream(stream_id);
                return;
            }
            self.sendToDownstream(stream_id, .data, buf[0..n]);
        }
    }
};
