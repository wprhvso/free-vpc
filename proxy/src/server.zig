const std = @import("std");
const Config = @import("config.zig").Config;
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");
const FrameQueue = @import("frame_queue.zig").FrameQueue;

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

const StreamState = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 1,
    downstream_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: futex.Mutex = .{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    downstream_queue: FrameQueue,
    streams: std.AutoHashMap(u32, *StreamState),
    streams_mutex: futex.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Server {
        const dq = FrameQueue.init(allocator, Config.common.queue_capacity) catch unreachable;
        return .{
            .allocator = allocator,
            .io = io,
            .downstream_queue = dq,
            .streams = std.AutoHashMap(u32, *StreamState).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.downstream_queue.deinit(self.allocator);
        self.streams.deinit();
    }

    pub fn start(self: *Server) !void {
        const listen_fd = try listenOn(Config.server.bind_host, Config.server.bind_port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

        std.debug.print("\x1b[32m[SERVER]\x1b[0m Edge listener ready on {s}:{d}\n", .{ Config.server.bind_host, Config.server.bind_port });

        while (true) {
            var client_addr: sockaddr = undefined;
            var client_len: u32 = @sizeOf(sockaddr);
            const accept_rc = std.os.linux.syscall4(.accept4, @as(usize, @bitCast(@as(isize, listen_fd))), @intFromPtr(&client_addr), @intFromPtr(&client_len), 0);
            if (@as(isize, @bitCast(accept_rc)) < 0) continue;
            const client_fd: i32 = @intCast(accept_rc);

            protocol.setNoDelay(client_fd);

            const stream = protocol.SocketStream{ .handle = client_fd };
            const th = std.Thread.spawn(.{}, handleHttp, .{ self, stream }) catch {
                stream.close();
                continue;
            };
            th.detach();
        }
    }

    fn handleHttp(self: *Server, stream: protocol.SocketStream) void {
        var header_buf: [4096]u8 = undefined;
        const drain_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch { stream.close(); return; };
        defer self.allocator.free(drain_buf);

        std.debug.print("\x1b[33m[SERVER]\x1b[0m Incoming connection accepted\n", .{});

        while (true) {
            var leftover: []const u8 = undefined;
            const hdrs = readHeadersFast(stream, &header_buf, &leftover) catch |err| {
                std.debug.print("\x1b[33m[SERVER]\x1b[0m Connection closed / error: {s}\n", .{@errorName(err)});
                stream.close();
                return;
            };

            const first_line = hdrs[0 .. std.mem.indexOf(u8, hdrs, "\r\n") orelse hdrs.len];
            std.debug.print("\x1b[33m[SERVER]\x1b[0m Got HTTP request: {s}\n", .{first_line});

            const is_push = std.mem.indexOf(u8, first_line, Config.common.push_path) != null;
            const is_pull = std.mem.indexOf(u8, first_line, Config.common.pull_path) != null;

            if (!is_push and !is_pull) {
                std.debug.print("\x1b[33m[SERVER]\x1b[0m Unknown path, returning 200 OK\n", .{});
                _ = stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK") catch {};
                continue;
            }

            var content_len: usize = 0;
            var is_keep_alive = true;
            var auth_ok = false;

            var h_it = std.mem.splitSequence(u8, hdrs, "\r\n");
            while (h_it.next()) |line| {
                if (line.len == 0) break;
                if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \t"), 10) catch 0;
                } else if (std.ascii.startsWithIgnoreCase(line, "connection:")) {
                    if (std.mem.indexOf(u8, line, "close") != null) is_keep_alive = false;
                } else if (std.ascii.startsWithIgnoreCase(line, Config.common.token_header)) {
                    const token_val = std.mem.trim(u8, line[Config.common.token_header.len + 1 ..], " \t");
                    if (std.mem.eql(u8, token_val, Config.common.token)) auth_ok = true;
                }
            }

            if (!auth_ok) {
                std.debug.print("\x1b[31m[SERVER]\x1b[0m 403 Forbidden: Invalid token\n", .{});
                _ = stream.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n") catch {};
                stream.close();
                return;
            }

            if (is_push) {
                if (content_len > 0) {
                    const body = self.allocator.alloc(u8, content_len) catch { stream.close(); return; };
                    defer self.allocator.free(body);

                    if (leftover.len > 0) {
                        const from_lo = @min(leftover.len, content_len);
                        @memcpy(body[0..from_lo], leftover[0..from_lo]);
                        if (content_len > from_lo) {
                            if (!protocol.readExactStream(stream, body[from_lo..content_len])) { stream.close(); return; }
                        }
                    } else {
                        if (!protocol.readExactStream(stream, body)) { stream.close(); return; }
                    }

                    std.debug.print("\x1b[35m[SERVER PUSH]\x1b[0m Processing {d} bytes\n", .{body.len});
                    self.processFrames(body);
                }
                _ = stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n") catch { stream.close(); return; };
            } else if (is_pull) {
                var batch_len = self.downstream_queue.drainBatch(drain_buf);
                if (batch_len == 0) {
                    std.debug.print("\x1b[34m[SERVER PULL]\x1b[0m Waiting for data (hold 10s)...\n", .{});
                    if (self.downstream_queue.waitData(Config.server.hold_timeout_ms)) {
                        batch_len = self.downstream_queue.drainBatch(drain_buf);
                    }
                }

                if (batch_len > 0) {
                    std.debug.print("\x1b[34m[SERVER PULL]\x1b[0m Returning {d} bytes\n", .{batch_len});
                    var resp_hdr: [256]u8 = undefined;
                    const hdr_text = std.fmt.bufPrint(&resp_hdr,
                        "HTTP/1.1 200 OK\r\n" ++
                        "Content-Type: application/octet-stream\r\n" ++
                        "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n" ++
                        "Pragma: no-cache\r\n" ++
                        "Content-Length: {d}\r\n" ++
                        "Connection: {s}\r\n\r\n",
                        .{ batch_len, if (is_keep_alive) "keep-alive" else "close" }
                    ) catch unreachable;

                    stream.writeAll(hdr_text) catch { stream.close(); return; };
                    stream.writeAll(drain_buf[0..batch_len]) catch { stream.close(); return; };
                } else {
                    std.debug.print("\x1b[34m[SERVER PULL]\x1b[0m Hold timeout, returning 204 No Content\n", .{});
                    const no_content = if (is_keep_alive)
                        "HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n"
                    else
                        "HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                    stream.writeAll(no_content) catch { stream.close(); return; };
                }
            }

            if (!is_keep_alive) {
                stream.close();
                return;
            }
        }
    }

    fn processFrames(self: *Server, body: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= body.len) {
            const hdr: *const protocol.Header = @ptrCast(@alignCast(body[offset..].ptr));
            if (hdr.magic != 0xCF01) break;
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > body.len) break;
            const payload = body[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

            std.debug.print("\x1b[35m[SERVER FRAME]\x1b[0m Stream #{d} cmd={any} len={d}\n", .{ hdr.stream_id, hdr.cmd, hdr.payload_len });

            switch (hdr.cmd) {
                .connect => self.handleConnect(hdr.stream_id, payload),
                .data => self.handleData(hdr.stream_id, hdr.seq_id, payload),
                .close => self.closeStream(hdr.stream_id),
                else => {},
            }
        }
    }

    fn handleData(self: *Server, stream_id: u32, seq_id: u32, payload: []const u8) void {
        self.streams_mutex.lock();
        const state_opt = self.streams.get(stream_id);
        self.streams_mutex.unlock();

        if (state_opt) |state| {
            state.mutex.lock();
            defer state.mutex.unlock();

            if (seq_id == state.expected_seq) {
                state.stream.writeAll(payload) catch { self.closeStream(stream_id); return; };
                state.expected_seq +%= 1;

                while (state.reorder_queue.fetchRemove(state.expected_seq)) |entry| {
                    defer self.allocator.free(entry.value);
                    state.stream.writeAll(entry.value) catch { self.closeStream(stream_id); return; };
                    state.expected_seq +%= 1;
                }
            } else if (seq_id > state.expected_seq) {
                if (state.reorder_queue.count() < Config.server.reorder_limit) {
                    const copy = self.allocator.alloc(u8, payload.len) catch return;
                    @memcpy(copy, payload);
                    state.reorder_queue.put(seq_id, copy) catch { self.allocator.free(copy); };
                }
            }
        }
    }

    fn handleConnect(self: *Server, stream_id: u32, payload: []const u8) void {
        if (payload.len < 4) { self.sendClose(stream_id); return; }
        const port = std.mem.readInt(u16, payload[0..2], .big);
        const target_type = payload[2];
        const addr_len = payload[3];

        if (payload.len < 4 + addr_len) { self.sendClose(stream_id); return; }
        const raw_addr = payload[4 .. 4 + addr_len];

        var octets: [4]u8 = .{ 0, 0, 0, 0 };

        if (target_type == 1) {
            if (addr_len != 4) { self.sendClose(stream_id); return; }
            @memcpy(&octets, raw_addr);
        } else if (target_type == 2) {
            std.debug.print("\x1b[36m[SERVER DNS]\x1b[0m Resolving {s}...\n", .{raw_addr});
            if (!protocol.resolveDnsA(raw_addr, &octets)) {
                std.debug.print("\x1b[31m[SERVER ERROR]\x1b[0m Failed to resolve DNS for {s}\n", .{raw_addr});
                self.sendClose(stream_id);
                return;
            }
        } else {
            self.sendClose(stream_id);
            return;
        }

        std.debug.print("\x1b[32m[SERVER]\x1b[0m Connecting Stream #{d} to {d}.{d}.{d}.{d}:{d}...\n", .{
            stream_id, octets[0], octets[1], octets[2], octets[3], port,
        });

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) { self.sendClose(stream_id); return; }
        const sock: i32 = @intCast(rc);

        protocol.setNoDelay(sock);

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            std.debug.print("\x1b[31m[SERVER]\x1b[0m Connect failed to target\n", .{});
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
            self.sendClose(stream_id);
            return;
        }

        std.debug.print("\x1b[32m[SERVER]\x1b[0m Connected target for Stream #{d}\n", .{stream_id});

        const target_conn = protocol.SocketStream{ .handle = sock };
        const state = self.allocator.create(StreamState) catch unreachable;
        state.* = .{
            .stream = target_conn,
            .expected_seq = 1,
            .reorder_queue = std.AutoHashMap(u32, []u8).init(self.allocator),
        };

        self.streams_mutex.lock();
        self.streams.put(stream_id, state) catch unreachable;
        self.streams_mutex.unlock();

        _ = self.downstream_queue.push(stream_id, 0, .connect_ok, "");
        std.debug.print("\x1b[32m[SERVER]\x1b[0m Sent connect_ok for Stream #{d}\n", .{stream_id});

        const th = std.Thread.spawn(.{}, targetReaderWorker, .{ self, stream_id, target_conn, state }) catch {
            self.closeStream(stream_id);
            return;
        };
        th.detach();
    }

    fn targetReaderWorker(self: *Server, stream_id: u32, target_stream: protocol.SocketStream, state: *StreamState) void {
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = target_stream.read(&buf) catch 0;
            if (n == 0) {
                std.debug.print("\x1b[33m[SERVER]\x1b[0m Stream #{d} target socket closed (EOF)\n", .{stream_id});
                self.closeStream(stream_id);
                return;
            }
            const s_seq = state.downstream_seq.fetchAdd(1, .monotonic);
            while (!self.downstream_queue.push(stream_id, s_seq, .data, buf[0..n])) {
                futex.Futex.wait(&state.downstream_seq, 0, 1);
            }
        }
    }

    fn sendClose(self: *Server, stream_id: u32) void {
        _ = self.downstream_queue.push(stream_id, 0, .close, "");
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();

        if (removed) |entry| {
            const state = entry.value;
            state.stream.shutdown();
            state.stream.close();

            var q_it = state.reorder_queue.iterator();
            while (q_it.next()) |q_e| self.allocator.free(q_e.value_ptr.*);
            state.reorder_queue.deinit();
            self.allocator.destroy(state);

            self.sendClose(stream_id);
        }
    }
};

fn readHeadersFast(stream: protocol.SocketStream, out_buf: []u8, leftover: *[]const u8) ![]const u8 {
    var total: usize = 0;
    while (total < out_buf.len) {
        if (std.mem.indexOf(u8, out_buf[0..total], "\r\n\r\n")) |idx| {
            const hdr_end = idx + 4;
            leftover.* = out_buf[hdr_end..total];
            return out_buf[0..hdr_end];
        }
        const n = try stream.read(out_buf[total..]);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }
    return error.HeadersTooLong;
}

fn listenOn(host: []const u8, port: u16) !i32 {
    const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
    const fd: i32 = @intCast(rc);
    const one: c_int = 1;
    _ = std.os.linux.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), 1, 2, @intFromPtr(&one), @sizeOf(c_int));

    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    _ = protocol.parseIp4(host, &octets);

    const addr = sockaddr_in{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @as(u32, @bitCast(octets)),
    };
    _ = std.os.linux.syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&addr), @sizeOf(sockaddr_in));
    _ = std.os.linux.syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), 128);
    return fd;
}
