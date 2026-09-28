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

fn getMilliTimestamp() u64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return @intCast((ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000));
}

const StreamState = struct {
    stream: protocol.SocketStream,
    expected_seq: u32 = 1,
    downstream_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    reorder_queue: std.AutoHashMap(u32, []u8),
    mutex: futex.Mutex = .{},
};

const ServerPipeContext = struct {
    gen: u64,
    stream: protocol.SocketStream,
    retired: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    wake_event: futex.Event = .{},
    done_event: futex.Event = .{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    downstream_queue: FrameQueue,
    streams: std.AutoHashMap(u32, *StreamState),
    streams_mutex: futex.Mutex = .{},
    active_leader: std.atomic.Value(?*ServerPipeContext) = std.atomic.Value(?*ServerPipeContext).init(null),
    leader_mutex: futex.Mutex = .{},

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

    pub fn emitRemoteLog(self: *Server, level: []const u8, component: []const u8, event: []const u8, stream_id: u32, data_json: []const u8) void {
        var scratch: [1024]u8 = undefined;
        const msg = std.fmt.bufPrint(&scratch,
            "{{\"ts\":{d},\"node\":\"server\",\"component\":\"{s}\",\"level\":\"{s}\",\"event\":\"{s}\",\"stream_id\":{d},\"data\":{s}}}",
            .{ getMilliTimestamp(), component, level, event, stream_id, data_json }
        ) catch return;

        _ = self.downstream_queue.push(0, 0, .log, msg);
        self.notifyLeader();
    }

    pub fn notifyLeader(self: *Server) void {
        self.leader_mutex.lock();
        if (self.active_leader.load(.acquire)) |ldr| {
            ldr.wake_event.set();
        }
        self.leader_mutex.unlock();
    }

    pub fn start(self: *Server) !void {
        const listen_fd = try listenOn(Config.server.bind_host, Config.server.bind_port);
        defer _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, listen_fd))));

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

        while (true) {
            var leftover: []const u8 = undefined;
            const hdrs = readHeadersFast(stream, &header_buf, &leftover) catch { stream.close(); return; };

            const first_line = hdrs[0 .. std.mem.indexOf(u8, hdrs, "\r\n") orelse hdrs.len];
            const is_pipe = std.mem.indexOf(u8, first_line, Config.common.pipe_path) != null;

            if (!is_pipe) {
                _ = stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK") catch {};
                continue;
            }

            var content_len: usize = 0;
            var auth_ok = false;
            var req_gen: u64 = 0;

            var h_it = std.mem.splitSequence(u8, hdrs, "\r\n");
            while (h_it.next()) |line| {
                if (line.len == 0) break;
                if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \t"), 10) catch 0;
                } else if (std.ascii.startsWithIgnoreCase(line, "x-gen:")) {
                    req_gen = std.fmt.parseInt(u64, std.mem.trim(u8, line["x-gen:".len..], " \t"), 10) catch 0;
                } else if (std.ascii.startsWithIgnoreCase(line, Config.common.token_header)) {
                    const token_val = std.mem.trim(u8, line[Config.common.token_header.len + 1 ..], " \t");
                    if (std.mem.eql(u8, token_val, Config.common.token)) auth_ok = true;
                }
            }

            if (!auth_ok) {
                _ = stream.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n") catch {};
                stream.close();
                return;
            }

            var pipe_log: [64]u8 = undefined;
            const pipe_slice = std.fmt.bufPrint(&pipe_log, "{{\"gen\":{d},\"bytes\":{d}}}", .{ req_gen, content_len }) catch "{}";
            self.emitRemoteLog("debug", "pipe", "request_received", 0, pipe_slice);

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

                self.processFrames(body);
            }

            const pipe_ctx = self.allocator.create(ServerPipeContext) catch { stream.close(); return; };
            pipe_ctx.* = .{
                .gen = req_gen,
                .stream = stream,
            };

            self.leader_mutex.lock();
            const prev_leader = self.active_leader.swap(pipe_ctx, .acq_rel);
            if (prev_leader) |old| {
                old.retired.store(true, .release);
                old.wake_event.set();
            }
            self.leader_mutex.unlock();

            if (prev_leader) |old| {
                var ret_log: [64]u8 = undefined;
                const ret_slice = std.fmt.bufPrint(&ret_log, "{{\"old_gen\":{d},\"new_gen\":{d}}}", .{ old.gen, req_gen }) catch "{}";
                self.emitRemoteLog("info", "baton", "preempt", 0, ret_slice);
            }

            const init_resp =
                "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: application/octet-stream\r\n" ++
                "Transfer-Encoding: chunked\r\n" ++
                "Cache-Control: no-cache, no-store, no-transform\r\n" ++
                "X-Accel-Buffering: no\r\n" ++
                "Connection: keep-alive\r\n\r\n";

            stream.writeAll(init_resp) catch {
                self.allocator.destroy(pipe_ctx);
                stream.close();
                return;
            };

            var init_ping_buf: [8192]u8 = @splat(0);
            const init_ping_hdr = protocol.Header{
                .magic = 0xCF01,
                .payload_len = 8192 - @sizeOf(protocol.Header),
                .stream_id = 0,
                .seq_id = 0,
                .cmd = .ping,
            };
            const init_hdr_bytes: *const [@sizeOf(protocol.Header)]u8 = @ptrCast(&init_ping_hdr);
            @memcpy(init_ping_buf[0..@sizeOf(protocol.Header)], init_hdr_bytes);

            var init_ch_hdr: [32]u8 = undefined;
            const init_ch_text = std.fmt.bufPrint(&init_ch_hdr, "{x}\r\n", .{init_ping_buf.len}) catch unreachable;
            stream.writeAll(init_ch_text) catch { self.allocator.destroy(pipe_ctx); stream.close(); return; };
            stream.writeAll(&init_ping_buf) catch { self.allocator.destroy(pipe_ctx); stream.close(); return; };
            stream.writeAll("\r\n") catch { self.allocator.destroy(pipe_ctx); stream.close(); return; };

            const drain_buf = self.allocator.alloc(u8, Config.common.http_chunk_size) catch {
                self.allocator.destroy(pipe_ctx);
                stream.close();
                return;
            };
            defer self.allocator.free(drain_buf);

            while (!pipe_ctx.retired.load(.acquire)) {
                _ = pipe_ctx.wake_event.wait(500);

                if (pipe_ctx.retired.load(.acquire)) break;

                const batch_len = self.downstream_queue.drainBatch(drain_buf);
                if (batch_len > 0) {
                    var ch_hdr: [32]u8 = undefined;
                    const ch_hdr_text = std.fmt.bufPrint(&ch_hdr, "{x}\r\n", .{batch_len}) catch unreachable;
                    stream.writeAll(ch_hdr_text) catch break;
                    stream.writeAll(drain_buf[0..batch_len]) catch break;
                    stream.writeAll("\r\n") catch break;
                }
            }

            stream.writeAll("0\r\n\r\n") catch {};
            pipe_ctx.done_event.set();
            self.allocator.destroy(pipe_ctx);
        }
    }

    fn processFrames(self: *Server, body: []const u8) void {
        var offset: usize = 0;
        while (offset + @sizeOf(protocol.Header) <= body.len) {
            var hdr: protocol.Header = undefined;
            @memcpy(std.mem.asBytes(&hdr), body[offset .. offset + @sizeOf(protocol.Header)]);

            if (hdr.magic != 0xCF01) break;
            offset += @sizeOf(protocol.Header);

            if (offset + hdr.payload_len > body.len) break;
            const payload = body[offset .. offset + hdr.payload_len];
            offset += hdr.payload_len;

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
            var dns_start_buf: [128]u8 = undefined;
            const dns_start_slice = std.fmt.bufPrint(&dns_start_buf, "{{\"domain\":\"{s}\"}}", .{raw_addr}) catch "{}";
            self.emitRemoteLog("info", "dns", "start", stream_id, dns_start_slice);

            const start_dns = getMilliTimestamp();
            if (!protocol.resolveDnsA(raw_addr, &octets)) {
                self.emitRemoteLog("error", "dns", "failed", stream_id, "{\"error\":\"resolve_timeout\"}");
                self.sendClose(stream_id);
                return;
            }
            const dns_dur = getMilliTimestamp() - start_dns;
            var dns_res: [128]u8 = undefined;
            const res_slice = std.fmt.bufPrint(&dns_res, "{{\"domain\":\"{s}\",\"ip\":\"{d}.{d}.{d}.{d}\",\"dur_ms\":{d}}}", .{ raw_addr, octets[0], octets[1], octets[2], octets[3], dns_dur }) catch "{}";
            self.emitRemoteLog("info", "dns", "done", stream_id, res_slice);
        } else {
            self.sendClose(stream_id);
            return;
        }

        const rc = std.os.linux.syscall3(.socket, 2, 1, 0);
        if (@as(isize, @bitCast(rc)) < 0) { self.sendClose(stream_id); return; }
        const sock: i32 = @intCast(rc);

        protocol.setNoDelay(sock);

        const target_addr = sockaddr_in{
            .family = 2,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @as(u32, @bitCast(octets)),
        };

        var conn_start_buf: [128]u8 = undefined;
        const conn_start_slice = std.fmt.bufPrint(&conn_start_buf, "{{\"ip\":\"{d}.{d}.{d}.{d}\",\"port\":{d}}}", .{ octets[0], octets[1], octets[2], octets[3], port }) catch "{}";
        self.emitRemoteLog("info", "target", "connect_start", stream_id, conn_start_slice);

        const start_tcp = getMilliTimestamp();
        const conn_rc = std.os.linux.syscall3(.connect, @as(usize, @bitCast(@as(isize, sock))), @intFromPtr(&target_addr), @sizeOf(sockaddr_in));
        if (@as(isize, @bitCast(conn_rc)) < 0) {
            _ = std.os.linux.syscall1(.close, @as(usize, @bitCast(@as(isize, sock))));
            self.emitRemoteLog("error", "target", "connect_failed", stream_id, "{\"error\":\"econnrefused\"}");
            self.sendClose(stream_id);
            return;
        }

        const tcp_dur = getMilliTimestamp() - start_tcp;
        var tcp_res: [128]u8 = undefined;
        const tcp_slice = std.fmt.bufPrint(&tcp_res, "{{\"ip\":\"{d}.{d}.{d}.{d}\",\"port\":{d},\"dur_ms\":{d}}}", .{ octets[0], octets[1], octets[2], octets[3], port, tcp_dur }) catch "{}";
        self.emitRemoteLog("info", "target", "connect_done", stream_id, tcp_slice);

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
        self.notifyLeader();

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
                self.closeStream(stream_id);
                return;
            }
            const s_seq = state.downstream_seq.fetchAdd(1, .monotonic);
            while (!self.downstream_queue.push(stream_id, s_seq, .data, buf[0..n])) {
                futex.Futex.wait(&state.downstream_seq, 0, 1);
            }
            self.notifyLeader();
        }
    }

    fn sendClose(self: *Server, stream_id: u32) void {
        _ = self.downstream_queue.push(stream_id, 0, .close, "");
        self.notifyLeader();
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

            self.emitRemoteLog("info", "stream", "closed", stream_id, "{}");
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
