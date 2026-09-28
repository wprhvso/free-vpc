const std = @import("std");
const protocol = @import("protocol.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    downstream_queue: std.ArrayList(u8) = .{},
    downstream_mutex: std.Thread.Mutex = .{},
    downstream_cond: std.Thread.Condition = .{},
    streams: std.AutoHashMap(u32, std.net.Stream),
    streams_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) Server {
        return .{
            .allocator = allocator,
            .host = host,
            .port = port,
            .downstream_queue = .{},
            .streams = std.AutoHashMap(u32, std.net.Stream).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.downstream_queue.deinit(self.allocator);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.close();
        }
        self.streams.deinit();
    }

    pub fn sendToDownstream(self: *Server, stream_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
        self.downstream_mutex.lock();
        defer self.downstream_mutex.unlock();
        protocol.writeFrame(&self.downstream_queue, self.allocator, stream_id, cmd, payload) catch return;
        self.downstream_cond.signal();
    }

    pub fn closeStream(self: *Server, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();
        if (removed) |entry| {
            var stream = entry.value;
            stream.close();
            self.sendToDownstream(stream_id, .close, "");
        }
    }

    pub fn start(self: *Server) !void {
        const addr = try std.net.Address.parseIp4(self.host, self.port);
        var net_server = try addr.listen(.{ .reuse_address = true });
        defer net_server.deinit();

        while (true) {
            const conn = net_server.accept() catch continue;
            const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, conn.stream });
            thread.detach();
        }
    }

    fn handleConnection(self: *Server, stream: std.net.Stream) void {
        defer stream.close();
        var read_buf: [8192]u8 = undefined;

        while (true) {
            var total_read: usize = 0;
            var header_end: ?usize = null;

            while (total_read < read_buf.len) {
                const n = stream.read(read_buf[total_read..]) catch 0;
                if (n == 0) return;
                total_read += n;

                if (std.mem.indexOf(u8, read_buf[0..total_read], "\r\n\r\n")) |idx| {
                    header_end = idx;
                    break;
                }
            }

            const h_end = header_end orelse return;
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

            if (std.mem.startsWith(u8, req_line, "POST /push")) {
                var content_len: usize = 0;
                if (findHeader(headers, "content-length:")) |val| {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, val, " \t"), 10) catch 0;
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
                    if (n == 0) return;
                    current_body_len += n;
                }

                self.processPushBody(body);

                const resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                _ = stream.writeAll(resp) catch return;
                continue;
            }

            if (std.mem.startsWith(u8, req_line, "GET /poll")) {
                self.downstream_mutex.lock();
                if (self.downstream_queue.items.len == 0) {
                    self.downstream_cond.timedWait(&self.downstream_mutex, 25 * std.time.ns_per_s) catch {};
                }

                if (self.downstream_queue.items.len > 0) {
                    const payload = self.allocator.dupe(u8, self.downstream_queue.items) catch {
                        self.downstream_mutex.unlock();
                        return;
                    };
                    self.downstream_queue.clearRetainingCapacity();
                    self.downstream_mutex.unlock();
                    defer self.allocator.free(payload);

                    var hdr_buf: [256]u8 = undefined;
                    const resp_hdr = std.fmt.bufPrint(&hdr_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n", .{payload.len}) catch return;
                    _ = stream.writeAll(resp_hdr) catch return;
                    _ = stream.writeAll(payload) catch return;
                } else {
                    self.downstream_mutex.unlock();
                    const resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                    _ = stream.writeAll(resp) catch return;
                }
                continue;
            }

            const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            _ = stream.writeAll(not_found) catch return;
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
        while (offset + 8 <= body.len) {
            const stream_id = std.mem.readInt(u32, body[offset..][0..4], .little);
            const cmd: protocol.Cmd = @enumFromInt(body[offset+4]);
            const flen = std.mem.readInt(u16, body[offset+6..][0..2], .little);
            offset += 8;

            if (offset + flen > body.len) break;
            const payload = body[offset..offset+flen];
            offset += flen;

            switch (cmd) {
                .connect => {
                    self.handleConnect(stream_id, payload);
                },
                .data => {
                    self.streams_mutex.lock();
                    const s_opt = self.streams.get(stream_id);
                    self.streams_mutex.unlock();
                    if (s_opt) |target_stream| {
                        _ = target_stream.writeAll(payload) catch {
                            self.closeStream(stream_id);
                        };
                    }
                },
                .close => {
                    self.closeStream(stream_id);
                },
                .ping => {
                    self.sendToDownstream(stream_id, .pong, "");
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

        const port = std.mem.readInt(u16, payload[0..][0..2], .big);
        const atyp = payload[2];
        const addr_len = payload[3];
        if (payload.len < 4 + addr_len) {
            self.sendToDownstream(stream_id, .close, "");
            return;
        }

        const addr_data = payload[4..4+addr_len];
        var target_addr: ?std.net.Address = null;

        if (atyp == 1 and addr_len == 4) {
            target_addr = std.net.Address.initIp4(addr_data[0..4].*, port);
        } else if (atyp == 2) {
            var list = std.net.getAddressList(self.allocator, addr_data, port) catch {
                self.sendToDownstream(stream_id, .close, "");
                return;
            };
            defer list.deinit();
            if (list.addrs.len > 0) {
                target_addr = list.addrs[0];
            }
        } else if (atyp == 4 and addr_len == 16) {
            target_addr = std.net.Address.initIp6(addr_data[0..16].*, port, 0, 0);
        }

        const final_addr = target_addr orelse {
            self.sendToDownstream(stream_id, .close, "");
            return;
        };

        const target_conn = std.net.tcpConnectToAddress(final_addr) catch {
            self.sendToDownstream(stream_id, .close, "");
            return;
        };

        self.streams_mutex.lock();
        self.streams.put(stream_id, target_conn) catch {
            self.streams_mutex.unlock();
            var tc = target_conn;
            tc.close();
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

    fn targetReaderWorker(self: *Server, stream_id: u32, target_stream: std.net.Stream) void {
        var buf: [8192]u8 = undefined;
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
