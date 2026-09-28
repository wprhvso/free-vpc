const std = @import("std");
const protocol = @import("protocol.zig");

pub const Client = struct {
    allocator: std.mem.Allocator,
    remote_url: []const u8,
    socks_addr: ?[]const u8,
    forward_rule: ?[]const u8,
    upstream_queue: std.ArrayList(u8) = .{},
    upstream_mutex: std.Thread.Mutex = .{},
    upstream_cond: std.Thread.Condition = .{},
    local_streams: std.AutoHashMap(u32, std.net.Stream),
    streams_mutex: std.Thread.Mutex = .{},
    next_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(allocator: std.mem.Allocator, remote_url: []const u8, socks_addr: ?[]const u8, forward_rule: ?[]const u8) Client {
        return .{
            .allocator = allocator,
            .remote_url = remote_url,
            .socks_addr = socks_addr,
            .forward_rule = forward_rule,
            .upstream_queue = .{},
            .local_streams = std.AutoHashMap(u32, std.net.Stream).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.upstream_queue.deinit(self.allocator);
        var it = self.local_streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.close();
        }
        self.local_streams.deinit();
    }

    pub fn sendToUpstream(self: *Client, stream_id: u32, cmd: protocol.Cmd, payload: []const u8) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        protocol.writeFrame(&self.upstream_queue, self.allocator, stream_id, cmd, payload) catch return;
        self.upstream_cond.signal();
    }

    pub fn closeLocalStream(self: *Client, stream_id: u32) void {
        self.streams_mutex.lock();
        const removed = self.local_streams.fetchRemove(stream_id);
        self.streams_mutex.unlock();
        if (removed) |entry| {
            var stream = entry.value;
            stream.close();
            self.sendToUpstream(stream_id, .close, "");
        }
    }

    pub fn start(self: *Client) !void {
        const push_thread = try std.Thread.spawn(.{}, upstreamPushWorker, .{self});
        push_thread.detach();

        const poll_thread1 = try std.Thread.spawn(.{}, downstreamPollWorker, .{self});
        poll_thread1.detach();

        const poll_thread2 = try std.Thread.spawn(.{}, downstreamPollWorker, .{self});
        poll_thread2.detach();

        if (self.forward_rule) |fwd| {
            const fwd_thread = try std.Thread.spawn(.{}, forwardListener, .{ self, fwd });
            fwd_thread.detach();
        }

        if (self.socks_addr) |socks| {
            try self.socksListener(socks);
        } else {
            while (true) {
                std.Thread.sleep(1 * std.time.ns_per_s);
            }
        }
    }

    fn upstreamPushWorker(self: *Client) void {
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();

        const push_url = std.fmt.allocPrint(self.allocator, "{s}/push", .{self.remote_url}) catch return;
        defer self.allocator.free(push_url);
        const uri = std.Uri.parse(push_url) catch return;

        while (true) {
            self.upstream_mutex.lock();
            while (self.upstream_queue.items.len == 0) {
                self.upstream_cond.wait(&self.upstream_mutex);
            }

            if (self.upstream_queue.items.len < 2048) {
                self.upstream_mutex.unlock();
                std.Thread.sleep(2 * std.time.ns_per_ms);
                self.upstream_mutex.lock();
            }

            const payload = self.allocator.dupe(u8, self.upstream_queue.items) catch {
                self.upstream_mutex.unlock();
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            self.upstream_queue.clearRetainingCapacity();
            self.upstream_mutex.unlock();

            var req = http_client.request(.POST, uri, .{}) catch {
                self.allocator.free(payload);
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };

            req.sendBodyComplete(payload) catch {
                req.deinit();
                self.allocator.free(payload);
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            self.allocator.free(payload);

            var head_buf: [1024]u8 = undefined;
            _ = req.receiveHead(&head_buf) catch {};
            req.deinit();
        }
    }

    fn downstreamPollWorker(self: *Client) void {
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();

        const poll_url = std.fmt.allocPrint(self.allocator, "{s}/poll", .{self.remote_url}) catch return;
        defer self.allocator.free(poll_url);
        const uri = std.Uri.parse(poll_url) catch return;

        var transfer_buf: [64]u8 = undefined;
        var body_buf: std.ArrayList(u8) = .{};
        defer body_buf.deinit(self.allocator);

        while (true) {
            var req = http_client.request(.GET, uri, .{}) catch {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                continue;
            };

            req.sendBodiless() catch {
                req.deinit();
                std.Thread.sleep(100 * std.time.ns_per_ms);
                continue;
            };

            var head_buf: [1024]u8 = undefined;
            var resp = req.receiveHead(&head_buf) catch {
                req.deinit();
                std.Thread.sleep(100 * std.time.ns_per_ms);
                continue;
            };

            if (resp.head.status == .ok) {
                body_buf.clearRetainingCapacity();
                const reader = resp.reader(&transfer_buf);
                var chunk_buf: [4096]u8 = undefined;

                while (true) {
                    const n = reader.readSliceShort(&chunk_buf) catch 0;
                    if (n == 0) break;
                    body_buf.appendSlice(self.allocator, chunk_buf[0..n]) catch break;
                }

                req.deinit();
                self.processPollBody(body_buf.items);
            } else {
                req.deinit();
                if (resp.head.status != .no_content) {
                    std.Thread.sleep(100 * std.time.ns_per_ms);
                }
            }
        }
    }

    fn processPollBody(self: *Client, body: []const u8) void {
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
                .data => {
                    self.streams_mutex.lock();
                    const s_opt = self.local_streams.get(stream_id);
                    self.streams_mutex.unlock();
                    if (s_opt) |local_stream| {
                        _ = local_stream.writeAll(payload) catch {
                            self.closeLocalStream(stream_id);
                        };
                    }
                },
                .close => {
                    self.streams_mutex.lock();
                    const removed = self.local_streams.fetchRemove(stream_id);
                    self.streams_mutex.unlock();
                    if (removed) |entry| {
                        var stream = entry.value;
                        stream.close();
                    }
                },
                else => {},
            }
        }
    }

    fn socksListener(self: *Client, socks_str: []const u8) !void {
        var port: u16 = 1080;
        var host = socks_str;

        if (std.mem.indexOfScalar(u8, socks_str, ':')) |colon| {
            host = socks_str[0..colon];
            port = std.fmt.parseInt(u16, socks_str[colon+1..], 10) catch 1080;
        }

        const addr = try std.net.Address.parseIp4(host, port);
        var listener = try addr.listen(.{ .reuse_address = true });
        defer listener.deinit();

        while (true) {
            const conn = listener.accept() catch continue;
            const thread = try std.Thread.spawn(.{}, handleSocksConnection, .{ self, conn.stream });
            thread.detach();
        }
    }

    fn handleSocksConnection(self: *Client, stream: std.net.Stream) void {
        var hand_buf: [257]u8 = undefined;
        var n = stream.read(hand_buf[0..2]) catch 0;
        if (n < 2 or hand_buf[0] != 5) {
            stream.close();
            return;
        }

        const nmethods = hand_buf[1];
        n = stream.read(hand_buf[0..nmethods]) catch 0;
        if (n < nmethods) {
            stream.close();
            return;
        }

        _ = stream.writeAll(&[_]u8{ 5, 0 }) catch {
            stream.close();
            return;
        };

        var req_buf: [4]u8 = undefined;
        n = stream.read(req_buf[0..4]) catch 0;
        if (n < 4 or req_buf[0] != 5 or req_buf[1] != 1) {
            stream.close();
            return;
        }

        const atyp = req_buf[3];
        var addr_buf: [256]u8 = undefined;
        var addr_len: u8 = 0;

        if (atyp == 1) {
            addr_len = 4;
            n = stream.read(addr_buf[0..4]) catch 0;
            if (n < 4) {
                stream.close();
                return;
            }
        } else if (atyp == 3) {
            var domain_len_buf: [1]u8 = undefined;
            n = stream.read(domain_len_buf[0..1]) catch 0;
            if (n < 1) {
                stream.close();
                return;
            }
            addr_len = domain_len_buf[0];
            n = stream.read(addr_buf[0..addr_len]) catch 0;
            if (n < addr_len) {
                stream.close();
                return;
            }
        } else if (atyp == 4) {
            addr_len = 16;
            n = stream.read(addr_buf[0..16]) catch 0;
            if (n < 16) {
                stream.close();
                return;
            }
        } else {
            stream.close();
            return;
        }

        var port_buf: [2]u8 = undefined;
        n = stream.read(port_buf[0..2]) catch 0;
        if (n < 2) {
            stream.close();
            return;
        }

        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        var conn_payload: std.ArrayList(u8) = .{};
        defer conn_payload.deinit(self.allocator);
        conn_payload.appendSlice(self.allocator, &port_buf) catch {
            stream.close();
            return;
        };
        conn_payload.append(self.allocator, if (atyp == 3) 2 else atyp) catch {
            stream.close();
            return;
        };
        conn_payload.append(self.allocator, addr_len) catch {
            stream.close();
            return;
        };
        conn_payload.appendSlice(self.allocator, addr_buf[0..addr_len]) catch {
            stream.close();
            return;
        };

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, stream) catch {
            self.streams_mutex.unlock();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        self.sendToUpstream(stream_id, .connect, conn_payload.items);

        const success_reply = [_]u8{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        _ = stream.writeAll(&success_reply) catch {
            self.closeLocalStream(stream_id);
            return;
        };

        var data_buf: [8192]u8 = undefined;
        while (true) {
            const rd = stream.read(&data_buf) catch 0;
            if (rd == 0) {
                self.closeLocalStream(stream_id);
                return;
            }
            self.sendToUpstream(stream_id, .data, data_buf[0..rd]);
        }
    }

    fn forwardListener(self: *Client, fwd_rule: []const u8) void {
        var it = std.mem.splitScalar(u8, fwd_rule, ':');
        const l_port_str = it.next() orelse return;
        const r_host = it.next() orelse return;
        const r_port_str = it.next() orelse return;

        const l_port = std.fmt.parseInt(u16, l_port_str, 10) catch return;
        const r_port = std.fmt.parseInt(u16, r_port_str, 10) catch return;

        const addr = std.net.Address.parseIp4("127.0.0.1", l_port) catch return;
        var listener = addr.listen(.{ .reuse_address = true }) catch return;
        defer listener.deinit();

        while (true) {
            const conn = listener.accept() catch continue;
            const thread = std.Thread.spawn(.{}, handleForwardConnection, .{ self, conn.stream, r_host, r_port }) catch {
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn handleForwardConnection(self: *Client, stream: std.net.Stream, r_host: []const u8, r_port: u16) void {
        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);

        var conn_payload: std.ArrayList(u8) = .{};
        defer conn_payload.deinit(self.allocator);

        var port_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &port_bytes, r_port, .big);
        conn_payload.appendSlice(self.allocator, &port_bytes) catch {
            stream.close();
            return;
        };

        if (std.net.Address.parseIp4(r_host, 0)) |ip4| {
            conn_payload.append(self.allocator, 1) catch {
                stream.close();
                return;
            };
            conn_payload.append(self.allocator, 4) catch {
                stream.close();
                return;
            };
            const octets = @as(*const [4]u8, @ptrCast(&ip4.in.sa.addr));
            conn_payload.appendSlice(self.allocator, octets) catch {
                stream.close();
                return;
            };
        } else |_| {
            conn_payload.append(self.allocator, 2) catch {
                stream.close();
                return;
            };
            conn_payload.append(self.allocator, @intCast(r_host.len)) catch {
                stream.close();
                return;
            };
            conn_payload.appendSlice(self.allocator, r_host) catch {
                stream.close();
                return;
            };
        }

        self.streams_mutex.lock();
        self.local_streams.put(stream_id, stream) catch {
            self.streams_mutex.unlock();
            stream.close();
            return;
        };
        self.streams_mutex.unlock();

        self.sendToUpstream(stream_id, .connect, conn_payload.items);

        var data_buf: [8192]u8 = undefined;
        while (true) {
            const rd = stream.read(&data_buf) catch 0;
            if (rd == 0) {
                self.closeLocalStream(stream_id);
                return;
            }
            self.sendToUpstream(stream_id, .data, data_buf[0..rd]);
        }
    }
};
