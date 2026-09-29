const std = @import("std");
const sync = @import("../common/sync.zig");
const protocol = @import("../common/protocol.zig");

pub const StreamContext = struct {
    stream_id: u32,
    client_stream: protocol.SocketStream,
    connected_event: sync.Event = .{},
    connect_success: bool = false,
    active: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    next_upstream_seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    accumulated_buf: [4096]u8 = undefined,
    accumulated_len: usize = 0,
    first_byte_time: i64 = 0,
    buf_mutex: sync.Mutex = .{},
};

pub const StreamManager = struct {
    mutex: sync.Mutex = .{},
    streams: std.AutoHashMap(u32, *StreamContext),
    next_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(allocator: std.mem.Allocator) StreamManager {
        return .{
            .streams = std.AutoHashMap(u32, *StreamContext).init(allocator),
        };
    }

    pub fn createStream(self: *StreamManager, allocator: std.mem.Allocator, client_stream: protocol.SocketStream) !*StreamContext {
        const sid = self.next_id.fetchAdd(1, .monotonic);
        const ctx = try allocator.create(StreamContext);
        ctx.* = .{
            .stream_id = sid,
            .client_stream = client_stream,
        };
        self.mutex.lock();
        try self.streams.put(sid, ctx);
        self.mutex.unlock();
        return ctx;
    }

    pub fn get(self: *StreamManager, stream_id: u32) ?*StreamContext {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.streams.get(stream_id);
    }

    pub fn remove(self: *StreamManager, stream_id: u32) ?*StreamContext {
        self.mutex.lock();
        defer self.mutex.unlock();
        return if (self.streams.fetchRemove(stream_id)) |kv| kv.value else null;
    }
};

pub var global_manager: ?*StreamManager = null;
