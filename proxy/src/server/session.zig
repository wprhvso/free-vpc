const std = @import("std");
const sync = @import("../common/sync.zig");
const protocol = @import("../common/protocol.zig");
const logger = @import("../common/logger.zig");
const Reassembler = @import("reassembler.zig").Reassembler;

pub const Session = struct {
    id: [32]u8,
    allocator: std.mem.Allocator,
    downstream_stream: ?protocol.SocketStream = null,
    downstream_mutex: sync.Mutex = .{},
    streams_mutex: sync.Mutex = .{},
    streams: std.AutoHashMap(u32, *StreamEntry),

    pub const StreamEntry = struct {
        id: u32,
        target_stream: protocol.SocketStream,
        reassembler: Reassembler,
        active: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    };

    pub fn init(allocator: std.mem.Allocator, session_id: []const u8) !*Session {
        const s = try allocator.create(Session);
        s.* = .{
            .id = undefined,
            .allocator = allocator,
            .streams = std.AutoHashMap(u32, *StreamEntry).init(allocator),
        };
        @memcpy(&s.id, session_id[0..32]);
        return s;
    }

    pub fn attachDownstream(self: *Session, stream: protocol.SocketStream) void {
        {
            self.downstream_mutex.lock();
            defer self.downstream_mutex.unlock();
            if (self.downstream_stream) |old| old.close();
            self.downstream_stream = stream;
        }
        logger.json(.info, "session", "downstream_attached", null, null, "{{\"session\":\"{s}\"}}", .{self.id});
    }

    pub fn sendDownstreamFrame(self: *Session, cmd: protocol.Cmd, stream_id: u32, payload: []const u8) !void {
        self.downstream_mutex.lock();
        defer self.downstream_mutex.unlock();

        const ds = self.downstream_stream orelse {
            logger.json(.err, "session", "downstream_null_cant_send", stream_id, null, "{{\"cmd\":\"{s}\"}}", .{@tagName(cmd)});
            return error.DownstreamNotConnected;
        };

        var hdr_buf: [16]u8 = undefined;
        const fh = protocol.FrameHeader{
            .magic = 0x5455,
            .cmd = cmd,
            .flags = 0,
            .stream_id = stream_id,
            .seq = 0,
            .payload_len = @intCast(payload.len),
        };
        fh.serialize(&hdr_buf);

        const total_len = 16 + payload.len;
        var chunk_hdr: [32]u8 = undefined;
        const ch_str = std.fmt.bufPrint(&chunk_hdr, "{x}\r\n", .{total_len}) catch return error.FormatError;

        ds.writeAll(ch_str) catch |err| {
            logger.json(.err, "session", "ds_write_chunk_err", stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            return err;
        };
        ds.writeAll(&hdr_buf) catch |err| {
            logger.json(.err, "session", "ds_write_hdr_err", stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            return err;
        };
        if (payload.len > 0) {
            ds.writeAll(payload) catch |err| {
                logger.json(.err, "session", "ds_write_payload_err", stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                return err;
            };
        }
        ds.writeAll("\r\n") catch |err| {
            logger.json(.err, "session", "ds_write_trailer_err", stream_id, null, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
            return err;
        };
    }
};

pub var global_session: ?*Session = null;

threadlocal var is_logging: bool = false;

pub fn serverLogHook(line: []const u8) void {
    if (is_logging) return;
    is_logging = true;
    defer is_logging = false;

    if (global_session) |s| {
        const payload = if (line.len > 0 and line[line.len - 1] == '\n') line[0 .. line.len - 1] else line;
        s.sendDownstreamFrame(.log, 0, payload) catch {};
    }
}
