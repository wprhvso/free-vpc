const std = @import("std");
const protocol = @import("protocol.zig");
const futex = @import("futex.zig");

pub const FrameQueue = struct {
    data: []u8,
    read_pos: usize = 0,
    write_pos: usize = 0,
    count: usize = 0,
    mutex: futex.Mutex = .{},
    has_data_event: futex.Event = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !FrameQueue {
        return .{
            .data = try allocator.alloc(u8, capacity),
        };
    }

    pub fn deinit(self: *FrameQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn push(self: *FrameQueue, stream_id: u32, seq_id: u32, cmd: protocol.Cmd, payload: []const u8) bool {
        const frame_size = @sizeOf(protocol.Header) + payload.len;
        if (frame_size > self.data.len) return false;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count + frame_size > self.data.len) return false;

        const hdr = protocol.Header{
            .magic = 0xCF01,
            .payload_len = @intCast(payload.len),
            .stream_id = stream_id,
            .seq_id = seq_id,
            .cmd = cmd,
        };

        const hdr_bytes: *const [@sizeOf(protocol.Header)]u8 = @ptrCast(&hdr);
        self.writeBytes(hdr_bytes);
        if (payload.len > 0) {
            self.writeBytes(payload);
        }

        self.count += frame_size;
        self.has_data_event.set();
        return true;
    }

    fn writeBytes(self: *FrameQueue, bytes: []const u8) void {
        const first = @min(bytes.len, self.data.len - self.write_pos);
        @memcpy(self.data[self.write_pos .. self.write_pos + first], bytes[0..first]);
        const second = bytes.len - first;
        if (second > 0) {
            @memcpy(self.data[0..second], bytes[first..]);
        }
        self.write_pos = (self.write_pos + bytes.len) % self.data.len;
    }

    fn peekBytes(self: *FrameQueue, dest: []u8, offset: usize) void {
        const pos = (self.read_pos + offset) % self.data.len;
        const first = @min(dest.len, self.data.len - pos);
        @memcpy(dest[0..first], self.data[pos .. pos + first]);
        const second = dest.len - first;
        if (second > 0) {
            @memcpy(dest[first..], self.data[0..second]);
        }
    }

    pub fn peekBatch(self: *FrameQueue, dest: []u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total: usize = 0;
        var r_pos = self.read_pos;
        var remaining = self.count;

        while (remaining >= @sizeOf(protocol.Header)) {
            var hdr: protocol.Header = undefined;
            const pos = r_pos % self.data.len;
            const first = @min(@sizeOf(protocol.Header), self.data.len - pos);
            @memcpy(std.mem.asBytes(&hdr)[0..first], self.data[pos .. pos + first]);
            const second = @sizeOf(protocol.Header) - first;
            if (second > 0) {
                @memcpy(std.mem.asBytes(&hdr)[first..], self.data[0..second]);
            }

            if (hdr.magic != 0xCF01) {
                break;
            }

            const frame_size = @sizeOf(protocol.Header) + hdr.payload_len;
            if (remaining < frame_size) break;
            if (total + frame_size > dest.len) break;

            const c_first = @min(frame_size, self.data.len - r_pos);
            @memcpy(dest[total .. total + c_first], self.data[r_pos .. r_pos + c_first]);
            const c_second = frame_size - c_first;
            if (c_second > 0) {
                @memcpy(dest[total + c_first .. total + frame_size], self.data[0..c_second]);
            }

            r_pos = (r_pos + frame_size) % self.data.len;
            remaining -= frame_size;
            total += frame_size;
        }

        return total;
    }

    pub fn commitBatch(self: *FrameQueue, len: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (len == 0) return;
        const actual_len = @min(len, self.count);
        self.read_pos = (self.read_pos + actual_len) % self.data.len;
        self.count -= actual_len;

        if (self.count == 0) {
            self.has_data_event.reset();
        }
    }

    pub fn drainBatch(self: *FrameQueue, dest: []u8) usize {
        const total = self.peekBatch(dest);
        self.commitBatch(total);
        return total;
    }

    pub fn waitData(self: *FrameQueue, timeout_ms: ?u64) bool {
        return self.has_data_event.wait(timeout_ms);
    }
};
