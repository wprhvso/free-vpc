const std = @import("std");
const sync = @import("../common/sync.zig");
const logger = @import("../common/logger.zig");
const protocol = @import("../common/protocol.zig");

pub const Reassembler = struct {
    target_stream: protocol.SocketStream,
    stream_id: u32,
    next_expected_seq: u32 = 1, // ИСПРАВЛЕНО: данные всегда начинаются с 1 (0 был на connect)
    mutex: sync.Mutex = .{},
    slots: [32]Slot = undefined,
    slots_count: usize = 0,

    const Slot = struct {
        seq: u32,
        len: u16,
        data: [4096]u8,
        in_use: bool = false,
    };

    pub fn init(stream_id: u32, target_stream: protocol.SocketStream) Reassembler {
        var r = Reassembler{
            .stream_id = stream_id,
            .target_stream = target_stream,
            .next_expected_seq = 1,
        };
        for (&r.slots) |*s| s.in_use = false;
        return r;
    }

    pub fn push(self: *Reassembler, seq: u32, data: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (seq < self.next_expected_seq) {
            return;
        }

        if (seq == self.next_expected_seq) {
            try self.target_stream.writeAll(data);
            self.next_expected_seq +%= 1;

            var progress = true;
            while (progress) {
                progress = false;
                for (&self.slots) |*slot| {
                    if (slot.in_use and slot.seq == self.next_expected_seq) {
                        try self.target_stream.writeAll(slot.data[0..slot.len]);
                        slot.in_use = false;
                        self.slots_count -= 1;
                        self.next_expected_seq +%= 1;
                        progress = true;
                        break;
                    }
                }
            }
            return;
        }

        if (self.slots_count >= self.slots.len) {
            logger.json(.err, "reassembler", "buffer_overflow", self.stream_id, seq, "{{\"slots\":{d}}}", .{self.slots_count});
            return error.ReassemblerOverflow;
        }

        for (&self.slots) |*slot| {
            if (!slot.in_use) {
                slot.seq = seq;
                slot.len = @intCast(@min(data.len, slot.data.len));
                @memcpy(slot.data[0..slot.len], data[0..slot.len]);
                slot.in_use = true;
                self.slots_count += 1;
                break;
            }
        }
    }
};
