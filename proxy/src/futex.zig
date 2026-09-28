const std = @import("std");

fn getMilliTimestamp() u64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return @intCast((ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000));
}

pub const Futex = struct {
    pub fn wait(val: *const std.atomic.Value(u32), expected: u32, timeout_ms: ?u64) void {
        const timespec = extern struct {
            sec: i64,
            nsec: i64,
        };
        var ts: timespec = undefined;
        const ts_ptr: usize = if (timeout_ms) |ms| blk: {
            ts = .{
                .sec = @intCast(ms / 1000),
                .nsec = @intCast((ms % 1000) * 1_000_000),
            };
            break :blk @intFromPtr(&ts);
        } else 0;

        _ = std.os.linux.syscall4(.futex, @intFromPtr(&val.raw), 0, expected, ts_ptr);
    }

    pub fn wake(val: *const std.atomic.Value(u32), count: u32) void {
        _ = std.os.linux.syscall3(.futex, @intFromPtr(&val.raw), 1, count);
    }
};

pub const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        while (self.state.swap(2, .acquire) != 0) {
            Futex.wait(&self.state, 2, null);
        }
    }

    pub fn unlock(self: *Mutex) void {
        if (self.state.swap(0, .release) == 2) {
            Futex.wake(&self.state, 1);
        }
    }
};

pub const Event = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn wait(self: *Event, timeout_ms: ?u64) bool {
        if (timeout_ms) |t_ms| {
            const start = getMilliTimestamp();
            while (self.state.load(.acquire) == 0) {
                const now = getMilliTimestamp();
                if (now >= start + t_ms) return false;
                const remaining = (start + t_ms) - now;
                Futex.wait(&self.state, 0, remaining);
                if (self.state.load(.acquire) != 0) return true;
                if (getMilliTimestamp() >= start + t_ms) return false;
            }
            return true;
        } else {
            while (self.state.load(.acquire) == 0) {
                Futex.wait(&self.state, 0, null);
            }
            return true;
        }
    }

    pub fn set(self: *Event) void {
        self.state.store(1, .release);
        Futex.wake(&self.state, std.math.maxInt(u32));
    }

    pub fn reset(self: *Event) void {
        self.state.store(0, .release);
    }
};
