const std = @import("std");
const futex = @import("futex.zig");

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn asStr(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

var log_mutex: futex.Mutex = .{};

fn getMilliTimestamp() u64 {
    const timespec = extern struct {
        sec: i64,
        nsec: i64,
    };
    var ts: timespec = undefined;
    _ = std.os.linux.syscall2(.clock_gettime, 0, @intFromPtr(&ts));
    return @intCast((ts.sec * 1000) + @divTrunc(ts.nsec, 1_000_000));
}

pub fn json(
    level: Level,
    subsys: []const u8,
    event: []const u8,
    comptime data_fmt: []const u8,
    args: anytype,
) void {
    var raw_buf: [2048]u8 = undefined;
    var data_buf: [1536]u8 = undefined;

    const data_str = std.fmt.bufPrint(&data_buf, data_fmt, args) catch "{}";

    log_mutex.lock();
    defer log_mutex.unlock();

    const line = std.fmt.bufPrint(
        &raw_buf,
        "{{\"ts\":{d},\"level\":\"{s}\",\"subsys\":\"{s}\",\"event\":\"{s}\",\"data\":{s}}}\n",
        .{
            getMilliTimestamp(),
            level.asStr(),
            subsys,
            event,
            data_str,
        },
    ) catch return;

    _ = std.os.linux.syscall3(
        .write,
        2,
        @intFromPtr(line.ptr),
        line.len,
    );
}
