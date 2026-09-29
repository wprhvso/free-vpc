const std = @import("std");
const futex = @import("futex.zig");

pub const Role = enum {
    client,
    server,

    pub fn asStr(self: Role) []const u8 {
        return switch (self) {
            .client => "client",
            .server => "server",
        };
    }
};

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

pub const LogHook = *const fn (line: []const u8) void;

var log_mutex: futex.Mutex = .{};
var global_role: Role = .client;
var global_hook: ?LogHook = null;

pub fn setRole(role: Role) void {
    global_role = role;
}

pub fn setHook(hook: ?LogHook) void {
    global_hook = hook;
}

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
        "{{\"ts\":{d},\"role\":\"{s}\",\"level\":\"{s}\",\"subsys\":\"{s}\",\"event\":\"{s}\",\"data\":{s}}}\n",
        .{
            getMilliTimestamp(),
            global_role.asStr(),
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

    if (global_hook) |hook| {
        // Drop trailing newline when transmitting over tunnel
        const payload = if (line.len > 0 and line[line.len - 1] == '\n') line[0 .. line.len - 1] else line;
        hook(payload);
    }
}
