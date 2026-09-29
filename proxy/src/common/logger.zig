const std = @import("std");
const sync = @import("sync.zig");

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
    fatal,

    pub fn asStr(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }
};

pub const LogHook = *const fn (line: []const u8) void;

var log_mutex: sync.Mutex = .{};
var global_role: Role = .client;
var global_hook: ?LogHook = null;

pub fn setRole(role: Role) void {
    global_role = role;
}

pub fn setHook(hook: ?LogHook) void {
    global_hook = hook;
}

pub fn json(
    level: Level,
    subsys: []const u8,
    event: []const u8,
    ctx_stream_id: ?u32,
    ctx_seq: ?u32,
    comptime data_fmt: []const u8,
    args: anytype,
) void {
    var raw_buf: [2048]u8 = undefined;
    var data_buf: [1536]u8 = undefined;
    var ctx_buf: [256]u8 = undefined;

    const data_str = std.fmt.bufPrint(&data_buf, data_fmt, args) catch "{}";

    const s_id_str = if (ctx_stream_id) |s| std.fmt.bufPrint(&raw_buf, "{d}", .{s}) catch "null" else "null";
    _ = s_id_str;
    const ctx_str = if (ctx_stream_id) |s| blk: {
        if (ctx_seq) |seq| {
            break :blk std.fmt.bufPrint(&ctx_buf, "{{\"stream_id\":{d},\"seq\":{d}}}", .{ s, seq }) catch "{}";
        } else {
            break :blk std.fmt.bufPrint(&ctx_buf, "{{\"stream_id\":{d},\"seq\":null}}", .{s}) catch "{}";
        }
    } else "{\"stream_id\":null,\"seq\":null}";

    log_mutex.lock();
    defer log_mutex.unlock();

    const line = std.fmt.bufPrint(
        &raw_buf,
        "{{\"ts\":{d},\"role\":\"{s}\",\"lvl\":\"{s}\",\"subsys\":\"{s}\",\"event\":\"{s}\",\"ctx\":{s},\"data\":{s}}}\n",
        .{
            sync.getMilliTimestamp(),
            global_role.asStr(),
            level.asStr(),
            subsys,
            event,
            ctx_str,
            data_str,
        },
    ) catch return;

    if (global_hook) |hook| {
        hook(line);
    } else {
        _ = std.os.linux.syscall3(
            .write,
            2,
            @intFromPtr(line.ptr),
            line.len,
        );
    }
}
