const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const proto_mod = b.createModule(.{
        .root_source_file = b.path("src/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/main_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("protocol", proto_mod);

    const client_exe = b.addExecutable(.{
        .name = "cf-proxy-client",
        .root_module = client_mod,
    });

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/main_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("protocol", proto_mod);

    const server_exe = b.addExecutable(.{
        .name = "cf-proxy-server",
        .root_module = server_mod,
    });

    if (b.lazyDependency("picohttpparser", .{})) |pico_dep| {
        client_mod.link_libc = true;
        client_mod.addIncludePath(pico_dep.path("."));
        client_mod.addCSourceFile(.{ .file = pico_dep.path("picohttpparser.c"), .flags = &.{"-O3"} });

        server_mod.link_libc = true;
        server_mod.addIncludePath(pico_dep.path("."));
        server_mod.addCSourceFile(.{ .file = pico_dep.path("picohttpparser.c"), .flags = &.{"-O3"} });
    }

    b.installArtifact(client_exe);
    b.installArtifact(server_exe);
}
