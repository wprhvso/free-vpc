const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const only_server = b.option(bool, "only-server", "Build only cf-proxy-server") orelse false;

    if (!only_server) {
        const client_exe = b.addExecutable(.{
            .name = "cf-proxy-client",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main_client.zig"),
                .target = target,
                .optimize = optimize,
                .strip = true,
            }),
        });
        b.installArtifact(client_exe);
    }

    const server_exe = b.addExecutable(.{
        .name = "cf-proxy-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_server.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });

    b.installArtifact(server_exe);
}
