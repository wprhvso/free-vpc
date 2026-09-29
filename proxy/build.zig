const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const client_exe = b.addExecutable(.{
        .name = "cf-proxy-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_client.zig"),
            .target = target,
            .optimize = .small,
            .strip = true,
        }),
    });

    const server_exe = b.addExecutable(.{
        .name = "cf-proxy-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_server.zig"),
            .target = target,
            .optimize = .small,
            .strip = true,
        }),
    });

    b.installArtifact(client_exe);
    b.installArtifact(server_exe);
}
