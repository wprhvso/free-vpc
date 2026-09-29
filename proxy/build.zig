const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Объявляем флаги сборки
    const only_client = b.option(bool, "only-client", "Собрать только клиент") orelse false;
    const only_server = b.option(bool, "only-server", "Собрать только сервер") orelse false;

    // Защита от одновременного указания обоих взаимоисключающих флагов
    if (only_client and only_server) {
        @panic("Нельзя указывать одновременно -Donly-client и -Donly-server!");
    }

    // Определяем, что нужно собирать (по умолчанию собираются оба)
    const build_client = !only_server;
    const build_server = !only_client;

    // 1. Сборка cf-proxy-client
    if (build_client) {
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

        // Создаем отдельный удобный шаг: zig build client
        const client_step = b.step("client", "Собрать только клиент");
        client_step.dependOn(&b.addInstallArtifact(client_exe, .{}).step);
    }

    // 2. Сборка cf-proxy-server
    if (build_server) {
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

        // Создаем отдельный удобный шаг: zig build server
        const server_step = b.step("server", "Собрать только сервер");
        server_step.dependOn(&b.addInstallArtifact(server_exe, .{}).step);
    }
}
