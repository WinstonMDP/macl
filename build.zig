pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "macl",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .optimize = b.standardOptimizeOption(.{}),
        }),
    });

    exe.linkLibC();
    exe.linkSystemLibrary("acl");
    exe.linkSystemLibrary("sqlite3");

    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| run_exe.addArgs(args);
    const run_step = b.step("run", "Run macl");
    run_step.dependOn(&run_exe.step);
}

const std = @import("std");
