const Build = @import("std").Build;

pub fn build(b: *Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const optimize = .ReleaseSmall;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "main",
        .root_module = exe_mod,
    });

    exe.entry = .{
        .symbol_name = "user_entrypoint",
    };

    const wax = b.dependency("wax", .{});
    exe.root_module.addImport("wax", wax.module("wax"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "run the app");
    run_step.dependOn(&run_cmd.step);
}
