const Build = @import("std").Build;

pub fn build(b: *Build) !void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const optimize = .ReleaseSmall;

    const wax = b.dependency("wax", .{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("wax", wax.module("wax"));

    const exe = b.addExecutable(.{
        .name = "main",
        .root_module = exe_mod,
    });

    exe.entry = .{
        .symbol_name = "user_entrypoint",
    };

    b.installArtifact(exe);

    // Tests
    const test_target = b.standardTargetOptions(.{});

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = test_target,
        .optimize = .Debug,
    });
    test_module.addImport("wax", wax.module("wax"));

    const tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_test = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_test.step);
}
