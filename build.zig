const Build = @import("std").Build;

pub fn build(b: *Build) void {
    _ = b.addModule("wax", .{
        .root_source_file = b.path("src/root.zig"),
    });

    // Tests
    const test_target = b.standardTargetOptions(.{});

    const tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    const run_test = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_test.step);
}
