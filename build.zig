const Build = @import("std").Build;

pub fn build(b: *Build) void {
    // Define the wasm32-freestanding target
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    // Set optimization mode
    const optimize = .ReleaseSmall;

    _ = b.addModule("wax", .{
        .root_source_file = b.path("src/wax.zig"), 
        .target = target,
        .optimize = optimize,
    });
}
