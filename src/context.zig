const std = @import("std");
const builtin = @import("builtin");
const arb_wasm_allocator = @import("mem/arb_wasm_allocator.zig").allocator;
const host = @import("hostio.zig");

// Context struct contains vm data like block number, timestamp, etc
// Plus access to storage via Context.store
pub const Context = struct {
    allocator: std.mem.Allocator,
    block: struct {
        number: u256,
    },
    calldata: []const u8,

    pub fn init(calldata_len: usize) !Context {
        // Conditional allocator based on target architecture
        const allocator = blk: {
            if (builtin.target.isWasm()) {
                break :blk arb_wasm_allocator;
            } else if (builtin.is_test) {
                break :blk std.testing.allocator; // Use dynamic allocator for tests
            } else {
                @compileError("Invalid target, no allocator found. (Target WASM or test builds only)");
            }
        };

        const calldata = try allocator.alloc(u8, calldata_len);
        host.read_args(&calldata[0]);

        return Context{
            .allocator = allocator,
            .block = .{ .number = 69 }, // Placeholder
            .calldata = calldata,
        };
    }

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.calldata);
    }
};
