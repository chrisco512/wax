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
    return_data: []u8,

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.calldata);
        self.allocator.free(self.return_data);
    }
};

pub fn createContext(calldata_len: usize) !Context {
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

    // const calldata = try allocator.alloc(u8, calldata_len);
    const calldata = allocator.alloc(u8, calldata_len) catch |err| {
        return err;
    };
    host.read_args(&calldata[0]);

    // TODO: Remove return_data from ctx
    const return_data = allocator.alloc(u8, 1024) catch |err| {
        return err;
    };

    return Context{
        .allocator = allocator,
        .block = .{ .number = 69 }, // Placeholder
        .calldata = calldata,
        .return_data = return_data,
    };
}
