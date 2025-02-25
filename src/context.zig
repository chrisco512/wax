const std = @import("std");
const builtin = @import("builtin");
const arb_wasm_allocator = @import("mem/arb_wasm_allocator.zig").allocator;
const host = @import("hostio.zig");
const wax = @import("root.zig");

// Context struct contains vm data like block number, timestamp, etc
// Plus access to storage via Context.store
// TODO: Need to think more about which fields here are mutable/immutable
// and how to protect certain values
pub const Context = struct {
    allocator: std.mem.Allocator,
    block: struct {
        number: u256,
    },
    calldata: []const u8,
    returndata: ?[]u8 = null,
    revertdata: ?[]u8 = null,

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
        if (self.returndata) |data| self.allocator.free(data);
        if (self.revertdata) |data| self.allocator.free(data);
    }

    pub fn revert(self: *Context, comptime ErrorType: type, err: ErrorType) !void {
        const err_data = try wax.encodeCustomError(ErrorType, err, self.allocator);

        if (self.revert_data == null) {
            self.revert_data = err_data;
        }

        return error.Revert;
    }
};
