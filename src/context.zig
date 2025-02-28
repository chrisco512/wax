const std = @import("std");
const builtin = @import("builtin");
const arb_wasm_allocator = @import("mem/arb_wasm_allocator.zig").allocator;
const host = @import("hostio.zig");
const wax = @import("root.zig");
const Store = @import("store.zig").Store;
const Address = @import("types.zig").Address;

// Context struct contains vm data like block number, timestamp, etc
// Plus access to storage via Context.store
// TODO: Need to think more about which fields here are mutable/immutable
// and how to protect certain values
pub fn Context(comptime UserStore: type) type {
    return struct {
        allocator: std.mem.Allocator,
        block: struct { number: u256 },
        calldata: []const u8,
        returndata: ?[]u8 = null,
        revertdata: ?[]u8 = null,
        store: Store(UserStore),

        pub fn init(calldata_len: usize) !@This() {
            const allocator = blk: {
                if (builtin.target.isWasm()) break :blk arb_wasm_allocator;
                if (builtin.is_test) break :blk std.testing.allocator;
                @compileError("Invalid target, no allocator found.");
            };

            const calldata = try allocator.alloc(u8, calldata_len);
            host.read_args(&calldata[0]);

            return .{
                .allocator = allocator,
                .block = .{ .number = 69 },
                .calldata = calldata,
                .store = .{}, // Use default proxy types
            };
        }

        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.calldata);
            if (self.returndata) |data| self.allocator.free(data);
            if (self.revertdata) |data| self.allocator.free(data);
        }

        pub fn revert(self: *@This(), comptime ErrorType: type, err: ErrorType) !void {
            const err_data = try wax.encodeCustomError(ErrorType, err, self.allocator);
            if (self.revertdata == null) self.revertdata = err_data;
            return error.Revert;
        }

        pub fn msg_sender(self: *@This()) Address {
            _ = self;
            var sender: [20]u8 = undefined;
            host.msg_sender(&sender[0]);
            return std.mem.readInt(u160, sender[0..], .big);
        }
    };
}
