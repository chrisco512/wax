const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Route = wax.Route;
const Router = wax.Router;
const Context = wax.Context;
const NextFn = wax.NextFn;
const createContext = wax.createContext;

fn mw(ctx: *const Context, next: *const NextFn) anyerror!void {
    if (builtin.is_test) {
        std.debug.print("in the mw\n", .{});
    }

    try next(ctx);
}

fn mw2(ctx: *const Context, next: *const NextFn) anyerror!void {
    if (builtin.is_test) {
        std.debug.print("in mw2, woo!\n", .{});
    }

    try next(ctx);
}

fn foo(ctx: *const Context) void {
    _ = ctx;

    if (builtin.is_test) {
        std.debug.print("foo says hello\n", .{});
    }
}

fn bar(ctx: *const Context, n: u256) u256 {
    _ = n;

    if (builtin.is_test) {
        std.debug.print("bar: blockNum: {d}\n", .{ctx.block.number});
    }

    return ctx.block.number;
}

export fn user_entrypoint(len: usize) i32 {
    var ctx = createContext(len) catch return 1;
    defer ctx.deinit();

    const routes = comptime [_]Route{
        Route.init("foo", .{}, foo),
        Route.init("bar", .{ mw, mw2 }, bar),
    };

    if (Router.handle(&routes, &ctx)) |_| {
        return 0;
    } else |_| {
        return 1;
    }
}

// Test setup
test "user_entrypoint with bar" {
    // Mock calldata: selector for "bar" + u256 argument (42)
    const selector = comptime wax.getSelector("bar", bar);
    const selector_bytes = [_]u8{
        @intCast((selector >> 24) & 0xFF),
        @intCast((selector >> 16) & 0xFF),
        @intCast((selector >> 8) & 0xFF),
        @intCast(selector & 0xFF),
    };
    var arg_bytes = [_]u8{0} ** 32;
    arg_bytes[31] = 42;
    var calldata: [36]u8 = undefined;
    @memcpy(calldata[0..4], &selector_bytes);
    @memcpy(calldata[4..36], &arg_bytes);

    // Mock hooks
    const MockHooks = struct {
        var mock_calldata: []const u8 = &.{};
        var result_data: ?[]u8 = null;

        pub fn pay_for_memory_grow(_: u32) callconv(.C) void {}

        pub fn read_args(dest: *u8) callconv(.C) void {
            const dest_ptr = @intFromPtr(dest);
            const src_ptr = @intFromPtr(mock_calldata.ptr);
            for (0..mock_calldata.len) |i| {
                const dest_addr = dest_ptr + i;
                const src_addr = src_ptr + i;
                @as(*u8, @ptrFromInt(dest_addr)).* = @as(*const u8, @ptrFromInt(src_addr)).*;
            }
        }

        pub fn write_result(data: *const u8, len: usize) callconv(.C) void {
            const allocator = std.testing.allocator;
            if (result_data) |old_data| allocator.free(old_data);
            result_data = allocator.alloc(u8, len) catch return;
            // Unsafe manual copy with pointer arithmetic
            const dest_ptr = @intFromPtr(result_data.?.ptr);
            const src_ptr = @intFromPtr(data);
            for (0..len) |i| {
                const dest_addr = dest_ptr + i;
                const src_addr = src_ptr + i;
                @as(*u8, @ptrFromInt(dest_addr)).* = @as(*const u8, @ptrFromInt(src_addr)).*;
            }
        }

        pub fn deinit() void {
            if (result_data) |data| {
                std.testing.allocator.free(data);
                result_data = null;
            }
        }
    };

    // Set mock calldata
    MockHooks.mock_calldata = &calldata;
    defer MockHooks.deinit();

    // Override VM hooks
    @export(&MockHooks.pay_for_memory_grow, .{ .name = "pay_for_memory_grow" });
    @export(&MockHooks.read_args, .{ .name = "read_args" });
    @export(&MockHooks.write_result, .{ .name = "write_result" });

    // Run the entrypoint
    const result = user_entrypoint(calldata.len);
    try std.testing.expectEqual(@as(i32, 0), result);

    // Verify return data
    const result_data = MockHooks.result_data orelse return error.NoResultData;
    try std.testing.expectEqual(@as(usize, 32), result_data.len); // u256 is 32 bytes
    const returned_value = std.mem.readInt(u256, result_data[0..32], .big);
    try std.testing.expectEqual(@as(u256, 69), returned_value);
}
