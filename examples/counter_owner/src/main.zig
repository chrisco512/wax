const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Router = wax.Router;
const Context = wax.Context;
const Address = wax.Address;

pub const NotOwner = struct {
    requester: Address,
    owner: Address,
};

pub const RawRevert = struct {};

pub const store = struct {
    count: u256,
    owner: Address,
};

fn onlyOwner(ctx: *Context(store), next: *const Router(store).NextFn) !void {
    const sender = ctx.msg_sender();
    const owner = ctx.store.owner.get();
    if (sender != owner) try ctx.revert(NotOwner, .{ .requester = sender, .owner = owner });
    try next(ctx);
}

fn claimOwnership(ctx: *Context(store)) !void {
    const current_owner = ctx.store.owner.get();
    const sender = ctx.msg_sender();
    if (current_owner != 0) {
        try ctx.revert(NotOwner, .{ .requester = sender, .owner = current_owner });
    }
    ctx.store.owner.set(sender);
}

fn increment(ctx: *Context(store)) !void {
    const current = ctx.store.count.get();
    ctx.store.count.set(current + 1);
}

fn count(ctx: *Context(store)) !u256 {
    return ctx.store.count.get();
}

export fn user_entrypoint(len: usize) i32 {
    var ctx = Context(store).init(len) catch return 1;
    defer ctx.deinit();

    const routes = comptime [_]Router(store).Route{
        Router(store).Route.init("count", .{}, count),
        Router(store).Route.init("increment", .{onlyOwner}, increment),
        Router(store).Route.init("claimOwnership", .{}, claimOwnership),
    };

    return Router(store).handle(&routes, &ctx);
}

// export fn user_entrypoint(len: usize) i32 {
//     var ctx = Context(store).init(len) catch return 1;
//     defer ctx.deinit();
//
//     const routes = comptime [_]Route{
//         Route.init("foo", .{}, foo),
//         Route.init("bar", .{ mw, mw2 }, bar),
//     };
//
//     return Router.handle(&routes, &ctx);
// }

// Test setup
// test "user_entrypoint with bar" {
//     // Mock calldata: selector for "bar" + u256 argument (42)
//     const selector = comptime wax.getSelector("bar", bar);
//     std.debug.print("Computed selector: 0x{x}\n", .{selector});
//     // const selector_bytes = [_]u8{ 0xc2, 0x98, 0x55, 0x78 }; // Hardcoded for now
//     const selector_bytes = [_]u8{
//         @intCast((selector >> 24) & 0xFF),
//         @intCast((selector >> 16) & 0xFF),
//         @intCast((selector >> 8) & 0xFF),
//         @intCast(selector & 0xFF),
//     };
//
//     var arg_bytes = [_]u8{0} ** 32;
//     arg_bytes[31] = 42;
//     var calldata: [36]u8 = undefined;
//     @memcpy(calldata[0..4], &selector_bytes);
//     @memcpy(calldata[4..36], &arg_bytes);
//
//     std.debug.print("Calldata[0..4]: {x}\n", .{calldata[0..4]}); // Verify selector
//
//     // Mock hooks
//     const MockHooks = struct {
//         var mock_calldata: []const u8 = &.{};
//         var result_data: ?[]u8 = null;
//
//         pub fn pay_for_memory_grow(_: u32) callconv(.C) void {}
//
//         pub fn read_args(dest: *u8) callconv(.C) void {
//             const dest_ptr = @intFromPtr(dest);
//             const src_ptr = @intFromPtr(mock_calldata.ptr);
//             for (0..mock_calldata.len) |i| {
//                 const dest_addr = dest_ptr + i;
//                 const src_addr = src_ptr + i;
//                 @as(*u8, @ptrFromInt(dest_addr)).* = @as(*const u8, @ptrFromInt(src_addr)).*;
//             }
//         }
//
//         pub fn write_result(data: *const u8, len: usize) callconv(.C) void {
//             const allocator = std.testing.allocator;
//             if (result_data) |old_data| allocator.free(old_data);
//             result_data = allocator.alloc(u8, len) catch return;
//             // Unsafe manual copy with pointer arithmetic
//             const dest_ptr = @intFromPtr(result_data.?.ptr);
//             const src_ptr = @intFromPtr(data);
//             for (0..len) |i| {
//                 const dest_addr = dest_ptr + i;
//                 const src_addr = src_ptr + i;
//                 @as(*u8, @ptrFromInt(dest_addr)).* = @as(*const u8, @ptrFromInt(src_addr)).*;
//             }
//         }
//
//         pub fn deinit() void {
//             if (result_data) |data| {
//                 std.testing.allocator.free(data);
//                 result_data = null;
//             }
//         }
//     };
//
//     // Set mock calldata
//     MockHooks.mock_calldata = &calldata;
//     defer MockHooks.deinit();
//
//     // Override VM hooks
//     @export(&MockHooks.pay_for_memory_grow, .{ .name = "pay_for_memory_grow" });
//     @export(&MockHooks.read_args, .{ .name = "read_args" });
//     @export(&MockHooks.write_result, .{ .name = "write_result" });
//
//     // Run the entrypoint
//     const result = user_entrypoint(calldata.len);
//     try std.testing.expectEqual(@as(i32, 0), result);
//
//     // Verify return data
//     const result_data = MockHooks.result_data orelse return error.NoResultData;
//     try std.testing.expectEqual(@as(usize, 32), result_data.len); // u256 is 32 bytes
//     const returned_value = std.mem.readInt(u256, result_data[0..32], .big);
//     try std.testing.expectEqual(@as(u256, 69), returned_value);
// }
