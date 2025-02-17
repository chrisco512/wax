const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Route = wax.Route;
const Router = wax.Router;
const hashAtComptime = wax.hashAtComptime;
const getSelector = wax.getSelector;
const Context = wax.Context;
const NextFn = wax.NextFn;

fn mw(ctx: *const Context, next: *const NextFn) anyerror!void {
    if (builtin.is_test) {
        std.debug.print("in the mw\n", .{});
    }

    try next(ctx);
}

fn mw2(ctx: *const Context, next: *const NextFn) anyerror!void {
    if (builtin.is_test) {
        std.debug.print("in mw2, bitches!\n", .{});
    }

    try next(ctx);
}

fn foo(ctx: *const Context) void {
    _ = ctx;

    if (builtin.is_test) {
        std.debug.print("foo says hello\n", .{});
    }
}

fn bar(ctx: *const Context) void {
    // _ = ctx;

    if (builtin.is_test) {
        std.debug.print("bar: blockNum: {d}\n", .{ctx.block.number});
    }
}

export fn user_entrypoint() u32 {
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer gpa.deinit();
    const selector = comptime getSelector("bar", bar);
    const ctx = Context{
        .block = .{
            .number = 69,
        },
        .calldata = &.{},
    };

    // Define routes here
    const routes = comptime [_]Route{
        Route.init("foo", .{}, foo),
        Route.init("bar", .{ mw, mw2 }, bar),
    };

    if (Router.handle(&routes, selector, &ctx)) |_| {
        return 1; // Success
    } else |_| {
        return 0; // General error code
    }
}

test "router" {
    _ = user_entrypoint();
}
