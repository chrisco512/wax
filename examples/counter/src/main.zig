const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Route = wax.Route;
const Router = wax.Router;
const hashAtComptime = wax.hashAtComptime;
const getSelector = wax.getSelector;
const Context = wax.Context;

fn foo(ctx: Context) void {
    _ = ctx;

    if (builtin.is_test) {
        std.debug.print("foo says hello\n", .{});
    }
}

fn bar(ctx: Context) void {
    // _ = ctx;

    if (builtin.is_test) {
        std.debug.print("bar: blockNum: {d}\n", .{ctx.block.number});
    }
}

// implement an increment, decrement, and getCount method
// keccak hash the function names to wire up the router
// log out to console
export fn user_entrypoint() u32 {
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer gpa.deinit();
    const selector = comptime getSelector("bar", bar);
    const ctx = Context{
        .block = .{
            .number = 69,
        },
    };

    // little-endian
    // const hello_value: u32 = std.mem.readInt(u32, hash_four, .little);

    // Define routes here
    const routes = comptime [_]Route{
        Route.init("foo", .{}, foo),
        Route.init("bar", .{}, bar),
    };

    const router = comptime Router.init(&routes);

    if (router.handle(selector, &.{}, &ctx)) |_| {
        return 1; // Success
    } else |_| {
        return 0; // General error code
    }
}

test "router" {
    _ = user_entrypoint();
}
