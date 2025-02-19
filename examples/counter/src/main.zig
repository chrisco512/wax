const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Route = wax.Route;
const Router = wax.Router;
const hashAtComptime = wax.hashAtComptime;
const getSelector = wax.getSelector;
const Context = wax.Context;
const NextFn = wax.NextFn;

// struct Contract {
//   owner: Address,
//
// }

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
    // var owner = ctx.store.owner.get();
    // ctx.store.owner.set(ctx.msg.sender());

    _ = ctx;

    if (builtin.is_test) {
        std.debug.print("foo says hello\n", .{});
    }
}

fn bar(ctx: *const Context, n: u256) void {
    // _ = ctx;
    _ = n;

    if (builtin.is_test) {
        std.debug.print("bar: blockNum: {d}\n", .{ctx.block.number});
    }
}

export fn user_entrypoint() u32 {
    // Conditional allocator based on target architecture
    const allocator = blk: {
        if (builtin.target.isWasm()) {
            // WASM target: Use WasmAllocator
            break :blk std.heap.wasm_allocator;
        } else {
            // Native target (e.g., testing): Use FixedBufferAllocator
            var buffer: [1024]u8 = undefined; // Adjust size as needed
            var fba = std.heap.FixedBufferAllocator.init(&buffer);
            break :blk fba.allocator();
        }
    };

    const selector = comptime getSelector("bar", bar);
    const ctx = Context{
        .allocator = allocator,
        .block = .{
            .number = 69,
        },
        .calldata = &.{},
        .return_data = &.{},
    };

    // const ctx = createContext(Contract.init(), calldata);

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
