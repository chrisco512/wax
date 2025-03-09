const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const Router = wax.Router(store);
const Context = wax.Context(store);
const StylusContract = wax.StylusContract;
const InitConfig = wax.StaticInitConfig;
const Route = Router.Route;
const NextFn = Router.NextFn;
const Address = wax.Address;

// Contract storage
const store = struct {
    count: u256,
    owner: Address,
};

const CounterOwner = struct {
    pub usingnamespace StylusContract(Context, Router, routes);
    // Public routes
    const routes = [_]Route{
        Route.init("count", .{}, count),
        Route.init("increment", .{onlyOwner}, increment),
        Route.init("claimOwnership", .{}, claimOwnership),
        Route.init("owner", .{}, owner),
    };

    // Custom Error
    pub const NotOwner = struct {
        requester: Address,
        owner: Address,
    };

    // Middleware
    fn onlyOwner(ctx: *Context, next: *const NextFn) !void {
        const sender = ctx.msg_sender();
        const current_owner = ctx.store.owner.get();
        if (sender != current_owner) {
            try ctx.revert(NotOwner, .{ .requester = sender, .owner = current_owner });
        }
        try next(ctx);
    }

    // Claim ownership of contract
    fn claimOwnership(ctx: *Context) !void {
        const current_owner = ctx.store.owner.get();
        const sender = ctx.msg_sender();
        if (current_owner != 0) {
            try ctx.revert(NotOwner, .{ .requester = sender, .owner = current_owner });
        }
        ctx.store.owner.set(sender);
    }

    fn owner(ctx: *Context) !Address {
        return ctx.store.owner.get();
    }

    fn increment(ctx: *Context) !void {
        const current = ctx.store.count.get();
        ctx.store.count.set(current + 1);
    }

    fn count(ctx: *Context) !u256 {
        return ctx.store.count.get();
    }
};

comptime {
    @export(&CounterOwner.entrypoint, InitConfig);
}
