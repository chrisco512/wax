const std = @import("std");
const builtin = @import("builtin");
const wax = @import("wax");

const StylusContract = wax.StylusContract;
const StylusContractTest = wax.StylusContractTest;
const InitConfig = wax.StaticInitConfig;

const Address = wax.Address;

// Contract storage
const store = struct {
    count: u256,
    owner: Address,
};

pub const NotOwner = struct {
    requester: Address,
    owner: Address,
};

pub fn Middleware(Context: type, NextFn: type) type {
    return struct {
        pub fn onlyOwner(ctx: *Context, next: *const NextFn) !void {
            const sender = ctx.msg_sender();
            const current_owner = ctx.store.owner.get();
            if (sender != current_owner) {
                try ctx.revert(NotOwner, .{ .requester = sender, .owner = current_owner });
            }
            try next(ctx);
        }
    };
}

pub fn CounterOwner(Context: type) type {
    return struct {
        // Claim ownership of contract
        pub fn claimOwnership(ctx: *Context) !void {
            const current_owner = ctx.store.owner.get();
            const sender = ctx.msg_sender();
            if (current_owner != 0) {
                try ctx.revert(NotOwner, .{ .requester = sender, .owner = current_owner });
            }
            ctx.store.owner.set(sender);
        }

        pub fn owner(ctx: *Context) !Address {
            return ctx.store.owner.get();
        }

        pub const increment_route = .{ .middlewares = &[_][]const u8{"onlyOwner"} };
        pub fn increment(ctx: *Context) !void {
            const current = ctx.store.count.get();
            ctx.store.count.set(current + 1);
        }

        pub fn count(ctx: *Context) !u256 {
            return ctx.store.count.get();
        }
    };
}

comptime {
    // const entrypoint = wax.createContract(CounterOwner, Middleware, store).entrypoint;
    @export(&wax.createContract(CounterOwner, Middleware, store).entrypoint, InitConfig);
}
