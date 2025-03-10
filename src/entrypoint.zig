const context = @import("context.zig");
const host = @import("hostio.zig");
const router = @import("router.zig");
const std = @import("std");

// Context
pub const Context = context.Context;
pub const Router = router.Router;
const Route = Router.Route;

pub fn createEntrypoint(
    comptime ContextType: type,
    comptime RouterType: type,
    comptime routes: anytype,
) type {
    return struct {
        pub fn entrypoint(len: usize) callconv(.C) i32 {
            var ctx = ContextType.init(len) catch return 1;
            defer ctx.deinit();

            return RouterType.handle(routes, &ctx);
        }
    };
}
// Thia method will add context to the contract and middleware, and return the entrypoint
pub fn createContract(comptime ContractType: fn (type) type, comptime MiddlewareType: ?fn (type, type) type, comptime StoreType: type) type {
    const RouterType = Router(StoreType);
    const ContextType = Context(StoreType);

    const EmptyMiddleware = struct {};

    const ContractWithContext = ContractType(ContextType);
    const MiddlewareWithContextAndNext = if (MiddlewareType) |MT|
        MT(ContextType, RouterType.NextFn)
    else
        EmptyMiddleware;

    const routes = RouterType.autoGenerateRoutes(ContractWithContext, MiddlewareWithContextAndNext);
    return createEntrypoint(ContextType, RouterType, routes);
}
