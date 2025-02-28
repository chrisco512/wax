const wax = @import("wax");

pub const store = struct {
    count: u256,
};

const Context = wax.Context(store);
const Router = wax.Router(store);
const Route = Router.Route;

fn increment(ctx: *Context) !void {
    const current = ctx.store.count.get();
    ctx.store.count.set(current + 1);
}

fn count(ctx: *Context) !u256 {
    return ctx.store.count.get();
}

export fn user_entrypoint(len: usize) i32 {
    var ctx = Context.init(len) catch return 1;
    defer ctx.deinit();

    const routes = comptime [_]Route{
        Route.init("count", .{}, count),
        Route.init("increment", .{}, increment),
    };

    return Router.handle(&routes, &ctx);
}
