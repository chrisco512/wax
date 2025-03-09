const wax = @import("wax");

const Context = wax.Context(store);
const Router = wax.Router(store);
const Route = Router.Route;

const store = struct {
    count: u256,
};

const Counter = struct {
    const routes = [_]Route{
        Route.init("count", .{}, count),
        Route.init("increment", .{}, increment),
    };

    fn increment(ctx: *Context) !void {
        const current = ctx.store.count.get();
        ctx.store.count.set(current + 1);
    }

    fn count(ctx: *Context) !u256 {
        return ctx.store.count.get();
    }

    pub export fn entrypoint(len: usize) i32 {
        var ctx = Context.init(len) catch return 1;
        defer ctx.deinit();

        return Router.handle(&routes, &ctx);
    }
};
comptime {
    @export(&Counter.entrypoint, .{ .name = "user_entrypoint", .linkage = .strong });
}
