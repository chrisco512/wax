const wax = @import("wax");

const Context = wax.Context(store);
const Router = wax.Router(store);
const StylusContract = wax.StylusContract;
const InitConfig = wax.StaticInitConfig;
const Route = Router.Route;

const store = struct {
    count: u256,
};

const Counter = struct {
    pub usingnamespace StylusContract(Context, Router, routes);

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
};

comptime {
    @export(&Counter.entrypoint, InitConfig);
}
