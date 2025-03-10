const wax = @import("wax");

const InitConfig = wax.StaticInitConfig;

const store = struct {
    count: u256,
};

pub fn Counter(Context: type) type {
    return struct {
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
    const contract = wax.createContract(Counter, null, store);
    @export(&contract.entrypoint, InitConfig);
}
