pub fn createEntrypoint(
    comptime ContextType: type,
    comptime RouterType: type,
    comptime routes: anytype,
) type {
    return struct {
        pub fn entrypoint(len: usize) callconv(.C) i32 {
            var ctx = ContextType.init(len) catch return 1;
            defer ctx.deinit();

            return RouterType.handle(&routes, &ctx);
        }
    };
}
