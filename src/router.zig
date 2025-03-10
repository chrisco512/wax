const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const context = @import("context.zig");
const host = @import("hostio.zig");
const getSelector = root.getSelector;
const decodeAndCallHandler = root.decodeAndCallHandler;
// Context
pub const Context = context.Context;

pub fn Router(comptime UserStore: type) type {
    return struct {
        pub const NextFn = fn (*Context(UserStore)) anyerror!void;
        pub const MiddlewareFn = fn (ctx: *Context(UserStore), next: *const NextFn) anyerror!void;

        pub const Route = struct {
            selector: u32,
            handler: *const NextFn,
            middleware: []*const MiddlewareFn,

            pub fn init(comptime name: []const u8, comptime middleware: anytype, comptime handler: anytype) Route {
                const selector = getSelector(name, handler);
                const mws = comptime blk: {
                    var mw_arr: [middleware.len]*const MiddlewareFn = undefined;
                    for (middleware, 0..) |mw, i| mw_arr[i] = &mw;
                    break :blk mw_arr;
                };
                const decodeHandler = returnDecodingFunction(handler);
                return .{ .selector = selector, .handler = &decodeHandler, .middleware = @constCast(mws[0..]) };
            }
        };

        fn buildChain(comptime r: Route) *const NextFn {
            comptime {
                var next: *const NextFn = r.handler;
                var i = r.middleware.len;
                while (i > 0) : (i -= 1) {
                    const middleware = r.middleware[i - 1];
                    const next_middleware = next;
                    const wrapper = struct {
                        fn wrapped(ctx: *Context(UserStore)) anyerror!void {
                            try middleware(ctx, next_middleware);
                        }
                    }.wrapped;
                    next = &wrapper;
                }
                return next;
            }
        }

        pub fn handle(comptime routes: []const Route, ctx: *Context(UserStore)) i32 {
            if (ctx.calldata.len < 4) return 1;
            const selector = std.mem.readInt(u32, ctx.calldata[0..4], .big);
            if (builtin.is_test) std.debug.print("Received selector: 0x{x}\n", .{selector});
            inline for (routes) |route| {
                if (builtin.is_test) std.debug.print("Route selector: 0x{x}\n", .{route.selector});
                if (route.selector == selector) {
                    const chain = comptime buildChain(route);
                    if (chain(ctx)) |_| {
                        if (ctx.returndata) |data| {
                            if (data.len > 0)
                                host.write_result(@ptrCast(data), data.len);
                        }
                        return 0;
                    } else |_| {
                        if (ctx.revertdata) |data| {
                            if (data.len > 0)
                                host.write_result(&data.ptr[0], data.len);
                        }
                        return 1;
                    }
                }
            }
            return 1;
        }

        pub fn returnDecodingFunction(comptime handler: anytype) NextFn {
            if (@typeInfo(@TypeOf(handler)) != .@"fn") {
                @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
            }

            return struct {
                pub fn call(ctx: *Context(UserStore)) anyerror!void {
                    try decodeAndCallHandler(UserStore, handler, ctx);
                }
            }.call;
        }

        // autoGenerateRoutes function - supports external middleware only
        pub fn autoGenerateRoutes(comptime ContractType: type, comptime MiddlewareType: type) []const Route {
            const Routes = struct {
                // Define Route struct in the scope
                const routes = blk: {
                    const contract_info = @typeInfo(ContractType);
                    if (contract_info != .@"struct") @compileError("Contract must be a struct");

                    const decls = contract_info.@"struct".decls;

                    // Calculate number of valid routes
                    var route_count: usize = 0;
                    for (decls) |decl| {
                        const value = @field(ContractType, decl.name);
                        const field_type = @TypeOf(value);

                        if (@typeInfo(field_type) == .@"fn") {
                            const func = @typeInfo(field_type).@"fn";
                            if (func.params.len >= 1 and decl.name.len > 0) {
                                route_count += 1;
                            }
                        }
                    }

                    // Create routes array
                    var temp_routes: [route_count]Route = undefined;
                    var route_index: usize = 0;

                    // generate routes...
                    for (decls) |decl| {
                        const value = @field(ContractType, decl.name);
                        const field_type = @TypeOf(value);

                        if (@typeInfo(field_type) == .@"fn") {
                            const func = @typeInfo(field_type).@"fn";

                            if (func.params.len >= 1 and decl.name.len > 0) {
                                const route_name = decl.name;
                                // var middlewares = [_]MiddlewareFn{};

                                // process middlewares...
                                const attr_name = route_name ++ "_route";
                                if (@hasDecl(ContractType, attr_name)) {
                                    const attr = @field(ContractType, attr_name);
                                    if (@hasField(@TypeOf(attr), "middlewares")) {
                                        // Process middleware list
                                        var middleware_count: usize = 0;
                                        var resolved_middlewares: [attr.middlewares.len]MiddlewareFn = undefined;

                                        for (attr.middlewares) |middleware_name| {
                                            if (resolveMiddleware(middleware_name, MiddlewareType)) |middleware_fn| {
                                                resolved_middlewares[middleware_count] = middleware_fn;
                                                middleware_count += 1;
                                            }
                                        }

                                        temp_routes[route_index] = Route.init(
                                            route_name,
                                            resolved_middlewares[0..middleware_count], // Use resolved middlewares
                                            value,
                                        );
                                    } else {
                                        // No middleware configuration, use empty array
                                        temp_routes[route_index] = Route.init(
                                            route_name,
                                            &[_]MiddlewareFn{}, // empty array
                                            value,
                                        );
                                    }
                                } else {
                                    // No middleware configuration, use empty array
                                    temp_routes[route_index] = Route.init(
                                        route_name,
                                        &[_]MiddlewareFn{}, // empty array
                                        value,
                                    );
                                }
                                route_index += 1;
                            }
                        }
                    }

                    break :blk temp_routes;
                };
            };
            return &Routes.routes;
        }

        // Resolve middleware function from middleware struct only with enhanced validation
        fn resolveMiddleware(comptime name: []const u8, comptime MiddlewareType: ?type) ?MiddlewareFn {
            if (MiddlewareType) |MT| {
                if (@hasDecl(MT, name)) {
                    const middleware = @field(MT, name);
                    const middleware_type = @TypeOf(middleware);

                    if (@typeInfo(middleware_type) == .@"fn") {
                        const func_info = @typeInfo(middleware_type).@"fn";
                        // Verify middleware has exactly 2 parameters
                        if (func_info.params.len < 2) {
                            @compileError("Middleware function '" ++ name ++ "' must take more 2 parameters (at least *Context and next)");
                        }

                        return middleware;
                    } else {
                        @compileError("Middleware '" ++ name ++ "' must be a function");
                    }
                } else {
                    @compileError("Middleware '" ++ name ++ "' not found in the middleware struct");
                }
            }

            return null;
        }
    };
}
