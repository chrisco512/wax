const std = @import("std");
const crypto = std.crypto;

pub fn zigToSolidityType(comptime T: type) []const u8 {
    return switch (@typeInfo(T)) {
        .int => |info| switch (info.signedness) {
            .signed => switch (info.bits) {
                8 => "int8",
                16 => "int16",
                32 => "int32",
                64 => "int64",
                128 => "int128",
                256 => "int256",
                else => @compileError("Unsupported integer type"),
            },
            .unsigned => switch (info.bits) {
                8 => "uint8",
                16 => "uint16",
                32 => "uint32",
                64 => "uint64",
                128 => "uint128",
                256 => "uint256",
                else => @compileError("Unsupported unsigned intger type"),
            },
        },
        .void => "",
        else => @compileError("Unsupported type: " ++ @typeName(T)),
    };
}

pub fn getSelector(comptime name: []const u8, comptime func: anytype) u32 {
    comptime {
        const func_info = @typeInfo(@TypeOf(func)).@"fn";

        // Append function name
        var sig: []const u8 = name;
        sig = sig ++ "(";

        // Append argument types
        for (func_info.params[1..], 0..) |param, i| {
            if (i > 0) sig = sig ++ ",";
            sig = sig ++ zigToSolidityType(param.type.?);
        }

        // Append closing parenthesis
        sig = sig ++ ")";

        const hash = hashAtComptime(sig);
        return (@as(u32, hash[0]) << 24) |
            (@as(u32, hash[1]) << 16) |
            (@as(u32, hash[2]) << 8) |
            @as(u32, hash[3]);
    }
}

pub fn bytesToHexString(comptime T: type, comptime bytes: []const u8) T {
    var result: T = undefined;
    comptime {
        if (@typeInfo(T) != .array or @typeInfo(T).array.len != bytes.len * 2) {
            @compileError("Result type must be an array with length " ++ bytes.len * 2);
        }
    }

    for (bytes, 0..) |byte, i| {
        _ = std.fmt.bufPrint(result[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }

    return result;
}

pub fn hashAtComptime(comptime data: []const u8) [32]u8 {
    comptime {
        @setEvalBranchQuota(100000);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(data, &hash, .{});
        return hash;
    }
}

pub const Context = struct {
    block: struct {
        number: u256,
    },
};

// pub const HandlerFn = *const anyopaque;
// pub const MiddlewareFn = *const fn (ctx: Context, next: *const fn (ctx: Context) void) void;
pub fn MiddlewareFn(comptime NextFn: type) type {
    return fn (ctx: *Context, next: NextFn) anyerror!void;
}

pub const Route = struct {
    selector: u32,
    handler: *const anyopaque,
    middleware: []const *const anyopaque,

    pub fn init(comptime name: []const u8, comptime middleware: anytype, comptime handler: anytype) Route {
        const selector = getSelector(name, handler);

        const mws = comptime blk: {
            var mw_arr: [middleware.len]*const anyopaque = undefined;
            for (middleware, 0..) |mw, i| {
                mw_arr[i] = &mw;
            }
            break :blk mw_arr;
        };

        // instead of storing the handler itself as the handler, we should
        // store a function that decodes and invokes the handler
        const decodeHandler = returnDecodingFunction(handler);

        return Route{
            .selector = selector,
            .handler = &decodeHandler,
            .middleware = &mws,
        };
    }
};

pub fn decodeAndCallHandler(comptime handler: anytype, ctx: *const Context, bytes: []const u8) !void {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const handler_info = @typeInfo(@TypeOf(handler)).@"fn";
    var byte_index: usize = 0;

    // generates a tuple of types representing the args expected for the handler
    const ArgsType = blk: {
        comptime var fields: [handler_info.params.len]type = undefined;
        inline for (handler_info.params, 0..) |param, i| {
            fields[i] = param.type.?;
        }
        break :blk std.meta.Tuple(&fields);
    };

    var args: ArgsType = undefined;
    args[0] = ctx.*;

    // Decode each argument from calldata, skipping ctx
    inline for (handler_info.params[1..], 0..) |param, i| {
        args[i] = try decodeByType(param.type.?, bytes, &byte_index);
    }

    // TODO: Encode return data from handler and write to buffer
    _ = @call(.auto, handler, args);
}

pub fn decodeByType(comptime T: type, bytes: []const u8, index: *usize) !T {
    const size = @sizeOf(T);
    const new_index = index.* + size;
    defer index.* = new_index;
    if (bytes.len < new_index) return error.NotEnoughBytes;

    return switch (@typeInfo(T)) {
        .Int => |info| blk: {
            const value = std.mem.readInt(T, bytes[index.*..new_index], .big);
            break :blk if (info.is_signed) @bitCast(value) else value;
        },
        else => @compileError("Unsupported type for decoding: " ++ @typeName(T)),
    };
}

const DecodeError = error{
    DecodeFailed,
};

const DecodingFn = fn (*const Context, []const u8) DecodeError!void;

pub fn returnDecodingFunction(comptime handler: anytype) DecodingFn {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    return struct {
        pub fn call(ctx: *const Context, bytes: []const u8) DecodeError!void {
            _ = try decodeAndCallHandler(handler, ctx, bytes);
        }
    }.call;
}

pub const Router = struct {
    routes: []const Route,

    pub fn init(comptime routes: []const Route) Router {
        return Router{
            .routes = routes,
        };
    }

    pub fn handle(self: *const Router, selector: u32, comptime calldata: []const u8, ctx: *const Context) !void {
        for (self.routes) |r| {
            if (r.selector == selector) {
                const NextFn = fn (*const Context, *const Route, []const u8) anyerror!void;
                const next: NextFn = struct {
                    fn call_next(context: *const Context, route: *const Route, cd: []const u8) anyerror!void {
                        const handlerFn: *const DecodingFn = @alignCast(@ptrCast(route.handler));
                        _ = try @call(.auto, handlerFn, .{ context, cd });
                    }
                }.call_next;

                // Build middleware chain in reverse order
                var i = r.middleware.len;
                while (i > 0) {
                    i -= 1;
                    const middleware: *const MiddlewareFn(NextFn) = @alignCast(@ptrCast(r.middleware[i]));
                    const old_next = next;
                    const next_wrapper: NextFn = struct {
                        fn wrap(context: *const Context, route: *const Route, cd: []const u8) anyerror!void {
                            try middleware(context, struct {
                                fn forward(ctx_fwd: *const Context) anyerror!void {
                                    try old_next(ctx_fwd, route, cd);
                                }
                            }.forward);
                        }
                    }.wrap;
                    _ = next_wrapper; // Use this to replace `next` if you need to chain further
                }

                try next(ctx, &r, calldata);
                return;

                //const handler = HandlerFn
                // Middleware execution logic
                // const NextFn = fn (*Context) anyerror!void;
                // const next: NextFn = struct {
                // fn call_next(context: *Context) anyerror!void {
                //                        Call the actual handler as the last middleware
                // const handlerFn: DecodingFn = @ptrCast(r.handler);
                // _ = @call(.auto, handlerFn, .{ context, calldata });
                // }
                // }.call_next;

                // Build middleware chain in reverse order
                // var i = r.middleware.len;
                // while (i > 0) {
                // i -= 1;
                // const middleware: MiddlewareFn(NextFn) = @ptrCast(r.middleware[i]);
                // const old_next = next;
                // next = struct {
                // fn wrap(context: *Context) anyerror!void {
                // try middleware(context, old_next);
                // }
                // }.wrap;
                // }
                //
                // try next(ctx);
                // return;
            }
        }
    }
};

test "hashAtComptime" {
    const input = "hello()";
    const expected = "19ff1d210e06a53ee50e5bad25fa509a6b00ed395695f7d9b82b68155d9e1065";

    const result = comptime hashAtComptime(input);
    var hex_result = comptime bytesToHexString([64]u8, &result);

    try std.testing.expectEqualStrings(expected, &hex_result);
}

test "getSelector" {
    const Contract = struct {
        pub fn incrementBy(amount: u256) void {
            _ = amount;
        }

        pub fn getCount() u256 {
            return 0;
        }
    };

    // Compute selectors at compile time
    const incrementBySelector = comptime getSelector("incrementBy", Contract.incrementBy);
    const getCountSelector = comptime getSelector("getCount", Contract.getCount);

    try std.testing.expectEqual(0x03df179c, incrementBySelector);
    try std.testing.expectEqual(0xa87d942c, getCountSelector);

    // Print selectors in hex
    // std.debug.print("incrementBy selector: 0x{x:0>8}\n", .{incrementBySelector});
    // std.debug.print("getCount selector: 0x{x:0>8}\n", .{getCountSelector});
}

test "zigToSolidityType" {
    const u256_abi = comptime zigToSolidityType(u256);
    try std.testing.expectEqualStrings(u256_abi, "uint256");
}
