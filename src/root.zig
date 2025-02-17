const std = @import("std");
const crypto = std.crypto;

// Converts a Zig type to a Solidity ABI type string
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
                else => @compileError("Unsupported unsigned integer type"),
            },
        },
        .void => "",
        else => @compileError("Unsupported type: " ++ @typeName(T)),
    };
}

// Given a name string and a function signature, computes a Solidity ABI 4-byte
// selector as a u32 at comptime
pub fn getSelector(comptime name: []const u8, comptime func: anytype) u32 {
    comptime {
        const func_info = @typeInfo(@TypeOf(func)).@"fn";

        if (func_info.params.len == 0 or func_info.params[0].type.? != *const Context) {
            @compileError("First parameter of func must be *const Context type");
        }

        // Append function name
        var sig: []const u8 = name;
        sig = sig ++ "(";

        // Append argument types
        if (func_info.params.len > 1) {
            for (func_info.params[1..], 0..) |param, i| {
                if (i > 0) sig = sig ++ ",";
                sig = sig ++ zigToSolidityType(param.type.?);
            }
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

// Converts a byte array at comptime to a hex-encoded string
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

// Comptime fn for computing the keccak256 hash of a string
pub fn hashAtComptime(comptime data: []const u8) [32]u8 {
    comptime {
        @setEvalBranchQuota(100000);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(data, &hash, .{});
        return hash;
    }
}

// Context struct contains vm data like block number, timestamp, etc
// Plus access to storage via Context.store
pub const Context = struct {
    block: struct {
        number: u256,
    },
    calldata: []const u8,
};

pub const NextFn = fn (*const Context) anyerror!void;
pub const MiddlewareFn = fn (ctx: *const Context, next: *const NextFn) anyerror!void;

// Routes define public methods for the smart contract
// Any number of middleware functions can be chained before the
// handler is invoked.
pub const Route = struct {
    selector: u32,
    handler: *const NextFn,
    middleware: []*const MiddlewareFn,

    pub fn init(comptime name: []const u8, comptime middleware: anytype, comptime handler: anytype) Route {
        // Encodes the selector according to Solidity ABI
        const selector = getSelector(name, handler);

        // Builds an array of middleware functions for this route
        const mws = comptime blk: {
            var mw_arr: [middleware.len]*const MiddlewareFn = undefined;
            for (middleware, 0..) |mw, i| {
                mw_arr[i] = &mw;
            }
            break :blk mw_arr;
        };

        // This wraps the handler in a decoder/encoder for Solidity compatibility
        const decodeHandler = returnDecodingFunction(handler);

        return Route{
            .selector = selector,
            .handler = &decodeHandler,
            .middleware = @constCast(mws[0..]),
        };
    }
};

// Returns a tuple of types for the parameters of a function
// We need this type to build the args tuple for the handler
pub fn getParamsType(comptime handler: anytype) type {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const handler_info = @typeInfo(@TypeOf(handler)).@"fn";

    // Generates a tuple of types for the parameters of the function
    const ParamsType = blk: {
        comptime var fields: [handler_info.params.len]type = undefined;
        inline for (handler_info.params, 0..) |param, i| {
            fields[i] = param.type.?;
        }
        break :blk std.meta.Tuple(&fields);
    };

    return ParamsType;
}

// This function expects a handler fn, Context
pub fn decodeHandlerArgs(comptime handler: anytype, ctx: *const Context) getParamsType(handler) {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const handler_info = @typeInfo(@TypeOf(handler)).@"fn";
    var byte_index: usize = 0;

    // Set up args tuple
    const ParamsType = getParamsType(handler);
    var args: ParamsType = undefined;
    args[0] = ctx;

    // Decode each argument from calldata, skipping context param
    inline for (handler_info.params[1..], 0..) |param, i| {
        args[i] = try decodeByType(param.type.?, ctx.calldata, &byte_index);
    }

    return args;
}

pub fn decodeAndCallHandler(comptime handler: anytype, ctx: *const Context) !void {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const args = decodeHandlerArgs(handler, ctx);

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

pub fn returnDecodingFunction(comptime handler: anytype) NextFn {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    return struct {
        pub fn call(ctx: *const Context) DecodeError!void {
            _ = try decodeAndCallHandler(handler, ctx);
        }
    }.call;
}

// Container for all public routes. Exposes a handle method which
// chooses the proper Route and chain calls all middleware functions
// before invoking the handler.
pub const Router = struct {
    fn buildChain(comptime r: Route) *const NextFn {
        comptime {
            // Start with the handler
            var next: *const NextFn = r.handler;

            // Build middleware chain in reverse order
            var i = r.middleware.len;
            while (i > 0) : (i -= 1) {
                const middleware = r.middleware[i - 1];
                const next_middleware = next;
                const wrapper = struct {
                    fn wrapped(ctx: *const Context) anyerror!void {
                        try middleware(ctx, next_middleware);
                    }
                }.wrapped;
                next = &wrapper;
            }

            return next;
        }
    }

    pub fn handle(comptime routes: []const Route, selector: u32, ctx: *const Context) !void {
        inline for (routes) |route| {
            if (route.selector == selector) {
                const chain = comptime buildChain(route);
                try chain(ctx);
                return;
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
        pub fn incrementBy(ctx: *const Context, amount: u256) void {
            _ = ctx;
            _ = amount;
        }

        pub fn getCount(ctx: *const Context) u256 {
            _ = ctx;
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
