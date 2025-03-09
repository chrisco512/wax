const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const context = @import("context.zig");
const host = @import("hostio.zig");
const entrypoint_module = @import("entrypoint.zig");
// Context
pub const Context = context.Context;

// Types
pub const types = @import("types.zig");
pub const Address = types.Address;
pub const StaticInitConfig: std.builtin.ExportOptions = .{ .name = "user_entrypoint", .linkage = .strong };

const ABI_SLOT_SIZE = 32;

pub const WaxError = error{
    Revert,
};

pub fn StylusContract(comptime ContextType: type, comptime RouterType: type, comptime routes: anytype) type {
    // Todo: add more features here that needs to init or check during compiling
    return entrypoint_module.createEntrypoint(ContextType, RouterType, routes);
}

// Converts a Zig type to a Solidity ABI type string
pub fn zigToSolidityType(comptime T: type) []const u8 {
    // special case for address to avoid u160 ambiguity
    if (T == Address) return "address";
    return switch (@typeInfo(T)) {
        .int => |info| blk: {
            if (info.signedness == .signed) {
                switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        break :blk "int" ++ std.fmt.comptimePrint("{}", .{info.bits})
                    else
                        @compileError("Unsupported signed integer size"),
                }
            } else {
                switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        break :blk "uint" ++ std.fmt.comptimePrint("{}", .{info.bits})
                    else
                        @compileError("Unsupported unsigned integer size"),
                }
            }
        },
        .bool => "bool",
        .array => |arr| if (arr.child == u8 and arr.len > 0)
            "bytes" ++ std.fmt.comptimePrint("{}", .{arr.len})
        else
            zigToSolidityType(arr.child) ++ "[" ++ std.fmt.comptimePrint("{}", .{arr.len}) ++ "]",
        .pointer => |p| if (p.size == .slice and p.child == u8) "bytes" else zigToSolidityType(p.child) ++ "[]",
        .@"struct" => |s| if (s.is_tuple) "tuple" else @compileError("Named structs need explicit Solidity mapping"),
        .@"enum" => "uint8", // Simplest case; extend if needed
        .void => "",
        else => @compileError("Unsupported type: " ++ @typeName(T)),
    };
}

// Given a name string and a function signature, computes a Solidity ABI 4-byte
// selector as a u32 at comptime
pub fn getSelector(comptime name: []const u8, comptime func: anytype) u32 {
    comptime {
        const func_info = @typeInfo(@TypeOf(func)).@"fn";

        // if (func_info.params.len == 0 or func_info.params[0].type.? != *Context) {
        //     @compileError("First parameter of func must be *Context type");
        // }

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

fn getErrorSelector(comptime signature: []const u8) u32 {
    // Compute Keccak-256 hash at compile time
    const hash = comptime hashAtComptime(signature);
    // Extract first 4 bytes for selector
    return (@as(u32, hash[0]) << 24) |
        (@as(u32, hash[1]) << 16) |
        (@as(u32, hash[2]) << 8) |
        @as(u32, hash[3]);
}

fn getErrorSignature(comptime ErrorType: type) []const u8 {
    // Verify that ErrorType is a struct
    if (@typeInfo(ErrorType) != .@"struct") {
        @compileError("Expected a struct type for ErrorType, got " ++ @typeName(ErrorType));
    }
    const struct_name = @typeName(ErrorType);
    const fields = @typeInfo(ErrorType).@"struct".fields;
    var sig: []const u8 = struct_name ++ "(";
    inline for (fields, 0..) |field, i| {
        if (i > 0) sig = sig ++ ",";
        sig = sig ++ zigToSolidityType(field.type);
    }
    sig = sig ++ ")";
    return sig;
}

pub fn encodeCustomError(comptime ErrorType: type, err: ErrorType, allocator: std.mem.Allocator) ![]u8 {
    // Get the signature from the error type
    const signature = comptime getErrorSignature(ErrorType);
    // Compute the selector at compile time
    const selector = comptime getErrorSelector(signature);

    // Initialize buffer for encoded data
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    // Append the 4-byte selector
    try buffer.appendSlice(&[_]u8{
        @intCast((selector >> 24) & 0xFF),
        @intCast((selector >> 16) & 0xFF),
        @intCast((selector >> 8) & 0xFF),
        @intCast(selector & 0xFF),
    });

    // Get the struct fields using reflection
    const fields = @typeInfo(ErrorType).@"struct".fields;

    // Encode each field according to its type
    inline for (fields) |field| {
        const value = @field(err, field.name);
        try encodeByType(field.type, value, &buffer);
    }

    // Return the encoded data
    return buffer.toOwnedSlice();
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
pub fn decodeHandlerArgs(comptime UserStore: type, comptime handler: anytype, ctx: *Context(UserStore)) !getParamsType(handler) {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const handler_info = @typeInfo(@TypeOf(handler)).@"fn";
    var byte_index: usize = 4; // skip the 4-byte selector

    // Set up args tuple
    const ParamsType = getParamsType(handler);
    var args: ParamsType = undefined;
    args[0] = ctx;

    // Decode each argument from calldata, skipping context param
    inline for (handler_info.params[1..], 0..) |param, i| {
        args[i + 1] = try decodeByType(param.type.?, ctx, &byte_index);
    }

    return args;
}

pub fn decodeAndCallHandler(comptime UserStore: type, comptime handler: anytype, ctx: *Context(UserStore)) !void {
    if (@typeInfo(@TypeOf(handler)) != .@"fn") {
        @compileError("Expected a function, but got " ++ @typeName(@TypeOf(handler)));
    }

    const handler_type_info = @typeInfo(@TypeOf(handler)).@"fn";
    const args = try decodeHandlerArgs(UserStore, handler, ctx);

    // Call the handler and capture the result
    const result = @call(.auto, handler, args);
    const ReturnType = handler_type_info.return_type orelse void;

    // Handle the return type
    switch (@typeInfo(ReturnType)) {
        .error_union => |eu| {
            if (result) |value| {
                // Success case: encode the payload if it’s not void
                if (eu.payload != void) {
                    var buffer = std.ArrayList(u8).init(ctx.allocator);
                    defer buffer.deinit();
                    try encodeByType(eu.payload, value, &buffer);
                    ctx.returndata = try buffer.toOwnedSlice();
                } else {
                    ctx.returndata = &.{};
                }
            } else |_| {
                return error.Revert; // Trigger the revert
            }
        },
        else => {
            // Non-error-union case: encode the result if not void
            if (ReturnType != void) {
                var buffer = std.ArrayList(u8).init(ctx.allocator);
                defer buffer.deinit();
                try encodeByType(ReturnType, result, &buffer);
                ctx.returndata = try buffer.toOwnedSlice();
            } else {
                ctx.returndata = &.{};
            }
        },
    }
}

pub fn decodeByType(comptime T: type, ctx: *const Context, index: *usize) !T {
    const bytes = ctx.calldata;
    const new_index = index.* + ABI_SLOT_SIZE;
    if (bytes.len < new_index) return error.NotEnoughBytes;

    // Convert slice to a pointer to a fixed-size array
    const slice = bytes[index.*..new_index];
    const ptr = @as(*const [32]u8, @ptrCast(slice));

    return switch (@typeInfo(T)) {
        .int => |info| blk: {
            defer index.* = new_index; // single 32-byte slot
            // Read as big-endian u256 first
            const value = std.mem.readInt(u256, ptr, .big);
            // Cast to target type, checking bounds if needed
            if (info.signedness == .signed) {
                const signed = @as(i256, @bitCast(value));
                switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        break :blk @truncate(signed)
                    else
                        @compileError("Unsupported signed integer size"),
                }
            } else {
                switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        break :blk @truncate(value)
                    else
                        @compileError("Unsupported unsigned integer size"),
                }
            }
        },
        .bool => blk: {
            defer index.* = new_index; // single 32-byte slot
            const value = std.mem.readInt(u8, ptr[31..32], .big); //Last byte
            if (value > 1) return error.InvalidBool;
            break :blk value == 1;
        },
        .array => |arr| blk: {
            if (arr.child == u8 and arr.len == 0) { // Dynamic types
                const offset = try readOffset(bytes, index); // Updates index by 32
                const len = try readLength(bytes, offset);
                if (bytes.len < offset + 32 + len) return error.NotEnoughBytes;
                break :blk bytes[offset + 32 .. offset + 32 + len];
            } else if (arr.len > 0 and arr.child == u8) { // Fixed bytes
                defer index.* = new_index; // single 32-byte slot
                var result: [arr.len]u8 = undefined;
                const start = 32 - arr.len;
                @memcpy(result[0..arr.len], ptr[start..32]);
                break :blk result;
            } else if (arr.len > 0) { // Fixed array T[k]
                var result: [arr.len]arr.child = undefined;
                index.* = new_index; // move past head
                for (&result) |*item| {
                    item.* = try decodeByType(arr.child, ctx, index); // recursive call updates index
                }
                break :blk result;
            } else { // Dynamic array T[]
                const offset = try readOffset(bytes, index); // updates index by 32
                const len = try readLength(bytes, offset);
                const result: []arr.child = @as([*]arr.child, @ptrFromInt(0))[0..len];
                var sub_index: usize = offset + 32; // start of data
                for (result) |*item| {
                    item.* = try decodeByType(arr.child, ctx, &sub_index);
                }
                break :blk result;
            }
        },
        .pointer => |p| blk: {
            if (p.size == .slice) { // string or bytes
                if (p.child == u8) {
                    const offset = try readOffset(bytes, index); // updates index by 32
                    const len = try readLength(bytes, offset);
                    if (bytes.len < offset + 32 + len) return error.NotEnoughBytes;
                    // Index stays at the end of the offset slot
                    break :blk bytes[offset + 32 .. offset + 32 + len];
                } else {
                    // Handle other slice types (e.g., []u256)
                    const offset = try readOffset(bytes, index);
                    const len = try readLength(bytes, offset);
                    const result = try ctx.allocator.alloc(p.child, len);
                    var sub_index: usize = offset + 32;
                    for (result) |*item| {
                        item.* = try decodeByType(p.child, ctx, &sub_index);
                    }
                    break :blk result;
                }
            }
            @compileError("Only slice pointers to u8 supported");
        },
        .@"struct" => |struct_info| blk: {
            var result: T = undefined;
            inline for (struct_info.fields) |field| {
                const FieldType = field.type;
                @field(result, field.name) = try decodeByType(FieldType, ctx, index); // recursive call updates index
            }
            break :blk result;
        },
        else => @compileError("Unsupported type for decoding: " ++ @typeName(T)),
    };
}

pub fn encodeByType(comptime T: type, value: T, buffer: *std.ArrayList(u8)) !void {
    if (T == void or T == anyerror!void) return;

    switch (@typeInfo(T)) {
        .int => |info| {
            // Ensure buffer has space for 32 bytes
            try buffer.appendNTimes(0, ABI_SLOT_SIZE); // Reserve space
            const slice = buffer.items[buffer.items.len - ABI_SLOT_SIZE ..][0..32];
            const ptr = @as(*[32]u8, @ptrCast(slice.ptr));
            if (info.signedness == .signed) {
                const extended = switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        @as(i256, @intCast(value))
                    else
                        @compileError("Unsupported signed integer type"),
                };
                std.mem.writeInt(i256, ptr, extended, .big);
            } else {
                const extended = switch (info.bits) {
                    else => if (info.bits % 8 == 0 and info.bits <= 256)
                        @as(u256, value)
                    else
                        @compileError("Unsupported unsigned integer size"),
                };
                std.mem.writeInt(u256, ptr, extended, .big);
            }
        },
        .bool => {
            // 32-byte slot, right-aligned
            try buffer.appendNTimes(0, 31);
            try buffer.append(@intFromBool(value));
        },
        .array => |arr| {
            if (arr.len == 0 and arr.child == u8) { // Dynamic bytes
                // Offset (32 bytes) + length (32 bytes) + padded data
                const data_start = buffer.items.len + 64; // Offset + length slots
                try buffer.appendNTimes(0, 24); // Pad offset to 32 bytes
                try buffer.appendSlice(std.mem.asBytes(&data_start)[0..8]); // Offset value
                try buffer.appendNTimes(0, 24); // Pad length to 32 bytes
                try buffer.appendSlice(std.mem.asBytes(&value.len)[0..8]); // Length value
                try buffer.appendSlice(value); // Data
                const padded_len = (value.len + 31) & ~@as(usize, 31); // Round up to 32-byte boundary
                try buffer.appendNTimes(0, padded_len - value.len); // Padding
            } else if (arr.len > 0 and arr.child == u8) { // Fixed bytes (e.g., bytes4)
                try buffer.appendNTimes(0, 32 - arr.len); // Left-pad to 32 bytes
                try buffer.appendSlice(&value);
            } else if (arr.len > 0) { // Fixed array (e.g., uint256[3])
                for (value) |item| {
                    try encodeByType(arr.child, item, buffer);
                }
            } else { // Dynamic array (e.g., uint256[])
                // Offset (32 bytes) + length (32 bytes) + elements
                const data_start = buffer.items.len + 64; // Offset + length slots
                try buffer.appendNTimes(0, 24); // Pad offset
                try buffer.appendSlice(std.mem.asBytes(&data_start)[0..8]);
                try buffer.appendNTimes(0, 24); // Pad length
                try buffer.appendSlice(std.mem.asBytes(&value.len)[0..8]);
                for (value) |item| {
                    try encodeByType(arr.child, item, buffer);
                }
            }
        },
        .pointer => |p| {
            if (p.size == .slice) {
                if (p.child == u8) { // Dynamic bytes (e.g., string)
                    // Offset (32 bytes) + length (32 bytes) + padded data
                    const data_start = buffer.items.len + 64;
                    try buffer.appendNTimes(0, 24); // Pad offset
                    try buffer.appendSlice(std.mem.asBytes(&data_start)[0..8]);
                    try buffer.appendNTimes(0, 24); // Pad length
                    try buffer.appendSlice(std.mem.asBytes(&value.len)[0..8]);
                    try buffer.appendSlice(value);
                    const padded_len = (value.len + 31) & ~@as(usize, 31);
                    try buffer.appendNTimes(0, padded_len - value.len);
                } else { // Dynamic array (e.g., uint256[])
                    const data_start = buffer.items.len + 64;
                    try buffer.appendNTimes(0, 24); // Pad offset
                    try buffer.appendSlice(std.mem.asBytes(&data_start)[0..8]);
                    try buffer.appendNTimes(0, 24); // Pad length
                    try buffer.appendSlice(std.mem.asBytes(&value.len)[0..8]);
                    for (value) |item| {
                        try encodeByType(p.child, item, buffer);
                    }
                }
            } else {
                @compileError("Unsupported pointer type");
            }
        },
        .@"struct" => |struct_info| {
            inline for (struct_info.fields) |field| {
                try encodeByType(field.type, @field(value, field.name), buffer);
            }
        },
        else => @compileError("Unsupported type for encoding: " ++ @typeName(T)),
    }
}

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
    };
}

fn readOffset(bytes: []const u8, index: *usize) !usize {
    const new_index = index.* + ABI_SLOT_SIZE;
    if (bytes.len < new_index) return error.NotEnoughBytes;
    defer index.* = new_index;

    const ptr = @as(*const [32]u8, @ptrCast(bytes[index.*..new_index]));
    const bytes_needed = @sizeOf(usize);
    const start = 32 - bytes_needed;
    const offset = std.mem.readInt(usize, ptr[start..32], .big);
    return offset;
}

fn readLength(bytes: []const u8, offset: usize) !usize {
    if (bytes.len < offset + 32) return error.NotEnoughBytes;
    const ptr = @as(*const [32]u8, @ptrCast(bytes[offset .. offset + 32]));
    const bytes_needed = @sizeOf(usize);
    const start = 32 - bytes_needed;
    return std.mem.readInt(usize, ptr[start..32], .big);
}

fn writeIntToSlot(comptime T: type, slot: []u8, value: T) void {
    if (@typeInfo(T) != .int) {
        @compileError("writeIntToSlot expects an integer type, got " ++ @typeName(T));
    }
    const bytes_needed = @divExact(@typeInfo(T).int.bits, 8);
    const pad_bytes = 32 - bytes_needed;
    const pad_value: u8 = if (@typeInfo(T).int.signedness == .signed and value < 0) 0xff else 0;
    @memset(slot[0..pad_bytes], pad_value);
    std.mem.writeInt(T, slot[pad_bytes..32], value, .big);
}

test "hashAtComptime" {
    const input = "hello()";
    const expected = "19ff1d210e06a53ee50e5bad25fa509a6b00ed395695f7d9b82b68155d9e1065";

    const result = comptime hashAtComptime(input);
    var hex_result = comptime bytesToHexString([64]u8, &result);

    try std.testing.expectEqualStrings(expected, &hex_result);
}

test "getSelector" {
    const Contract = struct {
        pub fn incrementBy(ctx: *Context, amount: u256) void {
            _ = ctx;
            _ = amount;
        }

        pub fn getCount(ctx: *Context) u256 {
            _ = ctx;
            return 0;
        }
    };

    // Compute selectors at compile time
    const incrementBySelector = comptime getSelector("incrementBy", Contract.incrementBy);
    const getCountSelector = comptime getSelector("getCount", Contract.getCount);

    try std.testing.expectEqual(0x03df179c, incrementBySelector);
    try std.testing.expectEqual(0xa87d942c, getCountSelector);
}

test "zigToSolidityType" {
    const u256_abi = comptime zigToSolidityType(u256);
    try std.testing.expectEqualStrings(u256_abi, "uint256");
}

test "decode and encode ABI" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit(); // Clean up after the test
    const allocator = arena.allocator();

    const Contract = struct {
        pub fn add(ctx: *Context, a: u256, b: u256) u256 {
            _ = ctx;
            return a + b;
        }
    };

    // Simulate calldata: selector (4 bytes) + a (32 bytes) + b (32 bytes)
    var calldata: [68]u8 = undefined;
    calldata[0..4].* = [_]u8{ 0x77, 0x0e, 0x7c, 0x9d };

    std.mem.writeInt(u256, calldata[4..36], 42, .big);
    std.mem.writeInt(u256, calldata[36..68], 58, .big);

    // Simulate return buffer
    var returndata: [32]u8 = undefined;
    var ctx = Context{
        .allocator = allocator,
        .block = .{ .number = 100 },
        .calldata = &calldata,
        .returndata = &returndata,
    };

    // Call the handler
    try decodeAndCallHandler(Contract.add, &ctx);

    // Verify the result (42 + 58 = 100)
    const result = std.mem.readInt(u256, returndata[0..32], .big);
    try std.testing.expectEqual(@as(u256, 100), result);
}

test "decode and encode all types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const Contract = struct {
        pub fn testTypes(
            ctx: *Context,
            u: u256,
            i: i128,
            addr: u160,
            b: bool,
            fixed: [4]u8,
            dyn: []const u8,
            arr: []const u256,
        ) struct { u256, bool, []const u8 } {
            _ = ctx;
            _ = i;
            _ = addr;
            _ = fixed;
            return .{ u + arr[0], b, dyn };
        }
    };

    var calldata: [356]u8 = undefined; // Already sized correctly
    var returndata: [256]u8 = undefined;
    var pos: usize = 0;

    @memcpy(calldata[pos .. pos + 4], &[_]u8{ 0x12, 0x34, 0x56, 0x78 });
    pos += 4;

    // u256 = 42
    writeIntToSlot(u256, calldata[pos .. pos + 32], 42);
    pos += 32;

    // i128 = -100
    writeIntToSlot(i128, calldata[pos .. pos + 32], -100);
    pos += 32;

    // addr = 0x1234...
    writeIntToSlot(u160, calldata[pos .. pos + 32], 0x1234567890abcdef1234567890abcdef12345678);
    pos += 32;

    // bool = true
    @memset(calldata[pos .. pos + 31], 0);
    calldata[pos + 31] = 1;
    // std.debug.print("Set bool: calldata[{d}] = {d}\n", .{ pos + 31, calldata[pos + 31] });
    pos += 32;

    // [4]u8 = "abcd"
    @memset(calldata[pos .. pos + 28], 0);
    @memcpy(calldata[pos + 28 .. pos + 32], "abcd");
    pos += 32;

    // Dynamic data setup
    const arg_end = 4 + 7 * 32; // 228
    const dyn_start = arg_end; // 228
    const arr_start = dyn_start + 64; // 292 (32 for length + 32 for padded "hello")

    // dyn offset and data (example)
    const slot_dyn_offset = calldata[pos .. pos + 32];
    @memset(slot_dyn_offset[0..24], 0);
    std.mem.writeInt(usize, @as(*[8]u8, @ptrCast(slot_dyn_offset[24..32])), dyn_start, .big);
    pos += 32;

    // arr offset
    const slot_arr_offset = calldata[pos .. pos + 32];
    @memset(slot_arr_offset[0..24], 0);
    std.mem.writeInt(usize, @as(*[8]u8, @ptrCast(slot_arr_offset[24..32])), arr_start, .big);
    pos += 32;

    // dyn data
    const slot_dyn_length = calldata[dyn_start .. dyn_start + 32];
    @memset(slot_dyn_length[0..24], 0);
    std.mem.writeInt(usize, @as(*[8]u8, @ptrCast(slot_dyn_length[24..32])), 5, .big);
    @memcpy(calldata[dyn_start + 32 .. dyn_start + 37], "hello");
    @memset(calldata[dyn_start + 37 .. dyn_start + 64], 0);

    // arr data
    const slot_arr_length = calldata[arr_start .. arr_start + 32];
    @memset(slot_arr_length[0..24], 0);
    std.mem.writeInt(usize, @as(*[8]u8, @ptrCast(slot_arr_length[24..32])), 1, .big);
    std.mem.writeInt(u256, calldata[arr_start + 32 .. arr_start + 64], 58, .big);

    // Verify boolean slot
    // std.debug.print("Before decode: calldata[131] = {d}\n", .{calldata[131]});

    var ctx = Context{
        .allocator = allocator,
        .block = .{ .number = 100 },
        .calldata = &calldata,
        .returndata = &returndata,
    };

    try decodeAndCallHandler(Contract.testTypes, &ctx);

    var ret_idx: usize = 0;
    const u_result = std.mem.readInt(u256, @as(*[32]u8, @ptrCast(returndata[0..32])), .big);
    ret_idx += 32;
    const b_result = returndata[ret_idx + 31] == 1;
    ret_idx += 32;
    const dyn_offset = std.mem.readInt(usize, @as(*const [8]u8, @ptrCast(returndata[ret_idx + 24 .. ret_idx + 32])), .big);
    ret_idx += 32;
    const dyn_len = std.mem.readInt(usize, @as(*const [8]u8, @ptrCast(returndata[dyn_offset + 24 .. dyn_offset + 32])), .big);
    const dyn_data = returndata[dyn_offset + 32 .. dyn_offset + 32 + dyn_len];

    try std.testing.expectEqual(@as(u256, 100), u_result);
    try std.testing.expectEqual(true, b_result);
    try std.testing.expectEqualStrings("hello", dyn_data);
}

test "router no matching route" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const Contract = struct {
        pub fn foo(ctx: *Context) anyerror!void {
            _ = ctx;
        }
    };

    var calldata = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // Random selector

    var ctx = Context{
        .allocator = allocator,
        .block = .{ .number = 69 },
        .calldata = &calldata,
        .returndata = &.{},
    };

    const Route = Router(.{}).Route;

    const routes = comptime [_]Route{
        Route.init("foo", .{}, Contract.foo),
    };

    const result = Router.handle(&routes, &ctx);
    try std.testing.expectEqual(@as(i32, 1), result);
}

test "router middleware and bar decoding" {
    const store = .{};
    const ContextType = Context(store);
    const NextFnType = Router(store).NextFn;
    const Route = Router(store).Route;

    const Contract = struct {
        pub fn test_mw(ctx: *ContextType, next: *const NextFnType) anyerror!void {
            try next(ctx);
        }

        pub fn test_mw2(ctx: *ContextType, next: *const NextFnType) anyerror!void {
            try next(ctx);
        }

        pub fn test_foo(ctx: *ContextType) anyerror!void {
            _ = ctx;
        }

        pub fn test_bar(ctx: *ContextType, n: u256) anyerror!void {
            try std.testing.expectEqual(@as(u256, 42), n);
            try std.testing.expectEqual(@as(u256, 69), ctx.block.number);
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const selector = comptime getSelector("bar", Contract.test_bar);
    const selector_bytes = [_]u8{
        @intCast((selector >> 24) & 0xFF),
        @intCast((selector >> 16) & 0xFF),
        @intCast((selector >> 8) & 0xFF),
        @intCast(selector & 0xFF),
    };
    var arg_bytes = [_]u8{0} ** 32;
    arg_bytes[31] = 42;
    var calldata: [36]u8 = undefined;
    @memcpy(calldata[0..4], &selector_bytes);
    @memcpy(calldata[4..36], &arg_bytes);

    var ctx = Context{
        .allocator = allocator,
        .block = .{ .number = 69 },
        .calldata = &calldata,
    };

    const routes = comptime [_]Route{
        Route.init("foo", .{}, Contract.test_foo),
        Route.init("bar", .{ Contract.test_mw, Contract.test_mw2 }, Contract.test_bar),
    };

    const result = Router.handle(&routes, &ctx);
    try std.testing.expectEqual(@as(i32, 0), result);
}

test "router invalid calldata" {
    const store = .{};
    const Route = Router(store).Route;
    const Contract = struct {
        pub fn foo(ctx: *Context) void {
            _ = ctx;
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var calldata = [_]u8{ 0x01, 0x02 }; // Too short

    var ctx = Context{
        .allocator = allocator,
        .block = .{ .number = 69 },
        .calldata = &calldata,
    };

    const routes = comptime [_]Route{
        Route.init("foo", .{}, Contract.foo),
    };

    const result = Router.handle(&routes, &ctx);
    try std.testing.expectEqual(@as(i32, 1), result);
}
