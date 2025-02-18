const std = @import("std");
const utils = @import("utils.zig");
const hostio = @import("hostio.zig");

pub fn Indexed(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const inner_type = T;
        pub const is_indexed = true;
        value: T,
    };
}

fn isIndexed(comptime T: type) bool {
    const type_info = @typeInfo(T);
    return switch (type_info) {
        .Struct => std.mem.indexOf(u8, @typeName(T), "event.Indexed") != null,
        else => false,
    };
}

// @Copyright: resue code in https://github.com/chrisco512/zigitrum
pub fn getEventSelector(comptime name: []const u8, Params: type) ![32]u8 {
    // building selector as compile time
    const signature = comptime blk: {
        var sig: []const u8 = name;
        sig = sig ++ "(";

        for (std.meta.fields(Params), 0..) |field, i| {
            if (i > 0) sig = sig ++ ",";
            const field_type = field.type;

            if (isIndexed(field_type)) {
                sig = sig ++ utils.zigToSolidityType(field_type.inner_type);
            } else {
                sig = sig ++ utils.zigToSolidityType(field_type);
            }
        }
        sig = sig ++ ")";

        // We shouldn't use hostio.keccak256 here, because this is running on compile time
        break :blk utils.hashAtComptime(sig);
    };
    return signature;
}

pub fn EventEmitter(comptime name: []const u8, comptime Params: type) type {
    // Compute signature at compile time
    const signature_selector = try getEventSelector(name, Params);

    // Pre-compute indexed fields at compile time
    const indexed_fields = comptime blk: {
        var fields: [std.meta.fields(Params).len]bool = undefined;
        for (std.meta.fields(Params), 0..) |field, i| {
            fields[i] = isIndexed(@TypeOf(@field(@as(Params, undefined), field.name)));
        }
        break :blk fields;
    };
    return struct {
        const Self = @This();

        // Generate event signature at compile time
        const signature = signature_selector;

        pub fn emit(_: *@This(), params: Params) !void {
            var topics = std.ArrayList([32]u8).init(utils.allocator);
            defer topics.deinit();

            // Add event signature as first topic
            try topics.append(signature);

            var data = std.ArrayList(u8).init(utils.allocator);
            defer data.deinit();

            // Pack indexed parameters into topics and non-indexed into data
            inline for (std.meta.fields(Params), 0..) |field, i| {
                const value = @field(params, field.name);
                if (indexed_fields[i]) {
                    const encoded = try utils.abi_encode(@TypeOf(value).inner_type, value.value);
                    try topics.append(encoded);
                } else {
                    const encoded = try utils.abi_encode(@TypeOf(value), value);
                    const encoded_bytes = try utils.bytes32ToBytes(encoded);
                    try data.appendSlice(encoded_bytes);
                }
            }

            try hostio.emit_evm_log(topics.items, data.items);
        }
    };
}
