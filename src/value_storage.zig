const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
const utils = @import("utils.zig");

fn StorageValue(comptime T: type) type {
    return struct {
        offset: u32,
        value: T,

        pub fn init(comptime offset_value: u32) @This() {
            return .{
                .offset = offset_value,
                .value = undefined,
            };
        }

        pub fn set_value(self: *@This(), value: T) void {
            utils.write_storage(utils.u32ToBytes(self.offset), value);
            self.value = value;
        }

        pub fn get_value(self: @This()) T {
            utils.read_storage(utils.u32ToBytes(self.offset));
            return self.value;
        }
    };
}

pub const U256Storage = struct {
    offset: u32,
    cache: []u8,

    pub fn init(comptime offset_value: u32) @This() {
        return .{
            .offset = offset_value,
            .cache = undefined,
        };
    }

    pub fn set_value(self: *@This(), value: u256) !void {
        const value_bytes = try utils.u256ToBytes(value);
        const offset_bytes = try utils.u32ToBytes(self.offset);
        try utils.write_storage(offset_bytes, value_bytes);
        if (utils.isSliceUndefined(self.cache)) {
            self.cache = utils.allocator.alloc(u8, 32) catch return error.OutOfMemory;
        }
        self.cache = value_bytes;
    }

    pub fn get_value(self: *@This()) !u256 {
        if (utils.isSliceUndefined(self.cache)) {
            const offset_bytes = try utils.u32ToBytes(self.offset);
            self.cache = try utils.read_storage(offset_bytes);
        }
        return utils.bytesToU256(self.cache);
    }
};

// Define mixin for shared initialization behavior
pub fn SolStorage(comptime Self: type) type {
    return struct {
        pub fn init() Self {
            var result: Self = undefined;
            comptime var offset: u32 = 0;
            inline for (std.meta.fields(Self)) |field| {
                @field(result, field.name) = switch (field.type) {
                    U256Storage => U256Storage.init(offset),
                    // StringStorageValue => StringStorageValue.init(offset),
                    else => unreachable,
                };
                offset += 1;
            }
            return result;
        }
    };
}

// String storage implementation
const StringStorageValue = StorageValue([]const u8);

// U256 storage implementation
const U256StorageValue = StorageValue(u256);

// Define mixin for shared initialization behavior
fn StorageInit(comptime Self: type) type {
    return struct {
        pub fn init() Self {
            var result: Self = undefined;
            comptime var offset: u32 = 0;
            inline for (std.meta.fields(Self)) |field| {
                @field(result, field.name) = switch (field.type) {
                    U256StorageValue => U256StorageValue.init(offset),
                    StringStorageValue => StringStorageValue.init(offset),
                    else => unreachable,
                };
                offset += 1;
            }
            return result;
        }
    };
}
