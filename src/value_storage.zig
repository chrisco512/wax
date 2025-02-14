const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
const utils = @import("utils.zig");

const HashMap = std.HashMap;
pub const Address: type = [20]u8;

const AddressUtils = utils.AddressUtils;
const U256Utils = utils.U256Utils;

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
    const inner_type: type = u256;

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

pub const AddressStorage = struct {
    offset: u32,
    cache: []u8,
    const inner_type: type = Address;

    pub fn init(comptime offset_value: u32) @This() {
        return .{
            .offset = offset_value,
            .cache = undefined,
        };
    }

    pub fn set_value(self: *@This(), value: Address) !void {
        const offset_bytes = try utils.u32ToBytes(self.offset);
        const address_bytes = try utils.addressToBytes(value);
        try utils.write_storage(offset_bytes, address_bytes);
        if (utils.isSliceUndefined(self.cache)) {
            self.cache = utils.allocator.alloc(u8, 32) catch return error.OutOfMemory;
        }
        self.cache = address_bytes;
    }

    pub fn get_value(self: *@This()) !Address {
        if (utils.isSliceUndefined(self.cache)) {
            const offset_bytes = try utils.u32ToBytes(self.offset);
            self.cache = try utils.read_storage(offset_bytes);
        }
        const result = utils.bytesToAddress(self.cache);
        return result;
    }
};

pub fn MappingStorage(comptime Key: type, comptime Value: type) type {
    // Validate storage types at compile time
    if (Key != AddressStorage and Key != U256Storage) {
        @compileError("Key of MappingStorage must be either AddressStorage or U256Storage");
    }
    if (Value != AddressStorage and Value != U256Storage) {
        @compileError("Value of MappingStorage must be either AddressStorage or U256Storage");
    }

    const KeyInnerType: type = Key.inner_type;
    const ValueInnerType: type = Value.inner_type;

    const key_utils = utils.getValueUtils(KeyInnerType);
    const value_utils = utils.getValueUtils(ValueInnerType);

    const converter_type = struct {
        key_utils: key_utils,
        value_utils: value_utils,
    };

    return struct {
        offset: u32,
        cache: std.AutoHashMap(KeyInnerType, ValueInnerType),
        converter: converter_type,

        pub fn init(comptime offset_value: u32) @This() {
            return .{ .offset = offset_value, .cache = undefined, .converter = .{
                .key_utils = key_utils{},
                .value_utils = value_utils{},
            } };
        }

        fn isCacheUndefined(self: *@This()) bool {
            return self.cache.count() == 0;
        }

        fn compute_mapping_slot(key: []const u8, slot: u256) ![]u8 {
            var concat: [64]u8 = undefined;
            const slot_bytes = try utils.u256ToBytes(slot);
            std.mem.copyForwards(u8, concat[0..32], key);
            std.mem.copyForwards(u8, concat[32..64], slot_bytes);
            return utils.keccak256(concat[0..]);
        }

        pub fn set_value(self: *@This(), key: KeyInnerType, value: ValueInnerType) !void {
            const key_bytes = try self.converter.key_utils.to_bytes(key);
            const value_bytes = try self.converter.value_utils.to_bytes(value);
            const key_offset = try compute_mapping_slot(key_bytes, @as(u256, self.offset));
            try utils.write_storage(key_offset, value_bytes);
            if (self.isCacheUndefined()) {
                self.cache = std.AutoHashMap(KeyInnerType, ValueInnerType).init(utils.allocator);
            }
            try self.cache.put(key, value);
        }

        pub fn get_value(self: *@This(), key: KeyInnerType) !ValueInnerType {
            if (self.isCacheUndefined()) {
                const key_bytes = try self.converter.key_utils.to_bytes(key);
                const key_offset = try compute_mapping_slot(key_bytes, @as(u256, self.offset));
                const result_bytes = try utils.read_storage(key_offset);
                const result = try self.converter.value_utils.from_bytes(result_bytes);
                self.cache = std.AutoHashMap(KeyInnerType, ValueInnerType).init(utils.allocator);
                try self.cache.put(key, result);
            }
            return self.cache.get(key) orelse error.KeyNotFound;
        }
    };
}

// Define mixin for shared initialization behavior
pub fn SolStorage(comptime Self: type) type {
    return struct {
        pub fn init() Self {
            var result: Self = undefined;
            comptime var offset: u32 = 0;
            inline for (std.meta.fields(Self)) |field| {
                @field(result, field.name) = switch (field.type) {
                    U256Storage => field.type.init(offset),
                    AddressStorage => field.type.init(offset),
                    // MappingStorage => field.type.init(offset),
                    else => field.type.init(offset),
                };
                offset += 1;
            }
            return result;
        }
    };
}
