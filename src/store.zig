const std = @import("std");
const host = @import("hostio.zig");
const Address = @import("types.zig").Address;

fn slotKey(comptime slot: usize) [32]u8 {
    var key: [32]u8 = undefined;
    @memset(&key, 0);
    std.mem.writeInt(u32, key[28..], slot, .big);
    return key;
}

pub fn Store(comptime UserStore: type) type {
    if (@typeInfo(UserStore) != .@"struct") {
        @compileError("Store must be a struct");
    }

    const fields = @typeInfo(UserStore).@"struct".fields;
    var struct_fields: [fields.len]std.builtin.Type.StructField = undefined;

    inline for (fields, 0..) |field, index| {
        const FieldType = field.type;
        const Proxy = struct {
            pub fn get(self: @This()) FieldType {
                _ = self;
                var dest: [32]u8 = undefined;
                const key = slotKey(index);
                host.storage_load_bytes32(&key[0], &dest[0]);
                return decode(FieldType, &dest);
            }

            pub fn set(self: @This(), value: FieldType) void {
                _ = self;
                var data: [32]u8 = undefined;
                encode(value, &data);
                const key = slotKey(index);
                host.storage_cache_bytes32(@ptrCast(&key), @ptrCast(&data));
                host.storage_flush_cache(false);
            }
        };
        struct_fields[index] = .{
            .name = field.name,
            .type = Proxy,
            .default_value_ptr = &Proxy{},
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = &struct_fields,
            .decls = &.{},
            .is_tuple = false,
        },
    });
}

fn decode(comptime T: type, bytes: *const [32]u8) T {
    return switch (T) {
        bool => bytes[31] != 0,
        Address => std.mem.readInt(u160, bytes[12..32], .big),
        else => switch (@typeInfo(T)) {
            .int => std.mem.readInt(T, bytes[32 - @sizeOf(T) ..], .big),
            else => @compileError("Unsupported type: " ++ @typeName(T)),
        },
    };
}

fn encode(value: anytype, dest: *[32]u8) void {
    const T = @TypeOf(value);
    switch (T) {
        bool => {
            std.mem.set(u8, dest[0..31], 0);
            dest[31] = if (value) 1 else 0;
        },
        Address => {
            std.mem.set(u8, dest[0..12], 0);
            std.mem.writeInt(u160, dest[12..32], value, .big);
        },
        else => switch (@typeInfo(T)) {
            .int => {
                @memset(dest, 0);
                std.mem.writeInt(T, dest[32 - @sizeOf(T) ..], value, .big);
            },
            else => @compileError("Unsupported type: " ++ @typeName(T)),
        },
    }
}
