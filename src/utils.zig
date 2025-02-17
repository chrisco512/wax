const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
const ValueStorage = @import("value_storage.zig");
const erc20 = @import("erc20.zig");
const zabi = @import("zabi");
const decoder = zabi.decoding.abi_decoder;

pub extern "vm_hooks" fn read_args(dest: *u8) void;
pub extern "vm_hooks" fn write_result(data: *const u8, len: usize) void;
pub extern "vm_hooks" fn storage_cache_bytes32(key: *const u8, value: *const u8) void;
pub extern "vm_hooks" fn storage_flush_cache(clear: bool) void;
pub extern "vm_hooks" fn storage_load_bytes32(key: *const u8, dest: *u8) void;
pub extern "vm_hooks" fn native_keccak256(bytes: *const u8, len: usize, output: *u8) void;
pub extern "vm_hooks" fn block_number() u64;
pub extern "vm_hooks" fn msg_sender(sender: *const u8) void;

// Standard ERC20 function selectors (first 4 bytes of keccak256 hash of function signatures)
const INITIATE_SELECTOR = [_]u8{ 0x79, 0x01, 0xea, 0x78 }; // initiate(uint256) 0x7901ea78
const TOTAL_SUPPLY_SELECTOR = [_]u8{ 0x18, 0x16, 0x0d, 0xdd }; // totalSupply() 0x18160ddd
const BALANCE_OF_SELECTOR = [_]u8{ 0x70, 0xa0, 0x82, 0x31 }; // balanceOf(address) 0x70a08231
const TRANSFER_SELECTOR = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb }; // transfer(address,uint256) 0xa9059cbb
const ALLOWANCE_SELECTOR = [_]u8{ 0xdd, 0x62, 0xed, 0x3e }; // allowance(address,address) 0xdd62ed3e
const APPROVE_SELECTOR = [_]u8{ 0x09, 0x5e, 0xa7, 0xb3 }; // approve(address,uint256) 0x095ea7b3
const TRANSFER_FROM_SELECTOR = [_]u8{ 0x23, 0xb8, 0x72, 0xdd }; // transferFrom(address,address,uint256) 0x23b872dd
const OWNER_SELECTOR = [_]u8{ 0x8d, 0xa5, 0xcb, 0x5b }; // owner() 0x8da5cb5b
const DECIMALS_SELECTOR = [_]u8{ 0x31, 0x3c, 0xe5, 0x67 }; // decimals() 0x313ce567
const NAME_SELECTOR = [_]u8{ 0x06, 0xfd, 0xde, 0x03 }; // name() 0x06fdde03
const SYMBOL_SELECTOR = [_]u8{ 0x95, 0xd8, 0x9b, 0x41 }; // symbol() 0x95d89b41

pub const ZERO_BYTES = [_]u8{0} ** 32;

// Uses our custom WasmAllocator which is a simple modification over the wasm allocator
// from the Zig standard library as of Zig 0.11.0.
pub const allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = &WasmAllocator.vtable,
};

// Reads input arguments from an external, WASM import into a dynamic slice.
pub fn get_input(len: usize) ![]u8 {
    const input = try allocator.alloc(u8, len);
    read_args(@ptrCast(input));
    return input;
}

// Outputs data as bytes via a write_result, external WASM import.
pub fn write_output(data: []u8) void {
    write_result(@ptrCast(data), data.len);
}

// For slices
pub fn left_pad(slice: []u8, size: usize) ![]u8 {
    const output = try allocator.alloc(u8, size);
    const padding = size - slice.len;
    std.mem.copyForwards(u8, output[padding..], slice);
    return output;
}

pub fn read_storage(key: []u8) ![]u8 {
    const key_to_read = try left_pad(key, 32);
    const output = try allocator.alloc(u8, 32);
    storage_load_bytes32(@ptrCast(key_to_read), @ptrCast(output));
    return output;
}

pub fn write_storage(key: []u8, value: []u8) !void {
    const key_to_set = try left_pad(key, 32);
    const value_to_set = try left_pad(value, 32);
    storage_cache_bytes32(@ptrCast(key_to_set), @ptrCast(value_to_set));
}

pub fn bytes32ToU256(bytes: [32]u8) u256 {
    return std.mem.readInt(u256, &bytes, .big);
}

pub fn bytes32ToBytes(bytes: [32]u8) ![]u8 {
    const result = try allocator.alloc(u8, 32);
    std.mem.copyBackwards(u8, result, &bytes);
    return result;
}

pub fn bytesToBytes32(bytes: []const u8) ![32]u8 {
    if (bytes.len > 32) return error.InputTooLong;

    var result: [32]u8 = [_]u8{0} ** 32;
    std.mem.copyBackwards(u8, &result, bytes);
    return result;
}

pub fn bytesToU256(bytes: []const u8) !u256 {
    if (bytes.len > 32) return error.InvalidLength;

    var padded: [32]u8 = [_]u8{0} ** 32;
    // Right-align the bytes for big numbers
    const start = 32 - bytes.len;
    std.mem.copyForwards(u8, padded[start..], bytes);

    return std.mem.readInt(u256, &padded, .big);
}

pub fn u256ToBytes(value: u256) ![]u8 {
    var temp: [32]u8 = undefined;
    std.mem.writeInt(u256, &temp, value, .big);

    const result = try allocator.alloc(u8, 32);
    std.mem.copyBackwards(u8, result, &temp);
    return result;
}

pub fn u32ToBytes32(value: u32) [32]u8 {
    var result: [32]u8 = [_]u8{0} ** 32;
    var temp: [4]u8 = undefined;
    std.mem.writeInt(u32, &temp, value, .big);
    std.mem.copyForwards(u8, result[28..], &temp);
    return result;
}

pub fn u32ToBytes(value: u32) ![]u8 {
    var temp: [4]u8 = undefined;
    const result = try allocator.alloc(u8, 32);

    // Fill with zeros
    @memset(result, 0);

    // Write u32 to temp buffer in big endian
    std.mem.writeInt(u32, &temp, value, .big);

    // Copy to last 4 bytes of result
    std.mem.copyForwards(u8, result[28..], &temp);
    return result;
}

pub fn u8ToBytes(value: u8) ![]u8 {
    var result = try allocator.alloc(u8, 32);
    // Zero initialize
    @memset(result, 0);
    // Write u8 to last byte
    result[31] = value;
    return result;
}

pub fn boolToBytes(value: bool) ![]u8 {
    var result = try allocator.alloc(u8, 32);
    // Zero initialize
    @memset(result, 0);
    // Write bool to last byte
    result[31] = @intFromBool(value);
    return result;
}

pub fn bytesToAddress(bytes: []const u8) !ValueStorage.Address {
    if (bytes.len != 20 and bytes.len != 32) return error.InvalidLength;

    var result: ValueStorage.Address = undefined;
    if (bytes.len == 32) {
        // Check if left padded (common case)
        var left_zeros = true;
        for (bytes[0..12]) |b| {
            if (b != 0) {
                left_zeros = false;
                break;
            }
        }

        if (left_zeros) {
            // Left padded - take last 20 bytes
            std.mem.copyBackwards(u8, &result, bytes[12..32]);
        } else {
            // Right padded - take first 20 bytes
            std.mem.copyBackwards(u8, &result, bytes[0..20]);
        }
    } else {
        std.mem.copyBackwards(u8, &result, bytes);
    }
    return result;
}

pub fn addressToBytes(address: ValueStorage.Address) ![]u8 {
    var result: []u8 = try allocator.alloc(u8, 32);
    std.mem.copyBackwards(u8, result[12..32], &address);
    return result;
}

pub fn dupeString(str: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, str.len);
    std.mem.copyForwards(u8, result, str);
    return result;
}

pub fn isSliceUndefined(slice: []const u8) bool {
    return slice.ptr == undefined or slice.len == 0;
}

pub const AddressUtils = struct {
    pub fn from_bytes(self: @This(), bytes: []u8) !ValueStorage.Address {
        _ = self;
        const result = try bytesToAddress(bytes);
        return result;
    }

    pub fn to_bytes(self: @This(), value: ValueStorage.Address) ![]u8 {
        _ = self;
        const result = try addressToBytes(value);
        return result;
    }

    pub fn is_zero_address(self: @This(), address: ValueStorage.Address) bool {
        _ = self;
        var is_zero = true;
        for (address) |b| {
            if (b != 0) {
                is_zero = false;
                break;
            }
        }
        return is_zero;
    }
};

pub const U256Utils = struct {
    pub fn from_bytes(self: @This(), bytes: []u8) !u256 {
        _ = self;
        const result = try bytesToU256(bytes);
        return result;
    }

    pub fn to_bytes(self: @This(), value: u256) ![]u8 {
        _ = self;
        const result = try u256ToBytes(value);
        return result;
    }
};

pub const VoidUtils = struct {
    pub fn from_bytes(self: @This(), bytes: []u8) !u256 {
        _ = self;
        _ = bytes;
        // Do nothing
        return 0;
    }

    pub fn to_bytes(self: @This(), value: u256) ![]u8 {
        _ = self;
        _ = value;
        // Do nothing
        return []u8{0};
    }
};

pub fn is_primitives(comptime T: type) bool {
    return switch (T) {
        u256 => true,
        ValueStorage.Address => true,
        bool => true,
        [32]u8 => true,
        else => false,
    };
}

pub fn getValueUtils(comptime T: type) type {
    return switch (T) {
        u256 => U256Utils,
        ValueStorage.Address => AddressUtils,
        else => VoidUtils,
    };
}

// Todo, implement a general use case method router
// Currently this router only supports standard erc20 interface
pub fn method_router(selector: [4]u8, data: []u8, contract: *erc20.ERC20) !void {
    switch (@as(u32, selector[0]) << 24 | @as(u32, selector[1]) << 16 | @as(u32, selector[2]) << 8 | @as(u32, selector[3])) {
        @as(u32, INITIATE_SELECTOR[0]) << 24 | @as(u32, INITIATE_SELECTOR[1]) << 16 | @as(u32, INITIATE_SELECTOR[2]) << 8 | @as(u32, INITIATE_SELECTOR[3]) => {
            const total_supply = try bytesToU256(data);
            try contract.initiate(total_supply);
        },
        @as(u32, TOTAL_SUPPLY_SELECTOR[0]) << 24 | @as(u32, TOTAL_SUPPLY_SELECTOR[1]) << 16 | @as(u32, TOTAL_SUPPLY_SELECTOR[2]) << 8 | @as(u32, TOTAL_SUPPLY_SELECTOR[3]) => {
            const total_supply = try contract.totalSupply();
            write_output(total_supply);
        },
        @as(u32, BALANCE_OF_SELECTOR[0]) << 24 | @as(u32, BALANCE_OF_SELECTOR[1]) << 16 | @as(u32, BALANCE_OF_SELECTOR[2]) << 8 | @as(u32, BALANCE_OF_SELECTOR[3]) => {
            // const decoded = try decoder.decodeAbiFunction([20]u8, allocator, encoded, .{});
            // try stdout.print("balanceOf called for address: 0x{}\n", .{std.fmt.fmtSliceHexLower(&decoded.result)});
            // Add balanceOf logic here
            const address = try bytesToAddress(data);
            const balance = try contract.balanceOf(address);
            const balance_bytes = try u256ToBytes(balance);
            write_output(balance_bytes);
        },
        @as(u32, TRANSFER_SELECTOR[0]) << 24 | @as(u32, TRANSFER_SELECTOR[1]) << 16 | @as(u32, TRANSFER_SELECTOR[2]) << 8 | @as(u32, TRANSFER_SELECTOR[3]) => {
            // try stdout.print("transfer called\n", .{});
            // Add transfer logic here
            const to = try bytesToAddress(data[0..32]);
            const value = try bytesToU256(data[32..]);
            const success = try contract.transfer(to, value);
            if (!success) {
                @panic("error transfer");
            }
        },
        @as(u32, ALLOWANCE_SELECTOR[0]) << 24 | @as(u32, ALLOWANCE_SELECTOR[1]) << 16 | @as(u32, ALLOWANCE_SELECTOR[2]) << 8 | @as(u32, ALLOWANCE_SELECTOR[3]) => {
            const owner_addr = try bytesToAddress(data[0..32]);
            const spender_addr = try bytesToAddress(data[32..64]);
            const allowance = try contract.allowance(owner_addr, spender_addr);
            const allowance_bytes = try u256ToBytes(allowance);
            write_output(allowance_bytes);
        },
        @as(u32, APPROVE_SELECTOR[0]) << 24 | @as(u32, APPROVE_SELECTOR[1]) << 16 | @as(u32, APPROVE_SELECTOR[2]) << 8 | @as(u32, APPROVE_SELECTOR[3]) => {
            const spender = try bytesToAddress(data[0..32]);
            const value = try bytesToU256(data[32..]);
            const success = try contract.approve(spender, value);
            if (!success) {
                @panic("error approve");
            }
        },
        @as(u32, TRANSFER_FROM_SELECTOR[0]) << 24 | @as(u32, TRANSFER_FROM_SELECTOR[1]) << 16 | @as(u32, TRANSFER_FROM_SELECTOR[2]) << 8 | @as(u32, TRANSFER_FROM_SELECTOR[3]) => {
            const from = try bytesToAddress(data[0..32]);
            const to = try bytesToAddress(data[32..64]);
            const value = try bytesToU256(data[64..]);
            const success = try contract.transferFrom(from, to, value);
            if (!success) {
                @panic("error transferFrom");
            }
        },
        @as(u32, OWNER_SELECTOR[0]) << 24 | @as(u32, OWNER_SELECTOR[1]) << 16 | @as(u32, OWNER_SELECTOR[2]) << 8 | @as(u32, OWNER_SELECTOR[3]) => {
            const owner = try contract.owner();
            const address_utils = AddressUtils{};
            const owner_bytes = try address_utils.to_bytes(owner);
            write_output(owner_bytes);
        },
        @as(u32, DECIMALS_SELECTOR[0]) << 24 | @as(u32, DECIMALS_SELECTOR[1]) << 16 | @as(u32, DECIMALS_SELECTOR[2]) << 8 | @as(u32, DECIMALS_SELECTOR[3]) => {
            const decimals = contract.decimals();
            const decimals_bytes = try u32ToBytes(decimals);
            write_output(decimals_bytes);
        },
        // @as(u32, NAME_SELECTOR[0]) << 24 | @as(u32, NAME_SELECTOR[1]) << 16 | @as(u32, NAME_SELECTOR[2]) << 8 | @as(u32, NAME_SELECTOR[3]) => {
        //     const name = try contract.name();
        //     const str_slice = try dupeString(name);
        //     write_output(str_slice);
        // },
        // @as(u32, SYMBOL_SELECTOR[0]) << 24 | @as(u32, SYMBOL_SELECTOR[1]) << 16 | @as(u32, SYMBOL_SELECTOR[2]) << 8 | @as(u32, SYMBOL_SELECTOR[3]) => {
        //     const symbol = try contract.symbol();
        //     const str_slice = try dupeString(symbol);
        //     write_output(str_slice);
        // },
        else => {},
    }
}

pub fn keccak256(data: []u8) ![32]u8 {
    const hashed = try allocator.alloc(u8, 32);
    native_keccak256(@ptrCast(data), data.len, @ptrCast(hashed));
    const output = try bytesToBytes32(hashed);
    return output;
}

pub fn get_msg_sender() !ValueStorage.Address {
    const sender = try allocator.alloc(u8, 32);
    msg_sender(@ptrCast(sender));
    return try bytesToAddress(sender);
}
