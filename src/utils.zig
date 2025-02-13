const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
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

// Standard ERC20 function selectors (first 4 bytes of keccak256 hash of function signatures)
const INITIATE_SELECTOR = [_]u8{ 0x79, 0x01, 0xea, 0x78 }; // initiate(uint256) 0x7901ea78
const TOTAL_SUPPLY_SELECTOR = [_]u8{ 0x18, 0x16, 0x0d, 0xdd }; // totalSupply() 0x18160ddd
const BALANCE_OF_SELECTOR = [_]u8{ 0x70, 0xa0, 0x82, 0x31 }; // balanceOf(address) 0x70a08231
const TRANSFER_SELECTOR = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb }; // transfer(address,uint256) 0xa9059cbb
const ALLOWANCE_SELECTOR = [_]u8{ 0xdd, 0x62, 0xed, 0x3e }; // allowance(address,address) 0xdd62ed3e
const APPROVE_SELECTOR = [_]u8{ 0x09, 0x5e, 0xa7, 0xb3 }; // approve(address,uint256) 0x095ea7b3
const TRANSFER_FROM_SELECTOR = [_]u8{ 0x23, 0xb8, 0x72, 0xdd }; // transferFrom(address,address,uint256) 0x23b872dd

// Storage slots
pub const SLOTS = struct {
    pub const NAME: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01 };
    pub const SYMBOL: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02 };
    pub const DECIMALS: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03 };
    pub const TOTAL_SUPPLY: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04 };
    pub const BALANCES: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05 };
    pub const ALLOWANCES: [32]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06 };
};

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
    storage_flush_cache(true);
}

pub fn bytes32ToU256(bytes: [32]u8) u256 {
    return std.mem.readInt(u256, &bytes, .big);
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

pub fn isSliceUndefined(slice: []const u8) bool {
    return slice.ptr == undefined or slice.len == 0;
}

pub fn method_router(selector: [4]u8, data: []u8, contract: *erc20.ERC20) !void {
    // _ = data;
    switch (@as(u32, selector[0]) << 24 | @as(u32, selector[1]) << 16 | @as(u32, selector[2]) << 8 | @as(u32, selector[3])) {
        @as(u32, INITIATE_SELECTOR[0]) << 24 | @as(u32, INITIATE_SELECTOR[1]) << 16 | @as(u32, INITIATE_SELECTOR[2]) << 8 | @as(u32, INITIATE_SELECTOR[3]) => {
            try contract.initiate(data);
        },
        @as(u32, TOTAL_SUPPLY_SELECTOR[0]) << 24 | @as(u32, TOTAL_SUPPLY_SELECTOR[1]) << 16 | @as(u32, TOTAL_SUPPLY_SELECTOR[2]) << 8 | @as(u32, TOTAL_SUPPLY_SELECTOR[3]) => {
            const total_supply = try contract.totalSupply();
            write_output(total_supply);
        },
        @as(u32, BALANCE_OF_SELECTOR[0]) << 24 | @as(u32, BALANCE_OF_SELECTOR[1]) << 16 | @as(u32, BALANCE_OF_SELECTOR[2]) << 8 | @as(u32, BALANCE_OF_SELECTOR[3]) => {
            // const decoded = try decoder.decodeAbiFunction([20]u8, allocator, encoded, .{});
            // try stdout.print("balanceOf called for address: 0x{}\n", .{std.fmt.fmtSliceHexLower(&decoded.result)});
            // Add balanceOf logic here
            const total_supply_u256 = try bytesToU256(data);
            const value_bytes = try u256ToBytes(total_supply_u256);
            write_output(value_bytes);
        },
        @as(u32, TRANSFER_SELECTOR[0]) << 24 | @as(u32, TRANSFER_SELECTOR[1]) << 16 | @as(u32, TRANSFER_SELECTOR[2]) << 8 | @as(u32, TRANSFER_SELECTOR[3]) => {
            // try stdout.print("transfer called\n", .{});
            // Add transfer logic here
        },
        @as(u32, ALLOWANCE_SELECTOR[0]) << 24 | @as(u32, ALLOWANCE_SELECTOR[1]) << 16 | @as(u32, ALLOWANCE_SELECTOR[2]) << 8 | @as(u32, ALLOWANCE_SELECTOR[3]) => {
            // try stdout.print("allowance called\n", .{});
            // Add allowance logic here
        },
        @as(u32, APPROVE_SELECTOR[0]) << 24 | @as(u32, APPROVE_SELECTOR[1]) << 16 | @as(u32, APPROVE_SELECTOR[2]) << 8 | @as(u32, APPROVE_SELECTOR[3]) => {
            // try stdout.print("approve called\n", .{});
            // Add approve logic here
        },
        @as(u32, TRANSFER_FROM_SELECTOR[0]) << 24 | @as(u32, TRANSFER_FROM_SELECTOR[1]) << 16 | @as(u32, TRANSFER_FROM_SELECTOR[2]) << 8 | @as(u32, TRANSFER_FROM_SELECTOR[3]) => {
            // Add transferFrom logic here
        },
        else => {},
    }
}

pub fn get_balance_slot(owner: []const u8) []u8 {
    return compute_mapping_slot(owner, SLOTS.BALANCES);
}

pub fn get_allowance_slot(owner: []const u8, spender: []const u8) []u8 {
    const spender_slot = compute_mapping_slot(spender, SLOTS.ALLOWANCES);
    return compute_mapping_slot(owner, std.mem.bytesToValue(u256, spender_slot));
}

pub fn keccak256(data: []u8) ![]u8 {
    const output = try allocator.alloc(u8, 32);
    native_keccak256(@ptrCast(data), data.len, @ptrCast(output));
    return output;
}

pub fn compute_mapping_slot(key: []const u8, slot: u256) []u8 {
    var concat: [64]u8 = undefined;
    std.mem.copyForwards(u8, concat[0..32], key);
    std.mem.copyForwards(u8, concat[32..64], &slot);
    return keccak256(concat[0..]);
}
