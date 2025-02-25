const std = @import("std");
const utils = @import("utils.zig");
const ValueStorage = @import("value_storage.zig");

pub extern "vm_hooks" fn read_args(dest: *u8) void;
pub extern "vm_hooks" fn write_result(data: *const u8, len: usize) void;
pub extern "vm_hooks" fn storage_cache_bytes32(key: *const u8, value: *const u8) void;
pub extern "vm_hooks" fn storage_flush_cache(clear: bool) void;
pub extern "vm_hooks" fn storage_load_bytes32(key: *const u8, dest: *u8) void;
pub extern "vm_hooks" fn native_keccak256(bytes: *const u8, len: usize, output: *u8) void;
pub extern "vm_hooks" fn block_number() u64;
pub extern "vm_hooks" fn msg_sender(sender: *const u8) void;
pub extern "vm_hooks" fn emit_log(data: *const u8, len: usize, topics: usize) void;
pub extern "vm_hooks" fn block_timestamp() u64;

// sload
pub fn read_storage(key: []u8) ![]u8 {
    const key_to_read = try utils.left_pad(key, 32);
    const output = try utils.allocator.alloc(u8, 32);
    storage_load_bytes32(@ptrCast(key_to_read), @ptrCast(output));
    return output;
}

// sstore
pub fn write_storage(key: []u8, value: []u8) !void {
    const key_to_set = try utils.left_pad(key, 32);
    const value_to_set = try utils.left_pad(value, 32);
    storage_cache_bytes32(@ptrCast(key_to_set), @ptrCast(value_to_set));
}

// Reads input arguments from an external, WASM import into a dynamic slice.
pub fn get_input(len: usize) ![]u8 {
    const input = try utils.allocator.alloc(u8, len);
    read_args(@ptrCast(input));
    return input;
}

// Outputs data as bytes via a write_result, external WASM import.
pub fn write_output(data: []u8) void {
    write_result(@ptrCast(data), data.len);
}

// Call native keccak256
pub fn keccak256(data: []u8) ![32]u8 {
    const hashed = try utils.allocator.alloc(u8, 32);
    native_keccak256(@ptrCast(data), data.len, @ptrCast(hashed));
    const output = try utils.bytesToBytes32(hashed);
    return output;
}

// Get run time msg.sender
pub fn get_msg_sender() !ValueStorage.Address {
    const sender = try utils.allocator.alloc(u8, 32);
    msg_sender(@ptrCast(sender));
    return try utils.bytesToAddress(sender);
}

// Emit EVM log
pub fn emit_evm_log(topics: [][32]u8, data: []u8) !void {
    if (topics.len > 4) {
        @panic("Too many topics");
    }
    const topic_bytes_len = 32 * topics.len;
    const total_bytes_len = topic_bytes_len + data.len;
    var bytes = try utils.allocator.alloc(u8, total_bytes_len);
    defer utils.allocator.free(bytes);

    // Copy each topic's bytes sequentially
    var i: usize = 0;
    for (topics) |topic| {
        std.mem.copyForwards(u8, bytes[i * 32 .. (i + 1) * 32], &topic);
        i += 1;
    }

    // Copy data after topics
    std.mem.copyForwards(u8, bytes[topic_bytes_len..], data);
    emit_log(@ptrCast(bytes), bytes.len, topics.len);
}

// Get runtime block.timestamp
pub fn get_block_timestamp() u256 {
    const result: u256 = block_timestamp();
    return result;
}

// Get runtime block.number
pub fn get_block_number() u256 {
    const result: u256 = block_number();
    return result;
}
