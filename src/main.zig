const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
const utils = @import("utils.zig");
const erc20 = @import("erc20.zig");

// External imports provided to all WASM programs on Stylus. These functions
// can be use to read input arguments coming into the program and output arguments to callers.

pub extern "vm_hooks" fn storage_cache_bytes32(key: *const u8, value: *const u8) void;
pub extern "vm_hooks" fn block_number() u64;
pub extern "vm_hooks" fn storage_flush_cache(clear: bool) void;

// Compile-time initialization
var Contract = blk: {
    break :blk erc20.ERC20.init();
};

// The main entrypoint to use for execution of the Stylus WASM program.
export fn user_entrypoint(len: usize) i32 {
    // Expects the input is a u16 encoded as little endian bytes.
    const input = utils.get_input(len) catch return 1;
    if (input.len < 4) {
        @panic("Incorect input length");
    }
    const selector: [4]u8 = input[0..4].*; // Cast slice to fixed array
    // utils.write_output(&selector);
    const data = input[4..];
    utils.method_router(selector, data, &Contract) catch return 1;

    // if (selector[0] == 0x01) {
    //     // const padded_key: []u8 = utils.left_pad(selector[1..4], 32) catch return 1;
    //     // const result = utils.read_storage(padded_key) catch return 1;
    //     // utils.write_output(result);
    //     _ = utils.get_msg_sender() catch return 1;
    // } else if (selector[0] == 0x02) {
    //     // const padded_key: []u8 = utils.left_pad(selector[1..4], 32) catch return 1;
    //     // utils.write_storage(padded_key, data) catch return 1;
    // } else {
    //     // const padded_key: []u8 = utils.left_pad(selector[1..4], 32) catch return 1;
    //     // input[0] = 0x99;
    //     // utils.write_output(padded_key);
    // }
    storage_flush_cache(false);
    return 0;
}
