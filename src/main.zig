const std = @import("std");
const WasmAllocator = @import("WasmAllocator.zig");
const utils = @import("utils.zig");

// External imports provided to all WASM programs on Stylus. These functions
// can be use to read input arguments coming into the program and output arguments to callers.

pub extern "vm_hooks" fn storage_cache_bytes32(key: *const u8, value: *const u8) void;
pub extern "vm_hooks" fn block_number() u64;
pub extern "vm_hooks" fn storage_flush_cache(clear: bool) void;

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
    utils.method_router(selector, data) catch return 1;

    // if (selector[0] == 0x01) {
    //     const padded_key: []u8 = utils.leftPad(selector[1..4], 32) catch return 1;
    //     const result = utils.read_storage(padded_key) catch return 1;
    //     utils.write_output(result);
    // } else if (selector[0] == 0x02) {
    //     const padded_key: []u8 = utils.leftPad(selector[1..4], 32) catch return 1;
    //     utils.write_storage(padded_key, data) catch return 1;
    // } else {
    //     const padded_key: []u8 = utils.leftPad(selector[1..4], 32) catch return 1;
    //     input[0] = 0x99;
    //     utils.write_output(padded_key);
    // }

    return 0;
}

// Uses the sieve algorithm to compute the first N primes. We output these
// to a fixed-size array, with a size determined at compile time. To check
// whether or not a number is prime, just pass in the number and receive a boolean output.
fn sieve_of_erathosthenes(comptime limit: usize, nth: u16) bool {
    var prime = [_]bool{true} ** limit;
    prime[0] = false;
    prime[1] = false;
    var i: usize = 2;
    while (i * i < limit) : (i += 1) {
        if (prime[i]) {
            var j = i * i;
            while (j < limit) : (j += i)
                prime[j] = false;
        }
    }
    return prime[nth];
}
