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
    const selector = input[0..4];
    const target = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    // const r = &target;
    const matches = std.mem.eql(u8, selector, &target);
    // if selector
    if (matches) {
        // const out = [4]u8{ 0x34, 0x34, 0x56, 0x78 };
        selector[0] = 0x56;
        const slot = [1]u8{0x34};
        const slot_1 = slot[0..];
        storage_cache_bytes32(@ptrCast(slot_1), @ptrCast(selector));
        // const out_data = out[0..4];
        const out = block_number();
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, out, .little);
        storage_flush_cache(true);
        utils.write_output(&bytes);
    } else {
        utils.write_output(selector);
    }

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
