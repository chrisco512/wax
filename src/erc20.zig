const std = @import("std");
const utils = @import("utils.zig");

pub fn name() ![]const u8 {
    // Todo logic
    return "TokenName";
}

pub fn symbol() ![]const u8 {
    // Todo logic
    return "TKN";
}

pub fn decimals() u8 {
    // Todo logic
    return 18;
}

pub fn initate(total_supply: []u8) !void {
    var slot_array: [32]u8 = utils.SLOTS.TOTAL_SUPPLY;
    try utils.write_storage(&slot_array, total_supply);
}

pub fn totalSupply() ![]u8 {
    var slot_array: [32]u8 = utils.SLOTS.TOTAL_SUPPLY;
    const total_supply = try utils.read_storage(&slot_array);
    return total_supply;
}

// pub fn balanceOf(owner: []const u8) u256 {
//     // Todo logic
//     return 1000;
// }

// pub fn transfer(to: []const u8, value: u256) bool {
//     // Todo logic
//     return true;
// }

// pub fn transferFrom(from: []const u8, to: []const u8, value: u256) bool {
//     // Todo logic
//     return true;
// }

// pub fn approve(spender: []const u8, value: u256) bool {
//     // Todo logic
//     return true;
// }

// pub fn allowance(owner: []const u8, spender: []const u8) u256 {
//     // Todo logic
//     return 500;
// }
