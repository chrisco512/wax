const std = @import("std");
const utils = @import("utils.zig");
const ValueStorage = @import("value_storage.zig");
const U256Storage = ValueStorage.U256Storage;
const SolStorage = ValueStorage.SolStorage;

pub const ERC20 = struct {
    pub usingnamespace SolStorage(@This());

    // Define state here
    total_supply: U256Storage,

    // // Define functions here
    // pub fn name() ![]const u8 {
    //     // Todo logic
    //     return "TokenName";
    // }

    // pub fn symbol() ![]const u8 {
    //     // Todo logic
    //     return "TKN";
    // }

    // pub fn decimals() u8 {
    //     // Todo logic
    //     return 18;
    // }

    pub fn initiate(self: *@This(), total_supply: []u8) !void {
        const total_supply_u256 = try utils.bytesToU256(total_supply);
        try self.total_supply.set_value(total_supply_u256);
    }

    pub fn totalSupply(self: *@This()) ![]u8 {
        const value = try self.total_supply.get_value();

        return utils.u256ToBytes(value);
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

};
