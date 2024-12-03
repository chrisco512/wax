const std = @import("std");

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

pub fn totalSupply() u256 {
    // Todo logic
    return 1000000;
}

pub fn balanceOf(owner: []const u8) u256 {
    // Todo logic
    return 1000;
}

pub fn transfer(to: []const u8, value: u256) bool {
    // Todo logic
    return true;
}

pub fn transferFrom(from: []const u8, to: []const u8, value: u256) bool {
    // Todo logic
    return true;
}

pub fn approve(spender: []const u8, value: u256) bool {
    // Todo logic
    return true;
}

pub fn allowance(owner: []const u8, spender: []const u8) u256 {
    // Todo logic
    return 500;
}
