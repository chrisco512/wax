const std = @import("std");

// Address type and utility functions
pub const Address = std.meta.Int(.unsigned, 160);

pub fn addressFromBytes(data: []const u8) !Address {
    if (data.len < 20) return error.InvalidAddressLength;
    var bytes: [32]u8 = undefined;
    @memset(bytes[0..12], 0);
    @memcpy(bytes[12..32], data[0..20]);
    return @truncate(std.mem.readInt(u256, &bytes, .big));
}

pub fn addressToBytes(addr: Address) [20]u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, addr, .big);
    var result: [20]u8 = undefined;
    @memcpy(&result, bytes[12..32]);
    return result;
}
