const std = @import("std");
const bls = @import("bls");

pub const generated_input_len_max = 32;
pub const generated_key_count_max = 4;

pub fn secretKey(scalar: u64) bls.SecretKey {
    std.debug.assert(scalar > 0);
    std.debug.assert(scalar <= @as(u64, generated_key_count_max) << 32);
    var encoded: [32]u8 = @splat(0);
    std.mem.writeInt(u64, encoded[24..32], scalar, .big);
    return bls.SecretKey.deserialize(&encoded) catch @panic("small nonzero scalar rejected");
}
