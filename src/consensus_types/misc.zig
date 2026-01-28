const std = @import("std");
const ssz = @import("ssz");

pub const Numbers = ssz.FixedListType(ssz.UintType(64), std.math.maxInt(u32));
pub const Roots = ssz.FixedListType(ssz.ByteVectorType(32), std.math.maxInt(u32));
