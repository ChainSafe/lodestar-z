const std = @import("std");
const ct = @import("consensus_types");
const digest = @import("./sha256.zig").digest;
const Root = ct.primitive.Root.Type;

pub fn verifyMerkleBranch(leaf: Root, proof: *const [33]Root, depth: usize, index: usize, root: Root) bool {
    var value = leaf;
    var tmp: [64]u8 = undefined;
    for (0..depth) |i| {
        if (@divFloor(index, std.math.powi(usize, 2, i) catch unreachable) % 2 != 0) {
            @memcpy(tmp[0..32], &proof[i]);
            @memcpy(tmp[32..], &value);
        } else {
            @memcpy(tmp[0..32], &value);
            @memcpy(tmp[32..], &proof[i]);
        }
        digest(&tmp, &value);
    }
    return std.mem.eql(u8, &root, &value);
}

// TODO: unit tests
