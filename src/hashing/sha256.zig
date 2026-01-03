const std = @import("std");
const hashtree = @import("hashtree");

fn hashComptime(out: [][32]u8, in: []const [32]u8) !void {
    if (in.len != 2 * out.len) {
        return error.InvalidInput;
    }
    for (0..in.len / 2) |i| {
        @setEvalBranchQuota(1_000_000);
        std.crypto.hash.sha2.Sha256.hash(
            @ptrCast(in[i * 2 .. i * 2 + 2]),
            &out[i],
            .{},
        );
    }
}

/// Hash a slice of 32-byte arrays into a slice of 32-byte outputs.
///
/// This function will error if `in.len != 2 * out.len`.
pub inline fn hash(out: [][32]u8, in: []const [32]u8) !void {
    if (@inComptime()) {
        try hashComptime(out, in);
    } else {
        try hashtree.hash(out, in);
    }
}

/// Hash a single pair of 32-byte arrays into a 32-byte output.
pub fn hashOne(out: *[32]u8, left: *const [32]u8, right: *const [32]u8) void {
    var in = [_][32]u8{ left.*, right.* };
    hash(@ptrCast(out), &in) catch unreachable;
}

test "hashOne works correctly" {
    const obj1: [32]u8 = [_]u8{1} ** 32;
    const obj2: [32]u8 = [_]u8{2} ** 32;
    var hash_result: [32]u8 = undefined;

    // Call the function and ensure it works without error
    hashOne(&hash_result, &obj1, &obj2);

    // Print the hash for manual inspection (optional)
    // std.debug.print("Hash value: {any}\n", .{hash_result});
    // std.debug.print("Hash hex: {s}\n", .{std.fmt.bytesToHex(hash_result, .lower)});
    // try std.testing.expect(mem.eql(u8, &hash_result, &expected_hash));
}

test hashOne {
    const in = [_][32]u8{[_]u8{1} ** 32} ** 4;
    var out: [2][32]u8 = undefined;
    try hash(&out, &in);
    // std.debug.print("@@@ out: {any}\n", .{out});
    var out2: [32]u8 = undefined;
    hashOne(&out2, &in[0], &in[2]);
    // std.debug.print("@@@ out2: {any}\n", .{out2});
    try std.testing.expectEqualSlices(u8, &out2, &out[0]);
    try std.testing.expectEqualSlices(u8, &out2, &out[1]);
}
