const std = @import("std");

const Depth = @import("depth.zig").Depth;
const max_depth_ = @import("depth.zig").max_depth;

/// This non-extern implementation is required to compute the zero hashes at comptime.
fn hashOne(out: *[32]u8, obj1: *const [32]u8, obj2: *const [32]u8) void {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(obj1);
    h.update(obj2);
    h.final(out);
}

pub fn ZeroHash(max_depth: u8) type {
    comptime {
        if (max_depth == 0) {
            @compileError("max_depth must be non-zero");
        }
    }

    return struct {
        hashes: [max_depth][32]u8,

        pub fn init() @This() {
            // It seems that the default sha2 implementation does a lot of comptime execution
            @setEvalBranchQuota(@as(usize, max_depth) * 10000);

            var zh: @This() = undefined;
            for (0..max_depth) |i| {
                if (i == 0) {
                    zh.hashes[i] = [_]u8{0} ** 32;
                } else {
                    hashOne(
                        &zh.hashes[i],
                        &(zh.hashes[i - 1]),
                        &(zh.hashes[i - 1]),
                    );
                }
            }
            return zh;
        }

        pub fn get(self: *const @This(), depth: u8) !*const [32]u8 {
            if (depth >= max_depth) {
                return error.OutOfBounds;
            }

            return &self.hashes[depth];
        }
    };
}

pub const zero_hash = ZeroHash(max_depth_).init();

pub fn getZeroHash(depth: Depth) *const [32]u8 {
    return zero_hash.get(depth) catch unreachable;
}

test "ZeroHash" {
    const hash = try zero_hash.get(1);
    const expected_hash = [_]u8{
        245, 165, 253, 66,  209, 106, 32,  48,
        39,  152, 239, 110, 211, 9,   151, 155,
        67,  0,   61,  35,  32,  217, 240, 232,
        234, 152, 49,  169, 39,  89,  251, 75,
    };
    try std.testing.expectEqualSlices(u8, &hash.*, &expected_hash);
    // std.debug.print("Hash value: {any}\n", .{hash});
}
