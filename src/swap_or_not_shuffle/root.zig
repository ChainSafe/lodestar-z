const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

pub const SEED_SIZE = 32;
const ROUND_SIZE = 1;
const POSITION_WINDOW_SIZE = 4;
const PIVOT_VIEW_SIZE = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

/// refer to https://github.com/ChainSafe/swap-or-not-shuffle/blob/64278ba174de65e70aa8d77a17f2c453d8e2d464/src/lib.rs#L51
const ShufflingManager = struct {
    buf: [TOTAL_SIZE]u8,

    pub fn init(seed: []const u8) !ShufflingManager {
        if (seed.len != SEED_SIZE) {
            return error.InvalidSeedLen;
        }
        var buf = [_]u8{0} ** TOTAL_SIZE;
        @memcpy(buf[0..SEED_SIZE], seed);
        return ShufflingManager{ .buf = buf };
    }

    /// Set the shuffling round.
    pub fn setRound(self: *@This(), round: u8) void {
        self.buf[SEED_SIZE] = round;
    }

    /// Returns the new pivot. It is "raw" because it has not modulo the list size (this must be
    /// done by the caller).
    pub fn rawPivot(self: *@This()) u64 {
        var digest = [_]u8{0} ** 32;
        Sha256.hash(self.buf[0..PIVOT_VIEW_SIZE], digest[0..], .{});
        const slice = std.mem.bytesAsSlice(u64, digest[0..8]);
        const value = slice[0];
        return if (native_endian == .big) @byteSwap(value) else value;
    }

    /// Add the current position into the buffer.
    pub fn mixInPosition(self: *@This(), position: usize) void {
        self.buf[PIVOT_VIEW_SIZE + 0] = @intCast((position >> 0) & 0xff);
        self.buf[PIVOT_VIEW_SIZE + 1] = @intCast((position >> 8) & 0xff);
        self.buf[PIVOT_VIEW_SIZE + 2] = @intCast((position >> 16) & 0xff);
        self.buf[PIVOT_VIEW_SIZE + 3] = @intCast((position >> 24) & 0xff);
    }

    /// Hash the entire buffer.
    pub fn hash(self: *const @This()) [32]u8 {
        var digest = [_]u8{0} ** 32;
        Sha256.hash(self.buf[0..TOTAL_SIZE], digest[0..], .{});
        return digest;
    }
};

/// Shuffles an entire list in-place.
///
/// Note: this is equivalent to the `compute_shuffled_index` function, except it shuffles an entire
/// list not just a single index. With large lists this function has been observed to be 250x
/// faster than running `compute_shuffled_index` across an entire list.
///
/// Credits to [@protolambda](https://github.com/protolambda) for defining this algorithm.
///
/// Shuffles if `forwards == true`, otherwise un-shuffles.
/// It holds that: shuffle_list(shuffle_list(l, r, s, true), r, s, false) == l
///           and: shuffle_list(shuffle_list(l, r, s, false), r, s, true) == l
///
/// The Eth2.0 spec mostly uses shuffling with `forwards == false`, because backwards
/// shuffled lists are slightly easier to specify, and slightly easier to compute.
///
/// The forwards shuffling of a list is equivalent to:
///
/// `[indices[x] for i in 0..n, where compute_shuffled_index(x) = i]`
///
/// Whereas the backwards shuffling of a list is:
///
/// `[indices[compute_shuffled_index(i)] for i in 0..n]`
///
/// Returns `None` under any of the following conditions:
///  - `list_size == 0`
///  - `list_size > 2**24`
///  - `list_size > usize::MAX / 2`
/// T should be u32 for Bun binding and ValidatorIndex/u64 for zig application
pub fn innerShuffleList(comptime T: type, out: []T, seed: []const u8, rounds: u8, forwards: bool) !void {
    if (rounds == 0) {
        // no shuffling rounds
        return;
    }

    const list_size = out.len;

    if (list_size <= 1) {
        // nothing to (un)shuffle
        return;
    }

    // ensure length of array fits in u32 or will panic)
    if (list_size > 0xffff_ffff) {
        return error.InvalidListSize;
    }

    var manager = try ShufflingManager.init(seed);
    var current_round = if (forwards) 0 else rounds - 1;

    while (true) {
        manager.setRound(current_round);

        // get raw pivot and modulo by list size to account for wrap around to guarantee pivot is within length
        const pivot = manager.rawPivot() % list_size;

        // cut range in half
        var mirror = (pivot + 1) >> 1;

        manager.mixInPosition(pivot >> 8);
        var source = manager.hash();
        var byte_v = source[(pivot & 0xff) >> 3];

        // swap-or-not from beginning of list to mirror point
        for (0..mirror) |i| {
            const j = pivot - i;

            if (j & 0xff == 0xff) {
                manager.mixInPosition(j >> 8);
                source = manager.hash();
            }

            const least_significant_bit_j: u3 = @intCast(j & 0x07);
            if (least_significant_bit_j == 0x07) {
                byte_v = source[(j & 0xff) >> 3];
            }
            const bit_v = (byte_v >> least_significant_bit_j) & 0x01;

            if (bit_v == 1) {
                // swap
                const tmp = out[i];
                out[i] = out[j];
                out[j] = tmp;
            }
        }

        // reset mirror to middle of opposing section of pivot
        mirror = (pivot + list_size + 1) >> 1;
        const end = list_size - 1;

        manager.mixInPosition(end >> 8);
        source = manager.hash();
        byte_v = source[(end & 0xff) >> 3];

        // swap-or-not from pivot to mirror
        for ((pivot + 1)..mirror, 0..) |i, loop_iter| {
            const j = end - loop_iter;

            if (j & 0xff == 0xff) {
                manager.mixInPosition(j >> 8);
                source = manager.hash();
            }

            const least_significant_bit_j: u3 = @intCast(j & 0x07);
            if (least_significant_bit_j == 0x07) {
                byte_v = source[(j & 0xff) >> 3];
            }
            const bit_v = (byte_v >> least_significant_bit_j) & 0x01;

            if (bit_v == 1) {
                // swap
                const tmp = out[i];
                out[i] = out[j];
                out[j] = tmp;
            }
        }

        // update currentRound and stop when reach end of predetermined rounds
        if (forwards) {
            current_round += 1;
            if (current_round >= rounds) {
                break;
            }
        } else {
            if (current_round == 0) {
                break;
            }
            current_round -= 1;
        }
    }
}

test "innerShuffleList" {
    var input = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    const seed = [_]u8{0} ** SEED_SIZE;
    const rounds = 32;
    // unshuffle
    const forwards = false;

    const shuffled_input = input[0..];
    try innerShuffleList(u32, shuffled_input, seed[0..], rounds, forwards);

    // Check that the input is shuffled
    try std.testing.expect(shuffled_input.len == input.len);
    // result is checked against @chainsafe/swap-or-not-shuffle
    const expected = [_]u32{ 6, 2, 3, 5, 1, 7, 8, 0, 4 };
    try std.testing.expectEqualSlices(u32, expected[0..], shuffled_input);

    // shuffle back
    const backwards = true;
    try innerShuffleList(u32, shuffled_input, seed[0..], rounds, backwards);

    // Check that the input is back to original
    const expected_input = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectEqualSlices(u32, expected_input[0..], shuffled_input);
}
