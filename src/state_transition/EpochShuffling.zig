//! EpochCache is the only consumer of this cache but an instance of EpochShuffling is shared across EpochCache instances
//! no EpochCache instance takes the ownership of shuffling
//! instead of that, we count on reference counting to deallocate the memory, see ReferenceCount() utility
const EpochShuffling = @This();

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const getSeed = @import("./utils/seed.zig").getSeed;
const c = @import("constants");
const Epoch = types.primitive.Epoch.Type;
const ReferenceCount = @import("./utils/reference_count.zig").ReferenceCount;

pub const Rc = ReferenceCount(*EpochShuffling);

const Committee = []const ValidatorIndex;
const SlotCommittees = []const Committee;
const EpochCommittees = [preset.SLOTS_PER_EPOCH]SlotCommittees;

// Shuffling constants
pub const SEED_SIZE = 32;
const ROUND_SIZE = 1;
const POSITION_WINDOW_SIZE = 4;
const PIVOT_VIEW_SIZE = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

allocator: Allocator,
epoch: Epoch,
// EpochShuffling takes ownership of all properties below
active_indices: []const ValidatorIndex,
shuffling: []const ValidatorIndex,
/// the internal last-level committee shared the same data with `shuffling` so don't need to free it
committees: EpochCommittees,
committees_per_slot: usize,

pub fn init(allocator: Allocator, seed: [32]u8, epoch: Epoch, active_indices: []const ValidatorIndex) !*EpochShuffling {
    const shuffling = try allocator.alloc(ValidatorIndex, active_indices.len);
    errdefer allocator.free(shuffling);
    std.mem.copyForwards(ValidatorIndex, shuffling, active_indices);
    try unshuffleList(shuffling, seed[0..], preset.SHUFFLE_ROUND_COUNT);
    const committees = try buildCommitteesFromShuffling(allocator, shuffling);

    const epoch_shuffling_ptr = try allocator.create(EpochShuffling);
    errdefer allocator.destroy(epoch_shuffling_ptr);
    epoch_shuffling_ptr.* = EpochShuffling{
        .allocator = allocator,
        .epoch = epoch,
        .active_indices = active_indices,
        .shuffling = shuffling,
        .committees = committees,
        .committees_per_slot = computeCommitteeCount(active_indices.len),
    };

    return epoch_shuffling_ptr;
}

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

    if (seed.len != SEED_SIZE) {
        return error.InvalidSeedLen;
    }

    // ensure length of array fits in u32 or will panic)
    if (list_size > std.math.maxInt(u32)) {
        return error.InvalidListSize;
    }

    // refer to https://github.com/ChainSafe/swap-or-not-shuffle/blob/64278ba174de65e70aa8d77a17f2c453d8e2d464/src/lib.rs#L51
    const ShufflingManager = struct {
        const ShufflingManager = @This();

        buf: [TOTAL_SIZE]u8,

        /// Set the shuffling round.
        pub fn setRound(self: *ShufflingManager, round: u8) void {
            self.buf[SEED_SIZE] = round;
        }

        /// Returns the new pivot. It is "raw" because it has not modulo the list size (this must be
        /// done by the caller).
        pub fn rawPivot(self: *ShufflingManager) u64 {
            var digest = [_]u8{0} ** 32;
            Sha256.hash(self.buf[0..PIVOT_VIEW_SIZE], digest[0..], .{});
            const slice = std.mem.bytesAsSlice(u64, digest[0..8]);
            const value = slice[0];
            return if (native_endian == .big) @byteSwap(value) else value;
        }

        /// Add the current position into the buffer.
        pub fn mixInPosition(self: *ShufflingManager, position: usize) void {
            self.buf[PIVOT_VIEW_SIZE + 0] = @intCast((position >> 0) & 0xff);
            self.buf[PIVOT_VIEW_SIZE + 1] = @intCast((position >> 8) & 0xff);
            self.buf[PIVOT_VIEW_SIZE + 2] = @intCast((position >> 16) & 0xff);
            self.buf[PIVOT_VIEW_SIZE + 3] = @intCast((position >> 24) & 0xff);
        }

        /// Hash the entire buffer.
        pub fn hash(self: *const ShufflingManager) [32]u8 {
            var digest = [_]u8{0} ** 32;
            Sha256.hash(self.buf[0..TOTAL_SIZE], digest[0..], .{});
            return digest;
        }
    };

    var buf = [_]u8{0} ** TOTAL_SIZE;
    @memcpy(buf[0..SEED_SIZE], seed);
    var manager = ShufflingManager{ .buf = buf };
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

pub fn deinit(self: *EpochShuffling) void {
    for (self.committees) |committees_per_slot| {
        // no need to free each committee since they are slices of `shuffling`
        self.allocator.free(committees_per_slot);
    }
    self.allocator.free(self.active_indices);
    self.allocator.free(self.shuffling);
    // no need to free `commitees` because it's stack allocation
    self.allocator.destroy(self);
}

fn buildCommitteesFromShuffling(allocator: Allocator, shuffling: []const ValidatorIndex) !EpochCommittees {
    const active_validator_count = shuffling.len;
    const committees_per_slot = computeCommitteeCount(active_validator_count);
    const committee_count = committees_per_slot * preset.SLOTS_PER_EPOCH;

    var epoch_committees: [preset.SLOTS_PER_EPOCH]SlotCommittees = undefined;
    for (0..preset.SLOTS_PER_EPOCH) |slot| {
        const slot_committees = try allocator.alloc(Committee, committees_per_slot);
        for (0..committees_per_slot) |committee_index| {
            const index = slot * committees_per_slot + committee_index;
            const start_offset = @divFloor(active_validator_count * index, committee_count);
            const end_offset = @divFloor(active_validator_count * (index + 1), committee_count);
            slot_committees[committee_index] = shuffling[start_offset..end_offset];
        }
        epoch_committees[slot] = slot_committees;
    }

    return epoch_committees;
}

/// unshuffle the `active_indices` array in place synchronously
fn unshuffleList(active_indices_to_shuffle: []ValidatorIndex, seed: []const u8, rounds: u8) !void {
    const forwards = false;
    return innerShuffleList(ValidatorIndex, active_indices_to_shuffle, seed, rounds, forwards);
}

fn computeCommitteeCount(active_validator_count: usize) usize {
    const validators_per_slot = @divFloor(active_validator_count, preset.SLOTS_PER_EPOCH);
    const committees_per_slot = @divFloor(validators_per_slot, preset.TARGET_COMMITTEE_SIZE);
    return @max(1, @min(preset.MAX_COMMITTEES_PER_SLOT, committees_per_slot));
}

test EpochShuffling {
    const validator_count_arr = comptime [_]usize{ 256, 2_000_000 };
    inline for (validator_count_arr) |validator_count| {
        const allocator = std.testing.allocator;
        const seed: [32]u8 = [_]u8{0} ** 32;
        const active_indices = try allocator.alloc(ValidatorIndex, validator_count);
        // active_indices is transferred to EpochShuffling so no need to free it here
        for (0..validator_count) |i| {
            active_indices[i] = @intCast(i);
        }

        var epoch_shuffling = try EpochShuffling.init(allocator, seed, 0, active_indices);
        defer epoch_shuffling.deinit();
    }
}

test innerShuffleList {
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

test unshuffleList {
    var active_indices: [5]ValidatorIndex = .{ 0, 1, 2, 3, 4 };
    const seed: [32]u8 = [_]u8{0} ** 32;

    try unshuffleList(&active_indices, &seed, 32);
}

test computeCommitteeCount {
    const committee_count = computeCommitteeCount(2_000_000);
    try std.testing.expectEqual(64, committee_count);
}
