const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const getSeed = @import("./seed.zig").getSeed;
const c = @import("constants");
const innerShuffleList = @import("./shuffle.zig").innerShuffleList;
const Epoch = types.primitive.Epoch.Type;
const ReferenceCount = @import("./reference_count.zig").ReferenceCount;

pub const EpochShufflingRc = ReferenceCount(*EpochShuffling);

const Committee = []const ValidatorIndex;
const SlotCommittees = []const Committee;
const EpochCommittees = [preset.SLOTS_PER_EPOCH]SlotCommittees;

/// EpochCache is the only consumer of this cache but an instance of EpochShuffling is shared across EpochCache instances
/// no EpochCache instance takes the ownership of shuffling
/// instead of that, we count on reference counting to deallocate the memory, see ReferenceCount() utility
pub const EpochShuffling = struct {
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
};

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

/// active_indices is allocated at consumer side and transfer ownership to EpochShuffling
pub fn computeEpochShuffling(allocator: Allocator, state: *const BeaconStateAllForks, active_indices: []ValidatorIndex, epoch: Epoch) !*EpochShuffling {
    var seed = [_]u8{0} ** 32;
    try getSeed(state, epoch, c.DOMAIN_BEACON_ATTESTER, &seed);
    return EpochShuffling.init(allocator, seed, epoch, active_indices);
}

/// unshuffle the `active_indices` array in place synchronously
fn unshuffleList(active_indices_to_shuffle: []ValidatorIndex, seed: []const u8, rounds: u8) !void {
    const forwards = false;
    return innerShuffleList(ValidatorIndex, active_indices_to_shuffle, seed, rounds, forwards);
}

test unshuffleList {
    var active_indices: [5]ValidatorIndex = .{ 0, 1, 2, 3, 4 };
    const seed: [32]u8 = [_]u8{0} ** 32;

    try unshuffleList(&active_indices, &seed, 32);
}

fn computeCommitteeCount(active_validator_count: usize) usize {
    const validators_per_slot = @divFloor(active_validator_count, preset.SLOTS_PER_EPOCH);
    const committees_per_slot = @divFloor(validators_per_slot, preset.TARGET_COMMITTEE_SIZE);
    return @max(1, @min(preset.MAX_COMMITTEES_PER_SLOT, committees_per_slot));
}

test computeCommitteeCount {
    const committee_count = computeCommitteeCount(2_000_000);
    try std.testing.expectEqual(64, committee_count);
}
