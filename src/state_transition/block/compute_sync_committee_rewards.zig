const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const AnyBeaconBlock = @import("fork_types").AnyBeaconBlock;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const SyncCommitteeReward = struct {
    validator_index: ValidatorIndex,
    reward: i64,
};

/// Calculate rewards for sync committee participants.
/// Returns rewards/penalties for each unique validator in the sync committee.
/// Validators can appear multiple times in the sync committee, so rewards are aggregated.
pub fn computeSyncCommitteeRewards(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    block: AnyBeaconBlock,
    validator_ids: []const ValidatorIndex,
) !std.ArrayList(SyncCommitteeReward) {
    const fork_seq = cached_state.state.forkSeq();
    if (fork_seq == .phase0) {
        return error.UnsupportedFork; // phase0 does not have sync committee
    }

    const epoch_cache = cached_state.getEpochCache();
    std.debug.assert(preset.SYNC_COMMITTEE_SIZE > 0);
    const sync_committee_indices = @as(*const [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex, @ptrCast(epoch_cache.current_sync_committee_indexed.get().getValidatorIndices()));
    const sync_participant_reward: i64 = @intCast(epoch_cache.sync_participant_reward);
    std.debug.assert(sync_participant_reward >= 0);

    const sync_aggregate = try block.beaconBlockBody().syncAggregate();
    const sync_committee_bits = sync_aggregate.sync_committee_bits;

    var reward_deltas = std.AutoHashMap(ValidatorIndex, i64).init(allocator);
    defer reward_deltas.deinit();

    for (0..preset.SYNC_COMMITTEE_SIZE) |i| {
        const validator_index = sync_committee_indices[i];
        const current_delta = reward_deltas.get(validator_index) orelse 0;

        if (sync_committee_bits.get(i) catch false) {
            // Positive rewards for participants
            try reward_deltas.put(validator_index, current_delta + sync_participant_reward);
        } else {
            // Negative rewards (penalties) for non-participants
            try reward_deltas.put(validator_index, current_delta - sync_participant_reward);
        }
    }

    var rewards = std.ArrayList(SyncCommitteeReward).init(allocator);
    errdefer rewards.deinit();

    var iter = reward_deltas.iterator();
    while (iter.next()) |entry| {
        try rewards.append(.{
            .validator_index = entry.key_ptr.*,
            .reward = entry.value_ptr.*,
        });
    }

    // Filter by validatorIds if provided
    if (validator_ids.len > 0) {
        var filters_set = std.AutoHashMap(ValidatorIndex, void).init(allocator);
        defer filters_set.deinit();

        for (validator_ids) |vid| {
            try filters_set.put(vid, {});
        }

        var filtered = std.ArrayList(SyncCommitteeReward).init(allocator);
        errdefer filtered.deinit();

        for (rewards.items) |reward| {
            if (filters_set.contains(reward.validator_index)) {
                try filtered.append(reward);
            }
        }

        rewards.deinit();
        return filtered;
    }

    return rewards;
}
