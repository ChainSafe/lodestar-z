const std = @import("std");
const blst = @import("blst");
const AggregatePublicKey = blst.AggregatePublicKey;
const Allocator = std.mem.Allocator;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EffectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const SyncCommittee = types.altair.SyncCommittee.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PublicKey = types.primitive.BLSPubkey.Type;
const ForkSeq = @import("config").ForkSeq;
const intSqrt = @import("../utils/math.zig").intSqrt;

pub const getNextSyncCommitteeIndices = @import("./seed.zig").getNextSyncCommitteeIndices;

pub const SyncCommitteeInfo = struct {
    indices: [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex,
    sync_committee: SyncCommittee,
};

/// Consumer must deallocate the returned `SyncCommitteeInfo` struct
pub fn getNextSyncCommittee(
    comptime fork: ForkSeq,
    allocator: Allocator,
    state: *ForkBeaconState(fork),
    active_validator_indices: []const ValidatorIndex,
    effective_balance_increments: EffectiveBalanceIncrements,
    out: *SyncCommitteeInfo,
) !void {
    const indices = &out.indices;
    try getNextSyncCommitteeIndices(allocator, state, active_validator_indices, effective_balance_increments, indices);
    var validators_view = try state.validators();

    // Using the index2pubkey cache is slower because it needs the serialized pubkey.
    const pubkeys = &out.sync_committee.pubkeys;
    var pubkeys_uncompressed: [preset.SYNC_COMMITTEE_SIZE]blst.PublicKey = undefined;
    for (indices, 0..indices.len) |index, i| {
        var validator_view = try validators_view.get(index);
        var validator: types.phase0.Validator.Type = undefined;
        try validator_view.toValue(allocator, &validator);
        pubkeys[i] = validator.pubkey;
        pubkeys_uncompressed[i] = try blst.PublicKey.uncompress(&pubkeys[i]);
    }

    const aggregated_pk = try AggregatePublicKey.aggregate(&pubkeys_uncompressed, false);
    out.sync_committee.aggregate_pubkey = aggregated_pk.toPublicKey().compress();
}

pub fn computeSyncParticipantReward(total_active_balance_increments: u64) u64 {
    const total_active_balance = total_active_balance_increments * preset.EFFECTIVE_BALANCE_INCREMENT;
    const base_reward_per_increment = @divFloor((preset.EFFECTIVE_BALANCE_INCREMENT * preset.BASE_REWARD_FACTOR), intSqrt(total_active_balance));
    const total_base_rewards = base_reward_per_increment * total_active_balance_increments;
    const max_participant_rewards = @divFloor(@divFloor(total_base_rewards * c.SYNC_REWARD_WEIGHT, c.WEIGHT_DENOMINATOR), preset.SLOTS_PER_EPOCH);
    return @divFloor(max_participant_rewards, preset.SYNC_COMMITTEE_SIZE);
}

pub fn computeBaseRewardPerIncrement(total_active_stake_by_increment: u64) u64 {
    const total_active_stake_sqrt = intSqrt(total_active_stake_by_increment * preset.EFFECTIVE_BALANCE_INCREMENT);
    return @divFloor((preset.EFFECTIVE_BALANCE_INCREMENT * preset.BASE_REWARD_FACTOR), total_active_stake_sqrt);
}
