const std = @import("std");
const blst = @import("blst");
const BlstPublicKey = blst.PublicKey;
const AggregatePublicKey = blst.AggregatePublicKey;
const Allocator = std.mem.Allocator;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const EffiectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const SyncCommittee = ssz.altair.SyncCommittee.Type;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const PublicKey = ssz.primitive.BLSPubkey.Type;
const ForkSeq = @import("config").ForkSeq;
const intSqrt = @import("../utils/math.zig").intSqrt;

pub const getNextSyncCommitteeIndices = @import("./seed.zig").getNextSyncCommitteeIndices;
const SyncCommitteeInfo = struct {
    indices: std.ArrayList(ValidatorIndex),
    sync_committee: *SyncCommittee,
};

/// Consumer must deallocate the returned `SyncCommitteeInfo` struct
/// TODO: remove if not used
pub fn getNextSyncCommittee(allocator: Allocator, state: *const BeaconStateAllForks, active_validators_indices: std.ArrayList(ValidatorIndex), effective_balance_increment: EffiectiveBalanceIncrements) !*SyncCommitteeInfo {
    const indices = std.ArrayList(ValidatorIndex).init(allocator).resize(preset.SYNC_COMMITTEE_SIZE);
    try getNextSyncCommitteeIndices(allocator, state, active_validators_indices, effective_balance_increment, indices.items);

    // Using the index2pubkey cache is slower because it needs the serialized pubkey.
    var pubkeys: [preset.SYNC_COMMITTEE_SIZE]PublicKey = undefined;
    for (indices, 0..) |index, i| {
        pubkeys[i] = state.validators()[index].pubkey;
    }

    const aggregated_pk = try AggregatePublicKey.aggregateSerialized(pubkeys[0..], false);
    const sync_committee = try allocator.create(SyncCommittee);
    errdefer allocator.destroy(sync_committee);
    sync_committee.* = .{
        .pubkeys = pubkeys,
        .aggregate_pubkey = aggregated_pk,
    };
    return .{
        .indices = indices,
        .sync_committee = sync_committee,
    };
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
