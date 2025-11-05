const std = @import("std");
const blst = @import("blst");
const AggregatePublicKey = blst.AggregatePublicKey;
const Allocator = std.mem.Allocator;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const EffiectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
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
    // TODO: switch to fixed-size array since preset.SYNC_COMMITTEE_SIZE is constant
    indices: std.ArrayList(ValidatorIndex),
    sync_committee: *SyncCommittee,

    pub fn deinit(self: *SyncCommitteeInfo, allocator: Allocator) void {
        allocator.destroy(self.sync_committee);
        self.indices.deinit();
    }
};

/// Consumer must deallocate the returned `SyncCommitteeInfo` struct
pub fn getNextSyncCommittee(allocator: Allocator, state: *const BeaconStateAllForks, active_validators_indices: []const ValidatorIndex, effective_balance_increment: EffiectiveBalanceIncrements, out: *SyncCommitteeInfo) !void {
    var indices = std.ArrayList(ValidatorIndex).init(allocator);
    try indices.resize(preset.SYNC_COMMITTEE_SIZE);
    try getNextSyncCommitteeIndices(allocator, state, active_validators_indices, effective_balance_increment, indices.items);

    // Using the index2pubkey cache is slower because it needs the serialized pubkey.
    var pubkeys: [preset.SYNC_COMMITTEE_SIZE]PublicKey = undefined;
    var blst_pubkeys: [preset.SYNC_COMMITTEE_SIZE]blst.PublicKey = undefined;
    for (indices.items, 0..) |index, i| {
        pubkeys[i] = state.validators().items[index].pubkey;
        blst_pubkeys[i] = try blst.PublicKey.uncompress(&pubkeys[i]);
    }

    const aggregated_pk = try AggregatePublicKey.aggregate(&blst_pubkeys, false);
    const sync_committee = try allocator.create(SyncCommittee);
    errdefer allocator.destroy(sync_committee);
    sync_committee.* = .{
        .pubkeys = pubkeys,
        .aggregate_pubkey = aggregated_pk.toPublicKey().compress(),
    };
    out.* = .{
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
