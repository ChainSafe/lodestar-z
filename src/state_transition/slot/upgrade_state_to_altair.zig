const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const getNextSyncCommittee = @import("../utils/sync_committee.zig").getNextSyncCommittee;
const SyncCommitteeInfo = @import("../utils/sync_committee.zig").SyncCommitteeInfo;
const sumTargetUnslashedBalanceIncrements = @import("../utils/target_unslashed_balance.zig").sumTargetUnslashedBalanceIncrements;
const computePreviousEpoch = @import("../utils/epoch.zig").computePreviousEpoch;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const RootCache = @import("../cache/RootCache.zig");
const getAttestationParticipationStatus = @import("../block//process_attestation_altair.zig").getAttestationParticipationStatus;

pub fn upgradeStateToAltair(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    var state = cached_state.state;
    if (!state.isPhase0()) {
        // already altair
        return error.StateIsNotPhase0;
    }
    const phase0_state = state.phase0;
    defer {
        types.phase0.BeaconState.deinit(allocator, phase0_state);
        allocator.destroy(phase0_state);
    }
    _ = try state.upgradeUnsafe(allocator);
    state.forkPtr().* = .{
        .previous_version = phase0_state.fork.current_version,
        .current_version = cached_state.config.chain.ALTAIR_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    const validator_count = state.validators().items.len;
    const previous_epoch_participations = state.previousEpochParticipations();
    try previous_epoch_participations.resize(allocator, validator_count);
    @memset(previous_epoch_participations.items, 0);

    const current_epoch_participations = state.currentEpochParticipations();
    try state.currentEpochParticipations().resize(allocator, validator_count);
    @memset(current_epoch_participations.items, 0);

    const inactivity_scores = state.inactivityScores();
    try inactivity_scores.resize(allocator, validator_count);
    @memset(inactivity_scores.items, 0);

    const epoch_cache = cached_state.getEpochCache();
    const active_indices = epoch_cache.next_shuffling.get().active_indices;
    var sync_committee_info: SyncCommitteeInfo = undefined;
    try getNextSyncCommittee(allocator, state, active_indices, epoch_cache.getEffectiveBalanceIncrements(), &sync_committee_info);
    defer sync_committee_info.deinit(allocator);
    state.currentSyncCommittee().* = sync_committee_info.sync_committee.*;
    state.nextSyncCommittee().* = sync_committee_info.sync_committee.*;

    try cached_state.epoch_cache_ref.get().setSyncCommitteesIndexed(sync_committee_info.indices.items);
    try translateParticipation(allocator, cached_state, phase0_state.previous_epoch_attestations);

    const previous_epoch = computePreviousEpoch(epoch_cache.epoch);
    epoch_cache.previous_target_unslashed_balance_increments = sumTargetUnslashedBalanceIncrements(state.previousEpochParticipations().items, previous_epoch, state.validators().items);
}

/// Translate_participation in https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/fork.md
fn translateParticipation(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, pending_attestations: types.phase0.EpochAttestations.Type) !void {
    const epoch_cache = cached_state.getEpochCache();
    const root_cache = try RootCache.init(allocator, cached_state);
    defer root_cache.deinit();
    const state = cached_state.state;
    const epoch_participation = state.previousEpochParticipations();
    try epoch_participation.resize(allocator, state.validators().items.len);
    @memset(epoch_participation.items, 0);

    for (pending_attestations.items) |*attestation| {
        const data = attestation.data;
        const attestation_flag = try getAttestationParticipationStatus(cached_state.state, data, attestation.inclusion_delay, epoch_cache.epoch, root_cache);
        const committee_indices = try epoch_cache.getBeaconCommittee(data.slot, data.index);
        const attesting_indices = try attestation.aggregation_bits.intersectValues(ValidatorIndex, allocator, committee_indices);
        defer attesting_indices.deinit();
        for (attesting_indices.items) |validator_index| {
            epoch_participation.items[validator_index] |= attestation_flag;
        }
    }
}
