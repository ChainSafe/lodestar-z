const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const getNextSyncCommittee = @import("../utils/sync_committee.zig").getNextSyncCommittee;
const SyncCommitteeInfo = @import("../utils/sync_committee.zig").SyncCommitteeInfo;
const sumTargetUnslashedBalanceIncrements = @import("../utils/target_unslashed_balance.zig").sumTargetUnslashedBalanceIncrements;
const computePreviousEpoch = @import("../utils/epoch.zig").computePreviousEpoch;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const RootCache = @import("../utils/root_cache.zig").RootCache;
const getAttestationParticipationStatus = @import("../block//process_attestation_altair.zig").getAttestationParticipationStatus;

pub fn upgradeStateToAltair(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var phase0_state = cached_state.state;
    if (phase0_state.forkSeq() != .phase0) {
        // already altair
        return error.StateIsNotPhase0;
    }
    var altair_state = try phase0_state.upgradeUnsafe();
    errdefer altair_state.deinit();

    const new_fork: types.altair.Fork.Type = .{
        .previous_version = try phase0_state.forkCurrentVersion(),
        .current_version = cached_state.config.chain.ALTAIR_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    try altair_state.setFork(&new_fork);

    const validator_count = try altair_state.validatorsCount();
    var previous_epoch_participations = try altair_state.previousEpochParticipation();
    try previous_epoch_participations.setLength(validator_count);

    var current_epoch_participations = try altair_state.currentEpochParticipation();
    try current_epoch_participations.setLength(validator_count);

    var inactivity_scores = try altair_state.inactivityScores();
    try inactivity_scores.setLength(validator_count);

    const epoch_cache = cached_state.getEpochCache();
    const active_indices = epoch_cache.next_shuffling.get().active_indices;

    var sync_committee_info: SyncCommitteeInfo = undefined;
    try getNextSyncCommittee(allocator, &altair_state, active_indices, epoch_cache.getEffectiveBalanceIncrements(), &sync_committee_info);

    try altair_state.setCurrentSyncCommittee(&sync_committee_info.sync_committee);
    try altair_state.setNextSyncCommittee(&sync_committee_info.sync_committee);

    try cached_state.epoch_cache_ref.get().setSyncCommitteesIndexed(&sync_committee_info.indices);

    var previous_epoch_participation = try translateParticipation(allocator, cached_state, try phase0_state.previousEpochPendingAttestations());
    defer previous_epoch_participation.deinit(allocator);
    try altair_state.setPreviousEpochParticipation(&previous_epoch_participation);

    var current_epoch_participation = try translateParticipation(allocator, cached_state, try phase0_state.currentEpochPendingAttestations());
    defer current_epoch_participation.deinit(allocator);
    try altair_state.setCurrentEpochParticipation(&current_epoch_participation);

    const previous_epoch = computePreviousEpoch(epoch_cache.epoch);
    try altair_state.commit();
    const validators = try altair_state.validatorsSlice(allocator);
    defer allocator.free(validators);
    epoch_cache.previous_target_unslashed_balance_increments = sumTargetUnslashedBalanceIncrements(previous_epoch_participation.items, previous_epoch, validators);
    epoch_cache.current_target_unslashed_balance_increments = sumTargetUnslashedBalanceIncrements(current_epoch_participation.items, epoch_cache.epoch, validators);

    phase0_state.deinit();
    cached_state.state.* = altair_state;
}

/// Translate_participation in https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/fork.md
/// Caller must free returned value
fn translateParticipation(allocator: Allocator, cached_state: *CachedBeaconState, pending_attestations_tree: types.phase0.EpochAttestations.TreeView) !types.altair.EpochParticipation.Type {
    const epoch_cache = cached_state.getEpochCache();
    const root_cache = try RootCache.init(allocator, cached_state);
    defer root_cache.deinit();

    const pending_attestations = try @constCast(&pending_attestations_tree).getAllReadonlyValues(allocator);
    defer {
        for (pending_attestations) |*attestation| {
            types.phase0.PendingAttestation.deinit(allocator, attestation);
        }
        allocator.free(pending_attestations);
    }

    // translate all participations into a flat array, then convert to tree view the end
    var epoch_participation = types.altair.EpochParticipation.default_value;
    const validator_count = try cached_state.state.validatorsCount();
    try epoch_participation.resize(allocator, validator_count);
    @memset(epoch_participation.items, 0);

    for (pending_attestations) |*attestation| {
        const data = &attestation.data;
        const attestation_flag = try getAttestationParticipationStatus(cached_state.state, data, attestation.inclusion_delay, epoch_cache.epoch, root_cache);
        const committee_indices = try epoch_cache.getBeaconCommittee(data.slot, data.index);
        const attesting_indices = try attestation.aggregation_bits.intersectValues(ValidatorIndex, allocator, committee_indices);
        defer attesting_indices.deinit();
        for (attesting_indices.items) |validator_index| {
            epoch_participation.items[validator_index] |= attestation_flag;
        }
    }

    return epoch_participation;
}
