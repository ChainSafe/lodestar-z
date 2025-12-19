const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const metrics = @import("../metrics.zig");
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const processJustificationAndFinalization = @import("./process_justification_and_finalization.zig").processJustificationAndFinalization;
const processInactivityUpdates = @import("./process_inactivity_updates.zig").processInactivityUpdates;
const processRegistryUpdates = @import("./process_registry_updates.zig").processRegistryUpdates;
const processSlashings = @import("./process_slashings.zig").processSlashings;
const processRewardsAndPenalties = @import("./process_rewards_and_penalties.zig").processRewardsAndPenalties;
const processEth1DataReset = @import("./process_eth1_data_reset.zig").processEth1DataReset;
const processPendingDeposits = @import("./process_pending_deposits.zig").processPendingDeposits;
const processPendingConsolidations = @import("./process_pending_consolidations.zig").processPendingConsolidations;
const processEffectiveBalanceUpdates = @import("./process_effective_balance_updates.zig").processEffectiveBalanceUpdates;
const processSlashingsReset = @import("./process_slashings_reset.zig").processSlashingsReset;
const processRandaoMixesReset = @import("./process_randao_mixes_reset.zig").processRandaoMixesReset;
const processHistoricalSummariesUpdate = @import("./process_historical_summaries_update.zig").processHistoricalSummariesUpdate;
const processHistoricalRootsUpdate = @import("./process_historical_roots_update.zig").processHistoricalRootsUpdate;
const processParticipationRecordUpdates = @import("./process_participation_record_updates.zig").processParticipationRecordUpdates;
const processParticipationFlagUpdates = @import("./process_participation_flag_updates.zig").processParticipationFlagUpdates;
const processSyncCommitteeUpdates = @import("./process_sync_committee_updates.zig").processSyncCommitteeUpdates;
const processProposerLookahead = @import("./process_proposer_lookahead.zig").processProposerLookahead;

pub fn processEpoch(allocator: std.mem.Allocator, cached_state: *CachedBeaconState, cache: *EpochTransitionCache) !void {
    const state = cached_state.state;

    var timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_justification_and_finalization });
    try processJustificationAndFinalization(cached_state, cache);
    _ = try timer.stopAndObserve();

    if (state.forkSeq().gte(.altair)) {
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_inactivity_updates });
        try processInactivityUpdates(cached_state, cache);
        _ = try timer.stopAndObserve();
    }

    timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_registry_updates });
    try processRegistryUpdates(cached_state, cache);
    _ = try timer.stopAndObserve();

    // TODO(bing): In lodestar-ts we accumulate slashing penalties and only update in processRewardsAndPenalties. Do the same?
    timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_slashings });
    try processSlashings(allocator, cached_state, cache);
    _ = try timer.stopAndObserve();

    timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_rewards_and_penalties });
    try processRewardsAndPenalties(allocator, cached_state, cache);

    try processEth1DataReset(cached_state, cache);

    if (state.forkSeq().gte(.electra)) {
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_pending_deposits });
        try processPendingDeposits(allocator, cached_state, cache);
        _ = try timer.stopAndObserve();
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_pending_consolidations });
        try processPendingConsolidations(cached_state, cache);
        _ = try timer.stopAndObserve();
    }

    // const numUpdate = processEffectiveBalanceUpdates(fork, state, cache);
    timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_effective_balance_updates });
    _ = try processEffectiveBalanceUpdates(allocator, cached_state, cache);
    _ = try timer.stopAndObserve();

    try processSlashingsReset(cached_state, cache);
    try processRandaoMixesReset(cached_state, cache);

    if (state.forkSeq().gte(.capella)) {
        try processHistoricalSummariesUpdate(cached_state, cache);
    } else {
        try processHistoricalRootsUpdate(cached_state, cache);
    }

    if (state.forkSeq() == .phase0) {
        try processParticipationRecordUpdates(cached_state);
    } else {
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_participation_flag_updates });
        try processParticipationFlagUpdates(cached_state);
        _ = try timer.stopAndObserve();
    }

    if (state.forkSeq().gte(.altair)) {
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_sync_committee_updates });
        try processSyncCommitteeUpdates(allocator, cached_state);
        _ = try timer.stopAndObserve();
    }

    if (state.forkSeq().gte(.fulu)) {
        timer = metrics.epoch_transition_step.startTimer(.{ .step = .process_proposer_lookahead });
        try processProposerLookahead(allocator, cached_state, cache);
        _ = try timer.stopAndObserve();
    }
}
