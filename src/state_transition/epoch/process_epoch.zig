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

    var timer = try metrics.state_transition.epoch_transition_step.time();
    try processJustificationAndFinalization(cached_state, cache);
    try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_justification_and_finalization });

    if (state.forkSeq().gte(.altair)) {
        timer = try metrics.state_transition.epoch_transition_step.time();
        try processInactivityUpdates(cached_state, cache);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_inactivity_updates });
    }

    timer = try metrics.state_transition.epoch_transition_step.time();
    try processRegistryUpdates(cached_state, cache);
    try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_registry_updates });

    // TODO(bing): In lodestar-ts we accumulate slashing penalties and only update in processRewardsAndPenalties. Do the same?
    timer = try metrics.state_transition.epoch_transition_step.time();
    try processSlashings(allocator, cached_state, cache);
    try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_slashings });

    timer = try metrics.state_transition.epoch_transition_step.time();
    try processRewardsAndPenalties(allocator, cached_state, cache);
    try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_rewards_and_penalties });

    try processEth1DataReset(cached_state, cache);

    if (state.forkSeq().gte(.electra)) {
        timer = try metrics.state_transition.epoch_transition_step.time();
        try processPendingDeposits(allocator, cached_state, cache);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_pending_deposits });

        timer = try metrics.state_transition.epoch_transition_step.time();
        try processPendingConsolidations(cached_state, cache);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_pending_consolidations });
    }

    // const numUpdate = processEffectiveBalanceUpdates(fork, state, cache);
    timer = try metrics.state_transition.epoch_transition_step.time();
    _ = try processEffectiveBalanceUpdates(allocator, cached_state, cache);
    try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_effective_balance_updates });

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
        timer = try metrics.state_transition.epoch_transition_step.time();
        try processParticipationFlagUpdates(cached_state);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_participation_flag_updates });
    }

    if (state.forkSeq().gte(.altair)) {
        timer = try metrics.state_transition.epoch_transition_step.time();
        try processSyncCommitteeUpdates(allocator, cached_state);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_sync_committee_updates });
    }

    if (state.forkSeq().gte(.fulu)) {
        timer = try metrics.state_transition.epoch_transition_step.time();
        try processProposerLookahead(allocator, cached_state, cache);
        try metrics.state_transition.epoch_transition_step.observeElapsed(&timer, .{ .step = .process_proposer_lookahead });
    }
}
