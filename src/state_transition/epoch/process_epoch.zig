const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
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

// TODO: add metrics
pub fn processEpoch(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *EpochTransitionCache,
) !void {
    try processJustificationAndFinalization(cached_state, cache);

    if (state.forkSeq().gte(.altair)) {
        try processInactivityUpdates(cached_state, cache);
    }

    try processRegistryUpdates(cached_state, cache);

    // TODO(bing): In lodestar-ts we accumulate slashing penalties and only update in processRewardsAndPenalties. Do the same?
    try processSlashings(allocator, cached_state, cache);

    try processRewardsAndPenalties(allocator, cached_state, cache);

    try processEth1DataReset(cached_state, cache);

    if (state.forkSeq().gte(.electra)) {
        try processPendingDeposits(allocator, cached_state, cache);
        try processPendingConsolidations(cached_state, cache);
    }

    // const numUpdate = processEffectiveBalanceUpdates(fork, state, cache);
    _ = try processEffectiveBalanceUpdates(allocator, cached_state, cache);

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
        try processParticipationFlagUpdates(cached_state);
    }

    if (state.forkSeq().gte(.altair)) {
        try processSyncCommitteeUpdates(allocator, cached_state);
    }

    if (state.forkSeq().gte(.fulu)) {
        try processProposerLookahead(allocator, cached_state, cache);
    }
}
