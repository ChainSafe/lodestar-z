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
    epoch_cache: *EpochCache,
    state: *ForkBeaconState(fork),
    cache: *EpochTransitionCache,
) !void {
    try processJustificationAndFinalization(fork, state, cache);

    if (comptime fork.gte(.altair)) {
        try processInactivityUpdates(fork, config, epoch_cache, state, cache);
    }

    try processRegistryUpdates(fork, config, epoch_cache, state, cache);

    // TODO(bing): In lodestar-ts we accumulate slashing penalties and only update in processRewardsAndPenalties. Do the same?
    try processSlashings(fork, allocator, epoch_cache, state, cache);

    try processRewardsAndPenalties(fork, allocator, config, epoch_cache, state, cache);

    try processEth1DataReset(fork, state, cache);

    if (comptime fork.gte(.electra)) {
        try processPendingDeposits(fork, allocator, config, epoch_cache, state, cache);
        try processPendingConsolidations(fork, epoch_cache, state, cache);
    }

    // const numUpdate = processEffectiveBalanceUpdates(fork, state, cache);
    _ = try processEffectiveBalanceUpdates(fork, allocator, epoch_cache, state, cache);

    try processSlashingsReset(fork, epoch_cache, state, cache);
    try processRandaoMixesReset(fork, state, cache);

    if (comptime fork.gte(.capella)) {
        try processHistoricalSummariesUpdate(fork, state, cache);
    } else {
        try processHistoricalRootsUpdate(fork, state, cache);
    }

    if (comptime fork == .phase0) {
        try processParticipationRecordUpdates(fork, state);
    } else {
        try processParticipationFlagUpdates(fork, state);
    }

    if (comptime fork.gte(.altair)) {
        try processSyncCommitteeUpdates(fork, allocator, epoch_cache, state);
    }

    if (comptime fork.gte(.fulu)) {
        try processProposerLookahead(fork, allocator, epoch_cache, state, cache);
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processEpoch - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 10_000);
    defer test_state.deinit();

    try processEpoch(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
