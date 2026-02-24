const std = @import("std");
const Timer = std.time.Timer;
const metrics = @import("../metrics.zig");
const observeEpochTransitionStep = metrics.observeEpochTransitionStep;

const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
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
const Node = @import("persistent_merkle_tree").Node;

pub fn processEpoch(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    cache: *EpochTransitionCache,
) !void {
    var timer = try Timer.start();
    try processJustificationAndFinalization(fork, state, cache);
    try observeEpochTransitionStep(.{ .step = .process_justification_and_finalization }, timer.read());

    if (comptime fork.gte(.altair)) {
        timer = try Timer.start();
        try processInactivityUpdates(fork, allocator, config, epoch_cache, state, cache);
        try observeEpochTransitionStep(.{ .step = .process_inactivity_updates }, timer.read());
    }

    timer = try Timer.start();
    try processRegistryUpdates(fork, config, epoch_cache, state, cache);
    try observeEpochTransitionStep(.{ .step = .process_registry_updates }, timer.read());

    timer = try Timer.start();
    const slashing_penalties = try processSlashings(fork, allocator, epoch_cache, state, cache, false);
    try observeEpochTransitionStep(.{ .step = .process_slashings }, timer.read());

    timer = try Timer.start();
    try processRewardsAndPenalties(fork, allocator, config, epoch_cache, state, cache, slashing_penalties);
    try observeEpochTransitionStep(.{ .step = .process_rewards_and_penalties }, timer.read());

    try processEth1DataReset(fork, state, cache);

    if (comptime fork.gte(.electra)) {
        timer = try Timer.start();
        try processPendingDeposits(fork, allocator, config, epoch_cache, state, cache);
        try observeEpochTransitionStep(.{ .step = .process_pending_deposits }, timer.read());

        timer = try Timer.start();
        try processPendingConsolidations(fork, epoch_cache, state, cache);
        try observeEpochTransitionStep(.{ .step = .process_pending_consolidations }, timer.read());
    }

    // const numUpdate = processEffectiveBalanceUpdates(fork, state, cache);
    timer = try Timer.start();
    _ = try processEffectiveBalanceUpdates(fork, allocator, epoch_cache, state, cache);
    try observeEpochTransitionStep(.{ .step = .process_effective_balance_updates }, timer.read());

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
        timer = try Timer.start();
        try processParticipationFlagUpdates(fork, state);
        try observeEpochTransitionStep(.{ .step = .process_participation_flag_updates }, timer.read());
    }

    if (comptime fork.gte(.altair)) {
        timer = try Timer.start();
        try processSyncCommitteeUpdates(fork, allocator, epoch_cache, state);
        try observeEpochTransitionStep(.{ .step = .process_sync_committee_updates }, timer.read());
    }

    if (comptime fork.gte(.fulu)) {
        timer = try Timer.start();
        try processProposerLookahead(fork, allocator, epoch_cache, state, cache);
        try observeEpochTransitionStep(.{ .step = .process_proposer_lookahead }, timer.read());
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processEpoch - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processEpoch(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
