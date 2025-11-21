const std = @import("std");
const m = @import("metrics");

// defaults to noop metrics, making this safe to use
// whether or not initializeMetrics is called
pub var metrics = m.initializeNoop(Metrics);

const Metrics = struct {
    /// as of Sep 2025, on mainnet, epoch transition time of lodestar is never less than 0.5s, and it could be up to 3s
    epoch_transition: EpochTransition,

    // epoch_transition_commit: EpochTransitionCommit,
    // epoch_transition_step: EpochTransitionStep,

    /// Time to process a block in seconds
    process_block: ProcessBlock,

    // process_block_commit: ProcessBlockCommit,
    // state_hash_tree_root: StateHashTreeRoot,
    //num_effective_balance_updates: NumEffectiveBalancesUpdates,
    //validators_in_activation_queue: ValidatorsInActivationQueue,
    //validators_in_exit_queue: ValidatorsInExitQueue,
    //pre_state_balances_nodes_populated_miss: PreStateBalancesNodesPopulatedMiss,
    //pre_state_balances_nodes_populated_hit: PreStateBalancesNodesPopulatedHit
    //pre_state_validators_nodes_populated_hit: preStateValidatorsNodesPopulatedHit,
    //pre_state_validators_nodes_populated_miss: preStateValidatorsNodesPopulatedMiss,
    //pre_state_cloned_count: PreStateClonedCount
    //post_state_balances_nodes_populated_miss: PostStateBalancesNodesPopulatedMiss,
    //post_state_balances_nodes_populated_hit: PostStateBalancesNodesPopulatedHit
    //post_state_validators_nodes_populated_hit: PostStateValidatorsNodesPopulatedHit,
    //post_state_validators_nodes_populated_miss: PostStateValidatorsNodesPopulatedMiss,
    //new_seen_attesters_per_block: NewSeenAttestersPerBlock,
    //new_seen_attesterse_effective_balances_per_block: NewSeenAttestersEffectiveBalancePerBlock    ,
    //attestations_per_block: AttestationsPerBlock    ,

    const EpochTransition = m.Histogram(f32, &.{ 0.2, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 10 });
    const ProcessBlock = m.Histogram(f32, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
};

// meant to be called once on application startup
pub fn initializeMetrics(comptime opts: m.RegistryOpts) !void {
    metrics = .{
        .process_block = Metrics.ProcessBlock.init("process_block", .{}, opts),
        .epoch_transition = Metrics.EpochTransition.init("lodestar_stfn_epoch_transition_seconds", .{}, opts),
    };
}

fn Observer(comptime H: type) type {
    return struct {
        hist: H,
        timer: std.time.Timer,

        pub fn stopAndObserve(obs: *@This()) f32 {
            const ns = obs.timer.read();
            const secs = @as(f32, @floatFromInt(ns)) / 1e9;
            obs.hist.observe(secs);
            return secs;
        }
    };
}

pub fn startTimer(hist: anytype) Observer(@TypeOf(hist)) {
    comptime if (@typeInfo(@TypeOf(hist)) != .pointer)
        @compileError("startTimer expects a pointer to a histogram");

    return .{
        .hist = hist,
        .timer = std.time.Timer.start() catch unreachable,
    };
}
