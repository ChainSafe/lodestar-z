const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");
const CachedBeaconStateAllForks = @import("cache/state_cache.zig").CachedBeaconStateAllForks;

// defaults to noop metrics, making this safe to use whether or not initializeMetrics is called
pub var state_transition = m.initializeNoop(Metrics);

pub const StateCloneSource = enum {
    stateTransition,
    processSlots,
};

pub const StateHashTreeRootSource = enum {
    state_transition,
    block_transition,
    prepare_next_slot,
    prepare_next_epoch,
    regen_state,
    compute_new_state_root,
};

pub const EpochTransitionStep = enum {
    before_process_epoch,
    after_process_epoch,
    final_process_epoch,
    process_justification_and_finalization,
    process_inactivity_updates,
    process_registry_updates,
    process_slashings,
    process_rewards_and_penalties,
    process_effective_balance_updates,
    process_participation_flag_updates,
    process_sync_committee_updates,
    process_pending_deposits,
    process_pending_consolidations,
    process_proposer_lookahead,
};

pub const ProposerRewardType = enum {
    attestation,
    sync_aggregate,
    slashing,
};

const SourceLabel = struct { source: StateCloneSource };
pub const HashTreeRootLabel = struct { source: StateHashTreeRootSource };
const EpochTransitionStepLabel = struct { step: EpochTransitionStep };
const ProposerRewardLabel = struct { type: ProposerRewardType };

pub const Metrics = struct {
    epoch_transition: EpochTransition,
    epoch_transition_commit: EpochTransitionCommit,
    epoch_transition_step: EpochTransitionStepTime,
    process_block: ProcessBlock,
    process_block_commit: ProcessBlockCommit,
    state_hash_tree_root: StateHashTreeRootTime,
    num_effective_balance_updates: CountGauge,
    validators_in_activation_queue: CountGauge,
    validators_in_exit_queue: CountGauge,
    pre_state_balances_nodes_populated_miss: GaugeVecSource,
    pre_state_balances_nodes_populated_hit: GaugeVecSource,
    pre_state_validators_nodes_populated_miss: GaugeVecSource,
    pre_state_validators_nodes_populated_hit: GaugeVecSource,
    pre_state_cloned_count: PreStateClonedCount,
    post_state_balances_nodes_populated_hit: CountGauge,
    post_state_balances_nodes_populated_miss: CountGauge,
    post_state_validators_nodes_populated_hit: CountGauge,
    post_state_validators_nodes_populated_miss: CountGauge,
    new_seen_attesters_per_block: CountGauge,
    new_seen_attesters_effective_balance_per_block: CountGauge,
    attestations_per_block: CountGauge,
    proposer_rewards: ProposerRewardsGauge,

    const EpochTransition = m.Histogram(f32, &.{ 0.2, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 10 });
    const EpochTransitionCommit = m.Histogram(f32, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const EpochTransitionStepTime = m.HistogramVec(f32, EpochTransitionStepLabel, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const ProcessBlock = m.Histogram(f32, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const ProcessBlockCommit = m.Histogram(f32, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const StateHashTreeRootTime = m.HistogramVec(f32, HashTreeRootLabel, &.{ 0.05, 0.1, 0.2, 0.5, 1, 1.5 });
    const CountGauge = m.Gauge(u64);
    const GaugeVecSource = m.GaugeVec(u64, SourceLabel);
    const PreStateClonedCount = m.Histogram(u32, &.{ 1, 2, 5, 10, 50, 250 });
    const ProposerRewardsGauge = m.GaugeVec(u64, ProposerRewardLabel);
};

/// Initializes all metrics for state transition. Requires an allocator for `GaugeVec` and `HistogramVec` metrics.
///
/// Meant to be called once on application startup.
pub fn initializeMetrics(allocator: Allocator, comptime opts: m.RegistryOpts) !void {
    state_transition = .{
        .epoch_transition = Metrics.EpochTransition.init(
            "lodestar_stfn_epoch_transition_seconds",
            .{ .help = "Time to process a single epoch transition in seconds" },
            opts,
        ),
        .epoch_transition_commit = Metrics.EpochTransitionCommit.init(
            "lodestar_stfn_epoch_transition_commit_seconds",
            .{ .help = "Time to call commit after process a single epoch transition in seconds" },
            opts,
        ),
        .epoch_transition_step = try Metrics.EpochTransitionStepTime.init(
            allocator,
            "lodestar_stfn_epoch_transition_step_seconds",
            .{ .help = "Time to call each step of epoch transition in seconds" },
            opts,
        ),
        .process_block = Metrics.ProcessBlock.init(
            "lodestar_stfn_process_block_seconds",
            .{ .help = "Time to process a single block in seconds" },
            opts,
        ),
        .process_block_commit = Metrics.ProcessBlockCommit.init(
            "lodestar_stfn_process_block_commit_seconds",
            .{ .help = "Time to call commit after process a single block in seconds" },
            opts,
        ),
        .state_hash_tree_root = try Metrics.StateHashTreeRootTime.init(
            allocator,
            "lodestar_stfn_hash_tree_root_seconds",
            .{ .help = "Time to compute the hash tree root of a post state in seconds" },
            opts,
        ),
        .num_effective_balance_updates = Metrics.CountGauge.init(
            "lodestar_stfn_effective_balance_updates_count",
            .{ .help = "Total count of effective balance updates" },
            opts,
        ),
        .validators_in_activation_queue = Metrics.CountGauge.init(
            "lodestar_stfn_validators_in_activation_queue",
            .{ .help = "Current number of validators in the activation queue" },
            opts,
        ),
        .validators_in_exit_queue = Metrics.CountGauge.init(
            "lodestar_stfn_validators_in_exit_queue",
            .{ .help = "Current number of validators in the exit queue" },
            opts,
        ),
        .pre_state_balances_nodes_populated_miss = try Metrics.GaugeVecSource.init(
            allocator,
            "lodestar_stfn_balances_nodes_populated_miss_total",
            .{ .help = "Total count state.balances nodesPopulated is false on stfn" },
            opts,
        ),
        .pre_state_balances_nodes_populated_hit = try Metrics.GaugeVecSource.init(
            allocator,
            "lodestar_stfn_balances_nodes_populated_hit_total",
            .{ .help = "Total count state.balances nodesPopulated is true on stfn" },
            opts,
        ),
        .pre_state_validators_nodes_populated_miss = try Metrics.GaugeVecSource.init(
            allocator,
            "lodestar_stfn_validators_nodes_populated_miss_total",
            .{ .help = "Total count state.validators nodesPopulated is false on stfn" },
            opts,
        ),
        .pre_state_validators_nodes_populated_hit = try Metrics.GaugeVecSource.init(
            allocator,
            "lodestar_stfn_validators_nodes_populated_hit_total",
            .{ .help = "Total count state.validators nodesPopulated is true on stfn" },
            opts,
        ),
        .pre_state_cloned_count = Metrics.PreStateClonedCount.init(
            "lodestar_stfn_state_cloned_count",
            .{ .help = "Histogram of cloned count per state every time state.clone() is called" },
            opts,
        ),
        .post_state_balances_nodes_populated_hit = Metrics.CountGauge.init(
            "lodestar_stfn_post_state_balances_nodes_populated_hit_total",
            .{ .help = "Total count state.validators nodesPopulated is true on stfn for post state" },
            opts,
        ),
        .post_state_balances_nodes_populated_miss = Metrics.CountGauge.init(
            "lodestar_stfn_post_state_balances_nodes_populated_miss_total",
            .{ .help = "Total count state.validators nodesPopulated is false on stfn for post state" },
            opts,
        ),
        .post_state_validators_nodes_populated_hit = Metrics.CountGauge.init(
            "lodestar_stfn_post_state_validators_nodes_populated_hit_total",
            .{ .help = "Total count state.validators nodesPopulated is true on stfn for post state" },
            opts,
        ),
        .post_state_validators_nodes_populated_miss = Metrics.CountGauge.init(
            "lodestar_stfn_post_state_validators_nodes_populated_miss_total",
            .{ .help = "Total count state.validators nodesPopulated is false on stfn for post state" },
            opts,
        ),
        .new_seen_attesters_per_block = Metrics.CountGauge.init(
            "lodestar_stfn_new_seen_attesters_per_block_total",
            .{ .help = "Total count of new seen attesters per block" },
            opts,
        ),
        .new_seen_attesters_effective_balance_per_block = Metrics.CountGauge.init(
            "lodestar_stfn_new_seen_attesters_effective_balance_per_block_total",
            .{ .help = "Total effective balance increment of new seen attesters per block" },
            opts,
        ),
        .attestations_per_block = Metrics.CountGauge.init(
            "lodestar_stfn_attestations_per_block_total",
            .{ .help = "Total count of attestations per block" },
            opts,
        ),
        .proposer_rewards = try Metrics.ProposerRewardsGauge.init(
            allocator,
            "lodestar_stfn_proposer_rewards_total",
            .{ .help = "Proposer reward by type per block" },
            opts,
        ),
    };
}

/// Deinitializes all `HistogramVec` and `GaugeVec` metrics for state transition.
pub fn deinitMetrics(current: *Metrics) void {
    current.epoch_transition_step.deinit();
    current.state_hash_tree_root.deinit();
    current.pre_state_balances_nodes_populated_miss.deinit();
    current.pre_state_balances_nodes_populated_hit.deinit();
    current.pre_state_validators_nodes_populated_miss.deinit();
    current.pre_state_validators_nodes_populated_hit.deinit();
    current.proposer_rewards.deinit();
}

/// An observer for tracking time.
fn Observer(comptime H: type) type {
    return struct {
        hist: H,
        timer: std.time.Timer,

        /// Stops the internal `timer` and calls `observe` on the internal `hist` to record time elapsed.
        pub fn stopAndObserve(obs: *@This()) f32 {
            const ns = obs.timer.read();
            const secs = @as(f32, @floatFromInt(ns)) / 1e9;
            obs.hist.observe(secs);
            return secs;
        }
    };
}

/// A labeled observer for tracking time.
fn LabeledObserver(comptime H: type, comptime L: type) type {
    return struct {
        hist: H,
        labels: L,
        timer: std.time.Timer,

        /// Stops the internal `timer` and calls `observe` on the internal `hist` to record time elapsed.
        pub fn stopAndObserve(obs: *@This()) !f32 {
            const ns = obs.timer.read();
            const secs = @as(f32, @floatFromInt(ns)) / 1e9;
            try obs.hist.observe(obs.labels, secs);
            return secs;
        }
    };
}

/// Initializes a `std.time.Timer` and returns an `Observer`.
///
/// Asserts that the given `hist` is a pointer.
pub fn startTimer(hist: anytype) Observer(@TypeOf(hist)) {
    std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
    return .{
        .hist = hist,
        .timer = std.time.Timer.start() catch unreachable,
    };
}

/// Initializes a `std.time.Timer` and returns a `LabeledObserver`.
///
/// Asserts that the given `hist` is a pointer.
pub fn startTimerLabeled(hist: anytype, labels: anytype) LabeledObserver(@TypeOf(hist), @TypeOf(labels)) {
    std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
    return .{
        .hist = hist,
        .labels = labels,
        .timer = std.time.Timer.start() catch unreachable,
    };
}

/// Specialized use of `startTimerLabeled` for the epoch transition steps.
pub fn startTimerEpochTransitionStep(labels: EpochTransitionStepLabel) LabeledObserver(@TypeOf(&state_transition.epoch_transition_step), @TypeOf(labels)) {
    return .{
        .hist = &state_transition.epoch_transition_step,
        .labels = labels,
        .timer = std.time.Timer.start() catch unreachable,
    };
}

// TODO: hook into CachedBeaconStateAllForks once cloned count and nodesPopulated caches are exposed.
pub fn onStateCloneMetrics(state: *CachedBeaconStateAllForks, collected: *Metrics, source: StateCloneSource) void {
    _ = state;
    _ = collected;
    _ = source;
}

// TODO: hook into CachedBeaconStateAllForks once nodesPopulated caches are exposed.
pub fn onPostStateMetrics(state: *CachedBeaconStateAllForks, collected: *Metrics) void {
    _ = state;
    _ = collected;
}
