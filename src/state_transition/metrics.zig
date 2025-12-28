const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

const CachedBeaconStateAllForks = @import("cache/state_cache.zig").CachedBeaconStateAllForks;

/// Defaults to noop metrics, making this safe to use whether or not `metrics.init` is called.
pub var state_transition = m.initializeNoop(Metrics);

pub const StateCloneSource = enum {
    state_transition,
    process_slots,
};

pub const StateHashTreeRootSource = enum {
    state_transition,
    block_transition,
    prepare_next_slot,
    prepare_next_epoch,
    regen_state,
    compute_new_state_root,
};

pub const EpochTransitionStepKind = enum {
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

pub const ProposerRewardKind = enum {
    attestation,
    sync_aggregate,
    slashing,
};

const StateCloneSourceLabel = struct { source: StateCloneSource };
const HashTreeRootLabel = struct { source: StateHashTreeRootSource };
const EpochTransitionStepLabel = struct { step: EpochTransitionStepKind };
const ProposerRewardLabel = struct { kind: ProposerRewardKind };

const Metrics = struct {
    epoch_transition: EpochTransition,
    epoch_transition_commit: EpochTransitionCommit,
    epoch_transition_step: EpochTransitionStep,
    process_block: ProcessBlock,
    process_block_commit: ProcessBlockCommit,
    state_hash_tree_root: StateHashTreeRoot,
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
    const EpochTransitionStep = m.HistogramVec(f32, EpochTransitionStepLabel, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const ProcessBlock = m.Histogram(f32, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const ProcessBlockCommit = m.Histogram(f32, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const StateHashTreeRoot = m.HistogramVec(f32, HashTreeRootLabel, &.{ 0.05, 0.1, 0.2, 0.5, 1, 1.5 });
    const CountGauge = m.Gauge(u64);
    const GaugeVecSource = m.GaugeVec(u64, StateCloneSourceLabel);
    const PreStateClonedCount = m.Histogram(u32, &.{ 1, 2, 5, 10, 50, 250 });
    const ProposerRewardsGauge = m.GaugeVec(u64, ProposerRewardLabel);

    pub fn onStateClone(self: *Metrics, state: *CachedBeaconStateAllForks, source: StateCloneSource) !void {
        try if (state.state.balances().items.len > 0)
            self.pre_state_balances_nodes_populated_hit.incr(.{ .source = source })
        else
            self.pre_state_balances_nodes_populated_miss.incr(.{ .source = source });

        try if (state.state.validators().items.len > 0)
            self.pre_state_validators_nodes_populated_hit.incr(.{ .source = source })
        else
            self.pre_state_validators_nodes_populated_miss.incr(.{ .source = source });
    }

    pub fn onPostState(self: *Metrics, state: *CachedBeaconStateAllForks) void {
        if (state.state.balances().items.len > 0)
            self.post_state_balances_nodes_populated_hit.incr()
        else
            self.post_state_balances_nodes_populated_miss.incr();

        if (state.state.validators().items.len > 0)
            self.post_state_validators_nodes_populated_hit.incr()
        else
            self.post_state_validators_nodes_populated_miss.incr();
    }
    /// Deinitializes all `HistogramVec` and `GaugeVec` metrics for state transition.
    pub fn deinit(self: *Metrics) void {
        self.epoch_transition_step.deinit();
        self.state_hash_tree_root.deinit();
        self.pre_state_balances_nodes_populated_miss.deinit();
        self.pre_state_balances_nodes_populated_hit.deinit();
        self.pre_state_validators_nodes_populated_miss.deinit();
        self.pre_state_validators_nodes_populated_hit.deinit();
        self.proposer_rewards.deinit();
    }
};

/// Initializes all metrics for state transition. Requires an allocator for `GaugeVec` and `HistogramVec` metrics.
///
/// Meant to be called once on application startup.
pub fn init(allocator: Allocator, comptime opts: m.RegistryOpts) !void {
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
        .epoch_transition_step = try Metrics.EpochTransitionStep.init(
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
        .state_hash_tree_root = try Metrics.StateHashTreeRoot.init(
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

/// Useful for conversion to seconds during isolated uses of `observe` that requires timing.
/// Prometheus recommends that time coding be in seconds.
///
/// See for example: https://prometheus.io/docs/instrumenting/writing_clientlibs/#gauge
pub fn readSeconds(timer: *std.time.Timer) f32 {
    return @floatFromInt(timer.read() / std.time.ns_per_s);
}

/// Observe a value in seconds for the `epoch_transition` histogram.
pub fn observeEpochTransition(ns: u64) !void {
    try state_transition.epoch_transition.observe(
        @floatFromInt(ns / std.time.ns_per_s),
    );
}

/// Observe a value in seconds for the `epoch_transition_step` labelled histogram.
pub fn observeEpochTransitionStep(
    labels: EpochTransitionStepLabel,
    ns: u64,
) !void {
    try state_transition.epoch_transition_step.observe(
        labels,
        @floatFromInt(ns / std.time.ns_per_s),
    );
}

/// Writes all metrics to `writer`.
pub fn write(writer: anytype) !void {
    try m.write(&state_transition, writer);
}
