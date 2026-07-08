const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

const CachedBeaconState = @import("cache/state_cache.zig").CachedBeaconState;

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

    const EpochTransition = m.Histogram(f64, &.{ 0.2, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 10 });
    const EpochTransitionCommit = m.Histogram(f64, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const EpochTransitionStep = m.HistogramVec(f64, EpochTransitionStepLabel, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const ProcessBlock = m.Histogram(f64, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const ProcessBlockCommit = m.Histogram(f64, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const StateHashTreeRoot = m.HistogramVec(f64, HashTreeRootLabel, &.{ 0.05, 0.1, 0.2, 0.5, 1, 1.5 });
    const CountGauge = m.Gauge(u64);
    const GaugeVecSource = m.GaugeVec(u64, StateCloneSourceLabel);
    const PreStateClonedCount = m.Histogram(u32, &.{ 1, 2, 5, 10, 50, 250 });
    const ProposerRewardsGauge = m.GaugeVec(u64, ProposerRewardLabel);

    //TODO: no-op for now; We need to check for populated nodes like in lodestar-ts
    pub fn onStateClone(_: *Metrics, _: *CachedBeaconState, _: StateCloneSource) !void {}

    //TODO: no-op for now; We need to check for populated nodes like in lodestar-ts
    pub fn onPostState(_: *Metrics, _: *CachedBeaconState) !void {}

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
pub fn init(allocator: Allocator, io: std.Io, comptime opts: m.RegistryOpts) !void {
    const metric_opts = comptime m.RegistryOpts{
        .prefix = if (opts.prefix.len == 0) "lodestar_" else opts.prefix,
        .exclude = opts.exclude,
    };

    var epoch_transition_step = try Metrics.EpochTransitionStep.init(
        allocator,
        io,
        "stfn_epoch_transition_step_seconds",
        .{ .help = "Time to call each step of epoch transition in seconds" },
        metric_opts,
    );
    errdefer epoch_transition_step.deinit();
    var state_hash_tree_root = try Metrics.StateHashTreeRoot.init(
        allocator,
        io,
        "stfn_hash_tree_root_seconds",
        .{ .help = "Time to compute the hash tree root of a post state in seconds" },
        metric_opts,
    );
    errdefer state_hash_tree_root.deinit();
    var pre_state_balances_nodes_populated_miss = try Metrics.GaugeVecSource.init(
        allocator,
        io,
        "stfn_balances_nodes_populated_miss_total",
        .{ .help = "Total count state.balances nodesPopulated is false on stfn" },
        metric_opts,
    );
    errdefer pre_state_balances_nodes_populated_miss.deinit();
    var pre_state_balances_nodes_populated_hit = try Metrics.GaugeVecSource.init(
        allocator,
        io,
        "stfn_balances_nodes_populated_hit_total",
        .{ .help = "Total count state.balances nodesPopulated is true on stfn" },
        metric_opts,
    );
    errdefer pre_state_balances_nodes_populated_hit.deinit();
    var pre_state_validators_nodes_populated_miss = try Metrics.GaugeVecSource.init(
        allocator,
        io,
        "stfn_validators_nodes_populated_miss_total",
        .{ .help = "Total count state.validators nodesPopulated is false on stfn" },
        metric_opts,
    );
    errdefer pre_state_validators_nodes_populated_miss.deinit();
    var pre_state_validators_nodes_populated_hit = try Metrics.GaugeVecSource.init(
        allocator,
        io,
        "stfn_validators_nodes_populated_hit_total",
        .{ .help = "Total count state.validators nodesPopulated is true on stfn" },
        metric_opts,
    );
    errdefer pre_state_validators_nodes_populated_hit.deinit();
    var proposer_rewards = try Metrics.ProposerRewardsGauge.init(
        allocator,
        io,
        "stfn_proposer_rewards_total",
        .{ .help = "Proposer reward by type per block" },
        metric_opts,
    );
    errdefer proposer_rewards.deinit();

    state_transition = .{
        .epoch_transition = Metrics.EpochTransition.init(
            "stfn_epoch_transition_seconds",
            .{ .help = "Time to process a single epoch transition in seconds" },
            metric_opts,
        ),
        .epoch_transition_commit = Metrics.EpochTransitionCommit.init(
            "stfn_epoch_transition_commit_seconds",
            .{ .help = "Time to call commit after process a single epoch transition in seconds" },
            metric_opts,
        ),
        .epoch_transition_step = epoch_transition_step,
        .process_block = Metrics.ProcessBlock.init(
            "stfn_process_block_seconds",
            .{ .help = "Time to process a single block in seconds" },
            metric_opts,
        ),
        .process_block_commit = Metrics.ProcessBlockCommit.init(
            "stfn_process_block_commit_seconds",
            .{ .help = "Time to call commit after process a single block in seconds" },
            metric_opts,
        ),
        .state_hash_tree_root = state_hash_tree_root,
        .num_effective_balance_updates = Metrics.CountGauge.init(
            "stfn_effective_balance_updates_count",
            .{ .help = "Total count of effective balance updates" },
            metric_opts,
        ),
        .validators_in_activation_queue = Metrics.CountGauge.init(
            "stfn_validators_in_activation_queue",
            .{ .help = "Current number of validators in the activation queue" },
            metric_opts,
        ),
        .validators_in_exit_queue = Metrics.CountGauge.init(
            "stfn_validators_in_exit_queue",
            .{ .help = "Current number of validators in the exit queue" },
            metric_opts,
        ),
        .pre_state_balances_nodes_populated_miss = pre_state_balances_nodes_populated_miss,
        .pre_state_balances_nodes_populated_hit = pre_state_balances_nodes_populated_hit,
        .pre_state_validators_nodes_populated_miss = pre_state_validators_nodes_populated_miss,
        .pre_state_validators_nodes_populated_hit = pre_state_validators_nodes_populated_hit,
        .pre_state_cloned_count = Metrics.PreStateClonedCount.init(
            "stfn_state_cloned_count",
            .{ .help = "Histogram of cloned count per state every time state.clone() is called" },
            metric_opts,
        ),
        .post_state_balances_nodes_populated_hit = Metrics.CountGauge.init(
            "stfn_post_state_balances_nodes_populated_hit_total",
            .{ .help = "Total count state.validators nodesPopulated is true on stfn for post state" },
            metric_opts,
        ),
        .post_state_balances_nodes_populated_miss = Metrics.CountGauge.init(
            "stfn_post_state_balances_nodes_populated_miss_total",
            .{ .help = "Total count state.validators nodesPopulated is false on stfn for post state" },
            metric_opts,
        ),
        .post_state_validators_nodes_populated_hit = Metrics.CountGauge.init(
            "stfn_post_state_validators_nodes_populated_hit_total",
            .{ .help = "Total count state.validators nodesPopulated is true on stfn for post state" },
            metric_opts,
        ),
        .post_state_validators_nodes_populated_miss = Metrics.CountGauge.init(
            "stfn_post_state_validators_nodes_populated_miss_total",
            .{ .help = "Total count state.validators nodesPopulated is false on stfn for post state" },
            metric_opts,
        ),
        .new_seen_attesters_per_block = Metrics.CountGauge.init(
            "stfn_new_seen_attesters_per_block_total",
            .{ .help = "Total count of new seen attesters per block" },
            metric_opts,
        ),
        .new_seen_attesters_effective_balance_per_block = Metrics.CountGauge.init(
            "stfn_new_seen_attesters_effective_balance_per_block_total",
            .{ .help = "Total effective balance increment of new seen attesters per block" },
            metric_opts,
        ),
        .attestations_per_block = Metrics.CountGauge.init(
            "stfn_attestations_per_block_total",
            .{ .help = "Total count of attestations per block" },
            metric_opts,
        ),
        .proposer_rewards = proposer_rewards,
    };
}

/// Observe a value in ns for the `epoch_transition_step` labelled histogram.
pub fn observeEpochTransitionStep(
    labels: EpochTransitionStepLabel,
    ns: u64,
) !void {
    try state_transition.epoch_transition_step.observe(
        labels,
        @as(f64, @floatFromInt(ns)) / std.time.ns_per_s,
    );
}

/// Writes all metrics to `writer`.
pub fn write(writer: *std.Io.Writer) !void {
    try m.write(&state_transition, writer);
}
