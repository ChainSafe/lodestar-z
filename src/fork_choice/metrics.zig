const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

const fork_choice = @import("fork_choice.zig");
const NotReorgedReason = fork_choice.NotReorgedReason;
const UpdateHeadOpt = fork_choice.UpdateHeadOpt;

/// Defaults to noop metrics, making this safe to use whether or not `metrics.init` is called.
pub var fork_choice_metrics = m.initializeNoop(Metrics);

const CallerLabel = struct { caller: UpdateHeadOpt };
const EntrypointLabel = struct { entrypoint: UpdateHeadOpt };
const ReasonLabel = struct { reason: NotReorgedReason };

const Metrics = struct {
    find_head: FindHead,
    requests: CountGauge,
    errors: ErrorsGauge,
    changed_head: CountGauge,
    reorg: CountGauge,
    reorg_distance: ReorgDistance,
    votes: CountGauge,
    queued_attestations: CountGauge,
    validated_attestation_datas: CountGauge,
    balances_length: CountGauge,
    nodes: CountGauge,
    indices: CountGauge,
    not_reorged_reason: NotReorgedReasonCounter,
    compute_deltas_duration: ComputeDeltasDuration,
    compute_deltas_deltas_count: CountGauge,
    compute_deltas_zero_deltas_count: CountGauge,
    compute_deltas_equivocating_validators: CountGauge,
    compute_deltas_old_inactive_validators: CountGauge,
    compute_deltas_new_inactive_validators: CountGauge,
    compute_deltas_unchanged_vote_validators: CountGauge,
    compute_deltas_new_vote_validators: CountGauge,

    const FindHead = m.HistogramVec(f64, CallerLabel, &.{ 0.1, 1, 10 });
    const CountGauge = m.Gauge(u64);
    const ErrorsGauge = m.GaugeVec(u64, EntrypointLabel);
    const ReorgDistance = m.Histogram(u64, &.{ 1, 2, 3, 5, 7, 10, 20, 30, 50, 100 });
    const NotReorgedReasonCounter = m.CounterVec(u64, ReasonLabel);
    const ComputeDeltasDuration = m.Histogram(f64, &.{ 0.01, 0.05, 0.1, 0.2 });

    pub fn deinit(self: *Metrics) void {
        self.find_head.deinit();
        self.errors.deinit();
        self.not_reorged_reason.deinit();
    }
};

/// Initializes all fork choice metrics. Requires an allocator for Vec metrics.
///
/// Meant to be called once on application startup.
pub fn init(allocator: Allocator, comptime opts: m.RegistryOpts) !void {
    var find_head = try Metrics.FindHead.init(
        allocator,
        "beacon_fork_choice_find_head_seconds",
        .{ .help = "Time to find head in seconds" },
        opts,
    );
    errdefer find_head.deinit();

    var errors = try Metrics.ErrorsGauge.init(
        allocator,
        "beacon_fork_choice_errors_total",
        .{ .help = "Count of fork choice errors" },
        opts,
    );
    errdefer errors.deinit();

    var not_reorged_reason = try Metrics.NotReorgedReasonCounter.init(
        allocator,
        "beacon_fork_choice_not_reorged_reason_total",
        .{ .help = "Count of not reorged reasons" },
        opts,
    );
    errdefer not_reorged_reason.deinit();

    fork_choice_metrics = .{
        .find_head = find_head,
        .requests = Metrics.CountGauge.init(
            "beacon_fork_choice_requests_total",
            .{ .help = "Count of fork choice head-finding attempts" },
            opts,
        ),
        .errors = errors,
        .changed_head = Metrics.CountGauge.init(
            "beacon_fork_choice_changed_head_total",
            .{ .help = "Count of head changes" },
            opts,
        ),
        .reorg = Metrics.CountGauge.init(
            "beacon_fork_choice_reorg_total",
            .{ .help = "Count of chain reorgs" },
            opts,
        ),
        .reorg_distance = Metrics.ReorgDistance.init(
            "beacon_fork_choice_reorg_distance",
            .{ .help = "Histogram of reorg distances" },
            opts,
        ),
        .votes = Metrics.CountGauge.init(
            "beacon_fork_choice_votes_count",
            .{ .help = "Current count of votes in fork choice" },
            opts,
        ),
        .queued_attestations = Metrics.CountGauge.init(
            "beacon_fork_choice_queued_attestations_count",
            .{ .help = "Current count of queued attestations per slot" },
            opts,
        ),
        .validated_attestation_datas = Metrics.CountGauge.init(
            "beacon_fork_choice_validated_attestation_datas_count",
            .{ .help = "Current count of validated attestation data" },
            opts,
        ),
        .balances_length = Metrics.CountGauge.init(
            "beacon_fork_choice_balances_length",
            .{ .help = "Current balances array length" },
            opts,
        ),
        .nodes = Metrics.CountGauge.init(
            "beacon_fork_choice_nodes_count",
            .{ .help = "Current number of nodes in fork choice" },
            opts,
        ),
        .indices = Metrics.CountGauge.init(
            "beacon_fork_choice_indices_count",
            .{ .help = "Current number of indices in fork choice" },
            opts,
        ),
        .not_reorged_reason = not_reorged_reason,
        .compute_deltas_duration = Metrics.ComputeDeltasDuration.init(
            "beacon_fork_choice_compute_deltas_seconds",
            .{ .help = "Time to compute deltas in seconds" },
            opts,
        ),
        .compute_deltas_deltas_count = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_deltas_count",
            .{ .help = "Number of deltas computed" },
            opts,
        ),
        .compute_deltas_zero_deltas_count = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_zero_deltas_count",
            .{ .help = "Number of zero deltas" },
            opts,
        ),
        .compute_deltas_equivocating_validators = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_equivocating_validators_count",
            .{ .help = "Number of equivocating validators" },
            opts,
        ),
        .compute_deltas_old_inactive_validators = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_old_inactive_validators_count",
            .{ .help = "Number of old inactive validators" },
            opts,
        ),
        .compute_deltas_new_inactive_validators = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_new_inactive_validators_count",
            .{ .help = "Number of new inactive validators" },
            opts,
        ),
        .compute_deltas_unchanged_vote_validators = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_unchanged_vote_validators_count",
            .{ .help = "Number of unchanged vote validators" },
            opts,
        ),
        .compute_deltas_new_vote_validators = Metrics.CountGauge.init(
            "beacon_fork_choice_compute_deltas_new_vote_validators_count",
            .{ .help = "Number of new vote validators" },
            opts,
        ),
    };
}

/// Useful for conversion to seconds during isolated uses of `observe` that requires timing.
pub fn readSeconds(timer: *std.time.Timer) f64 {
    return @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
}

/// Writes all fork choice metrics to `writer`.
pub fn write(writer: anytype) !void {
    try m.write(&fork_choice_metrics, writer);
}
