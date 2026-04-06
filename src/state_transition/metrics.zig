const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

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

const HashTreeRootLabel = struct { source: StateHashTreeRootSource };
const EpochTransitionStepLabel = struct { step: EpochTransitionStepKind };

pub const StateTransitionMetrics = struct {
    io: ?std.Io = null,
    epoch_transition: EpochTransition,
    epoch_transition_step: EpochTransitionStep,
    process_block: ProcessBlock,
    state_hash_tree_root: StateHashTreeRoot,

    const EpochTransition = m.Histogram(f64, &.{ 0.2, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 10 });
    const EpochTransitionStep = m.HistogramVec(f64, EpochTransitionStepLabel, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 0.75, 1 });
    const ProcessBlock = m.Histogram(f64, &.{ 0.005, 0.01, 0.02, 0.05, 0.1, 1 });
    const StateHashTreeRoot = m.HistogramVec(f64, HashTreeRootLabel, &.{ 0.05, 0.1, 0.2, 0.5, 1, 1.5 });

    pub fn init(allocator: Allocator, io: std.Io, comptime opts: m.RegistryOpts) !StateTransitionMetrics {
        var epoch_transition_step = try EpochTransitionStep.init(
            allocator,
            "lodestar_stfn_epoch_transition_step_seconds",
            .{ .help = "Time spent in each epoch-transition step in seconds" },
            opts,
        );
        errdefer epoch_transition_step.deinit();

        var state_hash_tree_root = try StateHashTreeRoot.init(
            allocator,
            "lodestar_stfn_hash_tree_root_seconds",
            .{ .help = "Time to compute a post-state hash tree root in seconds" },
            opts,
        );
        errdefer state_hash_tree_root.deinit();

        return .{
            .io = io,
            .epoch_transition = EpochTransition.init(
                "lodestar_stfn_epoch_transition_seconds",
                .{ .help = "Time to process a single epoch transition in seconds" },
                opts,
            ),
            .epoch_transition_step = epoch_transition_step,
            .process_block = ProcessBlock.init(
                "lodestar_stfn_process_block_seconds",
                .{ .help = "Time to process a single block in seconds" },
                opts,
            ),
            .state_hash_tree_root = state_hash_tree_root,
        };
    }

    pub fn initNoop() StateTransitionMetrics {
        return m.initializeNoop(StateTransitionMetrics);
    }

    pub fn isEnabled(self: *const StateTransitionMetrics) bool {
        return self.io != null;
    }

    pub fn deinit(self: *StateTransitionMetrics) void {
        if (!self.isEnabled()) return;
        self.epoch_transition_step.deinit();
        self.state_hash_tree_root.deinit();
        self.* = initNoop();
    }

    pub fn startTimer(self: *const StateTransitionMetrics) Timer {
        return Timer.start(self.io);
    }

    pub fn observeEpochTransitionStep(
        self: *StateTransitionMetrics,
        labels: EpochTransitionStepLabel,
        ns: u64,
    ) !void {
        try self.epoch_transition_step.observe(
            labels,
            @as(f64, @floatFromInt(ns)) / std.time.ns_per_s,
        );
    }

    pub fn write(self: *StateTransitionMetrics, writer: anytype) !void {
        try m.write(self, writer);
    }
};

var noop_metrics_instance = StateTransitionMetrics.initNoop();

pub fn noop() *StateTransitionMetrics {
    return &noop_metrics_instance;
}

pub const Timer = struct {
    start_time: ?std.Io.Clock.Timestamp = null,
    io: ?std.Io = null,

    pub fn start(io: ?std.Io) Timer {
        const actual_io = io orelse return .{};
        return .{
            .start_time = std.Io.Clock.Timestamp.now(actual_io, .awake),
            .io = actual_io,
        };
    }

    pub fn read(self: *Timer) u64 {
        const io = self.io orelse return 0;
        const start_time = self.start_time orelse return 0;
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        const duration = start_time.durationTo(now);
        return @intCast(@max(0, duration.raw.nanoseconds));
    }

    pub fn readSeconds(self: *Timer) f64 {
        return @as(f64, @floatFromInt(self.read())) / std.time.ns_per_s;
    }
};
