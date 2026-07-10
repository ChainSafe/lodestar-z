const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");
const buffer_pool = @import("../../util/buffer_pool.zig");

/// Per-tier counts, shared by the item-level `size` and epoch-level `epoch_size` gauges. An epoch
/// holding both an in-memory and a persisted entry counts toward both tiers.
pub const SizeCounts = struct {
    in_memory: u64,
    persisted: u64,
};

const PersistedLabel = struct { type: []const u8 };

/// Emitted as four parallel gauge series: `_sum`/`_avg`/`_min`/`_max`.
pub const AvgMinMax = struct {
    sum: f64 = 0,
    avg: f64 = 0,
    min: f64 = 0,
    max: f64 = 0,
};

/// No samples → all-zero (the gauge's empty-set value).
pub const AvgMinMaxAccumulator = struct {
    sum: f64 = 0,
    min: f64 = 0,
    max: f64 = 0,
    count: u64 = 0,

    pub fn add(self: *AvgMinMaxAccumulator, value: f64) void {
        if (self.count == 0) {
            self.min = value;
            self.max = value;
        } else {
            self.min = @min(self.min, value);
            self.max = @max(self.max, value);
        }
        self.sum += value;
        self.count += 1;
    }

    pub fn result(self: AvgMinMaxAccumulator) AvgMinMax {
        if (self.count == 0) return .{};
        return .{
            .sum = self.sum,
            .avg = self.sum / @as(f64, @floatFromInt(self.count)),
            .min = self.min,
            .max = self.max,
        };
    }
};

/// `size`/`epoch_size` are PULL gauges — same contract as `BlockStateCacheMetrics`'s.
pub const CpStateCacheMetrics = struct {
    lookups: Count,
    hits: Count,
    adds: Count,
    state_prune_from_memory_count: Count,
    persisted_state_remove_count: Count,
    size: SizeGauge,
    epoch_size: SizeGauge,
    reads_sum: F64Gauge,
    reads_avg: F64Gauge,
    reads_min: F64Gauge,
    reads_max: F64Gauge,
    seconds_since_last_read_sum: F64Gauge,
    seconds_since_last_read_avg: F64Gauge,
    seconds_since_last_read_min: F64Gauge,
    seconds_since_last_read_max: F64Gauge,
    state_cloned_count: ClonedHistogram,
    state_reload_duration: ReloadSecondsHistogram,
    state_reload_db_read_time: DbReadSecondsHistogram,
    state_reload_validators_serialize_duration: ValidatorsHistogram,
    state_reload_validators_serialize_alloc_count: Count,
    state_reload_epoch_diff: EpochDiffHistogram,
    state_reload_sec_from_slot: SlotSecondsHistogram,
    state_serialize_duration: SerializeSecondsHistogram,
    state_persist_sec_from_slot: SlotSecondsHistogram,

    const Count = m.Counter(u64);
    const SizeGauge = m.GaugeVec(u64, PersistedLabel);
    const F64Gauge = m.Gauge(f64);
    const ClonedHistogram = m.Histogram(u64, &.{ 1, 2, 5, 10, 50, 250 });
    // Each histogram carries its own bucket set; the sec-from-slot pair is the only genuine share.
    const ReloadSecondsHistogram = m.Histogram(f64, &.{ 0, 2, 4, 6, 8, 10, 12 });
    const DbReadSecondsHistogram = m.Histogram(f64, &.{ 0.01, 0.05, 0.1, 0.2, 0.5 });
    const ValidatorsHistogram = m.Histogram(f64, &.{ 0.1, 0.2, 0.5, 1 });
    const SerializeSecondsHistogram = m.Histogram(f64, &.{ 0.1, 0.5, 1, 2, 3, 4 });
    const SlotSecondsHistogram = m.Histogram(f64, &.{ 0, 2, 4, 6, 8, 10, 12 });
    const EpochDiffHistogram = m.Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32 });

    pub fn deinit(self: *CpStateCacheMetrics) void {
        self.size.deinit();
        self.epoch_size.deinit();
    }
};

/// `size`/`reads`/`seconds_since_last_read` are PULL gauges: the metrics module serializes whatever the
/// gauge holds at scrape time, so the cache refreshes them before `write()` (no push collect-callback).
pub const BlockStateCacheMetrics = struct {
    lookups: Count,
    hits: Count,
    adds: Count,
    size: Gauge,
    reads_sum: F64Gauge,
    reads_avg: F64Gauge,
    reads_min: F64Gauge,
    reads_max: F64Gauge,
    seconds_since_last_read_sum: F64Gauge,
    seconds_since_last_read_avg: F64Gauge,
    seconds_since_last_read_min: F64Gauge,
    seconds_since_last_read_max: F64Gauge,
    state_cloned_count: ClonedHistogram,

    const Count = m.Counter(u64);
    const Gauge = m.Gauge(u64);
    const F64Gauge = m.Gauge(f64);
    const ClonedHistogram = m.Histogram(u64, &.{ 1, 2, 5, 10, 50, 250 });
};

/// `initializeNoop` default: metrics always emit (no `enabled()` gate), so the cache is safe to use
/// whether or not `init` is called.
pub var block_cache_metrics = m.initializeNoop(BlockStateCacheMetrics);
pub var checkpoint_cache_metrics = m.initializeNoop(CpStateCacheMetrics);

/// Call once on startup. `io` is needed for the Vec metrics.
pub fn init(allocator: Allocator, io: std.Io, comptime opts: m.RegistryOpts) !void {
    var cp_size = try CpStateCacheMetrics.SizeGauge.init(
        allocator,
        io,
        "lodestar_cp_state_cache_size",
        .{ .help = "Checkpoint state cache size by storage tier" },
        opts,
    );
    errdefer cp_size.deinit();

    var cp_epoch_size = try CpStateCacheMetrics.SizeGauge.init(
        allocator,
        io,
        "lodestar_cp_state_epoch_size",
        .{ .help = "Checkpoint state cache distinct-epoch count" },
        opts,
    );
    errdefer cp_epoch_size.deinit();

    // Free the prior GaugeVecs before overwriting on re-init; harmless on the initial noop value.
    checkpoint_cache_metrics.deinit();

    checkpoint_cache_metrics = .{
        .lookups = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_lookups_total",
            .{ .help = "Checkpoint state cache lookups" },
            opts,
        ),
        .hits = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_hits_total",
            .{ .help = "Checkpoint state cache hits" },
            opts,
        ),
        .adds = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_adds_total",
            .{ .help = "Checkpoint state cache adds" },
            opts,
        ),
        .state_prune_from_memory_count = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_state_prune_from_memory_count",
            .{ .help = "Checkpoint states pruned from memory" },
            opts,
        ),
        .persisted_state_remove_count = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_persisted_state_remove_count",
            .{ .help = "Persisted checkpoint states removed from disk" },
            opts,
        ),
        .size = cp_size,
        .epoch_size = cp_epoch_size,
        .reads_sum = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_reads_sum",
            .{ .help = "Sum of checkpoint state cache items total read count" },
            opts,
        ),
        .reads_avg = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_reads_avg",
            .{ .help = "Avg of checkpoint state cache items total read count" },
            opts,
        ),
        .reads_min = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_reads_min",
            .{ .help = "Min of checkpoint state cache items total read count" },
            opts,
        ),
        .reads_max = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_reads_max",
            .{ .help = "Max of checkpoint state cache items total read count" },
            opts,
        ),
        .seconds_since_last_read_sum = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_seconds_since_last_read_sum",
            .{ .help = "Sum of seconds since checkpoint state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_avg = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_seconds_since_last_read_avg",
            .{ .help = "Avg of seconds since checkpoint state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_min = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_seconds_since_last_read_min",
            .{ .help = "Min of seconds since checkpoint state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_max = CpStateCacheMetrics.F64Gauge.init(
            "lodestar_cp_state_epoch_seconds_since_last_read_max",
            .{ .help = "Max of seconds since checkpoint state cache items were last read" },
            opts,
        ),
        .state_cloned_count = CpStateCacheMetrics.ClonedHistogram.init(
            "lodestar_cp_state_cache_state_cloned_count",
            .{ .help = "Clone count of a state served from the checkpoint cache" },
            opts,
        ),
        .state_reload_duration = CpStateCacheMetrics.ReloadSecondsHistogram.init(
            "lodestar_cp_state_cache_state_reload_seconds",
            .{ .help = "Time to reload a checkpoint state from disk in seconds" },
            opts,
        ),
        .state_reload_db_read_time = CpStateCacheMetrics.DbReadSecondsHistogram.init(
            "lodestar_cp_state_cache_state_reload_db_read_seconds",
            .{ .help = "Time to read a checkpoint state from the datastore in seconds" },
            opts,
        ),
        .state_reload_validators_serialize_duration = CpStateCacheMetrics.ValidatorsHistogram.init(
            "lodestar_cp_state_cache_state_reload_validators_serialize_seconds",
            .{ .help = "Histogram of time to serialize validators" },
            opts,
        ),
        .state_reload_validators_serialize_alloc_count = CpStateCacheMetrics.Count.init(
            "lodestar_cp_state_cache_state_reload_validators_serialize_alloc_count",
            .{ .help = "Total fresh allocations for validators serialization" },
            opts,
        ),
        .state_reload_epoch_diff = CpStateCacheMetrics.EpochDiffHistogram.init(
            "lodestar_cp_state_cache_state_reload_epoch_diff",
            .{ .help = "Epoch distance between a reload target and its seed state" },
            opts,
        ),
        .state_reload_sec_from_slot = CpStateCacheMetrics.SlotSecondsHistogram.init(
            "lodestar_cp_state_cache_state_reload_seconds_from_slot",
            .{ .help = "Histogram of time to load state from db since the clock slot" },
            opts,
        ),
        .state_serialize_duration = CpStateCacheMetrics.SerializeSecondsHistogram.init(
            "lodestar_cp_state_cache_state_serialize_seconds",
            .{ .help = "Time to serialize a checkpoint state for persistence in seconds" },
            opts,
        ),
        .state_persist_sec_from_slot = CpStateCacheMetrics.SlotSecondsHistogram.init(
            "lodestar_cp_state_cache_state_persist_seconds_from_slot",
            .{ .help = "Histogram of time to persist state to db since the clock slot" },
            opts,
        ),
    };

    block_cache_metrics = .{
        .lookups = BlockStateCacheMetrics.Count.init(
            "lodestar_state_cache_lookups_total",
            .{ .help = "Block state cache lookups" },
            opts,
        ),
        .hits = BlockStateCacheMetrics.Count.init(
            "lodestar_state_cache_hits_total",
            .{ .help = "Block state cache hits" },
            opts,
        ),
        .adds = BlockStateCacheMetrics.Count.init(
            "lodestar_state_cache_adds_total",
            .{ .help = "Block state cache adds" },
            opts,
        ),
        .size = BlockStateCacheMetrics.Gauge.init(
            "lodestar_state_cache_size",
            .{ .help = "Block state cache size" },
            opts,
        ),
        .reads_sum = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_reads_sum",
            .{ .help = "Sum of block state cache items total read count" },
            opts,
        ),
        .reads_avg = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_reads_avg",
            .{ .help = "Avg of block state cache items total read count" },
            opts,
        ),
        .reads_min = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_reads_min",
            .{ .help = "Min of block state cache items total read count" },
            opts,
        ),
        .reads_max = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_reads_max",
            .{ .help = "Max of block state cache items total read count" },
            opts,
        ),
        .seconds_since_last_read_sum = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_seconds_since_last_read_sum",
            .{ .help = "Sum of seconds since block state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_avg = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_seconds_since_last_read_avg",
            .{ .help = "Avg of seconds since block state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_min = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_seconds_since_last_read_min",
            .{ .help = "Min of seconds since block state cache items were last read" },
            opts,
        ),
        .seconds_since_last_read_max = BlockStateCacheMetrics.F64Gauge.init(
            "lodestar_state_cache_seconds_since_last_read_max",
            .{ .help = "Max of seconds since block state cache items were last read" },
            opts,
        ),
        .state_cloned_count = BlockStateCacheMetrics.ClonedHistogram.init(
            "lodestar_state_cache_state_cloned_count",
            .{ .help = "Clone count of a state served from the block cache" },
            opts,
        ),
    };
}

/// Only `CpStateCacheMetrics` owns `GaugeVec`s, so only it is freed; both globals are then reset to the
/// noop default so a later use of a deinit'd global (e.g. across tests sharing this process-global) is a
/// safe no-op rather than a use-after-free on the freed `GaugeVec` hash maps.
pub fn deinit() void {
    checkpoint_cache_metrics.deinit();
    checkpoint_cache_metrics = m.initializeNoop(CpStateCacheMetrics);
    block_cache_metrics = m.initializeNoop(BlockStateCacheMetrics);
}

pub fn checkpoint() *CpStateCacheMetrics {
    return &checkpoint_cache_metrics;
}

pub fn block() *BlockStateCacheMetrics {
    return &block_cache_metrics;
}

/// Caller must refresh the PULL gauges (see `CpStateCacheMetrics`) before calling, so the scrape
/// reflects current state.
pub fn write(writer: anytype) !void {
    try m.write(&block_cache_metrics, writer);
    try m.write(&checkpoint_cache_metrics, writer);
    try m.write(&buffer_pool.buffer_pool_metrics, writer);
}

/// Refresh ALL PULL gauges from the live caches, then serialize. The caches are taken as `anytype`
/// (`*BlockStateCache` / `*PersistentCheckpointStateCache`) to avoid a metrics↔cache cycle.
pub fn scrape(writer: anytype, block_cache: anytype, cp_cache: anytype, io: std.Io) !void {
    setBlockSize(@intCast(block_cache.size()));
    const brs = block_cache.scanReadStats(io);
    setBlockReads(brs.reads, brs.secs);

    try setCpSize(cp_cache.collectSizeCounts());
    try setCpEpochSize(cp_cache.collectEpochSizeCounts());
    const crs = cp_cache.scanCpReadStats(io);
    setCpReads(crs.reads, crs.secs);
    if (cp_cache.buffer_pool) |pool| buffer_pool.refreshMetrics(pool);

    try write(writer);
}

pub fn setCpSize(counts: SizeCounts) !void {
    return setSizeGauge(&checkpoint_cache_metrics.size, counts);
}

pub fn setCpEpochSize(counts: SizeCounts) !void {
    return setSizeGauge(&checkpoint_cache_metrics.epoch_size, counts);
}

fn setSizeGauge(gauge: *CpStateCacheMetrics.SizeGauge, counts: SizeCounts) !void {
    try gauge.set(.{ .type = "in-memory" }, counts.in_memory);
    try gauge.set(.{ .type = "persisted" }, counts.persisted);
}

pub fn setCpReads(reads: AvgMinMax, secs: AvgMinMax) void {
    checkpoint_cache_metrics.reads_sum.set(reads.sum);
    checkpoint_cache_metrics.reads_avg.set(reads.avg);
    checkpoint_cache_metrics.reads_min.set(reads.min);
    checkpoint_cache_metrics.reads_max.set(reads.max);
    checkpoint_cache_metrics.seconds_since_last_read_sum.set(secs.sum);
    checkpoint_cache_metrics.seconds_since_last_read_avg.set(secs.avg);
    checkpoint_cache_metrics.seconds_since_last_read_min.set(secs.min);
    checkpoint_cache_metrics.seconds_since_last_read_max.set(secs.max);
}

pub fn setBlockSize(value: u64) void {
    block_cache_metrics.size.set(value);
}

pub fn setBlockReads(reads: AvgMinMax, secs: AvgMinMax) void {
    block_cache_metrics.reads_sum.set(reads.sum);
    block_cache_metrics.reads_avg.set(reads.avg);
    block_cache_metrics.reads_min.set(reads.min);
    block_cache_metrics.reads_max.set(reads.max);
    block_cache_metrics.seconds_since_last_read_sum.set(secs.sum);
    block_cache_metrics.seconds_since_last_read_avg.set(secs.avg);
    block_cache_metrics.seconds_since_last_read_min.set(secs.min);
    block_cache_metrics.seconds_since_last_read_max.set(secs.max);
}

test "init compiles end-to-end" {
    // Init TWICE under testing.allocator: the second init's double-init guard must free the first
    // init's `cp.size`/`cp.epoch_size` GaugeVecs, so a leak would trip the testing allocator.
    try init(std.testing.allocator, std.testing.io, .{});
    try init(std.testing.allocator, std.testing.io, .{});
    defer deinit();

    try setCpSize(.{ .in_memory = 2, .persisted = 3 });
    try setCpEpochSize(.{ .in_memory = 4, .persisted = 1 });
    setCpReads(
        .{ .sum = 4, .avg = 2, .min = 1, .max = 3 },
        .{ .sum = 1.5, .avg = 0.75, .min = 0.25, .max = 1.25 },
    );
    setBlockSize(5);
    setBlockReads(
        .{ .sum = 4, .avg = 2, .min = 1, .max = 3 },
        .{ .sum = 1.5, .avg = 0.75, .min = 0.25, .max = 1.25 },
    );
}
