//! Benchmark for fork-specific epoch processing.
//!
//! Uses a mainnet state at slot 13180928.
//! Run with: zig build run:bench_process_epoch -Doptimize=ReleaseFast [-- /path/to/state.ssz]

const std = @import("std");
const zbench = @import("zbench");
const state_transition = @import("state_transition");
const types = @import("consensus_types");
const config = @import("config");
const ForkSeq = config.ForkSeq;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PubkeyIndexMap = state_transition.PubkeyIndexMap(ValidatorIndex);
const slotFromStateBytes = @import("utils.zig").slotFromStateBytes;
const loadState = @import("utils.zig").loadState;

const ProcessJustificationAndFinalizationBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessJustificationAndFinalizationBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processJustificationAndFinalization(cloned, cache) catch unreachable;
    }
};

const ProcessInactivityUpdatesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessInactivityUpdatesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processInactivityUpdates(cloned, cache) catch unreachable;
    }
};

const ProcessRewardsAndPenaltiesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessRewardsAndPenaltiesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processRewardsAndPenalties(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessRegistryUpdatesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessRegistryUpdatesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processRegistryUpdates(cloned, cache) catch unreachable;
    }
};

const ProcessSlashingsBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessSlashingsBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processSlashings(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessEth1DataResetBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessEth1DataResetBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processEth1DataReset(allocator, cloned, cache);
    }
};

const ProcessPendingDepositsBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessPendingDepositsBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processPendingDeposits(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessPendingConsolidationsBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessPendingConsolidationsBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processPendingConsolidations(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessEffectiveBalanceUpdatesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessEffectiveBalanceUpdatesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        _ = state_transition.processEffectiveBalanceUpdates(cloned, cache) catch unreachable;
    }
};

const ProcessSlashingsResetBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessSlashingsResetBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processSlashingsReset(cloned, cache);
    }
};

const ProcessRandaoMixesResetBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessRandaoMixesResetBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processRandaoMixesReset(cloned, cache);
    }
};

const ProcessHistoricalSummariesUpdateBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessHistoricalSummariesUpdateBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }
        state_transition.processHistoricalSummariesUpdate(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessParticipationFlagUpdatesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessParticipationFlagUpdatesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        state_transition.processParticipationFlagUpdates(allocator, cloned) catch unreachable;
    }
};

const ProcessSyncCommitteeUpdatesBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessSyncCommitteeUpdatesBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        state_transition.processSyncCommitteeUpdates(allocator, cloned) catch unreachable;
    }
};

const ProcessProposerLookaheadBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessProposerLookaheadBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer cache.deinit();
        state_transition.processProposerLookahead(allocator, cloned, cache) catch unreachable;
    }
};

const Step = enum {
    epoch_total,
    justification_finalization,
    inactivity_updates,
    rewards_and_penalties,
    registry_updates,
    slashings,
    eth1_data_reset,
    pending_deposits,
    pending_consolidations,
    effective_balance_updates,
    slashings_reset,
    randao_mixes_reset,
    historical_summaries,
    historical_roots,
    participation_flags,
    participation_record,
    sync_committee_updates,
    proposer_lookahead,
};

const step_count = std.enums.values(Step).len;
var step_durations_ns: [step_count]u128 = [_]u128{0} ** step_count;
var step_run_counts: [step_count]u64 = [_]u64{0} ** step_count;

fn resetSegmentStats() void {
    for (&step_durations_ns) |*v| v.* = 0;
    for (&step_run_counts) |*v| v.* = 0;
}

fn recordSegment(step: Step, duration_ns: u64) void {
    const idx = @intFromEnum(step);
    step_durations_ns[idx] += duration_ns;
    step_run_counts[idx] += 1;
}

fn elapsedSince(start: i128) u64 {
    return @as(u64, @intCast(std.time.nanoTimestamp() - start));
}

fn printSegmentStats(stdout: anytype) !void {
    try stdout.print("\nSegmented epoch breakdown:\n", .{});
    try stdout.print("{s:<28} {s:<8} {s:<14} {s:<14}\n", .{ "step", "runs", "total time", "time/run (avg)" });
    try stdout.print("{s:-<66}\n", .{""});
    for (std.enums.values(Step)) |step| {
        const idx = @intFromEnum(step);
        const count = step_run_counts[idx];
        if (count == 0) continue;
        const total_ns = step_durations_ns[idx];
        const avg_ns: u128 = total_ns / count;
        const total_ms = @as(f64, @floatFromInt(total_ns)) / std.time.ns_per_ms;
        const avg_ms = @as(f64, @floatFromInt(avg_ns)) / std.time.ns_per_ms;
        const total_s = total_ms / std.time.ms_per_s;
        if (total_ms >= std.time.ms_per_s) {
            try stdout.print("{s:<28} {d:<8} {d:>10.3}s   {d:>10.3}ms\n", .{ @tagName(step), count, total_s, avg_ms });
        } else {
            try stdout.print("{s:<28} {d:<8} {d:>10.3}ms   {d:>10.3}ms\n", .{ @tagName(step), count, total_ms, avg_ms });
        }
    }
    try stdout.print("\n", .{});
}

const ProcessEpochBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessEpochBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }

        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }

        state_transition.processEpoch(allocator, cloned, cache) catch unreachable;
    }
};

const ProcessEpochSegmentedBench = struct {
    cached_state: *CachedBeaconStateAllForks,

    pub fn run(self: ProcessEpochSegmentedBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }

        var cache = EpochTransitionCache.init(allocator, cloned) catch unreachable;
        defer {
            cache.deinit();
            allocator.destroy(cache);
        }

        const state = cloned.state;

        const epoch_start = std.time.nanoTimestamp();

        const jf_start = std.time.nanoTimestamp();
        state_transition.processJustificationAndFinalization(cloned, cache) catch unreachable;
        recordSegment(.justification_finalization, elapsedSince(jf_start));

        if (state.isPostAltair()) {
            const inactivity_start = std.time.nanoTimestamp();
            state_transition.processInactivityUpdates(cloned, cache) catch unreachable;
            recordSegment(.inactivity_updates, elapsedSince(inactivity_start));
        }

        const registry_start = std.time.nanoTimestamp();
        state_transition.processRegistryUpdates(cloned, cache) catch unreachable;
        recordSegment(.registry_updates, elapsedSince(registry_start));

        const slashings_start = std.time.nanoTimestamp();
        state_transition.processSlashings(allocator, cloned, cache) catch unreachable;
        recordSegment(.slashings, elapsedSince(slashings_start));

        const rewards_start = std.time.nanoTimestamp();
        state_transition.processRewardsAndPenalties(allocator, cloned, cache) catch unreachable;
        recordSegment(.rewards_and_penalties, elapsedSince(rewards_start));

        const eth1_start = std.time.nanoTimestamp();
        state_transition.processEth1DataReset(allocator, cloned, cache);
        recordSegment(.eth1_data_reset, elapsedSince(eth1_start));

        if (state.isPostElectra()) {
            const pending_deposits_start = std.time.nanoTimestamp();
            state_transition.processPendingDeposits(allocator, cloned, cache) catch unreachable;
            recordSegment(.pending_deposits, elapsedSince(pending_deposits_start));

            const pending_consolidations_start = std.time.nanoTimestamp();
            state_transition.processPendingConsolidations(allocator, cloned, cache) catch unreachable;
            recordSegment(.pending_consolidations, elapsedSince(pending_consolidations_start));
        }

        const eb_start = std.time.nanoTimestamp();
        _ = state_transition.processEffectiveBalanceUpdates(cloned, cache) catch unreachable;
        recordSegment(.effective_balance_updates, elapsedSince(eb_start));

        const slashings_reset_start = std.time.nanoTimestamp();
        state_transition.processSlashingsReset(cloned, cache);
        recordSegment(.slashings_reset, elapsedSince(slashings_reset_start));

        const randao_reset_start = std.time.nanoTimestamp();
        state_transition.processRandaoMixesReset(cloned, cache);
        recordSegment(.randao_mixes_reset, elapsedSince(randao_reset_start));

        if (state.isPostCapella()) {
            const historical_summaries_start = std.time.nanoTimestamp();
            state_transition.processHistoricalSummariesUpdate(allocator, cloned, cache) catch unreachable;
            recordSegment(.historical_summaries, elapsedSince(historical_summaries_start));
        } else {
            const historical_roots_start = std.time.nanoTimestamp();
            state_transition.processHistoricalRootsUpdate(allocator, cloned, cache) catch unreachable;
            recordSegment(.historical_roots, elapsedSince(historical_roots_start));
        }

        if (state.isPhase0()) {
            const participation_record_start = std.time.nanoTimestamp();
            state_transition.processParticipationRecordUpdates(allocator, cloned);
            recordSegment(.participation_record, elapsedSince(participation_record_start));
        } else {
            const participation_flag_start = std.time.nanoTimestamp();
            state_transition.processParticipationFlagUpdates(allocator, cloned) catch unreachable;
            recordSegment(.participation_flags, elapsedSince(participation_flag_start));
        }

        if (state.isPostAltair()) {
            const sync_updates_start = std.time.nanoTimestamp();
            state_transition.processSyncCommitteeUpdates(allocator, cloned) catch unreachable;
            recordSegment(.sync_committee_updates, elapsedSince(sync_updates_start));
        }

        if (state.isFulu()) {
            const lookahead_start = std.time.nanoTimestamp();
            state_transition.processProposerLookahead(allocator, cloned, cache) catch unreachable;
            recordSegment(.proposer_lookahead, elapsedSince(lookahead_start));
        }

        recordSegment(.epoch_total, elapsedSince(epoch_start));
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout = std.io.getStdOut().writer();

    // Parse CLI args for state file path
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const state_path = if (args.len > 1) args[1] else "bench/state_transition/state.ssz";

    try stdout.print("Loading state from {s}...\n", .{state_path});

    const state_file = try std.fs.cwd().openFile(state_path, .{});
    defer state_file.close();
    const state_bytes = try state_file.readToEndAlloc(allocator, 10_000_000_000);
    defer allocator.free(state_bytes);

    try stdout.print("State file loaded: {} bytes\n", .{state_bytes.len});

    // Detect fork from state SSZ bytes
    const chain_config = config.mainnet.chain_config;
    const slot = slotFromStateBytes(state_bytes);
    const detected_fork = config.mainnet.config.forkSeq(slot);
    try stdout.print("Benchmarking processEpoch with state at fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

    // Dispatch to fork-specific loading
    inline for (comptime std.enums.values(ForkSeq)) |fork| {
        if (detected_fork == fork) {
            return runBenchmark(fork, allocator, stdout, state_bytes, chain_config);
        }
    }
    return error.NoBenchmarkRan;
}

fn runBenchmark(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    stdout: anytype,
    state_bytes: []const u8,
    chain_config: config.ChainConfig,
) !void {
    const beacon_state = try loadState(fork, allocator, state_bytes);
    try stdout.print("State deserialized: slot={}, validators={}\n", .{
        beacon_state.slot(),
        beacon_state.validators().items.len,
    });

    const beacon_config = config.BeaconConfig.init(chain_config, beacon_state.genesisValidatorsRoot());

    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);

    try state_transition.syncPubkeys(beacon_state.validators().items, pubkey_index_map, index_pubkey_cache);

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    };

    const cached_state = try CachedBeaconStateAllForks.createCachedBeaconState(allocator, beacon_state, immutable_data, .{
        .skip_sync_committee_cache = !comptime fork.gte(.altair),
        .skip_sync_pubkeys = false,
    });

    try stdout.print("Cached state created at slot {}\n", .{cached_state.state.slot()});
    try stdout.print("\nStarting process_epoch benchmarks for {s} fork...\n\n", .{@tagName(fork)});

    var bench = zbench.Benchmark.init(allocator, .{ .iterations = 50 });
    defer bench.deinit();

    try bench.addParam("justification_finalization", &ProcessJustificationAndFinalizationBench{
        .cached_state = cached_state,
    }, .{});

    // Post-Altair
    if (comptime fork.gte(.altair)) {
        try bench.addParam("inactivity_updates", &ProcessInactivityUpdatesBench{
            .cached_state = cached_state,
        }, .{});
    }

    try bench.addParam("rewards_and_penalties", &ProcessRewardsAndPenaltiesBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("registry_updates", &ProcessRegistryUpdatesBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("slashings", &ProcessSlashingsBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("eth1_data_reset", &ProcessEth1DataResetBench{
        .cached_state = cached_state,
    }, .{});

    if (comptime fork.gte(.electra)) {
        try bench.addParam("pending_deposits", &ProcessPendingDepositsBench{
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("pending_consolidations", &ProcessPendingConsolidationsBench{
            .cached_state = cached_state,
        }, .{});
    }

    try bench.addParam("effective_balance_updates", &ProcessEffectiveBalanceUpdatesBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("slashings_reset", &ProcessSlashingsResetBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("randao_mixes_reset", &ProcessRandaoMixesResetBench{
        .cached_state = cached_state,
    }, .{});

    if (comptime fork.gte(.capella)) {
        try bench.addParam("historical_summaries", &ProcessHistoricalSummariesUpdateBench{
            .cached_state = cached_state,
        }, .{});
    }

    if (comptime fork.gte(.altair)) {
        try bench.addParam("participation_flags", &ProcessParticipationFlagUpdatesBench{
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("sync_committee_updates", &ProcessSyncCommitteeUpdatesBench{
            .cached_state = cached_state,
        }, .{});
    }

    // Post-Fulu
    if (comptime fork.gte(.fulu)) {
        try bench.addParam("proposer_lookahead", &ProcessProposerLookaheadBench{
            .cached_state = cached_state,
        }, .{});
    }

    // Non-segmented
    try bench.addParam("epoch(non-segmented)", &ProcessEpochBench{ .cached_state = cached_state }, .{});

    // Segmented (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("epoch(segmented)", &ProcessEpochSegmentedBench{ .cached_state = cached_state }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
