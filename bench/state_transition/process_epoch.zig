//! Benchmark for epoch processing (works for any fork)
// https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/beacon-chain.md#epoch-processing // fulu spec
//
// Benchmarks all process_epoch operations per spec:
// - process_justification_and_finalization
// - process_inactivity_updates
// - process_rewards_and_penalties
// - process_registry_updates
// - process_slashings
// - process_eth1_data_reset
// - process_pending_deposits
// - process_pending_consolidations
// - process_effective_balance_updates
// - process_slashings_reset
// - process_randao_mixes_reset
// - process_historical_summaries_update
// - process_participation_flag_updates
// - process_sync_committee_updates
// - process_proposer_lookahead

// printf "Date: %s\nKernel: %s\nCPU: %s\nCPUs: %s\nMemory: %sGi\n" "$(date)" "$(uname -sr)" "$(sysctl -n machdep.cpu.brand_string)" "$(sysctl -n hw.ncpu)" "$(echo "$(sysctl -n hw.memsize) / 1024 / 1024 / 1024" | bc)"
// Date: Tue Dec  9 2025
// Kernel: Darwin 25.1.0
// CPU: Apple M3
// CPUs: 8
// Memory: 16Gi
//
// zbuild run bench_process_epoch -Doptimize=ReleaseFast OR zbuild run bench_process_epoch -Doptimize=ReleaseFast -- path/to/state.ssz
//

// benchmark              runs     total time     time/run (avg ± σ)     (min ... max)                p75        p99        p995
// -----------------------------------------------------------------------------------------------------------------------------
// justification_finaliza 50       2.761s         55.231ms ± 28.408ms    (42.914ms ... 212.278ms)     52.687ms   212.278ms  212.278ms
// inactivity_updates     50       3.269s         65.395ms ± 56.716ms    (44.303ms ... 420.884ms)     63.98ms    420.884ms  420.884ms
// rewards_and_penalties  50       3.054s         61.097ms ± 14.23ms     (50.545ms ... 123.211ms)     65.181ms   123.211ms  123.211ms
// registry_updates       50       2.239s         44.787ms ± 3.212ms     (42.75ms ... 63.517ms)       44.919ms   63.517ms   63.517ms
// slashings              50       2.654s         53.081ms ± 20.441ms    (43.786ms ... 168.974ms)     52.541ms   168.974ms  168.974ms
// eth1_data_reset        50       3.279s         65.583ms ± 45.885ms    (43.824ms ... 334.921ms)     63.749ms   334.921ms  334.921ms
// pending_deposits       50       2.423s         48.47ms ± 5.328ms      (44.152ms ... 66.379ms)      50.604ms   66.379ms   66.379ms
// pending_consolidations 50       2.455s         49.113ms ± 26.513ms    (40.343ms ... 230.838ms)     47.555ms   230.838ms  230.838ms
// effective_balance_upda 50       2.855s         57.108ms ± 34.315ms    (45.385ms ... 283.733ms)     54.997ms   283.733ms  283.733ms
// slashings_reset        50       2.432s         48.648ms ± 6.057ms     (43.558ms ... 76.909ms)      51.305ms   76.909ms   76.909ms
// randao_mixes_reset     50       2.396s         47.932ms ± 11.039ms    (42.822ms ... 107.591ms)     45.983ms   107.591ms  107.591ms
// historical_summaries   50       2.626s         52.521ms ± 25.266ms    (43.366ms ... 169.103ms)     50.577ms   169.103ms  169.103ms
// participation_flags    50       1.49s          29.809ms ± 3.037ms     (26.777ms ... 44.142ms)      30.766ms   44.142ms   44.142ms
// sync_committee_updates 50       1.433s         28.671ms ± 1.48ms      (26.905ms ... 35.25ms)       29.028ms   35.25ms    35.25ms
// proposer_lookahead     50       4.737s         94.747ms ± 10.154ms    (87.623ms ... 151.313ms)     97.462ms   151.313ms  151.313ms
// process_epoch          50       6.467s         129.358ms ± 49.3ms     (112.78ms ... 454.686ms)     126.361ms  454.686ms  454.686ms
// epoch(segments)        50       6.123s         122.466ms ± 11.917ms   (112.619ms ... 176.248ms)    124.022ms  176.248ms  176.248ms

// Segmented epoch breakdown:
// step                         runs     total time     time/run (avg)
// ------------------------------------------------------------------
// epoch_total                  50            3.810s       76.201ms
// justification_finalization   50            0.084ms        0.002ms
// inactivity_updates           50          121.064ms        2.421ms
// rewards_and_penalties        50          343.620ms        6.872ms
// registry_updates             50            0.004ms        0.000ms
// slashings                    50            0.002ms        0.000ms
// eth1_data_reset              50            0.003ms        0.000ms
// pending_deposits             50           51.236ms        1.025ms
// pending_consolidations       50            0.067ms        0.001ms
// effective_balance_updates    50           97.227ms        1.945ms
// slashings_reset              50            0.064ms        0.001ms
// randao_mixes_reset           50            0.017ms        0.000ms
// historical_summaries         50            0.000ms        0.000ms
// participation_flags          50            7.565ms        0.151ms
// sync_committee_updates       50            0.007ms        0.000ms
// proposer_lookahead           50            3.189s       63.781ms

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
        const epoch_cache = cloned.getEpochCache();
        const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();
        state_transition.processProposerLookahead.processProposerLookahead(allocator, cloned.state, &effective_balance_increments) catch unreachable;
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
        const total_ms = @as(f64, @floatFromInt(total_ns)) / 1_000_000.0;
        const avg_ms = @as(f64, @floatFromInt(avg_ns)) / 1_000_000.0;
        if (total_ms >= 1000.0) {
            try stdout.print("{s:<28} {d:<8} {d:>10.3}s   {d:>10.3}ms\n", .{ @tagName(step), count, total_ms / 1000.0, avg_ms });
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
            const epoch_cache = cloned.getEpochCache();
            const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();
            state_transition.processProposerLookahead.processProposerLookahead(allocator, state, &effective_balance_increments) catch unreachable;
            recordSegment(.proposer_lookahead, elapsedSince(lookahead_start));
        }

        recordSegment(.epoch_total, elapsedSince(epoch_start));
    }
};

fn loadState(comptime fork: ForkSeq, allocator: std.mem.Allocator, state_bytes: []const u8) !*BeaconStateAllForks {
    const ForkTypes = @field(types, @tagName(fork));
    const BeaconState = ForkTypes.BeaconState;

    const state_data = try allocator.create(BeaconState.Type);
    errdefer allocator.destroy(state_data);
    state_data.* = BeaconState.default_value;
    try BeaconState.deserializeFromBytes(allocator, state_bytes, state_data);

    const beacon_state = try allocator.create(BeaconStateAllForks);
    beacon_state.* = @unionInit(BeaconStateAllForks, @tagName(fork), state_data);
    return beacon_state;
}

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
    const chain_config = config.mainnet_chain_config;
    const slot = config.slotFromStateBytes(state_bytes) orelse {
        try stdout.print("Error: Could not read slot from state SSZ bytes\n", .{});
        return error.InvalidStateBytes;
    };
    const detected_fork = config.forkSeqAtSlot(chain_config, slot);
    try stdout.print("Detected fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

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

    const beacon_config = try config.BeaconConfig.init(allocator, chain_config, beacon_state.genesisValidatorsRoot());

    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);

    try state_transition.syncPubkeys(beacon_state.validators().items, pubkey_index_map, index_pubkey_cache);

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    };

    const cached_state = try CachedBeaconStateAllForks.createCachedBeaconState(allocator, beacon_state, immutable_data, .{
        .skip_sync_committee_cache = !comptime fork.isPostAltair(),
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
    if (comptime fork.isPostAltair()) {
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

    if (comptime fork.isPostElectra()) {
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

    if (comptime fork.isPostCapella()) {
        try bench.addParam("historical_summaries", &ProcessHistoricalSummariesUpdateBench{
            .cached_state = cached_state,
        }, .{});
    }

    if (comptime fork.isPostAltair()) {
        try bench.addParam("participation_flags", &ProcessParticipationFlagUpdatesBench{
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("sync_committee_updates", &ProcessSyncCommitteeUpdatesBench{
            .cached_state = cached_state,
        }, .{});
    }

    // Post-Fulu
    if (comptime fork.isPostFulu()) {
        try bench.addParam("proposer_lookahead", &ProcessProposerLookaheadBench{
            .cached_state = cached_state,
        }, .{});
    }

    // Actual processEpoch function
    try bench.addParam("process_epoch", &ProcessEpochBench{ .cached_state = cached_state }, .{});

    // Segmented benchmark (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("epoch(segments)", &ProcessEpochSegmentedBench{ .cached_state = cached_state }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
