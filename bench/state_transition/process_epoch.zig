//! Benchmark for fork-specific epoch processing.
//!
//! Uses a mainnet state at slot 13180928.
//! Run with: zig build run:bench_process_epoch -Doptimize=ReleaseFast

const std = @import("std");
const zbench = @import("zbench");
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const types = @import("consensus_types");
const config = @import("config");
const download_era_options = @import("download_era_options");
const era = @import("era");
const ForkSeq = config.ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PubkeyIndexMap = state_transition.PubkeyIndexMap(ValidatorIndex);
const slotFromStateBytes = @import("utils.zig").slotFromStateBytes;
const loadState = @import("utils.zig").loadState;

fn ProcessJustificationAndFinalizationBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processJustificationAndFinalization(
                fork,
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessInactivityUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processInactivityUpdates(
                fork,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessRewardsAndPenaltiesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processRewardsAndPenalties(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessRegistryUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processRegistryUpdates(
                fork,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessSlashingsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processSlashings(
                fork,
                allocator,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessEth1DataResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processEth1DataReset(
                fork,
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessPendingDepositsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processPendingDeposits(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessPendingConsolidationsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processPendingConsolidations(
                fork,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessEffectiveBalanceUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            _ = state_transition.processEffectiveBalanceUpdates(
                fork,
                allocator,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessSlashingsResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processSlashingsReset(
                fork,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessRandaoMixesResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processRandaoMixesReset(
                fork,
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessHistoricalSummariesUpdateBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processHistoricalSummariesUpdate(
                fork,
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessParticipationFlagUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processParticipationFlagUpdates(
                fork,
                cloned.state.castToFork(fork),
            ) catch unreachable;
        }
    };
}

fn ProcessSyncCommitteeUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processSyncCommitteeUpdates(
                fork,
                allocator,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
            ) catch unreachable;
        }
    };
}

fn ProcessProposerLookaheadBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();
            state_transition.processProposerLookahead(
                fork,
                allocator,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

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

fn ProcessEpochBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }

            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();

            state_transition.processEpoch(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cache,
            ) catch unreachable;
        }
    };
}

fn ProcessEpochSegmentedBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }

            var cache = EpochTransitionCache.init(allocator, cloned.config, cloned.getEpochCache(), cloned.state) catch unreachable;
            defer cache.deinit();

            const fork_state = cloned.state.castToFork(fork);
            const epoch_cache = cloned.getEpochCache();

            const epoch_start = std.time.nanoTimestamp();

            const jf_start = std.time.nanoTimestamp();
            state_transition.processJustificationAndFinalization(fork, fork_state, &cache) catch unreachable;
            recordSegment(.justification_finalization, elapsedSince(jf_start));

            if (comptime fork.gte(.altair)) {
                const inactivity_start = std.time.nanoTimestamp();
                state_transition.processInactivityUpdates(
                    fork,
                    cloned.config,
                    epoch_cache,
                    fork_state,
                    &cache,
                ) catch unreachable;
                recordSegment(.inactivity_updates, elapsedSince(inactivity_start));
            }

            const registry_start = std.time.nanoTimestamp();
            state_transition.processRegistryUpdates(
                fork,
                cloned.config,
                epoch_cache,
                fork_state,
                &cache,
            ) catch unreachable;
            recordSegment(.registry_updates, elapsedSince(registry_start));

            const slashings_start = std.time.nanoTimestamp();
            state_transition.processSlashings(
                fork,
                allocator,
                epoch_cache,
                fork_state,
                &cache,
            ) catch unreachable;
            recordSegment(.slashings, elapsedSince(slashings_start));

            const rewards_start = std.time.nanoTimestamp();
            state_transition.processRewardsAndPenalties(
                fork,
                allocator,
                cloned.config,
                epoch_cache,
                fork_state,
                &cache,
            ) catch unreachable;
            recordSegment(.rewards_and_penalties, elapsedSince(rewards_start));

            const eth1_start = std.time.nanoTimestamp();
            state_transition.processEth1DataReset(fork, fork_state, &cache) catch unreachable;
            recordSegment(.eth1_data_reset, elapsedSince(eth1_start));

            if (comptime fork.gte(.electra)) {
                const pending_deposits_start = std.time.nanoTimestamp();
                state_transition.processPendingDeposits(
                    fork,
                    allocator,
                    cloned.config,
                    epoch_cache,
                    fork_state,
                    &cache,
                ) catch unreachable;
                recordSegment(.pending_deposits, elapsedSince(pending_deposits_start));

                const pending_consolidations_start = std.time.nanoTimestamp();
                state_transition.processPendingConsolidations(
                    fork,
                    epoch_cache,
                    fork_state,
                    &cache,
                ) catch unreachable;
                recordSegment(.pending_consolidations, elapsedSince(pending_consolidations_start));
            }

            const eb_start = std.time.nanoTimestamp();
            _ = state_transition.processEffectiveBalanceUpdates(
                fork,
                allocator,
                epoch_cache,
                fork_state,
                &cache,
            ) catch unreachable;
            recordSegment(.effective_balance_updates, elapsedSince(eb_start));

            const slashings_reset_start = std.time.nanoTimestamp();
            state_transition.processSlashingsReset(
                fork,
                epoch_cache,
                fork_state,
                &cache,
            ) catch unreachable;
            recordSegment(.slashings_reset, elapsedSince(slashings_reset_start));

            const randao_reset_start = std.time.nanoTimestamp();
            state_transition.processRandaoMixesReset(fork, fork_state, &cache) catch unreachable;
            recordSegment(.randao_mixes_reset, elapsedSince(randao_reset_start));

            if (comptime fork.gte(.capella)) {
                const historical_summaries_start = std.time.nanoTimestamp();
                state_transition.processHistoricalSummariesUpdate(fork, fork_state, &cache) catch unreachable;
                recordSegment(.historical_summaries, elapsedSince(historical_summaries_start));
            } else {
                const historical_roots_start = std.time.nanoTimestamp();
                state_transition.processHistoricalRootsUpdate(fork, fork_state, &cache) catch unreachable;
                recordSegment(.historical_roots, elapsedSince(historical_roots_start));
            }

            if (comptime fork == .phase0) {
                const participation_record_start = std.time.nanoTimestamp();
                state_transition.processParticipationRecordUpdates(fork, fork_state) catch unreachable;
                recordSegment(.participation_record, elapsedSince(participation_record_start));
            } else {
                const participation_flag_start = std.time.nanoTimestamp();
                state_transition.processParticipationFlagUpdates(fork, fork_state) catch unreachable;
                recordSegment(.participation_flags, elapsedSince(participation_flag_start));
            }

            if (comptime fork.gte(.altair)) {
                const sync_updates_start = std.time.nanoTimestamp();
                state_transition.processSyncCommitteeUpdates(
                    fork,
                    allocator,
                    epoch_cache,
                    fork_state,
                ) catch unreachable;
                recordSegment(.sync_committee_updates, elapsedSince(sync_updates_start));
            }

            if (comptime fork == .fulu) {
                const lookahead_start = std.time.nanoTimestamp();
                state_transition.processProposerLookahead(
                    fork,
                    allocator,
                    epoch_cache,
                    fork_state,
                    &cache,
                ) catch unreachable;
                recordSegment(.proposer_lookahead, elapsedSince(lookahead_start));
            }

            recordSegment(.epoch_total, elapsedSince(epoch_start));
        }
    };
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();
    var pool = try Node.Pool.init(allocator, 10_000_000);
    defer pool.deinit();

    // Use download_era_options.era_files[0] for state
    const era_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ download_era_options.era_out_dir, download_era_options.era_files[0] },
    );
    defer allocator.free(era_path);

    var era_reader = try era.Reader.open(allocator, config.mainnet.config, era_path);
    defer era_reader.close(allocator);

    const state_bytes = try era_reader.readSerializedState(allocator, null);
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
            return runBenchmark(fork, allocator, &pool, stdout, state_bytes, chain_config);
        }
    }
    return error.NoBenchmarkRan;
}

fn runBenchmark(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    stdout: anytype,
    state_bytes: []const u8,
    chain_config: config.ChainConfig,
) !void {
    const beacon_state = try loadState(fork, allocator, pool, state_bytes);
    try stdout.print("State deserialized: slot={}, validators={}\n", .{
        try beacon_state.slot(),
        try beacon_state.validatorsCount(),
    });

    const beacon_config = config.BeaconConfig.init(chain_config, (try beacon_state.genesisValidatorsRoot()).*);

    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);

    const validators = try beacon_state.validatorsSlice(allocator);
    defer allocator.free(validators);

    try state_transition.syncPubkeys(validators, pubkey_index_map, index_pubkey_cache);

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    };

    const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, beacon_state, immutable_data, .{
        .skip_sync_committee_cache = !comptime fork.gte(.altair),
        .skip_sync_pubkeys = false,
    });

    try stdout.print("Cached state created at slot {}\n", .{try cached_state.state.slot()});
    try stdout.print("\nStarting process_epoch benchmarks for {s} fork...\n\n", .{@tagName(fork)});

    var bench = zbench.Benchmark.init(allocator, .{ .iterations = 50 });
    defer bench.deinit();

    try bench.addParam("justification_finalization", &ProcessJustificationAndFinalizationBench(fork){
        .cached_state = cached_state,
    }, .{});

    if (comptime fork.gte(.altair)) {
        try bench.addParam("inactivity_updates", &ProcessInactivityUpdatesBench(fork){
            .cached_state = cached_state,
        }, .{});
    }

    try bench.addParam("rewards_and_penalties", &ProcessRewardsAndPenaltiesBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("registry_updates", &ProcessRegistryUpdatesBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("slashings", &ProcessSlashingsBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("eth1_data_reset", &ProcessEth1DataResetBench(fork){
        .cached_state = cached_state,
    }, .{});

    if (comptime fork.gte(.electra)) {
        try bench.addParam("pending_deposits", &ProcessPendingDepositsBench(fork){
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("pending_consolidations", &ProcessPendingConsolidationsBench(fork){
            .cached_state = cached_state,
        }, .{});
    }

    try bench.addParam("effective_balance_updates", &ProcessEffectiveBalanceUpdatesBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("slashings_reset", &ProcessSlashingsResetBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("randao_mixes_reset", &ProcessRandaoMixesResetBench(fork){
        .cached_state = cached_state,
    }, .{});

    if (comptime fork.gte(.capella)) {
        try bench.addParam("historical_summaries", &ProcessHistoricalSummariesUpdateBench(fork){
            .cached_state = cached_state,
        }, .{});
    }

    if (comptime fork.gte(.altair)) {
        try bench.addParam("participation_flags", &ProcessParticipationFlagUpdatesBench(fork){
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("sync_committee_updates", &ProcessSyncCommitteeUpdatesBench(fork){
            .cached_state = cached_state,
        }, .{});
    }

    if (comptime fork.gte(.fulu)) {
        try bench.addParam("proposer_lookahead", &ProcessProposerLookaheadBench(fork){
            .cached_state = cached_state,
        }, .{});
    }

    // Non-segmented
    try bench.addParam("epoch(non-segmented)", &ProcessEpochBench(fork){ .cached_state = cached_state }, .{});

    // Segmented (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("epoch(segmented)", &ProcessEpochSegmentedBench(fork){ .cached_state = cached_state }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
