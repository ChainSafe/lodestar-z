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
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ForkSeq = config.ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const slotFromStateBytes = @import("utils.zig").slotFromStateBytes;
const loadState = @import("utils.zig").loadState;

fn ProcessJustificationAndFinalizationBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;
            state_transition.processJustificationAndFinalization(
                fork,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessBeforeProcessEpochBench(comptime fork: ForkSeq) type {
    comptime _ = fork;
    return struct {
        cached_state: *CachedBeaconState,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            cloned.state.commit() catch unreachable;

            var epoch_transition_cache = EpochTransitionCache.init(
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state,
            ) catch unreachable;
            defer epoch_transition_cache.deinit();
        }
    };
}

fn ProcessInactivityUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;
            state_transition.processInactivityUpdates(
                fork,
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessRewardsAndPenaltiesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;
            const validator_count = cloned.state.validatorsCount() catch unreachable;
            cache.syncRewardPenaltyLengths(validator_count) catch unreachable;
            state_transition.processRewardsAndPenalties(
                fork,
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
                null,
            ) catch unreachable;
        }
    };
}

fn ProcessRegistryUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;
            state_transition.processRegistryUpdates(
                fork,
                cloned.config,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessSlashingsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;
            _ = state_transition.processSlashings(
                fork,
                allocator,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
                true,
            ) catch unreachable;
        }
    };
}

fn ProcessEth1DataResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processEth1DataReset(
                fork,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessPendingDepositsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processPendingDeposits(
                fork,
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessPendingConsolidationsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processPendingConsolidations(
                fork,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessEffectiveBalanceUpdatesBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            _ = state_transition.processEffectiveBalanceUpdates(
                fork,
                allocator,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessSlashingsResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processSlashingsReset(
                fork,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessRandaoMixesResetBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processRandaoMixesReset(
                fork,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

fn ProcessHistoricalSummariesUpdateBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processHistoricalSummariesUpdate(
                fork,
                cloned.state.castToFork(fork),
                cache,
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
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }

            state_transition.processSyncCommitteeUpdates(
                fork,
                allocator,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
            ) catch unreachable;
        }
    };
}

fn ProcessProposerLookaheadBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        epoch_transition_cache: *EpochTransitionCache,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const cache = self.epoch_transition_cache;

            state_transition.processProposerLookahead(
                fork,
                allocator,
                cloned.epoch_cache,
                cloned.state.castToFork(fork),
                cache,
            ) catch unreachable;
        }
    };
}

const Step = enum {
    epoch_total,
    before_process_epoch,
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

fn printSegmentStats() void {
    std.debug.print("\nSegmented epoch breakdown:\n", .{});
    std.debug.print("{s:<28} {s:<8} {s:<14} {s:<14}\n", .{ "step", "runs", "total time", "time/run (avg)" });
    std.debug.print("{s:-<66}\n", .{""});
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
            std.debug.print("{s:<28} {d:<8} {d:>10.3}s   {d:>10.3}ms\n", .{ @tagName(step), count, total_s, avg_ms });
        } else {
            std.debug.print("{s:<28} {d:<8} {d:>10.3}ms   {d:>10.3}ms\n", .{ @tagName(step), count, total_ms, avg_ms });
        }
    }
    std.debug.print("\n", .{});
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
            var cache = EpochTransitionCache.init(
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state,
            ) catch unreachable;
            defer cache.deinit();

            const validator_count = cloned.state.validatorsCount() catch unreachable;
            cache.syncRewardPenaltyLengths(validator_count) catch unreachable;

            state_transition.processEpoch(
                fork,
                allocator,
                cloned.config,
                cloned.epoch_cache,
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
            const epoch_start = std.time.nanoTimestamp();

            const before_start = std.time.nanoTimestamp();
            cloned.state.commit() catch unreachable;
            var cache_val = EpochTransitionCache.init(
                allocator,
                cloned.config,
                cloned.epoch_cache,
                cloned.state,
            ) catch unreachable;
            defer cache_val.deinit();
            const cache = &cache_val;
            recordSegment(.before_process_epoch, elapsedSince(before_start));

            const fork_state = cloned.state.castToFork(fork);
            const epoch_cache = cloned.epoch_cache;

            const jf_start = std.time.nanoTimestamp();
            state_transition.processJustificationAndFinalization(fork, fork_state, cache) catch unreachable;
            recordSegment(.justification_finalization, elapsedSince(jf_start));

            if (comptime fork.gte(.altair)) {
                const inactivity_start = std.time.nanoTimestamp();
                state_transition.processInactivityUpdates(
                    fork,
                    allocator,
                    cloned.config,
                    epoch_cache,
                    fork_state,
                    cache,
                ) catch unreachable;
                recordSegment(.inactivity_updates, elapsedSince(inactivity_start));
            }

            const registry_start = std.time.nanoTimestamp();
            state_transition.processRegistryUpdates(
                fork,
                cloned.config,
                epoch_cache,
                fork_state,
                cache,
            ) catch unreachable;
            recordSegment(.registry_updates, elapsedSince(registry_start));

            const slashings_start = std.time.nanoTimestamp();
            const slashing_penalties = state_transition.processSlashings(
                fork,
                allocator,
                epoch_cache,
                fork_state,
                cache,
                false,
            ) catch unreachable;
            recordSegment(.slashings, elapsedSince(slashings_start));

            const rewards_start = std.time.nanoTimestamp();
            state_transition.processRewardsAndPenalties(
                fork,
                allocator,
                cloned.config,
                epoch_cache,
                fork_state,
                cache,
                slashing_penalties,
            ) catch unreachable;
            recordSegment(.rewards_and_penalties, elapsedSince(rewards_start));

            const eth1_start = std.time.nanoTimestamp();
            state_transition.processEth1DataReset(fork, fork_state, cache) catch unreachable;
            recordSegment(.eth1_data_reset, elapsedSince(eth1_start));

            if (comptime fork.gte(.electra)) {
                const pending_deposits_start = std.time.nanoTimestamp();
                state_transition.processPendingDeposits(
                    fork,
                    allocator,
                    cloned.config,
                    epoch_cache,
                    fork_state,
                    cache,
                ) catch unreachable;
                recordSegment(.pending_deposits, elapsedSince(pending_deposits_start));

                const pending_consolidations_start = std.time.nanoTimestamp();
                state_transition.processPendingConsolidations(
                    fork,
                    epoch_cache,
                    fork_state,
                    cache,
                ) catch unreachable;
                recordSegment(.pending_consolidations, elapsedSince(pending_consolidations_start));
            }

            const eb_start = std.time.nanoTimestamp();
            _ = state_transition.processEffectiveBalanceUpdates(
                fork,
                allocator,
                epoch_cache,
                fork_state,
                cache,
            ) catch unreachable;
            recordSegment(.effective_balance_updates, elapsedSince(eb_start));

            const slashings_reset_start = std.time.nanoTimestamp();
            state_transition.processSlashingsReset(
                fork,
                epoch_cache,
                fork_state,
                cache,
            ) catch unreachable;
            recordSegment(.slashings_reset, elapsedSince(slashings_reset_start));

            const randao_reset_start = std.time.nanoTimestamp();
            state_transition.processRandaoMixesReset(fork, fork_state, cache) catch unreachable;
            recordSegment(.randao_mixes_reset, elapsedSince(randao_reset_start));

            if (comptime fork.gte(.capella)) {
                const historical_summaries_start = std.time.nanoTimestamp();
                state_transition.processHistoricalSummariesUpdate(fork, fork_state, cache) catch unreachable;
                recordSegment(.historical_summaries, elapsedSince(historical_summaries_start));
            } else {
                const historical_roots_start = std.time.nanoTimestamp();
                state_transition.processHistoricalRootsUpdate(fork, fork_state, cache) catch unreachable;
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
                    cache,
                ) catch unreachable;
                recordSegment(.proposer_lookahead, elapsedSince(lookahead_start));
            }

            recordSegment(.epoch_total, elapsedSince(epoch_start));
        }
    };
}

fn loadStateBytesFromConfiguredEraFiles(allocator: std.mem.Allocator, stdout: anytype) ![]const u8 {
    if (download_era_options.era_files.len == 0) return error.NoEraFilesConfigured;

    var last_err: ?anyerror = null;

    for (download_era_options.era_files) |era_file| {
        const era_path = try std.fs.path.join(
            allocator,
            &[_][]const u8{ download_era_options.era_out_dir, era_file },
        );
        defer allocator.free(era_path);

        var era_reader = era.Reader.open(allocator, config.mainnet.config, era_path) catch |err| {
            last_err = err;
            std.debug.print("Skipping ERA file {s}: {s}\n", .{ era_path, @errorName(err) });
            continue;
        };
        defer era_reader.close(allocator);

        const state_bytes = era_reader.readSerializedState(allocator, null) catch |err| {
            last_err = err;
            std.debug.print("Skipping ERA file {s}: {s}\n", .{ era_path, @errorName(err) });
            continue;
        };

        std.debug.print("State file loaded from {s}: {} bytes\n", .{ era_path, state_bytes.len });
        return state_bytes;
    }

    if (last_err) |err| return err;
    return error.NoUsableEraStateFound;
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);

    const allocator = gpa.allocator();
    _ = init; // TODO: wire up Io for bench output
    var pool = try Node.Pool.init(allocator, 10_000_000);
    defer pool.deinit();

    const state_bytes = try loadStateBytesFromConfiguredEraFiles(allocator, stdout);
    defer allocator.free(state_bytes);

    // Detect fork from state SSZ bytes
    const chain_config = config.mainnet.chain_config;
    const slot = slotFromStateBytes(state_bytes);
    const detected_fork = config.mainnet.config.forkSeq(slot);
    std.debug.print("Benchmarking processEpoch with state at fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

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
    defer state_transition.deinitStateTransition();

    var beacon_state: ?*AnyBeaconState = try loadState(fork, allocator, pool, state_bytes);
    defer if (beacon_state) |state| {
        state.deinit();
        allocator.destroy(state);
    };

    std.debug.print("State deserialized: slot={}, validators={}\n", .{
        try beacon_state.?.slot(),
        try beacon_state.?.validatorsCount(),
    });

    const beacon_config = config.BeaconConfig.init(chain_config, (try beacon_state.?.genesisValidatorsRoot()).*);

    var pubkey_index_map = state_transition.PubkeyIndexMap.init(allocator);
    defer pubkey_index_map.deinit();

    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);
    defer {
        index_pubkey_cache.deinit();
        allocator.destroy(index_pubkey_cache);
    }

    const validators = try beacon_state.?.validatorsSlice(allocator);
    defer allocator.free(validators);

    try state_transition.syncPubkeys(validators, &pubkey_index_map, index_pubkey_cache);

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = &pubkey_index_map,
    };

    const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, beacon_state.?, immutable_data, .{
        .skip_sync_committee_cache = !comptime fork.gte(.altair),
        .skip_sync_pubkeys = false,
    });
    beacon_state = null;
    defer {
        cached_state.deinit();
        allocator.destroy(cached_state);
    }

    var epoch_transition_cache = try EpochTransitionCache.init(
        allocator,
        cached_state.config,
        cached_state.epoch_cache,
        cached_state.state,
    );
    defer epoch_transition_cache.deinit();

    std.debug.print("Cached state created at slot {}\n", .{try cached_state.state.slot()});
    std.debug.print("\nStarting process_epoch benchmarks for {s} fork...\n\n", .{@tagName(fork)});

    var bench = zbench.Benchmark.init(allocator, .{ .iterations = 50 });
    defer bench.deinit();

    try bench.addParam("before_process_epoch", &ProcessBeforeProcessEpochBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("justification_finalization", &ProcessJustificationAndFinalizationBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    if (comptime fork.gte(.altair)) {
        try bench.addParam("inactivity_updates", &ProcessInactivityUpdatesBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});
    }

    try bench.addParam("rewards_and_penalties", &ProcessRewardsAndPenaltiesBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    try bench.addParam("registry_updates", &ProcessRegistryUpdatesBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    try bench.addParam("slashings", &ProcessSlashingsBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    try bench.addParam("eth1_data_reset", &ProcessEth1DataResetBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    if (comptime fork.gte(.electra)) {
        try bench.addParam("pending_deposits", &ProcessPendingDepositsBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});

        try bench.addParam("pending_consolidations", &ProcessPendingConsolidationsBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});
    }

    try bench.addParam("effective_balance_updates", &ProcessEffectiveBalanceUpdatesBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    try bench.addParam("slashings_reset", &ProcessSlashingsResetBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    try bench.addParam("randao_mixes_reset", &ProcessRandaoMixesResetBench(fork){
        .cached_state = cached_state,
        .epoch_transition_cache = &epoch_transition_cache,
    }, .{});

    if (comptime fork.gte(.capella)) {
        try bench.addParam("historical_summaries", &ProcessHistoricalSummariesUpdateBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});
    }

    if (comptime fork.gte(.altair)) {
        try bench.addParam("participation_flags", &ProcessParticipationFlagUpdatesBench(fork){
            .cached_state = cached_state,
        }, .{});

        try bench.addParam("sync_committee_updates", &ProcessSyncCommitteeUpdatesBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});
    }

    if (comptime fork.gte(.fulu)) {
        try bench.addParam("proposer_lookahead", &ProcessProposerLookaheadBench(fork){
            .cached_state = cached_state,
            .epoch_transition_cache = &epoch_transition_cache,
        }, .{});
    }

    // Non-segmented
    try bench.addParam("epoch(non-segmented)", &ProcessEpochBench(fork){
        .cached_state = cached_state,
    }, .{});

    // Segmented (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("epoch(segmented)", &ProcessEpochSegmentedBench(fork){
        .cached_state = cached_state,
    }, .{});

    try bench.run(init.io, std.Io.File.stdout());
    printSegmentStats();
}
