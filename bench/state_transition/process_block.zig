//! Benchmark for fork-specific block processing.
//!
//! Uses a mainnet state at slot 13180928 and block at slot 13180929.
//! Run with: zig build run:bench_process_block -Doptimize=ReleaseFast [-- /path/to/state.ssz /path/to/block.ssz]

const std = @import("std");
const zbench = @import("zbench");
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const types = @import("consensus_types");
const config = @import("config");
const fork_types = @import("fork_types");
const download_era_options = @import("download_era_options");
const era = @import("era");
const preset = state_transition.preset;
const ForkSeq = config.ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const BeaconBlock = fork_types.BeaconBlock;
const BeaconBlockBody = fork_types.BeaconBlockBody;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PubkeyIndexMap = state_transition.PubkeyIndexMap(ValidatorIndex);
const Withdrawals = types.capella.Withdrawals.Type;
const WithdrawalsResult = state_transition.WithdrawalsResult;
const BlockExternalData = state_transition.BlockExternalData;
const slotFromStateBytes = @import("utils.zig").slotFromStateBytes;
const loadState = @import("utils.zig").loadState;
const loadBlock = @import("utils.zig").loadBlock;

const BenchOpts = struct {
    verify_signature: bool,
};

fn ProcessBlockHeaderBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        block: *const BeaconBlock(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processBlockHeader(
                fork,
                allocator,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                .full,
                self.block,
            ) catch unreachable;
        }
    };
}

fn ProcessWithdrawalsBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }

            var withdrawals_result = WithdrawalsResult{
                .withdrawals = Withdrawals.initCapacity(allocator, preset.MAX_WITHDRAWALS_PER_PAYLOAD) catch unreachable,
            };
            defer withdrawals_result.withdrawals.deinit(allocator);

            var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
            defer withdrawal_balances.deinit();

            const state = cloned.state.castToFork(fork);
            state_transition.getExpectedWithdrawals(
                fork,
                allocator,
                cloned.getEpochCache(),
                state,
                &withdrawals_result,
                &withdrawal_balances,
            ) catch unreachable;

            const actual_withdrawals = self.body.executionPayload().inner.withdrawals;
            var payload_withdrawals_root: [32]u8 = undefined;
            types.capella.Withdrawals.hashTreeRoot(allocator, &actual_withdrawals, &payload_withdrawals_root) catch unreachable;

            state_transition.processWithdrawals(
                fork,
                allocator,
                state,
                withdrawals_result,
                payload_withdrawals_root,
            ) catch unreachable;
        }
    };
}

fn ProcessExecutionPayloadBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
            state_transition.processExecutionPayload(
                fork,
                allocator,
                cloned.config,
                cloned.state.castToFork(fork),
                cloned.getEpochCache().epoch,
                .full,
                self.body,
                external_data,
            ) catch unreachable;
        }
    };
}

fn ProcessRandaoBench(comptime fork: ForkSeq, comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        block: *const BeaconBlock(.full, fork),
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processRandao(
                fork,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                .full,
                self.body,
                self.block.proposerIndex(),
                opts.verify_signature,
            ) catch unreachable;
        }
    };
}

fn ProcessEth1DataBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processEth1Data(
                fork,
                cloned.state.castToFork(fork),
                self.body.eth1Data(),
            ) catch unreachable;
        }
    };
}

fn ProcessOperationsBench(comptime fork: ForkSeq, comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processOperations(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cloned.slashings_cache,
                .full,
                self.body,
                .{ .verify_signature = opts.verify_signature },
            ) catch unreachable;
        }
    };
}

fn ProcessSyncAggregateBench(comptime fork: ForkSeq, comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            state_transition.processSyncAggregate(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                self.body.syncAggregate(),
                opts.verify_signature,
            ) catch unreachable;
        }
    };
}

fn ProcessBlockBench(comptime fork: ForkSeq, comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        block: *const BeaconBlock(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
            state_transition.processBlock(
                fork,
                allocator,
                cloned.config,
                cloned.getEpochCache(),
                cloned.state.castToFork(fork),
                &cloned.slashings_cache,
                .full,
                self.block,
                external_data,
                .{ .verify_signature = opts.verify_signature },
            ) catch unreachable;
        }
    };
}

/// We segregate block processing into `Step`s for more insight into the perf of each part of the process.
const Step = enum {
    block_total,
    block_header,
    withdrawals,
    execution_payload,
    randao,
    eth1_data,
    operations,
    sync_aggregate,
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
    try stdout.print("\nSegmented block breakdown :\n", .{});
    try stdout.print("{s:<22} {s:<8} {s:<14} {s:<23}\n", .{ "step", "runs", "total time", "time/run (avg)" });
    try stdout.print("{s:-<69}\n", .{""});
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
            try stdout.print("{s:<22} {d:<8} {d:.3}s         {d:.3}ms\n", .{ @tagName(step), count, total_s, avg_ms });
        } else {
            try stdout.print("{s:<22} {d:<8} {d:.3}ms        {d:.3}ms\n", .{ @tagName(step), count, total_ms, avg_ms });
        }
    }
    try stdout.print("\n", .{});
}

fn ProcessBlockSegmentedBench(comptime fork: ForkSeq) type {
    return struct {
        cached_state: *CachedBeaconState,
        block: *const BeaconBlock(.full, fork),
        body: *const BeaconBlockBody(.full, fork),

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }

            const state = cloned.state.castToFork(fork);
            const epoch_cache = cloned.getEpochCache();

            const block_start = std.time.nanoTimestamp();

            const header_start = std.time.nanoTimestamp();
            state_transition.processBlockHeader(
                fork,
                allocator,
                epoch_cache,
                state,
                .full,
                self.block,
            ) catch unreachable;
            recordSegment(.block_header, elapsedSince(header_start));

            if (comptime fork.gte(.capella)) {
                const withdrawals_start = std.time.nanoTimestamp();
                var withdrawals_result = WithdrawalsResult{
                    .withdrawals = Withdrawals.initCapacity(allocator, preset.MAX_WITHDRAWALS_PER_PAYLOAD) catch unreachable,
                };
                defer withdrawals_result.withdrawals.deinit(allocator);
                var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
                defer withdrawal_balances.deinit();
                state_transition.getExpectedWithdrawals(
                    fork,
                    allocator,
                    epoch_cache,
                    state,
                    &withdrawals_result,
                    &withdrawal_balances,
                ) catch unreachable;
                const actual_withdrawals = self.body.executionPayload().inner.withdrawals;
                var payload_withdrawals_root: [32]u8 = undefined;
                types.capella.Withdrawals.hashTreeRoot(allocator, &actual_withdrawals, &payload_withdrawals_root) catch unreachable;
                state_transition.processWithdrawals(
                    fork,
                    allocator,
                    state,
                    withdrawals_result,
                    payload_withdrawals_root,
                ) catch unreachable;
                recordSegment(.withdrawals, elapsedSince(withdrawals_start));
            }

            if (comptime fork.gte(.bellatrix)) {
                const exec_start = std.time.nanoTimestamp();
                const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
                state_transition.processExecutionPayload(
                    fork,
                    allocator,
                    cloned.config,
                    state,
                    epoch_cache.epoch,
                    .full,
                    self.body,
                    external_data,
                ) catch unreachable;
                recordSegment(.execution_payload, elapsedSince(exec_start));
            }

            const randao_start = std.time.nanoTimestamp();
            state_transition.processRandao(
                fork,
                cloned.config,
                epoch_cache,
                state,
                .full,
                self.body,
                self.block.proposerIndex(),
                true,
            ) catch unreachable;
            recordSegment(.randao, elapsedSince(randao_start));

            const eth1_start = std.time.nanoTimestamp();
            state_transition.processEth1Data(
                fork,
                state,
                self.body.eth1Data(),
            ) catch unreachable;
            recordSegment(.eth1_data, elapsedSince(eth1_start));

            const ops_start = std.time.nanoTimestamp();
            state_transition.processOperations(
                fork,
                allocator,
                cloned.config,
                epoch_cache,
                state,
                &cloned.slashings_cache,
                .full,
                self.body,
                .{ .verify_signature = true },
            ) catch unreachable;
            recordSegment(.operations, elapsedSince(ops_start));

            if (comptime fork.gte(.altair)) {
                const sync_start = std.time.nanoTimestamp();
                state_transition.processSyncAggregate(
                    fork,
                    allocator,
                    cloned.config,
                    epoch_cache,
                    state,
                    self.body.syncAggregate(),
                    true,
                ) catch unreachable;
                recordSegment(.sync_aggregate, elapsedSince(sync_start));
            }

            recordSegment(.block_total, elapsedSince(block_start));
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

    const era_path_0 = try std.fs.path.join(
        allocator,
        &[_][]const u8{ download_era_options.era_out_dir, download_era_options.era_files[0] },
    );
    defer allocator.free(era_path_0);

    var era_reader_0 = try era.Reader.open(allocator, config.mainnet.config, era_path_0);
    defer era_reader_0.close(allocator);

    const state_bytes = try era_reader_0.readSerializedState(allocator, null);
    defer allocator.free(state_bytes);

    const chain_config = config.mainnet.chain_config;
    const slot = slotFromStateBytes(state_bytes);
    const detected_fork = config.mainnet.config.forkSeq(slot);
    try stdout.print("Benchmarking processBlock with state at fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

    // Use download_era_options.era_files[1] for state

    const era_path_1 = try std.fs.path.join(
        allocator,
        &[_][]const u8{ download_era_options.era_out_dir, download_era_options.era_files[1] },
    );
    defer allocator.free(era_path_1);

    var era_reader_1 = try era.Reader.open(allocator, config.mainnet.config, era_path_1);
    defer era_reader_1.close(allocator);

    const block_slot = try era.era.computeStartBlockSlotFromEraNumber(era_reader_1.era_number) + 1;

    const block_bytes = try era_reader_1.readSerializedBlock(allocator, block_slot) orelse return error.InvalidEraFile;
    defer allocator.free(block_bytes);

    inline for (comptime std.enums.values(ForkSeq)) |fork| {
        if (detected_fork == fork) return runBenchmark(fork, allocator, &pool, stdout, state_bytes, block_bytes, chain_config);
    }
    return error.NoBenchmarkRan;
}

fn runBenchmark(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    stdout: anytype,
    state_bytes: []const u8,
    block_bytes: []const u8,
    chain_config: config.ChainConfig,
) !void {
    const beacon_state = try loadState(fork, allocator, pool, state_bytes);
    var signed_beacon_block = try loadBlock(fork, allocator, block_bytes);
    defer signed_beacon_block.deinit(allocator);
    const any_block = signed_beacon_block.beaconBlock();
    const block = any_block.castToFork(.full, fork);
    const body = block.body();
    const block_slot = block.slot();
    try stdout.print("Block: slot: {}\n", .{block_slot});

    const beacon_config = config.BeaconConfig.init(chain_config, (try beacon_state.genesisValidatorsRoot()).*);
    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    defer pubkey_index_map.deinit();
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);
    defer {
        index_pubkey_cache.deinit();
        allocator.destroy(index_pubkey_cache);
    }
    const validators = try beacon_state.validatorsSlice(allocator);
    defer allocator.free(validators);

    try state_transition.syncPubkeys(validators, pubkey_index_map, index_pubkey_cache);

    const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, beacon_state, .{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    }, .{ .skip_sync_committee_cache = !comptime fork.gte(.altair), .skip_sync_pubkeys = false });
    defer {
        cached_state.deinit();
        allocator.destroy(cached_state);
    }

    try state_transition.state_transition.processSlots(
        allocator,
        cached_state,
        block_slot,
        .{},
    );
    try cached_state.state.commit();
    try state_transition.buildSlashingsCacheFromStateIfNeeded(allocator, cached_state.state, &cached_state.slashings_cache);
    try stdout.print("State: slot={}, validators={}\n", .{ try cached_state.state.slot(), try beacon_state.validatorsCount() });

    var bench = zbench.Benchmark.init(allocator, .{
        .iterations = 50,
    });
    defer bench.deinit();

    try bench.addParam("block_header", &ProcessBlockHeaderBench(fork){ .cached_state = cached_state, .block = block }, .{});

    if (comptime fork.gte(.capella)) {
        try bench.addParam("withdrawals", &ProcessWithdrawalsBench(fork){ .cached_state = cached_state, .body = body }, .{});
    }
    if (comptime fork.gte(.bellatrix)) {
        try bench.addParam("execution_payload", &ProcessExecutionPayloadBench(fork){ .cached_state = cached_state, .body = body }, .{});
    }

    try bench.addParam("randao", &ProcessRandaoBench(fork, .{ .verify_signature = true }){ .cached_state = cached_state, .block = block, .body = body }, .{});
    try bench.addParam("randao_no_sig", &ProcessRandaoBench(fork, .{ .verify_signature = false }){ .cached_state = cached_state, .block = block, .body = body }, .{});
    try bench.addParam("eth1_data", &ProcessEth1DataBench(fork){ .cached_state = cached_state, .body = body }, .{});
    try bench.addParam("operations", &ProcessOperationsBench(fork, .{ .verify_signature = true }){ .cached_state = cached_state, .body = body }, .{});
    try bench.addParam("operations_no_sig", &ProcessOperationsBench(fork, .{ .verify_signature = false }){ .cached_state = cached_state, .body = body }, .{});

    if (comptime fork.gte(.altair)) {
        try bench.addParam("sync_aggregate", &ProcessSyncAggregateBench(fork, .{ .verify_signature = true }){ .cached_state = cached_state, .body = body }, .{});
        try bench.addParam("sync_aggregate_no_sig", &ProcessSyncAggregateBench(fork, .{ .verify_signature = false }){ .cached_state = cached_state, .body = body }, .{});
    }

    try bench.addParam("process_block", &ProcessBlockBench(fork, .{ .verify_signature = true }){ .cached_state = cached_state, .block = block }, .{});
    try bench.addParam("process_block_no_sig", &ProcessBlockBench(fork, .{ .verify_signature = false }){ .cached_state = cached_state, .block = block }, .{});

    // // Segmented benchmark (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("block(segments)", &ProcessBlockSegmentedBench(fork){ .cached_state = cached_state, .block = block, .body = body }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
