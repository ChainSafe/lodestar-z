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
const download_era_options = @import("download_era_options");
const era = @import("era");
const preset = state_transition.preset;
const ForkSeq = config.ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const BeaconState = state_transition.BeaconState;
const SignedBlock = state_transition.SignedBlock;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const Body = state_transition.Body;
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

const ProcessBlockHeaderBench = struct {
    cached_state: *CachedBeaconState,
    signed_block: SignedBlock,

    pub fn run(self: ProcessBlockHeaderBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        const block = self.signed_block.message();
        state_transition.processBlockHeader(allocator, cloned, block) catch unreachable;
    }
};

const ProcessWithdrawalsBench = struct {
    cached_state: *CachedBeaconState,
    signed_block: SignedBlock,

    pub fn run(self: ProcessWithdrawalsBench, allocator: std.mem.Allocator) void {
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

        state_transition.getExpectedWithdrawals(allocator, &withdrawals_result, &withdrawal_balances, cloned) catch unreachable;

        const block = self.signed_block.message();
        const beacon_body = block.beaconBlockBody();
        const payload_withdrawals_root: [32]u8 = switch (beacon_body) {
            .regular => |b| blk: {
                const actual_withdrawals = b.executionPayload().getWithdrawals();
                var root: [32]u8 = undefined;
                types.capella.Withdrawals.hashTreeRoot(allocator, &actual_withdrawals, &root) catch unreachable;
                break :blk root;
            },
            .blinded => |b| b.executionPayloadHeader().getWithdrawalsRoot(),
        };

        state_transition.processWithdrawals(allocator, cloned, withdrawals_result, payload_withdrawals_root) catch unreachable;
    }
};

const ProcessExecutionPayloadBench = struct {
    cached_state: *CachedBeaconState,
    body: Body,

    pub fn run(self: ProcessExecutionPayloadBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
        state_transition.processExecutionPayload(allocator, cloned, self.body, external_data) catch unreachable;
    }
};

fn ProcessRandaoBench(comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const block = self.signed_block.message();
            const body = block.beaconBlockBody();
            state_transition.processRandao(cloned, body, block.proposerIndex(), opts.verify_signature) catch unreachable;
        }
    };
}

const ProcessEth1DataBench = struct {
    cached_state: *CachedBeaconState,
    signed_block: SignedBlock,

    pub fn run(self: ProcessEth1DataBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        const block = self.signed_block.message();
        const body = block.beaconBlockBody();
        state_transition.processEth1Data(allocator, cloned, body.eth1Data()) catch unreachable;
    }
};

fn ProcessOperationsBench(comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const block = self.signed_block.message();
            const body = block.beaconBlockBody();
            state_transition.processOperations(allocator, cloned, body, .{ .verify_signature = opts.verify_signature }) catch unreachable;
        }
    };
}

fn ProcessSyncAggregateBench(comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const block = self.signed_block.message();
            const body = block.beaconBlockBody();
            state_transition.processSyncAggregate(allocator, cloned, body.syncAggregate(), opts.verify_signature) catch unreachable;
        }
    };
}

fn ProcessBlockBench(comptime opts: BenchOpts) type {
    return struct {
        cached_state: *CachedBeaconState,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
            defer {
                cloned.deinit();
                allocator.destroy(cloned);
            }
            const block = self.signed_block.message();
            const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
            state_transition.processBlock(allocator, cloned, block, external_data, .{ .verify_signature = opts.verify_signature }) catch unreachable;
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

const ProcessBlockSegmentedBench = struct {
    cached_state: *CachedBeaconState,
    signed_block: SignedBlock,
    body: Body,

    pub fn run(self: @This(), allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{}) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }

        const block = self.signed_block.message();
        const beacon_body = block.beaconBlockBody();
        const state = cloned.state;

        const block_start = std.time.nanoTimestamp();

        const header_start = std.time.nanoTimestamp();
        state_transition.processBlockHeader(allocator, cloned, block) catch unreachable;
        recordSegment(.block_header, elapsedSince(header_start));

        if (state.forkSeq().gte(.capella)) {
            const withdrawals_start = std.time.nanoTimestamp();
            var withdrawals_result = WithdrawalsResult{
                .withdrawals = Withdrawals.initCapacity(allocator, preset.MAX_WITHDRAWALS_PER_PAYLOAD) catch unreachable,
            };
            defer withdrawals_result.withdrawals.deinit(allocator);
            var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
            defer withdrawal_balances.deinit();
            state_transition.getExpectedWithdrawals(allocator, &withdrawals_result, &withdrawal_balances, cloned) catch unreachable;
            const payload_withdrawals_root: [32]u8 = switch (beacon_body) {
                .regular => |b| blk: {
                    const actual_withdrawals = b.executionPayload().getWithdrawals();
                    var root: [32]u8 = undefined;
                    types.capella.Withdrawals.hashTreeRoot(allocator, &actual_withdrawals, &root) catch unreachable;
                    break :blk root;
                },
                .blinded => |b| b.executionPayloadHeader().getWithdrawalsRoot(),
            };
            state_transition.processWithdrawals(allocator, cloned, withdrawals_result, payload_withdrawals_root) catch unreachable;
            recordSegment(.withdrawals, elapsedSince(withdrawals_start));
        }

        if (state.forkSeq().gte(.bellatrix)) {
            const exec_start = std.time.nanoTimestamp();
            const external_data = BlockExternalData{ .execution_payload_status = .valid, .data_availability_status = .available };
            state_transition.processExecutionPayload(allocator, cloned, self.body, external_data) catch unreachable;
            recordSegment(.execution_payload, elapsedSince(exec_start));
        }

        const randao_start = std.time.nanoTimestamp();
        state_transition.processRandao(cloned, beacon_body, block.proposerIndex(), true) catch unreachable;
        recordSegment(.randao, elapsedSince(randao_start));

        const eth1_start = std.time.nanoTimestamp();
        state_transition.processEth1Data(allocator, cloned, beacon_body.eth1Data()) catch unreachable;
        recordSegment(.eth1_data, elapsedSince(eth1_start));

        const ops_start = std.time.nanoTimestamp();
        state_transition.processOperations(allocator, cloned, beacon_body, .{ .verify_signature = true }) catch unreachable;
        recordSegment(.operations, elapsedSince(ops_start));

        if (state.forkSeq().gte(.altair)) {
            const sync_start = std.time.nanoTimestamp();
            state_transition.processSyncAggregate(allocator, cloned, beacon_body.syncAggregate(), true) catch unreachable;
            recordSegment(.sync_aggregate, elapsedSince(sync_start));
        }

        recordSegment(.block_total, elapsedSince(block_start));
    }
};

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

fn runBenchmark(comptime fork: ForkSeq, allocator: std.mem.Allocator, pool: *Node.Pool, stdout: anytype, state_bytes: []const u8, block_bytes: []const u8, chain_config: config.ChainConfig) !void {
    const beacon_state = try loadState(fork, allocator, pool, state_bytes);
    const signed_beacon_block = try loadBlock(fork, allocator, block_bytes);
    const block_slot = signed_beacon_block.beaconBlock().slot();
    try stdout.print("Block: slot: {}\n", .{block_slot});

    const beacon_config = config.BeaconConfig.init(chain_config, (try beacon_state.genesisValidatorsRoot()).*);
    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);
    const validators = try beacon_state.validatorsSlice(allocator);
    defer allocator.free(validators);

    try state_transition.syncPubkeys(validators, pubkey_index_map, index_pubkey_cache);

    const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, beacon_state, .{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    }, .{ .skip_sync_committee_cache = !comptime fork.gte(.altair), .skip_sync_pubkeys = false });

    try state_transition.state_transition.processSlots(allocator, cached_state, block_slot, .{});
    try cached_state.state.commit();
    try stdout.print("State: slot={}, validators={}\n", .{ try cached_state.state.slot(), try beacon_state.validatorsCount() });

    const signed_block = SignedBlock{ .regular = signed_beacon_block };
    const body = Body{ .regular = signed_beacon_block.beaconBlock().beaconBlockBody() };

    var bench = zbench.Benchmark.init(allocator, .{
        .iterations = 50,
    });
    defer bench.deinit();

    try bench.addParam("block_header", &ProcessBlockHeaderBench{ .cached_state = cached_state, .signed_block = signed_block }, .{});

    if (comptime fork.gte(.capella)) {
        try bench.addParam("withdrawals", &ProcessWithdrawalsBench{ .cached_state = cached_state, .signed_block = signed_block }, .{});
    }
    if (comptime fork.gte(.bellatrix)) {
        try bench.addParam("execution_payload", &ProcessExecutionPayloadBench{ .cached_state = cached_state, .body = body }, .{});
    }

    try bench.addParam("randao", &ProcessRandaoBench(.{ .verify_signature = true }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
    try bench.addParam("randao_no_sig", &ProcessRandaoBench(.{ .verify_signature = false }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
    try bench.addParam("eth1_data", &ProcessEth1DataBench{ .cached_state = cached_state, .signed_block = signed_block }, .{});
    try bench.addParam("operations", &ProcessOperationsBench(.{ .verify_signature = true }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
    try bench.addParam("operations_no_sig", &ProcessOperationsBench(.{ .verify_signature = false }){ .cached_state = cached_state, .signed_block = signed_block }, .{});

    if (comptime fork.gte(.altair)) {
        try bench.addParam("sync_aggregate", &ProcessSyncAggregateBench(.{ .verify_signature = true }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
        try bench.addParam("sync_aggregate_no_sig", &ProcessSyncAggregateBench(.{ .verify_signature = false }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
    }

    try bench.addParam("process_block", &ProcessBlockBench(.{ .verify_signature = true }){ .cached_state = cached_state, .signed_block = signed_block }, .{});
    try bench.addParam("process_block_no_sig", &ProcessBlockBench(.{ .verify_signature = false }){ .cached_state = cached_state, .signed_block = signed_block }, .{});

    // // Segmented benchmark (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("block(segments)", &ProcessBlockSegmentedBench{ .cached_state = cached_state, .signed_block = signed_block, .body = body }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
