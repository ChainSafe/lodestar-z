//! Benchmark for block processing (works for any fork)
// https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/beacon-chain.md#block-processing //fulu specs
//
// Uses real mainnet state and block:
// - State: slot 13180928
// - Block: slot 13180929
//
// Run with: zbuild run bench_process_block -Doptimize=ReleaseFast
//
// Benchmarks all process_block operations per spec:
// - process_block_header
// - process_withdrawals (post-Capella)
// - process_execution_payload (post-Bellatrix)
// - process_randao
// - process_eth1_data
// - process_operations
// - process_sync_aggregate (post-Altair)

// printf "Date: %s\nKernel: %s\nCPU: %s\nCPUs: %s\nMemory: %sGi\n" "$(date)" "$(uname -sr)" "$(sysctl -n machdep.cpu.brand_string)" "$(sysctl -n hw.ncpu)" "$(echo "$(sysctl -n hw.memsize) / 1024 / 1024 / 1024" | bc)"
// Date: Tue Dec  9 2025
// Kernel: Darwin 25.1.0
// CPU: Apple M3
// CPUs: 8
// Memory: 16Gi
//
// zbuild run bench_process_block -Doptimize=ReleaseFast OR zbuild run bench_process_block -Doptimize=ReleaseFast -- /path/to/state.ssz /path/to/block.ssz

// State: slot=13180929, validators=2156873
// benchmark              runs     total time     time/run (avg ± σ)     (min ... max)                p75        p99        p995
// -----------------------------------------------------------------------------------------------------------------------------
// block_header           50       1.515s         30.312ms ± 9.578ms     (26.488ms ... 94.892ms)      30.18ms    94.892ms   94.892ms
// withdrawals            50       1.449s         28.99ms ± 2.556ms      (26.232ms ... 39.097ms)      29.447ms   39.097ms   39.097ms
// execution_payload      50       1.745s         34.917ms ± 11.606ms    (26.696ms ... 93.451ms)      38.481ms   93.451ms   93.451ms
// randao                 50       1.919s         38.384ms ± 5.864ms     (28.478ms ... 51.428ms)      41.875ms   51.428ms   51.428ms
// randao_no_sig          50       1.69s          33.814ms ± 13.099ms    (27.682ms ... 104.232ms)     32.55ms    104.232ms  104.232ms
// eth1_data              50       1.83s          36.601ms ± 33.016ms    (26.611ms ... 261.882ms)     32.772ms   261.882ms  261.882ms
// operations             50       2.277s         45.545ms ± 6.849ms     (41.418ms ... 90.257ms)      46.806ms   90.257ms   90.257ms
// operations_no_sig      50       1.535s         30.712ms ± 3.142ms     (27.777ms ... 44.238ms)      30.832ms   44.238ms   44.238ms
// sync_aggregate         50       1.539s         30.795ms ± 2.939ms     (26.857ms ... 41.007ms)      31.772ms   41.007ms   41.007ms
// sync_aggregate_no_sig  50       1.649s         32.984ms ± 25.843ms    (26.37ms ... 209.967ms)      30.63ms    209.967ms  209.967ms
// process_block          50       2.39s          47.811ms ± 6.151ms     (43.82ms ... 73.096ms)       47.603ms   73.096ms   73.096ms
// process_block_no_sig   50       1.657s         33.152ms ± 5.263ms     (29.143ms ... 60.873ms)      32.916ms   60.873ms   60.873ms
// block(segments)        50       2.555s         51.112ms ± 8.533ms     (44.404ms ... 95.221ms)      53.978ms   95.221ms   95.221ms

// Segmented block breakdown :
// step                   runs     total time     time/run (avg)
// ---------------------------------------------------------------------
// block_total            50       1.041s         20.828ms
// block_header           50       53.676ms        1.074ms
// withdrawals            50       1.191ms        0.024ms
// execution_payload      50       26.506ms        0.530ms
// randao                 50       38.248ms        0.765ms
// eth1_data              50       0.055ms        0.001ms
// operations             50       852.513ms        17.050ms
// sync_aggregate         50       69.058ms        1.381ms

const std = @import("std");
const zbench = @import("zbench");
const state_transition = @import("state_transition");
const types = @import("consensus_types");
const config = @import("config");
const preset = state_transition.preset;
const ForkSeq = config.ForkSeq;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
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
    cached_state: *CachedBeaconStateAllForks,
    signed_block: SignedBlock,

    pub fn run(self: ProcessBlockHeaderBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
        defer {
            cloned.deinit();
            allocator.destroy(cloned);
        }
        const block = self.signed_block.message();
        state_transition.processBlockHeader(allocator, cloned, block) catch unreachable;
    }
};

const ProcessWithdrawalsBench = struct {
    cached_state: *CachedBeaconStateAllForks,
    signed_block: SignedBlock,

    pub fn run(self: ProcessWithdrawalsBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
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
    cached_state: *CachedBeaconStateAllForks,
    body: Body,

    pub fn run(self: ProcessExecutionPayloadBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
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
        cached_state: *CachedBeaconStateAllForks,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator) catch unreachable;
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
    cached_state: *CachedBeaconStateAllForks,
    signed_block: SignedBlock,

    pub fn run(self: ProcessEth1DataBench, allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
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
        cached_state: *CachedBeaconStateAllForks,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator) catch unreachable;
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
        cached_state: *CachedBeaconStateAllForks,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator) catch unreachable;
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
        cached_state: *CachedBeaconStateAllForks,
        signed_block: SignedBlock,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const cloned = self.cached_state.clone(allocator) catch unreachable;
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
        const total_ms = @as(f64, @floatFromInt(total_ns)) / 1_000_000.0;
        const avg_ms = @as(f64, @floatFromInt(avg_ns)) / 1_000_000.0;
        if (total_ms >= 1000.0) {
            try stdout.print("{s:<22} {d:<8} {d:.3}s         {d:.3}ms\n", .{ @tagName(step), count, total_ms / 1000.0, avg_ms });
        } else {
            try stdout.print("{s:<22} {d:<8} {d:.3}ms        {d:.3}ms\n", .{ @tagName(step), count, total_ms, avg_ms });
        }
    }
    try stdout.print("\n", .{});
}

const ProcessBlockSegmentedBench = struct {
    cached_state: *CachedBeaconStateAllForks,
    signed_block: SignedBlock,
    body: Body,

    pub fn run(self: @This(), allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator) catch unreachable;
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

        if (state.isPostCapella()) {
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

        if (state.isPostBellatrix()) {
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

        if (state.isPostAltair()) {
            const sync_start = std.time.nanoTimestamp();
            state_transition.processSyncAggregate(allocator, cloned, beacon_body.syncAggregate(), true) catch unreachable;
            recordSegment(.sync_aggregate, elapsedSince(sync_start));
        }

        recordSegment(.block_total, elapsedSince(block_start));
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout = std.io.getStdOut().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const state_path = if (args.len > 1) args[1] else "bench/state_transition/state.ssz";
    const block_path = if (args.len > 2) args[2] else "bench/state_transition/block.ssz";

    const state_file = try std.fs.cwd().openFile(state_path, .{});
    defer state_file.close();
    const state_bytes = try state_file.readToEndAlloc(allocator, 10_000_000_000);
    defer allocator.free(state_bytes);

    const chain_config = config.mainnet.chain_config;
    const slot = slotFromStateBytes(state_bytes);
    const detected_fork = config.mainnet.config.forkSeq(slot);
    try stdout.print("Detected fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

    const block_file = try std.fs.cwd().openFile(block_path, .{});
    defer block_file.close();
    const block_bytes = try block_file.readToEndAlloc(allocator, 100_000_000);
    defer allocator.free(block_bytes);

    inline for (comptime std.enums.values(ForkSeq)) |fork| {
        if (detected_fork == fork) return runBenchmark(fork, allocator, stdout, state_bytes, block_bytes, chain_config);
    }
    return error.NoBenchmarkRan;
}

fn runBenchmark(comptime fork: ForkSeq, allocator: std.mem.Allocator, stdout: anytype, state_bytes: []const u8, block_bytes: []const u8, chain_config: config.ChainConfig) !void {
    const beacon_state = try loadState(fork, allocator, state_bytes);
    const signed_beacon_block = try loadBlock(fork, allocator, block_bytes);
    const block_slot = signed_beacon_block.beaconBlock().slot();

    const beacon_config = config.BeaconConfig.init(chain_config, beacon_state.genesisValidatorsRoot());
    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);
    try state_transition.syncPubkeys(beacon_state.validators().items, pubkey_index_map, index_pubkey_cache);

    const cached_state = try CachedBeaconStateAllForks.createCachedBeaconState(allocator, beacon_state, .{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    }, .{ .skip_sync_committee_cache = !comptime fork.gte(.altair), .skip_sync_pubkeys = false });

    try state_transition.state_transition.processSlotsWithTransientCache(allocator, cached_state, block_slot, .{});
    try stdout.print("State: slot={}, validators={}\n", .{ cached_state.state.slot(), beacon_state.validators().items.len });

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

    // Segmented benchmark (step-by-step timing)
    resetSegmentStats();
    try bench.addParam("block(segments)", &ProcessBlockSegmentedBench{ .cached_state = cached_state, .signed_block = signed_block, .body = body }, .{});

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
