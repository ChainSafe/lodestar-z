//! DST Nondeterminism Audit
//!
//! Document-as-code audit of every nondeterminism source in the BeaconNode.
//!
//! Core invariant: **same seed -> identical execution -> identical state roots**.
//!
//! Status legend:
//!   OK CAPTURED  -- goes through std.Io; SimIo intercepts deterministically.
//!   OK ACCEPTABLE -- uses real I/O but excluded from DST paths.
//!   FIXED LEAK   -- was bypassing SimIo; fix applied.
//!   WARNING      -- partially controlled; constraints documented.
//!
//! =========================================================================
//! AUDIT RESULTS
//! =========================================================================
//!
//! 1. TIME (wall clock reads)
//!    OK  SlotClock (src/node/clock.zig, src/testing/sim_clock.zig)
//!        Uses std.Io.Clock.real.now(io) -- intercepted by SimIo.nowFn.
//!        SimIo.advanceTime / advanceToSlot control all time progression.
//!
//!    ACCEPTABLE  unixTimestamp() in src/execution/http_engine.zig:268
//!        Uses raw std.os.linux.clock_gettime -- bypasses SimIo entirely.
//!        Only for JWT iat claim in execution engine HTTP client.
//!        SimIo panics on ALL net vtable entries, so this path is unreachable
//!        in DST. Fix if needed: pass io and use Io.Clock.real.now.
//!
//!    OK  std.time.ns_per_s / ns_per_ms -- compile-time constants, not I/O.
//!
//! 2. RANDOMNESS (PRNG, random bytes)
//!    OK  SimIo.randomFn / randomSecureFn
//!        io.random(buf) and io.randomSecure(buf) delegate to seeded DefaultPrng.
//!        Identical seed -> identical byte sequence.
//!
//!    OK  SimNetwork, SimStorage use *std.Random.DefaultPrng passed at init.
//!        Seeds derived from master seed (+1, +2, +3) -> fully determined.
//!
//!    OK  No std.crypto.random in production paths (verified by grep).
//!
//!    WARNING  @intFromPtr in bls/ThreadPool.zig test helpers (lines 392, 448).
//!             Uses stack address as PRNG seed. ACCEPTABLE: test blocks only.
//!
//! 3. NETWORK I/O (socket reads/writes, accept, connect)
//!    OK  All production net I/O uses std.Io.net.* -- SimIo panics on all
//!        net vtable entries (netListenIp, netAccept, netConnectIp, netSend...).
//!
//!    OK  SimNetwork replaces real networking in DST. Delivery order controlled
//!        by seeded PRNG + simulated latency. Same seed = same order.
//!
//! 4. FILE I/O (disk reads/writes)
//!    OK  Production file I/O uses std.Io.Dir.*/std.Io.File.* -- SimIo panics
//!        on all dir/file vtable entries.
//!
//!    ACCEPTABLE  LMDB uses real I/O (C lib). In DST BeaconDB is backed by
//!        MemoryKVStore, not LmdbKVStore. SimStorage replaces both.
//!
//!    OK  std.fs.path.join in beacon_node.zig:433 -- path string manipulation,
//!        no I/O. Production only (LMDB path), not called in DST.
//!
//! 5. THREAD SCHEDULING
//!    WARNING  bls/ThreadPool.zig spawns workers via std.Thread.spawn.
//!             CONTROLLED: n_workers=1 in DST; all work on calling thread.
//!
//!    WARNING  epoch_transition_cache.zig:142 -- global _reused_lock + _reused_cache.
//!             Single-threaded in DST so lock contention never occurs. Safe
//!             because the cache is a perf-only structure derived from validator
//!             set size (not a state source).
//!
//! 6. HASHMAP ITERATION ORDER (nondeterministic in Zig AutoHashMap)
//!    FIXED  src/chain/op_pool.zig -- getForBlock methods
//!           VoluntaryExitPool, ProposerSlashingPool, AttesterSlashingPool,
//!           and BlsChangePool iterated their backing HashMap without sorting.
//!           These items go into the beacon block body -> block root -> state root.
//!           Different insertion order -> different HashMap iteration ->
//!           different block content -> different state root. Live DST bug.
//!
//!           FIX APPLIED:
//!           - VoluntaryExitPool.getForBlock:    sorted by validator_index
//!           - ProposerSlashingPool.getForBlock: sorted by proposer_index
//!           - AttesterSlashingPool.getForBlock: sorted by hash-tree-root
//!           - BlsChangePool.getForBlock:        sorted by validator_index
//!
//!    NOTE   AttestationPool.getForBlock already sorts groups by size.
//!           Equal-size group ordering from HashMap is benign in DST because
//!           pool state is fixed before getForBlock is called.
//!
//!    OK  fork_choice/proto_array.zig:2125 -- integer subtraction, order-independent.
//!    OK  sync/peer_manager.zig -- getBestPeers sorts by head_slot after collect.
//!
//! 7. MEMORY ADDRESSES
//!    OK  @intFromPtr only in bls/ThreadPool.zig test helpers. No production use.
//!
//! 8. ALLOCATOR NONDETERMINISM
//!    OK  GPA returns different addresses across runs; no code sorts by address.
//!
//! =========================================================================
//! SUMMARY
//! =========================================================================
//!
//! BUG FIXED (1):
//!   op_pool.zig: getForBlock for VoluntaryExit, ProposerSlashing,
//!   AttesterSlashing, and BlsChange now sort before returning.
//!
//! ACCEPTABLE / OUT-OF-SCOPE (unreachable or replaced in DST):
//!   - unixTimestamp() in http_engine.zig (net blocked by SimIo panics)
//!   - LMDB real I/O (replaced by MemoryKVStore in DST)
//!   - BLS ThreadPool threading (n_workers=1 in DST)
//!   - Global epoch cache lock (single-threaded in DST)
//!   - @intFromPtr in BLS test helpers (test code only)
//!
//! LATENT / LOW RISK:
//!   - AttestationPool.getForBlock: equal-size group ordering.
//!     Benign in current DST usage (stable pool state before getForBlock).

const std = @import("std");
const testing = std.testing;

const SimIo = @import("sim_io.zig").SimIo;
const SimNetwork = @import("sim_network.zig").SimNetwork;
const SlotClock = @import("sim_clock.zig").SlotClock;
const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;
const Node = @import("persistent_merkle_tree").Node;
const op_pool = @import("chain").op_pool;
const types = @import("consensus_types");

// =========================================================================
// Source 1: Time -- SimIo intercepts std.Io.Clock reads
// =========================================================================

test "DST audit: SimIo time is deterministic" {
    const genesis: u64 = 1_700_000_000;
    var times_a: [5]i96 = undefined;
    var times_b: [5]i96 = undefined;

    for (0..2) |run| {
        var sim: SimIo = .{
            .prng = std.Random.DefaultPrng.init(42),
            .monotonic_ns = genesis * std.time.ns_per_s,
            .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
        };
        const sio = sim.io();
        for (0..5) |i| {
            sim.advanceToSlot(@intCast(i), genesis, 12);
            const t = std.Io.Clock.real.now(sio);
            (if (run == 0) &times_a else &times_b)[i] = t.nanoseconds;
        }
    }

    for (0..5) |i| try testing.expectEqual(times_a[i], times_b[i]);
}

// =========================================================================
// Source 2: Randomness -- seeded PRNG through SimIo
// =========================================================================

test "DST audit: SimIo randomness is deterministic" {
    var bytes_a: [64]u8 = undefined;
    var bytes_b: [64]u8 = undefined;
    {
        var sim: SimIo = .{ .prng = std.Random.DefaultPrng.init(99) };
        sim.io().random(&bytes_a);
    }
    {
        var sim: SimIo = .{ .prng = std.Random.DefaultPrng.init(99) };
        sim.io().random(&bytes_b);
    }
    try testing.expectEqualSlices(u8, &bytes_a, &bytes_b);
}

test "DST audit: different seeds produce different randomness" {
    var bytes_a: [32]u8 = undefined;
    var bytes_b: [32]u8 = undefined;
    {
        var sim: SimIo = .{ .prng = std.Random.DefaultPrng.init(1) };
        sim.io().random(&bytes_a);
    }
    {
        var sim: SimIo = .{ .prng = std.Random.DefaultPrng.init(2) };
        sim.io().random(&bytes_b);
    }
    try testing.expect(!std.mem.eql(u8, &bytes_a, &bytes_b));
}

// =========================================================================
// Source 3: Network I/O -- SimNetwork replaces real net
// =========================================================================

test "DST audit: SimNetwork delivery order is deterministic" {
    const genesis: u64 = 1_000_000;
    var order_a: [3]u8 = undefined;
    var order_b: [3]u8 = undefined;

    for (0..2) |run| {
        var sim: SimIo = .{
            .prng = std.Random.DefaultPrng.init(42),
            .monotonic_ns = genesis * std.time.ns_per_s,
            .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
        };
        var net_prng = std.Random.DefaultPrng.init(42);
        var net = SimNetwork.init(testing.allocator, &net_prng, .{
            .min_latency_ms = 10,
            .max_latency_ms = 50,
        });
        defer net.deinit();

        _ = try net.send(0, 3, "m0", .gossip, sim.monotonic_ns);
        _ = try net.send(1, 3, "m1", .gossip, sim.monotonic_ns);
        _ = try net.send(2, 3, "m2", .gossip, sim.monotonic_ns);
        sim.advanceTime(100 * std.time.ns_per_ms);

        const msgs = try net.tick(sim.monotonic_ns);
        const arr = if (run == 0) &order_a else &order_b;
        for (msgs, 0..) |msg, i| {
            if (i < 3) arr[i] = msg.from;
            testing.allocator.free(msg.data);
        }
    }

    try testing.expectEqualSlices(u8, &order_a, &order_b);
}

// =========================================================================
// Source 6: HashMap iteration -- op_pool fix verification
// =========================================================================

test "DST audit: VoluntaryExitPool.getForBlock sorted by validator_index" {
    var pool = op_pool.VoluntaryExitPool.init(testing.allocator);
    defer pool.deinit();

    for ([_]u64{ 9, 3, 7, 1, 5 }) |vi| try pool.add(makeTestExit(vi, 10));

    const result = try pool.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(usize, 5), result.len);
    for (result, 0..) |exit, i| {
        if (i > 0) try testing.expect(
            exit.message.validator_index >= result[i - 1].message.validator_index,
        );
    }
}

test "DST audit: ProposerSlashingPool.getForBlock sorted by proposer_index" {
    var pool = op_pool.ProposerSlashingPool.init(testing.allocator);
    defer pool.deinit();

    for ([_]u64{ 15, 3, 9, 0, 6 }) |pi| try pool.add(makeTestProposerSlashing(pi));

    const result = try pool.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(usize, 5), result.len);
    for (result, 0..) |slash, i| {
        if (i > 0) try testing.expect(
            slash.signed_header_1.message.proposer_index >=
                result[i - 1].signed_header_1.message.proposer_index,
        );
    }
}

test "DST audit: BlsChangePool.getForBlock sorted by validator_index" {
    var pool = op_pool.BlsChangePool.init(testing.allocator);
    defer pool.deinit();

    for ([_]u64{ 8, 2, 6, 0, 4 }) |vi| try pool.add(makeTestBlsChange(vi));

    const result = try pool.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(usize, 5), result.len);
    for (result, 0..) |change, i| {
        if (i > 0) try testing.expect(
            change.message.validator_index >= result[i - 1].message.validator_index,
        );
    }
}

test "DST audit: op_pool getForBlock is insertion-order independent" {
    // Two nodes receive same ops in different order; must produce same block.
    var pool_a = op_pool.VoluntaryExitPool.init(testing.allocator);
    defer pool_a.deinit();
    var pool_b = op_pool.VoluntaryExitPool.init(testing.allocator);
    defer pool_b.deinit();

    for ([_]u64{ 5, 2, 8, 1, 9 }) |vi| try pool_a.add(makeTestExit(vi, 5));
    for ([_]u64{ 9, 1, 8, 2, 5 }) |vi| try pool_b.add(makeTestExit(vi, 5));

    const result_a = try pool_a.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(result_a);
    const result_b = try pool_b.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(result_b);

    try testing.expectEqual(result_a.len, result_b.len);
    for (result_a, result_b) |a, b| {
        try testing.expectEqual(a.message.validator_index, b.message.validator_index);
        try testing.expectEqual(a.message.epoch, b.message.epoch);
    }
}

// =========================================================================
// Ultimate test: full state machine deterministic replay
// =========================================================================

test "DST audit: deterministic replay produces identical state" {
    // Run the full BeaconNode DST pipeline twice with the same seed and verify
    // every intermediate state root matches. This exercises the complete stack:
    // STFN, fork choice, block production, op pool, clock, randomness.
    const allocator = testing.allocator;
    const num_slots: u64 = 4;
    const seed: u64 = 12345;

    var roots_a: [num_slots][32]u8 = undefined;
    var roots_b: [num_slots][32]u8 = undefined;

    for (0..2) |run| {
        var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
        defer pool.deinit();

        var harness = try SimTestHarness.init(allocator, &pool, seed);
        defer harness.deinit();

        for (0..num_slots) |i| {
            const result = try harness.sim.processSlot(false);
            (if (run == 0) &roots_a else &roots_b)[i] = result.state_root;
        }
    }

    // Same seed MUST produce identical state roots on every slot.
    for (0..num_slots) |i| {
        try testing.expectEqualSlices(u8, &roots_a[i], &roots_b[i]);
    }
}

// =========================================================================
// Test helpers
// =========================================================================

fn makeTestExit(validator_index: u64, epoch: u64) types.phase0.SignedVoluntaryExit.Type {
    return .{
        .message = .{ .epoch = epoch, .validator_index = validator_index },
        .signature = [_]u8{0} ** 96,
    };
}

fn makeTestBlsChange(validator_index: u64) types.capella.SignedBLSToExecutionChange.Type {
    return .{
        .message = .{
            .validator_index = validator_index,
            .from_bls_pubkey = [_]u8{0} ** 48,
            .to_execution_address = [_]u8{0} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };
}

fn makeTestProposerSlashing(proposer_index: u64) types.phase0.ProposerSlashing.Type {
    const hdr: types.phase0.BeaconBlockHeader.Type = .{
        .slot = 0,
        .proposer_index = proposer_index,
        .parent_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .body_root = [_]u8{0} ** 32,
    };
    const signed_hdr: types.phase0.SignedBeaconBlockHeader.Type = .{
        .message = hdr,
        .signature = [_]u8{0} ** 96,
    };
    return .{
        .signed_header_1 = signed_hdr,
        .signed_header_2 = signed_hdr,
    };
}
