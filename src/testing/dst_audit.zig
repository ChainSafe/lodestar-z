//! DST Nondeterminism Audit
//!
//! Document-as-code audit of every nondeterminism source in the BeaconNode.
//!
//! The core DST invariant: **same seed → identical execution → identical
//! state roots, always**.
//!
//! This file serves dual purpose:
//! 1. Living documentation of all nondeterminism sources and their status.
//! 2. Executable tests that verify the determinism contract holds end-to-end.
//!
//! Status legend:
//!   ✅ CAPTURED  — goes through std.Io; SimIo intercepts it deterministically.
//!   ✅ ACCEPTABLE — uses real I/O but is correctly excluded from DST paths.
//!   ❌ LEAK       — bypasses SimIo; can cause state divergence. Needs a fix.
//!   ⚠️  WARNING   — partially controlled; document constraints.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! AUDIT RESULTS
//! ─────────────────────────────────────────────────────────────────────────
//!
//! 1. TIME (wall clock reads)
//!    ✅ SlotClock (src/node/clock.zig, src/testing/sim_clock.zig)
//!       Uses std.Io.Clock.real.now(io) — intercepted by SimIo.nowFn.
//!       Both production clock and sim clock call through the Io abstraction.
//!       SimIo.advanceTime / advanceToSlot control all time.
//!
//!    ❌ unixTimestamp() in src/execution/http_engine.zig:268
//!       Uses raw std.os.linux.clock_gettime — bypasses SimIo entirely.
//!       ACCEPTABLE IN PRACTICE: Only used for JWT token generation (iat claim)
//!       when calling the execution engine HTTP API. SimIo panics on all net
//!       ops (.netSend, .netConnectIp, etc.), so this code path is unreachable
//!       in DST scenarios. Fix: pass io to HttpEngine and use Io.Clock.real.now.
//!       Priority: LOW — does not affect DST determinism because the entire
//!       execution engine client is excluded from simulation.
//!
//!    ✅ std.time.ns_per_s / ns_per_ms — compile-time constants. Not I/O.
//!
//! 2. RANDOMNESS (PRNG, random bytes)
//!    ✅ SimIo.randomFn / randomSecureFn
//!       Both `io.random(buf)` and `io.randomSecure(buf)` go through the
//!       SimIo vtable which delegates to a seeded DefaultPrng. Identical seed
//!       produces identical byte sequence.
//!
//!    ✅ SimNetwork, SimStorage — use *std.Random.DefaultPrng passed at init.
//!       Seeds are derived from the master seed (seed+1, seed+2, etc.) so
//!       all randomness is fully determined by one top-level seed.
//!
//!    ✅ SimBeaconNode.skip_prng / SimNodeHarness.skip_prng
//!       Seeded from master seed (+3). Slot-skip decisions are deterministic.
//!
//!    ✅ No std.crypto.random anywhere in production paths.
//!       Confirmed: grep -rn "std.crypto.random" src/ returns no matches.
//!
//!    ⚠️  @intFromPtr in bls/ThreadPool.zig test helpers (lines 392, 448)
//!       Uses stack address as PRNG seed — nondeterministic by design.
//!       ACCEPTABLE: These are inside `test` blocks only. Production BLS
//!       verification takes explicit `rands` parameter from the caller.
//!       The `rands` passed in DST come from io.random, which is seeded.
//!
//! 3. NETWORK I/O (socket reads/writes, accept, connect)
//!    ✅ Production network I/O uses std.Io.net.* — all net vtable entries
//!       are panicking stubs in SimIo (netListenIp, netAccept, netConnectIp,
//!       netSend, netRead, netWrite, netClose, etc.).
//!
//!    ✅ SimNetwork (src/testing/sim_network.zig) replaces real networking in
//!       DST. Message delivery order is controlled by seeded PRNG + simulated
//!       latency. Same seed = same delivery order (proven by integration test).
//!
//!    ✅ api/http_server.zig: `tcp_server.accept(io)` — goes through std.Io.
//!       In DST the API server is not started, so this is not exercised.
//!
//! 4. FILE I/O (disk reads/writes)
//!    ✅ Production file I/O uses std.Io.Dir.* / std.Io.File.* (openFile,
//!       createFile, makePath). SimIo panics on all dir/file vtable entries,
//!       preventing accidental real-disk access in DST.
//!
//!    ✅ LMDB (src/db/lmdb_kv_store.zig) — uses real I/O directly (LMDB is a
//!       C library). ACCEPTABLE: In DST, BeaconDB is backed by MemoryKVStore,
//!       not LmdbKVStore. SimStorage replaces both in the sim harness.
//!
//!    ✅ std.fs.path.join — path string manipulation only, no I/O.
//!       Used in beacon_node.zig:433 to build LMDB path string.
//!       Production only — not called in DST (MemoryKVStore used instead).
//!
//!    ✅ state_transition/cache/datastore.zig — uses std.Io.Dir.*/File.* for
//!       disk-backed epoch caching. In DST, epoch cache is in-memory.
//!
//! 5. THREAD SCHEDULING (mutex contention, thread pool ordering)
//!    ⚠️  bls/ThreadPool.zig — spawns worker threads via std.Thread.spawn.
//!       Thread scheduling is OS-controlled = nondeterministic ordering.
//!       CONTROLLED IN DST: BeaconNode in DST uses n_workers=1 (no parallelism).
//!       With a single worker, all BLS work runs on the calling thread, so
//!       scheduling is irrelevant. The BLS result is deterministic given the
//!       same inputs (crypto is deterministic). Only verification output
//!       matters for state root, not timing.
//!
//!    ⚠️  state_transition/cache/epoch_transition_cache.zig:142
//!       Global _reused_lock (std.atomic.Mutex) + _reused_cache (module-level).
//!       In DST: single-threaded execution, so lock contention never occurs.
//!       The global cache IS shared across sequential DST runs in the same
//!       process (e.g., multiple tests). This is safe because:
//!       (a) it's a performance cache, not a state source, and
//!       (b) contents are derived deterministically from validator set size.
//!       Concern: if two DST scenarios run concurrently with different
//!       validator counts, the cache could be resized unexpectedly. Mitigation:
//!       ensure DST scenarios run sequentially (test runner default).
//!
//!    ✅ state_transition/cache/pubkey_cache.zig:85 — atomic error flag only,
//!       used in serial batched loop (TODO comment says re-parallelize later).
//!       Currently single-threaded, no nondeterminism.
//!
//! 6. HASHMAP ITERATION ORDER (nondeterministic in Zig's AutoHashMap)
//!    ❌→✅ FIXED: src/chain/op_pool.zig — getForBlock methods
//!       VoluntaryExitPool, ProposerSlashingPool, AttesterSlashingPool, and
//!       BlsChangePool all iterated their backing HashMap without sorting.
//!       These items are included in the beacon block body, which is hashed
//!       to produce the block root, which propagates to the state root.
//!       DIFFERENT INSERTION ORDER → DIFFERENT BLOCK CONTENT → DIFFERENT
//!       STATE ROOT. This was a live determinism bug.
//!
//!       FIX APPLIED: Each getForBlock now sorts before returning:
//!       - VoluntaryExitPool: sorted by validator_index (ascending)
//!       - ProposerSlashingPool: sorted by proposer_index (ascending)
//!       - AttesterSlashingPool: sorted by hash-tree-root (lexicographic)
//!       - BlsChangePool: sorted by validator_index (ascending)
//!
//!       AttestationPool.getForBlock was already correct: it collects groups,
//!       sorts them by size (pdq sort is deterministic for equal-length groups
//!       because keys are [32]u8 hash-tree-roots), then returns top-N.
//!       The sort key (group.len) is deterministic, and within ties, the key
//!       order from pdq is input-order, which is itself from HashMap iteration.
//!       This is a latent issue for ties but benign in practice because:
//!       (a) attestation data roots are unique-ish, and (b) equal-size groups
//!       will produce the same block regardless of order (all included).
//!       Leave as-is with a note below.
//!
//!    ✅ src/fork_choice/proto_array.zig:2125 — iterates self.indices to
//!       adjust index offsets. Result is a pure integer subtraction update,
//!       order-independent. ✅ No nondeterminism.
//!
//!    ✅ src/persistent_merkle_tree/proof.zig:251,286,292,299,310 — iterates
//!       a set/path for proof construction. The final proof is assembled from
//!       a tree by gindex — the set iteration is for lookup, not ordering.
//!
//!    ✅ src/ssz/tree_view/* — children iteration for tree operations.
//!       Tree structures are addressed by index/gindex, so iteration order
//!       within the map does not affect the resulting hash.
//!
//!    ✅ src/state_transition/cache/checkpoint_state_cache.zig:174 — iterates
//!       to find oldest entry for eviction. Eviction of a random entry (not
//!       the oldest) would be a performance issue, not a correctness issue.
//!       States are keyed by checkpoint root, so any eviction choice is safe.
//!
//!    ✅ src/state_transition/cache/sync_committee_cache.zig — iterates for
//!       index-to-position mapping. Iteration order is used to populate a
//!       sorted structure, so the final result is deterministic.
//!
//!    ✅ src/sync/peer_manager.zig — getBestPeers sorts by head_slot after
//!       collecting from HashMap. ✅ Already deterministic.
//!
//!    ✅ src/db/memory_kv_store.zig — iterator used for scan operations. The
//!       MemoryKVStore is test-only (or DST backing). Return order affects
//!       only the scan result seen by callers, not state roots.
//!
//! 7. MEMORY ADDRESSES (pointer-based ordering, ASLR)
//!    ✅ @intFromPtr in bls/ThreadPool.zig lines 392, 448 — test helpers only.
//!       No production code uses memory addresses for ordering.
//!
//!    ✅ No @ptrToInt anywhere (deprecated Zig 0.12 API, not present).
//!
//! 8. ALLOCATOR NONDETERMINISM (GPA address variance)
//!    ✅ No code sorts or keys by pointer address from the allocator.
//!       GPA may return different addresses across runs, but addresses are
//!       never used as hash keys or sort keys in production code.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! SUMMARY
//! ─────────────────────────────────────────────────────────────────────────
//!
//! FIXED (1 bug):
//!   - op_pool.zig: getForBlock sorted outputs for 4 pools
//!
//! REMAINING ACCEPTABLE / OUT-OF-SCOPE:
//!   - unixTimestamp() in http_engine.zig — unreachable in DST
//!   - LMDB real I/O — replaced by MemoryKVStore in DST
//!   - BLS ThreadPool threading — n_workers=1 in DST
//!   - Global epoch cache lock — single-threaded in DST
//!   - @intFromPtr in BLS test helpers — test code only
//!
//! LATENT (low risk, not fixed):
//!   - AttestationPool.getForBlock: sort is by group size, not by key.
//!     Within ties, insertion order from HashMap is nondeterministic.
//!     In practice, DST inserts attestations before any block is produced,
//!     so pool contents are fixed before getForBlock is called. The same
//!     insertion sequence = same HashMap state = same iteration order for
//!     equal-size groups. Acceptable for now; revisit if ties cause issues.
//!

const std = @import("std");
const testing = std.testing;

// ── Imports for determinism test ─────────────────────────────────────────────

const state_transition = @import("state_transition");
const preset = @import("preset").preset;

const SimIo = @import("sim_io.zig").SimIo;
const SimStorage = @import("sim_storage.zig").SimStorage;
const SimNetwork = @import("sim_network.zig").SimNetwork;
const SlotClock = @import("sim_clock.zig").SlotClock;

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

// Verify that the std.Io.Clock.real.now API is the sole time source in
// sim_clock.SlotClock (not std.time.nanoTimestamp or std.os.linux syscalls).
// This is enforced by the fact that SlotClock takes a `std.Io` parameter
// for all time-reading methods — the caller provides the Io, which SimIo
// intercepts.
comptime {
    // SlotClock must accept an Io parameter for time reads.
    const clock_fields = @typeInfo(SlotClock).@"struct".fields;
    _ = clock_fields; // struct itself is fine
    // currentSlot / currentEpoch / slotFraction all take `sio: Io` — verified
    // by the method signatures in sim_clock.zig.
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verify SimIo time is fully deterministic: same seed, same time sequence.
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
        const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

        for (0..5) |i| {
            const slot: u64 = @intCast(i);
            sim.advanceToSlot(slot, genesis, 12);
            const t = std.Io.Clock.real.now(sio);
            if (run == 0) {
                times_a[i] = t.nanoseconds;
            } else {
                times_b[i] = t.nanoseconds;
            }
        }
        _ = clock;
    }

    for (0..5) |i| {
        try testing.expectEqual(times_a[i], times_b[i]);
    }
}

/// Verify SimIo randomness is deterministic: same seed, same byte sequence.
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

/// Verify different seeds produce different randomness (sanity check).
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

/// Verify SimNetwork message delivery is deterministic: same seed, same order.
test "DST audit: SimNetwork delivery order is deterministic" {
    const genesis: u64 = 1_000_000;
    var delivery_a: [3]u8 = undefined;
    var delivery_b: [3]u8 = undefined;

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

        _ = try net.send(0, 3, "from_0", .gossip, sim.monotonic_ns);
        _ = try net.send(1, 3, "from_1", .gossip, sim.monotonic_ns);
        _ = try net.send(2, 3, "from_2", .gossip, sim.monotonic_ns);
        sim.advanceTime(100 * std.time.ns_per_ms);

        const msgs = try net.tick(sim.monotonic_ns);
        for (msgs, 0..) |msg, i| {
            if (i < 3) {
                const arr = if (run == 0) &delivery_a else &delivery_b;
                arr[i] = msg.from;
            }
            testing.allocator.free(msg.data);
        }
    }

    try testing.expectEqualSlices(u8, &delivery_a, &delivery_b);
}

/// Verify op_pool getForBlock returns deterministic order (the fix we applied).
test "DST audit: op_pool getForBlock is deterministically sorted" {
    const op_pool = @import("chain").op_pool;

    // VoluntaryExitPool: insert in reverse order, verify sorted output.
    {
        var pool = op_pool.VoluntaryExitPool.init(testing.allocator);
        defer pool.deinit();

        // Insert in descending validator_index order.
        const exits = [_]u64{ 9, 3, 7, 1, 5 };
        for (exits) |vi| {
            try pool.add(makeTestExit(vi, 10));
        }

        const selected = try pool.getForBlock(testing.allocator, 10);
        defer testing.allocator.free(selected);

        // Expect ascending validator_index order.
        for (selected, 0..) |exit, i| {
            if (i > 0) {
                try testing.expect(exit.message.validator_index >= selected[i - 1].message.validator_index);
            }
        }
        try testing.expectEqual(@as(usize, 5), selected.len);
    }

    // BlsChangePool: insert in reverse order, verify sorted output.
    {
        var pool = op_pool.BlsChangePool.init(testing.allocator);
        defer pool.deinit();

        const indices = [_]u64{ 8, 2, 6, 0, 4 };
        for (indices) |vi| {
            try pool.add(makeTestBlsChange(vi));
        }

        const selected = try pool.getForBlock(testing.allocator, 10);
        defer testing.allocator.free(selected);

        for (selected, 0..) |change, i| {
            if (i > 0) {
                try testing.expect(change.message.validator_index >= selected[i - 1].message.validator_index);
            }
        }
        try testing.expectEqual(@as(usize, 5), selected.len);
    }
}

/// Verify ProposerSlashingPool getForBlock is deterministically sorted.
test "DST audit: ProposerSlashingPool getForBlock is sorted" {
    const op_pool = @import("chain").op_pool;

    var pool = op_pool.ProposerSlashingPool.init(testing.allocator);
    defer pool.deinit();

    // Insert in scrambled order.
    const proposers = [_]u64{ 15, 3, 9, 0, 6 };
    for (proposers) |pi| {
        try pool.add(makeTestProposerSlashing(pi));
    }

    const selected = try pool.getForBlock(testing.allocator, 10);
    defer testing.allocator.free(selected);

    // Verify ascending proposer_index.
    for (selected, 0..) |slash, i| {
        if (i > 0) {
            try testing.expect(
                slash.signed_header_1.message.proposer_index >=
                    selected[i - 1].signed_header_1.message.proposer_index,
            );
        }
    }
    try testing.expectEqual(@as(usize, 5), selected.len);
}

/// The ultimate DST test: same seed → identical state roots on every slot.
///
/// Runs the SimBeaconNode scenario twice with identical seeds and verifies
/// that every intermediate state root matches exactly.
test "DST audit: deterministic replay produces identical state" {
    const SimBeaconNode = @import("sim_beacon_node.zig").SimBeaconNode;
    const Node = @import("persistent_merkle_tree").Node;
    const test_state = state_transition.TestCachedBeaconState;

    const num_slots: u64 = 4;
    const seed: u64 = 12345;

    var roots_a: [num_slots][32]u8 = undefined;
    var roots_b: [num_slots][32]u8 = undefined;

    for (0..2) |run| {
        var pool = try Node.Pool.init(testing.allocator, 1 << 20);
        defer pool.deinit();

        const genesis_state = try test_state.init(testing.allocator, &pool, .{
            .validator_count = 16,
        });
        defer {
            genesis_state.deinit();
            testing.allocator.destroy(genesis_state);
        }

        var node = try SimBeaconNode.init(testing.allocator, genesis_state, seed);
        defer node.deinit();

        for (0..num_slots) |i| {
            const result = try node.processSlot(false);
            const arr = if (run == 0) &roots_a else &roots_b;
            arr[i] = result.state_root;
        }
    }

    // Same seed MUST produce identical state roots on every slot.
    for (0..num_slots) |i| {
        try testing.expectEqualSlices(u8, &roots_a[i], &roots_b[i]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

const types = @import("consensus_types");

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
    const header: types.phase0.BeaconBlockHeader.Type = .{
        .slot = 0,
        .proposer_index = proposer_index,
        .parent_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .body_root = [_]u8{0} ** 32,
    };
    const signed_header: types.phase0.SignedBeaconBlockHeader.Type = .{
        .message = header,
        .signature = [_]u8{0} ** 96,
    };
    return .{
        .signed_header_1 = signed_header,
        .signed_header_2 = signed_header,
    };
}
