//! Storage fault injection DST tests.
//!
//! Exercises SimStorage's fault injection capabilities:
//!   - Write failure during epoch boundary: verify graceful degradation.
//!   - Read corruption: verify the node handles ReadCorruption errors.
//!   - DB full simulation: reject all writes after N ops.
//!   - Deterministic replay: same seed = same fault sequence.
//!
//! These tests operate at the SimStorage level (unit tests) and at the
//! controller-backed multi-node level for integration scenarios.

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;

const sim_storage = @import("sim_storage.zig");
const SimStorage = sim_storage.SimStorage;
const StorageError = sim_storage.StorageError;
const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;
const SimController = @import("sim_controller.zig").SimController;

// ── Test 1: Write failure during epoch boundary ────────────────────────
//
// SimStorage is configured with a write failure rate that triggers
// during state archival. We simulate this by writing blocks/states
// with intermittent failures and verifying graceful error handling.

test "fault: write failure — intermittent, stats tracked correctly" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .write_failure_rate = 0.3, // 30% write failure rate
    });
    defer storage.deinit();

    var writes_attempted: u64 = 0;
    var writes_failed: u64 = 0;

    // Attempt 20 block writes. Some will fail.
    for (0..20) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);

        const data = "block_data";
        storage.putBlock(root, data) catch |err| switch (err) {
            error.WriteFailure => {
                writes_failed += 1;
            },
            else => return err,
        };
        writes_attempted += 1;
    }

    // Some writes should have failed (30% rate, 20 attempts → expect ~6 failures).
    // With seeded PRNG the exact count is deterministic; just verify > 0 failures.
    try testing.expect(writes_failed > 0);
    try testing.expect(writes_failed < writes_attempted);
    try testing.expectEqual(writes_failed, storage.stats.write_failures);

    // Successfully written blocks should be readable.
    const successful_writes = writes_attempted - writes_failed;
    try testing.expectEqual(@as(u64, successful_writes), @as(u64, storage.blockCount()));
}

// ── Test 2: Write failure — 100% rate, total failure ──────────────────

test "fault: write failure — 100% rate rejects all writes" {
    var prng = std.Random.DefaultPrng.init(1);
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .write_failure_rate = 1.0,
    });
    defer storage.deinit();

    const root = [_]u8{0xAA} ** 32;

    // All write types should fail.
    try testing.expectError(error.WriteFailure, storage.putBlock(root, "b"));
    try testing.expectError(error.WriteFailure, storage.putState(root, "s"));
    try testing.expectError(error.WriteFailure, storage.putBlob(root, 0, "bl"));

    try testing.expectEqual(@as(u64, 3), storage.stats.write_failures);
    try testing.expectEqual(@as(u32, 0), storage.blockCount());
    try testing.expectEqual(@as(u32, 0), storage.stateCount());
    try testing.expectEqual(@as(u32, 0), storage.blobCount());

    // Reads on non-existent keys return null (not error).
    const result = try storage.getBlock(root);
    try testing.expectEqual(@as(?[]const u8, null), result);
}

// ── Test 3: Read corruption — node handles error gracefully ───────────

test "fault: read corruption — error returned, not crash" {
    var prng = std.Random.DefaultPrng.init(7);
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .read_corruption_rate = 1.0, // Always corrupt reads
    });
    defer storage.deinit();

    const root = [_]u8{0xBB} ** 32;
    const data = "corrupted_block";

    // Write succeeds (no write failure configured).
    try storage.putBlock(root, data);
    try testing.expectEqual(@as(u32, 1), storage.blockCount());

    // Read returns corruption error.
    const block_result = storage.getBlock(root);
    try testing.expectError(error.ReadCorruption, block_result);

    // Same for states and blobs.
    try storage.putState(root, "state");
    const state_result = storage.getState(root);
    try testing.expectError(error.ReadCorruption, state_result);

    try storage.putBlob(root, 0, "blob");
    const blob_result = storage.getBlob(root, 0);
    try testing.expectError(error.ReadCorruption, blob_result);

    try testing.expectEqual(@as(u64, 3), storage.stats.read_corruptions);
}

// ── Test 4: Read corruption — intermittent, some reads succeed ────────

test "fault: read corruption — intermittent, partial reads succeed" {
    var prng = std.Random.DefaultPrng.init(100);
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .read_corruption_rate = 0.5, // 50% corruption rate
    });
    defer storage.deinit();

    // Write 20 blocks.
    for (0..20) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        try storage.putBlock(root, "data");
    }
    try testing.expectEqual(@as(u32, 20), storage.blockCount());

    // Read all 20 blocks. Some succeed, some corrupt.
    var reads_ok: u64 = 0;
    var reads_corrupted: u64 = 0;

    for (0..20) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);

        _ = storage.getBlock(root) catch |err| switch (err) {
            error.ReadCorruption => {
                reads_corrupted += 1;
                continue;
            },
            else => return err,
        };
        reads_ok += 1;
    }

    // With 50% rate, we expect roughly half to corrupt (exact count is deterministic).
    try testing.expect(reads_ok > 0);
    try testing.expect(reads_corrupted > 0);
    try testing.expectEqual(reads_corrupted, storage.stats.read_corruptions);
}

// ── Test 5: DB full — reject all writes after N ops ───────────────────
//
// Simulates a "disk full" scenario by using 100% write failure rate
// after pre-loading some data. This exercises the graceful degradation
// path: the node can still read previously stored data, but new writes fail.

test "fault: db full — reads succeed, new writes fail" {
    var prng = std.Random.DefaultPrng.init(5);

    // Phase 1: Normal operation — write some blocks.
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .write_failure_rate = 0.0, // No failures yet
    });
    defer storage.deinit();

    const num_initial = 5;
    for (0..num_initial) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        try storage.putBlock(root, "existing_block");
    }
    try testing.expectEqual(@as(u32, num_initial), storage.blockCount());

    // Phase 2: DB full — reconfigure to 100% write failure.
    storage.config.write_failure_rate = 1.0;

    // New writes fail.
    const new_root = [_]u8{0xFF} ** 32;
    const write_result = storage.putBlock(new_root, "new_block");
    try testing.expectError(error.WriteFailure, write_result);

    // Old blocks still readable (no read corruption configured).
    for (0..num_initial) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        const data = try storage.getBlock(root);
        try testing.expect(data != null);
        try testing.expectEqualStrings("existing_block", data.?);
    }

    // Block count unchanged (no new blocks added).
    try testing.expectEqual(@as(u32, num_initial), storage.blockCount());
    try testing.expectEqual(@as(u64, 1), storage.stats.write_failures);
}

// ── Test 6: DB full — write N then reject all ──────────────────────────
//
// More granular test: writes succeed until a threshold, then fail.
// Simulates running out of disk space mid-operation.

test "fault: db full — threshold-based exhaustion" {
    var prng = std.Random.DefaultPrng.init(9);
    var storage = SimStorage.init(testing.allocator, &prng, .{
        .write_failure_rate = 0.0,
    });
    defer storage.deinit();

    const capacity: usize = 10;

    // Write exactly `capacity` blocks successfully.
    for (0..capacity) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        root[1] = @intCast(i >> 8);
        try storage.putBlock(root, "block");
    }
    try testing.expectEqual(@as(u32, capacity), storage.blockCount());
    try testing.expectEqual(@as(u64, capacity), storage.stats.blocks_written);

    // Simulate DB full: all writes now fail.
    storage.config.write_failure_rate = 1.0;

    // Attempt 5 more writes — all fail.
    var overflow_failures: u64 = 0;
    for (capacity..capacity + 5) |i| {
        var root = [_]u8{0} ** 32;
        root[0] = @intCast(i & 0xFF);
        root[1] = @intCast(i >> 8);
        storage.putBlock(root, "overflow") catch |err| {
            if (err == error.WriteFailure) overflow_failures += 1;
        };
    }
    try testing.expectEqual(@as(u64, 5), overflow_failures);

    // Block count stays at capacity.
    try testing.expectEqual(@as(u32, capacity), storage.blockCount());

    // Reads still work.
    const root_0 = [_]u8{0} ** 32;
    const data = try storage.getBlock(root_0);
    try testing.expect(data != null);
}

// ── Test 7: Deterministic fault replay ───────────────────────────────
//
// Same seed → same fault sequence. Essential for DST reproducibility.

test "fault: deterministic replay — same seed, same fault pattern" {
    var failure_patterns: [2][20]bool = undefined;

    for (0..2) |run| {
        var prng = std.Random.DefaultPrng.init(42);
        var storage = SimStorage.init(testing.allocator, &prng, .{
            .write_failure_rate = 0.4,
        });
        defer storage.deinit();

        for (0..20) |i| {
            var root = [_]u8{0} ** 32;
            root[0] = @intCast(i);

            failure_patterns[run][i] = blk: {
                storage.putBlock(root, "data") catch |err| {
                    if (err == error.WriteFailure) break :blk true;
                };
                break :blk false;
            };
        }
    }

    // Same seed → identical failure pattern.
    try testing.expectEqualSlices(bool, &failure_patterns[0], &failure_patterns[1]);
}

// ── Test 8: Fault injection in multi-node context ─────────────────────
//
// Verify that a multi-node run completes without panicking even when the
// underlying network has both packet loss and reordering (stress test
// of the fault injection integration with controller-backed simulation).

test "fault: controller with network faults — no panics or safety violations" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 2,
        .seed = 888,
        .validator_count = 64,
        .participation_rate = 0.7,
        .network = .{
            .packet_loss_rate = 0.2,
            .packet_duplicate_rate = 0.1,
            .packet_reorder_rate = 0.15,
            .min_latency_ms = 5,
            .max_latency_ms = 100,
        },
    });
    defer ctrl.deinit();

    try ctrl.advanceSlots(preset.SLOTS_PER_EPOCH * 3);
    const result = ctrl.getFinalityResult();

    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try testing.expectEqual(@as(u64, preset.SLOTS_PER_EPOCH * 3), result.slots_processed);
}

// ── Test 9: Storage stats are tracked correctly ───────────────────────

test "fault: storage stats — comprehensive tracking" {
    var prng = std.Random.DefaultPrng.init(0);
    var storage = SimStorage.init(testing.allocator, &prng, .{});
    defer storage.deinit();

    const r1 = [_]u8{1} ** 32;
    const r2 = [_]u8{2} ** 32;
    const r3 = [_]u8{3} ** 32;

    try storage.putBlock(r1, "b1");
    try storage.putBlock(r2, "b2");
    try storage.putState(r3, "s1");
    try storage.putBlob(r1, 0, "bl1");
    try storage.putBlob(r1, 1, "bl2");

    _ = try storage.getBlock(r1);
    _ = try storage.getBlock(r2);
    _ = try storage.getBlock(r3); // miss
    _ = try storage.getState(r3);
    _ = try storage.getBlob(r1, 0);
    _ = try storage.getBlob(r1, 2); // miss

    try testing.expectEqual(@as(u64, 2), storage.stats.blocks_written);
    try testing.expectEqual(@as(u64, 3), storage.stats.blocks_read); // 2 hits + 1 miss
    try testing.expectEqual(@as(u64, 1), storage.stats.states_written);
    try testing.expectEqual(@as(u64, 1), storage.stats.states_read);
    try testing.expectEqual(@as(u64, 2), storage.stats.blobs_written);
    try testing.expectEqual(@as(u64, 2), storage.stats.blobs_read); // 1 hit + 1 miss
    try testing.expectEqual(@as(u64, 0), storage.stats.write_failures);
    try testing.expectEqual(@as(u64, 0), storage.stats.read_corruptions);
}
