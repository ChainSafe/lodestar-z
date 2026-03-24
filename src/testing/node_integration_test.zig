//! Node integration test: genesis → block import → STFN → DB → API query → req/resp.
//!
//! This is the ultimate end-to-end test for the BeaconNode pipeline.
//! It proves the full stack works together with real data — no mocks.
//!
//! Pipeline under test:
//!   genesis state
//!     → BeaconNode.initFromGenesis
//!     → BlockGenerator.generateBlock
//!     → BeaconNode.importBlock (STFN + DB + fork choice)
//!     → api_handlers.beacon.getGenesis / getBlockHeader
//!     → BeaconNode.onReqResp(.status)
//!     → BeaconNode.getHead() (fork choice head)

const std = @import("std");
const testing = std.testing;

const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const preset = @import("preset").preset;

const BeaconNode = @import("node").BeaconNode;
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const freeResponseChunks = networking.freeResponseChunks;

const api_mod = @import("api");
const api_handlers = api_mod.handlers;
const api_types = api_mod.types;

const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;

// ---------------------------------------------------------------------------
// Test 1: Full pipeline — genesis → blocks → API → req/resp
// ---------------------------------------------------------------------------

test "node integration: genesis → blocks → API" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    // 1. Init harness: creates BeaconNode + genesis state (64 validators).
    var harness = try SimTestHarness.init(allocator, &pool, 42);
    defer harness.deinit();

    const node = harness.node;

    // Verify genesis head.
    {
        const head = node.getHead();
        try testing.expectEqual(@as(u64, 0), head.slot);
    }

    // 2. Generate and import 3 blocks.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);
    try testing.expectEqual(@as(u64, 1), r1.slot);

    const r2 = try harness.sim.processSlot(false);
    try testing.expect(r2.block_processed);
    try testing.expectEqual(@as(u64, 2), r2.slot);

    const r3 = try harness.sim.processSlot(false);
    try testing.expect(r3.block_processed);
    try testing.expectEqual(@as(u64, 3), r3.slot);

    // Verify head advanced.
    {
        const head = node.getHead();
        try testing.expectEqual(@as(u64, 3), head.slot);
        // Block root is non-zero.
        try testing.expect(!std.mem.eql(u8, &head.root, &([_]u8{0} ** 32)));
    }

    // 3. Query the Beacon API handlers directly (no HTTP).

    // GET /eth/v1/beacon/genesis
    const genesis_resp = api_handlers.beacon.getGenesis(node.api_context);
    // Finalized = true for genesis.
    try testing.expect(genesis_resp.finalized == true);

    // GET /eth/v1/beacon/headers/head — should reflect imported slot.
    const head_header_resp = try api_handlers.beacon.getBlockHeader(
        node.api_context,
        .head,
    );
    try testing.expectEqual(@as(u64, 3), head_header_resp.data.header.message.slot);
    // Canonical = true for the head block.
    try testing.expect(head_header_resp.data.canonical);
    // Root is non-zero.
    try testing.expect(!std.mem.eql(u8, &head_header_resp.data.root, &([_]u8{0} ** 32)));

    // 4. Test req/resp Status round-trip.
    const peer_status = StatusMessage.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
    };
    var status_buf: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&peer_status, &status_buf);

    const chunks = try node.onReqResp(.status, &status_buf);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    // Decode the response and verify it reflects the imported chain state.
    var our_status: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &our_status);
    // Our response head_slot should be 3 (the last imported block).
    try testing.expectEqual(@as(u64, 3), our_status.head_slot);
    // Head root should be non-zero.
    try testing.expect(!std.mem.eql(u8, &our_status.head_root, &([_]u8{0} ** 32)));

    // 5. Verify fork choice head matches API response root.
    const fc_head = node.getHead();
    try testing.expectEqual(@as(u64, 3), fc_head.slot);
    try testing.expectEqualSlices(u8, &fc_head.root, &our_status.head_root);
}

// ---------------------------------------------------------------------------
// Test 2: 100% attestation participation — verify finality advances
// ---------------------------------------------------------------------------

test "node integration: attestations → finality advances" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 99);
    defer harness.deinit();

    const node = harness.node;

    // Enable 100% validator participation.
    harness.sim.participation_rate = 1.0;

    // Process enough slots to cross 3 epochs (supermajority finality requires ~2 epochs).
    const slots_needed: u64 = 3 * preset.SLOTS_PER_EPOCH + 1;
    try harness.sim.processSlots(slots_needed, 0.0);

    try testing.expectEqual(slots_needed, harness.sim.slots_processed);
    try testing.expectEqual(slots_needed, harness.sim.blocks_processed);
    // At least 3 epoch transitions occurred.
    try testing.expect(harness.sim.epochs_processed >= 3);

    // With 100% participation over 3 epochs, finality should have advanced.
    const head = node.getHead();
    try testing.expect(head.finalized_epoch > 0);

    // API sync status reflects the new head slot.
    const sync = node.getSyncStatus();
    try testing.expectEqual(slots_needed, sync.head_slot);
    try testing.expect(!sync.is_syncing);
}

// ---------------------------------------------------------------------------
// Test 3: Skip slots — head root doesn't change on skipped slots
// ---------------------------------------------------------------------------

test "node integration: skip slots → head root unchanged" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 7);
    defer harness.deinit();

    const node = harness.node;

    // Import one real block.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);
    const head_after_block = node.getHead();
    try testing.expectEqual(@as(u64, 1), head_after_block.slot);
    const root_after_block = head_after_block.root;

    // Skip 3 slots — no blocks imported.
    const skip1 = try harness.sim.processSlot(true);
    try testing.expect(!skip1.block_processed);

    const skip2 = try harness.sim.processSlot(true);
    try testing.expect(!skip2.block_processed);

    const skip3 = try harness.sim.processSlot(true);
    try testing.expect(!skip3.block_processed);

    // Head root must be the same — no new blocks imported.
    const head_after_skips = node.getHead();
    try testing.expectEqualSlices(u8, &root_after_block, &head_after_skips.root);

    // The head_tracker slot advanced.
    try testing.expectEqual(@as(u64, 4), node.head_tracker.head_slot);

    // Import another block after the skips — head root should change.
    const r5 = try harness.sim.processSlot(false);
    try testing.expect(r5.block_processed);
    try testing.expectEqual(@as(u64, 5), r5.slot);

    const head_final = node.getHead();
    try testing.expect(!std.mem.eql(u8, &root_after_block, &head_final.root));
}

// ---------------------------------------------------------------------------
// Test 4: DB persistence — blocks survive the cache and are fetchable
// ---------------------------------------------------------------------------

test "node integration: DB persistence — imported blocks retrievable by root" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 11);
    defer harness.deinit();

    const node = harness.node;

    // Import 5 blocks.
    for (0..5) |_| {
        _ = try harness.sim.processSlot(false);
    }

    // For each slot 1–5, the block root is in head_tracker.slot_roots.
    for (1..6) |slot| {
        const block_root = node.head_tracker.getBlockRoot(slot);
        try testing.expect(block_root != null);

        // Fetch from DB — must exist.
        const block_bytes = try node.db.getBlock(block_root.?);
        try testing.expect(block_bytes != null);
        if (block_bytes) |bytes| {
            allocator.free(bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Test 5: BeaconBlocksByRange req/resp with real imported blocks
// ---------------------------------------------------------------------------

test "node integration: BeaconBlocksByRange req/resp with real blocks" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 55);
    defer harness.deinit();

    const node = harness.node;

    // Import 4 blocks at slots 1–4.
    for (0..4) |_| {
        _ = try harness.sim.processSlot(false);
    }

    // Request blocks [1, 3) — slots 1, 2, 3.
    const range_req = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = 1,
        .count = 3,
        .step = 1,
    };
    var range_buf: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&range_req, &range_buf);

    const chunks = try node.onReqResp(.beacon_blocks_by_range, &range_buf);
    defer freeResponseChunks(allocator, chunks);

    // 3 blocks should be returned.
    try testing.expectEqual(@as(usize, 3), chunks.len);
    for (chunks) |chunk| {
        try testing.expectEqual(networking.protocol.ResponseCode.success, chunk.result);
        // Each payload is non-empty SSZ bytes.
        try testing.expect(chunk.ssz_payload.len > 0);
    }
}
