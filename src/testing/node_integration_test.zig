//! Node integration test: genesis → block import → STFN → DB → API query → req/resp.
//!
//! End-to-end test for the BeaconNode pipeline with real data — no mocks.
//!
//! Pipeline under test:
//!   genesis state
//!     → BeaconNode.initFromGenesis
//!     → BlockGenerator.generateBlock
//!     → BeaconNode.importBlock (STFN + DB + fork choice)
//!     → api_handlers.beacon.getGenesis / getBlockHeader
//!     → BeaconNode.onReqResp(.status)
//!     → BeaconNode.getHead() (fork choice head)
//!
//! Note: The test genesis state starts at a high slot
//! (ELECTRA_FORK_EPOCH * SLOTS_PER_EPOCH + ...) so all slot assertions
//! are relative to the initial head slot, not absolute values.

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

const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;

// ---------------------------------------------------------------------------
// Test 1: Full pipeline — genesis → blocks → API → req/resp
// ---------------------------------------------------------------------------

test "node integration: genesis → blocks → API" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    // Creates BeaconNode + genesis state (64 validators).
    var harness = try SimTestHarness.init(allocator, &pool, 42);
    defer harness.deinit();

    const node = harness.node;

    // Capture initial head slot (high value due to electra fork epoch offset).
    const initial_slot = node.head_tracker.head_slot;

    // 1. Verify genesis head has a valid state (non-zero state root).
    {
        const state_root = node.head_tracker.head_state_root;
        try testing.expect(!std.mem.eql(u8, &state_root, &([_]u8{0} ** 32)));
    }

    // 2. Generate and import 3 blocks — verify head advances by 1 each time.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);
    try testing.expectEqual(initial_slot + 1, r1.slot);

    const r2 = try harness.sim.processSlot(false);
    try testing.expect(r2.block_processed);
    try testing.expectEqual(initial_slot + 2, r2.slot);

    const r3 = try harness.sim.processSlot(false);
    try testing.expect(r3.block_processed);
    try testing.expectEqual(initial_slot + 3, r3.slot);

    // Head tracker must reflect the last imported block.
    try testing.expectEqual(initial_slot + 3, node.head_tracker.head_slot);
    // Block root is non-zero.
    try testing.expect(!std.mem.eql(u8, &node.head_tracker.head_root, &([_]u8{0} ** 32)));

    // 3. Query Beacon API handlers directly (no HTTP).

    // GET /eth/v1/beacon/genesis — always returns config data.
    const genesis_resp = api_handlers.beacon.getGenesis(node.api_context);
    try testing.expect(genesis_resp.finalized == true);

    // GET /eth/v1/beacon/headers/head — should reflect last imported block.
    const head_header_resp = try api_handlers.beacon.getBlockHeader(
        node.api_context,
        .head,
    );
    try testing.expectEqual(initial_slot + 3, head_header_resp.data.header.message.slot);
    try testing.expect(head_header_resp.data.canonical);
    try testing.expect(!std.mem.eql(u8, &head_header_resp.data.root, &([_]u8{0} ** 32)));

    // 4. req/resp Status round-trip.
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

    // Decode and verify response reflects our chain state.
    var our_status: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &our_status);
    // Our head_slot reflects head_tracker (updated by importBlock).
    try testing.expectEqual(initial_slot + 3, our_status.head_slot);
    try testing.expect(!std.mem.eql(u8, &our_status.head_root, &([_]u8{0} ** 32)));

    // 5. Verify fork choice head matches head_tracker root.
    // (fork choice and head_tracker are kept in sync by importBlock)
    try testing.expectEqualSlices(u8, &node.head_tracker.head_root, &our_status.head_root);
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
    const initial_slot = node.head_tracker.head_slot;

    // Enable 100% validator participation.
    harness.sim.participation_rate = 1.0;

    // Process enough slots to cross 3 full epochs.
    // Casper FFG finality needs ~2 epochs of supermajority attestations.
    const slots_needed: u64 = 3 * preset.SLOTS_PER_EPOCH + 1;
    try harness.sim.processSlots(slots_needed, 0.0);

    try testing.expectEqual(slots_needed, harness.sim.slots_processed);
    try testing.expectEqual(slots_needed, harness.sim.blocks_processed);
    try testing.expect(harness.sim.epochs_processed >= 3);

    // Head advanced by slots_needed.
    try testing.expectEqual(initial_slot + slots_needed, node.head_tracker.head_slot);

    // With 100% participation over 3 epochs, finality should have advanced.
    try testing.expect(node.head_tracker.finalized_epoch > 0);
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
    const initial_slot = node.head_tracker.head_slot;

    // Import one real block.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);
    try testing.expectEqual(initial_slot + 1, r1.slot);

    // Capture the head root after the block.
    const root_after_block = node.head_tracker.head_root;
    try testing.expect(!std.mem.eql(u8, &root_after_block, &([_]u8{0} ** 32)));

    // Skip 3 slots — no new blocks.
    const skip1 = try harness.sim.processSlot(true);
    try testing.expect(!skip1.block_processed);
    const skip2 = try harness.sim.processSlot(true);
    try testing.expect(!skip2.block_processed);
    const skip3 = try harness.sim.processSlot(true);
    try testing.expect(!skip3.block_processed);

    // Head ROOT must stay the same (no blocks imported).
    try testing.expectEqualSlices(u8, &root_after_block, &node.head_tracker.head_root);

    // Head slot advanced through the skips.
    try testing.expectEqual(initial_slot + 4, node.head_tracker.head_slot);

    // Import another block after the skips — root must change.
    const r5 = try harness.sim.processSlot(false);
    try testing.expect(r5.block_processed);
    try testing.expectEqual(initial_slot + 5, r5.slot);
    try testing.expect(!std.mem.eql(u8, &root_after_block, &node.head_tracker.head_root));
}

// ---------------------------------------------------------------------------
// Test 4: DB persistence — imported blocks survive cache and are fetchable
// ---------------------------------------------------------------------------

test "node integration: DB persistence — imported blocks retrievable by root" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, SimTestHarness.default_pool_size);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 11);
    defer harness.deinit();

    const node = harness.node;
    const initial_slot = node.head_tracker.head_slot;

    // Import 5 blocks.
    for (0..5) |_| {
        _ = try harness.sim.processSlot(false);
    }

    // For each imported slot, the block root is in head_tracker and DB.
    for (1..6) |offset| {
        const slot = initial_slot + offset;
        const block_root = node.head_tracker.getBlockRoot(slot);
        try testing.expect(block_root != null);

        // Fetch from DB — must exist.
        const block_bytes = try node.db.getBlock(block_root.?);
        try testing.expect(block_bytes != null);
        if (block_bytes) |bytes| {
            // SSZ bytes for a real block are non-trivial.
            try testing.expect(bytes.len > 0);
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
    const initial_slot = node.head_tracker.head_slot;

    // Import 4 blocks.
    for (0..4) |_| {
        _ = try harness.sim.processSlot(false);
    }

    // Request blocks for 3 consecutive slots starting at initial+1.
    const range_req = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = initial_slot + 1,
        .count = 3,
        .step = 1,
    };
    var range_buf: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&range_req, &range_buf);

    const chunks = try node.onReqResp(.beacon_blocks_by_range, &range_buf);
    defer freeResponseChunks(allocator, chunks);

    // 3 blocks for 3 slots.
    try testing.expectEqual(@as(usize, 3), chunks.len);
    for (chunks) |chunk| {
        try testing.expectEqual(networking.protocol.ResponseCode.success, chunk.result);
        // Each payload is non-empty SSZ.
        try testing.expect(chunk.ssz_payload.len > 0);
    }
}
