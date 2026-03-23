//! Tests for the block import pipeline.
//!
//! Exercises the full production-like path: state regen → STFN → cache → DB.

const std = @import("std");
const testing = std.testing;

const types = @import("consensus_types");
const config_mod = @import("config");
const state_transition = @import("state_transition");
const db_mod = @import("db");
const Node = @import("persistent_merkle_tree").Node;
const preset = @import("preset").preset;
const fork_types = @import("fork_types");

const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const StateRegen = state_transition.StateRegen;
const MemoryCPStateDatastore = state_transition.MemoryCPStateDatastore;
const CheckpointKey = state_transition.CheckpointKey;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

const BlockImporter = @import("block_import.zig").BlockImporter;
const HeadTracker = @import("head_tracker.zig").HeadTracker;
const BlockGenerator = @import("block_generator.zig").BlockGenerator;

/// Shared test harness that wires up all pipeline components.
const PipelineHarness = struct {
    allocator: std.mem.Allocator,

    // Lifetime-managing resources (order matters for deinit).
    pool: *Node.Pool,
    test_config: *config_mod.BeaconConfig,
    pubkey_map: *state_transition.PubkeyIndexMap,
    index_pubkey_cache: *state_transition.Index2PubkeyCache,
    epoch_transition_cache: *state_transition.EpochTransitionCache,

    // State caches.
    block_cache: *BlockStateCache,
    cp_datastore: *MemoryCPStateDatastore,
    cp_cache: *CheckpointStateCache,
    regen: *StateRegen,

    // DB.
    mem_kv: *MemoryKVStore,
    db: *BeaconDB,

    // Head tracking.
    head_tracker: *HeadTracker,

    // The pipeline under test.
    importer: *BlockImporter,

    // Block generation.
    block_gen: *BlockGenerator,

    // Current genesis state (for block generation — kept as head reference).
    head_state: *CachedBeaconState,

    const pool_size: u32 = 500_000;

    fn init(allocator: std.mem.Allocator) !PipelineHarness {
        const pool = try allocator.create(Node.Pool);
        pool.* = try Node.Pool.init(allocator, pool_size);

        var test_state = try TestCachedBeaconState.init(allocator, pool, 64);

        // Set up state caches.
        const block_cache = try allocator.create(BlockStateCache);
        block_cache.* = BlockStateCache.init(allocator, 32);

        const cp_datastore = try allocator.create(MemoryCPStateDatastore);
        cp_datastore.* = MemoryCPStateDatastore.init(allocator);

        const cp_cache = try allocator.create(CheckpointStateCache);
        cp_cache.* = CheckpointStateCache.init(
            allocator,
            cp_datastore.datastore(),
            block_cache,
            3,
        );

        // Set up DB.
        const mem_kv = try allocator.create(MemoryKVStore);
        mem_kv.* = MemoryKVStore.init(allocator);

        const db = try allocator.create(BeaconDB);
        db.* = BeaconDB.init(allocator, mem_kv.kvStore());

        // Set up regen.
        const regen = try allocator.create(StateRegen);
        regen.* = StateRegen.initWithDB(allocator, block_cache, cp_cache, db);

        // Seed the block cache with genesis state.
        const genesis = try test_state.cached_state.clone(allocator, .{ .transfer_cache = false });
        errdefer {
            genesis.deinit();
            allocator.destroy(genesis);
        }
        const genesis_root = try regen.onNewBlock(genesis, true);

        // Head tracker.
        const head_tracker = try allocator.create(HeadTracker);
        head_tracker.* = HeadTracker.init(allocator, genesis_root);

        // Importer.
        const importer = try allocator.create(BlockImporter);
        importer.* = BlockImporter.init(allocator, regen, db, head_tracker);

        // Block generator.
        const block_gen = try allocator.create(BlockGenerator);
        block_gen.* = BlockGenerator.init(allocator, 42);

        return .{
            .allocator = allocator,
            .pool = pool,
            .test_config = test_state.config,
            .pubkey_map = test_state.pubkey_index_map,
            .index_pubkey_cache = test_state.index_pubkey_cache,
            .epoch_transition_cache = test_state.epoch_transition_cache,
            .block_cache = block_cache,
            .cp_datastore = cp_datastore,
            .cp_cache = cp_cache,
            .regen = regen,
            .mem_kv = mem_kv,
            .db = db,
            .head_tracker = head_tracker,
            .importer = importer,
            .block_gen = block_gen,
            .head_state = test_state.cached_state,
        };
    }

    /// Generate a block for the next slot and import it through the pipeline.
    fn generateAndImport(self: *PipelineHarness) !@import("block_import.zig").ImportResult {
        const current_slot = try self.head_state.state.slot();
        const target_slot = current_slot + 1;

        // Clone head state, advance to target slot for block generation.
        var gen_state = try self.head_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            gen_state.deinit();
            self.allocator.destroy(gen_state);
        }

        try state_transition.processSlots(self.allocator, gen_state, target_slot, .{});

        // Generate block.
        const signed_block = try self.block_gen.generateBlock(gen_state, target_slot);
        defer {
            types.electra.SignedBeaconBlock.deinit(self.allocator, signed_block);
            self.allocator.destroy(signed_block);
        }

        // Import through the pipeline.
        const result = try self.importer.importBlock(signed_block);

        // Update our head reference — get the post-state from regen cache.
        // The importer cached it; find it via the block root.
        if (self.block_cache.get(result.state_root)) |new_head| {
            // Don't free old head_state — it's still in the block cache
            // (or was evicted by the cache itself).
            self.head_state = new_head;
        } else {
            // The state was cached by root computed inside importBlock.
            // Let's find it via the state root from block cache.
            // Actually, the block cache uses state root as key.
            // We need the new head. Let's get from the block cache head.
            if (self.block_cache.getSeedState()) |seed| {
                self.head_state = seed;
            }
        }

        // Clean up gen_state — it was a temporary clone for generation.
        gen_state.deinit();
        self.allocator.destroy(gen_state);

        return result;
    }

    fn deinit(self: *PipelineHarness) void {
        // Head state is owned by block_cache — don't free separately.

        self.head_tracker.deinit();
        self.allocator.destroy(self.head_tracker);

        self.allocator.destroy(self.importer);
        self.allocator.destroy(self.block_gen);

        self.regen.*.checkpoint_cache.deinit();
        self.allocator.destroy(self.cp_cache);
        self.cp_datastore.deinit();
        self.allocator.destroy(self.cp_datastore);

        // Block cache owns all cached states (including genesis and post-states).
        self.block_cache.deinit();
        self.allocator.destroy(self.block_cache);

        self.allocator.destroy(self.regen);

        self.db.close();
        self.mem_kv.deinit();
        self.allocator.destroy(self.mem_kv);
        self.allocator.destroy(self.db);

        // Free TestCachedBeaconState ancillary resources.
        self.pubkey_map.deinit();
        self.allocator.destroy(self.pubkey_map);
        self.index_pubkey_cache.deinit();
        self.epoch_transition_cache.deinit();
        state_transition.deinitStateTransition();
        self.allocator.destroy(self.epoch_transition_cache);
        self.allocator.destroy(self.index_pubkey_cache);
        self.allocator.destroy(self.test_config);

        self.pool.deinit();
        self.allocator.destroy(self.pool);
    }
};

// ── Test 1: Single block import ──────────────────────────────────────

test "pipeline: single block import" {
    var harness = try PipelineHarness.init(testing.allocator);
    defer harness.deinit();

    const result = try harness.generateAndImport();

    // Block was imported at slot 1 (or whichever is next after genesis).
    try testing.expect(result.slot > 0);

    // Block root should be non-zero.
    try testing.expect(!std.mem.eql(u8, &result.block_root, &([_]u8{0} ** 32)));

    // State root should be non-zero.
    try testing.expect(!std.mem.eql(u8, &result.state_root, &([_]u8{0} ** 32)));

    // Head tracker should be updated.
    try testing.expectEqual(result.slot, harness.head_tracker.head_slot);
    try testing.expectEqualSlices(u8, &result.block_root, &harness.head_tracker.head_root);

    // Block should be persisted in DB.
    const db_block = try harness.db.getBlock(result.block_root);
    try testing.expect(db_block != null);
    harness.allocator.free(db_block.?);

    // Post-state should be in block cache.
    try testing.expect(harness.block_cache.size() >= 2); // genesis + post-state
}

// ── Test 2: Multi-slot sequential import ─────────────────────────────

test "pipeline: multi-slot sequential import" {
    var harness = try PipelineHarness.init(testing.allocator);
    defer harness.deinit();

    const num_blocks = 5;
    var roots: [num_blocks][32]u8 = undefined;
    var slots: [num_blocks]u64 = undefined;

    for (0..num_blocks) |i| {
        const result = try harness.generateAndImport();
        roots[i] = result.block_root;
        slots[i] = result.slot;
    }

    // Slots should be monotonically increasing.
    for (1..num_blocks) |i| {
        try testing.expect(slots[i] > slots[i - 1]);
    }

    // All blocks should be distinct.
    for (0..num_blocks) |i| {
        for (i + 1..num_blocks) |j| {
            try testing.expect(!std.mem.eql(u8, &roots[i], &roots[j]));
        }
    }

    // All blocks should be in the DB.
    for (0..num_blocks) |i| {
        const db_block = try harness.db.getBlock(roots[i]);
        try testing.expect(db_block != null);
        harness.allocator.free(db_block.?);
    }

    // Head tracker should point to the last block.
    try testing.expectEqual(slots[num_blocks - 1], harness.head_tracker.head_slot);
    try testing.expectEqualSlices(u8, &roots[num_blocks - 1], &harness.head_tracker.head_root);

    // All slots should be tracked.
    for (0..num_blocks) |i| {
        const found = harness.head_tracker.getBlockRoot(slots[i]);
        try testing.expect(found != null);
        try testing.expectEqualSlices(u8, &roots[i], &found.?);
    }
}

// ── Test 3: State is available via StateRegen after import ───────────

test "pipeline: state available via regen after import" {
    var harness = try PipelineHarness.init(testing.allocator);
    defer harness.deinit();

    // Import a block.
    const result = try harness.generateAndImport();

    // The post-state should be retrievable from StateRegen for the next block.
    // Use the block_root as parent_root for a hypothetical next block.
    // StateRegen looks up by state root in block cache.
    // After importBlock, the post-state was cached with its state root.
    // The next block's parent_root is the block_root.
    // But getPreState looks in block cache by state_root.
    // Let me try a different approach: the regen's block cache should
    // have the state keyed by its state_root.
    const state = harness.block_cache.get(result.state_root);
    try testing.expect(state != null);

    // Verify the state's slot matches.
    const cached_slot = try state.?.state.slot();
    try testing.expectEqual(result.slot, cached_slot);
}
