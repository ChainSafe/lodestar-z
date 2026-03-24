//! Real gossip validation callbacks reading from BeaconNode state.
//!
//! These are the concrete implementations of the `GossipCallbacks` vtable
//! defined in `networking/gossip_context.zig`.  They live here (in the `node`
//! package) because they need direct access to `BeaconNode` internals.
//!
//! Wire-up in `beacon_node.zig`:
//! ```zig
//! const gossip_ctx = @import("networking").gossip_context;
//! var gc = gossip_ctx.NodeGossipContext.init(allocator, @ptrCast(self));
//! defer gc.deinit();
//! gc.fixupPointers(slot, epoch, finalized_slot, &gossip_callbacks.callbacks);
//! ```

const std = @import("std");
const BeaconNode = @import("beacon_node.zig").BeaconNode;
const networking = @import("networking");
const GossipCallbacks = networking.gossip_context.GossipCallbacks;

/// Exported vtable — pass `&gossip_callbacks.callbacks` to `fixupPointers`.
pub const callbacks = GossipCallbacks{
    .getProposerIndex = getProposerIndex,
    .isKnownBlockRoot = isKnownBlockRoot,
    .isValidatorActive = isValidatorActive,
    .getValidatorCount = getValidatorCount,
};

/// Returns the expected block proposer for `slot` from the head state's
/// epoch cache.  Returns `null` when the cache doesn't cover `slot`
/// (e.g., cache is for a different epoch).
fn getProposerIndex(ptr: *anyopaque, slot: u64) ?u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return null;
    const proposer = cached.getBeaconProposer(slot) catch return null;
    return @intCast(proposer);
}

/// Returns true if `root` appears in the head tracker's slot→root map.
/// The map is bounded (≈ SLOTS_PER_EPOCH entries), so the linear scan
/// over values is O(32) in practice.
fn isKnownBlockRoot(ptr: *anyopaque, root: [32]u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var it = node.head_tracker.slot_roots.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr, &root)) return true;
    }
    return false;
}

/// Returns true if validator `index` has activation_epoch ≤ epoch < exit_epoch
/// per the head state's validator registry.
fn isValidatorActive(ptr: *anyopaque, index: u64, epoch: u64) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return false;
    const validators = cached.state.validatorsSlice(node.allocator) catch return false;
    defer node.allocator.free(validators);
    if (index >= validators.len) return false;
    const v = &validators[index];
    return v.activation_epoch <= epoch and epoch < v.exit_epoch;
}

/// Returns the total validator count via the epoch cache's pubkey index.
/// Includes all validators (active, pending, exited) — matches spec intent
/// of "within bounds of the known validator set".
fn getValidatorCount(ptr: *anyopaque) u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return 0;
    return @intCast(cached.epoch_cache.index_to_pubkey.items.len);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const testing = std.testing;
const state_transition = @import("state_transition");
const persistent_merkle_tree = @import("persistent_merkle_tree");

fn makeGenesisNode(allocator: std.mem.Allocator) !*BeaconNode {
    const Node = persistent_merkle_tree.Node;
    const pool_size = 256 * 8;
    var pool = try Node.Pool.init(allocator, pool_size);
    // NOTE: pool is leaked here — acceptable for short-lived tests.
    // Use defer pool.deinit() if you need strict cleanup in your own code.
    _ = pool; // suppress unused warning; pool lives for duration of test

    // Re-create a fresh pool for the state (pool must outlive node).
    var pool2 = try Node.Pool.init(allocator, pool_size);
    errdefer pool2.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool2, 16);
    // test_state owns pool2 — caller defers node.deinit() only.

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    errdefer node.deinit();

    const genesis_state = try test_state.cached_state.clone(allocator, .{});
    try genesis_state.state.setSlot(0);
    try node.initFromGenesis(genesis_state);

    // deinit test_state (releases its local copy; node has cloned what it needs)
    test_state.deinit();
    pool2.deinit();

    return node;
}

test "GossipContext: getProposerIndex returns valid index after genesis" {
    const alloc = testing.allocator;
    const gossip_ctx = networking.gossip_context;

    const node = try makeGenesisNode(alloc);
    defer node.deinit();

    var gc = gossip_ctx.NodeGossipContext.init(alloc, @ptrCast(node));
    defer gc.deinit();
    gc.fixupPointers(0, 0, 0, &callbacks);

    const proposer = gc.ctx.getProposerIndex(gc.ctx.ptr, 0);
    try testing.expect(proposer != null);
    const vc = gc.ctx.getValidatorCount(gc.ctx.ptr);
    try testing.expect(vc > 0);
    try testing.expect(proposer.? < vc);
}

test "GossipContext: isKnownBlockRoot true for genesis root" {
    const alloc = testing.allocator;
    const gossip_ctx = networking.gossip_context;

    const node = try makeGenesisNode(alloc);
    defer node.deinit();

    var gc = gossip_ctx.NodeGossipContext.init(alloc, @ptrCast(node));
    defer gc.deinit();
    gc.fixupPointers(0, 0, 0, &callbacks);

    const genesis_root = node.head_tracker.head_root;
    try testing.expect(gc.ctx.isKnownBlockRoot(gc.ctx.ptr, genesis_root));
}
