//! NodeGossipContext: type-erased gossip validation vtable.
//!
//! Provides a concrete `NodeGossipContext` struct that owns the six SeenSets
//! and holds a `GossipValidationContext` wired to caller-supplied callbacks.
//!
//! The actual callback implementations that read from BeaconNode live in
//! `src/node/gossip_callbacks.zig` (node package), where BeaconNode is
//! accessible.  This file is intentionally free of any `node` package import
//! to avoid a circular dependency (networking ← node ← networking).
//!
//! Usage (from beacon_node.zig):
//! ```zig
//! const gossip_context = @import("networking").gossip_context;
//! var gc = gossip_context.NodeGossipContext.init(allocator, @ptrCast(self));
//! defer gc.deinit();
//! gc.fixupPointers(slot, epoch, finalized_slot, &beaconNodeCallbacks);
//! // pass &gc.ctx to P2pConfig.validator
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

const gossip_validation = @import("gossip_validation.zig");
pub const GossipValidationContext = gossip_validation.GossipValidationContext;
pub const SeenSet = gossip_validation.SeenSet;

/// Vtable for the four state queries.  Callers supply this when calling
/// `fixupPointers`.  This decouples the struct layout from the implementation.
pub const GossipCallbacks = struct {
    getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
    isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
    isValidatorActive: *const fn (ptr: *anyopaque, validator_index: u64, epoch: u64) bool,
    getValidatorCount: *const fn (ptr: *anyopaque) u32,
};

/// Gossip validation context that owns all six SeenSets.
///
/// The `ctx` field is the `GossipValidationContext` suitable for passing to
/// `P2pConfig.validator`.
///
/// **Lifecycle:**
/// 1. Call `init` with an allocator and the opaque node pointer.
/// 2. Place the struct in its final location (heap, field of another struct).
/// 3. Call `fixupPointers` to wire the self-referential SeenSet pointers and
///    the callback vtable.
/// 4. Pass `&gc.ctx` wherever a `*GossipValidationContext` is expected.
/// 5. Call `deinit` to release the SeenSets.
pub const NodeGossipContext = struct {
    /// Type-erased pointer passed through to each callback.
    node: *anyopaque,

    seen_blocks: SeenSet,
    seen_aggregators: SeenSet,
    seen_exits: SeenSet,
    seen_proposer_slashings: SeenSet,
    seen_attester_slashings: SeenSet,
    seen_bls_changes: SeenSet,

    /// Ready-to-use context.  Valid only after `fixupPointers`.
    ctx: GossipValidationContext,

    pub fn init(allocator: Allocator, node_ptr: *anyopaque) NodeGossipContext {
        return .{
            .node = node_ptr,
            .seen_blocks = SeenSet.init(allocator),
            .seen_aggregators = SeenSet.init(allocator),
            .seen_exits = SeenSet.init(allocator),
            .seen_proposer_slashings = SeenSet.init(allocator),
            .seen_attester_slashings = SeenSet.init(allocator),
            .seen_bls_changes = SeenSet.init(allocator),
            .ctx = undefined,
        };
    }

    pub fn deinit(self: *NodeGossipContext) void {
        self.seen_blocks.deinit();
        self.seen_aggregators.deinit();
        self.seen_exits.deinit();
        self.seen_proposer_slashings.deinit();
        self.seen_attester_slashings.deinit();
        self.seen_bls_changes.deinit();
    }

    /// Wire self-referential SeenSet pointers and the callback vtable.
    /// Must be called after the struct is at its final memory address.
    pub fn fixupPointers(
        self: *NodeGossipContext,
        current_slot: u64,
        current_epoch: u64,
        finalized_slot: u64,
        callbacks: *const GossipCallbacks,
    ) void {
        self.ctx = .{
            .ptr = self.node,
            .current_slot = current_slot,
            .current_epoch = current_epoch,
            .finalized_slot = finalized_slot,
            .seen_block_roots = &self.seen_blocks,
            .seen_aggregators = &self.seen_aggregators,
            .seen_voluntary_exits = &self.seen_exits,
            .seen_proposer_slashings = &self.seen_proposer_slashings,
            .seen_attester_slashings = &self.seen_attester_slashings,
            .seen_bls_changes = &self.seen_bls_changes,
            .getProposerIndex = callbacks.getProposerIndex,
            .isKnownBlockRoot = callbacks.isKnownBlockRoot,
            .isValidatorActive = callbacks.isValidatorActive,
            .getValidatorCount = callbacks.getValidatorCount,
        };
    }
};
