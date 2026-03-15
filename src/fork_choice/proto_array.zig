const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const math = std.math;
const testing = std.testing;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");
const preset_mod = @import("preset");
const preset = preset_mod.preset;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

const proto_node = @import("proto_node.zig");
const ProtoBlock = proto_node.ProtoBlock;
const ProtoNode = proto_node.ProtoNode;
const ExecutionStatus = proto_node.ExecutionStatus;
const PayloadStatus = proto_node.PayloadStatus;
const BlockExtraMeta = proto_node.BlockExtraMeta;

const LVHExecError = proto_node.LVHExecError;

const ZERO_HASH = constants.ZERO_HASH;
const GENESIS_EPOCH = preset_mod.GENESIS_EPOCH;

/// PTC (Payload Timeliness Committee) vote threshold.
/// More than PAYLOAD_TIMELY_THRESHOLD payload_present votes = payload is timely.
/// Spec: gloas/fork-choice.md (PAYLOAD_TIMELY_THRESHOLD = PTC_SIZE // 2)
const PAYLOAD_TIMELY_THRESHOLD: u32 = preset.PTC_SIZE / 2;

/// Minimum number of finalized nodes before pruning is triggered.
/// TS ref: DEFAULT_PRUNE_THRESHOLD in packages/fork-choice/src/protoArray/protoArray.ts
pub const DEFAULT_PRUNE_THRESHOLD: u32 = 0;

// ── Hash context for [32]u8 roots ──

/// Hash context for [32]u8 roots used in index maps.
/// Uses first 8 bytes as u64 hash — sufficient entropy for SHA-256 block roots.
pub const RootContext = struct {
    pub fn hash(_: RootContext, key: Root) u64 {
        return std.mem.readInt(u64, key[0..8], .little);
    }
    pub fn eql(_: RootContext, a: Root, b: Root) bool {
        return std.mem.eql(u8, &a, &b);
    }
};

// ── Variant indices (Gloas multi-node support) ──

/// Indices into ProtoArray.nodes for a block root.
///
/// Pre-Gloas: a single node index (the block is always FULL).
/// Gloas: 2-3 node indices (PENDING, EMPTY, and optionally FULL).
pub const VariantIndices = union(enum) {
    /// Pre-Gloas: single node (always PayloadStatus.full).
    pre_gloas: u32,
    /// Gloas: variant nodes for the same block root.
    gloas: GloasIndices,

    pub const GloasIndices = struct {
        /// Index of the PENDING variant node.
        pending: u32,
        /// Index of the EMPTY variant node.
        empty: u32,
        /// Index of the FULL variant node (null until payload arrives).
        full: ?u32 = null,
    };

    /// Get the default index for a block root.
    /// Pre-Gloas: the pre_gloas index. Gloas: the PENDING index.
    /// TS: getDefaultVariant() + getNodeIndexByRootAndStatus().
    pub fn defaultIndex(self: VariantIndices) u32 {
        return switch (self) {
            .pre_gloas => |idx| idx,
            .gloas => |g| g.pending,
        };
    }

    /// Get the index for a specific payload status.
    /// Returns null if the requested Gloas variant does not exist yet.
    /// Asserts that pre-Gloas blocks are only queried with .full status.
    pub fn getByPayloadStatus(self: VariantIndices, status: PayloadStatus) ?u32 {
        return switch (self) {
            // Pre-Gloas: only FULL variant exists — PENDING and EMPTY are invalid (unreachable).
            .pre_gloas => |idx| switch (status) {
                .full => idx,
                .pending, .empty => unreachable,
            },
            .gloas => |g| switch (status) {
                .pending => g.pending,
                .empty => g.empty,
                .full => g.full,
            },
        };
    }

    /// Get all valid indices as a bounded array (1 for pre-Gloas, 2-3 for Gloas).
    pub fn allIndices(self: VariantIndices) std.BoundedArray(u32, 3) {
        var result = std.BoundedArray(u32, 3){};
        switch (self) {
            .pre_gloas => |idx| result.appendAssumeCapacity(idx),
            .gloas => |g| {
                result.appendAssumeCapacity(g.pending);
                result.appendAssumeCapacity(g.empty);
                if (g.full) |f| result.appendAssumeCapacity(f);
            },
        }
        return result;
    }
};

// ── ProtoArray errors ──

/// Errors from the ProtoArray (low-level DAG operations).
pub const ProtoArrayError = error{
    FinalizedNodeUnknown,
    JustifiedNodeUnknown,
    InvalidFinalizedRootChange,
    InvalidNodeIndex,
    InvalidParentIndex,
    InvalidBestChildIndex,
    InvalidJustifiedIndex,
    InvalidBestDescendantIndex,
    DeltaOverflow,
    IndexOverflow,
    RevertedFinalizedEpoch,
    InvalidBestNode,
    InvalidBlockExecutionStatus,
    InvalidJustifiedExecutionStatus,
    InvalidLVHExecutionResponse,
    UnknownParentBlock,
    MissingProtoArrayBlock,
    UnknownAncestor,
};

// ── ProtoArray ──

pub const ProtoArray = struct {
    /// Flat array DAG — nodes stored in insertion order.
    /// Parent always has a lower index than any of its children.
    nodes: std.ArrayListUnmanaged(ProtoNode),

    /// Block root -> node index(es) mapping.
    indices: std.HashMapUnmanaged(Root, VariantIndices, RootContext, 80),

    /// Minimum number of finalized nodes before pruning is triggered.
    prune_threshold: u32,

    // ── Checkpoint state ──

    justified_epoch: Epoch,
    justified_root: Root,
    finalized_epoch: Epoch,
    finalized_root: Root,

    // ── Proposer boost tracking ──

    previous_proposer_boost: ?ProposerBoost,

    // ── Gloas (ePBS) state ──

    /// PTC (Payload Timeliness Committee) votes per block root.
    /// Bit i is set when PTC member i voted payload_present=true.
    /// Spec: gloas/fork-choice.md#modified-store
    ptc_votes: std.HashMapUnmanaged(Root, PtcVotes, RootContext, 80),

    /// Error from the last validateLatestHash call, if any.
    /// Stored for upper-layer query; does not affect core algorithm.
    lvh_error: ?LVHExecError,

    pub const PtcVotes = std.StaticBitSet(preset.PTC_SIZE);

    pub const ProposerBoost = struct {
        root: Root,
        score: u64,
    };

    pub fn init(
        justified_epoch: Epoch,
        justified_root: Root,
        finalized_epoch: Epoch,
        finalized_root: Root,
        prune_threshold: u32,
    ) ProtoArray {
        return .{
            .nodes = .empty,
            .indices = .{},
            .prune_threshold = prune_threshold,
            .justified_epoch = justified_epoch,
            .justified_root = justified_root,
            .finalized_epoch = finalized_epoch,
            .finalized_root = finalized_root,
            .previous_proposer_boost = null,
            .ptc_votes = .{},
            .lvh_error = null,
        };
    }

    pub fn deinit(self: *ProtoArray, allocator: Allocator) void {
        self.ptc_votes.deinit(allocator);
        self.indices.deinit(allocator);
        self.nodes.deinit(allocator);
        self.* = undefined;
    }

    /// Create a ProtoArray from a genesis/anchor block.
    /// The block's block_root is used as its target_root since it lies on an epoch boundary.
    /// TS ref: ProtoArray.initialize() in packages/fork-choice/src/protoArray/protoArray.ts
    pub fn initialize(
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError)!ProtoArray {
        var proto_array = ProtoArray.init(
            block.justified_epoch,
            block.justified_root,
            block.finalized_epoch,
            block.finalized_root,
            DEFAULT_PRUNE_THRESHOLD,
        );
        errdefer proto_array.deinit(allocator);

        // Use block_root as target_root — genesis/anchor always sits on an epoch boundary.
        var anchor = block;
        anchor.target_root = block.block_root;

        try proto_array.onBlock(allocator, anchor, current_slot, null);

        return proto_array;
    }

    // ── Accessors ──

    /// Get the default/canonical payload status for a block root.
    /// Pre-Gloas: returns .full (payload embedded in block).
    /// Gloas: returns .pending (canonical variant).
    /// Returns null if the block root is not found.
    pub fn getDefaultVariant(self: *const ProtoArray, block_root: Root) ?PayloadStatus {
        const vi = self.indices.get(block_root) orelse return null;
        return switch (vi) {
            .pre_gloas => .full,
            .gloas => .pending,
        };
    }

    /// Get the node index for the default/canonical variant in a single hash lookup.
    /// Pre-Gloas: returns the single (FULL) index.
    /// Gloas: returns the PENDING variant index.
    pub fn getDefaultNodeIndex(self: *const ProtoArray, block_root: Root) ?u32 {
        const vi = self.indices.get(block_root) orelse return null;
        return vi.defaultIndex();
    }

    /// Get node index for a specific root + payload status combination.
    pub fn getNodeIndexByRootAndStatus(
        self: *const ProtoArray,
        root: Root,
        status: PayloadStatus,
    ) ?u32 {
        const vi = self.indices.get(root) orelse return null;
        return vi.getByPayloadStatus(status);
    }

    /// Returns true if a block with the given root has been inserted.
    pub fn hasBlock(self: *const ProtoArray, root: Root) bool {
        return self.indices.get(root) != null;
    }

    // ── onBlock ──

    /// Register a block with the fork choice. It is only sane to supply
    /// a null parent for the genesis block.
    ///
    /// Pre-Gloas (block.parent_block_hash == null): Creates a single FULL node.
    /// Gloas (block.parent_block_hash != null): Creates PENDING + EMPTY nodes.
    /// Spec: gloas/fork-choice.md#modified-on_block
    pub fn onBlock(
        self: *ProtoArray,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        // Skip duplicate blocks.
        if (self.hasBlock(block.block_root)) return;

        // Reject blocks with invalid execution status.
        if (block.extra_meta.executionStatus() == .invalid) {
            return error.InvalidBlockExecutionStatus;
        }

        if (block.parent_block_hash != null) {
            try self.onBlockGloas(allocator, block, current_slot, proposer_boost_root);
        } else {
            try self.onBlockPreGloas(allocator, block, current_slot, proposer_boost_root);
        }
    }

    fn onBlockPreGloas(
        self: *ProtoArray,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        var node = ProtoNode.fromBlock(block);
        assert(node.payload_status == .full);
        assert(block.parent_block_hash == null);

        // Look up parent index.
        node.parent = self.getNodeIndexByRootAndStatus(block.parent_root, .full);

        // Pre-allocate capacity before mutating state.
        try self.nodes.ensureUnusedCapacity(allocator, 1);
        try self.indices.ensureUnusedCapacity(allocator, 1);

        const node_index: u32 = @intCast(self.nodes.items.len);
        self.nodes.appendAssumeCapacity(node);
        self.indices.putAssumeCapacity(block.block_root, .{ .pre_gloas = node_index });

        if (node.parent) |parent_index| {
            self.maybeUpdateBestChildAndDescendant(parent_index, node_index, current_slot, proposer_boost_root);

            if (block.extra_meta.executionStatus() == .valid) {
                try self.propagateValidExecutionStatusByIndex(parent_index);
            }
        }
    }

    fn onBlockGloas(
        self: *ProtoArray,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        // Gloas: Create PENDING + EMPTY nodes with correct parent relationships
        // Parent of new PENDING node = parent block's EMPTY or FULL (inter-block edge)
        // Parent of new EMPTY node = own PENDING node (intra-block edge)
        assert(block.parent_block_hash != null);
        assert(block.extra_meta.executionStatus() != .invalid);

        // For fork transition: if parent is pre-Gloas, point to parent's FULL
        // Otherwise, determine which parent payload status this block extends
        var parent_index: ?u32 = null;

        // Check if parent exists by getting variants
        if (self.indices.get(block.parent_root)) |parent_vi| {
            parent_index = switch (parent_vi) {
                // Fork transition: parent is pre-Gloas, so it only has FULL variant
                .pre_gloas => |idx| idx,
                // Both blocks are Gloas: determine which parent payload status to extend
                .gloas => |g| blk: {
                    const parent_status = try self.getParentPayloadStatus(block.parent_root, block.parent_block_hash);
                    break :blk switch (parent_status) {
                        .full => g.full orelse g.empty,
                        .empty => g.empty,
                        .pending => g.pending,
                    };
                },
            };
        }
        // else: parent doesn't exist, parent_index remains null (orphan block)

        // Pre-allocate capacity for all mutations before modifying state.
        // 2 nodes (PENDING + EMPTY), 1 index entry, 1 ptc_votes entry.
        try self.nodes.ensureUnusedCapacity(allocator, 2);
        try self.indices.ensureUnusedCapacity(allocator, 1);
        try self.ptc_votes.ensureUnusedCapacity(allocator, 1);

        // Create PENDING node
        var pending_node = ProtoNode.fromBlock(block);
        pending_node.payload_status = .pending;
        pending_node.parent = parent_index; // Points to parent's EMPTY/FULL or FULL (for transition)

        const pending_index: u32 = @intCast(self.nodes.items.len);
        self.nodes.appendAssumeCapacity(pending_node);

        // Create EMPTY variant as a child of PENDING
        var empty_node = ProtoNode.fromBlock(block);
        empty_node.payload_status = .empty;
        empty_node.parent = pending_index; // Points to own PENDING

        const empty_index: u32 = @intCast(self.nodes.items.len);
        self.nodes.appendAssumeCapacity(empty_node);

        // Store both variants in the indices
        // [PENDING, EMPTY, null] - FULL will be added later if payload arrives
        self.indices.putAssumeCapacity(block.block_root, .{
            .gloas = .{ .pending = pending_index, .empty = empty_index },
        });

        // Update bestChild pointers
        if (parent_index) |pi| {
            self.maybeUpdateBestChildAndDescendant(pi, pending_index, current_slot, proposer_boost_root);

            if (block.extra_meta.executionStatus() == .valid) {
                try self.propagateValidExecutionStatusByIndex(pi);
            }
        }

        // Update bestChild for PENDING → EMPTY edge
        self.maybeUpdateBestChildAndDescendant(pending_index, empty_index, current_slot, proposer_boost_root);

        // Initialize PTC votes for this block (all false initially)
        // Spec: gloas/fork-choice.md#modified-on_block
        self.ptc_votes.putAssumeCapacity(block.block_root, PtcVotes.initEmpty());
    }

    /// Called when an execution payload is received for a block (Gloas only).
    /// Creates a FULL variant node as a child of PENDING (sibling to EMPTY).
    /// Both EMPTY and FULL have parent = own PENDING node.
    ///
    /// The FULL node receives EL payload metadata (block hash, number, state root)
    /// since these are unknown at onBlock time.
    /// Spec: gloas/fork-choice.md (on_execution_payload event)
    pub fn onPayload(
        self: *ProtoArray,
        allocator: Allocator,
        block_root: Root,
        current_slot: Slot,
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_payload_state_root: Root,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        const vi_ptr = self.indices.getPtr(block_root) orelse return;

        switch (vi_ptr.*) {
            .pre_gloas => return, // Pre-Gloas: payload already embedded.
            .gloas => |*g| {
                if (g.full != null) return; // Already have FULL variant.

                // Create FULL node from PENDING, as a child of PENDING.
                const pending_node = self.nodes.items[g.pending];
                var full_node = pending_node;
                full_node.payload_status = .full;
                full_node.parent = g.pending;
                full_node.best_child = null;
                full_node.best_descendant = null;
                full_node.weight = 0;

                // Set EL payload metadata on the FULL node.
                full_node.extra_meta = .{
                    .post_merge = BlockExtraMeta.PostMergeMeta.init(
                        execution_payload_block_hash,
                        execution_payload_number,
                        .valid,
                        .available,
                    ),
                };
                full_node.state_root = execution_payload_state_root;
                full_node.block_hash_from_bid = execution_payload_block_hash;

                // Pre-allocate capacity before mutating state.
                try self.nodes.ensureUnusedCapacity(allocator, 1);

                const full_index: u32 = @intCast(self.nodes.items.len);
                self.nodes.appendAssumeCapacity(full_node);
                g.full = full_index;

                // Update best child/descendant: PENDING -> FULL.
                self.maybeUpdateBestChildAndDescendant(
                    g.pending,
                    full_index,
                    current_slot,
                    proposer_boost_root,
                );
            },
        }
    }

    /// Iterate backwards through the array, touching all nodes and their parents and potentially
    /// the best-child of each parent.
    ///
    /// The structure of the `self.nodes` array ensures that the child of each node is always
    /// touched before its parent.
    ///
    /// For each node, the following is done:
    ///
    /// - Update the node's weight with the corresponding delta.
    /// - Back-propagate each node's delta to its parents delta.
    /// - Compare the current node with the parents best-child, updating it if the current node
    ///   should become the best child.
    /// - If required, update the parents best-descendant with the current node or its best-descendant.
    pub fn applyScoreChanges(
        self: *ProtoArray,
        deltas: []i64,
        proposer_boost: ?ProposerBoost,
        justified_epoch: Epoch,
        justified_root: Root,
        finalized_epoch: Epoch,
        finalized_root: Root,
        current_slot: Slot,
    ) ProtoArrayError!void {
        assert(deltas.len == self.nodes.items.len);
        if (finalized_epoch < self.finalized_epoch) return error.RevertedFinalizedEpoch;

        self.maybeUpdateCheckpoints(
            justified_epoch,
            justified_root,
            finalized_epoch,
            finalized_root,
        );

        try self.updateWeights(
            deltas,
            proposer_boost,
        );

        self.updateBestDescendants(
            current_slot,
            if (proposer_boost) |boost|
                boost.root
            else
                null,
        );

        // Update the previous proposer boost.
        self.previous_proposer_boost = proposer_boost;
    }

    /// Update checkpoint state if any value changed.
    inline fn maybeUpdateCheckpoints(
        self: *ProtoArray,
        justified_epoch: Epoch,
        justified_root: Root,
        finalized_epoch: Epoch,
        finalized_root: Root,
    ) void {
        const changed =
            justified_epoch != self.justified_epoch or
            !std.mem.eql(u8, &justified_root, &self.justified_root) or
            finalized_epoch != self.finalized_epoch or
            !std.mem.eql(u8, &finalized_root, &self.finalized_root);

        if (changed) {
            self.justified_epoch = justified_epoch;
            self.justified_root = justified_root;
            self.finalized_epoch = finalized_epoch;
            self.finalized_root = finalized_root;
        }
    }

    /// Pass 1 (backward): iterate backwards through all indices in `self.nodes`.
    /// Apply proposer boost, compute node deltas, update weights,
    /// and back-propagate to parents.
    fn updateWeights(
        self: *ProtoArray,
        deltas: []i64,
        proposer_boost: ?ProposerBoost,
    ) ProtoArrayError!void {
        assert(deltas.len == self.nodes.items.len);

        // Iterate backwards through all indices in self.nodes
        var node_index: u32 = @intCast(self.nodes.items.len);
        while (node_index > 0) {
            node_index -= 1;
            const node = &self.nodes.items[node_index];

            // There is no need to adjust the balances or manage parent of the zero hash since it
            // is an alias to the genesis block. The weight applied to the genesis block is
            // irrelevant as we _always_ choose it and it's impossible for it to have a parent.
            if (std.mem.eql(u8, &node.block_root, &ZERO_HASH)) continue;

            const current_boost: u64 = if (proposer_boost) |b| (if (std.mem.eql(u8, &b.root, &node.block_root)) b.score else 0) else 0;
            const previous_boost: u64 = if (self.previous_proposer_boost) |p| (if (std.mem.eql(u8, &p.root, &node.block_root)) p.score else 0) else 0;

            // If this node's execution status has been marked invalid, then the weight of the node
            // needs to be taken out of consideration after which the node weight will become 0
            // for subsequent iterations of applyScoreChanges
            const node_delta: i64 = if (node.extra_meta.executionStatus() == .invalid)
                math.negate(node.weight) catch return error.DeltaOverflow
            else
                math.sub(i64, math.add(i64, deltas[node_index], math.cast(i64, current_boost) orelse return error.DeltaOverflow) catch return error.DeltaOverflow, math.cast(i64, previous_boost) orelse return error.DeltaOverflow) catch return error.DeltaOverflow;

            // Apply the delta to the node
            node.weight = math.add(i64, node.weight, node_delta) catch return error.DeltaOverflow;

            // Back-propagate the node's delta to its parent delta.
            if (node.parent) |parent_index| {
                assert(parent_index < deltas.len);
                deltas[parent_index] = math.add(i64, deltas[parent_index], node_delta) catch return error.DeltaOverflow;
            }
        }
    }

    /// Pass 2 (backward): iterate backwards through all indices in `self.nodes`.
    ///
    /// We _must_ perform these functions separate from the weight-updating loop above to ensure
    /// that we have a fully coherent set of weights before updating parent
    /// best-child/descendant.
    fn updateBestDescendants(
        self: *ProtoArray,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) void {
        var node_index: u32 = @intCast(self.nodes.items.len);
        while (node_index > 0) {
            node_index -= 1;
            if (self.nodes.items[node_index].parent) |parent_index| {
                assert(parent_index < self.nodes.items.len);
                self.maybeUpdateBestChildAndDescendant(
                    parent_index,
                    node_index,
                    current_slot,
                    proposer_boost_root,
                );
            }
        }
    }

    /// Follows the best-descendant links to find the best-block (i.e., head-block).
    ///
    /// Returns the ProtoNode representing the head.
    /// For pre-Gloas forks, only FULL variants exist (payload embedded).
    /// For Gloas, may return PENDING/EMPTY/FULL variants.
    ///
    /// The justified node is always considered viable for head per spec:
    ///   def get_head(store: Store) -> Root:
    ///     blocks = get_filtered_block_tree(store)
    ///     head = store.justified_checkpoint.root
    pub fn findHead(
        self: *const ProtoArray,
        justified_root: Root,
        current_slot: Slot,
    ) ProtoArrayError!*const ProtoNode {
        if (self.lvh_error != null) return error.InvalidLVHExecutionResponse;

        const justified_index = self.getDefaultNodeIndex(justified_root) orelse return error.JustifiedNodeUnknown;
        assert(justified_index < self.nodes.items.len);

        // Get canonical node: FULL for pre-Gloas, PENDING for Gloas.
        const justified_node = &self.nodes.items[justified_index];
        if (justified_node.extra_meta.executionStatus() == .invalid) {
            return error.InvalidJustifiedExecutionStatus;
        }

        const best_descendant_index = justified_node.best_descendant orelse justified_index;
        assert(best_descendant_index < self.nodes.items.len);

        // Perform a sanity check that the node is indeed valid to be the head.
        const best_node = &self.nodes.items[best_descendant_index];
        if (best_descendant_index != justified_index and !self.nodeIsViableForHead(best_node, current_slot)) return error.InvalidBestNode;

        return best_node;
    }

    // ── Parent payload status ──

    /// Return the parent ProtoNode given its root and optional block hash.
    ///
    /// Pre-Gloas (parent_block_hash == null): looks up the single index by root.
    /// If a Gloas variant is found when pre-Gloas is expected, returns error.
    /// Post-Gloas (parent_block_hash != null): delegates to getNodeByRootAndBlockHash.
    pub fn getParent(
        self: *const ProtoArray,
        parent_root: Root,
        parent_block_hash: ?Root,
    ) ?*const ProtoNode {
        const parent_bh = parent_block_hash orelse {
            // Pre-Gloas path: look up by root with FULL status.
            const idx = self.getNodeIndexByRootAndStatus(parent_root, .full) orelse return null;
            return &self.nodes.items[idx];
        };

        // Post-Gloas path: find by root + block hash.
        return self.getNodeByRootAndBlockHash(parent_root, parent_bh);
    }

    /// Returns an EMPTY or FULL ProtoNode that has matching block root and block hash.
    ///
    /// Searches the variant nodes (FULL first, then EMPTY for Gloas; single node for pre-Gloas)
    /// for one whose executionPayloadBlockHash matches the given block_hash.
    /// PENDING is skipped because its executionPayloadBlockHash is the same as EMPTY's.
    /// Returns null if no matching variant is found.
    pub fn getNodeByRootAndBlockHash(self: *const ProtoArray, block_root: Root, block_hash: Root) ?*const ProtoNode {
        const vi = self.indices.get(block_root) orelse return null;

        switch (vi) {
            .pre_gloas => |idx| {
                const node = &self.nodes.items[idx];
                if (node.extra_meta.executionPayloadBlockHash()) |node_bh| {
                    if (std.mem.eql(u8, &block_hash, &node_bh)) return node;
                }
                return null;
            },
            .gloas => |g| {
                // Check FULL variant first (may not exist yet), then EMPTY.
                if (g.full) |full_idx| {
                    const node = &self.nodes.items[full_idx];
                    if (node.extra_meta.executionPayloadBlockHash()) |node_bh| {
                        if (std.mem.eql(u8, &block_hash, &node_bh)) return node;
                    }
                }

                const node = &self.nodes.items[g.empty];
                if (node.extra_meta.executionPayloadBlockHash()) |node_bh| {
                    if (std.mem.eql(u8, &block_hash, &node_bh)) return node;
                }

                // PENDING is the same as EMPTY so not likely we can return it
                // also it's only specific for fork-choice
                return null;
            },
        }
    }

    /// Determine which parent payload status a block extends.
    /// Spec: gloas/fork-choice.md#new-get_parent_payload_status
    ///
    ///   def get_parent_payload_status(store: Store, block: BeaconBlock) -> PayloadStatus:
    ///     parent = store.blocks[block.parent_root]
    ///     parent_block_hash = block.body.signed_execution_payload_bid.message.parent_block_hash
    ///     message_block_hash = parent.body.signed_execution_payload_bid.message.block_hash_from_bid
    ///     return FULL if parent_block_hash == message_block_hash else EMPTY
    ///
    /// In lodestar forkchoice we don't store the full bid, so we compare parent_block_hash
    /// in child's bid with block_hash_from_bid in parent's variants:
    ///   - If it matches FULL variant, return .full
    ///   - If it matches EMPTY variant, return .empty
    ///   - If no match, return error.UnknownParentBlock
    ///
    /// For pre-Gloas blocks (parent_block_hash == null): always returns .full.
    pub fn getParentPayloadStatus(
        self: *const ProtoArray,
        parent_root: Root,
        parent_block_hash: ?Root,
    ) ProtoArrayError!PayloadStatus {
        const parent_bh = parent_block_hash orelse return .full;

        const parent_node = self.getNodeByRootAndBlockHash(parent_root, parent_bh) orelse
            return error.UnknownParentBlock;
        return parent_node.payload_status;
    }

    /// Check if parent node is FULL.
    /// Returns true if the parent payload status (determined by parent_block_hash) is FULL.
    /// Spec: gloas/fork-choice.md#new-is_parent_node_full
    pub fn isParentNodeFull(
        self: *const ProtoArray,
        parent_root: Root,
        parent_block_hash: ?Root,
    ) ProtoArrayError!bool {
        return (try self.getParentPayloadStatus(parent_root, parent_block_hash)) == .full;
    }

    // ── Best child/descendant ──

    /// Observe the parent at `parent_index` with respect to the child at `child_index` and
    /// potentially modify the parent's best_child and best_descendant values.
    ///
    /// Four outcomes:
    ///   1. The child is already the best child but it's now invalid due to a FFG
    ///      change and should be removed.
    ///   2. The child is already the best child and the parent is updated with the
    ///      new best descendant.
    ///   3. The child is not the best child but becomes the best child.
    ///   4. The child is not the best child and does not become the best child.
    fn maybeUpdateBestChildAndDescendant(
        self: *ProtoArray,
        parent_index: u32,
        child_index: u32,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) void {
        assert(child_index < self.nodes.items.len);
        assert(parent_index < self.nodes.items.len);

        const child = &self.nodes.items[child_index];
        const parent = &self.nodes.items[parent_index];

        const result = self.compareCandidateChild(
            parent,
            child,
            child_index,
            current_slot,
            proposer_boost_root,
        );

        // Apply the result (same pointer — compareCandidateChild is const).
        self.nodes.items[parent_index].best_child = result.best_child;
        self.nodes.items[parent_index].best_descendant = result.best_descendant;
    }

    const ChildAndDescendant = struct {
        best_child: ?u32,
        best_descendant: ?u32,
    };

    /// Compare `child` against the parent's current best child
    /// and return the new best_child / best_descendant pair.
    ///
    /// These three variables are aliases to the three options that we may set the
    /// parent.best_child and parent.best_descendant to. Aliases are used to assist
    /// readability.
    fn compareCandidateChild(
        self: *const ProtoArray,
        parent: *const ProtoNode,
        child: *const ProtoNode,
        child_index: u32,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) ChildAndDescendant {
        const child_leads_to_viable =
            self.nodeLeadsToViableHead(child, current_slot);

        const change_to_child = ChildAndDescendant{
            .best_child = child_index,
            .best_descendant = child.best_descendant orelse
                child_index,
        };
        const change_to_null = ChildAndDescendant{
            .best_child = null,
            .best_descendant = null,
        };
        const no_change = ChildAndDescendant{
            .best_child = parent.best_child,
            .best_descendant = parent.best_descendant,
        };

        const best_child_index = parent.best_child orelse {
            // There is no current best-child and the child is viable.
            // There is no current best-child but the child is not viable.
            return if (child_leads_to_viable)
                change_to_child
            else
                no_change;
        };

        if (best_child_index == child_index) {
            // The child is already the best-child of the parent but it's not viable
            // for the head, so remove it.
            // The child is already the best-child, set it again to ensure that the
            // best-descendant of the parent is updated.
            return if (!child_leads_to_viable)
                change_to_null
            else
                change_to_child;
        }

        // The child is not the best-child but might become it.
        return self.compareAgainstBestChild(
            best_child_index,
            child,
            child_leads_to_viable,
            change_to_child,
            no_change,
            current_slot,
            proposer_boost_root,
        );
    }

    /// Compare candidate child against the existing best child.
    ///
    /// Both nodes lead to viable heads (or both don't), need to pick winner.
    /// Pre-fulu we pick whichever has higher weight, tie-breaker by root.
    /// Post-fulu we pick whichever has higher weight, then tie-breaker by root,
    /// then tie-breaker by getPayloadStatusTiebreaker.
    /// Gloas: nodes from previous slot (n-1) with EMPTY/FULL variant have
    /// weight hardcoded to 0.
    fn compareAgainstBestChild(
        self: *const ProtoArray,
        best_child_index: u32,
        child: *const ProtoNode,
        child_leads_to_viable: bool,
        change_to_child: ChildAndDescendant,
        no_change: ChildAndDescendant,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) ChildAndDescendant {
        assert(best_child_index < self.nodes.items.len);

        const best_child =
            &self.nodes.items[best_child_index];
        const best_child_leads_to_viable =
            self.nodeLeadsToViableHead(best_child, current_slot);

        // The child leads to a viable head, but the current best-child doesn't (or vice versa).
        if (child_leads_to_viable != best_child_leads_to_viable) {
            return if (child_leads_to_viable)
                change_to_child
            else
                no_change;
        }

        // Different effective weights, choose the winner by weight.
        const child_ew = effectiveWeight(child, current_slot);
        const best_child_ew = effectiveWeight(best_child, current_slot);

        if (child_ew != best_child_ew) {
            return if (child_ew >= best_child_ew) change_to_child else no_change;
        }

        // Different blocks, tie-breaker by root.
        if (!std.mem.eql(u8, &child.block_root, &best_child.block_root)) {
            const root_cmp = std.mem.order(u8, &child.block_root, &best_child.block_root);
            return if (root_cmp != .lt) change_to_child else no_change;
        }

        // Same effective weight and same root — Gloas EMPTY vs FULL from n-1,
        // tie-breaker by payload status.
        // Note: pre-Gloas, each child node of a block has a unique root,
        // so this point should not be reached.
        const child_tb = self.getPayloadStatusTiebreaker(child, current_slot, proposer_boost_root);
        const best_tb = self.getPayloadStatusTiebreaker(best_child, current_slot, proposer_boost_root);
        return if (child_tb > best_tb) change_to_child else no_change;
    }

    /// Return node weight or 0 for Gloas EMPTY/FULL nodes from
    /// the previous slot (slot + 1 == current_slot).
    fn effectiveWeight(
        node: *const ProtoNode,
        current_slot: Slot,
    ) i64 {
        const is_gloas = node.parent_block_hash != null;
        const is_variant =
            node.payload_status != .pending;
        const is_prev_slot =
            node.slot + 1 == current_slot;
        return if (is_gloas and is_variant and is_prev_slot)
            0
        else
            node.weight;
    }

    /// Get the payload status tiebreaker value for Gloas node comparison.
    ///
    /// For PENDING nodes or nodes not from the previous slot, returns the raw payload status ordinal.
    /// For FULL nodes from the previous slot, returns FULL if shouldExtendPayload is true,
    /// otherwise demotes to PENDING (0) to deprioritize stale payloads.
    fn getPayloadStatusTiebreaker(self: *const ProtoArray, node: *const ProtoNode, current_slot: Slot, proposer_boost_root: ?Root) u2 {
        // PENDING nodes or nodes not from the previous slot: return raw payload status.
        if (node.payload_status == .pending or node.slot + 1 != current_slot) return @intFromEnum(node.payload_status);
        if (node.payload_status == .empty) return @intFromEnum(PayloadStatus.empty);

        // FULL node from previous slot — check shouldExtendPayload.
        const should_extend = self.shouldExtendPayload(node.block_root, proposer_boost_root) catch false;
        return if (should_extend) @intFromEnum(PayloadStatus.full) else @intFromEnum(PayloadStatus.pending);
    }

    // ── Viability checks ──

    /// Indicates if the node itself is viable for the head, or if its best descendant
    /// is viable for the head.
    fn nodeLeadsToViableHead(
        self: *const ProtoArray,
        node: *const ProtoNode,
        current_slot: Slot,
    ) bool {
        const best_descendant_is_viable =
            if (node.best_descendant) |bd_index| blk: {
                assert(bd_index < self.nodes.items.len);
                break :blk self.nodeIsViableForHead(
                    &self.nodes.items[bd_index],
                    current_slot,
                );
            } else false;

        return best_descendant_is_viable or
            self.nodeIsViableForHead(node, current_slot);
    }

    /// Equivalent to the `filter_block_tree` function in the Ethereum consensus spec:
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/phase0/fork-choice.md#filter_block_tree
    ///
    /// Any node that has a different finalized or justified epoch should not be viable
    /// for the head.
    ///
    /// If block is from a previous epoch, filter using unrealized justification &
    /// finalization information (pull-up FFG).
    /// If block is from the current epoch, filter using the head state's justification
    /// & finalization information.
    ///
    /// The voting source should be at the same height as the store's justified checkpoint
    /// or not more than two epochs ago.
    fn nodeIsViableForHead(
        self: *const ProtoArray,
        node: *const ProtoNode,
        current_slot: Slot,
    ) bool {
        assert(self.finalized_epoch <= self.justified_epoch);
        assert(self.nodes.items.len > 0);

        // If node has invalid executionStatus, it can't be a viable head.
        if (node.extra_meta.executionStatus() == .invalid) {
            return false;
        }

        // If block is from a previous epoch, filter using unrealized justification &
        // finalization information. If block is from the current epoch, filter using
        // the head state's justification & finalization information.
        const current_epoch = computeEpochAtSlot(current_slot);
        const node_epoch = computeEpochAtSlot(node.slot);
        const voting_source_epoch = if (node_epoch < current_epoch)
            node.unrealized_justified_epoch
        else
            node.justified_epoch;

        // The voting source should be at the same height as the store's justified checkpoint
        // or not more than two epochs ago.
        const correct_justified =
            (self.justified_epoch == GENESIS_EPOCH) or
            (voting_source_epoch == self.justified_epoch) or
            (voting_source_epoch + 2 >= current_epoch);

        const correct_finalized =
            (self.finalized_epoch == GENESIS_EPOCH) or
            self.isFinalizedRootOrDescendant(node);

        return correct_justified and correct_finalized;
    }

    /// Return true if `node` is equal to or a descendant of the finalized node.
    ///
    /// Performance optimization: checks finalized/justified epoch+root pairs before
    /// walking the parent chain, since these are known ancestors of `node` that are
    /// likely to coincide with the store's finalized checkpoint.
    fn isFinalizedRootOrDescendant(
        self: *const ProtoArray,
        node: *const ProtoNode,
    ) bool {
        if (node.finalized_epoch == self.finalized_epoch and
            std.mem.eql(u8, &node.finalized_root, &self.finalized_root))
        {
            return true;
        }
        if (node.justified_epoch == self.finalized_epoch and
            std.mem.eql(u8, &node.justified_root, &self.finalized_root))
        {
            return true;
        }
        if (node.unrealized_finalized_epoch == self.finalized_epoch and
            std.mem.eql(
                u8,
                &node.unrealized_finalized_root,
                &self.finalized_root,
            ))
        {
            return true;
        }
        if (node.unrealized_justified_epoch == self.finalized_epoch and
            std.mem.eql(
                u8,
                &node.unrealized_justified_root,
                &self.finalized_root,
            ))
        {
            return true;
        }

        // Slow path: walk the parent chain.
        const finalized_slot = computeStartSlotAtEpoch(self.finalized_epoch);
        const ancestor_node = self.getAncestorOrNull(
            node.block_root,
            finalized_slot,
        );
        return self.finalized_epoch == GENESIS_EPOCH or
            (if (ancestor_node) |a|
                std.mem.eql(
                    u8,
                    &a.block_root,
                    &self.finalized_root,
                )
            else
                false);
    }

    /// Get ancestor node at a given slot. Returns error if the block root is
    /// missing or the ancestor cannot be found in the parent chain.
    /// Spec: gloas/fork-choice.md#modified-get_ancestor
    ///
    /// Walks the parent chain via `parentRoot` (through indices map, not parent index).
    /// For Gloas blocks, returns the correct payload variant at the ancestor slot.
    ///
    /// NOTE: May be expensive — potentially walks through the entire fork of head
    /// to finalized block.
    fn getAncestor(
        self: *const ProtoArray,
        block_root: Root,
        ancestor_slot: Slot,
    ) ProtoArrayError!*const ProtoNode {
        assert(self.nodes.items.len > 0);
        assert(self.nodes.items.len <= math.maxInt(u32));

        const vi = self.indices.get(block_root) orelse
            return error.MissingProtoArrayBlock;
        const block_index = vi.defaultIndex();
        const block = &self.nodes.items[block_index];

        if (block.slot <= ancestor_slot) return block;

        var current_block = block;
        var parent_vi = self.indices.get(
            current_block.parent_root,
        ) orelse return error.UnknownAncestor;
        var parent_index = parent_vi.defaultIndex();
        var parent_block = &self.nodes.items[parent_index];

        while (parent_block.slot > ancestor_slot) {
            current_block = parent_block;
            parent_vi = self.indices.get(
                current_block.parent_root,
            ) orelse return error.UnknownAncestor;
            parent_index = parent_vi.defaultIndex();
            parent_block = &self.nodes.items[parent_index];
        }

        // For Gloas blocks, return the correct payload variant of the parent.
        if (current_block.parent_block_hash != null) {
            const parent_status =
                try self.getParentPayloadStatus(
                    current_block.parent_root,
                    current_block.parent_block_hash,
                );
            const variant_index =
                self.getNodeIndexByRootAndStatus(
                    current_block.parent_root,
                    parent_status,
                ) orelse return error.UnknownAncestor;
            return &self.nodes.items[variant_index];
        }

        return parent_block;
    }

    /// Get ancestor node at a given slot, or null if not found.
    /// Wraps getAncestor, converting errors to null.
    fn getAncestorOrNull(
        self: *const ProtoArray,
        block_root: Root,
        ancestor_slot: Slot,
    ) ?*const ProtoNode {
        return self.getAncestor(block_root, ancestor_slot) catch null;
    }

    // ── Execution status propagation ──

    /// Propagate valid execution status up the ancestor chain.
    /// Continues while encountering syncing status.
    ///
    /// If PayloadSeparated, that means the node is either PENDING or EMPTY,
    /// there could be some ancestor still has syncing status.
    fn propagateValidExecutionStatusByIndex(
        self: *ProtoArray,
        valid_node_index: u32,
    ) ProtoArrayError!void {
        assert(valid_node_index < self.nodes.items.len);

        var node_index: ?u32 = valid_node_index;
        while (node_index) |idx| {
            const node = &self.nodes.items[idx];
            switch (node.extra_meta) {
                .post_merge => |m| {
                    switch (m.execution_status) {
                        .valid => return,
                        .pre_merge => unreachable,
                        .payload_separated => {
                            // Continue upward (Gloas).
                            node_index = node.parent;
                            continue;
                        },
                        .syncing, .invalid => {},
                    }
                },
                .pre_merge => return,
            }
            try self.validateNodeByIndex(idx);
            node_index = node.parent;
        }
    }

    /// Validate a single node's execution status.
    /// Throws if the node has Invalid status
    /// (Invalid -> Valid is a consensus failure).
    /// If the node has Syncing status, promotes it to Valid.
    /// TODO: populate lvh_error on InvalidLVHExecutionResponse.
    fn validateNodeByIndex(
        self: *ProtoArray,
        node_index: u32,
    ) ProtoArrayError!void {
        assert(node_index < self.nodes.items.len);

        const node = &self.nodes.items[node_index];
        switch (node.extra_meta) {
            .post_merge => |*m| {
                switch (m.execution_status) {
                    .invalid => {
                        return error.InvalidLVHExecutionResponse;
                    },
                    .syncing => m.execution_status = .valid,
                    .valid, .pre_merge, .payload_separated => {},
                }
            },
            .pre_merge => {},
        }
    }

    // ── PTC (Payload Timeliness Committee) ──

    /// Update PTC votes for multiple validators attesting to a block.
    /// Spec: gloas/fork-choice.md#new-on_payload_attestation_message
    ///
    /// Called when payload attestations are processed (from blocks or the wire).
    ///
    pub fn notifyPtcMessages(
        self: *ProtoArray,
        block_root: Root,
        ptc_indices: []const u32,
        payload_present: bool,
    ) void {
        // Block not found or not a Gloas block, ignore.
        const votes = self.ptc_votes.getPtr(block_root) orelse return;
        for (ptc_indices) |idx| {
            assert(idx < preset.PTC_SIZE); // Invalid PTC index
            votes.setValue(idx, payload_present);
        }
    }

    /// Check if execution payload for a block is timely.
    /// Spec: gloas/fork-choice.md#new-is_payload_timely
    ///
    /// Returns true if:
    ///   1. Block has PTC votes tracked
    ///   2. Payload is locally available (FULL variant exists in proto array)
    ///   3. More than PAYLOAD_TIMELY_THRESHOLD (>50% of PTC) members voted payload_present=true
    ///
    pub fn isPayloadTimely(
        self: *const ProtoArray,
        block_root: Root,
    ) bool {
        // Block not found or not a Gloas block.
        const votes = self.ptc_votes.get(block_root) orelse return false;

        // Payload is locally available if proto array
        // has FULL variant of the block.
        if (self.getNodeIndexByRootAndStatus(
            block_root,
            .full,
        ) == null) return false;

        // Count votes for payload_present=true.
        return votes.count() > PAYLOAD_TIMELY_THRESHOLD;
    }

    /// Determine if we should extend the payload (prefer FULL over EMPTY).
    /// Spec: gloas/fork-choice.md#new-should_extend_payload
    ///
    /// Returns true if:
    ///   1. Payload is timely, OR
    ///   2. No proposer boost root (null/zero hash), OR
    ///   3. Proposer boost root's parent is not this block, OR
    ///   4. Proposer boost root extends FULL parent.
    ///
    pub fn shouldExtendPayload(
        self: *const ProtoArray,
        block_root: Root,
        proposer_boost_root: ?Root,
    ) ProtoArrayError!bool {
        // Condition 1: Payload is timely.
        if (self.isPayloadTimely(block_root)) return true;

        // Condition 2: No proposer boost root.
        const boost_root = proposer_boost_root orelse return true;
        if (std.mem.eql(u8, &boost_root, &ZERO_HASH)) return true;

        // Get proposer boost block.
        // We don't care about variant here, just need proposer boost block info.
        const boost_index = self.getDefaultNodeIndex(boost_root) orelse
            // Proposer boost block not found, default to extending payload.
            return true;
        const boost_node = &self.nodes.items[boost_index];

        // Condition 3: Proposer boost root's parent is not this block.
        if (!std.mem.eql(u8, &boost_node.parent_root, &block_root)) return true;

        // Condition 4: Proposer boost root extends FULL parent.
        return try self.isParentNodeFull(
            boost_node.parent_root,
            boost_node.parent_block_hash,
        );
    }
};

// ── Tests ──

const TestBlock = struct {
    fn genesis() ProtoBlock {
        return .{
            .slot = 0,
            .block_root = ZERO_HASH,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .target_root = ZERO_HASH,
            .justified_epoch = 0,
            .justified_root = ZERO_HASH,
            .finalized_epoch = 0,
            .finalized_root = ZERO_HASH,
            .unrealized_justified_epoch = 0,
            .unrealized_justified_root = ZERO_HASH,
            .unrealized_finalized_epoch = 0,
            .unrealized_finalized_root = ZERO_HASH,
            .extra_meta = .{ .pre_merge = {} },
            .timeliness = false,
        };
    }

    fn withRoot(root: Root) ProtoBlock {
        var block = genesis();
        block.block_root = root;
        return block;
    }

    fn withSlotAndRoot(slot: Slot, root: Root) ProtoBlock {
        var block = genesis();
        block.slot = slot;
        block.block_root = root;
        return block;
    }

    fn withParent(block: ProtoBlock, parent_root: Root) ProtoBlock {
        var b = block;
        b.parent_root = parent_root;
        return b;
    }

    fn asGloas(block: ProtoBlock) ProtoBlock {
        var b = block;
        b.block_hash_from_bid = ZERO_HASH;
        b.parent_block_hash = ZERO_HASH;
        // TS stores bid hash in executionPayloadBlockHash for PENDING/EMPTY nodes.
        // Mirror that convention so getNodeByRootAndBlockHash works correctly.
        b.extra_meta = .{
            .post_merge = BlockExtraMeta.PostMergeMeta.init(
                ZERO_HASH,
                0,
                .payload_separated,
                .pre_data,
            ),
        };
        return b;
    }

    fn asGloasWithBidHash(block: ProtoBlock, bid_hash: Root) ProtoBlock {
        var b = block;
        b.block_hash_from_bid = bid_hash;
        b.parent_block_hash = ZERO_HASH;
        // TS stores bid hash in executionPayloadBlockHash for PENDING/EMPTY nodes.
        // Mirror that convention so getNodeByRootAndBlockHash works correctly.
        b.extra_meta = .{
            .post_merge = BlockExtraMeta.PostMergeMeta.init(
                bid_hash,
                0,
                .payload_separated,
                .pre_data,
            ),
        };
        return b;
    }

    fn withParentBlockHash(block: ProtoBlock, parent_bh: Root) ProtoBlock {
        var b = block;
        b.parent_block_hash = parent_bh;
        return b;
    }

    fn withExtraMeta(block: ProtoBlock, meta: BlockExtraMeta) ProtoBlock {
        var b = block;
        b.extra_meta = meta;
        return b;
    }
};

fn makeRoot(byte: u8) Root {
    var root = ZERO_HASH;
    root[0] = byte;
    return root;
}

test "init and deinit" {
    var pa = ProtoArray.init(1, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), pa.nodes.items.len);
    try testing.expectEqual(@as(Epoch, 1), pa.justified_epoch);
    try testing.expectEqual(@as(Epoch, 0), pa.finalized_epoch);
    try testing.expectEqual(@as(?ProtoArray.ProposerBoost, null), pa.previous_proposer_boost);
}

test "onBlock adds genesis" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    try testing.expectEqual(@as(usize, 1), pa.nodes.items.len);
    const node = &pa.nodes.items[0];
    try testing.expectEqual(@as(?u32, null), node.parent);
    try testing.expectEqual(@as(i64, 0), node.weight);
    try testing.expectEqual(PayloadStatus.full, node.payload_status);

    // Indices map should have a single entry.
    const vi = pa.indices.get(ZERO_HASH).?;
    try testing.expectEqual(VariantIndices{ .pre_gloas = 0 }, vi);
}

test "onBlock duplicate is no-op" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    try testing.expectEqual(@as(usize, 1), pa.nodes.items.len);
}

test "onBlock rejects invalid execution status" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    var block = TestBlock.withRoot(makeRoot(1));
    block.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .invalid, .available),
    };
    try testing.expectError(
        error.InvalidBlockExecutionStatus,
        pa.onBlock(testing.allocator, block, 0, null),
    );
    try testing.expectEqual(@as(usize, 0), pa.nodes.items.len);
}

test "onBlock links parent" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const child_root = makeRoot(2);

    try pa.onBlock(testing.allocator, TestBlock.withRoot(parent_root), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withRoot(child_root), parent_root), 0, null);

    try testing.expectEqual(@as(usize, 2), pa.nodes.items.len);
    const child = &pa.nodes.items[1];
    try testing.expectEqual(@as(?u32, 0), child.parent);
}

test "onBlock unknown parent stays null" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const unknown_parent = makeRoot(99);
    var block = TestBlock.withRoot(makeRoot(1));
    block.parent_root = unknown_parent;
    try pa.onBlock(testing.allocator, block, 0, null);

    const node = &pa.nodes.items[0];
    try testing.expectEqual(@as(?u32, null), node.parent);
}

test "onBlock updates best_child" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const child_root = makeRoot(2);

    try pa.onBlock(testing.allocator, TestBlock.withRoot(parent_root), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withRoot(child_root), parent_root), 0, null);

    const parent = &pa.nodes.items[0];
    try testing.expectEqual(@as(?u32, 1), parent.best_child);
    try testing.expectEqual(@as(?u32, 1), parent.best_descendant);
}

test "onBlock multiple children root tiebreak" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const child_a = makeRoot(2);
    const child_b = makeRoot(3); // Higher root wins.

    try pa.onBlock(testing.allocator, TestBlock.withRoot(parent_root), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withRoot(child_a), parent_root), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withRoot(child_b), parent_root), 0, null);

    const parent = &pa.nodes.items[0];
    // child_b has higher root (0x03 > 0x02), so it should be best_child.
    try testing.expectEqual(@as(?u32, 2), parent.best_child);
}

test "onBlock Gloas creates PENDING and EMPTY" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    var block = TestBlock.withRoot(root);
    block = TestBlock.asGloas(block);

    try pa.onBlock(testing.allocator, block, 0, null);

    // Two nodes: PENDING + EMPTY.
    try testing.expectEqual(@as(usize, 2), pa.nodes.items.len);

    const pending = &pa.nodes.items[0];
    try testing.expectEqual(PayloadStatus.pending, pending.payload_status);
    try testing.expectEqual(@as(?u32, null), pending.parent);

    const empty = &pa.nodes.items[1];
    try testing.expectEqual(PayloadStatus.empty, empty.payload_status);
    try testing.expectEqual(@as(?u32, 0), empty.parent); // Parent is PENDING.
}

test "onBlock Gloas stores gloas VariantIndices" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    const vi = pa.indices.get(root).?;
    switch (vi) {
        .gloas => |g| {
            try testing.expectEqual(@as(u32, 0), g.pending);
            try testing.expectEqual(@as(u32, 1), g.empty);
            try testing.expectEqual(@as(?u32, null), g.full);
        },
        .pre_gloas => return error.TestUnexpectedResult,
    }
}

test "onBlock Gloas with parent links correctly" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const child_root = makeRoot(2);

    // Parent is pre-Gloas (single FULL node).
    try pa.onBlock(testing.allocator, TestBlock.withRoot(parent_root), 0, null);

    // Child is Gloas.
    const child_block = TestBlock.asGloas(TestBlock.withParent(TestBlock.withRoot(child_root), parent_root));
    try pa.onBlock(testing.allocator, child_block, 0, null);

    // PENDING's parent should point to the pre-Gloas parent (index 0).
    const pending = &pa.nodes.items[1];
    try testing.expectEqual(@as(?u32, 0), pending.parent);
    try testing.expectEqual(PayloadStatus.pending, pending.payload_status);

    // EMPTY's parent should point to own PENDING (index 1).
    const empty = &pa.nodes.items[2];
    try testing.expectEqual(@as(?u32, 1), empty.parent);
    try testing.expectEqual(PayloadStatus.empty, empty.payload_status);
}

test "onPayload adds FULL variant" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);
    try testing.expectEqual(@as(usize, 2), pa.nodes.items.len);

    const payload_hash = makeRoot(0xAA);
    try pa.onPayload(testing.allocator, root, 0, payload_hash, 42, ZERO_HASH, null);

    // Now 3 nodes: PENDING, EMPTY, FULL.
    try testing.expectEqual(@as(usize, 3), pa.nodes.items.len);

    const full = &pa.nodes.items[2];
    try testing.expectEqual(PayloadStatus.full, full.payload_status);
    try testing.expectEqual(@as(?u32, 0), full.parent); // Parent is PENDING.
    // FULL node has EL metadata.
    try testing.expectEqual(ExecutionStatus.valid, full.extra_meta.executionStatus());
    try testing.expectEqual(payload_hash, full.extra_meta.executionPayloadBlockHash().?);

    // VariantIndices updated.
    const vi = pa.indices.get(root).?;
    switch (vi) {
        .gloas => |g| try testing.expectEqual(@as(?u32, 2), g.full),
        .pre_gloas => return error.TestUnexpectedResult,
    }
}

test "onPayload duplicate is no-op" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);
    try pa.onPayload(testing.allocator, root, 0, makeRoot(0xBB), 1, ZERO_HASH, null);
    try pa.onPayload(testing.allocator, root, 0, makeRoot(0xCC), 2, ZERO_HASH, null); // Second call is no-op.

    try testing.expectEqual(@as(usize, 3), pa.nodes.items.len);
}

test "onPayload for pre-Gloas is no-op" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.withRoot(root), 0, null);
    try pa.onPayload(testing.allocator, root, 0, makeRoot(0xDD), 1, ZERO_HASH, null);

    try testing.expectEqual(@as(usize, 1), pa.nodes.items.len);
}

test "propagateValidExecutionStatusByIndex marks syncing ancestors" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root_a = makeRoot(1);
    const root_b = makeRoot(2);

    // Parent with syncing status.
    var parent_block = TestBlock.withRoot(root_a);
    parent_block.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .syncing, .available),
    };
    try pa.onBlock(testing.allocator, parent_block, 0, null);

    // Child with valid status — triggers upward propagation.
    var child_block = TestBlock.withParent(TestBlock.withRoot(root_b), root_a);
    child_block.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 1, .valid, .available),
    };
    try pa.onBlock(testing.allocator, child_block, 0, null);

    // Parent should now be valid.
    const parent = &pa.nodes.items[0];
    try testing.expectEqual(ExecutionStatus.valid, parent.extra_meta.executionStatus());
}

test "VariantIndices defaultIndex" {
    const pre_gloas = VariantIndices{ .pre_gloas = 42 };
    try testing.expectEqual(@as(u32, 42), pre_gloas.defaultIndex());

    const gloas = VariantIndices{ .gloas = .{ .pending = 10, .empty = 11, .full = 12 } };
    try testing.expectEqual(@as(u32, 10), gloas.defaultIndex());
}

test "VariantIndices getByPayloadStatus" {
    const pre_gloas = VariantIndices{ .pre_gloas = 5 };
    try testing.expectEqual(@as(?u32, 5), pre_gloas.getByPayloadStatus(.full));

    const gloas = VariantIndices{ .gloas = .{ .pending = 10, .empty = 11 } };
    try testing.expectEqual(@as(?u32, 10), gloas.getByPayloadStatus(.pending));
    try testing.expectEqual(@as(?u32, 11), gloas.getByPayloadStatus(.empty));
    try testing.expectEqual(@as(?u32, null), gloas.getByPayloadStatus(.full));
}

test "VariantIndices allIndices" {
    const pre_gloas = VariantIndices{ .pre_gloas = 5 };
    const pre_gloas_all = pre_gloas.allIndices();
    try testing.expectEqual(@as(usize, 1), pre_gloas_all.len);
    try testing.expectEqual(@as(u32, 5), pre_gloas_all.get(0));

    const gloas_no_full = VariantIndices{ .gloas = .{ .pending = 10, .empty = 11 } };
    const gloas_all = gloas_no_full.allIndices();
    try testing.expectEqual(@as(usize, 2), gloas_all.len);

    const gloas_with_full = VariantIndices{ .gloas = .{ .pending = 10, .empty = 11, .full = 12 } };
    const gloas_all_3 = gloas_with_full.allIndices();
    try testing.expectEqual(@as(usize, 3), gloas_all_3.len);
}

test "getParentPayloadStatus pre-Gloas returns full" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    // Pre-Gloas block (no parent_block_hash) → always FULL.
    try testing.expectEqual(PayloadStatus.full, try pa.getParentPayloadStatus(makeRoot(1), null));
}

test "getParentPayloadStatus matching FULL variant returns full" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const bid_hash = makeRoot(0xAA);
    const payload_hash = makeRoot(0xCC);

    // Add parent with bid block hash, then create FULL with payload_hash.
    try pa.onBlock(testing.allocator, TestBlock.asGloasWithBidHash(TestBlock.withRoot(parent_root), bid_hash), 0, null);
    try pa.onPayload(testing.allocator, parent_root, 0, payload_hash, 1, makeRoot(0xDD), null);

    // parent_block_hash matches FULL's executionPayloadBlockHash (payload_hash) → FULL.
    try testing.expectEqual(PayloadStatus.full, try pa.getParentPayloadStatus(parent_root, payload_hash));
}

test "getParentPayloadStatus matching EMPTY variant returns empty" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const bid_hash = makeRoot(0xAA);

    // Add parent with bid block hash — only PENDING + EMPTY exist (no onPayload).
    try pa.onBlock(testing.allocator, TestBlock.asGloasWithBidHash(TestBlock.withRoot(parent_root), bid_hash), 0, null);

    // parent_block_hash matches EMPTY's executionPayloadBlockHash (bid_hash) → EMPTY.
    try testing.expectEqual(PayloadStatus.empty, try pa.getParentPayloadStatus(parent_root, bid_hash));
}

test "getParentPayloadStatus mismatched bid hash returns error" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const bid_hash = makeRoot(0xAA);

    // Add parent with bid block hash 0xAA.
    try pa.onBlock(testing.allocator, TestBlock.asGloasWithBidHash(TestBlock.withRoot(parent_root), bid_hash), 0, null);

    // parent_block_hash is 0xBB (no variant matches) → error.
    try testing.expectError(error.UnknownParentBlock, pa.getParentPayloadStatus(parent_root, makeRoot(0xBB)));
}

test "onBlockGloas links to correct parent variant via parent_block_hash" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const parent_root = makeRoot(1);
    const bid_hash = makeRoot(0xAA);
    const payload_hash = makeRoot(0xCC);

    // Parent: Gloas block with bid hash 0xAA.
    try pa.onBlock(testing.allocator, TestBlock.asGloasWithBidHash(TestBlock.withRoot(parent_root), bid_hash), 0, null);
    // Add FULL variant with execution_payload_block_hash = 0xCC.
    try pa.onPayload(testing.allocator, parent_root, 0, payload_hash, 42, ZERO_HASH, null);

    const parent_vi = pa.indices.get(parent_root).?;
    const parent_empty_idx = parent_vi.gloas.empty;
    const parent_full_idx = parent_vi.gloas.full.?;

    // Child A: parent_block_hash matches FULL's executionPayloadBlockHash (payload_hash) → links to FULL.
    var child_a = TestBlock.asGloasWithBidHash(
        TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(2)), parent_root),
        ZERO_HASH,
    );
    child_a.parent_block_hash = payload_hash;
    try pa.onBlock(testing.allocator, child_a, 1, null);

    const child_a_pending = &pa.nodes.items[pa.indices.get(makeRoot(2)).?.gloas.pending];
    try testing.expectEqual(parent_full_idx, child_a_pending.parent.?);

    // Child B: parent_block_hash matches EMPTY's executionPayloadBlockHash (bid_hash) → links to EMPTY.
    var child_b = TestBlock.asGloasWithBidHash(
        TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(3)), parent_root),
        ZERO_HASH,
    );
    child_b.parent_block_hash = bid_hash;
    try pa.onBlock(testing.allocator, child_b, 1, null);

    const child_b_pending = &pa.nodes.items[pa.indices.get(makeRoot(3)).?.gloas.pending];
    try testing.expectEqual(parent_empty_idx, child_b_pending.parent.?);
}

test "onBlockGloas initializes PTC votes" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    // PTC votes should be initialized to all false.
    const votes = pa.ptc_votes.get(root).?;
    try testing.expectEqual(@as(usize, 0), votes.count());
}

test "notifyPtcMessages sets votes" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    // Record some PTC votes.
    const indices = [_]u32{ 0, 1 };
    pa.notifyPtcMessages(root, &indices, true);

    const votes = pa.ptc_votes.get(root).?;
    try testing.expect(votes.isSet(0));
    try testing.expect(votes.isSet(1));
    if (preset.PTC_SIZE > 2) {
        try testing.expect(!votes.isSet(2));
    }
}

test "isPayloadTimely without FULL returns false" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    // Set all PTC votes to true, but no FULL variant.
    pa.ptc_votes.getPtr(root).?.* = ProtoArray.PtcVotes.initFull();

    try testing.expect(!pa.isPayloadTimely(root));
}

test "isPayloadTimely with FULL and supermajority returns true" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    // Add FULL variant.
    try pa.onPayload(testing.allocator, root, 0, makeRoot(0xAA), 1, ZERO_HASH, null);

    // Set more than PAYLOAD_TIMELY_THRESHOLD votes to true.
    pa.ptc_votes.getPtr(root).?.* = ProtoArray.PtcVotes.initFull();

    try testing.expect(pa.isPayloadTimely(root));
}

test "shouldExtendPayload timely payload returns true" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);
    try pa.onPayload(testing.allocator, root, 0, makeRoot(0xAA), 1, ZERO_HASH, null);

    // Make payload timely.
    pa.ptc_votes.getPtr(root).?.* = ProtoArray.PtcVotes.initFull();

    try testing.expect(try pa.shouldExtendPayload(root, null));
    try testing.expect(try pa.shouldExtendPayload(root, ZERO_HASH));
}

test "shouldExtendPayload no proposer boost returns true" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.asGloas(TestBlock.withRoot(root)), 0, null);

    // Not timely, but no proposer boost → extend.
    try testing.expect(try pa.shouldExtendPayload(root, null));
    try testing.expect(try pa.shouldExtendPayload(root, ZERO_HASH));
}

test "applyScoreChanges proposer boost does not accumulate across repeated calls" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const child_root = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(
        testing.allocator,
        TestBlock.withParent(TestBlock.withSlotAndRoot(1, child_root), ZERO_HASH),
        1,
        null,
    );

    const boost = ProtoArray.ProposerBoost{ .root = child_root, .score = 34 };

    var deltas_1 = [_]i64{ 0, 0 };
    try pa.applyScoreChanges(&deltas_1, boost, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    const weight_after_first = pa.nodes.items[1].weight;

    var deltas_2 = [_]i64{ 0, 0 };
    try pa.applyScoreChanges(&deltas_2, boost, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expectEqual(weight_after_first, pa.nodes.items[1].weight);
}

// Tree:
//            0
//           / \
//          1   2
//         / \
//        3   4
//       / \
//      5   6
//
test "findHead tiebreak without votes" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), ZERO_HASH), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_2), ZERO_HASH), 1, null);

    const root_3 = makeRoot(3);
    const root_4 = makeRoot(4);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_3), root_1), 2, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_4), root_1), 2, null);

    const root_5 = makeRoot(5);
    const root_6 = makeRoot(6);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(3, root_5), root_3), 3, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(3, root_6), root_3), 3, null);

    // No votes: highest-root tiebreak picks root_2 (0x02 > 0x01).
    var deltas = [_]i64{0} ** 7;
    try pa.applyScoreChanges(&deltas, null, 0, ZERO_HASH, 0, ZERO_HASH, 3);

    var head = try pa.findHead(ZERO_HASH, 3);
    try testing.expectEqual(root_2, head.block_root);

    // Weight on left branch shifts head to root_6.
    var deltas_vote = [_]i64{ 0, 0, 0, 0, 0, 0, 10 };
    try pa.applyScoreChanges(&deltas_vote, null, 0, ZERO_HASH, 0, ZERO_HASH, 3);

    head = try pa.findHead(ZERO_HASH, 3);
    try testing.expectEqual(root_6, head.block_root);
}

// Tree:
//       0
//      / \
//     1   2
//
test "votes shift head between branches" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), ZERO_HASH), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_2), ZERO_HASH), 1, null);

    // Vote 10 for root_1, 0 for root_2 → head is root_1.
    var deltas_a = [_]i64{ 0, 10, 0 };
    try pa.applyScoreChanges(&deltas_a, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);

    var head = try pa.findHead(ZERO_HASH, 1);
    try testing.expectEqual(root_1, head.block_root);

    // Move votes: -10 from root_1, +20 to root_2 → head is root_2.
    var deltas_b = [_]i64{ 0, -10, 20 };
    try pa.applyScoreChanges(&deltas_b, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);

    head = try pa.findHead(ZERO_HASH, 1);
    try testing.expectEqual(root_2, head.block_root);
}

// Chain: 0 (j=0,f=0) → 1 (j=0,f=0) → 2 (j=1,f=0) → 3 (j=2,f=1)
test "findHead with ffg checkpoint updates" {
    const root_0 = ZERO_HASH;
    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    const root_3 = makeRoot(3);

    var pa = ProtoArray.init(0, root_0, 0, root_0, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), root_0), 1, null);

    var block_2 = TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_2), root_1);
    block_2.justified_epoch = 1;
    block_2.justified_root = root_0;
    block_2.unrealized_justified_epoch = 1;
    block_2.unrealized_justified_root = root_0;
    try pa.onBlock(testing.allocator, block_2, 2, null);

    var block_3 = TestBlock.withParent(TestBlock.withSlotAndRoot(3, root_3), root_2);
    block_3.justified_epoch = 2;
    block_3.justified_root = root_1;
    block_3.finalized_epoch = 1;
    block_3.finalized_root = root_0;
    block_3.unrealized_justified_epoch = 2;
    block_3.unrealized_justified_root = root_1;
    block_3.unrealized_finalized_epoch = 1;
    block_3.unrealized_finalized_root = root_0;
    try pa.onBlock(testing.allocator, block_3, 3, null);

    var deltas_0 = [_]i64{0} ** 4;
    try pa.applyScoreChanges(&deltas_0, null, 0, root_0, 0, root_0, 3);

    var head = try pa.findHead(root_0, 3);
    try testing.expectEqual(root_3, head.block_root);

    // Advance finalized to epoch 1 — head stays at block 3.
    var deltas_1 = [_]i64{0} ** 4;
    try pa.applyScoreChanges(&deltas_1, null, 2, root_1, 1, root_0, 3);

    head = try pa.findHead(root_0, 3);
    try testing.expectEqual(root_3, head.block_root);
}

// Tree:
//       0
//      / \
//     1   2
//     |   |
//     3   4
//
test "votes shift head in binary tree" {
    const root_0 = ZERO_HASH;
    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    const root_3 = makeRoot(3);
    const root_4 = makeRoot(4);

    var pa = ProtoArray.init(0, root_0, 0, root_0, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), root_0), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_2), root_0), 1, null);

    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_3), root_1), 2, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_4), root_2), 2, null);

    var deltas = [_]i64{ 0, 0, 0, 10, 0 };
    try pa.applyScoreChanges(&deltas, null, 0, root_0, 0, root_0, 2);

    var head = try pa.findHead(root_0, 2);
    try testing.expectEqual(root_3, head.block_root);

    var deltas_2 = [_]i64{ 0, 0, 0, -10, 20 };
    try pa.applyScoreChanges(&deltas_2, null, 0, root_0, 0, root_0, 2);

    head = try pa.findHead(root_0, 2);
    try testing.expectEqual(root_4, head.block_root);
}

// Tree:
//       0 (finalized)
//      / \
//     1   2
//     |
//     3
//
test "isFinalizedRootOrDescendant" {
    const finalized_root = ZERO_HASH;
    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    const root_3 = makeRoot(3);

    var pa = ProtoArray.init(0, finalized_root, 0, finalized_root, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), finalized_root), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_2), finalized_root), 1, null);

    var block_3 = TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_3), root_1);
    block_3.finalized_epoch = 1;
    block_3.finalized_root = root_1;
    block_3.unrealized_finalized_epoch = 1;
    block_3.unrealized_finalized_root = root_1;
    try pa.onBlock(testing.allocator, block_3, 2, null);

    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[0]));
    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[1]));
    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[2]));
    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[3]));

    // Advance finalized to root_1 — root_2 is no longer a descendant.
    pa.finalized_epoch = 1;
    pa.finalized_root = root_1;

    try testing.expect(!pa.isFinalizedRootOrDescendant(&pa.nodes.items[2]));
    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[1]));
    try testing.expect(pa.isFinalizedRootOrDescendant(&pa.nodes.items[3]));
}

// Tree:
//       0
//      / \
//     1   2
//
test "invalid execution status zeroes weight and moves head" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    var child_1 = TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(1)), ZERO_HASH);
    child_1.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(makeRoot(0xA1), 1, .syncing, .available),
    };
    try pa.onBlock(testing.allocator, child_1, 1, null);

    var child_2 = TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(2)), ZERO_HASH);
    child_2.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(makeRoot(0xA2), 2, .syncing, .available),
    };
    try pa.onBlock(testing.allocator, child_2, 1, null);

    var deltas = [_]i64{ 0, 30, 10 };
    try pa.applyScoreChanges(&deltas, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);

    var head = try pa.findHead(ZERO_HASH, 1);
    try testing.expectEqual(makeRoot(1), head.block_root);

    pa.nodes.items[1].extra_meta.post_merge.execution_status = .invalid;

    var deltas_2 = [_]i64{ 0, 0, 0 };
    try pa.applyScoreChanges(&deltas_2, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expectEqual(@as(i64, 0), pa.nodes.items[1].weight);

    head = try pa.findHead(ZERO_HASH, 1);
    try testing.expectEqual(makeRoot(2), head.block_root);
}

test "invalid execution status reverts proposer boost" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    var child = TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(1)), ZERO_HASH);
    child.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(makeRoot(0xA1), 1, .syncing, .available),
    };
    try pa.onBlock(testing.allocator, child, 1, null);

    const boost = ProtoArray.ProposerBoost{ .root = makeRoot(1), .score = 1000 };
    var deltas = [_]i64{ 0, 5 };
    try pa.applyScoreChanges(&deltas, boost, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expect(pa.nodes.items[1].weight > 5);

    pa.nodes.items[1].extra_meta.post_merge.execution_status = .invalid;

    var deltas_2 = [_]i64{ 0, 0 };
    try pa.applyScoreChanges(&deltas_2, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expectEqual(@as(i64, 0), pa.nodes.items[1].weight);
}

test "findHead unknown justified root returns error" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);

    try testing.expectError(error.JustifiedNodeUnknown, pa.findHead(makeRoot(0xFF), 0));
}

test "nodeIsViableForHead rejects invalid execution" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    // Can't insert invalid directly, so insert as syncing then mutate.
    var block_syncing = TestBlock.withRoot(makeRoot(1));
    block_syncing.extra_meta = .{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .syncing, .available),
    };
    try pa.onBlock(testing.allocator, block_syncing, 0, null);

    try testing.expect(pa.nodeIsViableForHead(&pa.nodes.items[0], 0));

    pa.nodes.items[0].extra_meta.post_merge.execution_status = .invalid;
    try testing.expect(!pa.nodeIsViableForHead(&pa.nodes.items[0], 0));
}

test "negative weight delta propagation" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, makeRoot(1)), ZERO_HASH), 1, null);

    // Add weight then remove more than exists.
    var deltas_add = [_]i64{ 0, 10 };
    try pa.applyScoreChanges(&deltas_add, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expectEqual(@as(i64, 10), pa.nodes.items[1].weight);

    var deltas_sub = [_]i64{ 0, -20 };
    try pa.applyScoreChanges(&deltas_sub, null, 0, ZERO_HASH, 0, ZERO_HASH, 1);
    try testing.expectEqual(@as(i64, -10), pa.nodes.items[1].weight);
}

// Chain: 0 → 1 → 2 → 3
test "getAncestor returns ancestor at slot" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root_0 = ZERO_HASH;
    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    const root_3 = makeRoot(3);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), root_0), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_2), root_1), 2, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(3, root_3), root_2), 3, null);

    const ancestor = try pa.getAncestor(root_3, 1);
    try testing.expectEqual(root_1, ancestor.block_root);

    const genesis_ancestor = try pa.getAncestor(root_3, 0);
    try testing.expectEqual(root_0, genesis_ancestor.block_root);
}

test "getAncestor at own slot returns self" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root_1 = makeRoot(1);
    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(5, root_1), ZERO_HASH), 5, null);

    const ancestor = try pa.getAncestor(root_1, 5);
    try testing.expectEqual(root_1, ancestor.block_root);
}

test "getAncestor skips slot gap" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root_0 = ZERO_HASH;
    const root_1 = makeRoot(1);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(5, root_1), root_0), 5, null);

    // Slot 3 is between genesis(0) and root_1(5) — snaps to genesis.
    const ancestor = try pa.getAncestor(root_1, 3);
    try testing.expectEqual(root_0, ancestor.block_root);
}

// Tree:
//        0
//       / \
//      1   2
//      |   |
//      3   4
//
test "getAncestor finds common ancestor" {
    var pa = ProtoArray.init(0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const root_0 = ZERO_HASH;
    const root_1 = makeRoot(1);
    const root_2 = makeRoot(2);
    const root_3 = makeRoot(3);
    const root_4 = makeRoot(4);

    try pa.onBlock(testing.allocator, TestBlock.genesis(), 0, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_1), root_0), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(1, root_2), root_0), 1, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_3), root_1), 2, null);
    try pa.onBlock(testing.allocator, TestBlock.withParent(TestBlock.withSlotAndRoot(2, root_4), root_2), 2, null);

    const anc_left = try pa.getAncestor(root_3, 0);
    const anc_right = try pa.getAncestor(root_4, 0);
    try testing.expectEqual(root_0, anc_left.block_root);
    try testing.expectEqual(root_0, anc_right.block_root);
    try testing.expectEqual(anc_left.block_root, anc_right.block_root);
}
