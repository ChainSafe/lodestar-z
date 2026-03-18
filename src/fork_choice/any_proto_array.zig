const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const ForkSeq = @import("config").ForkSeq;
const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;

const proto_array_mod = @import("proto_array.zig");
const ProtoArrayFn = proto_array_mod.ProtoArray;
const ProtoArrayError = proto_array_mod.ProtoArrayError;
const DEFAULT_PRUNE_THRESHOLD = proto_array_mod.DEFAULT_PRUNE_THRESHOLD;

const proto_node = @import("proto_node.zig");
const ProtoBlock = proto_node.ProtoBlock;
const ProtoNodeFn = proto_node.ProtoNode;
const PayloadStatus = proto_node.PayloadStatus;
const BlockExtraMeta = proto_node.BlockExtraMeta;
const LVHExecResponse = proto_node.LVHExecResponse;

const ZERO_HASH = constants.ZERO_HASH;

/// Returns the concrete ProtoArray type for a given fork.
fn ProtoArrayForFork(comptime fork: ForkSeq) type {
    return ProtoArrayFn(fork);
}

/// Convert a ProtoNode from one fork to another, preserving DAG metadata.
///
/// Uses toBlock()/fromBlock() to transfer all block fields through the
/// fork-independent ProtoBlock intermediary, then copies DAG-only fields
/// (parent, weight, best_child, best_descendant) which are not part of ProtoBlock.
fn migrateNode(
    comptime from: ForkSeq,
    comptime to: ForkSeq,
    old_node: ProtoNodeFn(from),
) ProtoNodeFn(to) {
    var new_node = ProtoNodeFn(to).fromBlock(old_node.toBlock());
    new_node.parent = old_node.parent;
    new_node.weight = old_node.weight;
    new_node.best_child = old_node.best_child;
    new_node.best_descendant = old_node.best_descendant;
    return new_node;
}

/// Convert an index entry from one fork's format to another's.
///
/// Pre-Gloas uses u32 (single node per block root).
/// Gloas uses GloasIndices (pending, empty, full variant indices).
/// When migrating pre-Gloas -> Gloas, each u32 index maps to all three
/// variant slots since pre-Gloas blocks are always "full" (payload embedded).
fn migrateIndexEntry(
    comptime from: ForkSeq,
    comptime to: ForkSeq,
    old_entry: ProtoArrayForFork(from).IndexEntry,
) ProtoArrayForFork(to).IndexEntry {
    const from_is_gloas = comptime from.gte(.gloas);
    const to_is_gloas = comptime to.gte(.gloas);

    if (from_is_gloas and to_is_gloas) {
        // GloasIndices -> GloasIndices: identical layout.
        return old_entry;
    } else if (!from_is_gloas and !to_is_gloas) {
        // u32 -> u32: identical layout.
        return old_entry;
    } else if (!from_is_gloas and to_is_gloas) {
        // u32 -> GloasIndices: pre-Gloas node maps to all three variant slots.
        return .{ .pending = old_entry, .empty = old_entry, .full = old_entry };
    } else {
        @compileError("Cannot downgrade from Gloas to pre-Gloas");
    }
}

/// Runtime dispatch wrapper for the comptime-parameterized `ProtoArray(ForkSeq)`.
///
/// Each variant holds a `ProtoArray(fork)` for the corresponding fork.
/// Methods dispatch via `inline else` to the active variant, providing
/// a uniform API regardless of which fork is active at runtime.
///
/// Follows the same pattern as `AnyBeaconState` in `src/fork_types/any_beacon_state.zig`.
pub const AnyProtoArray = union(ForkSeq) {
    phase0: ProtoArrayForFork(.phase0),
    altair: ProtoArrayForFork(.altair),
    bellatrix: ProtoArrayForFork(.bellatrix),
    capella: ProtoArrayForFork(.capella),
    deneb: ProtoArrayForFork(.deneb),
    electra: ProtoArrayForFork(.electra),
    fulu: ProtoArrayForFork(.fulu),
    gloas: ProtoArrayForFork(.gloas),

    /// Fork-independent proposer boost data.
    ///
    /// Structurally identical to each `ProtoArray(fork).ProposerBoost`
    /// but defined here to provide a common type across all fork variants.
    pub const ProposerBoost = struct {
        root: Root,
        score: u64,
    };

    // ── Factory functions ──

    /// Create an empty AnyProtoArray for the given fork with checkpoint state.
    pub fn initForFork(
        fork: ForkSeq,
        justified_epoch: Epoch,
        justified_root: Root,
        finalized_epoch: Epoch,
        finalized_root: Root,
        prune_threshold: u32,
    ) AnyProtoArray {
        switch (fork) {
            inline else => |f| {
                return @unionInit(
                    AnyProtoArray,
                    @tagName(f),
                    ProtoArrayForFork(f).init(
                        justified_epoch,
                        justified_root,
                        finalized_epoch,
                        finalized_root,
                        prune_threshold,
                    ),
                );
            },
        }
    }

    /// Create an AnyProtoArray initialized with a genesis/anchor block.
    pub fn initializeForFork(
        fork: ForkSeq,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError)!AnyProtoArray {
        switch (fork) {
            inline else => |f| {
                const pa = try ProtoArrayForFork(f).initialize(
                    allocator,
                    block,
                    current_slot,
                );
                return @unionInit(AnyProtoArray, @tagName(f), pa);
            },
        }
    }

    // ── Tag / cast ──

    /// Return the active fork tag.
    pub fn forkSeq(self: AnyProtoArray) ForkSeq {
        return switch (self) {
            inline else => |_, tag| tag,
        };
    }

    /// Cast to a concrete `ProtoArray(f)` pointer for direct access.
    /// Caller must ensure the active tag matches `f`.
    pub fn castToFork(self: *AnyProtoArray, comptime f: ForkSeq) *ProtoArrayForFork(f) {
        return &@field(self, @tagName(f));
    }

    // ── Dispatch methods ──

    /// Free all owned memory.
    pub fn deinit(self: *AnyProtoArray, allocator: Allocator) void {
        switch (self.*) {
            inline else => |*pa| pa.deinit(allocator),
        }
    }

    /// Get the default/canonical payload status for a block root.
    /// Pre-Gloas: returns .full. Gloas: returns .pending.
    /// Returns null if the block root is not found.
    pub fn getDefaultVariant(self: *AnyProtoArray, block_root: Root) ?PayloadStatus {
        return switch (self.*) {
            inline else => |*pa| pa.getDefaultVariant(block_root),
        };
    }

    /// Get the node index for the default/canonical variant.
    /// Pre-Gloas: returns the single (FULL) index.
    /// Gloas: returns the PENDING variant index.
    pub fn getDefaultNodeIndex(self: *AnyProtoArray, block_root: Root) ?u32 {
        return switch (self.*) {
            inline else => |*pa| pa.getDefaultNodeIndex(block_root),
        };
    }

    /// Get node index for a specific root + payload status combination.
    pub fn getNodeIndexByRootAndStatus(
        self: *AnyProtoArray,
        root: Root,
        status: PayloadStatus,
    ) ?u32 {
        return switch (self.*) {
            inline else => |*pa| pa.getNodeIndexByRootAndStatus(root, status),
        };
    }

    /// Returns true if a block with the given root has been inserted.
    pub fn hasBlock(self: *AnyProtoArray, root: Root) bool {
        return switch (self.*) {
            inline else => |*pa| pa.hasBlock(root),
        };
    }

    /// Register a block with the fork choice.
    pub fn onBlock(
        self: *AnyProtoArray,
        allocator: Allocator,
        block: ProtoBlock,
        current_slot: Slot,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        switch (self.*) {
            inline else => |*pa| try pa.onBlock(
                allocator,
                block,
                current_slot,
                proposer_boost_root,
            ),
        }
    }

    /// Called when an execution payload is received for a block (Gloas only).
    pub fn onExecutionPayload(
        self: *AnyProtoArray,
        allocator: Allocator,
        block_root: Root,
        current_slot: Slot,
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_payload_state_root: Root,
        proposer_boost_root: ?Root,
    ) (Allocator.Error || ProtoArrayError)!void {
        switch (self.*) {
            inline else => |*pa| try pa.onExecutionPayload(
                allocator,
                block_root,
                current_slot,
                execution_payload_block_hash,
                execution_payload_number,
                execution_payload_state_root,
                proposer_boost_root,
            ),
        }
    }

    /// Apply score changes and update best descendants.
    ///
    /// Converts the fork-independent `ProposerBoost` to the variant's
    /// internal `ProposerBoost` type via field-by-field copy.
    pub fn applyScoreChanges(
        self: *AnyProtoArray,
        deltas: []i64,
        proposer_boost: ?ProposerBoost,
        justified_epoch: Epoch,
        justified_root: Root,
        finalized_epoch: Epoch,
        finalized_root: Root,
        current_slot: Slot,
    ) ProtoArrayError!void {
        switch (self.*) {
            inline else => |*pa, fork_tag| {
                const PA = ProtoArrayForFork(fork_tag);
                const inner_boost: ?PA.ProposerBoost = if (proposer_boost) |b|
                    .{ .root = b.root, .score = b.score }
                else
                    null;
                try pa.applyScoreChanges(
                    deltas,
                    inner_boost,
                    justified_epoch,
                    justified_root,
                    finalized_epoch,
                    finalized_root,
                    current_slot,
                );
            },
        }
    }

    /// Find the head block (best descendant of the justified root).
    ///
    /// Returns a fork-independent `ProtoBlock` via `toBlock()` conversion,
    /// since the underlying `*const Node` type differs per variant.
    pub fn findHeadBlock(
        self: *AnyProtoArray,
        justified_root: Root,
        current_slot: Slot,
    ) ProtoArrayError!ProtoBlock {
        switch (self.*) {
            inline else => |*pa| {
                const node = try pa.findHead(justified_root, current_slot);
                return node.toBlock();
            },
        }
    }

    /// Return a stack-copy ProtoBlock by root and payload status, or null.
    pub fn getBlock(
        self: *AnyProtoArray,
        root: Root,
        status: PayloadStatus,
    ) ?ProtoBlock {
        return switch (self.*) {
            inline else => |*pa| pa.getBlock(root, status),
        };
    }

    /// Return the number of unique block roots in the DAG.
    pub fn length(self: *AnyProtoArray) usize {
        return switch (self.*) {
            inline else => |*pa| pa.length(),
        };
    }

    /// Check if descendant_root is a descendant of (or equal to) ancestor_root.
    pub fn isDescendant(
        self: *AnyProtoArray,
        ancestor_root: Root,
        ancestor_status: PayloadStatus,
        descendant_root: Root,
        descendant_status: PayloadStatus,
    ) bool {
        return switch (self.*) {
            inline else => |*pa| pa.isDescendant(
                ancestor_root,
                ancestor_status,
                descendant_root,
                descendant_status,
            ),
        };
    }

    /// Process execution layer response for latest valid hash.
    pub fn validateLatestHash(
        self: *AnyProtoArray,
        allocator: Allocator,
        response: LVHExecResponse,
        current_slot: Slot,
    ) (Allocator.Error || ProtoArrayError)!void {
        switch (self.*) {
            inline else => |*pa| try pa.validateLatestHash(
                allocator,
                response,
                current_slot,
            ),
        }
    }

    /// Prune nodes before the finalized root, adjusting all indices.
    /// Returns the number of nodes pruned.
    pub fn maybePrune(
        self: *AnyProtoArray,
        finalized_root: Root,
    ) ProtoArrayError!u32 {
        return switch (self.*) {
            inline else => |*pa| try pa.maybePrune(finalized_root),
        };
    }

    // ── Fork upgrade ──

    /// Upgrade the ProtoArray to a later fork, migrating all internal state.
    ///
    /// If the active fork is already at or past `to`, this is a no-op.
    ///
    /// Migration strategy:
    ///   - Pre-Gloas to pre-Gloas: trivial (identical node/index layout).
    ///   - Pre-Gloas to Gloas: converts u32 indices to GloasIndices (all three
    ///     variant slots point to the same node), adds Gloas fields to nodes.
    ///   - Gloas to Gloas: no-op (caught by gte check).
    pub fn upgradeToFork(
        self: *AnyProtoArray,
        comptime to: ForkSeq,
        allocator: Allocator,
    ) Allocator.Error!void {
        switch (self.*) {
            inline else => |*pa, from_tag| {
                // Already at or past target fork.
                if (comptime from_tag.gte(to)) return;

                const ToPA = ProtoArrayForFork(to);

                // Create new ProtoArray with the same checkpoint state.
                var new_pa = ToPA.init(
                    pa.justified_epoch,
                    pa.justified_root,
                    pa.finalized_epoch,
                    pa.finalized_root,
                    pa.prune_threshold,
                );
                errdefer new_pa.deinit(allocator);

                // Copy proposer boost (field-by-field for type safety).
                new_pa.previous_proposer_boost = if (pa.previous_proposer_boost) |b|
                    .{ .root = b.root, .score = b.score }
                else
                    null;

                // Copy LVH error.
                new_pa.lvh_error = pa.lvh_error;

                // Migrate nodes.
                try new_pa.nodes.ensureTotalCapacity(allocator, pa.nodes.items.len);
                for (pa.nodes.items) |old_node| {
                    new_pa.nodes.appendAssumeCapacity(migrateNode(from_tag, to, old_node));
                }

                // Migrate indices.
                try new_pa.indices.ensureUnusedCapacity(allocator, pa.indices.count());
                var iter = pa.indices.iterator();
                while (iter.next()) |entry| {
                    new_pa.indices.putAssumeCapacity(
                        entry.key_ptr.*,
                        migrateIndexEntry(from_tag, to, entry.value_ptr.*),
                    );
                }

                // Deinit old variant, then write new.
                pa.deinit(allocator);
                self.* = @unionInit(AnyProtoArray, @tagName(to), new_pa);
            },
        }
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
};

fn makeRoot(byte: u8) Root {
    var root = ZERO_HASH;
    root[0] = byte;
    return root;
}

test "AnyProtoArray forkSeq returns correct active tag" {
    var pa = AnyProtoArray.initForFork(.phase0, 0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);
    try testing.expectEqual(ForkSeq.phase0, pa.forkSeq());

    var pa2 = AnyProtoArray.initForFork(.gloas, 0, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa2.deinit(testing.allocator);
    try testing.expectEqual(ForkSeq.gloas, pa2.forkSeq());
}

test "AnyProtoArray castToFork returns correctly typed pointer" {
    var pa = AnyProtoArray.initForFork(.altair, 1, ZERO_HASH, 0, ZERO_HASH, 0);
    defer pa.deinit(testing.allocator);

    const typed = pa.castToFork(.altair);
    try testing.expectEqual(@as(Epoch, 1), typed.justified_epoch);
    try testing.expectEqual(@as(Epoch, 0), typed.finalized_epoch);
}

test "AnyProtoArray basic dispatch: deinit, length, hasBlock" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), pa.length());
    try testing.expect(pa.hasBlock(ZERO_HASH));
    try testing.expect(!pa.hasBlock(makeRoot(0xff)));
}

test "AnyProtoArray onBlock and findHeadBlock" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    // Add a child block at slot 1.
    const child_root = makeRoot(1);
    const child = TestBlock.withParent(
        TestBlock.withSlotAndRoot(1, child_root),
        ZERO_HASH,
    );
    try pa.onBlock(testing.allocator, child, 1, null);

    try testing.expectEqual(@as(usize, 2), pa.length());
    try testing.expect(pa.hasBlock(child_root));

    // Head should be the child (best descendant of justified root).
    const head = try pa.findHeadBlock(ZERO_HASH, 1);
    try testing.expectEqual(@as(Slot, 1), head.slot);
    try testing.expect(std.mem.eql(u8, &child_root, &head.block_root));
}

test "AnyProtoArray upgradeToFork phase0 to altair (same layout)" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    try testing.expectEqual(ForkSeq.phase0, pa.forkSeq());

    // Add a child block before upgrading.
    const child_root = makeRoot(1);
    const child = TestBlock.withParent(
        TestBlock.withSlotAndRoot(1, child_root),
        ZERO_HASH,
    );
    try pa.onBlock(testing.allocator, child, 1, null);
    try testing.expectEqual(@as(usize, 2), pa.length());

    try pa.upgradeToFork(.altair, testing.allocator);
    defer pa.deinit(testing.allocator);

    try testing.expectEqual(ForkSeq.altair, pa.forkSeq());
    try testing.expectEqual(@as(usize, 2), pa.length());
    try testing.expect(pa.hasBlock(ZERO_HASH));
    try testing.expect(pa.hasBlock(child_root));

    // Head should still be the child after upgrade.
    const head = try pa.findHeadBlock(ZERO_HASH, 1);
    try testing.expectEqual(@as(Slot, 1), head.slot);
    try testing.expect(std.mem.eql(u8, &child_root, &head.block_root));
}

test "AnyProtoArray upgradeToFork fulu to gloas (layout change)" {
    var pa = try AnyProtoArray.initializeForFork(
        .fulu,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    try testing.expectEqual(ForkSeq.fulu, pa.forkSeq());
    try testing.expectEqual(@as(usize, 1), pa.length());

    try pa.upgradeToFork(.gloas, testing.allocator);
    defer pa.deinit(testing.allocator);

    try testing.expectEqual(ForkSeq.gloas, pa.forkSeq());
    try testing.expectEqual(@as(usize, 1), pa.length());
    try testing.expect(pa.hasBlock(ZERO_HASH));

    // After upgrade to Gloas, the pre-Gloas block should be accessible
    // via all three payload status variants (all mapped to same node).
    const block_full = pa.getBlock(ZERO_HASH, .full);
    try testing.expect(block_full != null);
    try testing.expectEqual(PayloadStatus.full, block_full.?.payload_status);

    const block_pending = pa.getBlock(ZERO_HASH, .pending);
    try testing.expect(block_pending != null);

    const block_empty = pa.getBlock(ZERO_HASH, .empty);
    try testing.expect(block_empty != null);
}

test "AnyProtoArray upgradeToFork is no-op for same or past fork" {
    var pa = try AnyProtoArray.initializeForFork(
        .deneb,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    // Upgrade to same fork: no-op.
    try pa.upgradeToFork(.deneb, testing.allocator);
    try testing.expectEqual(ForkSeq.deneb, pa.forkSeq());
    try testing.expectEqual(@as(usize, 1), pa.length());

    // Upgrade to earlier fork: no-op.
    try pa.upgradeToFork(.phase0, testing.allocator);
    try testing.expectEqual(ForkSeq.deneb, pa.forkSeq());
}

test "AnyProtoArray getDefaultVariant and getDefaultNodeIndex" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    // Pre-Gloas: default variant is .full.
    try testing.expectEqual(@as(?PayloadStatus, .full), pa.getDefaultVariant(ZERO_HASH));
    try testing.expectEqual(@as(?u32, 0), pa.getDefaultNodeIndex(ZERO_HASH));

    // Unknown root returns null.
    try testing.expectEqual(@as(?PayloadStatus, null), pa.getDefaultVariant(makeRoot(0xff)));
    try testing.expectEqual(@as(?u32, null), pa.getDefaultNodeIndex(makeRoot(0xff)));
}

test "AnyProtoArray getBlock returns null for unknown root" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    try testing.expect(pa.getBlock(ZERO_HASH, .full) != null);
    try testing.expect(pa.getBlock(makeRoot(0xff), .full) == null);
}

test "AnyProtoArray isDescendant through dispatch" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    const child_root = makeRoot(1);
    const child = TestBlock.withParent(
        TestBlock.withSlotAndRoot(1, child_root),
        ZERO_HASH,
    );
    try pa.onBlock(testing.allocator, child, 1, null);

    // child is a descendant of genesis.
    try testing.expect(pa.isDescendant(ZERO_HASH, .full, child_root, .full));
    // genesis is NOT a descendant of child.
    try testing.expect(!pa.isDescendant(child_root, .full, ZERO_HASH, .full));
    // A node is a descendant of itself.
    try testing.expect(pa.isDescendant(child_root, .full, child_root, .full));
}

test "AnyProtoArray maybePrune through dispatch" {
    var pa = try AnyProtoArray.initializeForFork(
        .phase0,
        testing.allocator,
        TestBlock.genesis(),
        0,
    );
    defer pa.deinit(testing.allocator);

    // Prune with genesis as finalized: prune_threshold is 0, finalized is at index 0,
    // so nothing is pruned (no nodes before finalized).
    const pruned = try pa.maybePrune(ZERO_HASH);
    try testing.expectEqual(@as(u32, 0), pruned);
}
