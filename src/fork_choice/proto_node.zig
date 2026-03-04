const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

/// Sentinel for "no parent" — root node of the DAG.
pub const ZERO_HASH: Root = .{0} ** 32;

/// Sentinel for "validator has no valid vote" (e.g., vote target was pruned).
/// Safe because 0xFFFFFFFF / slots-per-year > 1,634 years of non-finalized network.
pub const NULL_VOTE_INDEX: u32 = 0xFFFFFFFF;

/// Execution status of a block in fork choice.
///
/// State transitions:
///   Syncing → Valid    ✅ (EL confirmed payload valid)
///   Syncing → Invalid  ✅ (EL confirmed payload invalid)
///   Valid → Invalid    ❌ (never reverts once valid)
///   Invalid → *        ❌ (terminal state)
pub const ExecutionStatus = enum(u3) {
    /// EL confirmed payload valid.
    valid,
    /// EL is syncing; payload validity unknown (optimistic sync).
    syncing,
    /// Block is from before The Merge; no execution payload exists.
    pre_merge,
    /// EL confirmed payload invalid (terminal state).
    invalid,
    /// Gloas: beacon block without embedded execution payload (ePBS).
    /// The execution payload arrives separately via SignedExecutionPayloadEnvelope.
    payload_separated,
};

/// Data availability status for a block's blob data.
pub const DataAvailabilityStatus = enum(u2) {
    /// Block is from before data availability requirements.
    pre_data,
    /// Validator activities can't be performed on out-of-range data.
    out_of_range,
    /// Data is available and verified.
    available,
    /// Gloas: beacon blocks have no DA requirement; execution payload is separate.
    not_required,
};

/// Metadata that depends on whether the block is pre-merge or post-merge.
pub const BlockExtraMeta = union(enum) {
    post_merge: PostMergeMeta,
    pre_merge: void,

    pub const PostMergeMeta = struct {
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_status: ExecutionStatus,
        data_availability_status: DataAvailabilityStatus,
    };

    pub fn executionStatus(self: BlockExtraMeta) ExecutionStatus {
        return switch (self) {
            .post_merge => |m| m.execution_status,
            .pre_merge => .pre_merge,
        };
    }

    pub fn dataAvailabilityStatus(self: BlockExtraMeta) DataAvailabilityStatus {
        return switch (self) {
            .post_merge => |m| m.data_availability_status,
            .pre_merge => .pre_data,
        };
    }
};

/// A block to be applied to the fork choice DAG.
/// Corresponds to Lodestar's `ProtoBlock`.
pub const ProtoBlock = struct {
    // ── Core fields used by ProtoArray algorithm ──
    slot: Slot,
    block_root: Root,
    parent_root: Root,

    // ── Passthrough: not used by ProtoArray, but needed by upstream ──
    state_root: Root,
    /// The root that would be used for attestation.data.target.root
    /// if a LMD vote were cast for this block.
    target_root: Root,

    // ── FFG checkpoints (realized) ──
    justified_epoch: Epoch,
    justified_root: Root,
    finalized_epoch: Epoch,
    finalized_root: Root,

    // ── Unrealized checkpoints (pull-up FFG, anti-bouncing attack) ──
    unrealized_justified_epoch: Epoch,
    unrealized_justified_root: Root,
    unrealized_finalized_epoch: Epoch,
    unrealized_finalized_root: Root,

    // ── Execution layer metadata ──
    extra_meta: BlockExtraMeta,

    /// Whether block arrived before the 4-second mark (timeliness for late-block reorg).
    timeliness: bool,

    // ── Gloas (ePBS) fields ──
    builder_index: ?ValidatorIndex = null,
    block_hash_hex: ?Root = null,
};

/// A node in the ProtoArray DAG = ProtoBlock + DAG metadata.
///
/// All indices refer to positions in the flat `nodes` array.
/// This is a cache-friendly design: no pointers, no heap allocations per node.
pub const ProtoNode = struct {
    block: ProtoBlock,

    /// Index of parent node in the nodes array. null for the root.
    parent: ?u32 = null,

    /// LMD-GHOST weight: sum of effective balances of validators
    /// whose latest vote is for this subtree.
    weight: i64 = 0,

    /// Index of the highest-weight child.
    best_child: ?u32 = null,

    /// Index of the best leaf reachable from this node.
    /// findHead: justified_root → bestDescendant in O(1).
    best_descendant: ?u32 = null,
};

/// Response from the execution layer about a payload's validity.
pub const LVHExecResponse = union(enum) {
    valid: LVHValidResponse,
    invalid: LVHInvalidResponse,
};

pub const LVHValidResponse = struct {
    latest_valid_exec_hash: Root,
};

pub const LVHInvalidResponse = struct {
    /// The last valid execution payload hash. null means the EL doesn't know
    /// the last valid point — this triggers an irrecoverable error.
    latest_valid_exec_hash: ?Root,
    invalidate_from_parent_block_root: Root,
};

// ── Tests ──

test "ExecutionStatus enum values" {
    try testing.expectEqual(@intFromEnum(ExecutionStatus.valid), 0);
    try testing.expectEqual(@intFromEnum(ExecutionStatus.syncing), 1);
    try testing.expectEqual(@intFromEnum(ExecutionStatus.pre_merge), 2);
    try testing.expectEqual(@intFromEnum(ExecutionStatus.invalid), 3);
    try testing.expectEqual(@intFromEnum(ExecutionStatus.payload_separated), 4);
}

test "DataAvailabilityStatus enum values" {
    try testing.expectEqual(@intFromEnum(DataAvailabilityStatus.pre_data), 0);
    try testing.expectEqual(@intFromEnum(DataAvailabilityStatus.available), 2);
}

test "ZERO_HASH is all zeros" {
    for (ZERO_HASH) |byte| {
        try testing.expectEqual(byte, 0);
    }
}

test "NULL_VOTE_INDEX sentinel value" {
    try testing.expectEqual(NULL_VOTE_INDEX, 0xFFFFFFFF);
}

test "BlockExtraMeta pre_merge accessors" {
    const meta = BlockExtraMeta{ .pre_merge = {} };
    try testing.expectEqual(meta.executionStatus(), .pre_merge);
    try testing.expectEqual(meta.dataAvailabilityStatus(), .pre_data);
}

test "BlockExtraMeta post_merge accessors" {
    const meta = BlockExtraMeta{
        .post_merge = .{
            .execution_payload_block_hash = ZERO_HASH,
            .execution_payload_number = 42,
            .execution_status = .syncing,
            .data_availability_status = .available,
        },
    };
    try testing.expectEqual(meta.executionStatus(), .syncing);
    try testing.expectEqual(meta.dataAvailabilityStatus(), .available);
}

test "ProtoNode default values" {
    const block = ProtoBlock{
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
    const node = ProtoNode{ .block = block };

    try testing.expectEqual(node.parent, null);
    try testing.expectEqual(node.weight, 0);
    try testing.expectEqual(node.best_child, null);
    try testing.expectEqual(node.best_descendant, null);
    try testing.expectEqual(node.block.builder_index, null);
    try testing.expectEqual(node.block.block_hash_hex, null);
}
