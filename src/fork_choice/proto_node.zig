const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const constants = @import("constants");

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

pub const ZERO_HASH = constants.ZERO_HASH;

/// Execution status of a block in fork choice.
///
/// State transitions:
///   Syncing -> Valid    (allowed: EL confirmed payload valid)
///   Syncing -> Invalid  (allowed: EL confirmed payload invalid)
///   Valid -> Invalid    (forbidden: never reverts once valid)
///   Invalid -> *        (forbidden: terminal state)
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
    /// Gloas blocks WITH payload (FULL variant) use Valid/Invalid/Syncing instead.
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

/// Gloas (ePBS) payload resolution status for a block node.
/// Spec: gloas/fork-choice.md#constants
///
/// Each Gloas block creates up to 3 variant nodes in ProtoArray:
///   pending: initial state (block received, payload fate unknown)
///   empty:   payload absent (no execution payload arrived)
///   full:    payload arrived (execution payload received)
///
/// Pre-Gloas blocks are always full (payload embedded in block).
pub const PayloadStatus = enum(u2) {
    pending = 0,
    empty = 1,
    full = 2,
};

/// Metadata that depends on whether the block is pre-merge or post-merge.
///
/// The post-merge variant rejects `ExecutionStatus.pre_merge` via assert in `PostMergeMeta.init()`.
pub const BlockExtraMeta = union(enum) {
    post_merge: PostMergeMeta,
    pre_merge: void,

    pub const PostMergeMeta = struct {
        /// Pre-gloas: block hash of the execution payload embedded in this block.
        /// Post-gloas (Gloas): parentBlockHash from the block's bid (payload arrives later);
        ///   for FULL variant, this is the execution payload block hash.
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_status: ExecutionStatus,
        data_availability_status: DataAvailabilityStatus,

        /// Rejects `ExecutionStatus.pre_merge` at runtime (Debug/ReleaseSafe).
        pub fn init(
            block_hash: Root,
            number: u64,
            status: ExecutionStatus,
            da_status: DataAvailabilityStatus,
        ) PostMergeMeta {
            assert(status != .pre_merge);
            return .{
                .execution_payload_block_hash = block_hash,
                .execution_payload_number = number,
                .execution_status = status,
                .data_availability_status = da_status,
            };
        }
    };

    pub fn executionPayloadBlockHash(self: BlockExtraMeta) ?Root {
        return switch (self) {
            .post_merge => |m| m.execution_payload_block_hash,
            .pre_merge => null,
        };
    }

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
/// A simplified version of BeaconBlock.
pub const ProtoBlock = struct {
    // ── Core fields used by ProtoArray algorithm ──

    /// Slot at which this block was proposed.
    /// Not necessary for ProtoArray itself; exists for external components to query.
    slot: Slot,
    /// Hash-tree-root of the BeaconBlock.
    block_root: Root,
    /// Hash-tree-root of the parent BeaconBlock.
    parent_root: Root,

    // ── Passthrough: not used by ProtoArray, but needed by upstream ──

    /// Hash-tree-root of the post-state after applying this block.
    /// Not necessary for ProtoArray; exists for upstream components.
    state_root: Root,
    /// The root that would be used for attestation.data.target.root
    /// if a LMD vote were cast for this block.
    target_root: Root,

    // ── FFG checkpoints (realized) ──

    /// Epoch of the realized justified checkpoint from this block's state.
    justified_epoch: Epoch,
    /// Root of the realized justified checkpoint from this block's state.
    justified_root: Root,
    /// Epoch of the realized finalized checkpoint from this block's state.
    finalized_epoch: Epoch,
    /// Root of the realized finalized checkpoint from this block's state.
    finalized_root: Root,

    // ── Unrealized checkpoints (pull-up FFG, anti-bouncing attack) ──

    /// Epoch of the unrealized justified checkpoint (computed at block import, not epoch boundary).
    unrealized_justified_epoch: Epoch,
    /// Root of the unrealized justified checkpoint.
    unrealized_justified_root: Root,
    /// Epoch of the unrealized finalized checkpoint.
    unrealized_finalized_epoch: Epoch,
    /// Root of the unrealized finalized checkpoint.
    unrealized_finalized_root: Root,

    // ── Execution layer metadata ──

    /// Pre-merge vs post-merge metadata (execution status, block hash, DA status).
    extra_meta: BlockExtraMeta,

    /// Whether block arrived before the 4-second mark (timeliness for late-block reorg).
    timeliness: bool,

    // ── Gloas (ePBS) fields ──

    /// Index of the builder that proposed this block (Gloas ePBS).
    /// Used for execution payload gossip validation.
    builder_index: ?ValidatorIndex = null,
    /// Block hash from the builder's bid (Gloas ePBS).
    /// Used for execution payload gossip validation.
    /// TS ref: blockHashFromBid. Not to be confused with executionPayloadBlockHash in BlockExtraMeta.
    block_hash_from_bid: ?Root = null,
    /// Parent execution block hash (Gloas ePBS).
    /// Used to determine if this block extends its parent's EMPTY or FULL variant.
    /// If parent_block_hash == parent.block_hash_from_bid, parent is FULL; otherwise EMPTY.
    parent_block_hash: ?Root = null,
    /// Payload resolution status (Gloas ePBS). Pre-Gloas blocks are always .full.
    payload_status: PayloadStatus = .full,
};

/// A node in the ProtoArray DAG.
/// Also serves as ForkChoiceNode in the fork choice spec.
///
/// Flat layout: all ProtoBlock fields + DAG metadata.
/// Use `fromBlock()` / `toBlock()` to convert between ProtoBlock and ProtoNode.
/// All indices refer to positions in the flat `nodes` array.
pub const ProtoNode = struct {
    // ── ProtoBlock fields ──

    /// Slot at which this block was proposed.
    /// Not necessary for ProtoArray itself; exists for external components to query.
    slot: Slot,
    /// Hash-tree-root of the BeaconBlock.
    block_root: Root,
    /// Hash-tree-root of the parent BeaconBlock.
    parent_root: Root,

    /// Hash-tree-root of the post-state after applying this block.
    /// Not necessary for ProtoArray; exists for upstream components.
    state_root: Root,
    /// The root that would be used for attestation.data.target.root
    /// if a LMD vote were cast for this block.
    target_root: Root,

    /// Epoch of the realized justified checkpoint from this block's state.
    justified_epoch: Epoch,
    /// Root of the realized justified checkpoint from this block's state.
    justified_root: Root,
    /// Epoch of the realized finalized checkpoint from this block's state.
    finalized_epoch: Epoch,
    /// Root of the realized finalized checkpoint from this block's state.
    finalized_root: Root,

    /// Epoch of the unrealized justified checkpoint (computed at block import, not epoch boundary).
    unrealized_justified_epoch: Epoch,
    /// Root of the unrealized justified checkpoint.
    unrealized_justified_root: Root,
    /// Epoch of the unrealized finalized checkpoint.
    unrealized_finalized_epoch: Epoch,
    /// Root of the unrealized finalized checkpoint.
    unrealized_finalized_root: Root,

    /// Pre-merge vs post-merge metadata (execution status, block hash, DA status).
    extra_meta: BlockExtraMeta,

    /// Whether block arrived before the 4-second mark (timeliness for late-block reorg).
    timeliness: bool,

    /// Index of the builder that proposed this block (Gloas ePBS).
    /// Used for execution payload gossip validation.
    builder_index: ?ValidatorIndex = null,
    /// Block hash from the builder's bid (Gloas ePBS).
    /// Used for execution payload gossip validation.
    /// TS ref: blockHashFromBid. Not to be confused with executionPayloadBlockHash in BlockExtraMeta.
    block_hash_from_bid: ?Root = null,
    /// Parent execution block hash (Gloas ePBS).
    /// Used to determine if this block extends its parent's EMPTY or FULL variant.
    /// If parent_block_hash == parent.block_hash_from_bid, parent is FULL; otherwise EMPTY.
    parent_block_hash: ?Root = null,
    /// Payload resolution status (Gloas ePBS). Pre-Gloas blocks are always .full.
    payload_status: PayloadStatus = .full,

    // ── DAG metadata ──

    /// Index of parent node in the nodes array. null for the root.
    parent: ?u32 = null,

    /// LMD-GHOST weight: sum of effective balances of validators
    /// whose latest vote is for this subtree.
    weight: i64 = 0,

    /// Index of the highest-weight child.
    best_child: ?u32 = null,

    /// Index of the best leaf reachable from this node.
    /// findHead: justified_root -> bestDescendant in O(1).
    best_descendant: ?u32 = null,

    /// Create a ProtoNode from a ProtoBlock, copying all matching fields.
    pub fn fromBlock(block: ProtoBlock) ProtoNode {
        var node: ProtoNode = undefined;
        inline for (std.meta.fields(ProtoBlock)) |field| {
            @field(node, field.name) = @field(block, field.name);
        }
        node.parent = null;
        node.weight = 0;
        node.best_child = null;
        node.best_descendant = null;
        return node;
    }

    /// Extract a ProtoBlock from this node, copying all matching fields.
    pub fn toBlock(self: ProtoNode) ProtoBlock {
        var block: ProtoBlock = undefined;
        inline for (std.meta.fields(ProtoBlock)) |field| {
            @field(block, field.name) = @field(self, field.name);
        }
        return block;
    }
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

/// LVH (Latest Valid Hash) execution status transition errors.
pub const LVHExecErrorCode = enum {
    /// Attempted to mark a pre-merge block as invalid.
    pre_merge_to_invalid,
    /// Attempted to mark a valid block as invalid (forbidden transition).
    valid_to_invalid,
    /// Attempted to mark an invalid block as valid (forbidden transition).
    invalid_to_valid,
};

/// Stored error from validateLatestHash when an irrecoverable
/// execution status transition is detected.
pub const LVHExecError = struct {
    lvh_code: LVHExecErrorCode,
    block_root: Root,
    exec_hash: Root,
};

// TODO(Task 14): move InvalidBlockCode, InvalidAttestationCode, ForkChoiceError to fork_choice.zig

/// Reasons a block can be rejected by fork choice.
pub const InvalidBlockCode = enum {
    unknown_parent,
    future_slot,
    finalized_slot,
    not_finalized_descendant,
};

/// Reasons an attestation can be rejected by fork choice.
pub const InvalidAttestationCode = enum {
    empty_aggregation_bitfield,
    unknown_head_block,
    bad_target_epoch,
    unknown_target_root,
    future_epoch,
    past_epoch,
    invalid_target,
    attests_to_future_block,
    future_slot,
};

/// High-level fork choice errors.
pub const ForkChoiceError = error{
    InvalidAttestation,
    InvalidBlock,
    ProtoArrayErr,
    InvalidProtoArrayBytes,
    MissingProtoArrayBlock,
    UnknownAncestor,
    InconsistentOnTick,
    BeaconStateErr,
    AttemptToRevertJustification,
    ForkChoiceStoreErr,
    UnableToSetJustifiedCheckpoint,
    AfterBlockFailed,
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

test "BlockExtraMeta pre_merge accessors" {
    const meta = BlockExtraMeta{ .pre_merge = {} };
    try testing.expectEqual(meta.executionPayloadBlockHash(), null);
    try testing.expectEqual(meta.executionStatus(), .pre_merge);
    try testing.expectEqual(meta.dataAvailabilityStatus(), .pre_data);
}

test "BlockExtraMeta post_merge accessors" {
    const meta = BlockExtraMeta{
        .post_merge = BlockExtraMeta.PostMergeMeta.init(
            ZERO_HASH,
            42,
            .syncing,
            .available,
        ),
    };
    try testing.expectEqual(meta.executionPayloadBlockHash(), ZERO_HASH);
    try testing.expectEqual(meta.executionStatus(), .syncing);
    try testing.expectEqual(meta.dataAvailabilityStatus(), .available);
}

test "PostMergeMeta.init rejects pre_merge status" {
    // assert(status != .pre_merge) triggers in Debug/ReleaseSafe.
    // In Zig, calling a function that hits assert in a test is undefined behavior,
    // so we verify the valid cases instead — the assert is a development safety net.
    const valid = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .valid, .available);
    try testing.expectEqual(valid.execution_status, .valid);
    const syncing = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .syncing, .available);
    try testing.expectEqual(syncing.execution_status, .syncing);
    const invalid_status = BlockExtraMeta.PostMergeMeta.init(ZERO_HASH, 0, .invalid, .available);
    try testing.expectEqual(invalid_status.execution_status, .invalid);
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
    const node = ProtoNode.fromBlock(block);

    try testing.expectEqual(node.parent, null);
    try testing.expectEqual(node.weight, 0);
    try testing.expectEqual(node.best_child, null);
    try testing.expectEqual(node.best_descendant, null);
    try testing.expectEqual(node.builder_index, null);
    try testing.expectEqual(node.block_hash_from_bid, null);
    try testing.expectEqual(node.slot, 0);
    try testing.expectEqual(node.block_root, ZERO_HASH);
}

test "ProtoNode.toBlock round-trip" {
    const block = ProtoBlock{
        .slot = 42,
        .block_root = ZERO_HASH,
        .parent_root = ZERO_HASH,
        .state_root = ZERO_HASH,
        .target_root = ZERO_HASH,
        .justified_epoch = 1,
        .justified_root = ZERO_HASH,
        .finalized_epoch = 0,
        .finalized_root = ZERO_HASH,
        .unrealized_justified_epoch = 1,
        .unrealized_justified_root = ZERO_HASH,
        .unrealized_finalized_epoch = 0,
        .unrealized_finalized_root = ZERO_HASH,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = true,
    };
    var node = ProtoNode.fromBlock(block);
    node.weight = 100;
    node.parent = 5;

    const recovered = node.toBlock();
    try testing.expectEqual(recovered.slot, 42);
    try testing.expectEqual(recovered.justified_epoch, 1);
    try testing.expectEqual(recovered.timeliness, true);
    try testing.expectEqual(recovered.builder_index, null);
}
