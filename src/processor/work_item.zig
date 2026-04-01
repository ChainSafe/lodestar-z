//! Work item types for the BeaconProcessor.
//!
//! Every unit of work that enters the beacon processor is represented as a
//! `WorkItem` tagged union. The `WorkType` enum doubles as the tag and
//! encodes strict priority order — lower ordinal = higher priority.

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");

// Re-export primitive types used in payloads.
const Slot = consensus_types.primitive.Slot.Type;
const Root = consensus_types.primitive.Root.Type;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

/// Maximum number of attestations in a single batch for BLS batch verification.
pub const max_attestation_batch_size: u32 = 64;

/// Maximum number of aggregates in a single batch for BLS batch verification.
pub const max_aggregate_batch_size: u32 = 64;

// ---------------------------------------------------------------------------
// Placeholder types for entities not yet defined elsewhere.
// ---------------------------------------------------------------------------

/// Opaque peer identifier. TODO: Replace with real PeerId from networking.
pub const PeerId = u64;

/// Ethereum gossipsub message identifier: first 20 bytes of the spec hash.
pub const MessageId = [20]u8;

/// Phase within a slot, used by the clock fiber.
pub const SlotPhase = enum(u8) {
    /// t=0 — slot starts.
    start,
    /// t=4s — attestation deadline (1/3 of slot).
    attestation_deadline,
    /// t=8s — aggregate deadline (2/3 of slot).
    aggregate_deadline,
};

/// Opaque handle for execution payload envelope. TODO: Replace with real type.
pub const ExecutionPayloadHandle = *anyopaque;

/// Type-erased handle for queued gossip payload data.
///
/// The gossip layer can attach an owned payload wrapper with a concrete
/// `deinit()` method, and the processor can later destroy it without knowing
/// the concrete type.
pub const GossipDataHandle = struct {
    ptr: *anyopaque,
    deinitFn: *const fn (ptr: *anyopaque) void,

    pub fn initOwned(comptime T: type, ptr: *T) GossipDataHandle {
        return .{
            .ptr = @ptrCast(ptr),
            .deinitFn = struct {
                fn call(raw: *anyopaque) void {
                    const typed: *T = @ptrCast(@alignCast(raw));
                    typed.deinit();
                }
            }.call,
        };
    }

    pub fn initBorrowed(ptr: *anyopaque) GossipDataHandle {
        return .{
            .ptr = ptr,
            .deinitFn = struct {
                fn call(_: *anyopaque) void {}
            }.call,
        };
    }

    pub fn cast(self: GossipDataHandle, comptime T: type) *T {
        return @ptrCast(@alignCast(self.ptr));
    }

    pub fn deinit(self: GossipDataHandle) void {
        self.deinitFn(self.ptr);
    }
};

// ---------------------------------------------------------------------------
// Work payload structs — one per logical work type.
// ---------------------------------------------------------------------------

/// Gossip-received signed beacon block.
pub const GossipBlockWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    block: AnySignedBeaconBlock,
    seen_timestamp_ns: i64,
};

/// Gossip-received blob sidecar.
pub const GossipBlobWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Gossip-received data column sidecar.
pub const GossipColumnWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Gossip-received execution payload (Gloas).
pub const GossipPayloadWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    payload: ExecutionPayloadHandle,
    seen_timestamp_ns: i64,
};

/// A gossip block that arrived early and was delayed until its slot.
pub const DelayedBlockWork = struct {
    block: AnySignedBeaconBlock,
    seen_timestamp_ns: i64,
};

/// Column reconstruction from partial data columns.
pub const ColumnReconstructionWork = struct {
    block_root: Root,
    slot: u64,
};

/// Unaggregated attestation from gossip.
pub const AttestationWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    subnet_id: u8,
    seen_timestamp_ns: i64,
};

/// Batch of unaggregated attestations for BLS batch verification.
pub const AttestationBatchWork = struct {
    items: [*]AttestationWork,
    count: u32,
};

/// Aggregated attestation from gossip.
pub const AggregateWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Batch of aggregated attestations for BLS batch verification.
pub const AggregateBatchWork = struct {
    items: [*]AggregateWork,
    count: u32,
};

/// Attestation or aggregate awaiting an unknown block.
pub const ReprocessWork = struct {
    block_root: Root,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Sync committee message from gossip.
pub const SyncMessageWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    slot: u64,
    subnet_id: u8,
    seen_timestamp_ns: i64,
};

/// Sync committee contribution from gossip.
pub const SyncContributionWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    slot: u64,
    seen_timestamp_ns: i64,
};

/// Pool object from gossip: voluntary exit, proposer slashing,
/// attester slashing, or BLS-to-execution change.
pub const PoolObjectWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Gloas-era work items: payload attestation, execution payload bid,
/// proposer preferences.
pub const GloasWork = struct {
    peer_id: PeerId,
    message_id: MessageId,
    slot: u64,
    seen_timestamp_ns: i64,
};

/// Block received via RPC (range sync or root request).
pub const RpcBlockWork = struct {
    block: AnySignedBeaconBlock,
    block_root: Root,
    seen_timestamp_ns: i64,
};

/// Blob received via RPC.
pub const RpcBlobWork = struct {
    blob: *anyopaque,
    block_root: Root,
    seen_timestamp_ns: i64,
};

/// Data column received via RPC.
pub const RpcColumnWork = struct {
    column: *anyopaque,
    block_root: Root,
    seen_timestamp_ns: i64,
};

/// Range sync chain segment (batch of blocks).
pub const ChainSegmentWork = struct {
    blocks: [*]AnySignedBeaconBlock,
    block_count: u32,
    seen_timestamp_ns: i64,
};

/// Backfill historical chain segment.
pub const BackfillWork = struct {
    blocks: [*]AnySignedBeaconBlock,
    block_count: u32,
    seen_timestamp_ns: i64,
};

/// Inbound req/resp request to serve to a peer.
pub const ReqRespWork = struct {
    peer_id: PeerId,
    /// Opaque request context for sending the response.
    /// TODO: Replace with real ReqRespContext pointer.
    request_context: u64,
    seen_timestamp_ns: i64,
};

/// API request routed through the processor for prioritisation.
pub const ApiWork = struct {
    /// Opaque handle to the pending HTTP response.
    /// TODO: Replace with real ApiResponseHandle.
    response_handle: u64,
    seen_timestamp_ns: i64,
};

/// Slot-phase tick from the clock fiber.
pub const SlotTickWork = struct {
    slot: u64,
    phase: SlotPhase,
};

/// Message to trigger reprocessing of deferred items.
pub const ReprocessMessage = struct {
    block_root: Root,
    slot: u64,
};

/// Light client serving work.
pub const LightClientWork = struct {
    peer_id: PeerId,
    request_context: u64,
    seen_timestamp_ns: i64,
};

// ---------------------------------------------------------------------------
// WorkType — priority-ordered enum. Lower ordinal = higher priority.
// ---------------------------------------------------------------------------

/// Work type tag. Ordinal encodes strict priority: 0 is highest.
pub const WorkType = enum(u8) {
    // -- Sync (highest priority) --
    chain_segment = 0,
    rpc_block = 1,
    rpc_blob = 2,
    rpc_custody_column = 3,

    // -- Gossip: blocks + DA --
    delayed_block = 4,
    gossip_block = 5,
    gossip_execution_payload = 6,
    gossip_blob = 7,
    gossip_data_column = 8,
    column_reconstruction = 9,

    // -- API high priority --
    api_request_p0 = 10,

    // -- Attestations (batch-formed) --
    aggregate = 11,
    attestation = 12,
    aggregate_batch = 13,
    attestation_batch = 14,

    // -- Gloas: payload attestation --
    gossip_payload_attestation = 15,

    // -- Sync committee --
    sync_contribution = 16,
    sync_message = 17,

    // -- Reprocessing --
    unknown_block_aggregate = 18,
    unknown_block_attestation = 19,

    // -- Gloas --
    gossip_execution_payload_bid = 20,
    gossip_proposer_preferences = 21,

    // -- Peer serving --
    status = 22,
    blocks_by_range = 23,
    blocks_by_root = 24,
    blobs_by_range = 25,
    blobs_by_root = 26,
    columns_by_range = 27,
    columns_by_root = 28,

    // -- Pool objects --
    gossip_attester_slashing = 29,
    gossip_proposer_slashing = 30,
    gossip_voluntary_exit = 31,
    gossip_bls_to_exec = 32,

    // -- Low priority --
    api_request_p1 = 33,
    backfill_segment = 34,

    // -- Light client --
    lc_bootstrap = 35,
    lc_finality_update = 36,
    lc_optimistic_update = 37,
    lc_updates_by_range = 38,

    // -- Internal --
    slot_tick = 39,
    reprocess = 40,

    /// Total number of work types. Useful for sizing per-type metric arrays.
    pub const count: u32 = 41;

    /// Returns true if this work type should be dropped during initial sync.
    pub fn dropDuringSync(self: WorkType) bool {
        return switch (self) {
            .attestation,
            .aggregate,
            .attestation_batch,
            .aggregate_batch,
            .unknown_block_attestation,
            .unknown_block_aggregate,
            .sync_message,
            .sync_contribution,
            .gossip_payload_attestation,
            .lc_bootstrap,
            .lc_finality_update,
            .lc_optimistic_update,
            .lc_updates_by_range,
            => true,
            else => false,
        };
    }
};

// ---------------------------------------------------------------------------
// WorkItem — the tagged union.
// ---------------------------------------------------------------------------

/// Every unit of work entering the BeaconProcessor.
pub const WorkItem = union(WorkType) {
    // -- Sync --
    chain_segment: ChainSegmentWork,
    rpc_block: RpcBlockWork,
    rpc_blob: RpcBlobWork,
    rpc_custody_column: RpcColumnWork,

    // -- Gossip: blocks + DA --
    delayed_block: DelayedBlockWork,
    gossip_block: GossipBlockWork,
    gossip_execution_payload: GossipPayloadWork,
    gossip_blob: GossipBlobWork,
    gossip_data_column: GossipColumnWork,
    column_reconstruction: ColumnReconstructionWork,

    // -- API high priority --
    api_request_p0: ApiWork,

    // -- Attestations --
    aggregate: AggregateWork,
    attestation: AttestationWork,
    aggregate_batch: AggregateBatchWork,
    attestation_batch: AttestationBatchWork,

    // -- Gloas --
    gossip_payload_attestation: GloasWork,

    // -- Sync committee --
    sync_contribution: SyncContributionWork,
    sync_message: SyncMessageWork,

    // -- Reprocessing --
    unknown_block_aggregate: ReprocessWork,
    unknown_block_attestation: ReprocessWork,

    // -- Gloas --
    gossip_execution_payload_bid: GloasWork,
    gossip_proposer_preferences: GloasWork,

    // -- Peer serving --
    status: ReqRespWork,
    blocks_by_range: ReqRespWork,
    blocks_by_root: ReqRespWork,
    blobs_by_range: ReqRespWork,
    blobs_by_root: ReqRespWork,
    columns_by_range: ReqRespWork,
    columns_by_root: ReqRespWork,

    // -- Pool objects --
    gossip_attester_slashing: PoolObjectWork,
    gossip_proposer_slashing: PoolObjectWork,
    gossip_voluntary_exit: PoolObjectWork,
    gossip_bls_to_exec: PoolObjectWork,

    // -- Low priority --
    api_request_p1: ApiWork,
    backfill_segment: BackfillWork,

    // -- Light client --
    lc_bootstrap: LightClientWork,
    lc_finality_update: LightClientWork,
    lc_optimistic_update: LightClientWork,
    lc_updates_by_range: LightClientWork,

    // -- Internal --
    slot_tick: SlotTickWork,
    reprocess: ReprocessMessage,

    /// Returns the work type tag.
    pub fn workType(self: WorkItem) WorkType {
        return std.meta.activeTag(self);
    }

    /// Returns true if this item should be dropped during initial sync.
    pub fn dropDuringSync(self: WorkItem) bool {
        return self.workType().dropDuringSync();
    }

    pub fn deinit(self: WorkItem, allocator: std.mem.Allocator) void {
        switch (self) {
            .delayed_block => |work| work.block.deinit(allocator),
            .gossip_block => |work| work.block.deinit(allocator),
            .gossip_blob => |work| work.data.deinit(),
            .gossip_data_column => |work| work.data.deinit(),
            .rpc_block => |work| work.block.deinit(allocator),
            .attestation => |work| work.data.deinit(),
            .aggregate => |work| work.data.deinit(),
            .unknown_block_aggregate => |work| work.data.deinit(),
            .unknown_block_attestation => |work| work.data.deinit(),
            .sync_contribution => |work| work.data.deinit(),
            .sync_message => |work| work.data.deinit(),
            .gossip_attester_slashing => |work| work.data.deinit(),
            .gossip_proposer_slashing => |work| work.data.deinit(),
            .gossip_voluntary_exit => |work| work.data.deinit(),
            .gossip_bls_to_exec => |work| work.data.deinit(),
            else => {},
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "WorkType: priority ordering" {
    const chain = @intFromEnum(WorkType.chain_segment);
    const gossip = @intFromEnum(WorkType.gossip_block);
    const attest = @intFromEnum(WorkType.attestation);
    const backfill = @intFromEnum(WorkType.backfill_segment);

    try std.testing.expect(chain < gossip);
    try std.testing.expect(gossip < attest);
    try std.testing.expect(attest < backfill);
}

test "WorkType: drop_during_sync flags" {
    try std.testing.expect(WorkType.attestation.dropDuringSync());
    try std.testing.expect(WorkType.sync_message.dropDuringSync());
    try std.testing.expect(!WorkType.gossip_block.dropDuringSync());
    try std.testing.expect(!WorkType.rpc_block.dropDuringSync());
    try std.testing.expect(!WorkType.gossip_attester_slashing.dropDuringSync());
}

test "WorkItem: tag extraction" {
    const item = WorkItem{ .slot_tick = .{ .slot = 42, .phase = .start } };
    try std.testing.expectEqual(WorkType.slot_tick, item.workType());
    try std.testing.expect(!item.dropDuringSync());
}
