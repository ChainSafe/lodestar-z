//! Work item types for the BeaconProcessor.
//!
//! Every unit of work that enters the beacon processor is represented as a
//! `WorkItem` tagged union. The `WorkType` enum doubles as the tag and
//! encodes strict priority order — lower ordinal = higher priority.

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const config_mod = @import("config");

// Re-export primitive types used in payloads.
const Slot = consensus_types.primitive.Slot.Type;
const Root = consensus_types.primitive.Root.Type;
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const SignedVoluntaryExit = consensus_types.phase0.SignedVoluntaryExit.Type;
const ProposerSlashing = consensus_types.phase0.ProposerSlashing.Type;
const SignedBLSToExecutionChange = consensus_types.capella.SignedBLSToExecutionChange.Type;
const SyncCommitteeMessage = consensus_types.altair.SyncCommitteeMessage.Type;
const SignedContributionAndProof = consensus_types.altair.SignedContributionAndProof.Type;
const ForkSeq = config_mod.ForkSeq;

pub const GossipTopicType = enum {
    beacon_block,
    beacon_aggregate_and_proof,
    beacon_attestation,
    voluntary_exit,
    proposer_slashing,
    attester_slashing,
    bls_to_execution_change,
    blob_sidecar,
    sync_committee_contribution_and_proof,
    sync_committee,
    data_column_sidecar,

    pub fn topicName(self: GossipTopicType) []const u8 {
        return switch (self) {
            .beacon_block => "beacon_block",
            .beacon_aggregate_and_proof => "beacon_aggregate_and_proof",
            .beacon_attestation => "beacon_attestation",
            .voluntary_exit => "voluntary_exit",
            .proposer_slashing => "proposer_slashing",
            .attester_slashing => "attester_slashing",
            .bls_to_execution_change => "bls_to_execution_change",
            .blob_sidecar => "blob_sidecar",
            .sync_committee_contribution_and_proof => "sync_committee_contribution_and_proof",
            .sync_committee => "sync_committee",
            .data_column_sidecar => "data_column_sidecar",
        };
    }
};

/// Maximum number of attestations in a single batch for BLS batch verification.
pub const max_attestation_batch_size: u32 = 64;

/// Maximum number of aggregates in a single batch for BLS batch verification.
pub const max_aggregate_batch_size: u32 = 64;

/// Maximum number of sync committee messages in a single batch for BLS batch verification.
pub const max_sync_message_batch_size: u32 = 64;

// ---------------------------------------------------------------------------
// Concrete queue-boundary types.
// ---------------------------------------------------------------------------

/// Ethereum gossipsub message identifier: first 20 bytes of the spec hash.
pub const MessageId = [20]u8;

/// Stable provenance key for queued gossip work.
///
/// The processor currently needs a lightweight source identifier for logging,
/// metrics, and future peer-scoring/reporting hooks. It does not require the
/// full libp2p peer ID bytes on the hot gossip path.
pub const GossipSource = struct {
    key: u64 = 0,

    pub fn fromOpaqueBytes(seed: u64, maybe_bytes: ?[]const u8) GossipSource {
        const bytes = maybe_bytes orelse return .{};
        return .{ .key = std.hash.Wyhash.hash(seed, bytes) };
    }

    pub fn isKnown(self: GossipSource) bool {
        return self.key != 0;
    }
};

/// Concrete peer identity for queued req/resp and service work.
pub const PeerIdHandle = union(enum) {
    none,
    borrowed: []const u8,
    owned: struct {
        bytes: []u8,
        allocator: std.mem.Allocator,
    },

    pub fn initBorrowed(peer_id: []const u8) PeerIdHandle {
        return .{ .borrowed = peer_id };
    }

    pub fn initOwned(allocator: std.mem.Allocator, peer_id: []const u8) !PeerIdHandle {
        return .{
            .owned = .{
                .bytes = try allocator.dupe(u8, peer_id),
                .allocator = allocator,
            },
        };
    }

    pub fn bytes(self: PeerIdHandle) ?[]const u8 {
        return switch (self) {
            .none => null,
            .borrowed => |peer_id| peer_id,
            .owned => |owned| owned.bytes,
        };
    }

    pub fn deinit(self: PeerIdHandle) void {
        switch (self) {
            .owned => |owned| owned.allocator.free(owned.bytes),
            else => {},
        }
    }
};

/// Phase within a slot, used by the clock fiber.
pub const SlotPhase = enum(u8) {
    /// t=0 — slot starts.
    start,
    /// t=4s — attestation deadline (1/3 of slot).
    attestation_deadline,
    /// t=8s — aggregate deadline (2/3 of slot).
    aggregate_deadline,
};

/// Type-erased handle for queued payload and request context data.
///
/// The producer can attach an owned wrapper with a concrete `deinit()` method,
/// and the processor can later destroy it without knowing the concrete type.
pub const OpaqueHandle = struct {
    ptr: *anyopaque,
    deinitFn: *const fn (ptr: *anyopaque) void,

    pub fn initOwned(comptime T: type, ptr: *T) OpaqueHandle {
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

    pub fn initBorrowed(ptr: *anyopaque) OpaqueHandle {
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

pub const GossipDataHandle = OpaqueHandle;
pub const ExecutionPayloadHandle = OpaqueHandle;
pub const RpcBlobHandle = OpaqueHandle;
pub const RpcColumnHandle = OpaqueHandle;
pub const ReqRespRequestHandle = OpaqueHandle;
pub const ApiResponseHandle = OpaqueHandle;
pub const LightClientRequestHandle = OpaqueHandle;

pub const OwnedSszBytes = struct {
    ssz_bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn dupe(allocator: std.mem.Allocator, ssz_bytes: []const u8) !OwnedSszBytes {
        return .{
            .ssz_bytes = try allocator.dupe(u8, ssz_bytes),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *OwnedSszBytes) void {
        self.allocator.free(self.ssz_bytes);
    }
};

/// Raw inbound gossip admitted into the processor before topic-specific decode.
pub const RawGossipWork = struct {
    source: GossipSource,
    message_id: MessageId,
    peer_id: PeerIdHandle = .none,
    topic_type: GossipTopicType,
    subnet_id: ?u8 = null,
    fork_digest: [4]u8,
    fork_seq: ForkSeq,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

// ---------------------------------------------------------------------------
// Work payload structs — one per logical work type.
// ---------------------------------------------------------------------------

/// Gossip-received signed beacon block.
pub const GossipBlockWork = struct {
    source: GossipSource,
    message_id: MessageId,
    block: AnySignedBeaconBlock,
    peer_id: PeerIdHandle = .none,
    seen_timestamp_ns: i64,
};

/// Gossip-received blob sidecar.
pub const GossipBlobWork = struct {
    source: GossipSource,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Gossip-received data column sidecar.
pub const GossipColumnWork = struct {
    source: GossipSource,
    message_id: MessageId,
    data: GossipDataHandle,
    seen_timestamp_ns: i64,
};

/// Gossip-received execution payload (Gloas).
pub const GossipPayloadWork = struct {
    source: GossipSource,
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
pub const ResolvedAttestation = struct {
    validator_index: ValidatorIndex,
    validator_committee_index: u32,
    committee_size: u32,
    signing_root: Root,
    expected_subnet: u8,
    already_seen: bool = false,
};

/// Aggregated attestation from gossip, resolved once at ingress.
pub const ResolvedAggregate = struct {
    attestation_signing_root: Root,
    selection_signing_root: Root,
    aggregate_signing_root: Root,
    attesting_indices: []const ValidatorIndex,
    owned_attesting_indices: ?[]ValidatorIndex = null,

    pub fn initOwned(
        attesting_indices: []ValidatorIndex,
        attestation_signing_root: Root,
        selection_signing_root: Root,
        aggregate_signing_root: Root,
    ) ResolvedAggregate {
        return .{
            .attestation_signing_root = attestation_signing_root,
            .selection_signing_root = selection_signing_root,
            .aggregate_signing_root = aggregate_signing_root,
            .attesting_indices = attesting_indices,
            .owned_attesting_indices = attesting_indices,
        };
    }

    pub fn deinit(self: ResolvedAggregate, allocator: std.mem.Allocator) void {
        if (self.owned_attesting_indices) |attesting_indices| {
            allocator.free(attesting_indices);
        }
    }
};

/// Unaggregated attestation from gossip.
pub const AttestationWork = struct {
    source: GossipSource,
    message_id: MessageId,
    attestation: AnyGossipAttestation,
    attestation_data_root: Root,
    resolved: ResolvedAttestation,
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
    source: GossipSource,
    message_id: MessageId,
    aggregate: AnySignedAggregateAndProof,
    attestation_data_root: Root,
    resolved: ResolvedAggregate,
    seen_timestamp_ns: i64,
};

/// Batch of aggregated attestations for BLS batch verification.
pub const AggregateBatchWork = struct {
    items: [*]AggregateWork,
    count: u32,
};

/// Batch of sync committee messages for BLS batch verification.
pub const SyncMessageBatchWork = struct {
    items: [*]SyncMessageWork,
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
    source: GossipSource,
    message_id: MessageId,
    message: SyncCommitteeMessage,
    subnet_id: u8,
    seen_timestamp_ns: i64,
};

/// Sync committee contribution from gossip.
pub const SyncContributionWork = struct {
    source: GossipSource,
    message_id: MessageId,
    signed_contribution: SignedContributionAndProof,
    seen_timestamp_ns: i64,
};

pub const VoluntaryExitWork = struct {
    source: GossipSource,
    message_id: MessageId,
    exit: SignedVoluntaryExit,
    seen_timestamp_ns: i64,
};

pub const ProposerSlashingWork = struct {
    source: GossipSource,
    message_id: MessageId,
    slashing: ProposerSlashing,
    seen_timestamp_ns: i64,
};

pub const AttesterSlashingWork = struct {
    source: GossipSource,
    message_id: MessageId,
    slashing: AnyAttesterSlashing,
    seen_timestamp_ns: i64,
};

pub const BlsToExecutionChangeWork = struct {
    source: GossipSource,
    message_id: MessageId,
    change: SignedBLSToExecutionChange,
    seen_timestamp_ns: i64,
};

/// Gloas-era work items: payload attestation, execution payload bid,
/// proposer preferences.
pub const GloasWork = struct {
    source: GossipSource,
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
    blob: RpcBlobHandle,
    block_root: Root,
    seen_timestamp_ns: i64,
};

/// Data column received via RPC.
pub const RpcColumnWork = struct {
    column: RpcColumnHandle,
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
    peer_id: PeerIdHandle,
    request: ReqRespRequestHandle,
    seen_timestamp_ns: i64,
};

/// API request routed through the processor for prioritisation.
pub const ApiWork = struct {
    response: ApiResponseHandle,
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
    peer_id: PeerIdHandle,
    request: LightClientRequestHandle,
    seen_timestamp_ns: i64,
};

// ---------------------------------------------------------------------------
// WorkType — priority-ordered enum. Lower ordinal = higher priority.
// ---------------------------------------------------------------------------

/// Work type tag. Ordinal encodes strict priority: 0 is highest.
pub const WorkType = enum(u8) {
    // -- Sync (highest priority) --
    chain_segment = 0,
    rpc_block = 2,
    rpc_blob = 3,
    rpc_custody_column = 4,

    // -- Raw gossip admission --
    raw_gossip_fast = 5,
    raw_gossip_attestation = 6,
    raw_gossip_aggregate = 7,
    raw_gossip_sync_contribution = 8,
    raw_gossip_sync_message = 9,
    raw_gossip_pool_object = 10,

    // -- Gossip: blocks + DA --
    delayed_block = 11,
    gossip_block = 12,
    gossip_execution_payload = 13,
    gossip_blob = 14,
    gossip_data_column = 15,
    column_reconstruction = 16,

    // -- API high priority --
    api_request_p0 = 17,

    // -- Attestations (batch-formed) --
    aggregate = 18,
    attestation = 19,
    aggregate_batch = 20,
    attestation_batch = 21,

    // -- Gloas: payload attestation --
    gossip_payload_attestation = 22,

    // -- Sync committee --
    sync_contribution = 23,
    sync_message = 24,
    sync_message_batch = 25,

    // -- Gloas --
    gossip_execution_payload_bid = 26,
    gossip_proposer_preferences = 27,

    // -- Peer serving --
    status = 28,
    blocks_by_range = 29,
    blocks_by_root = 30,
    blobs_by_range = 31,
    blobs_by_root = 32,
    columns_by_range = 33,
    columns_by_root = 34,

    // -- Pool objects --
    gossip_attester_slashing = 35,
    gossip_proposer_slashing = 36,
    gossip_voluntary_exit = 37,
    gossip_bls_to_exec = 38,

    // -- Low priority --
    api_request_p1 = 39,
    backfill_segment = 40,

    // -- Light client --
    lc_bootstrap = 41,
    lc_finality_update = 42,
    lc_optimistic_update = 43,
    lc_updates_by_range = 44,

    // -- Internal --
    slot_tick = 45,
    reprocess = 46,

    /// Total number of work types. Useful for sizing per-type metric arrays.
    pub const count: u32 = 47;

    /// Returns true if this work type should be dropped during initial sync.
    pub fn dropDuringSync(self: WorkType) bool {
        return switch (self) {
            .attestation,
            .aggregate,
            .attestation_batch,
            .aggregate_batch,
            .sync_message,
            .sync_message_batch,
            .sync_contribution,
            .gossip_payload_attestation,
            .lc_bootstrap,
            .lc_finality_update,
            .lc_optimistic_update,
            .lc_updates_by_range,
            .raw_gossip_attestation,
            .raw_gossip_aggregate,
            .raw_gossip_sync_contribution,
            .raw_gossip_sync_message,
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

    // -- Raw gossip admission --
    raw_gossip_fast: RawGossipWork,
    raw_gossip_attestation: RawGossipWork,
    raw_gossip_aggregate: RawGossipWork,
    raw_gossip_sync_contribution: RawGossipWork,
    raw_gossip_sync_message: RawGossipWork,
    raw_gossip_pool_object: RawGossipWork,

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
    sync_message_batch: SyncMessageBatchWork,

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
    gossip_attester_slashing: AttesterSlashingWork,
    gossip_proposer_slashing: ProposerSlashingWork,
    gossip_voluntary_exit: VoluntaryExitWork,
    gossip_bls_to_exec: BlsToExecutionChangeWork,

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
            .raw_gossip_fast,
            .raw_gossip_attestation,
            .raw_gossip_aggregate,
            .raw_gossip_sync_contribution,
            .raw_gossip_sync_message,
            .raw_gossip_pool_object,
            => |work| {
                work.peer_id.deinit();
                work.data.deinit();
            },
            .delayed_block => |work| work.block.deinit(allocator),
            .gossip_block => |work| {
                work.block.deinit(allocator);
                work.peer_id.deinit();
            },
            .gossip_execution_payload => |work| work.payload.deinit(),
            .gossip_blob => |work| work.data.deinit(),
            .gossip_data_column => |work| work.data.deinit(),
            .rpc_block => |work| work.block.deinit(allocator),
            .rpc_blob => |work| work.blob.deinit(),
            .rpc_custody_column => |work| work.column.deinit(),
            .attestation => |work| {
                var attestation = work.attestation;
                attestation.deinit(allocator);
            },
            .aggregate => |work| {
                work.resolved.deinit(allocator);
                var aggregate = work.aggregate;
                aggregate.deinit(allocator);
            },
            .sync_contribution => {},
            .sync_message => {},
            .sync_message_batch => {},
            .gossip_attester_slashing => |work| {
                var slashing = work.slashing;
                slashing.deinit(allocator);
            },
            .gossip_proposer_slashing => {},
            .gossip_bls_to_exec => {},
            .status => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .blocks_by_range => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .blocks_by_root => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .blobs_by_range => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .blobs_by_root => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .columns_by_range => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .columns_by_root => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .api_request_p0 => |work| work.response.deinit(),
            .api_request_p1 => |work| work.response.deinit(),
            .lc_bootstrap => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .lc_finality_update => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .lc_optimistic_update => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
            .lc_updates_by_range => |work| {
                work.peer_id.deinit();
                work.request.deinit();
            },
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
