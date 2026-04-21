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

/// Typed inbound gossip admitted into the processor before topic-specific decode.
///
/// The payload bytes may remain raw SSZ, but the queue tag is already topic-specific.
pub const GossipWork = struct {
    source: GossipSource,
    message_id: MessageId,
    peer_id: PeerIdHandle = .none,
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
    rpc_block = 1,
    rpc_blob = 2,
    rpc_custody_column = 3,

    // -- Typed fast-lane gossip ingress --
    gossip_block_ingress = 4,
    gossip_blob_ingress = 5,
    gossip_data_column_ingress = 6,

    // -- Prepared fast-lane gossip --
    delayed_block = 7,
    gossip_block = 8,
    gossip_execution_payload = 9,
    gossip_blob = 10,
    gossip_data_column = 11,
    column_reconstruction = 12,

    // -- API high priority --
    api_request_p0 = 13,

    // -- Recovered unknown-root fast lanes --
    recovered_unknown_block_aggregate = 14,
    recovered_unknown_block_aggregate_batch = 15,
    recovered_unknown_block_attestation = 16,
    recovered_unknown_block_attestation_batch = 17,

    // -- Typed control gossip ingress --
    gossip_aggregate_ingress = 18,
    gossip_sync_contribution_ingress = 19,
    gossip_sync_message_ingress = 20,
    gossip_voluntary_exit_ingress = 21,
    gossip_proposer_slashing_ingress = 22,
    gossip_attester_slashing_ingress = 23,
    gossip_bls_to_exec_ingress = 24,

    // -- Typed overload gossip ingress --
    gossip_attestation_ingress = 25,

    // -- Attestations (batch-formed) --
    aggregate = 26,
    aggregate_batch = 27,
    attestation = 28,
    attestation_batch = 29,

    // -- Gloas: payload attestation --
    gossip_payload_attestation = 30,

    // -- Sync committee --
    sync_contribution = 31,
    sync_message = 32,
    sync_message_batch = 33,

    // -- Gloas --
    gossip_execution_payload_bid = 34,
    gossip_proposer_preferences = 35,

    // -- Peer serving --
    status = 36,
    blocks_by_range = 37,
    blocks_by_root = 38,
    blobs_by_range = 39,
    blobs_by_root = 40,
    columns_by_range = 41,
    columns_by_root = 42,

    // -- Pool objects --
    gossip_attester_slashing = 43,
    gossip_proposer_slashing = 44,
    gossip_voluntary_exit = 45,
    gossip_bls_to_exec = 46,

    // -- Low priority --
    api_request_p1 = 47,
    backfill_segment = 48,

    // -- Light client --
    lc_bootstrap = 49,
    lc_finality_update = 50,
    lc_optimistic_update = 51,
    lc_updates_by_range = 52,

    // -- Internal --
    slot_tick = 53,
    reprocess = 54,

    /// Total number of work types. Useful for sizing per-type metric arrays.
    pub const count: u32 = 55;

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
            .gossip_attestation_ingress,
            .gossip_aggregate_ingress,
            .gossip_sync_contribution_ingress,
            .gossip_sync_message_ingress,
            => true,
            else => false,
        };
    }

    pub fn gossipIngressTopicType(self: WorkType) ?GossipTopicType {
        return switch (self) {
            .gossip_block_ingress => .beacon_block,
            .gossip_blob_ingress => .blob_sidecar,
            .gossip_data_column_ingress => .data_column_sidecar,
            .gossip_attestation_ingress => .beacon_attestation,
            .gossip_aggregate_ingress => .beacon_aggregate_and_proof,
            .gossip_sync_contribution_ingress => .sync_committee_contribution_and_proof,
            .gossip_sync_message_ingress => .sync_committee,
            .gossip_voluntary_exit_ingress => .voluntary_exit,
            .gossip_proposer_slashing_ingress => .proposer_slashing,
            .gossip_attester_slashing_ingress => .attester_slashing,
            .gossip_bls_to_exec_ingress => .bls_to_execution_change,
            else => null,
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

    // -- Typed gossip ingress --
    gossip_block_ingress: GossipWork,
    gossip_blob_ingress: GossipWork,
    gossip_data_column_ingress: GossipWork,

    // -- Gossip: blocks + DA --
    delayed_block: DelayedBlockWork,
    gossip_block: GossipBlockWork,
    gossip_execution_payload: GossipPayloadWork,
    gossip_blob: GossipBlobWork,
    gossip_data_column: GossipColumnWork,
    column_reconstruction: ColumnReconstructionWork,

    // -- API high priority --
    api_request_p0: ApiWork,

    // -- Recovered unknown-root fast lanes --
    recovered_unknown_block_aggregate: AggregateWork,
    recovered_unknown_block_aggregate_batch: AggregateBatchWork,
    recovered_unknown_block_attestation: AttestationWork,
    recovered_unknown_block_attestation_batch: AttestationBatchWork,

    // -- Typed control gossip ingress --
    gossip_aggregate_ingress: GossipWork,
    gossip_sync_contribution_ingress: GossipWork,
    gossip_sync_message_ingress: GossipWork,
    gossip_voluntary_exit_ingress: GossipWork,
    gossip_proposer_slashing_ingress: GossipWork,
    gossip_attester_slashing_ingress: GossipWork,
    gossip_bls_to_exec_ingress: GossipWork,

    // -- Typed overload gossip ingress --
    gossip_attestation_ingress: GossipWork,

    // -- Attestations --
    aggregate: AggregateWork,
    aggregate_batch: AggregateBatchWork,
    attestation: AttestationWork,
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
            .gossip_block_ingress,
            .gossip_blob_ingress,
            .gossip_data_column_ingress,
            .gossip_aggregate_ingress,
            .gossip_sync_contribution_ingress,
            .gossip_sync_message_ingress,
            .gossip_voluntary_exit_ingress,
            .gossip_proposer_slashing_ingress,
            .gossip_attester_slashing_ingress,
            .gossip_bls_to_exec_ingress,
            .gossip_attestation_ingress,
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
            .attestation,
            .recovered_unknown_block_attestation,
            => |work| {
                var attestation = work.attestation;
                attestation.deinit(allocator);
            },
            .aggregate,
            .recovered_unknown_block_aggregate,
            => |work| {
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
    const recovered = @intFromEnum(WorkType.recovered_unknown_block_attestation);
    const attest = @intFromEnum(WorkType.attestation);
    const backfill = @intFromEnum(WorkType.backfill_segment);

    try std.testing.expect(chain < gossip);
    try std.testing.expect(gossip < recovered);
    try std.testing.expect(recovered < attest);
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
