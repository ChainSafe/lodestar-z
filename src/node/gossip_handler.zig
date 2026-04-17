//! GossipHandler: two-phase gossip message processing.
//!
//! When a gossip message arrives via GossipSub, this module:
//! 1. Snappy-decompresses + SSZ-decodes the payload
//! 2. Runs fast Phase 1 validation (slot bounds, dedup, proposer checks — < 1 ms)
//!    → returns ACCEPT / REJECT / IGNORE to gossipsub
//! 3. On ACCEPT, queues a Phase 2 work item for full processing
//!    (STFN, signature verification, DA checks, fork choice update)
//!
//! The handler is type-erased to avoid circular dependencies between the `node`
//! and `networking` packages — the node pointer and import function are passed
//! as `*anyopaque` + function pointer.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#topics-and-messages

const std = @import("std");
const scoped_log = std.log.scoped(.gossip_handler);
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");

const networking = @import("networking");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const preset = @import("preset").preset;
const preset_root = @import("preset");
const fork_types = @import("fork_types");
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const GossipTopicType = networking.GossipTopicType;
const gossip_decoding = networking.gossip_decoding;

const chain = @import("chain");
const SeenCache = chain.SeenCache;
const PreparedBlockInput = chain.PreparedBlockInput;
const chain_gossip = chain.gossip_validation;

const BeaconMetrics = @import("metrics.zig").BeaconMetrics;

const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const WorkItem = processor_mod.WorkItem;
const GossipSource = processor_mod.work_item.GossipSource;
const MessageId = processor_mod.work_item.MessageId;
const GossipDataHandle = processor_mod.work_item.GossipDataHandle;
const OwnedSszBytes = processor_mod.work_item.OwnedSszBytes;
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
const GossipAction = chain_gossip.GossipAction;
const AttestationGossipAction = chain_gossip.AttestationGossipAction;
const ChainState = chain_gossip.ChainState;
const GossipRejectReason = networking.peer_scoring.GossipRejectReason;
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const ProposerSlashing = types.phase0.ProposerSlashing.Type;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;
const SignedContributionAndProof = types.altair.SignedContributionAndProof.Type;
const SyncCommitteeMessage = types.altair.SyncCommitteeMessage.Type;
const slow_gossip_phase1_log_ns: u64 = 100 * std.time.ns_per_ms;

/// Error set for gossip processing failures.
pub const GossipHandlerError = error{
    /// Gossip validation returned Ignore — message silently dropped.
    ValidationIgnored,
    /// Gossip validation was accepted into an asynchronous validator path.
    ValidationDeferred,
    /// Gossip validation returned Reject — peer should be penalized.
    ValidationRejected,
    /// Gossip message was validly parsed but routed to the wrong subnet.
    WrongSubnet,
    /// Gossip message failed BLS verification.
    InvalidSignature,
    /// Decode failed (bad snappy or SSZ).
    DecodeFailed,
};

pub const GossipProcessResult = union(enum) {
    accepted,
    deferred,
    ignored,
    rejected: GossipRejectReason,
    failed: anyerror,
};

/// Handles incoming gossip messages with two-phase validation.
///
/// **Phase 1** (fast, < 1 ms): decode + lightweight checks → ACCEPT/REJECT/IGNORE.
/// **Phase 2** (slow, queued): full STFN, signature verification, fork choice.
///
/// Lifecycle:
/// 1. `create` — allocate and wire callbacks
/// 2. `onGossipMessage` (or topic-specific methods)
/// 3. `deinit` — release SeenCache and struct
/// Heap-allocated copy of a decoded gossip payload's SSZ bytes.
/// Used when the processor needs to import an object from raw SSZ later.
pub const QueuedSszBytes = struct {
    ssz_bytes: []u8,
    allocator: std.mem.Allocator,
    fork_seq: ForkSeq,

    pub fn deinit(self: *QueuedSszBytes) void {
        self.allocator.free(self.ssz_bytes);
        self.allocator.destroy(self);
    }
};

pub const GossipIngressMetadata = struct {
    source: GossipSource = .{},
    message_id: MessageId = std.mem.zeroes(MessageId),
    seen_timestamp_ns: i64 = 0,
    peer_id: ?[]const u8 = null,
};

pub const UnknownParentBlock = struct {
    block: AnySignedBeaconBlock,
    block_root: [32]u8,
    seen_timestamp_sec: u64,
    peer_id: ?[]const u8,
};

pub const GossipHandler = struct {
    allocator: Allocator,
    io: std.Io,

    /// Type-erased *BeaconNode.
    node: *anyopaque,

    /// Called to run full STFN + chain import on a validated block.
    /// Receives a parsed block plus canonical root/provenance metadata.
    importPreparedBlockFn: *const fn (ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void,

    /// Called when a gossip block has an unknown parent. The block should be
    /// retained locally for unknown-parent sync, while still returning IGNORE
    /// to gossipsub so it is not propagated onward.
    queueUnknownBlockFn: ?*const fn (ptr: *anyopaque, block: UnknownParentBlock) anyerror!void = null,

    /// Resolve attestation committee metadata, signing root, and duplicate state.
    resolveAttestationFn: *const fn (
        ptr: *anyopaque,
        attestation: *const AnyGossipAttestation,
        attestation_data_root: *const [32]u8,
    ) anyerror!ResolvedAttestation,

    /// Resolve aggregate committee metadata, attesting indices, and signing roots.
    resolveAggregateFn: *const fn (
        ptr: *anyopaque,
        aggregate: *const AnySignedAggregateAndProof,
        attestation_data_root: *const [32]u8,
    ) anyerror!ResolvedAggregate,

    /// Called to import a validated attestation into fork choice + pool.
    importResolvedAttestationFn: ?*const fn (
        ptr: *anyopaque,
        attestation: *const AnyGossipAttestation,
        attestation_data_root: *const [32]u8,
        resolved: *const ResolvedAttestation,
    ) anyerror!void,

    /// Called when a gossip attestation votes for an unknown beacon_block_root.
    queueUnknownBlockAttestationFn: ?*const fn (
        ptr: *anyopaque,
        block_root: [32]u8,
        work: processor_mod.work_item.AttestationWork,
        peer_id: ?[]const u8,
    ) anyerror!bool = null,

    /// Called to import a validated voluntary exit into the op pool.
    importVoluntaryExitFn: ?*const fn (ptr: *anyopaque, exit: *const SignedVoluntaryExit) anyerror!void,

    /// Called to import a validated proposer slashing into the op pool.
    importProposerSlashingFn: ?*const fn (ptr: *anyopaque, slashing: *const ProposerSlashing) anyerror!void,

    /// Called to import a validated attester slashing into the op pool.
    importAttesterSlashingFn: ?*const fn (ptr: *anyopaque, slashing: *const AnyAttesterSlashing) anyerror!void,

    /// Called to import a validated BLS-to-execution change into the op pool.
    importBlsChangeFn: ?*const fn (ptr: *anyopaque, change: *const SignedBLSToExecutionChange) anyerror!void,

    /// Called to import a validated blob sidecar into the chain DA ingress.
    importBlobSidecarFn: *const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import a validated data column sidecar into the chain DA ingress.
    importDataColumnSidecarFn: *const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    // ── BLS signature verification callbacks ────────────────────────────
    // These are called between Phase 1 (cheap checks) and Phase 2 (import).
    // Each receives the raw decompressed SSZ bytes and returns true if the
    // signature(s) are valid. The BeaconNode implementation constructs
    // appropriate signature sets using its state caches.
    //
    // When null, signature verification is skipped (unsafe — for testing only).

    /// Verify block proposer BLS signature. Returns true if valid.
    verifyBlockSignatureFn: ?*const fn (ptr: *anyopaque, block: *const AnySignedBeaconBlock) bool,

    /// Verify voluntary exit BLS signature. Returns true if valid.
    verifyVoluntaryExitSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify proposer slashing BLS signatures (both headers). Returns true if valid.
    verifyProposerSlashingSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify attester slashing BLS signatures (both indexed attestations). Returns true if valid.
    verifyAttesterSlashingSignatureFn: ?*const fn (ptr: *anyopaque, slashing: *const AnyAttesterSlashing) bool,

    /// Verify BLS-to-execution change signature. Returns true if valid.
    verifyBlsChangeSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify attestation BLS signature. Returns true if valid.
    verifyAttestationSignatureFn: ?*const fn (
        ptr: *anyopaque,
        attestation: *const AnyGossipAttestation,
        resolved: *const ResolvedAttestation,
    ) bool,

    /// Verify aggregate and proof BLS signatures (selection proof + aggregator + aggregate). Returns true if valid.
    verifyAggregateSignatureFn: ?*const fn (
        ptr: *anyopaque,
        aggregate: *const AnySignedAggregateAndProof,
        resolved: *const ResolvedAggregate,
    ) bool,

    /// Called to import a validated aggregate into fork choice + aggregate pool.
    importResolvedAggregateFn: ?*const fn (
        ptr: *anyopaque,
        aggregate: *const AnySignedAggregateAndProof,
        attestation_data_root: *const [32]u8,
        resolved: *const ResolvedAggregate,
    ) anyerror!void,

    /// Called when a gossip aggregate votes for an unknown beacon_block_root.
    queueUnknownBlockAggregateFn: ?*const fn (
        ptr: *anyopaque,
        block_root: [32]u8,
        work: processor_mod.work_item.AggregateWork,
        peer_id: ?[]const u8,
    ) anyerror!bool = null,

    /// Verify sync committee message BLS signature. Returns true if valid.
    verifySyncCommitteeSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify sync committee contribution selection proof, aggregator signature,
    /// and contribution signature. Returns an error so callers can distinguish
    /// between IGNORE and REJECT outcomes.
    verifySyncContributionSignatureFn: *const fn (ptr: *anyopaque, signed_contribution: *const SignedContributionAndProof) anyerror!u32,

    /// Verify blob sidecar proposer signature, inclusion proof, and KZG proof.
    /// Returns an error so callers can distinguish between IGNORE and REJECT outcomes.
    verifyBlobSidecarFn: *const fn (ptr: *anyopaque, sidecar: *const types.deneb.BlobSidecar.Type) anyerror!void,

    /// Verify data column sidecar proposer signature, inclusion proof, and KZG proofs.
    /// Returns an error so callers can distinguish between IGNORE and REJECT outcomes.
    verifyDataColumnSidecarFn: *const fn (ptr: *anyopaque, sidecar: *const types.fulu.DataColumnSidecar.Type) anyerror!void,

    /// Returns true if the validator is a member of the sync committee subnet
    /// for the given slot.
    isValidSyncCommitteeSubnetFn: *const fn (ptr: *anyopaque, slot: u64, validator_index: u64, subnet: u64) bool,

    /// Returns the blob sidecar subnet count for the given slot.
    getBlobSidecarSubnetCountFn: *const fn (ptr: *anyopaque, slot: u64) u64,

    /// Called to import a validated sync committee contribution into the pool.
    importSyncContributionFn: *const fn (ptr: *anyopaque, signed_contribution: *const SignedContributionAndProof) anyerror!void,

    /// Called to import a validated sync committee message into the pool.
    importSyncCommitteeMessageFn: ?*const fn (ptr: *anyopaque, message: *const SyncCommitteeMessage, subnet: u64) anyerror!void,

    /// Gossip dedup caches (owned). Used by Phase 1 fast validation.
    seen_cache: SeenCache,

    /// Slot/epoch state for validation — caller must keep this current.
    current_slot: u64,
    current_epoch: u64,
    finalized_slot: u64,
    /// Active fork sequence for fork-aware gossip deserialization.
    /// Must be updated on fork transitions via updateForkSeq().
    current_fork_seq: ForkSeq,

    /// Vtable for state queries (proposer schedule, known roots, etc.).
    getForkSeqForSlot: *const fn (ptr: *anyopaque, slot: u64) ForkSeq,
    getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
    isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
    getKnownBlockInfo: *const fn (ptr: *anyopaque, root: [32]u8) ?chain_gossip.ChainState.KnownBlockInfo,
    getValidatorCount: *const fn (ptr: *anyopaque) u32,

    /// Optional metrics pointer — records gossip accept/reject/ignore counts.
    metrics: ?*BeaconMetrics = null,

    /// Optional BeaconProcessor for enqueue-based processing.
    /// When set, Phase 2 work (import, chain validation) is enqueued
    /// into priority queues instead of executing inline.
    /// When null, falls back to inline processing (tests, early init).
    beacon_processor: ?*BeaconProcessor = null,

    pub const RequiredPhase2Fns = struct {
        importSyncContributionFn: *const fn (ptr: *anyopaque, signed_contribution: *const SignedContributionAndProof) anyerror!void,
        importBlobSidecarFn: *const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,
        importDataColumnSidecarFn: *const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,
        verifySyncContributionSignatureFn: *const fn (ptr: *anyopaque, signed_contribution: *const SignedContributionAndProof) anyerror!u32,
        verifyBlobSidecarFn: *const fn (ptr: *anyopaque, sidecar: *const types.deneb.BlobSidecar.Type) anyerror!void,
        verifyDataColumnSidecarFn: *const fn (ptr: *anyopaque, sidecar: *const types.fulu.DataColumnSidecar.Type) anyerror!void,
        getBlobSidecarSubnetCountFn: *const fn (ptr: *anyopaque, slot: u64) u64,
    };

    /// Allocate a GossipHandler on the heap and initialise owned SeenCache.
    pub fn create(
        allocator: Allocator,
        io: std.Io,
        node: *anyopaque,
        importPreparedBlockFn: *const fn (ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void,
        getForkSeqForSlot: *const fn (ptr: *anyopaque, slot: u64) ForkSeq,
        getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
        isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
        getKnownBlockInfo: *const fn (ptr: *anyopaque, root: [32]u8) ?chain_gossip.ChainState.KnownBlockInfo,
        getValidatorCount: *const fn (ptr: *anyopaque) u32,
        resolveAttestationFn: *const fn (
            ptr: *anyopaque,
            attestation: *const AnyGossipAttestation,
            attestation_data_root: *const [32]u8,
        ) anyerror!ResolvedAttestation,
        resolveAggregateFn: *const fn (
            ptr: *anyopaque,
            aggregate: *const AnySignedAggregateAndProof,
            attestation_data_root: *const [32]u8,
        ) anyerror!ResolvedAggregate,
        isValidSyncCommitteeSubnetFn: *const fn (ptr: *anyopaque, slot: u64, validator_index: u64, subnet: u64) bool,
        required_phase2: RequiredPhase2Fns,
    ) !*GossipHandler {
        const self = try allocator.create(GossipHandler);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .node = node,
            .importPreparedBlockFn = importPreparedBlockFn,
            .queueUnknownBlockFn = null,
            .resolveAttestationFn = resolveAttestationFn,
            .resolveAggregateFn = resolveAggregateFn,
            .importResolvedAttestationFn = null,
            .queueUnknownBlockAttestationFn = null,
            .importVoluntaryExitFn = null,
            .importProposerSlashingFn = null,
            .importAttesterSlashingFn = null,
            .importBlsChangeFn = null,
            .importBlobSidecarFn = required_phase2.importBlobSidecarFn,
            .importDataColumnSidecarFn = required_phase2.importDataColumnSidecarFn,
            .verifyBlockSignatureFn = null,
            .verifyVoluntaryExitSignatureFn = null,
            .verifyProposerSlashingSignatureFn = null,
            .verifyAttesterSlashingSignatureFn = null,
            .verifyBlsChangeSignatureFn = null,
            .verifyAttestationSignatureFn = null,
            .verifyAggregateSignatureFn = null,
            .importResolvedAggregateFn = null,
            .queueUnknownBlockAggregateFn = null,
            .verifySyncCommitteeSignatureFn = null,
            .verifySyncContributionSignatureFn = required_phase2.verifySyncContributionSignatureFn,
            .verifyBlobSidecarFn = required_phase2.verifyBlobSidecarFn,
            .verifyDataColumnSidecarFn = required_phase2.verifyDataColumnSidecarFn,
            .isValidSyncCommitteeSubnetFn = isValidSyncCommitteeSubnetFn,
            .getBlobSidecarSubnetCountFn = required_phase2.getBlobSidecarSubnetCountFn,
            .importSyncContributionFn = required_phase2.importSyncContributionFn,
            .importSyncCommitteeMessageFn = null,
            .seen_cache = SeenCache.init(allocator),
            .current_slot = 0,
            .current_epoch = 0,
            .finalized_slot = 0,
            .current_fork_seq = .phase0,
            .getForkSeqForSlot = getForkSeqForSlot,
            .getProposerIndex = getProposerIndex,
            .isKnownBlockRoot = isKnownBlockRoot,
            .getKnownBlockInfo = getKnownBlockInfo,
            .getValidatorCount = getValidatorCount,
        };
        return self;
    }

    pub fn deinit(self: *GossipHandler) void {
        self.seen_cache.deinit();
        self.allocator.destroy(self);
    }

    /// Update clock state used for gossip validation.
    /// Call once per slot transition.
    pub fn updateClock(self: *GossipHandler, slot: u64, epoch: u64, finalized_slot: u64) void {
        self.current_slot = slot;
        self.current_epoch = epoch;
        self.finalized_slot = finalized_slot;
        self.seen_cache.pruneSyncContributions(slot);
    }

    /// Update the active fork sequence for fork-aware deserialization.
    /// Call on fork transitions (e.g., when the fork digest changes).
    pub fn updateForkSeq(self: *GossipHandler, fork_seq: ForkSeq) void {
        self.current_fork_seq = fork_seq;
    }

    /// Build a ChainState snapshot for fast Phase 1 validation.
    fn makeChainState(self: *GossipHandler) ChainState {
        return .{
            .current_slot = self.current_slot,
            .current_epoch = self.current_epoch,
            .finalized_slot = self.finalized_slot,
            .seen_cache = &self.seen_cache,
            .ptr = self.node,
            .getProposerIndex = self.getProposerIndex,
            .isKnownBlockRoot = self.isKnownBlockRoot,
            .getKnownBlockInfo = self.getKnownBlockInfo,
            .getValidatorCount = self.getValidatorCount,
        };
    }

    /// Map a GossipAction to an error (or success for accept).
    fn checkAction(action: GossipAction) GossipHandlerError!void {
        switch (action) {
            .accept => {},
            .ignore => return GossipHandlerError.ValidationIgnored,
            .reject => return GossipHandlerError.ValidationRejected,
        }
    }

    fn classifyAttestationAction(action: AttestationGossipAction) GossipHandlerError!bool {
        return switch (action) {
            .accept => false,
            .unknown_beacon_block => true,
            .ignore => GossipHandlerError.ValidationIgnored,
            .reject => GossipHandlerError.ValidationRejected,
        };
    }

    fn resolveAttestation(
        self: *GossipHandler,
        attestation: *const AnyGossipAttestation,
        attestation_data_root: *const [32]u8,
    ) anyerror!ResolvedAttestation {
        return self.resolveAttestationFn(self.node, attestation, attestation_data_root);
    }

    fn resolveAggregate(
        self: *GossipHandler,
        aggregate: *const AnySignedAggregateAndProof,
        attestation_data_root: *const [32]u8,
    ) anyerror!ResolvedAggregate {
        return self.resolveAggregateFn(self.node, aggregate, attestation_data_root);
    }

    fn dupeQueuedSszBytes(self: *GossipHandler, ssz_bytes: []const u8) ?GossipDataHandle {
        const queued = self.allocator.create(QueuedSszBytes) catch return null;
        const ssz_copy = self.allocator.dupe(u8, ssz_bytes) catch {
            self.allocator.destroy(queued);
            return null;
        };
        queued.* = .{
            .ssz_bytes = ssz_copy,
            .allocator = self.allocator,
            .fork_seq = self.current_fork_seq,
        };
        return GossipDataHandle.initOwned(QueuedSszBytes, queued);
    }

    fn dupeOwnedSszBytes(self: *GossipHandler, ssz_bytes: []const u8) ?OwnedSszBytes {
        return OwnedSszBytes.dupe(self.allocator, ssz_bytes) catch null;
    }

    fn parseSignedAggregateAndProof(self: *GossipHandler, ssz_bytes: []const u8) ?AnySignedAggregateAndProof {
        return AnySignedAggregateAndProof.deserialize(self.allocator, self.current_fork_seq, ssz_bytes) catch null;
    }

    fn parseSignedBeaconBlock(self: *GossipHandler, slot: u64, ssz_bytes: []const u8) ?AnySignedBeaconBlock {
        return AnySignedBeaconBlock.deserialize(
            self.allocator,
            .full,
            self.getForkSeqForSlot(self.node, slot),
            ssz_bytes,
        ) catch null;
    }

    fn parseGossipAttestation(self: *GossipHandler, ssz_bytes: []const u8) ?AnyGossipAttestation {
        return AnyGossipAttestation.deserialize(self.allocator, self.current_fork_seq, ssz_bytes) catch null;
    }

    fn parseSignedVoluntaryExit(ssz_bytes: []const u8) ?SignedVoluntaryExit {
        var exit: SignedVoluntaryExit = undefined;
        types.phase0.SignedVoluntaryExit.deserializeFromBytes(ssz_bytes, &exit) catch return null;
        return exit;
    }

    fn parseProposerSlashing(ssz_bytes: []const u8) ?ProposerSlashing {
        var slashing: ProposerSlashing = undefined;
        types.phase0.ProposerSlashing.deserializeFromBytes(ssz_bytes, &slashing) catch return null;
        return slashing;
    }

    fn parseAttesterSlashing(self: *GossipHandler, ssz_bytes: []const u8) ?AnyAttesterSlashing {
        return AnyAttesterSlashing.deserialize(self.allocator, self.current_fork_seq, ssz_bytes) catch null;
    }

    fn parseBlsChange(ssz_bytes: []const u8) ?SignedBLSToExecutionChange {
        var change: SignedBLSToExecutionChange = undefined;
        types.capella.SignedBLSToExecutionChange.deserializeFromBytes(ssz_bytes, &change) catch return null;
        return change;
    }

    fn parseSignedContributionAndProof(ssz_bytes: []const u8) ?SignedContributionAndProof {
        var signed_contribution: SignedContributionAndProof = undefined;
        types.altair.SignedContributionAndProof.deserializeFromBytes(ssz_bytes, &signed_contribution) catch return null;
        return signed_contribution;
    }

    fn parseSyncCommitteeMessage(ssz_bytes: []const u8) ?SyncCommitteeMessage {
        var message: SyncCommitteeMessage = undefined;
        types.altair.SyncCommitteeMessage.deserializeFromBytes(ssz_bytes, &message) catch return null;
        return message;
    }

    /// Called when a gossip message arrives on the beacon_block topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/proposer/parent_root
    /// 2. Phase 1: fast validation (< 1 ms)
    /// 3. Phase 2: queue full import as a work item
    pub fn onBeaconBlock(self: *GossipHandler, message_data: []const u8) !void {
        return self.onBeaconBlockWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onBeaconBlockWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_BEACON_BLOCK) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_block, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const blk = decoded.beacon_block;

        // Compute a cheap synthetic block root for dedup.
        // Full HTR is expensive; use (slot, proposer, parent_root prefix) as key.
        var block_root: [32]u8 = std.mem.zeroes([32]u8);
        std.mem.writeInt(u64, block_root[0..8], blk.slot, .little);
        std.mem.writeInt(u64, block_root[8..16], blk.proposer_index, .little);
        @memcpy(block_root[16..32], blk.parent_root[0..16]);

        // Phase 1b: Fast validation.
        var chain_state = self.makeChainState();
        const validation = chain_gossip.validateGossipBlockDetailed(
            blk.slot,
            blk.proposer_index,
            blk.parent_root,
            block_root,
            &chain_state,
        );
        switch (validation) {
            .accept => {
                var any_signed: ?AnySignedBeaconBlock = self.parseSignedBeaconBlock(blk.slot, ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
                errdefer if (any_signed) |*block| block.deinit(self.allocator);

                // Phase 1c: BLS signature verification (expensive but required before ACCEPT).
                // [REJECT] The proposer signature is valid.
                if (self.verifyBlockSignatureFn) |verifyFn| {
                    if (!verifyFn(self.node, &any_signed.?)) {
                        scoped_log.debug("Gossip block rejected: invalid proposer signature slot={d}", .{blk.slot});
                        return GossipHandlerError.InvalidSignature;
                    }
                }

                // Phase 2: Full import (STFN + fork choice).
                if (self.beacon_processor) |bp| {
                    bp.ingest(.{ .gossip_block = .{
                        .source = metadata.source,
                        .message_id = metadata.message_id,
                        .block = any_signed.?,
                        .peer_id = if (metadata.peer_id) |peer_id|
                            processor_mod.PeerIdHandle.initOwned(self.allocator, peer_id) catch .none
                        else
                            .none,
                        .seen_timestamp_ns = metadata.seen_timestamp_ns,
                    } });
                    any_signed = null;
                    return;
                }

                var full_block_root: [32]u8 = undefined;
                try any_signed.?.beaconBlock().hashTreeRoot(self.allocator, &full_block_root);
                const seen_timestamp_sec: u64 = if (metadata.seen_timestamp_ns > 0)
                    @intCast(@divFloor(metadata.seen_timestamp_ns, std.time.ns_per_s))
                else
                    0;
                var prepared: PreparedBlockInput = .{
                    .block = any_signed.?,
                    .source = .gossip,
                    .block_root = full_block_root,
                    .seen_timestamp_sec = seen_timestamp_sec,
                };
                prepared.setPeerId(metadata.peer_id);
                any_signed = null;
                try self.importPreparedBlockFn(self.node, prepared);
                return;
            },
            .reject => return GossipHandlerError.ValidationRejected,
            .ignore => return GossipHandlerError.ValidationIgnored,
            .ignore_parent_unknown => {
                if (self.queueUnknownBlockFn) |queueFn| {
                    var any_signed = self.parseSignedBeaconBlock(blk.slot, ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
                    errdefer any_signed.deinit(self.allocator);

                    var full_block_root: [32]u8 = undefined;
                    try any_signed.beaconBlock().hashTreeRoot(self.allocator, &full_block_root);
                    const seen_timestamp_sec: u64 = if (metadata.seen_timestamp_ns > 0)
                        @intCast(@divFloor(metadata.seen_timestamp_ns, std.time.ns_per_s))
                    else
                        0;
                    try queueFn(self.node, .{
                        .block = any_signed,
                        .block_root = full_block_root,
                        .seen_timestamp_sec = seen_timestamp_sec,
                        .peer_id = metadata.peer_id,
                    });
                    any_signed = undefined;
                    self.seen_cache.markBlockSeen(block_root, blk.slot) catch {};
                }
                return GossipHandlerError.ValidationIgnored;
            },
        }
    }

    /// Called when a gossip attestation arrives on a `beacon_attestation_{subnet}` topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/committee/target/attester
    /// 2. Phase 1: fast validation (< 1 ms) — slot range, committee bounds, dedup
    /// 3. Phase 2: import to fork choice + attestation pool
    pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onAttestationWithMetadata(subnet_id, message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onAttestationWithMetadata(
        self: *GossipHandler,
        subnet_id: u64,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_ATTESTATION) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Deserialize the full gossip attestation wrapper once so the
        // processor and importer can use the real fork-typed object.
        var attestation = self.parseGossipAttestation(ssz_bytes) orelse {
            scoped_log.debug(
                "Failed to parse gossip attestation: fork_seq={s} subnet={d} compressed_len={d} ssz_len={d}",
                .{ @tagName(self.current_fork_seq), subnet_id, message_data.len, ssz_bytes.len },
            );
            return GossipHandlerError.DecodeFailed;
        };
        var attestation_owned = true;
        defer if (attestation_owned) attestation.deinit(self.allocator);
        const data = attestation.data();
        var attestation_data_root: [32]u8 = undefined;
        types.phase0.AttestationData.hashTreeRoot(&data, &attestation_data_root) catch
            return GossipHandlerError.DecodeFailed;
        const committee_index = attestation.committeeIndex();

        // Phase 1b: Fast validation.
        var chain_state = self.makeChainState();
        const action = if (self.current_fork_seq.gte(.electra))
            chain_gossip.validateGossipElectraAttestation(
                data.slot,
                data.index,
                data.target.epoch,
                data.beacon_block_root,
                data.target.root,
                committee_index,
                self.current_fork_seq.gte(.gloas),
                &chain_state,
            )
        else
            chain_gossip.validateGossipAttestation(
                data.slot,
                committee_index,
                data.target.epoch,
                data.beacon_block_root,
                data.target.root,
                &chain_state,
            );
        const queue_unknown_block = try classifyAttestationAction(action);

        if (attestation.participantCount() != 1) {
            return GossipHandlerError.ValidationRejected;
        }

        const resolved = self.resolveAttestation(&attestation, &attestation_data_root) catch |err| switch (err) {
            error.NoHeadState,
            error.EpochShufflingNotFound,
            error.CommitteeIndexOutOfBounds,
            => return GossipHandlerError.ValidationIgnored,
            error.InvalidGossipAttestation,
            error.AttesterNotInCommittee,
            error.ValidatorIndexOutOfBounds,
            => return GossipHandlerError.ValidationRejected,
            else => return err,
        };
        if (resolved.expected_subnet != subnet_id) {
            return GossipHandlerError.WrongSubnet;
        }
        if (resolved.already_seen) {
            return GossipHandlerError.ValidationIgnored;
        }

        if (queue_unknown_block) {
            if (self.queueUnknownBlockAttestationFn) |queueFn| {
                attestation_owned = false;
                const queued = try queueFn(self.node, data.beacon_block_root, .{
                    .source = metadata.source,
                    .message_id = metadata.message_id,
                    .attestation = attestation,
                    .attestation_data_root = attestation_data_root,
                    .resolved = resolved,
                    .subnet_id = @intCast(subnet_id),
                    .seen_timestamp_ns = metadata.seen_timestamp_ns,
                }, metadata.peer_id);
                if (queued) return GossipHandlerError.ValidationDeferred;
                attestation_owned = true;
            }
            return GossipHandlerError.ValidationIgnored;
        }

        if (!chain_state.isKnownBlockRoot(chain_state.ptr, data.beacon_block_root)) {
            if (self.queueUnknownBlockAttestationFn) |queueFn| {
                attestation_owned = false;
                const queued = try queueFn(self.node, data.beacon_block_root, .{
                    .source = metadata.source,
                    .message_id = metadata.message_id,
                    .attestation = attestation,
                    .attestation_data_root = attestation_data_root,
                    .resolved = resolved,
                    .subnet_id = @intCast(subnet_id),
                    .seen_timestamp_ns = metadata.seen_timestamp_ns,
                }, metadata.peer_id);
                if (queued) return GossipHandlerError.ValidationDeferred;
                attestation_owned = true;
            }
            return GossipHandlerError.ValidationIgnored;
        }

        // Phase 2: Import to fork choice + attestation pool.
        // When processor is available, defer BLS to batch verification.
        // Attestations are LIFO-queued and batched for efficient BLS verification.
        if (self.beacon_processor) |bp| {
            attestation_owned = false;
            bp.ingest(.{ .attestation = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .attestation = attestation,
                .attestation_data_root = attestation_data_root,
                .resolved = resolved,
                .subnet_id = @intCast(subnet_id),
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return GossipHandlerError.ValidationDeferred;
        }

        // Phase 1c: BLS signature verification (only for inline processing path).
        // [REJECT] The attestation signature is valid.
        if (self.verifyAttestationSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, &attestation, &resolved)) {
                scoped_log.debug("Gossip attestation rejected: invalid signature slot={d}", .{data.slot});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Fallback: inline processing.
        if (self.importResolvedAttestationFn) |importFn| {
            importFn(self.node, &attestation, &attestation_data_root, &resolved) catch |err| {
                scoped_log.debug("attestation import failed for slot {d}: {}", .{ data.slot, err });
            };
        }
    }

    /// Called when a gossip aggregate arrives on the `beacon_aggregate_and_proof` topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract aggregator/attestation fields
    /// 2. Phase 1: fast validation (aggregator bounds, slot range, dedup)
    /// 3. Phase 2: import to fork choice + attestation pool
    pub fn onAggregateAndProof(self: *GossipHandler, message_data: []const u8) !void {
        return self.onAggregateAndProofWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onAggregateAndProofWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Parse the full aggregate once so validation, verification, and import
        // all work from the same fork-typed object.
        var signed_aggregate = self.parseSignedAggregateAndProof(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        var aggregate_owned = true;
        defer if (aggregate_owned) signed_aggregate.deinit(self.allocator);
        const attestation = signed_aggregate.attestation();
        const att_data = attestation.data();
        var attestation_data_root: [32]u8 = undefined;
        types.phase0.AttestationData.hashTreeRoot(&att_data, &attestation_data_root) catch
            return GossipHandlerError.DecodeFailed;

        // Phase 1b: Fast validation.
        var chain_state = self.makeChainState();
        const action = switch (signed_aggregate) {
            .phase0 => chain_gossip.validateGossipAggregate(
                signed_aggregate.aggregatorIndex(),
                signed_aggregate.slot(),
                signed_aggregate.targetEpoch(),
                att_data.beacon_block_root,
                att_data.target.root,
                signed_aggregate.participantCount(),
                &chain_state,
            ),
            .electra => chain_gossip.validateGossipElectraAggregate(
                signed_aggregate.aggregatorIndex(),
                signed_aggregate.slot(),
                signed_aggregate.targetEpoch(),
                att_data.beacon_block_root,
                att_data.target.root,
                signed_aggregate.dataIndex(),
                signed_aggregate.committeeCount(),
                signed_aggregate.participantCount(),
                &chain_state,
            ),
        };
        const queue_unknown_block = try classifyAttestationAction(action);

        var resolved = self.resolveAggregate(&signed_aggregate, &attestation_data_root) catch |err| switch (err) {
            error.NoHeadState,
            error.EpochShufflingNotFound,
            error.CommitteeIndexOutOfBounds,
            => return GossipHandlerError.ValidationIgnored,
            error.InvalidGossipAttestation,
            error.AttesterNotInCommittee,
            error.ValidatorIndexOutOfBounds,
            error.InvalidAggregatorIndex,
            error.AggregatorNotInCommittee,
            error.InvalidSelectionProof,
            error.EmptyAggregateAttestation,
            => return GossipHandlerError.ValidationRejected,
            else => return err,
        };
        var resolved_owned = true;
        defer if (resolved_owned) resolved.deinit(self.allocator);

        if (queue_unknown_block) {
            if (self.queueUnknownBlockAggregateFn) |queueFn| {
                aggregate_owned = false;
                resolved_owned = false;
                const queued = try queueFn(self.node, att_data.beacon_block_root, .{
                    .source = metadata.source,
                    .message_id = metadata.message_id,
                    .aggregate = signed_aggregate,
                    .attestation_data_root = attestation_data_root,
                    .resolved = resolved,
                    .seen_timestamp_ns = metadata.seen_timestamp_ns,
                }, metadata.peer_id);
                if (queued) return GossipHandlerError.ValidationDeferred;
                aggregate_owned = true;
                resolved_owned = true;
            }
            return GossipHandlerError.ValidationIgnored;
        }

        if (!chain_state.isKnownBlockRoot(chain_state.ptr, att_data.beacon_block_root)) {
            if (self.queueUnknownBlockAggregateFn) |queueFn| {
                aggregate_owned = false;
                resolved_owned = false;
                const queued = try queueFn(self.node, att_data.beacon_block_root, .{
                    .source = metadata.source,
                    .message_id = metadata.message_id,
                    .aggregate = signed_aggregate,
                    .attestation_data_root = attestation_data_root,
                    .resolved = resolved,
                    .seen_timestamp_ns = metadata.seen_timestamp_ns,
                }, metadata.peer_id);
                if (queued) return GossipHandlerError.ValidationDeferred;
                aggregate_owned = true;
                resolved_owned = true;
            }
            return GossipHandlerError.ValidationIgnored;
        }

        // Phase 2: Import aggregate to fork choice + attestation pool.
        // When processor is available, defer the expensive BLS checks to
        // processor-side batch verification.
        if (self.beacon_processor) |bp| {
            aggregate_owned = false;
            resolved_owned = false;
            bp.ingest(.{ .aggregate = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .aggregate = signed_aggregate,
                .attestation_data_root = attestation_data_root,
                .resolved = resolved,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return GossipHandlerError.ValidationDeferred;
        }

        // Phase 1c: BLS signature verification.
        // [REJECT] selection_proof, aggregator signature, and aggregate signature are all valid.
        if (self.verifyAggregateSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, &signed_aggregate, &resolved)) {
                scoped_log.debug("Gossip aggregate rejected: invalid signature aggregator={d}", .{signed_aggregate.aggregatorIndex()});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Fallback: inline processing.
        if (self.importResolvedAggregateFn) |importFn| {
            importFn(self.node, &signed_aggregate, &attestation_data_root, &resolved) catch |err| {
                scoped_log.debug("aggregate import failed for aggregator {d}: {}", .{ signed_aggregate.aggregatorIndex(), err });
            };
            return;
        }
    }

    /// Called when a voluntary_exit gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract validator index and exit epoch
    /// 2. Phase 1: basic bounds check (validator index within set)
    /// 3. Phase 2: import to op pool
    pub fn onVoluntaryExit(self: *GossipHandler, message_data: []const u8) !void {
        return self.onVoluntaryExitWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onVoluntaryExitWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .voluntary_exit, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const exit = decoded.voluntary_exit;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state = self.makeChainState();
        const action_exit = chain_gossip.validateGossipVoluntaryExit(
            exit.validator_index,
            exit.exit_epoch,
            &chain_state,
        );
        try checkAction(action_exit);

        // Phase 1c: BLS signature verification.
        // [REJECT] The voluntary exit signature is valid.
        if (self.verifyVoluntaryExitSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                scoped_log.debug("Gossip voluntary exit rejected: invalid signature validator={d}", .{exit.validator_index});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Phase 2: import to op pool.
        const signed_exit = parseSignedVoluntaryExit(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .gossip_voluntary_exit = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .exit = signed_exit,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importVoluntaryExitFn) |importFn| {
            importFn(self.node, &signed_exit) catch |err| {
                scoped_log.debug("voluntary exit import failed for validator {d}: {}", .{ exit.validator_index, err });
            };
        }

        scoped_log.debug("Accepted voluntary_exit: validator={d} epoch={d}", .{
            exit.validator_index, exit.exit_epoch,
        });
    }

    /// Called when a proposer_slashing gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract proposer index, header slots/body roots
    /// 2. Phase 1: headers must have same slot but different body roots (different blocks)
    /// 3. Phase 2: import to op pool
    pub fn onProposerSlashing(self: *GossipHandler, message_data: []const u8) !void {
        return self.onProposerSlashingWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onProposerSlashingWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .proposer_slashing, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const ps = decoded.proposer_slashing;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_ps = self.makeChainState();
        const action_ps = chain_gossip.validateGossipProposerSlashing(
            ps.proposer_index,
            ps.header_1_slot,
            ps.header_2_slot,
            ps.header_1_body_root,
            ps.header_2_body_root,
            &chain_state_ps,
        );
        try checkAction(action_ps);

        // Phase 1c: BLS signature verification.
        // [REJECT] Both signed header signatures are valid.
        if (self.verifyProposerSlashingSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                scoped_log.debug("Gossip proposer slashing rejected: invalid signature proposer={d}", .{ps.proposer_index});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Phase 2: import to op pool.
        const slashing = parseProposerSlashing(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .gossip_proposer_slashing = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .slashing = slashing,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importProposerSlashingFn) |importFn| {
            importFn(self.node, &slashing) catch |err| {
                scoped_log.debug("proposer slashing import failed for proposer {d}: {}", .{ ps.proposer_index, err });
            };
        }

        scoped_log.debug("Accepted proposer_slashing: proposer={d} slot={d}", .{
            ps.proposer_index, ps.header_1_slot,
        });
    }

    /// Called when an attester_slashing gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → check slashable attestation data
    /// 2. Phase 1: attestation data must be slashable (double vote or surround vote)
    /// 3. Phase 2: import raw SSZ to op pool (full deserialization happens at pool layer)
    pub fn onAttesterSlashing(self: *GossipHandler, message_data: []const u8) !void {
        return self.onAttesterSlashingWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onAttesterSlashingWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for parse, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        var slashing = self.parseAttesterSlashing(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        var slashing_owned = true;
        defer if (slashing_owned) slashing.deinit(self.allocator);

        var slashing_root: [32]u8 = undefined;
        slashing.hashTreeRoot(self.allocator, &slashing_root) catch return GossipHandlerError.DecodeFailed;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_as = self.makeChainState();
        const action_as = chain_gossip.validateGossipAttesterSlashing(
            slashing.isSlashable(),
            slashing_root,
            &chain_state_as,
        );
        try checkAction(action_as);

        // Phase 1c: BLS signature verification.
        // [REJECT] Both indexed attestation signatures are valid.
        if (self.verifyAttesterSlashingSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, &slashing)) {
                scoped_log.debug("Gossip attester slashing rejected: invalid signature", .{});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Phase 2: import the fully typed slashing.
        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .gossip_attester_slashing = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .slashing = slashing,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            slashing_owned = false;
            return;
        }

        // Fallback: inline processing.
        if (self.importAttesterSlashingFn) |importFn| {
            importFn(self.node, &slashing) catch |err| {
                scoped_log.debug("attester slashing import failed: {}", .{err});
            };
        }

        scoped_log.debug("Accepted attester_slashing", .{});
    }

    /// Called when a bls_to_execution_change gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract validator index
    /// 2. Phase 1: validator index must be within known set
    /// 3. Phase 2: import to op pool
    pub fn onBlsToExecutionChange(self: *GossipHandler, message_data: []const u8) !void {
        return self.onBlsToExecutionChangeWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onBlsToExecutionChangeWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .bls_to_execution_change, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const change = decoded.bls_to_execution_change;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_bls = self.makeChainState();
        const action_bls = chain_gossip.validateGossipBlsToExecutionChange(
            change.validator_index,
            &chain_state_bls,
        );
        try checkAction(action_bls);

        // Phase 1c: BLS signature verification.
        // [REJECT] The BLS-to-execution change signature is valid.
        if (self.verifyBlsChangeSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                scoped_log.debug("Gossip BLS change rejected: invalid signature validator={d}", .{change.validator_index});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Phase 2: import to op pool.
        const signed_change = parseBlsChange(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .gossip_bls_to_exec = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .change = signed_change,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importBlsChangeFn) |importFn| {
            importFn(self.node, &signed_change) catch |err| {
                scoped_log.debug("BLS change import failed for validator {d}: {}", .{ change.validator_index, err });
            };
        }

        scoped_log.debug("Accepted bls_to_execution_change: validator={d}", .{
            change.validator_index,
        });
    }

    /// Called when a sync_committee_contribution_and_proof gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract aggregator, contribution fields
    /// 2. Phase 1: basic bounds check (aggregator within validator set)
    /// 3. Phase 2: log acceptance (no sync contribution pool yet)
    pub fn onSyncCommitteeContribution(self: *GossipHandler, message_data: []const u8) !void {
        return self.onSyncCommitteeContributionWithMetadata(message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onSyncCommitteeContributionWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .sync_committee_contribution_and_proof, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const contrib = decoded.sync_committee_contribution_and_proof;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_sc = self.makeChainState();
        const action_sc = chain_gossip.validateGossipSyncContributionAndProof(
            contrib.aggregator_index,
            contrib.contribution_slot,
            &chain_state_sc,
        );
        try checkAction(action_sc);

        // Lodestar ignores duplicate aggregators and duplicate participant
        // supersets before signature verification.
        const signed_contribution = parseSignedContributionAndProof(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        if (self.seen_cache.syncContributionParticipantsKnown(&signed_contribution.message.contribution)) {
            return GossipHandlerError.ValidationIgnored;
        }
        if (self.seen_cache.isSyncContributionAggregatorKnown(
            signed_contribution.message.contribution.slot,
            signed_contribution.message.contribution.subcommittee_index,
            @intCast(signed_contribution.message.aggregator_index),
        )) {
            return GossipHandlerError.ValidationIgnored;
        }

        const participant_count = self.verifySyncContributionSignatureFn(self.node, &signed_contribution) catch |err| switch (err) {
            error.ValidatorNotFound,
            error.InvalidSubcommitteeIndex,
            error.ValidatorNotInSyncCommittee,
            error.NoParticipant,
            error.InvalidSelectionProof,
            error.InvalidSignature,
            => {
                scoped_log.debug("Gossip sync contribution rejected: aggregator={d} slot={d} err={}", .{
                    contrib.aggregator_index,
                    contrib.contribution_slot,
                    err,
                });
                return GossipHandlerError.ValidationRejected;
            },
            else => return err,
        };
        self.seen_cache.markSyncContributionSeen(&signed_contribution.message, participant_count) catch
            return GossipHandlerError.ValidationIgnored;

        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .sync_contribution = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .signed_contribution = signed_contribution,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        self.importSyncContributionFn(self.node, &signed_contribution) catch |err| {
            scoped_log.debug("sync contribution import failed: {}", .{err});
        };

        scoped_log.debug("Accepted sync_committee_contribution_and_proof: aggregator={d} slot={d} subcommittee={d}", .{
            contrib.aggregator_index,
            contrib.contribution_slot,
            contrib.subcommittee_index,
        });
    }

    /// Called when a sync_committee gossip message (SyncCommitteeMessage) arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot, validator index
    /// 2. Phase 1: basic bounds check
    /// 3. Phase 2: import into the sync committee message pool
    pub fn onSyncCommitteeMessage(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onSyncCommitteeMessageWithMetadata(subnet_id, message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onSyncCommitteeMessageWithMetadata(
        self: *GossipHandler,
        subnet_id: u64,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .sync_committee, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const msg = decoded.sync_committee;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_sm = self.makeChainState();
        const action_sm = chain_gossip.validateGossipSyncCommitteeMessage(
            msg.validator_index,
            msg.slot,
            &chain_state_sm,
        );
        try checkAction(action_sm);

        if (!self.isValidSyncCommitteeSubnetFn(self.node, msg.slot, msg.validator_index, subnet_id)) {
            return GossipHandlerError.WrongSubnet;
        }

        const sync_message = parseSyncCommitteeMessage(ssz_bytes) orelse return GossipHandlerError.DecodeFailed;
        if (self.beacon_processor) |bp| {
            bp.ingest(.{ .sync_message = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .message = sync_message,
                .subnet_id = @intCast(subnet_id),
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return GossipHandlerError.ValidationDeferred;
        }

        // Phase 1c: BLS signature verification.
        // [REJECT] The sync committee message signature is valid.
        if (self.verifySyncCommitteeSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                scoped_log.debug("Gossip sync committee message rejected: invalid signature validator={d}", .{msg.validator_index});
                return GossipHandlerError.InvalidSignature;
            }
        }

        // Phase 2: import to sync committee message pool.
        // Fallback: inline processing.
        if (self.importSyncCommitteeMessageFn) |importFn| {
            importFn(self.node, &sync_message, subnet_id) catch |err| {
                scoped_log.debug("sync committee message import failed: {}", .{err});
            };
        }

        scoped_log.debug("Accepted sync_committee message: validator={d} slot={d} subnet={d}", .{
            msg.validator_index,
            msg.slot,
            subnet_id,
        });
    }

    /// Called when a blob_sidecar gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract index, slot, proposer
    /// 2. Phase 1: basic bounds check (slot range, proposer)
    /// 3. Phase 2: decompress full payload and import via BeaconNode
    pub fn onBlobSidecar(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onBlobSidecarWithMetadata(subnet_id, message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onBlobSidecarWithMetadata(
        self: *GossipHandler,
        subnet_id: u64,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_BLOB_SIDECAR) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .blob_sidecar, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const blob = decoded.blob_sidecar;

        // Phase 1: fast validation via chain gossip validation layer.
        var chain_state_blob = self.makeChainState();
        const action_blob = chain_gossip.validateGossipBlobSidecar(
            blob.slot,
            blob.proposer_index,
            blob.index,
            subnet_id,
            self.getBlobSidecarSubnetCountFn(self.node, blob.slot),
            blob.block_parent_root,
            blob.block_root,
            &chain_state_blob,
        );
        try checkAction(action_blob);

        var full_blob = types.deneb.BlobSidecar.default_value;
        types.deneb.BlobSidecar.deserializeFromBytes(self.allocator, ssz_bytes, &full_blob) catch
            return GossipHandlerError.DecodeFailed;
        defer types.deneb.BlobSidecar.deinit(self.allocator, &full_blob);

        self.verifyBlobSidecarFn(self.node, &full_blob) catch |err| switch (err) {
            error.ParentUnknown,
            error.ParentStateUnavailable,
            error.NoPreStateAvailable,
            error.NotLaterThanParent,
            => return GossipHandlerError.ValidationIgnored,
            error.InvalidBlobIndex,
            error.InvalidProposer,
            error.InvalidSignature,
            error.InvalidInclusionProof,
            error.InvalidKzgProof,
            => {
                scoped_log.debug("Gossip blob sidecar rejected: slot={d} proposer={d} index={d} err={}", .{
                    full_blob.slot,
                    full_blob.proposer_index,
                    full_blob.index,
                    err,
                });
                return GossipHandlerError.ValidationRejected;
            },
            else => return err,
        };

        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_blob = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Phase 2: hand off to chain DA ingress.
        self.importBlobSidecarFn(self.node, ssz_bytes) catch |err| {
            scoped_log.debug("blob sidecar import failed: {}", .{err});
        };

        scoped_log.debug("Accepted blob_sidecar: index={d} slot={d} proposer={d} ({d} bytes)", .{
            blob.index,
            blob.slot,
            blob.proposer_index,
            ssz_bytes.len,
        });
    }

    pub fn onDataColumnSidecar(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onDataColumnSidecarWithMetadata(subnet_id, message_data, .{}) catch |err| return normalizeTopicError(err);
    }

    fn onDataColumnSidecarWithMetadata(
        self: *GossipHandler,
        subnet_id: u64,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .data_column_sidecar, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const sidecar = decoded.data_column_sidecar;

        var chain_state = self.makeChainState();
        const action = chain_gossip.validateGossipDataColumnSidecar(
            sidecar.slot,
            sidecar.proposer_index,
            sidecar.index,
            sidecar.block_parent_root,
            sidecar.block_root,
            &chain_state,
        );
        try checkAction(action);

        if (sidecar.index % preset_root.DATA_COLUMN_SIDECAR_SUBNET_COUNT != subnet_id) {
            return GossipHandlerError.WrongSubnet;
        }

        var full_sidecar = types.fulu.DataColumnSidecar.default_value;
        types.fulu.DataColumnSidecar.deserializeFromBytes(self.allocator, ssz_bytes, &full_sidecar) catch
            return GossipHandlerError.DecodeFailed;
        defer types.fulu.DataColumnSidecar.deinit(self.allocator, &full_sidecar);

        self.verifyDataColumnSidecarFn(self.node, &full_sidecar) catch |err| switch (err) {
            error.ParentUnknown,
            error.ParentStateUnavailable,
            error.NoPreStateAvailable,
            => return GossipHandlerError.ValidationIgnored,
            error.NotLaterThanParent,
            => return GossipHandlerError.ValidationRejected,
            error.InvalidColumnIndex,
            error.InvalidCommitmentCount,
            error.InvalidProofCount,
            error.InvalidColumnCount,
            error.InvalidProposer,
            error.InvalidSignature,
            error.InvalidInclusionProof,
            error.InvalidKzgProof,
            => {
                scoped_log.debug("Gossip data column sidecar rejected: slot={d} proposer={d} index={d} err={}", .{
                    full_sidecar.slot,
                    full_sidecar.proposer_index,
                    full_sidecar.index,
                    err,
                });
                return GossipHandlerError.ValidationRejected;
            },
            else => return err,
        };

        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_data_column = .{
                .source = metadata.source,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        self.importDataColumnSidecarFn(self.node, ssz_bytes) catch |err| {
            scoped_log.debug("data column sidecar import failed: {}", .{err});
        };

        scoped_log.debug("Accepted data_column_sidecar: index={d} slot={d} proposer={d}", .{
            sidecar.index,
            sidecar.slot,
            sidecar.proposer_index,
        });
    }

    fn elapsedPhase1Ns(self: *const GossipHandler, started_ns: i128) u64 {
        const now_ns = monotonicNowNs(self.io);
        return @intCast(if (now_ns > started_ns) now_ns - started_ns else 0);
    }

    fn monotonicNowNs(io: std.Io) i128 {
        return std.Io.Timestamp.now(io, .awake).toNanoseconds();
    }

    fn maybeLogSlowPhase1(
        topic: GossipTopicType,
        outcome: []const u8,
        elapsed_ns: u64,
        payload_bytes: usize,
    ) void {
        if (elapsed_ns < slow_gossip_phase1_log_ns) return;
        scoped_log.debug(
            "slow gossip phase1 topic={s} outcome={s} elapsed_ms={d} payload_bytes={d}",
            .{ topic.topicName(), outcome, @divTrunc(elapsed_ns, std.time.ns_per_ms), payload_bytes },
        );
    }

    fn recordProcessResult(
        self: *GossipHandler,
        topic: GossipTopicType,
        result: GossipProcessResult,
        elapsed_ns: u64,
        payload_bytes: usize,
    ) GossipProcessResult {
        const elapsed_seconds = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        switch (result) {
            .accepted => {
                if (self.metrics) |m| {
                    m.observeGossipResult(topic, .accepted);
                    m.observeGossipPhase1(topic, .accepted, elapsed_seconds);
                }
                maybeLogSlowPhase1(topic, "accepted", elapsed_ns, payload_bytes);
            },
            .deferred => {
                if (self.metrics) |m| {
                    m.observeGossipResult(topic, .accepted);
                    m.observeGossipPhase1(topic, .accepted, elapsed_seconds);
                }
                maybeLogSlowPhase1(topic, "deferred", elapsed_ns, payload_bytes);
            },
            .ignored => {
                if (self.metrics) |m| {
                    m.observeGossipResult(topic, .ignored);
                    m.observeGossipPhase1(topic, .ignored, elapsed_seconds);
                }
                maybeLogSlowPhase1(topic, "ignored", elapsed_ns, payload_bytes);
            },
            .rejected => {
                if (self.metrics) |m| {
                    m.observeGossipResult(topic, .rejected);
                    m.observeGossipPhase1(topic, .rejected, elapsed_seconds);
                }
                maybeLogSlowPhase1(topic, "rejected", elapsed_ns, payload_bytes);
            },
            .failed => |err| {
                if (elapsed_ns >= slow_gossip_phase1_log_ns) {
                    scoped_log.debug(
                        "slow gossip phase1 topic={s} outcome=failed elapsed_ms={d} payload_bytes={d} err={}",
                        .{ topic.topicName(), @divTrunc(elapsed_ns, std.time.ns_per_ms), payload_bytes, err },
                    );
                }
            },
        }
        return result;
    }

    fn defaultRejectReason(topic: GossipTopicType) GossipRejectReason {
        return networking.peer_scoring.defaultGossipRejectReason(topic);
    }

    fn processResultError(result: GossipProcessResult) anyerror!void {
        switch (result) {
            .accepted => {},
            .deferred => {},
            .ignored => return GossipHandlerError.ValidationIgnored,
            .rejected => |reason| switch (reason) {
                .decode_failed => return GossipHandlerError.DecodeFailed,
                else => return GossipHandlerError.ValidationRejected,
            },
            .failed => |err| return err,
        }
    }

    fn normalizeTopicError(err: anyerror) anyerror {
        return switch (err) {
            GossipHandlerError.WrongSubnet,
            GossipHandlerError.InvalidSignature,
            => GossipHandlerError.ValidationRejected,
            else => err,
        };
    }

    pub fn processGossipMessage(self: *GossipHandler, topic: GossipTopicType, data: []const u8) GossipProcessResult {
        return self.processGossipMessageWithSubnetAndMetadata(topic, null, data, .{});
    }

    pub fn processGossipMessageWithSubnetAndMetadata(
        self: *GossipHandler,
        topic: GossipTopicType,
        subnet_id: ?u8,
        data: []const u8,
        metadata: GossipIngressMetadata,
    ) GossipProcessResult {
        if (self.metrics) |m| m.incrGossipReceived(topic);
        const started_ns = monotonicNowNs(self.io);

        self.onGossipMessageWithSubnetAndMetadata(topic, subnet_id, data, metadata) catch |err| {
            return self.recordProcessResult(topic, switch (err) {
                GossipHandlerError.ValidationDeferred => .deferred,
                GossipHandlerError.ValidationIgnored => .ignored,
                GossipHandlerError.WrongSubnet => .{ .rejected = .wrong_subnet },
                GossipHandlerError.InvalidSignature => .{ .rejected = .invalid_signature },
                GossipHandlerError.ValidationRejected => .{ .rejected = defaultRejectReason(topic) },
                GossipHandlerError.DecodeFailed => .{ .rejected = .decode_failed },
                else => .{ .failed = err },
            }, self.elapsedPhase1Ns(started_ns), data.len);
        };

        return self.recordProcessResult(topic, .accepted, self.elapsedPhase1Ns(started_ns), data.len);
    }

    /// Route a gossip message by topic type.
    pub fn onGossipMessage(self: *GossipHandler, topic: GossipTopicType, data: []const u8) !void {
        try processResultError(self.processGossipMessage(topic, data));
    }

    /// Route a gossip message by topic type, with optional subnet_id for subnet-indexed topics.
    pub fn onGossipMessageWithSubnet(self: *GossipHandler, topic: GossipTopicType, subnet_id: ?u8, data: []const u8) !void {
        try processResultError(self.processGossipMessageWithSubnetAndMetadata(topic, subnet_id, data, .{}));
    }

    pub fn onGossipMessageWithSubnetAndMetadata(
        self: *GossipHandler,
        topic: GossipTopicType,
        subnet_id: ?u8,
        data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        switch (topic) {
            .beacon_block => try self.onBeaconBlockWithMetadata(data, metadata),
            .beacon_attestation => try self.onAttestationWithMetadata(@as(u64, subnet_id orelse 0), data, metadata),
            .beacon_aggregate_and_proof => try self.onAggregateAndProofWithMetadata(data, metadata),
            .voluntary_exit => try self.onVoluntaryExitWithMetadata(data, metadata),
            .proposer_slashing => try self.onProposerSlashingWithMetadata(data, metadata),
            .attester_slashing => try self.onAttesterSlashingWithMetadata(data, metadata),
            .bls_to_execution_change => try self.onBlsToExecutionChangeWithMetadata(data, metadata),
            .sync_committee_contribution_and_proof => try self.onSyncCommitteeContributionWithMetadata(data, metadata),
            .sync_committee => try self.onSyncCommitteeMessageWithMetadata(@as(u64, subnet_id orelse 0), data, metadata),
            .blob_sidecar => try self.onBlobSidecarWithMetadata(@as(u64, subnet_id orelse 0), data, metadata),
            .data_column_sidecar => try self.onDataColumnSidecarWithMetadata(@as(u64, subnet_id orelse 0), data, metadata),
        }
    }
};
