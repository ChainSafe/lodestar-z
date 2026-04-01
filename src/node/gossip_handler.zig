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
const Allocator = std.mem.Allocator;
const testing = std.testing;

const networking = @import("networking");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const GossipTopicType = networking.GossipTopicType;
const gossip_decoding = networking.gossip_decoding;

const chain = @import("chain");
const SeenCache = chain.SeenCache;
const chain_gossip = chain.gossip_validation;

const BeaconMetrics = @import("metrics.zig").BeaconMetrics;

const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const WorkItem = processor_mod.WorkItem;
const MessageId = processor_mod.work_item.MessageId;
const GossipDataHandle = processor_mod.work_item.GossipDataHandle;
const GossipAction = chain_gossip.GossipAction;
const ChainState = chain_gossip.ChainState;

/// Error set for gossip processing failures.
pub const GossipHandlerError = error{
    /// Gossip validation returned Ignore — message silently dropped.
    ValidationIgnored,
    /// Gossip validation returned Reject — peer should be penalized.
    ValidationRejected,
    /// Decode failed (bad snappy or SSZ).
    DecodeFailed,
};

pub const GossipProcessResult = union(enum) {
    accepted,
    ignored,
    rejected,
    decode_failed,
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
/// Heap-allocated attestation data for processor batch processing.
/// Allocated by gossip handler, freed by processor handler after BLS verification.
pub const QueuedAttestation = struct {
    att: gossip_decoding.DecodedAttestation,
    /// Owned copy of decompressed SSZ bytes for BLS signature verification.
    ssz_bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *QueuedAttestation) void {
        self.allocator.free(self.ssz_bytes);
        self.allocator.destroy(self);
    }
};

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
    peer_id: u64 = 0,
    message_id: MessageId = std.mem.zeroes(MessageId),
    seen_timestamp_ns: i64 = 0,
};

pub const GossipHandler = struct {
    allocator: Allocator,

    /// Type-erased *BeaconNode.
    node: *anyopaque,

    /// Called to run full STFN + chain import on a validated block.
    /// Receives raw SSZ bytes (decompressed, not Snappy-wrapped).
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    /// Called to import a validated attestation into fork choice + pool.
    /// Null until wired by BeaconNode (attestation import is optional during early bringup).
    importAttestationFn: ?*const fn (
        ptr: *anyopaque,
        attestation_slot: u64,
        committee_index: u64,
        target_root: [32]u8,
        target_epoch: u64,
        validator_index: u64,
        beacon_block_root: [32]u8,
        source_epoch: u64,
        source_root: [32]u8,
    ) anyerror!void,

    /// Called to import a validated voluntary exit into the op pool.
    importVoluntaryExitFn: ?*const fn (ptr: *anyopaque, validator_index: u64, epoch: u64) anyerror!void,

    /// Called to import raw proposer slashing SSZ bytes into the op pool.
    importProposerSlashingFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import raw attester slashing SSZ bytes into the op pool.
    importAttesterSlashingFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import raw BLS-to-execution change SSZ bytes into the op pool.
    importBlsChangeFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import a validated blob sidecar into the chain DA ingress.
    importBlobSidecarFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import a validated data column sidecar into the chain DA ingress.
    importDataColumnSidecarFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    // ── BLS signature verification callbacks ────────────────────────────
    // These are called between Phase 1 (cheap checks) and Phase 2 (import).
    // Each receives the raw decompressed SSZ bytes and returns true if the
    // signature(s) are valid. The BeaconNode implementation constructs
    // appropriate signature sets using its state caches.
    //
    // When null, signature verification is skipped (unsafe — for testing only).

    /// Verify block proposer BLS signature. Returns true if valid.
    verifyBlockSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify voluntary exit BLS signature. Returns true if valid.
    verifyVoluntaryExitSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify proposer slashing BLS signatures (both headers). Returns true if valid.
    verifyProposerSlashingSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify attester slashing BLS signatures (both indexed attestations). Returns true if valid.
    verifyAttesterSlashingSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify BLS-to-execution change signature. Returns true if valid.
    verifyBlsChangeSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify attestation BLS signature. Returns true if valid.
    verifyAttestationSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify aggregate and proof BLS signatures (selection proof + aggregator + aggregate). Returns true if valid.
    verifyAggregateSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Verify sync committee message BLS signature. Returns true if valid.
    verifySyncCommitteeSignatureFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) bool,

    /// Called to import a validated sync committee contribution into the pool.
    /// Receives raw decompressed SSZ bytes.
    importSyncContributionFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void,

    /// Called to import a validated sync committee message into the pool.
    /// Args: (ptr, subnet, slot, beacon_block_root, validator_index, signature_bytes)
    importSyncCommitteeMessageFn: ?*const fn (ptr: *anyopaque, ssz_bytes: []const u8, subnet: u64) anyerror!void,

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
    getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
    isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
    getValidatorCount: *const fn (ptr: *anyopaque) u32,

    /// Optional metrics pointer — records gossip accept/reject/ignore counts.
    metrics: ?*BeaconMetrics = null,

    /// Optional BeaconProcessor for enqueue-based processing.
    /// When set, Phase 2 work (import, chain validation) is enqueued
    /// into priority queues instead of executing inline.
    /// When null, falls back to inline processing (tests, early init).
    beacon_processor: ?*BeaconProcessor = null,

    /// Allocate a GossipHandler on the heap and initialise owned SeenCache.
    pub fn create(
        allocator: Allocator,
        node: *anyopaque,
        importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,
        getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
        isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
        getValidatorCount: *const fn (ptr: *anyopaque) u32,
    ) !*GossipHandler {
        const self = try allocator.create(GossipHandler);
        self.* = .{
            .allocator = allocator,
            .node = node,
            .importBlockFn = importBlockFn,
            .importAttestationFn = null,
            .importVoluntaryExitFn = null,
            .importProposerSlashingFn = null,
            .importAttesterSlashingFn = null,
            .importBlsChangeFn = null,
            .importBlobSidecarFn = null,
            .importDataColumnSidecarFn = null,
            .verifyBlockSignatureFn = null,
            .verifyVoluntaryExitSignatureFn = null,
            .verifyProposerSlashingSignatureFn = null,
            .verifyAttesterSlashingSignatureFn = null,
            .verifyBlsChangeSignatureFn = null,
            .verifyAttestationSignatureFn = null,
            .verifyAggregateSignatureFn = null,
            .verifySyncCommitteeSignatureFn = null,
            .importSyncContributionFn = null,
            .importSyncCommitteeMessageFn = null,
            .seen_cache = SeenCache.init(allocator),
            .current_slot = 0,
            .current_epoch = 0,
            .finalized_slot = 0,
            .current_fork_seq = .phase0,
            .getProposerIndex = getProposerIndex,
            .isKnownBlockRoot = isKnownBlockRoot,
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

    /// Called when a gossip message arrives on the beacon_block topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/proposer/parent_root
    /// 2. Phase 1: fast validation (< 1 ms)
    /// 3. Phase 2: queue full import as a work item
    pub fn onBeaconBlock(self: *GossipHandler, message_data: []const u8) !void {
        return self.onBeaconBlockWithMetadata(message_data, .{});
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
        const action = chain_gossip.validateGossipBlock(
            blk.slot,
            blk.proposer_index,
            blk.parent_root,
            block_root,
            &chain_state,
        );
        try checkAction(action);

        // Phase 1c: BLS signature verification (expensive but required before ACCEPT).
        // [REJECT] The proposer signature is valid.
        if (self.verifyBlockSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip block rejected: invalid proposer signature slot={d}", .{blk.slot});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: Full import (STFN + fork choice).
        if (self.beacon_processor) |bp| {
            const any_signed = AnySignedBeaconBlock.deserialize(
                self.allocator,
                .full,
                self.current_fork_seq,
                ssz_bytes,
            ) catch return GossipHandlerError.DecodeFailed;
            bp.ingest(.{ .gossip_block = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .block = any_signed,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        try self.importBlockFn(self.node, ssz_bytes);
    }

    /// Called when a gossip attestation arrives on a `beacon_attestation_{subnet}` topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/committee/target/attester
    /// 2. Phase 1: fast validation (< 1 ms) — slot range, committee bounds, dedup
    /// 3. Phase 2: import to fork choice + attestation pool
    pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onAttestationWithMetadata(subnet_id, message_data, .{});
    }

    fn onAttestationWithMetadata(
        self: *GossipHandler,
        subnet_id: u64,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // TODO: Validate attestation is on the correct subnet.
        // Spec: compute_subnet_for_attestation(committees_per_slot, slot, committee_index) == subnet_id
        // Requires epoch cache access (committee count per slot) — needs a callback or state query.
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_ATTESTATION) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_attestation, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const att = decoded.beacon_attestation;

        // Phase 1b: Fast validation.
        var chain_state = self.makeChainState();
        const action = chain_gossip.validateGossipAttestation(
            att.slot,
            att.committee_index,
            att.target_epoch,
            att.target_root,
            &chain_state,
        );
        try checkAction(action);

        // Phase 2: Import to fork choice + attestation pool.
        // When processor is available, defer BLS to batch verification.
        // Attestations are LIFO-queued and batched for efficient BLS verification.
        if (self.beacon_processor) |bp| {
            // Allocate owned copy of decoded attestation + SSZ bytes for the processor.
            const queued = self.allocator.create(QueuedAttestation) catch return;
            const ssz_copy = self.allocator.dupe(u8, ssz_bytes) catch {
                self.allocator.destroy(queued);
                return;
            };
            queued.* = .{
                .att = att,
                .ssz_bytes = ssz_copy,
                .allocator = self.allocator,
            };
            bp.ingest(.{ .attestation = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = GossipDataHandle.initOwned(QueuedAttestation, queued),
                .subnet_id = @intCast(subnet_id),
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Phase 1c: BLS signature verification (only for inline processing path).
        // [REJECT] The attestation signature is valid.
        if (self.verifyAttestationSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip attestation rejected: invalid signature slot={d}", .{att.slot});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Fallback: inline processing.
        if (self.importAttestationFn) |importFn| {
            importFn(
                self.node,
                att.slot,
                att.committee_index,
                att.target_root,
                att.target_epoch,
                att.attester_index,
                att.beacon_block_root,
                att.source_epoch,
                att.source_root,
            ) catch |err| {
                std.log.warn("Attestation import failed for slot {d}: {}", .{ att.slot, err });
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
        return self.onAggregateAndProofWithMetadata(message_data, .{});
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

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_aggregate_and_proof, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const agg = decoded.beacon_aggregate_and_proof;

        // Phase 1b: Fast validation.
        var chain_state = self.makeChainState();
        const action = chain_gossip.validateGossipAggregate(
            agg.aggregator_index,
            agg.attestation_slot,
            agg.attestation_target_epoch,
            agg.aggregation_bits_count,
            &chain_state,
        );
        try checkAction(action);

        // Phase 1c: BLS signature verification.
        // [REJECT] selection_proof, aggregator signature, and aggregate signature are all valid.
        if (self.verifyAggregateSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip aggregate rejected: invalid signature aggregator={d}", .{agg.aggregator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: Import aggregate to fork choice + attestation pool.
        // When processor is available, enqueue for priority-ordered batch processing.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .aggregate = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline logging (no full import yet).
        std.log.info("Accepted aggregate: aggregator={d} slot={d} target_epoch={d}", .{
            agg.aggregator_index,
            agg.attestation_slot,
            agg.attestation_target_epoch,
        });
    }

    /// Called when a voluntary_exit gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract validator index and exit epoch
    /// 2. Phase 1: basic bounds check (validator index within set)
    /// 3. Phase 2: import to op pool
    pub fn onVoluntaryExit(self: *GossipHandler, message_data: []const u8) !void {
        return self.onVoluntaryExitWithMetadata(message_data, .{});
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
                std.log.warn("Gossip voluntary exit rejected: invalid signature validator={d}", .{exit.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import to op pool.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_voluntary_exit = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importVoluntaryExitFn) |importFn| {
            importFn(self.node, exit.validator_index, exit.exit_epoch) catch |err| {
                std.log.warn("Voluntary exit import failed for validator {d}: {}", .{ exit.validator_index, err });
            };
        }

        std.log.info("Accepted voluntary_exit: validator={d} epoch={d}", .{
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
        return self.onProposerSlashingWithMetadata(message_data, .{});
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
                std.log.warn("Gossip proposer slashing rejected: invalid signature proposer={d}", .{ps.proposer_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes to op pool.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_proposer_slashing = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importProposerSlashingFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("Proposer slashing import failed for proposer {d}: {}", .{ ps.proposer_index, err });
            };
        }

        std.log.info("Accepted proposer_slashing: proposer={d} slot={d}", .{
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
        return self.onAttesterSlashingWithMetadata(message_data, .{});
    }

    fn onAttesterSlashingWithMetadata(
        self: *GossipHandler,
        message_data: []const u8,
        metadata: GossipIngressMetadata,
    ) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data, gossip_decoding.MAX_GOSSIP_SIZE_DEFAULT) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .attester_slashing, ssz_bytes, self.current_fork_seq) catch
            return GossipHandlerError.DecodeFailed;
        const as = decoded.attester_slashing;

        // Phase 1: fast validation via chain gossip validation layer.
        // Compute a dedup key from SSZ bytes (use first 32 bytes of snappy-free data as root).
        var slashing_root: [32]u8 = std.mem.zeroes([32]u8);
        const key_len = @min(ssz_bytes.len, 32);
        @memcpy(slashing_root[0..key_len], ssz_bytes[0..key_len]);
        var chain_state_as = self.makeChainState();
        const action_as = chain_gossip.validateGossipAttesterSlashing(
            as.is_slashable,
            slashing_root,
            &chain_state_as,
        );
        try checkAction(action_as);

        // Phase 1c: BLS signature verification.
        // [REJECT] Both indexed attestation signatures are valid.
        if (self.verifyAttesterSlashingSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip attester slashing rejected: invalid signature", .{});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_attester_slashing = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importAttesterSlashingFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("Attester slashing import failed: {}", .{err});
            };
        }

        std.log.info("Accepted attester_slashing", .{});
    }

    /// Called when a bls_to_execution_change gossip message arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract validator index
    /// 2. Phase 1: validator index must be within known set
    /// 3. Phase 2: import to op pool
    pub fn onBlsToExecutionChange(self: *GossipHandler, message_data: []const u8) !void {
        return self.onBlsToExecutionChangeWithMetadata(message_data, .{});
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
                std.log.warn("Gossip BLS change rejected: invalid signature validator={d}", .{change.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes to op pool.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_bls_to_exec = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importBlsChangeFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("BLS change import failed for validator {d}: {}", .{ change.validator_index, err });
            };
        }

        std.log.info("Accepted bls_to_execution_change: validator={d}", .{
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
        return self.onSyncCommitteeContributionWithMetadata(message_data, .{});
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

        // Phase 2: import to sync contribution pool.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .sync_contribution = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .slot = contrib.contribution_slot,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importSyncContributionFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("Sync contribution import failed: {}", .{err});
            };
        }

        std.log.info("Accepted sync_committee_contribution_and_proof: aggregator={d} slot={d} subcommittee={d}", .{
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
    /// 3. Phase 2: log acceptance (no sync committee message pool yet)
    pub fn onSyncCommitteeMessage(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        return self.onSyncCommitteeMessageWithMetadata(subnet_id, message_data, .{});
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

        // Phase 1c: BLS signature verification.
        // [REJECT] The sync committee message signature is valid.
        if (self.verifySyncCommitteeSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip sync committee message rejected: invalid signature validator={d}", .{msg.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import to sync committee message pool.
        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .sync_message = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .slot = msg.slot,
                .subnet_id = @intCast(subnet_id),
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Fallback: inline processing.
        if (self.importSyncCommitteeMessageFn) |importFn| {
            importFn(self.node, ssz_bytes, subnet_id) catch |err| {
                std.log.warn("Sync committee message import failed: {}", .{err});
            };
        }

        std.log.info("Accepted sync_committee message: validator={d} slot={d} subnet={d}", .{
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
        return self.onBlobSidecarWithMetadata(subnet_id, message_data, .{});
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
            blob.block_parent_root,
            &chain_state_blob,
        );
        try checkAction(action_blob);

        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_blob = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        // Phase 2: hand off to chain DA ingress.
        if (self.importBlobSidecarFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("Blob sidecar import failed: {}", .{err});
            };
        }

        std.log.info("Accepted blob_sidecar: index={d} slot={d} proposer={d} ({d} bytes)", .{
            blob.index,
            blob.slot,
            blob.proposer_index,
            ssz_bytes.len,
        });
    }

    pub fn onDataColumnSidecar(self: *GossipHandler, message_data: []const u8) !void {
        return self.onDataColumnSidecarWithMetadata(message_data, .{});
    }

    fn onDataColumnSidecarWithMetadata(
        self: *GossipHandler,
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

        if (self.beacon_processor) |bp| {
            const queued = self.dupeQueuedSszBytes(ssz_bytes) orelse return;
            bp.ingest(.{ .gossip_data_column = .{
                .peer_id = metadata.peer_id,
                .message_id = metadata.message_id,
                .data = queued,
                .seen_timestamp_ns = metadata.seen_timestamp_ns,
            } });
            return;
        }

        if (self.importDataColumnSidecarFn) |importFn| {
            importFn(self.node, ssz_bytes) catch |err| {
                std.log.warn("Data column sidecar import failed: {}", .{err});
            };
        }

        std.log.info("Accepted data_column_sidecar: index={d} slot={d} proposer={d}", .{
            sidecar.index,
            sidecar.slot,
            sidecar.proposer_index,
        });
    }

    fn recordProcessResult(self: *GossipHandler, result: GossipProcessResult) GossipProcessResult {
        switch (result) {
            .accepted => if (self.metrics) |m| m.gossip_messages_validated.incr(),
            .ignored => if (self.metrics) |m| m.gossip_messages_ignored.incr(),
            .rejected, .decode_failed => if (self.metrics) |m| m.gossip_messages_rejected.incr(),
            .failed => {},
        }
        return result;
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
        if (self.metrics) |m| m.gossip_messages_received.incr();

        self.onGossipMessageWithSubnetAndMetadata(topic, subnet_id, data, metadata) catch |err| {
            return self.recordProcessResult(switch (err) {
                GossipHandlerError.ValidationIgnored => .ignored,
                GossipHandlerError.ValidationRejected => .rejected,
                GossipHandlerError.DecodeFailed => .decode_failed,
                else => .{ .failed = err },
            });
        };

        return self.recordProcessResult(.accepted);
    }

    /// Route a gossip message by topic type.
    pub fn onGossipMessage(self: *GossipHandler, topic: GossipTopicType, data: []const u8) !void {
        switch (self.processGossipMessage(topic, data)) {
            .accepted => {},
            .ignored => return GossipHandlerError.ValidationIgnored,
            .rejected => return GossipHandlerError.ValidationRejected,
            .decode_failed => return GossipHandlerError.DecodeFailed,
            .failed => |err| return err,
        }
    }

    /// Route a gossip message by topic type, with optional subnet_id for subnet-indexed topics.
    pub fn onGossipMessageWithSubnet(self: *GossipHandler, topic: GossipTopicType, subnet_id: ?u8, data: []const u8) !void {
        switch (self.processGossipMessageWithSubnetAndMetadata(topic, subnet_id, data, .{})) {
            .accepted => {},
            .ignored => return GossipHandlerError.ValidationIgnored,
            .rejected => return GossipHandlerError.ValidationRejected,
            .decode_failed => return GossipHandlerError.DecodeFailed,
            .failed => |err| return err,
        }
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
            .data_column_sidecar => try self.onDataColumnSidecarWithMetadata(data, metadata),
        }
    }
};

// ============================================================
// Tests
// ============================================================

const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;

// --- Test stubs ---

var g_imported_count: u32 = 0;

fn stubImportBlock(_: *anyopaque, _: []const u8) anyerror!void {
    g_imported_count += 1;
}

fn stubGetProposerIndex(_: *anyopaque, slot: u64) ?u32 {
    return @intCast(slot % 100);
}

fn stubIsKnownBlockRoot(_: *anyopaque, _: [32]u8) bool {
    return true; // all parents known
}

fn stubGetValidatorCount(_: *anyopaque) u32 {
    return 1000;
}

fn makeTestHandler(allocator: Allocator) !*GossipHandler {
    var dummy_node: u8 = 0;
    return GossipHandler.create(
        allocator,
        @ptrCast(&dummy_node),
        &stubImportBlock,
        &stubGetProposerIndex,
        &stubIsKnownBlockRoot,
        &stubGetValidatorCount,
    );
}

fn makeSnappyBlock(allocator: Allocator, slot: u64, proposer: u64) ![]u8 {
    const snappy = @import("snappy").frame;
    var block: phase0.SignedBeaconBlock.Type = phase0.SignedBeaconBlock.default_value;
    block.message.slot = slot;
    block.message.proposer_index = proposer;
    block.message.parent_root = [_]u8{0xAA} ** 32;

    const ssz_size = phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_buf = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_buf);
    _ = phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_buf);

    return snappy.compress(allocator, ssz_buf);
}

test "GossipHandler: onBeaconBlock imports valid block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(10, 0, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    try handler.onBeaconBlock(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: onBeaconBlock ignores duplicate block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(10, 0, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    try handler.onBeaconBlock(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: onBeaconBlock ignores future slot" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(5, 0, 0);

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onBeaconBlock ignores finalized block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(30, 0, 20);

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onAttestation decodes and validates" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra); // SingleAttestation format requires Electra+

    // Create a valid SingleAttestation, serialize, compress.
    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.committee_index = 0;
    att.attester_index = 5;
    att.data.slot = 96;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32; // known root (mock returns true)
    att.data.beacon_block_root = [_]u8{0xBB} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    // Should pass validation (epoch 3 is current).
    try handler.onAttestation(0, compressed);
}

test "GossipHandler: onAttestation rejects stale epoch" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra); // SingleAttestation format requires Electra+

    // Attestation from epoch 0 — outside current/previous window.
    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.data.slot = 5;
    att.data.target.epoch = 0;
    att.data.target.root = [_]u8{0xAA} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.onAttestation(0, compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onGossipMessage routes beacon_block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(42, 1, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 42, 42);
    defer alloc.free(compressed);

    try handler.onGossipMessage(.beacon_block, compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: decode failures are returned as errors" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    // Sending invalid data (not valid snappy) should return DecodeFailed
    // for topics that now have real handlers.
    const dummy = [_]u8{ 0, 1, 2, 3 };
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.voluntary_exit, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.proposer_slashing, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.attester_slashing, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.bls_to_execution_change, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.blob_sidecar, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.data_column_sidecar, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.sync_committee, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.sync_committee_contribution_and_proof, null, &dummy));
}

test "GossipHandler: onAggregateAndProof validates and accepts" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    // Create a valid SignedAggregateAndProof.
    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    // Need at least 1 set bit for aggregation_bits.
    // Default aggregation_bits is empty — allocate a single byte with bit 0 set.
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try snappy.compress(alloc, ssz_buf);
    defer alloc.free(compressed);

    try handler.onAggregateAndProof(compressed);
}
