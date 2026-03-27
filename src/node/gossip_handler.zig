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
const GossipTopicType = networking.GossipTopicType;
const gossip_decoding = networking.gossip_decoding;
const DecodedGossipMessage = networking.DecodedGossipMessage;

const chain = @import("chain");
const SeenCache = chain.SeenCache;
const chain_gossip = chain.gossip_validation;
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

/// Handles incoming gossip messages with two-phase validation.
///
/// **Phase 1** (fast, < 1 ms): decode + lightweight checks → ACCEPT/REJECT/IGNORE.
/// **Phase 2** (slow, queued): full STFN, signature verification, fork choice.
///
/// Lifecycle:
/// 1. `create` — allocate and wire callbacks
/// 2. `onGossipMessage` (or topic-specific methods)
/// 3. `deinit` — release SeenCache and struct
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

    /// Vtable for state queries (proposer schedule, known roots, etc.).
    getProposerIndex: *const fn (slot: u64) ?u32,
    isKnownBlockRoot: *const fn (root: [32]u8) bool,
    getValidatorCount: *const fn () u32,

    /// Allocate a GossipHandler on the heap and initialise owned SeenCache.
    pub fn create(
        allocator: Allocator,
        node: *anyopaque,
        importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,
        getProposerIndex: *const fn (slot: u64) ?u32,
        isKnownBlockRoot: *const fn (root: [32]u8) bool,
        getValidatorCount: *const fn () u32,
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

    /// Build a ChainState snapshot for fast Phase 1 validation.
    fn makeChainState(self: *GossipHandler) ChainState {
        return .{
            .current_slot = self.current_slot,
            .current_epoch = self.current_epoch,
            .finalized_slot = self.finalized_slot,
            .seen_cache = &self.seen_cache,
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

    /// Called when a gossip message arrives on the beacon_block topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/proposer/parent_root
    /// 2. Phase 1: fast validation (< 1 ms)
    /// 3. Phase 2: queue full import as a work item
    pub fn onBeaconBlock(self: *GossipHandler, message_data: []const u8) !void {
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_block, ssz_bytes) catch
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
        // TODO: Replace direct call with WorkItem queue push.
        try self.importBlockFn(self.node, ssz_bytes);
    }

    /// Called when a gossip attestation arrives on a `beacon_attestation_{subnet}` topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/committee/target/attester
    /// 2. Phase 1: fast validation (< 1 ms) — slot range, committee bounds, dedup
    /// 3. Phase 2: import to fork choice + attestation pool
    pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        // TODO: Validate attestation is on the correct subnet.
        // Spec: compute_subnet_for_attestation(committees_per_slot, slot, committee_index) == subnet_id
        // Requires epoch cache access (committee count per slot) — needs a callback or state query.
        _ = subnet_id;

        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_attestation, ssz_bytes) catch
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

        // Phase 1c: BLS signature verification.
        // [REJECT] The attestation signature is valid.
        if (self.verifyAttestationSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip attestation rejected: invalid signature slot={d}", .{att.slot});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: Import to fork choice + attestation pool.
        // TODO: Replace direct call with WorkItem queue push.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .beacon_aggregate_and_proof, ssz_bytes) catch
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

        // Phase 2: log acceptance.
        // TODO: Full import — extract attestation from aggregate, convert to
        // phase0.Attestation, call importAttestationFn.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .voluntary_exit, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const exit = decoded.voluntary_exit;

        // Phase 1: basic validation — validator index must be within known set.
        const vc = self.getValidatorCount();
        if (exit.validator_index >= vc) return GossipHandlerError.ValidationRejected;

        // Phase 1: exit epoch must be <= current epoch (can't exit in the future).
        if (exit.exit_epoch > self.current_epoch) return GossipHandlerError.ValidationIgnored;

        // Phase 1c: BLS signature verification.
        // [REJECT] The voluntary exit signature is valid.
        if (self.verifyVoluntaryExitSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip voluntary exit rejected: invalid signature validator={d}", .{exit.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import to op pool.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .proposer_slashing, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const ps = decoded.proposer_slashing;

        // Phase 1: proposer must be within known validator set.
        const vc = self.getValidatorCount();
        if (ps.proposer_index >= vc) return GossipHandlerError.ValidationRejected;

        // Phase 1: headers must have the same slot (same proposer slot).
        if (ps.header_1_slot != ps.header_2_slot) return GossipHandlerError.ValidationRejected;

        // Phase 1: body roots must differ (different blocks for same slot = slashable).
        if (std.mem.eql(u8, &ps.header_1_body_root, &ps.header_2_body_root))
            return GossipHandlerError.ValidationRejected;

        // Phase 1c: BLS signature verification.
        // [REJECT] Both signed header signatures are valid.
        if (self.verifyProposerSlashingSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip proposer slashing rejected: invalid signature proposer={d}", .{ps.proposer_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes to op pool.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .attester_slashing, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const as = decoded.attester_slashing;

        // Phase 1: attestation data must be slashable.
        if (!as.is_slashable) return GossipHandlerError.ValidationRejected;

        // Phase 1c: BLS signature verification.
        // [REJECT] Both indexed attestation signatures are valid.
        if (self.verifyAttesterSlashingSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip attester slashing rejected: invalid signature", .{});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .bls_to_execution_change, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const change = decoded.bls_to_execution_change;

        // Phase 1: validator index must be within known set.
        const vc = self.getValidatorCount();
        if (change.validator_index >= vc) return GossipHandlerError.ValidationRejected;

        // Phase 1c: BLS signature verification.
        // [REJECT] The BLS-to-execution change signature is valid.
        if (self.verifyBlsChangeSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip BLS change rejected: invalid signature validator={d}", .{change.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import raw SSZ bytes to op pool.
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
        // Decompress once — reused for decode and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .sync_committee_contribution_and_proof, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const contrib = decoded.sync_committee_contribution_and_proof;

        // Phase 1: aggregator must be within known validator set.
        const vc = self.getValidatorCount();
        if (contrib.aggregator_index >= vc) return GossipHandlerError.ValidationRejected;

        // Phase 1: contribution slot must be within valid range.
        if (contrib.contribution_slot > self.current_slot + 1) return GossipHandlerError.ValidationIgnored;
        if (self.finalized_slot > 0 and contrib.contribution_slot < self.finalized_slot) return GossipHandlerError.ValidationIgnored;

        // Phase 2: import to sync contribution pool.
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
        // Decompress once — reused for decode, BLS verify, and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .sync_committee, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const msg = decoded.sync_committee;

        // Phase 1: validator must be within known set.
        const vc = self.getValidatorCount();
        if (msg.validator_index >= vc) return GossipHandlerError.ValidationRejected;

        // Phase 1: slot must be within valid range.
        if (msg.slot > self.current_slot + 1) return GossipHandlerError.ValidationIgnored;
        if (self.finalized_slot > 0 and msg.slot < self.finalized_slot) return GossipHandlerError.ValidationIgnored;

        // Phase 1c: BLS signature verification.
        // [REJECT] The sync committee message signature is valid.
        if (self.verifySyncCommitteeSignatureFn) |verifyFn| {
            if (!verifyFn(self.node, ssz_bytes)) {
                std.log.warn("Gossip sync committee message rejected: invalid signature validator={d}", .{msg.validator_index});
                return GossipHandlerError.ValidationRejected;
            }
        }

        // Phase 2: import to sync committee message pool.
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
        // Decompress once — reused for decode and import.
        const ssz_bytes = gossip_decoding.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        // Phase 1a: Decode from already-decompressed SSZ bytes.
        const decoded = gossip_decoding.decodeFromSszBytes(self.allocator, .blob_sidecar, ssz_bytes) catch
            return GossipHandlerError.DecodeFailed;
        const blob = decoded.blob_sidecar;

        // Phase 1: blob index must match subnet_id.
        if (blob.index != subnet_id) return GossipHandlerError.ValidationRejected;

        // Phase 1: slot must be within valid range.
        if (blob.slot > self.current_slot + 1) return GossipHandlerError.ValidationIgnored;
        if (self.finalized_slot > 0 and blob.slot < self.finalized_slot) return GossipHandlerError.ValidationIgnored;

        // Phase 1: proposer must be within known validator set.
        const vc = self.getValidatorCount();
        if (blob.proposer_index >= vc) return GossipHandlerError.ValidationRejected;

        // Compute block root from the signed block header in the sidecar.
        // For now, use a synthetic root from (slot, proposer, parent) like blocks.
        var block_root: [32]u8 = std.mem.zeroes([32]u8);
        std.mem.writeInt(u64, block_root[0..8], blob.slot, .little);
        std.mem.writeInt(u64, block_root[8..16], blob.proposer_index, .little);
        @memcpy(block_root[16..32], blob.block_parent_root[0..16]);

        // Import via the node (type-erased). We use importBlockFn's node pointer
        // to access importBlobSidecar. Since we can't call importBlobSidecar directly
        // through the type-erased pointer, we log and skip for now.
        // TODO: Add importBlobSidecarFn callback like importAttestationFn.
        std.log.info("Accepted blob_sidecar: index={d} slot={d} proposer={d} ({d} bytes)", .{
            blob.index,
            blob.slot,
            blob.proposer_index,
            ssz_bytes.len,
        });
    }

    /// Route a gossip message by topic type.
    pub fn onGossipMessage(self: *GossipHandler, topic: GossipTopicType, data: []const u8) !void {
        self.onGossipMessageWithSubnet(topic, null, data) catch |err| {
            switch (err) {
                GossipHandlerError.ValidationIgnored => {},
                else => return err,
            }
        };
    }

    /// Route a gossip message by topic type, with optional subnet_id for subnet-indexed topics.
    pub fn onGossipMessageWithSubnet(self: *GossipHandler, topic: GossipTopicType, subnet_id: ?u8, data: []const u8) !void {
        switch (topic) {
            .beacon_block => try self.onBeaconBlock(data),
            .beacon_attestation => try self.onAttestation(@as(u64, subnet_id orelse 0), data),
            .beacon_aggregate_and_proof => try self.onAggregateAndProof(data),
            .voluntary_exit => try self.onVoluntaryExit(data),
            .proposer_slashing => try self.onProposerSlashing(data),
            .attester_slashing => try self.onAttesterSlashing(data),
            .bls_to_execution_change => try self.onBlsToExecutionChange(data),
            .sync_committee_contribution_and_proof => try self.onSyncCommitteeContribution(data),
            .sync_committee => try self.onSyncCommitteeMessage(@as(u64, subnet_id orelse 0), data),
            .blob_sidecar => try self.onBlobSidecar(@as(u64, subnet_id orelse 0), data),
            .data_column_sidecar => {}, // Handled directly in BeaconNode.processGossipEventsFromSlice
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

fn stubGetProposerIndex(slot: u64) ?u32 {
    return @intCast(slot % 100);
}

fn stubIsKnownBlockRoot(_: [32]u8) bool {
    return true; // all parents known
}

fn stubGetValidatorCount() u32 {
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

test "GossipHandler: onGossipMessage no-ops for data_column_sidecar" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    // data_column_sidecar is the only topic that is a no-op in GossipHandler
    // (handled directly in BeaconNode.processGossipEventsFromSlice).
    const dummy = [_]u8{ 0, 1, 2, 3 };
    try handler.onGossipMessage(.data_column_sidecar, &dummy);
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
