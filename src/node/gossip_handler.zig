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
const decodeGossipMessage = networking.decodeGossipMessage;
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
    ) anyerror!void,

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
        // Phase 1a: Decompress + decode.
        const decoded = decodeGossipMessage(self.allocator, .beacon_block, message_data) catch
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

        // Phase 2: Full import (STFN + fork choice).
        // TODO: Replace direct call with WorkItem queue push.
        // The block should be enqueued as a WorkItem{ .gossip_block = ssz_bytes }
        // for the processor thread pool. For now, call import directly.
        const snappy = @import("networking").gossip_decoding;
        const ssz_bytes = snappy.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        try self.importBlockFn(self.node, ssz_bytes);
    }

    /// Called when a gossip attestation arrives on a `beacon_attestation_{subnet}` topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress + SSZ decode → extract slot/committee/target/attester
    /// 2. Phase 1: fast validation (< 1 ms) — slot range, committee bounds, dedup
    /// 3. Phase 2: import to fork choice + attestation pool
    pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        _ = subnet_id;

        // Phase 1a: Decompress + decode.
        const decoded = decodeGossipMessage(self.allocator, .beacon_attestation, message_data) catch
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
        // Phase 1a: Decompress + decode.
        const decoded = decodeGossipMessage(self.allocator, .beacon_aggregate_and_proof, message_data) catch
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

        // Phase 2: log acceptance.
        // TODO: Full import — extract attestation from aggregate, convert to
        // phase0.Attestation, call importAttestationFn. For now, we validate
        // and accept for gossipsub scoring but skip pool insertion since we
        // don't have the full Attestation struct from the decoded fields.
        std.log.info("Accepted aggregate: aggregator={d} slot={d} target_epoch={d}", .{
            agg.aggregator_index,
            agg.attestation_slot,
            agg.attestation_target_epoch,
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
            .voluntary_exit => {}, // TODO: Phase 1 validate + queue WorkItem
            .proposer_slashing => {}, // TODO: Phase 1 validate + queue WorkItem
            .attester_slashing => {}, // TODO: Phase 1 validate + queue WorkItem
            .bls_to_execution_change => {}, // TODO: Phase 1 validate + queue WorkItem
            else => {},
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

test "GossipHandler: onGossipMessage no-ops for unsupported topics" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    const dummy = [_]u8{ 0, 1, 2, 3 };
    try handler.onGossipMessage(.voluntary_exit, &dummy);
    try handler.onGossipMessage(.proposer_slashing, &dummy);
    try handler.onGossipMessage(.attester_slashing, &dummy);
    try handler.onGossipMessage(.bls_to_execution_change, &dummy);
    try handler.onGossipMessage(.blob_sidecar, &dummy);
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
