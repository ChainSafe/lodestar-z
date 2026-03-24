//! GossipHandler: routes incoming gossip messages through validate → decode → import.
//!
//! When a gossip message arrives via GossipSub, this module:
//! 1. Snappy-decompresses the payload
//! 2. SSZ-deserializes based on topic type
//! 3. Runs lightweight gossip validation (slot bounds, dedup, proposer checks)
//! 4. Dispatches to the appropriate pipeline (import for blocks, fork choice for attestations)
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
const gossip_validation = networking.gossip_validation;
const ValidationResult = networking.ValidationResult;
const GossipValidationContext = networking.GossipValidationContext;
const decodeGossipMessage = networking.decodeGossipMessage;
const DecodedGossipMessage = networking.DecodedGossipMessage;

/// Error set for gossip processing failures.
pub const GossipHandlerError = error{
    /// Gossip validation returned Ignore — message silently dropped.
    ValidationIgnored,
    /// Gossip validation returned Reject — peer should be penalized.
    ValidationRejected,
    /// Decode failed (bad snappy or SSZ).
    DecodeFailed,
};

/// Handles incoming gossip messages and routes them to the right pipeline.
///
/// Lifecycle:
/// 1. `init` — allocate and wire
/// 2. `onGossipMessage` (or specific `onBeaconBlock` / `onAttestation`)
/// 3. `deinit` — release validation SeenSets
pub const GossipHandler = struct {
    allocator: Allocator,

    /// Type-erased *BeaconNode.
    node: *anyopaque,

    /// Called to run full STFN + chain import on a validated block.
    /// Receives raw SSZ bytes (decompressed, not Snappy-wrapped).
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    /// Gossip validation SeenSets (owned).
    seen_blocks: gossip_validation.SeenSet,
    seen_aggregators: gossip_validation.SeenSet,
    seen_exits: gossip_validation.SeenSet,
    seen_proposer_slashings: gossip_validation.SeenSet,
    seen_attester_slashings: gossip_validation.SeenSet,

    /// Slot/epoch state for validation — caller must keep this current.
    current_slot: u64,
    current_epoch: u64,
    finalized_slot: u64,

    /// Vtable for state queries (proposer schedule, known roots, etc.).
    /// Wired from gossip_callbacks or a test stub.
    getProposerIndex: *const fn (slot: u64) ?u32,
    isKnownBlockRoot: *const fn (root: [32]u8) bool,
    isValidatorActive: *const fn (validator_index: u64, epoch: u64) bool,
    getValidatorCount: *const fn () u32,

    /// Allocate a GossipHandler on the heap and initialise owned SeenSets.
    ///
    /// The caller must call `deinit` to free both the SeenSets and the struct
    /// itself.
    pub fn create(
        allocator: Allocator,
        node: *anyopaque,
        importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,
        getProposerIndex: *const fn (slot: u64) ?u32,
        isKnownBlockRoot: *const fn (root: [32]u8) bool,
        isValidatorActive: *const fn (validator_index: u64, epoch: u64) bool,
        getValidatorCount: *const fn () u32,
    ) !*GossipHandler {
        const self = try allocator.create(GossipHandler);
        self.* = .{
            .allocator = allocator,
            .node = node,
            .importBlockFn = importBlockFn,
            .seen_blocks = gossip_validation.SeenSet.init(allocator),
            .seen_aggregators = gossip_validation.SeenSet.init(allocator),
            .seen_exits = gossip_validation.SeenSet.init(allocator),
            .seen_proposer_slashings = gossip_validation.SeenSet.init(allocator),
            .seen_attester_slashings = gossip_validation.SeenSet.init(allocator),
            .current_slot = 0,
            .current_epoch = 0,
            .finalized_slot = 0,
            .getProposerIndex = getProposerIndex,
            .isKnownBlockRoot = isKnownBlockRoot,
            .isValidatorActive = isValidatorActive,
            .getValidatorCount = getValidatorCount,
        };
        return self;
    }

    pub fn deinit(self: *GossipHandler) void {
        self.seen_blocks.deinit();
        self.seen_aggregators.deinit();
        self.seen_exits.deinit();
        self.seen_proposer_slashings.deinit();
        self.seen_attester_slashings.deinit();
        self.allocator.destroy(self);
    }

    /// Update clock state used for gossip validation.
    /// Call once per slot transition.
    pub fn updateClock(self: *GossipHandler, slot: u64, epoch: u64, finalized_slot: u64) void {
        self.current_slot = slot;
        self.current_epoch = epoch;
        self.finalized_slot = finalized_slot;
    }

    /// Build a temporary GossipValidationContext pointing at our SeenSets.
    fn makeCtx(self: *GossipHandler) GossipValidationContext {
        return .{
            .current_slot = self.current_slot,
            .current_epoch = self.current_epoch,
            .finalized_slot = self.finalized_slot,
            .seen_block_roots = &self.seen_blocks,
            .seen_aggregators = &self.seen_aggregators,
            .seen_voluntary_exits = &self.seen_exits,
            .seen_proposer_slashings = &self.seen_proposer_slashings,
            .seen_attester_slashings = &self.seen_attester_slashings,
            .getProposerIndex = self.getProposerIndex,
            .isKnownBlockRoot = self.isKnownBlockRoot,
            .isValidatorActive = self.isValidatorActive,
            .getValidatorCount = self.getValidatorCount,
        };
    }

    /// Called when a gossip message arrives on the beacon_block topic.
    ///
    /// Pipeline:
    /// 1. Snappy decompress
    /// 2. SSZ deserialize → extract slot/proposer/parent_root
    /// 3. Gossip validation (slot bounds, dedup, proposer check)
    /// 4. importBlockFn (full STFN + chain import)
    pub fn onBeaconBlock(self: *GossipHandler, message_data: []const u8) !void {
        // 1+2. Decompress + decode.
        const decoded = decodeGossipMessage(self.allocator, .beacon_block, message_data) catch
            return GossipHandlerError.DecodeFailed;
        const blk = decoded.beacon_block;

        // Compute a synthetic block root from slot + proposer for dedup purposes.
        // Full block root hashing is expensive; we use a cheap key here.
        // The actual HTR dedup happens inside importBlock if needed.
        var block_root: [32]u8 = std.mem.zeroes([32]u8);
        std.mem.writeInt(u64, block_root[0..8], blk.slot, .little);
        std.mem.writeInt(u64, block_root[8..16], blk.proposer_index, .little);
        // Mix in parent_root to distinguish equivocating blocks at the same slot.
        @memcpy(block_root[16..32], blk.parent_root[0..16]);

        // 3. Gossip validation.
        var ctx = self.makeCtx();
        const result = gossip_validation.validateBeaconBlock(
            blk.slot,
            blk.proposer_index,
            blk.parent_root,
            block_root,
            &ctx,
        );
        switch (result) {
            .accept => {},
            .ignore => return GossipHandlerError.ValidationIgnored,
            .reject => return GossipHandlerError.ValidationRejected,
        }

        // 4. Decompress again to get raw SSZ for importBlockFn.
        //    (decodeGossipMessage decompresses internally but doesn't expose bytes.)
        const snappy = @import("networking").gossip_decoding;
        const ssz_bytes = snappy.decompressGossipPayload(self.allocator, message_data) catch
            return GossipHandlerError.DecodeFailed;
        defer self.allocator.free(ssz_bytes);

        try self.importBlockFn(self.node, ssz_bytes);
    }

    /// Called when a gossip attestation arrives.
    ///
    /// Pipeline:
    /// 1. Snappy decompress
    /// 2. SSZ deserialize (stub — attestation decode not yet implemented)
    /// 3. Validate epoch/committee
    /// 4. Add to attestation pool / fork choice
    pub fn onAttestation(self: *GossipHandler, subnet_id: u64, message_data: []const u8) !void {
        // Attestation decoding is not yet supported by gossip_decoding.zig.
        // The beacon_attestation topic returns UnsupportedTopicType from decodeGossipMessage.
        // This stub acknowledges receipt without panicking, so the message pipeline
        // doesn't break when attestations arrive. Full implementation tracked separately.
        _ = self;
        _ = subnet_id;
        _ = message_data;
        // TODO: implement once gossip_decoding supports beacon_attestation
    }

    /// Route a gossip message by topic type.
    pub fn onGossipMessage(self: *GossipHandler, topic: GossipTopicType, data: []const u8) !void {
        switch (topic) {
            .beacon_block => try self.onBeaconBlock(data),
            .beacon_attestation => try self.onAttestation(0, data),
            .voluntary_exit => {}, // TODO: add to op pool
            .proposer_slashing => {}, // TODO: add to op pool
            .attester_slashing => {}, // TODO: add to op pool
            .bls_to_execution_change => {}, // TODO: add to op pool
            else => {},
        }
    }
};

// ============================================================
// Tests
// ============================================================

const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;
const snappy_frame = @import("networking").gossip_decoding;

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

fn stubIsValidatorActive(_: u64, _: u64) bool {
    return true;
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
        &stubIsValidatorActive,
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

    // Set clock so slot 10 is valid (proposer index = 10 % 100 = 10).
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

    // First: accepted and imported.
    try handler.onBeaconBlock(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);

    // Second: ignored (already in seen_blocks).
    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
    try testing.expectEqual(@as(u32, 1), g_imported_count); // no second import
}

test "GossipHandler: onBeaconBlock ignores future slot" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    // current_slot = 5, block slot = 10 → too far in the future.
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

    // finalized_slot = 20, block slot = 10 → already finalized.
    handler.updateClock(30, 0, 20);

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onAttestation is a no-op stub" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    // Attestation decoding not yet supported — should return without error.
    try handler.onAttestation(0, &[_]u8{ 0, 1, 2, 3 });
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
    // These should all return without error.
    try handler.onGossipMessage(.voluntary_exit, &dummy);
    try handler.onGossipMessage(.proposer_slashing, &dummy);
    try handler.onGossipMessage(.attester_slashing, &dummy);
    try handler.onGossipMessage(.bls_to_execution_change, &dummy);
    try handler.onGossipMessage(.blob_sidecar, &dummy);
}
