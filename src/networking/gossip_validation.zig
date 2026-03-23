//! Gossip message validation for the Ethereum consensus P2P protocol.
//!
//! Implements per-topic validation rules as defined in the consensus spec:
//! https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
//!
//! Each gossip message must be validated before being accepted into the local mesh.
//! Validation returns Accept (propagate), Reject (penalize sender), or Ignore
//! (don't propagate but don't penalize).
//!
//! The validation functions are designed to be testable with mock contexts.
//! The actual beacon state access is abstracted through `GossipValidationContext`.

const std = @import("std");
const testing = std.testing;
const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;
const preset = @import("preset").preset;

/// Result of validating a gossip message.
///
/// These correspond to the libp2p gossipsub validation outcomes:
/// - `accept`: Valid message, propagate to mesh peers.
/// - `reject`: Invalid message, penalize the sender peer.
/// - `ignore`: Not invalid but don't propagate (e.g., already seen, not timely).
pub const ValidationResult = enum {
    accept,
    reject,
    ignore,
};

/// An opaque set for tracking already-seen items, keyed by a fixed-size byte array.
///
/// Uses a bounded hash map to avoid unbounded memory growth. When full, the oldest
/// entries should be evicted (the caller manages eviction policy).
pub const SeenSet = struct {
    const Key = [32]u8;
    const Map = std.AutoHashMap(Key, void);

    map: Map,

    pub fn init(allocator: std.mem.Allocator) SeenSet {
        return .{ .map = Map.init(allocator) };
    }

    pub fn deinit(self: *SeenSet) void {
        self.map.deinit();
    }

    /// Returns true if the key was already in the set.
    pub fn contains(self: *const SeenSet, key: Key) bool {
        return self.map.contains(key);
    }

    /// Insert a key. Returns true if the key was newly inserted (not already present).
    pub fn insert(self: *SeenSet, key: Key) !bool {
        const result = try self.map.getOrPut(key);
        return !result.found_existing;
    }
};

/// A key for deduplicating aggregate attestations: (aggregator_index, epoch).
pub fn aggregatorKey(aggregator_index: u64, epoch: u64) [32]u8 {
    var key: [32]u8 = std.mem.zeroes([32]u8);
    std.mem.writeInt(u64, key[0..8], aggregator_index, .little);
    std.mem.writeInt(u64, key[8..16], epoch, .little);
    // Domain separator to avoid collisions with other seen sets.
    key[16] = 0x01;
    return key;
}

/// A key for deduplicating voluntary exits: validator_index.
pub fn validatorKey(validator_index: u64) [32]u8 {
    var key: [32]u8 = std.mem.zeroes([32]u8);
    std.mem.writeInt(u64, key[0..8], validator_index, .little);
    key[16] = 0x02;
    return key;
}

/// A key for deduplicating proposer slashings: proposer_index.
pub fn proposerSlashingKey(proposer_index: u64) [32]u8 {
    var key: [32]u8 = std.mem.zeroes([32]u8);
    std.mem.writeInt(u64, key[0..8], proposer_index, .little);
    key[16] = 0x03;
    return key;
}

/// A key for deduplicating attester slashings.
/// Uses hash of the concatenated attestation indices.
pub fn attesterSlashingKey(indices: []const u64) [32]u8 {
    var hasher = std.hash.Wyhash.init(0x04);
    for (indices) |idx| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, idx, .little);
        hasher.update(&buf);
    }
    var key: [32]u8 = std.mem.zeroes([32]u8);
    const hash = hasher.final();
    std.mem.writeInt(u64, key[0..8], hash, .little);
    key[16] = 0x04;
    return key;
}

/// Context provided to validation functions by the beacon node.
///
/// This is a lightweight interface that abstracts the beacon state access.
/// The caller provides function pointers for state queries. This allows
/// validation functions to be tested with mock implementations.
pub const GossipValidationContext = struct {
    /// Current slot from the node's clock.
    current_slot: u64,
    /// Current epoch derived from current_slot.
    current_epoch: u64,
    /// Finalized slot (start slot of the finalized epoch).
    finalized_slot: u64,

    /// Set of already-seen block roots (for block dedup).
    seen_block_roots: *SeenSet,
    /// Set of already-seen aggregator keys (for aggregate dedup).
    seen_aggregators: *SeenSet,
    /// Set of already-seen voluntary exit validator indices.
    seen_voluntary_exits: *SeenSet,
    /// Set of already-seen proposer slashing proposer indices.
    seen_proposer_slashings: *SeenSet,
    /// Set of already-seen attester slashing keys.
    seen_attester_slashings: *SeenSet,

    /// Returns the expected proposer index for a given slot, or null if unknown.
    getProposerIndex: *const fn (slot: u64) ?u32,
    /// Returns whether a block root is known (has been seen as a parent).
    isKnownBlockRoot: *const fn (root: [32]u8) bool,
    /// Returns whether a validator is active at the given epoch.
    isValidatorActive: *const fn (validator_index: u64, epoch: u64) bool,
    /// Returns the total validator count (for bounds checking).
    getValidatorCount: *const fn () u32,
};

// ============================================================
// Per-topic validation functions
// ============================================================

/// Validate a `SignedBeaconBlock` received on the `beacon_block` gossip topic.
///
/// Reference: consensus-specs/specs/phase0/p2p-interface.md#beacon_block
///
/// This performs the subset of validations that don't require full signature
/// verification (which is deferred to a later stage).
pub fn validateBeaconBlock(
    block_slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    ctx: *GossipValidationContext,
) ValidationResult {
    // [IGNORE] The block is not from a future slot.
    // Allow current_slot + 1 with MAXIMUM_GOSSIP_CLOCK_DISPARITY tolerance,
    // but reject anything beyond that.
    if (block_slot > ctx.current_slot + 1) return .ignore;

    // [IGNORE] The block is from a slot greater than the latest finalized slot.
    if (block_slot <= ctx.finalized_slot) return .ignore;

    // [IGNORE] The block is the first block with valid signature received for the proposer for the slot.
    const was_new = ctx.seen_block_roots.insert(block_root) catch return .ignore;
    if (!was_new) return .ignore;

    // [REJECT] The proposer_index is valid (within known validator set).
    const validator_count = ctx.getValidatorCount();
    if (proposer_index >= validator_count) return .reject;

    // [REJECT] The block is proposed by the expected proposer_index for the block's slot.
    if (ctx.getProposerIndex(block_slot)) |expected_proposer| {
        if (proposer_index != expected_proposer) return .reject;
    } else {
        // If we can't determine the expected proposer, we can't validate.
        // Per spec: IGNORE rather than REJECT when proposer check is inconclusive.
        return .ignore;
    }

    // [IGNORE] The block's parent has been seen.
    if (!ctx.isKnownBlockRoot(parent_root)) return .ignore;

    return .accept;
}

/// Validate a `SignedAggregateAndProof` received on the `beacon_aggregate_and_proof` topic.
///
/// Reference: consensus-specs/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
pub fn validateAggregateAndProof(
    aggregator_index: u64,
    attestation_slot: u64,
    attestation_target_epoch: u64,
    aggregation_bits_count: u64,
    ctx: *GossipValidationContext,
) ValidationResult {
    // [REJECT] The aggregator_index is valid.
    const validator_count = ctx.getValidatorCount();
    if (aggregator_index >= validator_count) return .reject;

    // [REJECT] attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots.
    // The spec says: aggregate.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE
    // In practice this means current or previous epoch.
    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;
    if (attestation_epoch != ctx.current_epoch and
        (ctx.current_epoch == 0 or attestation_epoch != ctx.current_epoch - 1))
    {
        return .reject;
    }

    // [REJECT] The aggregate attestation's epoch matches its target.
    if (attestation_epoch != attestation_target_epoch) return .reject;

    // [REJECT] The aggregate attestation has participants.
    if (aggregation_bits_count == 0) return .reject;

    // [IGNORE] The (aggregator_index, epoch) pair has not been seen before.
    const key = aggregatorKey(aggregator_index, attestation_epoch);
    const was_new = ctx.seen_aggregators.insert(key) catch return .ignore;
    if (!was_new) return .ignore;

    return .accept;
}

/// Validate a `SignedVoluntaryExit` received on the `voluntary_exit` topic.
///
/// Reference: consensus-specs/specs/phase0/p2p-interface.md#voluntary_exit
pub fn validateVoluntaryExit(
    validator_index: u64,
    exit_epoch: u64,
    ctx: *GossipValidationContext,
) ValidationResult {
    // [REJECT] The validator_index is valid.
    const validator_count = ctx.getValidatorCount();
    if (validator_index >= validator_count) return .reject;

    // [IGNORE] The voluntary exit is the first valid exit for this validator.
    const key = validatorKey(validator_index);
    const was_new = ctx.seen_voluntary_exits.insert(key) catch return .ignore;
    if (!was_new) return .ignore;

    // [REJECT] The validator is active at the current epoch.
    if (!ctx.isValidatorActive(validator_index, ctx.current_epoch)) return .reject;

    // [REJECT] The exit epoch is not in the future.
    // (The exit should be processable now or in the past.)
    if (exit_epoch > ctx.current_epoch) return .reject;

    return .accept;
}

/// Validate a `ProposerSlashing` received on the `proposer_slashing` topic.
///
/// Reference: consensus-specs/specs/phase0/p2p-interface.md#proposer_slashing
pub fn validateProposerSlashing(
    proposer_index: u64,
    header_1_slot: u64,
    header_2_slot: u64,
    header_1_root: [32]u8,
    header_2_root: [32]u8,
    ctx: *GossipValidationContext,
) ValidationResult {
    // [REJECT] The proposer_index is valid.
    const validator_count = ctx.getValidatorCount();
    if (proposer_index >= validator_count) return .reject;

    // [IGNORE] The proposer slashing is the first one received for the proposer.
    const key = proposerSlashingKey(proposer_index);
    const was_new = ctx.seen_proposer_slashings.insert(key) catch return .ignore;
    if (!was_new) return .ignore;

    // [REJECT] The two headers must be for the same slot.
    if (header_1_slot != header_2_slot) return .reject;

    // [REJECT] The two headers must differ (same headers = not a slashable offence).
    if (std.mem.eql(u8, &header_1_root, &header_2_root)) return .reject;

    return .accept;
}

/// Validate an `AttesterSlashing` received on the `attester_slashing` topic.
///
/// Reference: consensus-specs/specs/phase0/p2p-interface.md#attester_slashing
pub fn validateAttesterSlashing(
    /// Intersection of attesting indices from both attestations.
    slashable_indices: []const u64,
    ctx: *GossipValidationContext,
) ValidationResult {
    // [REJECT] The attestations must have slashable indices.
    if (slashable_indices.len == 0) return .reject;

    // [IGNORE] At least one index in the intersection has not been seen in any prior attester slashing.
    const key = attesterSlashingKey(slashable_indices);
    const was_new = ctx.seen_attester_slashings.insert(key) catch return .ignore;
    if (!was_new) return .ignore;

    return .accept;
}

// ============================================================
// Tests
// ============================================================

// --- Mock context helpers ---

fn mockGetProposerIndex(slot: u64) ?u32 {
    // Slot 100 => proposer 5, everything else => proposer 0.
    if (slot == 100) return 5;
    return 0;
}

fn mockIsKnownBlockRoot(root: [32]u8) bool {
    // Treat the zero root as unknown, everything else as known.
    return !std.mem.eql(u8, &root, &([_]u8{0} ** 32));
}

fn mockIsValidatorActive(validator_index: u64, _: u64) bool {
    // Validator 999 is inactive, all others active.
    return validator_index != 999;
}

fn mockGetValidatorCount() u32 {
    return 1000;
}

fn createMockContext(allocator: std.mem.Allocator) !struct {
    ctx: GossipValidationContext,
    seen_blocks: SeenSet,
    seen_aggs: SeenSet,
    seen_exits: SeenSet,
    seen_proposer: SeenSet,
    seen_attester: SeenSet,
} {
    return .{
        .ctx = .{
            .current_slot = 100,
            .current_epoch = 3, // slot 100 / 32 = 3
            .finalized_slot = 64, // epoch 2
            .seen_block_roots = undefined, // Will be set below
            .seen_aggregators = undefined,
            .seen_voluntary_exits = undefined,
            .seen_proposer_slashings = undefined,
            .seen_attester_slashings = undefined,
            .getProposerIndex = &mockGetProposerIndex,
            .isKnownBlockRoot = &mockIsKnownBlockRoot,
            .isValidatorActive = &mockIsValidatorActive,
            .getValidatorCount = &mockGetValidatorCount,
        },
        .seen_blocks = SeenSet.init(allocator),
        .seen_aggs = SeenSet.init(allocator),
        .seen_exits = SeenSet.init(allocator),
        .seen_proposer = SeenSet.init(allocator),
        .seen_attester = SeenSet.init(allocator),
    };
}

test "beacon_block: accept valid block" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const parent_root = [_]u8{0xAA} ** 32;
    const block_root = [_]u8{0xBB} ** 32;

    const result = validateBeaconBlock(100, 5, parent_root, block_root, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, result);
}

test "beacon_block: ignore future slot" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateBeaconBlock(102, 5, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, result);
}

test "beacon_block: ignore finalized slot" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateBeaconBlock(64, 5, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, result);
}

test "beacon_block: ignore already seen" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const block_root = [_]u8{0xBB} ** 32;
    const parent_root = [_]u8{0xAA} ** 32;

    // First time: accept.
    const result1 = validateBeaconBlock(100, 5, parent_root, block_root, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, result1);

    // Second time: ignore (already seen).
    const result2 = validateBeaconBlock(100, 5, parent_root, block_root, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, result2);
}

test "beacon_block: reject wrong proposer" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Slot 100 expects proposer 5, but we send proposer 7.
    const result = validateBeaconBlock(100, 7, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "beacon_block: reject invalid proposer index" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Proposer index 1000 >= validator count (1000).
    const result = validateBeaconBlock(100, 1000, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "beacon_block: ignore unknown parent" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Zero root is "unknown" in our mock.
    const unknown_parent = [_]u8{0} ** 32;
    const result = validateBeaconBlock(100, 5, unknown_parent, [_]u8{0xCC} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, result);
}

test "aggregate_and_proof: accept valid aggregate" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Slot 96 = epoch 3 (current), 10 aggregation bits, target epoch 3.
    const result = validateAggregateAndProof(5, 96, 3, 10, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, result);
}

test "aggregate_and_proof: reject empty aggregation bits" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateAggregateAndProof(5, 96, 3, 0, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "aggregate_and_proof: reject wrong epoch" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Slot 32 = epoch 1, but current epoch is 3, and 1 != 3 and 1 != 2.
    const result = validateAggregateAndProof(5, 32, 1, 10, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "aggregate_and_proof: ignore duplicate" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const r1 = validateAggregateAndProof(5, 96, 3, 10, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, r1);

    const r2 = validateAggregateAndProof(5, 96, 3, 10, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, r2);
}

test "aggregate_and_proof: reject mismatched target epoch" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Slot 96 = epoch 3, but target_epoch says 2.
    const result = validateAggregateAndProof(5, 96, 2, 10, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "voluntary_exit: accept valid exit" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateVoluntaryExit(10, 3, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, result);
}

test "voluntary_exit: ignore duplicate" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const r1 = validateVoluntaryExit(10, 3, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, r1);

    const r2 = validateVoluntaryExit(10, 3, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, r2);
}

test "voluntary_exit: reject inactive validator" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Validator 999 is inactive in our mock.
    const result = validateVoluntaryExit(999, 3, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "voluntary_exit: reject future exit epoch" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    // Exit epoch 5 > current epoch 3.
    const result = validateVoluntaryExit(10, 5, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "proposer_slashing: accept valid slashing" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateProposerSlashing(
        5,
        100,
        100,
        [_]u8{0xAA} ** 32,
        [_]u8{0xBB} ** 32,
        &mock.ctx,
    );
    try testing.expectEqual(ValidationResult.accept, result);
}

test "proposer_slashing: reject different slots" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const result = validateProposerSlashing(
        5,
        100,
        101,
        [_]u8{0xAA} ** 32,
        [_]u8{0xBB} ** 32,
        &mock.ctx,
    );
    try testing.expectEqual(ValidationResult.reject, result);
}

test "proposer_slashing: reject same headers" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const same_root = [_]u8{0xAA} ** 32;
    const result = validateProposerSlashing(5, 100, 100, same_root, same_root, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "proposer_slashing: ignore duplicate" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const r1 = validateProposerSlashing(5, 100, 100, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, r1);

    const r2 = validateProposerSlashing(5, 100, 100, [_]u8{0xCC} ** 32, [_]u8{0xDD} ** 32, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, r2);
}

test "attester_slashing: accept valid slashing" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const indices = [_]u64{ 1, 2, 3 };
    const result = validateAttesterSlashing(&indices, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, result);
}

test "attester_slashing: reject empty indices" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const indices = [_]u64{};
    const result = validateAttesterSlashing(&indices, &mock.ctx);
    try testing.expectEqual(ValidationResult.reject, result);
}

test "attester_slashing: ignore duplicate" {
    var mock = try createMockContext(testing.allocator);
    defer mock.seen_blocks.deinit();
    defer mock.seen_aggs.deinit();
    defer mock.seen_exits.deinit();
    defer mock.seen_proposer.deinit();
    defer mock.seen_attester.deinit();

    mock.ctx.seen_block_roots = &mock.seen_blocks;
    mock.ctx.seen_aggregators = &mock.seen_aggs;
    mock.ctx.seen_voluntary_exits = &mock.seen_exits;
    mock.ctx.seen_proposer_slashings = &mock.seen_proposer;
    mock.ctx.seen_attester_slashings = &mock.seen_attester;

    const indices = [_]u64{ 1, 2, 3 };
    const r1 = validateAttesterSlashing(&indices, &mock.ctx);
    try testing.expectEqual(ValidationResult.accept, r1);

    const r2 = validateAttesterSlashing(&indices, &mock.ctx);
    try testing.expectEqual(ValidationResult.ignore, r2);
}
