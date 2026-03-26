//! Fast gossip validation — Phase 1 checks for gossipsub ACCEPT/REJECT/IGNORE.
//!
//! These functions run in the hot path of gossip message processing and must
//! complete in < 1 ms.  They perform only lightweight checks:
//!   - Slot range / timing
//!   - Proposer / committee index bounds
//!   - Parent known (block root lookup)
//!   - Duplicate detection (via SeenCache)
//!
//! Full validation (STFN, signature verification, DA checks, fork choice update)
//! is deferred to Phase 2 work items queued after ACCEPT.
//!
//! Reference:
//!   - consensus-specs/specs/phase0/p2p-interface.md
//!   - Lodestar chain/validation/block.ts
//!   - Lodestar chain/validation/attestation.ts

const std = @import("std");
const testing = std.testing;

const SeenCache = @import("seen_cache.zig").SeenCache;
const preset = @import("preset").preset;
const preset_root = @import("preset");

/// Outcome of Phase 1 gossip validation.
///
/// Maps directly to libp2p gossipsub validation results:
/// - `accept` — valid so far, propagate and queue Phase 2.
/// - `reject` — definitively invalid, penalize peer.
/// - `ignore` — not invalid but don't propagate (duplicate, not timely, unknown parent).
pub const GossipAction = enum {
    accept,
    reject,
    ignore,
};

/// Maximum number of slots a block can be in the future before we ignore it.
/// Accounts for MAXIMUM_GOSSIP_CLOCK_DISPARITY (500 ms ≈ 0–1 slots).
const MAX_FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Read-only chain state snapshot for fast gossip validation.
///
/// The caller provides this with current clock values and function pointers
/// for state queries that can be satisfied from caches (no disk I/O).
pub const ChainState = struct {
    /// Current wall-clock slot.
    current_slot: u64,
    /// Current epoch derived from current_slot.
    current_epoch: u64,
    /// Start slot of the finalized epoch.
    finalized_slot: u64,
    /// Mutable reference to the node's dedup caches.
    seen_cache: *SeenCache,

    /// Returns expected block proposer for `slot`, or null if cache miss.
    getProposerIndex: *const fn (slot: u64) ?u32,
    /// Returns true if `root` is a known block in our fork choice.
    isKnownBlockRoot: *const fn (root: [32]u8) bool,
    /// Returns the total validator count for bounds checking.
    getValidatorCount: *const fn () u32,
};

// ── Block validation ────────────────────────────────────────────────────────

/// Fast Phase 1 validation for a `SignedBeaconBlock` on the `beacon_block` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#beacon_block):
/// 1. [IGNORE] Block is not from a future slot (with clock disparity tolerance).
/// 2. [IGNORE] Block slot is greater than the finalized slot.
/// 3. [IGNORE] Block has not been seen before (dedup via SeenCache).
/// 4. [REJECT] Proposer index is within the known validator set.
/// 5. [REJECT] Proposer matches the expected proposer for the slot.
/// 6. [IGNORE] Parent block root is known.
pub fn validateGossipBlock(
    block_slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    // [IGNORE] Not from a future slot (tolerate current_slot + 1 for clock disparity).
    if (block_slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (block_slot <= state.finalized_slot) return .ignore;

    // [IGNORE] Not a duplicate — first block for this root.
    if (state.seen_cache.hasSeenBlock(block_root)) return .ignore;
    state.seen_cache.markBlockSeen(block_root, block_slot) catch return .ignore;

    // [REJECT] Proposer index within validator set bounds.
    const validator_count = state.getValidatorCount();
    if (proposer_index >= validator_count) return .reject;

    // [REJECT] Proposer matches expected for this slot.
    if (state.getProposerIndex(block_slot)) |expected| {
        if (proposer_index != expected) return .reject;
    } else {
        // Can't determine expected proposer — inconclusive, don't penalize.
        return .ignore;
    }

    // [IGNORE] Parent root is known in our fork choice.
    if (!state.isKnownBlockRoot(parent_root)) return .ignore;

    return .accept;
}

// ── Attestation validation ──────────────────────────────────────────────────

/// Fast Phase 1 validation for an attestation on a `beacon_attestation_{subnet}` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#beacon_attestation_subnet_id):
/// 1. [IGNORE] Attestation slot is within propagation range (current/previous epoch).
/// 2. [REJECT] Attestation epoch matches the target epoch.
/// 3. [REJECT] Committee index is within bounds.
/// 4. [IGNORE] Target block root is known (unknown → .ignore for reprocess queue).
pub fn validateGossipAttestation(
    attestation_slot: u64,
    committee_index: u64,
    target_epoch: u64,
    target_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;

    // [IGNORE] Attestation slot is within the propagation window (current or previous epoch).
    const in_current = attestation_epoch == state.current_epoch;
    const in_previous = state.current_epoch > 0 and attestation_epoch == state.current_epoch - 1;
    if (!in_current and !in_previous) return .ignore;

    // [REJECT] Attestation epoch must match the target epoch.
    if (attestation_epoch != target_epoch) return .reject;

    // [REJECT] Committee index must be in bounds.
    // MAX_COMMITTEES_PER_SLOT is the upper bound for committee indices.
    if (committee_index >= preset.MAX_COMMITTEES_PER_SLOT) return .reject;

    // [IGNORE] Target block root must be known.
    // If unknown, the message may be valid but we can't process it yet.
    // Callers should queue for reprocessing when the target block arrives.
    if (!state.isKnownBlockRoot(target_root)) return .ignore;

    return .accept;
}

// ── Aggregate validation ────────────────────────────────────────────────────

/// Fast Phase 1 validation for a `SignedAggregateAndProof` on the
/// `beacon_aggregate_and_proof` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#beacon_aggregate_and_proof):
/// 1. [REJECT] Aggregator index is within validator set bounds.
/// 2. [REJECT] Attestation slot is within propagation range.
/// 3. [REJECT] Attestation epoch matches target epoch.
/// 4. [REJECT] Aggregate has at least one participant.
/// 5. [IGNORE] (aggregator_index, epoch) pair has not been seen before.
pub fn validateGossipAggregate(
    aggregator_index: u64,
    attestation_slot: u64,
    target_epoch: u64,
    aggregation_bits_count: u64,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Aggregator index within validator set.
    const validator_count = state.getValidatorCount();
    if (aggregator_index >= validator_count) return .reject;

    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;

    // [REJECT] Attestation slot is within propagation window.
    const in_current = attestation_epoch == state.current_epoch;
    const in_previous = state.current_epoch > 0 and attestation_epoch == state.current_epoch - 1;
    if (!in_current and !in_previous) return .reject;

    // [REJECT] Attestation epoch matches target epoch.
    if (attestation_epoch != target_epoch) return .reject;

    // [REJECT] Aggregate has participants.
    if (aggregation_bits_count == 0) return .reject;

    // [IGNORE] Deduplicate by (aggregator_index, epoch).
    if (state.seen_cache.hasSeenAggregator(@intCast(aggregator_index), attestation_epoch)) return .ignore;
    state.seen_cache.markAggregatorSeen(@intCast(aggregator_index), attestation_epoch) catch return .ignore;

    return .accept;
}

// ============================================================
// Tests
// ============================================================

fn mockGetProposerIndex(slot: u64) ?u32 {
    if (slot == 100) return 5;
    return 0;
}

fn mockIsKnownBlockRoot(root: [32]u8) bool {
    // Zero root = unknown, everything else = known.
    return !std.mem.eql(u8, &root, &([_]u8{0} ** 32));
}

fn mockGetValidatorCount() u32 {
    return 1000;
}

fn makeMockChainState(seen_cache: *SeenCache) ChainState {
    return .{
        .current_slot = 100,
        .current_epoch = 3, // slot 100 / 32 = 3
        .finalized_slot = 64, // epoch 2 start
        .seen_cache = seen_cache,
        .getProposerIndex = &mockGetProposerIndex,
        .isKnownBlockRoot = &mockIsKnownBlockRoot,
        .getValidatorCount = &mockGetValidatorCount,
    };
}

// ── Block tests ─────────────────────────────────────────────────────────────

test "gossip block: accept valid block" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const parent = [_]u8{0xAA} ** 32;
    const root = [_]u8{0xBB} ** 32;

    const result = validateGossipBlock(100, 5, parent, root, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip block: ignore future slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipBlock(102, 5, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip block: ignore finalized slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipBlock(64, 5, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip block: ignore duplicate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const parent = [_]u8{0xAA} ** 32;
    const root = [_]u8{0xBB} ** 32;

    const r1 = validateGossipBlock(100, 5, parent, root, &state);
    try testing.expectEqual(GossipAction.accept, r1);

    const r2 = validateGossipBlock(100, 5, parent, root, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip block: reject wrong proposer" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 100 expects proposer 5, but we send proposer 7.
    const result = validateGossipBlock(100, 7, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip block: reject proposer index out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipBlock(100, 1000, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip block: ignore unknown parent" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Zero root is "unknown" in mock.
    const result = validateGossipBlock(100, 5, [_]u8{0} ** 32, [_]u8{0xCC} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

// ── Attestation tests ───────────────────────────────────────────────────────

test "gossip attestation: accept valid attestation" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3 (current), committee 0, target epoch 3, known root.
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip attestation: ignore stale epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 32 = epoch 1, current is 3. Epoch 1 is not current (3) or previous (2).
    const result = validateGossipAttestation(32, 0, 1, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip attestation: reject mismatched target epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3, but target says epoch 2.
    const result = validateGossipAttestation(96, 0, 2, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip attestation: reject committee index out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAttestation(96, preset.MAX_COMMITTEES_PER_SLOT, 3, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip attestation: ignore unknown target root" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Zero root is unknown — should return .ignore for reprocess queue.
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

// ── Aggregate tests ─────────────────────────────────────────────────────────

test "gossip aggregate: accept valid aggregate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(5, 96, 3, 10, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip aggregate: reject aggregator out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(1000, 96, 3, 10, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip aggregate: reject empty aggregation bits" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(5, 96, 3, 0, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip aggregate: ignore duplicate aggregator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);

    const r1 = validateGossipAggregate(5, 96, 3, 10, &state);
    try testing.expectEqual(GossipAction.accept, r1);

    const r2 = validateGossipAggregate(5, 96, 3, 10, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip aggregate: reject stale epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 32 = epoch 1, not in current (3) or previous (2).
    const result = validateGossipAggregate(5, 32, 1, 10, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip aggregate: reject mismatched target epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3, but target says 2.
    const result = validateGossipAggregate(5, 96, 2, 10, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

// ── Data column sidecar validation (PeerDAS / Fulu) ─────────────────────────

/// Fast Phase 1 validation for a `DataColumnSidecar` on the
/// `data_column_sidecar_{subnet_id}` topic.
///
/// Checks (spec reference: fulu/p2p-interface.md#data_column_sidecar_subnet_id):
/// 1. [REJECT] Column index is less than NUMBER_OF_COLUMNS.
/// 2. [IGNORE] Not from a future slot (with clock disparity tolerance).
/// 3. [IGNORE] Slot is greater than the finalized slot.
/// 4. [IGNORE] Not already seen — first column for this (root, index) pair.
/// 5. [REJECT] Proposer index is within the known validator set.
/// 6. [IGNORE] Parent block root is known in our fork choice.
pub fn validateGossipDataColumnSidecar(
    block_slot: u64,
    proposer_index: u64,
    column_index: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Column index must be < NUMBER_OF_COLUMNS.
    if (column_index >= preset_root.NUMBER_OF_COLUMNS) return .reject;

    // [IGNORE] Not from a future slot (tolerate current_slot + 1 for clock disparity).
    if (block_slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (block_slot <= state.finalized_slot) return .ignore;

    // [IGNORE] Not a duplicate — first sidecar for this (block_root, column_index).
    if (state.seen_cache.hasSeenDataColumn(block_root, column_index)) return .ignore;
    state.seen_cache.markDataColumnSeen(block_root, column_index) catch return .ignore;

    // [REJECT] Proposer index within validator set bounds.
    const validator_count = state.getValidatorCount();
    if (proposer_index >= validator_count) return .reject;

    // [IGNORE] Parent root is known in our fork choice.
    if (!state.isKnownBlockRoot(parent_root)) return .ignore;

    return .accept;
}

// ── Data column sidecar tests ───────────────────────────────────────────────

test "gossip data column: accept valid sidecar" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const parent = [_]u8{0xAA} ** 32;
    const root = [_]u8{0xBB} ** 32;

    const result = validateGossipDataColumnSidecar(100, 5, 0, parent, root, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip data column: reject column index out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const parent = [_]u8{0xAA} ** 32;
    const root = [_]u8{0xBB} ** 32;

    // NUMBER_OF_COLUMNS is 128 for mainnet; any index >= 128 should be rejected.
    const result = validateGossipDataColumnSidecar(100, 5, preset_root.NUMBER_OF_COLUMNS, parent, root, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip data column: ignore future slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipDataColumnSidecar(102, 5, 0, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip data column: ignore finalized slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipDataColumnSidecar(64, 5, 0, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip data column: ignore duplicate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const parent = [_]u8{0xAA} ** 32;
    const root = [_]u8{0xCC} ** 32;

    const r1 = validateGossipDataColumnSidecar(100, 5, 3, parent, root, &state);
    try testing.expectEqual(GossipAction.accept, r1);

    const r2 = validateGossipDataColumnSidecar(100, 5, 3, parent, root, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip data column: ignore unknown parent" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Zero root is "unknown" in mock.
    const result = validateGossipDataColumnSidecar(100, 5, 0, [_]u8{0} ** 32, [_]u8{0xDD} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip data column: reject proposer out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipDataColumnSidecar(100, 1000, 0, [_]u8{0xAA} ** 32, [_]u8{0xEE} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}
