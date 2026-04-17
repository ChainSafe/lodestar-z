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

/// Fast-validation result for gossip that depends on attestation data.
///
/// `unknown_beacon_block` is intentionally distinct from a generic `ignore` so
/// the caller can trigger the unknown-block recovery path instead of dropping
/// orphan attestations and aggregates on the floor.
pub const AttestationGossipAction = enum {
    accept,
    reject,
    ignore,
    unknown_beacon_block,
};

pub const GossipBlockValidation = enum {
    accept,
    reject,
    ignore,
    ignore_parent_unknown,
};

/// Maximum number of slots a block can be in the future before we ignore it.
/// Accounts for MAXIMUM_GOSSIP_CLOCK_DISPARITY (500 ms ≈ 0–1 slots).
const MAX_FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Read-only chain state snapshot for fast gossip validation.
///
/// The caller provides this with current clock values and function pointers
/// for state queries that can be satisfied from caches (no disk I/O).
pub const ChainState = struct {
    pub const KnownBlockInfo = struct {
        slot: u64,
        target_root: [32]u8,
    };

    /// Current wall-clock slot.
    current_slot: u64,
    /// Current epoch derived from current_slot.
    current_epoch: u64,
    /// Start slot of the finalized epoch.
    finalized_slot: u64,
    /// Mutable reference to the node's dedup caches.
    seen_cache: *SeenCache,

    /// Type-erased context pointer passed through to each callback.
    /// The concrete type is known only to the caller (e.g. *BeaconNode).
    ptr: *anyopaque,

    /// Returns expected block proposer for `slot`, or null if cache miss.
    getProposerIndex: *const fn (ptr: *anyopaque, slot: u64) ?u32,
    /// Returns true if `root` is a known block in our fork choice.
    isKnownBlockRoot: *const fn (ptr: *anyopaque, root: [32]u8) bool,
    /// Returns slot/target-root metadata for `root` if it is known in fork choice.
    getKnownBlockInfo: *const fn (ptr: *anyopaque, root: [32]u8) ?KnownBlockInfo,
    /// Returns the total validator count for bounds checking.
    getValidatorCount: *const fn (ptr: *anyopaque) u32,
};

fn validateHeadBlockAndTargetRoot(
    attestation_slot: u64,
    target_epoch: u64,
    beacon_block_root: [32]u8,
    target_root: [32]u8,
    state: *const ChainState,
) ?AttestationGossipAction {
    const head_block = state.getKnownBlockInfo(state.ptr, beacon_block_root) orelse return .unknown_beacon_block;
    if (!state.isKnownBlockRoot(state.ptr, target_root)) return .ignore;
    if (head_block.slot > attestation_slot) return .ignore;

    const head_block_epoch = head_block.slot / preset.SLOTS_PER_EPOCH;
    const expected_target = if (target_epoch > head_block_epoch)
        beacon_block_root
    else
        head_block.target_root;
    if (!std.mem.eql(u8, &expected_target, &target_root)) return .reject;

    return null;
}

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
pub fn validateGossipBlockDetailed(
    block_slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    state: *const ChainState,
) GossipBlockValidation {
    // [IGNORE] Not from a future slot (tolerate current_slot + 1 for clock disparity).
    if (block_slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (block_slot <= state.finalized_slot) return .ignore;

    // [IGNORE] Not a duplicate — first block for this root.
    if (state.seen_cache.hasSeenBlock(block_root)) return .ignore;

    // [REJECT] Proposer index within validator set bounds.
    const validator_count = state.getValidatorCount(state.ptr);
    if (proposer_index >= validator_count) return .reject;

    // [REJECT] Proposer matches expected for this slot.
    if (state.getProposerIndex(state.ptr, block_slot)) |expected| {
        if (proposer_index != expected) return .reject;
    } else {
        // Can't determine expected proposer — inconclusive, don't penalize.
        return .ignore;
    }

    // [IGNORE] Parent root is known in our fork choice.
    if (!state.isKnownBlockRoot(state.ptr, parent_root)) return .ignore_parent_unknown;

    // Mark block as seen only after ALL checks pass — avoids poisoning the
    // seen-cache with blocks that would be rejected/ignored.
    state.seen_cache.markBlockSeen(block_root, block_slot) catch return .ignore;

    return .accept;
}

pub fn validateGossipBlock(
    block_slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    return switch (validateGossipBlockDetailed(
        block_slot,
        proposer_index,
        parent_root,
        block_root,
        state,
    )) {
        .accept => .accept,
        .reject => .reject,
        .ignore, .ignore_parent_unknown => .ignore,
    };
}

// ── Attestation validation ──────────────────────────────────────────────────

/// Fast Phase 1 validation for an attestation on a `beacon_attestation_{subnet}` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#beacon_attestation_subnet_id):
/// 1. [IGNORE] Attestation slot is within propagation range (current/previous epoch).
/// 2. [REJECT] Attestation epoch matches the target epoch.
/// 3. [REJECT] Committee index is within bounds.
/// 4. [UNKNOWN_BEACON_BLOCK] Head block root is known in fork choice.
/// 5. [IGNORE] Target checkpoint root is known and matches the head block.
pub fn validateGossipAttestation(
    attestation_slot: u64,
    committee_index: u64,
    target_epoch: u64,
    beacon_block_root: [32]u8,
    target_root: [32]u8,
    state: *const ChainState,
) AttestationGossipAction {
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

    if (validateHeadBlockAndTargetRoot(
        attestation_slot,
        target_epoch,
        beacon_block_root,
        target_root,
        state,
    )) |action| return action;

    return .accept;
}

// ── Electra attestation validation ──────────────────────────────────────────

/// Fast Phase 1 validation for an Electra/Fulu `SingleAttestation` on a
/// `beacon_attestation_{subnet}` topic.
///
/// Checks (spec reference: electra/p2p-interface.md#beacon_attestation_subnet_id):
/// 1. [IGNORE] Attestation slot is within propagation range (current/previous epoch).
/// 2. [REJECT] Attestation epoch matches the target epoch.
/// 3. [REJECT] Pre-Gloas: `attestation.data.index == 0`.
/// 4. [REJECT] Post-Gloas: `attestation.data.index < 2`, and
///    `attestation.data.index == 0` if `block.slot == attestation.slot`.
/// 5. [REJECT] `attestation.committee_index` is in bounds.
/// 6. [UNKNOWN_BEACON_BLOCK] Head block root is known in fork choice.
/// 7. [IGNORE] Target checkpoint root is known and matches the head block.
///
/// Membership of `attester_index` in the resolved committee is checked later,
/// once committee data has been loaded from the epoch cache.
pub fn validateGossipElectraAttestation(
    attestation_slot: u64,
    data_index: u64,
    target_epoch: u64,
    beacon_block_root: [32]u8,
    target_root: [32]u8,
    committee_index: u64,
    is_post_gloas: bool,
    state: *const ChainState,
) AttestationGossipAction {
    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;

    // [IGNORE] Attestation slot is within the propagation window.
    const in_current = attestation_epoch == state.current_epoch;
    const in_previous = state.current_epoch > 0 and attestation_epoch == state.current_epoch - 1;
    if (!in_current and !in_previous) return .ignore;

    // [REJECT] Attestation epoch must match the target epoch.
    if (attestation_epoch != target_epoch) return .reject;

    if (is_post_gloas) {
        // [REJECT] Post-Gloas data.index must encode EMPTY or FULL only.
        if (data_index >= 2) return .reject;
    } else {
        // [REJECT] Pre-Gloas data.index must always be 0.
        if (data_index != 0) return .reject;
    }

    // [REJECT] Committee index must be in bounds.
    if (committee_index >= preset.MAX_COMMITTEES_PER_SLOT) return .reject;

    if (validateHeadBlockAndTargetRoot(
        attestation_slot,
        target_epoch,
        beacon_block_root,
        target_root,
        state,
    )) |action| return action;

    const head_block = state.getKnownBlockInfo(state.ptr, beacon_block_root) orelse return .unknown_beacon_block;
    if (is_post_gloas and head_block.slot == attestation_slot and data_index != 0) return .reject;

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
    beacon_block_root: [32]u8,
    target_root: [32]u8,
    aggregation_bits_count: u64,
    state: *const ChainState,
) AttestationGossipAction {
    // [REJECT] Aggregator index within validator set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (aggregator_index >= validator_count) return .reject;

    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;

    // [REJECT] Attestation slot is within propagation window.
    const in_current = attestation_epoch == state.current_epoch;
    const in_previous = state.current_epoch > 0 and attestation_epoch == state.current_epoch - 1;
    if (!in_current and !in_previous) return .reject;

    // [REJECT] Attestation epoch matches target epoch.
    if (attestation_epoch != target_epoch) return .reject;

    if (validateHeadBlockAndTargetRoot(
        attestation_slot,
        target_epoch,
        beacon_block_root,
        target_root,
        state,
    )) |action| return action;

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

var mock_dummy_ctx: u8 = 0;

fn mockGetProposerIndex(_: *anyopaque, slot: u64) ?u32 {
    if (slot == 100) return 5;
    return 0;
}

fn mockIsKnownBlockRoot(_: *anyopaque, root: [32]u8) bool {
    // Zero root = unknown, everything else = known.
    return !std.mem.eql(u8, &root, &([_]u8{0} ** 32));
}

fn mockGetKnownBlockInfo(_: *anyopaque, root: [32]u8) ?ChainState.KnownBlockInfo {
    if (std.mem.eql(u8, &root, &([_]u8{0} ** 32))) return null;
    return if (root[0] == 0xBB)
        .{
            .slot = 96,
            .target_root = [_]u8{0xBB} ** 32,
        }
    else
        .{
            .slot = 95,
            .target_root = [_]u8{0xAA} ** 32,
        };
}

fn mockGetValidatorCount(_: *anyopaque) u32 {
    return 1000;
}

fn makeMockChainState(seen_cache: *SeenCache) ChainState {
    return .{
        .current_slot = 100,
        .current_epoch = 3, // slot 100 / 32 = 3
        .finalized_slot = 64, // epoch 2 start
        .seen_cache = seen_cache,
        .ptr = &mock_dummy_ctx,
        .getProposerIndex = &mockGetProposerIndex,
        .isKnownBlockRoot = &mockIsKnownBlockRoot,
        .getKnownBlockInfo = &mockGetKnownBlockInfo,
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

test "gossip block: detailed validation distinguishes unknown parent" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipBlockDetailed(100, 5, [_]u8{0} ** 32, [_]u8{0xCC} ** 32, &state);
    try testing.expectEqual(GossipBlockValidation.ignore_parent_unknown, result);
}

// ── Attestation tests ───────────────────────────────────────────────────────

test "gossip attestation: accept valid attestation" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3 (current), committee 0, target epoch 3, known root.
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.accept, result);
}

test "gossip attestation: ignore stale epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 32 = epoch 1, current is 3. Epoch 1 is not current (3) or previous (2).
    const result = validateGossipAttestation(32, 0, 1, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.ignore, result);
}

test "gossip attestation: reject mismatched target epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3, but target says epoch 2.
    const result = validateGossipAttestation(96, 0, 2, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip attestation: reject committee index out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAttestation(96, preset.MAX_COMMITTEES_PER_SLOT, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip attestation: ignore unknown target root" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Zero root is unknown — should return .ignore for reprocess queue.
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.ignore, result);
}

test "gossip attestation: ignore unknown beacon block root" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0} ** 32, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.unknown_beacon_block, result);
}

test "gossip attestation: reject invalid target root for known head block" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0xCC} ** 32, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

// ── Aggregate tests ─────────────────────────────────────────────────────────

test "gossip aggregate: accept valid aggregate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.accept, result);
}

test "gossip aggregate: reject aggregator out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(1000, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip aggregate: reject empty aggregation bits" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip aggregate: ignore duplicate aggregator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);

    const r1 = validateGossipAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.accept, r1);

    const r2 = validateGossipAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.ignore, r2);
}

test "gossip aggregate: reject stale epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 32 = epoch 1, not in current (3) or previous (2).
    const result = validateGossipAggregate(5, 32, 1, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip aggregate: reject mismatched target epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3, but target says 2.
    const result = validateGossipAggregate(5, 96, 2, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip aggregate: unknown beacon block root is surfaced for retry" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();

    const state = makeMockChainState(&cache);
    const result = validateGossipAggregate(5, 96, 3, [_]u8{0} ** 32, [_]u8{0xAA} ** 32, 10, &state);
    try testing.expectEqual(AttestationGossipAction.unknown_beacon_block, result);
}

// ── Electra aggregate validation ────────────────────────────────────────────

/// Fast Phase 1 validation for an Electra `SignedAggregateAndProof` on the
/// `beacon_aggregate_and_proof` topic.
///
/// Electra changes:
///   - `data.index` must be 0
///   - `committee_bits` must have at least one bit set
///   - Aggregation bits span all committees in committee_bits
///
/// Checks:
/// 1. [REJECT] Aggregator index is within validator set bounds.
/// 2. [REJECT] Attestation slot is within propagation range.
/// 3. [REJECT] Attestation epoch matches target epoch.
/// 4. [REJECT] data.index must be 0.
/// 5. [REJECT] committee_bits must have exactly one bit set.
/// 6. [REJECT] Aggregate has at least one participant.
/// 7. [IGNORE] (aggregator_index, epoch) pair has not been seen before.
pub fn validateGossipElectraAggregate(
    aggregator_index: u64,
    attestation_slot: u64,
    target_epoch: u64,
    beacon_block_root: [32]u8,
    target_root: [32]u8,
    data_index: u64,
    committee_bits_count: u32,
    aggregation_bits_count: u64,
    state: *const ChainState,
) AttestationGossipAction {
    // [REJECT] Aggregator index within validator set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (aggregator_index >= validator_count) return .reject;

    const attestation_epoch = attestation_slot / preset.SLOTS_PER_EPOCH;

    // [REJECT] Attestation slot is within propagation window.
    const in_current = attestation_epoch == state.current_epoch;
    const in_previous = state.current_epoch > 0 and attestation_epoch == state.current_epoch - 1;
    if (!in_current and !in_previous) return .reject;

    // [REJECT] Attestation epoch matches target epoch.
    if (attestation_epoch != target_epoch) return .reject;

    if (validateHeadBlockAndTargetRoot(
        attestation_slot,
        target_epoch,
        beacon_block_root,
        target_root,
        state,
    )) |action| return action;

    // [REJECT] data.index must be 0 in Electra.
    if (data_index != 0) return .reject;

    // [REJECT] committee_bits must have exactly one bit set (Electra spec).
    if (committee_bits_count != 1) return .reject;

    // [REJECT] Aggregate has participants.
    if (aggregation_bits_count == 0) return .reject;

    // [IGNORE] Deduplicate by (aggregator_index, epoch).
    if (state.seen_cache.hasSeenAggregator(@intCast(aggregator_index), attestation_epoch)) return .ignore;
    state.seen_cache.markAggregatorSeen(@intCast(aggregator_index), attestation_epoch) catch return .ignore;

    return .accept;
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
    const validator_count = state.getValidatorCount(state.ptr);
    if (proposer_index >= validator_count) return .reject;

    // [IGNORE] Parent root is known in our fork choice.
    if (!state.isKnownBlockRoot(state.ptr, parent_root)) return .ignore;

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

// ── Blob sidecar validation ─────────────────────────────────────────────────

/// Fast Phase 1 validation for a `BlobSidecar` on the `blob_sidecar_{subnet_id}` topic.
///
/// Checks (spec reference: deneb/p2p-interface.md#blob_sidecar_subnet_id):
/// 1. [REJECT]  blob.index must match the subnet_id.
/// 2. [IGNORE]  Not from a future slot (with clock disparity tolerance).
/// 3. [IGNORE]  Slot is greater than the finalized slot.
/// 4. [REJECT]  Proposer index is within the known validator set.
/// 5. [IGNORE]  Parent block root is known in our fork choice.
pub fn validateGossipBlobSidecar(
    block_slot: u64,
    proposer_index: u64,
    blob_index: u64,
    subnet_id: u64,
    parent_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    // [REJECT] blob.index must match subnet_id.
    if (blob_index != subnet_id) return .reject;

    // [IGNORE] Not from a future slot.
    if (block_slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (block_slot <= state.finalized_slot) return .ignore;

    // [REJECT] Proposer index within validator set bounds.
    const validator_count = state.getValidatorCount(state.ptr);
    if (proposer_index >= validator_count) return .reject;

    // [IGNORE] Parent root is known in our fork choice.
    if (!state.isKnownBlockRoot(state.ptr, parent_root)) return .ignore;

    return .accept;
}

// ── Voluntary exit validation ───────────────────────────────────────────────

/// Fast Phase 1 validation for a `SignedVoluntaryExit` on the `voluntary_exit` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#voluntary_exit):
/// 1. [REJECT]  Validator index is within the known validator set.
/// 2. [IGNORE]  Not already seen for this validator (dedup via SeenCache).
/// 3. [IGNORE]  Exit epoch is not in the future (exit must be processable now).
pub fn validateGossipVoluntaryExit(
    validator_index: u64,
    exit_epoch: u64,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Validator index within known set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (validator_index >= validator_count) return .reject;

    // [IGNORE] Deduplicate: first valid exit for this validator.
    if (state.seen_cache.hasSeenExit(@intCast(validator_index))) return .ignore;
    state.seen_cache.markExitSeen(@intCast(validator_index)) catch return .ignore;

    // [IGNORE] Exit epoch must not be in the future (can't exit before the epoch is reached).
    if (exit_epoch > state.current_epoch) return .ignore;

    return .accept;
}

// ── Proposer slashing validation ────────────────────────────────────────────

/// Fast Phase 1 validation for a `ProposerSlashing` on the `proposer_slashing` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#proposer_slashing):
/// 1. [REJECT]  Proposer index is within the known validator set.
/// 2. [IGNORE]  Not already seen for this proposer (dedup via SeenCache).
/// 3. [REJECT]  Both headers are for the same slot (required for slashing).
/// 4. [REJECT]  Headers differ (same body root = not slashable).
pub fn validateGossipProposerSlashing(
    proposer_index: u64,
    header_1_slot: u64,
    header_2_slot: u64,
    header_1_body_root: [32]u8,
    header_2_body_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Proposer index within known validator set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (proposer_index >= validator_count) return .reject;

    // [IGNORE] Deduplicate: first valid slashing for this proposer.
    if (state.seen_cache.hasSeenProposerSlashing(@intCast(proposer_index))) return .ignore;
    state.seen_cache.markProposerSlashingSeen(@intCast(proposer_index)) catch return .ignore;

    // [REJECT] Both headers must be for the same slot.
    if (header_1_slot != header_2_slot) return .reject;

    // [REJECT] Headers must differ (otherwise not slashable).
    if (std.mem.eql(u8, &header_1_body_root, &header_2_body_root)) return .reject;

    return .accept;
}

// ── Attester slashing validation ────────────────────────────────────────────

/// Fast Phase 1 validation for an `AttesterSlashing` on the `attester_slashing` topic.
///
/// Checks (spec reference: phase0/p2p-interface.md#attester_slashing):
/// 1. [REJECT]  The attestation data must be slashable (double vote or surround vote).
/// 2. [IGNORE]  Not already seen (dedup by slashing root).
pub fn validateGossipAttesterSlashing(
    is_slashable: bool,
    slashing_root: [32]u8,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Attestation data must be slashable.
    if (!is_slashable) return .reject;

    // [IGNORE] Deduplicate by slashing root.
    if (state.seen_cache.hasSeenAttesterSlashing(slashing_root)) return .ignore;
    state.seen_cache.markAttesterSlashingSeen(slashing_root) catch return .ignore;

    return .accept;
}

// ── BLS-to-execution change validation ─────────────────────────────────────

/// Fast Phase 1 validation for a `SignedBLSToExecutionChange` on the
/// `bls_to_execution_change` topic.
///
/// Checks (spec reference: capella/p2p-interface.md#bls_to_execution_change):
/// 1. [REJECT]  Validator index is within the known validator set.
/// 2. [IGNORE]  Not already seen for this validator (dedup via SeenCache).
pub fn validateGossipBlsToExecutionChange(
    validator_index: u64,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Validator index within known set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (validator_index >= validator_count) return .reject;

    // [IGNORE] Deduplicate: first valid change for this validator.
    if (state.seen_cache.hasSeenBlsChange(@intCast(validator_index))) return .ignore;
    state.seen_cache.markBlsChangeSeen(@intCast(validator_index)) catch return .ignore;

    return .accept;
}

// ── Sync committee message validation ──────────────────────────────────────

/// Fast Phase 1 validation for a `SyncCommitteeMessage` on a
/// `sync_committee_{subnet}` topic.
///
/// Checks (spec reference: altair/p2p-interface.md#sync_committee_message):
/// 1. [REJECT]  Validator index is within the known validator set.
/// 2. [IGNORE]  Slot is not from a future slot.
/// 3. [IGNORE]  Slot is not already finalized.
pub fn validateGossipSyncCommitteeMessage(
    validator_index: u64,
    slot: u64,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Validator index within known set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (validator_index >= validator_count) return .reject;

    // [IGNORE] Not from a future slot.
    if (slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (state.finalized_slot > 0 and slot < state.finalized_slot) return .ignore;

    return .accept;
}

// ── Sync committee contribution validation ──────────────────────────────────

/// Fast Phase 1 validation for a `SignedContributionAndProof` on the
/// `sync_committee_contribution_and_proof` topic.
///
/// Checks (spec reference: altair/p2p-interface.md#sync_committee_contribution_and_proof):
/// 1. [REJECT]  Aggregator index is within the known validator set.
/// 2. [IGNORE]  Contribution slot is not from a future slot.
/// 3. [IGNORE]  Contribution slot is not already finalized.
pub fn validateGossipSyncContributionAndProof(
    aggregator_index: u64,
    contribution_slot: u64,
    state: *const ChainState,
) GossipAction {
    // [REJECT] Aggregator index within known set.
    const validator_count = state.getValidatorCount(state.ptr);
    if (aggregator_index >= validator_count) return .reject;

    // [IGNORE] Not from a future slot.
    if (contribution_slot > state.current_slot + MAX_FUTURE_SLOT_TOLERANCE) return .ignore;

    // [IGNORE] Not already finalized.
    if (state.finalized_slot > 0 and contribution_slot < state.finalized_slot) return .ignore;

    return .accept;
}

// ── Tests for new validators ────────────────────────────────────────────────

test "gossip blob sidecar: accept valid sidecar" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipBlobSidecar(100, 5, 0, 0, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip blob sidecar: reject wrong subnet" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipBlobSidecar(100, 5, 2, 3, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip blob sidecar: ignore future slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipBlobSidecar(102, 5, 0, 0, [_]u8{0xAA} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip voluntary exit: accept valid exit" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipVoluntaryExit(10, 3, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip voluntary exit: reject out of bounds validator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipVoluntaryExit(1000, 3, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip voluntary exit: ignore duplicate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const r1 = validateGossipVoluntaryExit(10, 3, &state);
    try testing.expectEqual(GossipAction.accept, r1);
    const r2 = validateGossipVoluntaryExit(10, 3, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip voluntary exit: ignore future exit epoch" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache); // current_epoch = 3
    const result = validateGossipVoluntaryExit(11, 5, &state); // exit_epoch 5 > current 3
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip proposer slashing: accept valid slashing" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipProposerSlashing(5, 100, 100, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip proposer slashing: reject different slots" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipProposerSlashing(5, 100, 101, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip proposer slashing: reject identical headers" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const same = [_]u8{0xAA} ** 32;
    const result = validateGossipProposerSlashing(5, 100, 100, same, same, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip proposer slashing: ignore duplicate proposer" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const r1 = validateGossipProposerSlashing(5, 100, 100, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, &state);
    try testing.expectEqual(GossipAction.accept, r1);
    const r2 = validateGossipProposerSlashing(5, 100, 100, [_]u8{0xCC} ** 32, [_]u8{0xDD} ** 32, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip attester slashing: accept slashable" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const root = [_]u8{0x11} ** 32;
    const result = validateGossipAttesterSlashing(true, root, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip attester slashing: reject not slashable" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const root = [_]u8{0x22} ** 32;
    const result = validateGossipAttesterSlashing(false, root, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip attester slashing: ignore duplicate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const root = [_]u8{0x33} ** 32;
    const r1 = validateGossipAttesterSlashing(true, root, &state);
    try testing.expectEqual(GossipAction.accept, r1);
    const r2 = validateGossipAttesterSlashing(true, root, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip bls change: accept valid change" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipBlsToExecutionChange(42, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip bls change: reject out of bounds validator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipBlsToExecutionChange(1000, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip bls change: ignore duplicate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const r1 = validateGossipBlsToExecutionChange(42, &state);
    try testing.expectEqual(GossipAction.accept, r1);
    const r2 = validateGossipBlsToExecutionChange(42, &state);
    try testing.expectEqual(GossipAction.ignore, r2);
}

test "gossip sync committee message: accept valid message" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncCommitteeMessage(5, 100, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip sync committee message: reject out of bounds validator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncCommitteeMessage(1000, 100, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip sync committee message: ignore future slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncCommitteeMessage(5, 110, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

test "gossip sync contribution: accept valid contribution" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncContributionAndProof(5, 100, &state);
    try testing.expectEqual(GossipAction.accept, result);
}

test "gossip sync contribution: reject out of bounds aggregator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncContributionAndProof(1000, 100, &state);
    try testing.expectEqual(GossipAction.reject, result);
}

test "gossip sync contribution: ignore future slot" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipSyncContributionAndProof(5, 110, &state);
    try testing.expectEqual(GossipAction.ignore, result);
}

// ── Electra attestation tests ───────────────────────────────────────────────

test "gossip electra attestation: accept valid attestation" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    // Slot 96 = epoch 3 (current), data.index=0, committee_index=2
    const result = validateGossipElectraAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 2, false, &state);
    try testing.expectEqual(AttestationGossipAction.accept, result);
}

test "gossip electra attestation: reject nonzero data.index" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 1, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, false, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra attestation: reject committee index out of bounds" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, preset.MAX_COMMITTEES_PER_SLOT, false, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra attestation: ignore unknown target root" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 0, 3, [_]u8{0xAA} ** 32, [_]u8{0} ** 32, 0, false, &state);
    try testing.expectEqual(AttestationGossipAction.ignore, result);
}

test "gossip gloas attestation: accept payload-present vote for prior-slot block" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 1, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 2, true, &state);
    try testing.expectEqual(AttestationGossipAction.accept, result);
}

test "gossip gloas attestation: reject premature payload-present vote for same-slot block" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 1, 3, [_]u8{0xBB} ** 32, [_]u8{0xBB} ** 32, 2, true, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip gloas attestation: reject payload status values above full" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAttestation(96, 2, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 2, true, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra aggregate: accept valid aggregate" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 1, 10, &state);
    try testing.expectEqual(AttestationGossipAction.accept, result);
}

test "gossip electra aggregate: reject nonzero data.index" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 1, 2, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra aggregate: reject zero committee bits" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 0, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra aggregate: reject zero aggregation bits" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 2, 0, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra aggregate: reject multiple committee bits" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    // 2 committee bits set — spec requires exactly 1
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 2, 10, &state);
    try testing.expectEqual(AttestationGossipAction.reject, result);
}

test "gossip electra aggregate: ignore duplicate aggregator" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const r1 = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 1, 10, &state);
    try testing.expectEqual(AttestationGossipAction.accept, r1);
    const r2 = validateGossipElectraAggregate(5, 96, 3, [_]u8{0xAA} ** 32, [_]u8{0xAA} ** 32, 0, 1, 10, &state);
    try testing.expectEqual(AttestationGossipAction.ignore, r2);
}

test "gossip electra aggregate: unknown beacon block root is surfaced for retry" {
    var cache = SeenCache.init(testing.allocator);
    defer cache.deinit();
    const state = makeMockChainState(&cache);
    const result = validateGossipElectraAggregate(5, 96, 3, [_]u8{0} ** 32, [_]u8{0xAA} ** 32, 0, 1, 10, &state);
    try testing.expectEqual(AttestationGossipAction.unknown_beacon_block, result);
}
