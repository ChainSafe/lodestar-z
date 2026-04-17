//! Deterministic attestation generator for simulation testing.
//!
//! Generates structurally valid Electra attestations for inclusion in
//! beacon blocks.  Attestations use stub signatures (zero bytes) and are
//! intended for state transition testing with `verify_signatures: false`.
//!
//! In the Ethereum protocol:
//!   - Each slot, validators are assigned to committees.
//!   - Each committee attests to the head of the chain.
//!   - Attestations from slot N are included in blocks at slot N+1 or later.
//!
//! For simulation we generate "perfect" attestations where a configurable
//! fraction of assigned validators attest correctly.  Participation
//! selection is deterministic from the attestation slot so that all nodes
//! in a cluster simulation produce identical blocks.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const ssz = @import("ssz");
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");

const CachedBeaconState = state_transition.CachedBeaconState;
const EpochCache = state_transition.EpochCache;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;
const validateAttestation = state_transition.validateAttestation;

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const AttestationData = types.phase0.AttestationData.Type;
const ElectraAttestation = types.electra.Attestation.Type;

const CommitteeBits = ssz.BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);
const AggregationBits = ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT);

/// Generate attestations for inclusion in a block at `block_slot`.
///
/// Attestations are for the PREVIOUS slot (`block_slot - 1`).
/// For genesis slot (block_slot == 0), returns an empty list.
///
/// The generator creates one aggregate attestation per committee at the
/// attestation slot.  Each committee's aggregation bits are populated
/// according to `participation_rate`.  Validator selection is
/// deterministic from the attestation slot (not from a node-private
/// PRNG) so that every node in a cluster produces identical blocks.
///
/// Caller owns the returned list and each attestation's aggregation_bits.
/// Free with `deinitAttestations`.
pub fn generateAttestations(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    block_slot: Slot,
    participation_rate: f64,
) !std.ArrayListUnmanaged(ElectraAttestation) {
    var result = std.ArrayListUnmanaged(ElectraAttestation).empty;
    errdefer deinitAttestations(allocator, &result);

    const state = cached_state.state;
    const epoch_cache = cached_state.epoch_cache;

    // No attestations for the first slot (nothing to attest to).
    if (block_slot == 0) return result;

    const attestation_slot = block_slot - 1;
    const att_epoch = computeEpochAtSlot(attestation_slot);

    // Get committee count for the attestation slot's epoch.
    const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(att_epoch) catch return result;
    if (committees_per_slot == 0) return result;

    // beacon_block_root: root of the block at attestation_slot.
    const beacon_block_root = getBlockRootAtSlot(
        .electra,
        state.castToFork(.electra),
        attestation_slot,
    ) catch return result;

    // Target checkpoint: epoch boundary block root for the attestation epoch.
    const target_epoch_start_slot = computeStartSlotAtEpoch(att_epoch);
    const target_root = if (target_epoch_start_slot < attestation_slot)
        (getBlockRootAtSlot(.electra, state.castToFork(.electra), target_epoch_start_slot) catch return result)
    else
        // Attestation is at the epoch start — target root = beacon_block_root.
        beacon_block_root;

    // Source checkpoint: current or previous justified depending on epoch.
    const current_epoch = epoch_cache.epoch;
    var source_checkpoint: Checkpoint = undefined;
    if (att_epoch == current_epoch) {
        try state.currentJustifiedCheckpoint(&source_checkpoint);
    } else {
        try state.previousJustifiedCheckpoint(&source_checkpoint);
    }

    const att_data = AttestationData{
        .slot = attestation_slot,
        .index = 0, // Electra: always 0, committee identity is in committee_bits.
        .beacon_block_root = beacon_block_root.*,
        .source = source_checkpoint,
        .target = .{
            .epoch = att_epoch,
            .root = target_root.*,
        },
    };

    // Slot-deterministic PRNG — ensures all nodes in a cluster produce
    // identical attestation bitfields for the same slot.
    var slot_prng = std.Random.DefaultPrng.init(attestation_slot *% 0x9E3779B97F4A7C15 +% 0xBF58476D1CE4E5B9);

    // Generate one attestation per committee.
    for (0..committees_per_slot) |committee_idx| {
        const committee = epoch_cache.getBeaconCommittee(attestation_slot, committee_idx) catch continue;
        if (committee.len == 0) continue;

        // committee_bits: only this committee's bit is set.
        var committee_bits = CommitteeBits.Type.empty;
        committee_bits.set(committee_idx, true) catch continue;

        // aggregation_bits: one bit per validator in this committee.
        var aggregation_bits = AggregationBits.Type.fromBitLen(allocator, committee.len) catch continue;
        errdefer aggregation_bits.deinit(allocator);

        var any_participating = false;
        for (0..committee.len) |vi| {
            const participating = if (participation_rate >= 1.0)
                true
            else if (participation_rate <= 0.0)
                false
            else blk: {
                const rand_val: f64 = @as(f64, @floatFromInt(slot_prng.random().int(u32))) /
                    @as(f64, @floatFromInt(std.math.maxInt(u32)));
                break :blk rand_val < participation_rate;
            };

            if (participating) {
                aggregation_bits.set(allocator, vi, true) catch continue;
                any_participating = true;
            }
        }

        // Skip committees with zero participation (spec requires at least one true bit).
        if (!any_participating) {
            aggregation_bits.deinit(allocator);
            continue;
        }

        try result.append(allocator, .{
            .aggregation_bits = aggregation_bits,
            .data = att_data,
            .signature = types.primitive.BLSSignature.default_value,
            .committee_bits = committee_bits,
        });
    }

    return result;
}

/// Free all attestations in the list (deinit aggregation_bits).
pub fn deinitAttestations(allocator: Allocator, attestations: *std.ArrayListUnmanaged(ElectraAttestation)) void {
    for (attestations.items) |*att| {
        types.electra.Attestation.deinit(allocator, att);
    }
    attestations.deinit(allocator);
}

// ── Unit tests ───────────────────────────────────────────────────────

const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const BlockGenerator = @import("block_generator.zig").BlockGenerator;

test "attestation_generator: no attestations at genesis slot" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    // block_slot == 0: no previous slot to attest to.
    var atts = try generateAttestations(allocator, test_state.cached_state, 0, 1.0);
    defer deinitAttestations(allocator, &atts);
    try testing.expectEqual(@as(usize, 0), atts.items.len);
}

test "attestation_generator: generates attestations for each committee" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    // Advance state by one slot so there's a block root to attest to.
    const start_slot = try test_state.cached_state.state.slot();
    const target_slot = start_slot + 1;

    try state_transition.processSlots(allocator, test_state.cached_state, target_slot, .{});

    var block_gen = BlockGenerator.init(allocator, 42);
    const signed_block = try block_gen.generateBlock(test_state.cached_state, target_slot);
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, signed_block);
        allocator.destroy(signed_block);
    }

    // Apply block.
    const any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = signed_block };
    const block = any_signed.beaconBlock();
    switch (block.blockType()) {
        inline else => |bt| {
            try state_transition.processBlock(
                .electra,
                allocator,
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state.castToFork(.electra),
                &test_state.cached_state.slashings_cache,
                bt,
                block.castToFork(bt, .electra),
                .{ .execution_payload_status = .valid, .data_availability_status = .available },
                .{ .verify_signature = false },
            );
        },
    }
    try test_state.cached_state.state.commit();

    // Now generate attestations for the NEXT slot (target_slot + 1).
    const att_slot = target_slot + 1;
    try state_transition.processSlots(allocator, test_state.cached_state, att_slot, .{});

    var atts = try generateAttestations(allocator, test_state.cached_state, att_slot, 1.0);
    defer deinitAttestations(allocator, &atts);

    // With 64 validators and minimal preset, we should get at least 1 committee.
    try testing.expect(atts.items.len > 0);

    // Each attestation should have committee_bits with exactly one bit set.
    for (atts.items) |*att| {
        var true_bits: usize = 0;
        for (0..preset.MAX_COMMITTEES_PER_SLOT) |i| {
            if ((att.committee_bits.get(i) catch false)) true_bits += 1;
        }
        try testing.expectEqual(@as(usize, 1), true_bits);

        // Attestation data should reference the correct slot.
        try testing.expectEqual(target_slot, att.data.slot);

        // Index should be 0 (Electra).
        try testing.expectEqual(@as(u64, 0), att.data.index);
    }
}

test "attestation_generator: zero participation produces no attestations" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const start_slot = try test_state.cached_state.state.slot();
    const target_slot = start_slot + 1;
    try state_transition.processSlots(allocator, test_state.cached_state, target_slot, .{});

    var block_gen = BlockGenerator.init(allocator, 42);
    const signed_block = try block_gen.generateBlock(test_state.cached_state, target_slot);
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, signed_block);
        allocator.destroy(signed_block);
    }

    const any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = signed_block };
    const block = any_signed.beaconBlock();
    switch (block.blockType()) {
        inline else => |bt| {
            try state_transition.processBlock(
                .electra,
                allocator,
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state.castToFork(.electra),
                &test_state.cached_state.slashings_cache,
                bt,
                block.castToFork(bt, .electra),
                .{ .execution_payload_status = .valid, .data_availability_status = .available },
                .{ .verify_signature = false },
            );
        },
    }
    try test_state.cached_state.state.commit();

    const att_slot = target_slot + 1;
    try state_transition.processSlots(allocator, test_state.cached_state, att_slot, .{});

    var atts = try generateAttestations(allocator, test_state.cached_state, att_slot, 0.0);
    defer deinitAttestations(allocator, &atts);
    try testing.expectEqual(@as(usize, 0), atts.items.len);
}

test "attestation_generator: deterministic — same slot same attestations" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const start_slot = try test_state.cached_state.state.slot();
    const target_slot = start_slot + 1;
    try state_transition.processSlots(allocator, test_state.cached_state, target_slot, .{});

    var block_gen = BlockGenerator.init(allocator, 42);
    const signed_block = try block_gen.generateBlock(test_state.cached_state, target_slot);
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, signed_block);
        allocator.destroy(signed_block);
    }

    const any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = signed_block };
    const block = any_signed.beaconBlock();
    switch (block.blockType()) {
        inline else => |bt| {
            try state_transition.processBlock(
                .electra,
                allocator,
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state.castToFork(.electra),
                &test_state.cached_state.slashings_cache,
                bt,
                block.castToFork(bt, .electra),
                .{ .execution_payload_status = .valid, .data_availability_status = .available },
                .{ .verify_signature = false },
            );
        },
    }
    try test_state.cached_state.state.commit();

    const att_slot = target_slot + 1;
    try state_transition.processSlots(allocator, test_state.cached_state, att_slot, .{});

    // Run twice — same slot should produce same attestations.
    var counts: [2]usize = undefined;
    for (0..2) |run| {
        var atts = try generateAttestations(allocator, test_state.cached_state, att_slot, 0.7);
        defer deinitAttestations(allocator, &atts);
        counts[run] = atts.items.len;
    }

    try testing.expectEqual(counts[0], counts[1]);
}

test "attestation_generator: electra validation rejects aggregation bits longer than maximum" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    var justified_checkpoint: Checkpoint = undefined;
    const state_slot = try test_state.cached_state.state.slot();
    const attestation_slot = state_slot - preset.MIN_ATTESTATION_INCLUSION_DELAY;
    const attestation_epoch = computeEpochAtSlot(attestation_slot);
    if (attestation_epoch == test_state.cached_state.epoch_cache.epoch) {
        try test_state.cached_state.state.currentJustifiedCheckpoint(&justified_checkpoint);
    } else {
        try test_state.cached_state.state.previousJustifiedCheckpoint(&justified_checkpoint);
    }

    const committee = try test_state.cached_state.epoch_cache.getBeaconCommittee(attestation_slot, 0);
    try testing.expect(committee.len > 0);

    var committee_bits = CommitteeBits.Type.empty;
    try committee_bits.set(0, true);

    var aggregation_bits = try AggregationBits.Type.fromBitLen(allocator, committee.len);
    defer aggregation_bits.deinit(allocator);
    try aggregation_bits.set(allocator, 0, true);

    var malformed = ElectraAttestation{
        .aggregation_bits = aggregation_bits,
        .data = .{
            .slot = attestation_slot,
            .index = 0,
            .beacon_block_root = [_]u8{0} ** 32,
            .source = justified_checkpoint,
            .target = .{
                .epoch = attestation_epoch,
                .root = [_]u8{0} ** 32,
            },
        },
        .signature = types.primitive.BLSSignature.default_value,
        .committee_bits = committee_bits,
    };
    malformed.aggregation_bits.bit_len = preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT + 1;

    try testing.expectError(
        error.InvalidAttestationCommitteeAggregationBitsLengthMismatch,
        validateAttestation(
            .electra,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &malformed,
        ),
    );
}
