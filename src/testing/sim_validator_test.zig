//! Tests for SimValidator — duty tracking and block/attestation production.

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const types = @import("consensus_types");

const SimValidator = @import("sim_validator.zig").SimValidator;
const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;

// ── Test 1: Validator ownership ──────────────────────────────────────

test "sim_validator: validator ownership range" {
    var val = SimValidator.init(testing.allocator, 10, 20, 42);

    try testing.expect(val.ownsValidator(10));
    try testing.expect(val.ownsValidator(15));
    try testing.expect(val.ownsValidator(19));
    try testing.expect(!val.ownsValidator(9));
    try testing.expect(!val.ownsValidator(20));
    try testing.expectEqual(@as(u64, 10), val.validatorCount());
}

// ── Test 2: Duty computation ─────────────────────────────────────────

test "sim_validator: compute duties finds assignments" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    // Create a validator covering ALL validator indices (0..64).
    var val = SimValidator.init(allocator, 0, 64, 42);

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();

    // Advance state by one slot for duty computation.
    var advanced = try head_state.clone(allocator, .{ .transfer_cache = false });
    defer {
        advanced.deinit();
        allocator.destroy(advanced);
    }
    try state_transition.processSlots(allocator, advanced, current_slot + 1, .{});

    var duties = try val.computeDuties(allocator, advanced, current_slot + 1);
    defer {
        for (duties.committee_assignments.items) |*a| a.deinit(allocator);
        duties.committee_assignments.deinit(allocator);
    }

    // With all 64 validators, we must be the proposer.
    try testing.expect(duties.is_proposer);

    // With all 64 validators, we should have committee assignments.
    try testing.expect(duties.committee_assignments.items.len > 0);
}

// ── Test 3: Block production ─────────────────────────────────────────

test "sim_validator: produces block when proposer" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    // Validator covering all indices (guaranteed to be proposer).
    var val = SimValidator.init(allocator, 0, 64, 42);

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();
    const target_slot = current_slot + 1;

    // Advance state.
    var advanced = try head_state.clone(allocator, .{ .transfer_cache = false });
    defer {
        advanced.deinit();
        allocator.destroy(advanced);
    }
    try state_transition.processSlots(allocator, advanced, target_slot, .{});

    // Produce block.
    const result = try val.produceBlock(advanced, target_slot);
    try testing.expect(result != null);

    const block = result.?.signed_block;
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, block);
        allocator.destroy(block);
    }

    try testing.expectEqual(target_slot, block.message.slot);
    try testing.expectEqual(@as(u64, 1), val.blocks_proposed);
}

// ── Test 4: Skip proposal ────────────────────────────────────────────

test "sim_validator: skips proposal when skip_next_proposal is set" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    var val = SimValidator.init(allocator, 0, 64, 42);
    val.skip_next_proposal = true;

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();
    const target_slot = current_slot + 1;

    var advanced = try head_state.clone(allocator, .{ .transfer_cache = false });
    defer {
        advanced.deinit();
        allocator.destroy(advanced);
    }
    try state_transition.processSlots(allocator, advanced, target_slot, .{});

    const result = try val.produceBlock(advanced, target_slot);
    try testing.expect(result == null);
    try testing.expectEqual(@as(u64, 1), val.proposals_skipped);
    try testing.expect(!val.skip_next_proposal); // Reset after skip.
}

// ── Test 5: Attestation production ───────────────────────────────────

test "sim_validator: produces attestations for assigned committees" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    // Process TWO slots to have a block root in the state for attestation.
    // Block at slot N creates a block root available in state at slot N.
    // Attestation for slot N references getBlockRootAtSlot(N) which needs
    // slot N to be in the state's block_roots array.
    _ = try harness.sim.processSlot(false);
    _ = try harness.sim.processSlot(false);

    var val = SimValidator.init(allocator, 0, 64, 42);

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();
    // Attest to the previous slot (which has a block root in state).
    const att_slot = current_slot - 1;

    var atts = try val.produceAttestations(allocator, head_state, att_slot);
    defer atts.deinit(allocator);

    // With 64 validators all assigned, we should get attestations.
    try testing.expect(atts.attestations.items.len > 0);
    try testing.expect(val.attestations_produced > 0);

    // Each attestation should reference the correct slot.
    for (atts.attestations.items) |att| {
        try testing.expectEqual(att_slot, att.data.slot);
    }
}

// ── Test 6: Zero participation produces no attestations ──────────────

test "sim_validator: zero participation produces no attestations" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    _ = try harness.sim.processSlot(false);
    _ = try harness.sim.processSlot(false);

    var val = SimValidator.init(allocator, 0, 64, 42);
    val.participation_rate = 0.0;

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();

    var atts = try val.produceAttestations(allocator, head_state, current_slot - 1);
    defer atts.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), atts.attestations.items.len);
}

// ── Test 7: Skip attestations flag ───────────────────────────────────

test "sim_validator: skip_attestations flag prevents production" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    _ = try harness.sim.processSlot(false);
    _ = try harness.sim.processSlot(false);

    var val = SimValidator.init(allocator, 0, 64, 42);
    val.skip_attestations = true;

    const head_state = harness.sim.getHeadState() orelse unreachable;
    const current_slot = try head_state.state.slot();

    var atts = try val.produceAttestations(allocator, head_state, current_slot - 1);
    defer atts.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), atts.attestations.items.len);
}
