//! Validator API handlers.
//!
//! Implements the `/eth/v1/validator/*` Beacon API endpoints used by
//! validator clients to obtain duties and submit messages.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const preset = @import("preset").preset;

// ---------------------------------------------------------------------------
// Duty types
// ---------------------------------------------------------------------------

/// Proposer duty for a single slot in an epoch.
pub const ProposerDuty = struct {
    /// BLS public key of the proposer (48 bytes, hex-encoded in JSON).
    pubkey: [48]u8,
    /// Validator index of the proposer.
    validator_index: u64,
    /// Slot within the epoch for which this validator is the proposer.
    slot: u64,
};

/// Attester duty for a single validator in an epoch.
pub const AttesterDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    committee_index: u64,
    committee_length: u64,
    committees_at_slot: u64,
    validator_committee_index: u64,
    slot: u64,
};

/// Sync committee duty for a single validator in a sync period.
pub const SyncDuty = struct {
    pubkey: [48]u8,
    validator_index: u64,
    /// Indices of the validator within the sync committee.
    validator_sync_committee_indices: []const u64,
};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /eth/v1/validator/duties/proposer/{epoch}
///
/// Returns the proposer duties for every slot in the given epoch.
///
/// Note: A complete implementation requires access to the EpochCache built
/// from the head state (or the state at the start of the requested epoch).
/// The EpochCache is not yet wired into ApiContext; this handler returns a
/// stub array of SLOTS_PER_EPOCH entries with zero pubkeys and a proposer
/// index of 0 for every slot.  Replace once EpochCache access is available.
pub fn getProposerDuties(ctx: *ApiContext, epoch: u64) ![]ProposerDuty {
    // TODO: Wire up real EpochCache lookup.
    // Steps:
    //   1. Compute epoch_start_slot = epoch * SLOTS_PER_EPOCH.
    //   2. Load (or regen) the state at epoch_start_slot via ctx.regen.
    //   3. Read the epoch_cache.proposers[] array (one entry per slot).
    //   4. Fetch validator pubkeys from the state's validator list.
    //   5. Build and return the ProposerDuty array.
    const slots_per_epoch = preset.SLOTS_PER_EPOCH;
    const epoch_start = epoch * slots_per_epoch;

    const duties = try ctx.allocator.alloc(ProposerDuty, slots_per_epoch);
    errdefer ctx.allocator.free(duties);

    for (duties, 0..) |*duty, i| {
        duty.* = .{
            .pubkey = [_]u8{0} ** 48,
            .validator_index = 0,
            .slot = epoch_start + i,
        };
    }

    return duties;
}

/// GET /eth/v1/validator/duties/attester/{epoch}
///
/// Returns attester duties for the requested validators in the given epoch.
///
/// Note: Stub — returns NotImplemented until EpochCache is wired.
pub fn getAttesterDuties(
    _: *ApiContext,
    _: u64,
    _: []const u64,
) ![]AttesterDuty {
    // TODO: Implement once EpochCache and validator index lookup are available.
    return error.NotImplemented;
}

/// POST /eth/v1/validator/duties/sync/{epoch}
///
/// Returns sync committee duties for the requested validators in the given epoch.
///
/// Note: Stub — returns NotImplemented until SyncCommittee state access is wired.
pub fn getSyncDuties(
    _: *ApiContext,
    _: u64,
    _: []const u64,
) ![]SyncDuty {
    // TODO: Implement once sync committee state queries are available.
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getProposerDuties returns SLOTS_PER_EPOCH entries" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const duties = try getProposerDuties(&tc.ctx, 0);
    defer tc.ctx.allocator.free(duties);

    try std.testing.expectEqual(preset.SLOTS_PER_EPOCH, duties.len);
}

test "getProposerDuties assigns correct slots for epoch 0" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const duties = try getProposerDuties(&tc.ctx, 0);
    defer tc.ctx.allocator.free(duties);

    for (duties, 0..) |duty, i| {
        try std.testing.expectEqual(@as(u64, i), duty.slot);
    }
}

test "getProposerDuties assigns correct slots for epoch 3" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const epoch: u64 = 3;
    const duties = try getProposerDuties(&tc.ctx, epoch);
    defer tc.ctx.allocator.free(duties);

    const expected_start = epoch * preset.SLOTS_PER_EPOCH;
    try std.testing.expectEqual(expected_start, duties[0].slot);
    try std.testing.expectEqual(expected_start + preset.SLOTS_PER_EPOCH - 1, duties[duties.len - 1].slot);
}

test "getAttesterDuties returns NotImplemented" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAttesterDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
}

test "getSyncDuties returns NotImplemented" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
}
