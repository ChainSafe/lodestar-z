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
const CachedBeaconState = context.CachedBeaconState;
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const EpochCache = state_transition.EpochCache;

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
/// Uses the EpochCache from the head CachedBeaconState to look up real
/// proposer assignments and validator pubkeys. Falls back to a zeroed
/// stub if the head state is unavailable.
pub fn getProposerDuties(ctx: *ApiContext, epoch: u64) ![]ProposerDuty {
    const slots_per_epoch = preset.SLOTS_PER_EPOCH;
    const epoch_start = epoch * slots_per_epoch;

    const duties = try ctx.allocator.alloc(ProposerDuty, slots_per_epoch);
    errdefer ctx.allocator.free(duties);

    // Try to get real data from the head state's epoch cache.
    const head_state: ?*CachedBeaconState = blk: {
        const cb = ctx.head_state orelse break :blk null;
        break :blk cb.getHeadStateFn(cb.ptr);
    };

    if (head_state) |state| {
        const epoch_cache = state.epoch_cache;
        // Check if this epoch cache covers the requested epoch.
        // The epoch cache has proposers for its current epoch.
        if (epoch_cache.epoch == epoch) {
            // Read proposers from the epoch cache and resolve pubkeys from the state.
            const validators = try state.state.validatorsSlice(ctx.allocator);
            defer ctx.allocator.free(validators);

            for (duties, 0..) |*duty, i| {
                const proposer_index = epoch_cache.proposers[i];
                const pubkey = if (proposer_index < validators.len) validators[proposer_index].pubkey else [_]u8{0} ** 48;
                duty.* = .{
                    .pubkey = pubkey,
                    .validator_index = proposer_index,
                    .slot = epoch_start + i,
                };
            }
            return duties;
        }
    }

    // Fallback: return stub duties with zeroed pubkeys.
    for (duties, 0..) |*duty, i| {
        duty.* = .{
            .pubkey = [_]u8{0} ** 48,
            .validator_index = 0,
            .slot = epoch_start + i,
        };
    }

    return duties;
}

/// POST /eth/v1/validator/duties/attester/{epoch}
///
/// Returns attester duties for the requested validators in the given epoch.
///
/// Uses the EpochCache shuffling to compute committee assignments.
pub fn getAttesterDuties(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) ![]AttesterDuty {
    const cb = ctx.head_state orelse return error.NotImplemented;
    const state = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
    const epoch_cache = state.epoch_cache;

    // We can serve duties for the current or next epoch.
    const shuffling = epoch_cache.getShufflingAtEpochOrNull(epoch) orelse return error.NotImplemented;

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);

    const committees_per_slot = shuffling.committees_per_slot;
    const epoch_start = epoch * preset.SLOTS_PER_EPOCH;

    var result = std.ArrayListUnmanaged(AttesterDuty).empty;
    errdefer result.deinit(ctx.allocator);

    // For each requested validator, find which slot/committee they belong to.
    for (validator_indices) |vi| {
        // Walk all committees in the epoch to find this validator.
        for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
            const slot = epoch_start + slot_offset;
            for (0..committees_per_slot) |committee_idx| {
                const committee = try epoch_cache.getBeaconCommittee(@intCast(slot), @intCast(committee_idx));
                for (committee, 0..) |member, pos| {
                    if (member == vi) {
                        const pubkey = if (vi < validators.len) validators[vi].pubkey else [_]u8{0} ** 48;
                        try result.append(ctx.allocator, .{
                            .pubkey = pubkey,
                            .validator_index = vi,
                            .committee_index = @intCast(committee_idx),
                            .committee_length = @intCast(committee.len),
                            .committees_at_slot = @intCast(committees_per_slot),
                            .validator_committee_index = @intCast(pos),
                            .slot = slot,
                        });
                        break;
                    }
                }
            }
        }
    }

    return result.toOwnedSlice(ctx.allocator);
}

/// POST /eth/v1/validator/duties/sync/{epoch}
///
/// Returns sync committee duties for the requested validators in the given epoch.
///
/// Uses the sync committee cache from the epoch cache.
pub fn getSyncDuties(
    ctx: *ApiContext,
    epoch: u64,
    validator_indices: []const u64,
) ![]SyncDuty {
    const cb = ctx.head_state orelse return error.NotImplemented;
    const state = cb.getHeadStateFn(cb.ptr) orelse return error.StateNotAvailable;
    const epoch_cache = state.epoch_cache;

    // Get the indexed sync committee for this epoch.
    const sync_committee = epoch_cache.getIndexedSyncCommitteeAtEpoch(epoch) catch return error.NotImplemented;
    const sync_indices = sync_committee.getValidatorIndices();

    const validators = try state.state.validatorsSlice(ctx.allocator);
    defer ctx.allocator.free(validators);

    var result = std.ArrayListUnmanaged(SyncDuty).empty;
    errdefer result.deinit(ctx.allocator);

    for (validator_indices) |vi| {
        // Collect all positions where this validator appears in the sync committee.
        var positions = std.ArrayListUnmanaged(u64).empty;
        errdefer positions.deinit(ctx.allocator);

        for (sync_indices, 0..) |member, pos| {
            if (member == vi) {
                try positions.append(ctx.allocator, @intCast(pos));
            }
        }

        if (positions.items.len > 0) {
            const pubkey = if (vi < validators.len) validators[vi].pubkey else [_]u8{0} ** 48;
            try result.append(ctx.allocator, .{
                .pubkey = pubkey,
                .validator_index = vi,
                .validator_sync_committee_indices = try positions.toOwnedSlice(ctx.allocator),
            });
        } else {
            positions.deinit(ctx.allocator);
        }
    }

    return result.toOwnedSlice(ctx.allocator);
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

test "getAttesterDuties returns NotImplemented without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getAttesterDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
}

test "getSyncDuties returns NotImplemented without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getSyncDuties(&tc.ctx, 0, &[_]u64{});
    try std.testing.expectError(error.NotImplemented, result);
}
