const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Validator = types.phase0.Validator;

pub const EffectiveBalanceIncrements = std.ArrayList(u16);
pub const EffectiveBalanceIncrementsRc = ReferenceCount(EffectiveBalanceIncrements);

/// Allocates `EffectiveBalanceIncrements` with capacity slightly larger than `validator_count`.
///
/// This allows some slack for later usage of `effective_balance_increments` to not have to reallocate
/// for a while.
pub fn effectiveBalanceIncrementsInit(allocator: Allocator, validator_count: usize) !EffectiveBalanceIncrements {
    const capacity = 1024 * @divFloor(validator_count + 1024, 1024);
    var increments = try EffectiveBalanceIncrements.initCapacity(allocator, capacity);
    try increments.resize(validator_count);
    @memset(increments.items[0..validator_count], 0);
    return increments;
}

/// Returns effective balance increments with inactive and slashed validators zeroed out.
///
/// This is consumed by fork-choice which uses deltas, so we return "by increment" (in ether) values.
/// Inactive validators and slashed active validators get zeroed out so they don't contribute
/// to fork-choice weight calculations.
///
/// `active_indices` must be sorted in ascending order (as produced by EpochShuffling).
/// Writes into caller-provided `out` buffer. The caller owns the memory.
pub fn getEffectiveBalanceIncrementsZeroInactive(
    effective_balance_increments: EffectiveBalanceIncrements,
    active_indices: []const ValidatorIndex,
    validators: []const Validator.Type,
    out: []u16,
) void {
    const validator_count = validators.len;
    std.debug.assert(effective_balance_increments.items.len >= validator_count);
    std.debug.assert(out.len >= validator_count);
    // active_indices must not exceed validator_count
    std.debug.assert(active_indices.len <= validator_count);

    // Copy all effective balance increments into the output buffer
    @memcpy(out[0..validator_count], effective_balance_increments.items[0..validator_count]);

    // Walk through validators and active_indices together.
    // active_indices is sorted, so we advance through it with index j.
    // For each validator:
    //   - if it matches active_indices[j], it's active: keep balance unless slashed
    //   - otherwise it's inactive: zero it out
    var j: usize = 0;
    for (0..validator_count) |i| {
        if (j < active_indices.len and i == active_indices[j]) {
            // Active validator
            j += 1;
            if (validators[i].slashed) {
                out[i] = 0;
            }
        } else {
            // Inactive validator
            out[i] = 0;
        }
    }

    // Assert we consumed all active indices
    std.debug.assert(j == active_indices.len);
}

test "getEffectiveBalanceIncrementsZeroInactive: zeroes inactive and slashed validators" {
    const allocator = std.testing.allocator;

    // Set up 5 validators with varying balances
    var increments = try effectiveBalanceIncrementsInit(allocator, 5);
    defer increments.deinit();

    increments.items[0] = 32; // active, not slashed -> keep
    increments.items[1] = 31; // inactive -> zero
    increments.items[2] = 32; // active, slashed -> zero
    increments.items[3] = 30; // active, not slashed -> keep
    increments.items[4] = 28; // inactive -> zero

    // active_indices: validators 0, 2, 3 are active (sorted)
    const active_indices = &[_]ValidatorIndex{ 0, 2, 3 };

    // Build minimal validators - only slashed field matters for this function
    const current_epoch: u64 = 10;
    var validators: [5]Validator.Type = undefined;
    for (&validators) |*v| {
        v.* = std.mem.zeroes(Validator.Type);
        // Default: inactive (exit_epoch <= current_epoch)
        v.activation_epoch = 0;
        v.exit_epoch = 0;
    }
    // Validator 0: active, not slashed
    validators[0].activation_epoch = 0;
    validators[0].exit_epoch = current_epoch + 1;
    validators[0].slashed = false;
    // Validator 1: inactive
    validators[1].activation_epoch = 0;
    validators[1].exit_epoch = current_epoch - 1;
    validators[1].slashed = false;
    // Validator 2: active, slashed
    validators[2].activation_epoch = 0;
    validators[2].exit_epoch = current_epoch + 1;
    validators[2].slashed = true;
    // Validator 3: active, not slashed
    validators[3].activation_epoch = 0;
    validators[3].exit_epoch = current_epoch + 1;
    validators[3].slashed = false;
    // Validator 4: inactive
    validators[4].activation_epoch = 0;
    validators[4].exit_epoch = current_epoch - 1;
    validators[4].slashed = false;

    var out: [5]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(increments, active_indices, &validators, &out);

    try std.testing.expectEqual(@as(u16, 32), out[0]); // active, not slashed -> kept
    try std.testing.expectEqual(@as(u16, 0), out[1]); // inactive -> zeroed
    try std.testing.expectEqual(@as(u16, 0), out[2]); // active, slashed -> zeroed
    try std.testing.expectEqual(@as(u16, 30), out[3]); // active, not slashed -> kept
    try std.testing.expectEqual(@as(u16, 0), out[4]); // inactive -> zeroed
}

test "getEffectiveBalanceIncrementsZeroInactive: all active" {
    const allocator = std.testing.allocator;

    var increments = try effectiveBalanceIncrementsInit(allocator, 3);
    defer increments.deinit();

    increments.items[0] = 32;
    increments.items[1] = 32;
    increments.items[2] = 32;

    const active_indices = &[_]ValidatorIndex{ 0, 1, 2 };

    var validators: [3]Validator.Type = undefined;
    for (&validators) |*v| {
        v.* = std.mem.zeroes(Validator.Type);
        v.activation_epoch = 0;
        v.exit_epoch = 100;
        v.slashed = false;
    }

    var out: [3]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(increments, active_indices, &validators, &out);

    try std.testing.expectEqual(@as(u16, 32), out[0]);
    try std.testing.expectEqual(@as(u16, 32), out[1]);
    try std.testing.expectEqual(@as(u16, 32), out[2]);
}

test "getEffectiveBalanceIncrementsZeroInactive: all inactive" {
    const allocator = std.testing.allocator;

    var increments = try effectiveBalanceIncrementsInit(allocator, 3);
    defer increments.deinit();

    increments.items[0] = 32;
    increments.items[1] = 31;
    increments.items[2] = 30;

    const active_indices = &[_]ValidatorIndex{};

    var validators: [3]Validator.Type = undefined;
    for (&validators) |*v| {
        v.* = std.mem.zeroes(Validator.Type);
        v.activation_epoch = 0;
        v.exit_epoch = 0;
        v.slashed = false;
    }

    var out: [3]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(increments, active_indices, &validators, &out);

    try std.testing.expectEqual(@as(u16, 0), out[0]);
    try std.testing.expectEqual(@as(u16, 0), out[1]);
    try std.testing.expectEqual(@as(u16, 0), out[2]);
}
