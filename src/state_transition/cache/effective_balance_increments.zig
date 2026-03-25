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
    effective_balance_increments: *const EffectiveBalanceIncrements,
    active_indices: []const ValidatorIndex,
    validators: []const Validator.Type,
    out: []u16,
) void {
    const validator_count = validators.len;
    std.debug.assert(effective_balance_increments.items.len >= validator_count);
    std.debug.assert(out.len >= validator_count);
    std.debug.assert(active_indices.len <= validator_count);

    // Zero the entire output buffer, then selectively set balances for active non-slashed validators.
    // This is more efficient than copying all balances and then zeroing inactive ones, because
    // active_indices is typically a small subset and we avoid touching every element twice.
    @memset(out[0..validator_count], 0);

    for (active_indices) |vi| {
        if (!validators[vi].slashed) {
            out[vi] = effective_balance_increments.items[vi];
        }
    }
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

    // Only the slashed field matters — active/inactive is determined by active_indices
    var validators: [5]Validator.Type = undefined;
    for (&validators) |*v| {
        v.* = std.mem.zeroes(Validator.Type);
    }
    validators[2].slashed = true; // validator 2: active but slashed -> zero

    var out: [5]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(&increments, active_indices, &validators, &out);

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
    }

    var out: [3]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(&increments, active_indices, &validators, &out);

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
    }

    var out: [3]u16 = undefined;
    getEffectiveBalanceIncrementsZeroInactive(&increments, active_indices, &validators, &out);

    try std.testing.expectEqual(@as(u16, 0), out[0]);
    try std.testing.expectEqual(@as(u16, 0), out[1]);
    try std.testing.expectEqual(@as(u16, 0), out[2]);
}
