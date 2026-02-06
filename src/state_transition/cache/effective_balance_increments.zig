const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;

pub const EffectiveBalanceIncrements = std.ArrayList(u16);
pub const EffectiveBalanceIncrementsRc = ReferenceCount(EffectiveBalanceIncrements);

pub fn getEffectiveBalanceIncrementsZeroed(allocator: Allocator, len: usize, capacity: usize) !EffectiveBalanceIncrements {
    var increments = try EffectiveBalanceIncrements.initCapacity(allocator, capacity);
    try increments.resize(len);
    for (0..len) |i| {
        increments.items[i] = 0;
    }
    return increments;
}

pub fn getEffectiveBalanceIncrementsWithLen(allocator: Allocator, validator_count: usize) !EffectiveBalanceIncrements {
    const capacity = 1024 * @divFloor(validator_count + 1024, 1024);
    return getEffectiveBalanceIncrementsZeroed(allocator, validator_count, capacity);
}

/// unused, but may be useful for testing or other purposes
pub fn getEffectiveBalanceIncrements(allocator: Allocator, state: AnyBeaconState) !EffectiveBalanceIncrements {
    const validators = try state.validatorsSlice(allocator);
    defer allocator.free(validators);

    var increments = try EffectiveBalanceIncrements.initCapacity(allocator, validators.len);
    try increments.resize(validators.len);

    for (validators, 0..) |validator, i| {
        increments.items[i] = @divFloor(validator.effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT);
    }
}

// TODO: unit tests
