const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;
const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;

pub const EffectiveBalanceIncrements = std.ArrayList(u16);
pub const EffectiveBalanceIncrementsRc = ReferenceCount(EffectiveBalanceIncrements);

pub fn getEffectiveBalanceIncrementsZeroed(allocator: Allocator, len: usize) !EffectiveBalanceIncrements {
    var increments = try EffectiveBalanceIncrements.initCapacity(allocator, len);
    try increments.resize(len);
    for (0..len) |i| {
        increments.items[i] = 0;
    }
    return increments;
}

pub fn getEffectiveBalanceIncrementsWithLen(allocator: Allocator, validator_count: usize) !EffectiveBalanceIncrements {
    const len = 1024 * @divFloor(validator_count + 1024, 1024);
    return getEffectiveBalanceIncrementsZeroed(allocator, len);
}

pub fn getEffectiveBalanceIncrements(allocator: Allocator, state: BeaconStateAllForks) !EffectiveBalanceIncrements {
    const validator_count = state.validators().items.len;
    var increments = try EffectiveBalanceIncrements.initCapacity(allocator, validator_count);
    try increments.resize(validator_count);

    for (0..validator_count) |i| {
        const validator = state.validators()[i];
        increments.items[i] = @divFloor(validator.effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT);
    }
}

// TODO: unit tests
