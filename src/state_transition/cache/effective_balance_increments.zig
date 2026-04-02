const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;

pub const EffectiveBalanceIncrements = std.array_list.AlignedManaged(u16, null);
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

test "effectiveBalanceIncrementsInit basic allocation" {
    const allocator = std.testing.allocator;
    var increments = try effectiveBalanceIncrementsInit(allocator, 100);
    defer increments.deinit();

    try std.testing.expectEqual(@as(usize, 100), increments.items.len);
    // Capacity should be rounded up to next 1024 boundary
    try std.testing.expectEqual(@as(usize, 1024), increments.capacity);
    // All values should be zero
    for (increments.items) |val| {
        try std.testing.expectEqual(@as(u16, 0), val);
    }
}

test "effectiveBalanceIncrementsInit capacity rounding" {
    const allocator = std.testing.allocator;

    // Exactly 1024 validators
    {
        var increments = try effectiveBalanceIncrementsInit(allocator, 1024);
        defer increments.deinit();
        try std.testing.expectEqual(@as(usize, 1024), increments.items.len);
        try std.testing.expectEqual(@as(usize, 2048), increments.capacity);
    }

    // Just over 1024 boundary
    {
        var increments = try effectiveBalanceIncrementsInit(allocator, 1025);
        defer increments.deinit();
        try std.testing.expectEqual(@as(usize, 1025), increments.items.len);
        try std.testing.expectEqual(@as(usize, 2048), increments.capacity);
    }

    // Zero validators
    {
        var increments = try effectiveBalanceIncrementsInit(allocator, 0);
        defer increments.deinit();
        try std.testing.expectEqual(@as(usize, 0), increments.items.len);
    }
}
