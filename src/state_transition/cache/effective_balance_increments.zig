const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const ReferenceCount = @import("../utils/reference_count.zig").ReferenceCount;

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

// TODO: unit tests

test "effectiveBalanceIncrementsInit - basic" {
    const allocator = std.testing.allocator;
    var increments = try effectiveBalanceIncrementsInit(allocator, 1000);
    defer increments.deinit();

    try std.testing.expectEqual(@as(usize, 1000), increments.items.len);
    // Capacity should be rounded up to next 1024 boundary
    try std.testing.expectEqual(@as(usize, 1024), increments.capacity);
    // All values should be zero
    for (increments.items) |v| {
        try std.testing.expectEqual(@as(u16, 0), v);
    }
}

test "effectiveBalanceIncrementsInit - capacity rounding" {
    const allocator = std.testing.allocator;

    // Exactly 1024 validators → capacity = 2048 (1024 * ((1024 + 1024) / 1024))
    var inc1 = try effectiveBalanceIncrementsInit(allocator, 1024);
    defer inc1.deinit();
    try std.testing.expectEqual(@as(usize, 1024), inc1.items.len);
    try std.testing.expectEqual(@as(usize, 2048), inc1.capacity);

    // 0 validators → capacity = 1024 (1024 * ((0 + 1024) / 1024))
    var inc0 = try effectiveBalanceIncrementsInit(allocator, 0);
    defer inc0.deinit();
    try std.testing.expectEqual(@as(usize, 0), inc0.items.len);
    try std.testing.expectEqual(@as(usize, 1024), inc0.capacity);

    // 2000 validators → capacity = 3072 (1024 * ((2000 + 1024) / 1024))
    var inc2k = try effectiveBalanceIncrementsInit(allocator, 2000);
    defer inc2k.deinit();
    try std.testing.expectEqual(@as(usize, 2000), inc2k.items.len);
    // (2000 + 1024) / 1024 = 2 (integer division), 1024 * 2 = 2048... wait
    // Actually: 1024 * @divFloor(2000 + 1024, 1024) = 1024 * @divFloor(3024, 1024) = 1024 * 2 = 2048
    try std.testing.expectEqual(@as(usize, 2048), inc2k.capacity);
}
