const std = @import("std");
const c = @import("custody.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;

// Literal outputs from consensus-specs v1.7.0-alpha.11, commit
// 7d5f3348d7b947851861745be9ce0ba30e526531, specs/fulu/das-core.md:get_custody_groups.
// Extracted Python source SHA256: 9aa7c369849da48f2810db79c05022d8e4f471ab7c20afab152938b38e5b476e.
test "custody pinned independent vectors and integer byte order" {
    const cases = [_]struct { id: [32]u8, expected: []const u8, hashes: u16 }{
        .{ .id = @splat(0), .expected = &.{ 1, 17, 19, 42, 75, 87, 102, 117 }, .hashes = 8 },
        .{ .id = @splat(255), .expected = &.{ 1, 17, 19, 42, 47, 75, 87, 102 }, .hashes = 8 },
        .{ .id = ordered_id, .expected = &.{ 40, 57, 61, 84, 102, 105, 113, 120 }, .hashes = 9 },
    };
    for (&cases) |*case| {
        var work = try c.Derivation.init(&case.id, .{ .groups = 128, .columns = 128 }, 8);
        const groups = (try work.step(64)).?;
        try equal(@as(usize, 8), groups.count());
        for (case.expected) |group| try expect(groups.isSet(group));
        try equal(case.hashes, work.hashes);
    }
}
const ordered_id: [32]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

test "custody resumable near-full duplicates and work exhaustion discard partial groups" {
    var work = try c.Derivation.init(&ordered_id, .{ .groups = 128, .columns = 128 }, 127);
    try expect(try work.step(64) == null);
    try equal(@as(u16, 64), work.hashes);
    var result: ?c.Groups = null;
    for (0..8) |_| result = try work.step(64);
    try equal(@as(u16, 545), work.hashes);
    try equal(@as(usize, 127), result.?.count());
    try expect(!result.?.isSet(89));
    work = try c.Derivation.init(&ordered_id, .{ .groups = 128, .columns = 128 }, 127);
    _ = try work.step(64);
    work.hashes = 4096;
    try std.testing.expectError(error.WorkLimit, work.step(64));
    try equal(@as(usize, 0), work.groups.count());
    try std.testing.expectError(error.WorkLimit, work.step(64));
}

test "custody group column mapping independent runtime and preset boundaries" {
    var work = try c.Derivation.init(&ordered_id, .{ .groups = 64, .columns = 128 }, 8);
    const groups = (try work.step(64)).?;
    for ([_]u8{ 20, 38, 40, 41, 49, 56, 57, 61 }) |group| try expect(groups.isSet(group));
    try equal(@as(u16, 9), work.hashes);
    var columns: [128]u16 = undefined;
    const config: c.Config = .{ .groups = 64, .columns = 128 };
    try equal(@as(usize, 2), try config.columnsForGroup(20, &columns));
    try std.testing.expectEqualSlices(u16, &.{ 20, 84 }, columns[0..2]);
    try std.testing.expectError(error.InvalidGroup, config.columnsForGroup(64, &columns));
    try std.testing.expectError(error.OutputTooSmall, config.columnsForGroup(20, columns[0..1]));
    const preset_columns = @import("preset").NUMBER_OF_COLUMNS;
    work = try c.Derivation.init(&ordered_id, .{ .groups = @min(128, preset_columns), .columns = preset_columns }, @min(128, preset_columns));
    try equal(@as(usize, @min(128, preset_columns)), (try work.step(0)).?.count());
    try equal(@as(u16, 0), work.hashes);
    work = try c.Derivation.init(&ordered_id, config, 0);
    try equal(@as(usize, 0), (try work.step(0)).?.count());
    try std.testing.expectError(error.InvalidCount, c.Derivation.init(&ordered_id, config, 65));
    for ([_]c.Config{ .{ .groups = 0, .columns = 128 }, .{ .groups = 129, .columns = 128 }, .{ .groups = 3, .columns = 128 }, .{ .groups = 64, .columns = 0 } }) |invalid| {
        try std.testing.expectError(error.InvalidConfig, c.Derivation.init(&ordered_id, invalid, 1));
    }
}
