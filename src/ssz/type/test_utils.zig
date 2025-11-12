const std = @import("std");
const assert = std.debug.assert;
const isFixedType = @import("type_kind.zig").isFixedType;
const isBitVectorType = @import("bit_vector.zig").isBitVectorType;

/// Tests that two values of the same type `T` hash to the same root.
pub fn expectEqualRoots(comptime T: type, expected: T.Type, actual: T.Type) !void {
    var expected_buf: [32]u8 = undefined;
    var actual_buf: [32]u8 = undefined;

    try T.hashTreeRoot(&expected, &expected_buf);
    try T.hashTreeRoot(&actual, &actual_buf);

    try std.testing.expectEqualSlices(u8, &expected_buf, &actual_buf);
}

/// Tests that two values of the same type `T` hash to the same root.
///
/// Same as `expectEqualRoots`, except with allocation.
pub fn expectEqualRootsAlloc(comptime T: type, allocator: std.mem.Allocator, expected: T.Type, actual: T.Type) !void {
    var expected_buf: [32]u8 = undefined;
    var actual_buf: [32]u8 = undefined;

    try T.hashTreeRoot(allocator, &expected, &expected_buf);
    try T.hashTreeRoot(allocator, &actual, &actual_buf);

    try std.testing.expectEqualSlices(u8, &expected_buf, &actual_buf);
}

/// Tests that two values of the same type `T` serialize to the same byte array.
pub fn expectEqualSerialized(comptime T: type, expected: T.Type, actual: T.Type) !void {
    var expected_buf: [T.fixed_size]u8 = undefined;
    var actual_buf: [T.fixed_size]u8 = undefined;

    _ = T.serializeIntoBytes(&expected, &expected_buf);
    _ = T.serializeIntoBytes(&actual, &actual_buf);
    try std.testing.expectEqualSlices(u8, &expected_buf, &actual_buf);
}

/// Tests that two values of the same type `T` serialize to the same byte array.
///
/// Same as `expectEqualSerialized`, except with allocation.
pub fn expectEqualSerializedAlloc(comptime T: type, allocator: std.mem.Allocator, expected: T.Type, actual: T.Type) !void {
    const expected_buf = try allocator.alloc(u8, T.serializedSize(&expected));
    defer allocator.free(expected_buf);
    const actual_buf = try allocator.alloc(u8, T.serializedSize(&actual));
    defer allocator.free(actual_buf);

    _ = T.serializeIntoBytes(&expected, expected_buf);
    _ = T.serializeIntoBytes(&actual, actual_buf);
    try std.testing.expectEqualSlices(u8, expected_buf, actual_buf);
}
