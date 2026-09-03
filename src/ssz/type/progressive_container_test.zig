//! Tests for `progressive_container.zig`.

const std = @import("std");
const UintType = @import("uint.zig").UintType;
const FixedListType = @import("list.zig").FixedListType;
const FixedProgressiveContainerType = @import("progressive_container.zig").FixedProgressiveContainerType;
const VariableProgressiveContainerType = @import("progressive_container.zig").VariableProgressiveContainerType;

test "ProgressiveContainerType " {
    // Square with active_fields=[1, 0, 1]
    const Square = FixedProgressiveContainerType(struct {
        side: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 1, 0, 1 });

    // Circle with active_fields=[0, 1, 1]
    const Circle = FixedProgressiveContainerType(struct {
        radius: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 0, 1, 1 });

    var square: Square.Type = undefined;
    square.side = 10;
    square.color = 5;

    var circle: Circle.Type = undefined;
    circle.radius = 7;
    circle.color = 5;

    // Test that both serialize correctly
    var square_buf: [Square.fixed_size]u8 = undefined;
    _ = Square.serializeIntoBytes(&square, &square_buf);

    var circle_buf: [Circle.fixed_size]u8 = undefined;
    _ = Circle.serializeIntoBytes(&circle, &circle_buf);

    // Test deserialization
    var square2: Square.Type = undefined;
    try Square.deserializeFromBytes(&square_buf, &square2);
    try std.testing.expectEqual(square.side, square2.side);
    try std.testing.expectEqual(square.color, square2.color);

    // Test hash tree root - color should be at the same gindex for both
    var square_root: [32]u8 = undefined;
    try Square.hashTreeRoot(&square, &square_root);

    var circle_root: [32]u8 = undefined;
    try Circle.hashTreeRoot(&circle, &circle_root);

    // The roots should be different since the structures are different
    try std.testing.expect(!std.mem.eql(u8, &square_root, &circle_root));
}

test "ProgressiveContainerType - variable" {
    const allocator = std.testing.allocator;
    const Foo = VariableProgressiveContainerType(struct {
        a: FixedListType(UintType(8), 32, .{}),
        b: FixedListType(UintType(8), 32, .{}),
        c: FixedListType(UintType(8), 32, .{}),
    }, &[_]u1{ 1, 1, 0, 1 });

    var f: Foo.Type = undefined;
    f.a = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    f.b = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    f.c = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 10);
    defer f.a.deinit(allocator);
    defer f.b.deinit(allocator);
    defer f.c.deinit(allocator);
    f.a.expandToCapacity();
    f.b.expandToCapacity();
    f.c.expandToCapacity();

    const f_buf = try allocator.alloc(u8, Foo.serializedSize(&f));
    defer allocator.free(f_buf);
    _ = Foo.serializeIntoBytes(&f, f_buf);

    var f2: Foo.Type = Foo.default_value;
    try Foo.deserializeFromBytes(allocator, f_buf, &f2);
    defer Foo.deinit(allocator, &f2);
}
