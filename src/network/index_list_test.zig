const std = @import("std");
const l = @import("index_list.zig");

test "index lists unlink ends and middle and reuse independent memberships" {
    var rows: [3]struct { a: l.Link = .{}, b: l.Link = .{} } = @splat(.{});
    var first: l.List = .{};
    var second: l.List = .{};
    first.append(&rows, "a", 1);
    first.prepend(&rows, "a", 0);
    first.append(&rows, "a", 2);
    second.append(&rows, "b", 1);
    first.remove(&rows, "a", 1);
    try std.testing.expectEqual(@as(u32, 0), first.pop(&rows, "a").?);
    try std.testing.expectEqual(@as(u32, 2), first.pop(&rows, "a").?);
    try std.testing.expect(first.pop(&rows, "a") == null);
    try std.testing.expectEqual(@as(u32, 1), second.pop(&rows, "b").?);
    first.append(&rows, "a", 1);
    try std.testing.expectEqual(@as(u32, 1), first.pop(&rows, "a").?);
}
