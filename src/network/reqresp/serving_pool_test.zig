const std = @import("std");
const Pool = @import("ServingPool.zig");
const AddressGroup = @import("udp").AddressGroup;
const RequestHandle = @import("events.zig").RequestHandle;
const codec = @import("codec.zig");

test "serving capacity bounds independent groups and retained executions" {
    var pool = try Pool.init(std.testing.allocator, 32, 1, codec.frame_scratch_max);
    defer pool.deinit(std.testing.allocator);
    var groups: [33]AddressGroup = undefined;
    for (&groups, 0..) |*group, index| group.* = .{ .ip4 = .{ 192, 0, @intCast(index) } };
    for (groups[0..32], 0..) |group, index| {
        const slot = pool.available(group).?;
        const scratch = pool.acquire(slot, .{ .index = @intCast(index), .generation = 1, .direction = .inbound }, group);
        try std.testing.expectEqual(@as(usize, codec.frame_scratch_max), scratch.len);
        try std.testing.expectEqual(@as(?u16, null), pool.available(group));
    }
    try std.testing.expectEqual(@as(?u16, null), pool.available(groups[32]));
    const retiring: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    const serving = pool.retain(retiring) orelse return error.TestUnexpectedResult;
    pool.retire(0);
    try std.testing.expectEqual(@as(?u16, null), pool.available(groups[0]));
    try std.testing.expectEqual(@as(?u16, null), pool.available(groups[32]));
    try std.testing.expect(pool.release(serving));
    try std.testing.expectEqual(@as(?u16, 0), pool.available(groups[32]));
    try std.testing.expectEqual(@as(usize, 32 * codec.frame_scratch_max), pool.scratch.len);
}

test "serving handles reject stale releases across retention and request reuse" {
    var pool = try Pool.init(std.testing.allocator, 1, 1, codec.frame_scratch_max);
    defer pool.deinit(std.testing.allocator);
    const group: AddressGroup = .{ .ip4 = .{ 192, 0, 2 } };
    const request: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    _ = pool.acquire(0, request, group);
    const first = pool.retain(request).?;
    try std.testing.expect(pool.retain(request) == null);
    try std.testing.expect(pool.release(first));
    try std.testing.expect(!pool.release(first));
    const second = pool.retain(request).?;
    try std.testing.expect(!pool.release(first));
    pool.retire(0);
    try std.testing.expect(pool.available(group) == null);
    try std.testing.expect(pool.release(second));
    try std.testing.expectEqual(@as(?u16, 0), pool.available(group));
    _ = pool.acquire(0, .{ .index = 0, .generation = 2, .direction = .inbound }, group);
    const third = pool.retain(.{ .index = 0, .generation = 2, .direction = .inbound }).?;
    try std.testing.expect(!pool.release(second));
    try std.testing.expect(!pool.release(.{ .index = 1, .generation = third.generation }));
    try std.testing.expect(pool.release(third));
    pool.retire(0);
}

test "serving generations exhaust without wrapping" {
    var pool = try Pool.init(std.testing.allocator, 1, 1, codec.frame_scratch_max);
    defer pool.deinit(std.testing.allocator);
    const group: AddressGroup = .{ .ip4 = .{ 192, 0, 2 } };
    const request: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    pool.entries[0].generation = std.math.maxInt(u64) - 1;
    _ = pool.acquire(0, request, group);
    const retained = pool.retain(request).?;
    try std.testing.expectEqual(std.math.maxInt(u64), retained.generation);
    try std.testing.expect(pool.release(retained));
    try std.testing.expect(pool.retain(request) == null);
    pool.retire(0);
    try std.testing.expect(pool.available(group) == null);
}
