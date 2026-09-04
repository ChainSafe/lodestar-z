const std = @import("std");
const schedule = @import("schedule.zig");
const types = @import("../types.zig");

const address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4001 } };

test "schedule retains immutable datagrams until their exact deadline without duplication" {
    var queue = try schedule.Queue.init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);
    const owner = @import("api.zig").Handle{ .index = 0, .generation = 9 };
    var bytes = [_]u8{ 1, 2, 3 };
    try queue.put(owner, .{ .bytes = &bytes, .to = address, .transmit_at_ns = 1000001 });
    bytes[0] = 99;
    try std.testing.expect(queue.ready(0, 1000000) == null);
    try std.testing.expectEqual(@as(?u64, 1000001), queue.nextDeadline());
    const sent = queue.ready(0, 1000001).?;
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, sent.bytes);
    try std.testing.expect(sent.to.eql(address));
    queue.remove(0);
    try std.testing.expect(queue.ready(0, 1000001) == null);
    try std.testing.expect(queue.nextDeadline() == null);
}

test "schedule reserves storage for each connection and rejects duplicate generation output" {
    var queue = try schedule.Queue.init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);
    var bytes = [_]u8{1};
    const sent = types.Sent{ .bytes = &bytes, .to = address, .transmit_at_ns = 100 };
    try queue.put(.{ .index = 0, .generation = 1 }, sent);
    try std.testing.expectError(error.Occupied, queue.put(.{ .index = 0, .generation = 1 }, sent));
    try queue.put(.{ .index = 1, .generation = 2 }, sent);
    try std.testing.expectEqual(@as(usize, 2), queue.count);
    try std.testing.expectEqual(@as(u32, 1), queue.owner(0).?.generation);
    queue.remove(0);
    try queue.put(.{ .index = 0, .generation = 3 }, sent);
    try std.testing.expectEqual(@as(u32, 3), queue.owner(0).?.generation);
}

test "schedule rotates busy connections across aggregate work limited turns" {
    var cursor = schedule.Cursor{};
    const active = [_]u16{ 4, 1, 9 };
    var serviced = [_]u8{0} ** 10;
    for (0..6) |_| {
        var turn = schedule.Turn.init(1, 2);
        while (turn.takeWork()) {
            const index = cursor.next(&active).?;
            serviced[index] += 1;
            turn.recordSend();
            if (!turn.canSend()) break;
        }
        try std.testing.expectEqual(@as(u32, 1), turn.sent);
        try std.testing.expectEqual(@as(u32, 1), turn.work);
    }
    for (active) |index| try std.testing.expectEqual(@as(u8, 2), serviced[index]);
    try std.testing.expect(cursor.next(&.{}) == null);
    try std.testing.expectEqual(@as(?u16, 3), cursor.next(&.{3}));
}

test "schedule rounds relative waits up without overflow or early transmission" {
    try std.testing.expectEqual(@as(u64, 1), schedule.remainingMs(1000001, 1000000));
    try std.testing.expectEqual(@as(u64, 2), schedule.remainingMs(1000001, 0));
    try std.testing.expectEqual(@as(u64, 0), schedule.remainingMs(1000001, 1000001));
    try std.testing.expectEqual(@as(u64, 18446744073710), schedule.remainingMs(std.math.maxInt(u64), 0));
}

fn allocateQueue(allocator: std.mem.Allocator) !void {
    var queue = try schedule.Queue.init(allocator, 4);
    defer queue.deinit(allocator);
}

test "schedule startup allocation failure leaves no retained storage" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocateQueue, .{});
}
