//! Tests for `scheduler.zig`.

const std = @import("std");
const testing = std.testing;
const types = @import("../types.zig");
const event = @import("event.zig");
const Scheduler = @import("scheduler.zig").Scheduler;

fn voteFor(v: u32) event.Payload {
    return .{ .vote = .{ .val_index = v, .slot = 1, .head = types.genesis_root } };
}

test "popAt returns deliveries in order and only at the asked phase" {
    const scheduler = try testing.allocator.create(Scheduler);
    defer testing.allocator.destroy(scheduler);
    scheduler.init();

    scheduler.push(5, .before_tick, 1, &voteFor(1));
    scheduler.push(5, .before_tick, 0, &voteFor(2));
    scheduler.push(5, .after_tick, 0, &voteFor(3));
    scheduler.push(5, .before_tick, 0, &voteFor(4));
    try testing.expectEqual(@as(u32, 4), scheduler.len());

    try testing.expectEqual(@as(?event.Delivery, null), scheduler.popAt(4, .before_tick));
    try testing.expectEqual(@as(u32, 2), scheduler.popAt(5, .before_tick).?.payload.vote.val_index);
    try testing.expectEqual(@as(u32, 4), scheduler.popAt(5, .before_tick).?.payload.vote.val_index);
    try testing.expectEqual(@as(u32, 1), scheduler.popAt(5, .before_tick).?.payload.vote.val_index);
    try testing.expectEqual(@as(?event.Delivery, null), scheduler.popAt(5, .before_tick));
    try testing.expectEqual(@as(u32, 3), scheduler.popAt(5, .after_tick).?.payload.vote.val_index);
    try testing.expectEqual(@as(u32, 0), scheduler.len());
    try testing.expectEqual(@as(?event.Delivery, null), scheduler.popAt(6, .before_tick));
}

test "an empty scheduler pops nothing" {
    const scheduler = try testing.allocator.create(Scheduler);
    defer testing.allocator.destroy(scheduler);
    scheduler.init();
    try testing.expectEqual(@as(?event.Delivery, null), scheduler.popAt(0, .before_tick));
    try testing.expectEqual(@as(u32, 0), scheduler.len());
}
