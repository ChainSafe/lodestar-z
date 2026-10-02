const std = @import("std");
const Schedule = @import("schedule.zig").Schedule;

test "schedule merge has an identity and is associative commutative and idempotent" {
    const schedules = [_]Schedule{
        .{},
        .{ .runnable = true },
        .{ .deadline_ms = 0 },
        .{ .deadline_ms = 25 },
        .{ .runnable = true, .deadline_ms = 50 },
        .{ .deadline_ms = std.math.maxInt(u64) },
    };
    for (schedules) |a| {
        try std.testing.expectEqualDeep(a, a.merge(.{}));
        try std.testing.expectEqualDeep(a, a.merge(a));
        for (schedules) |b| {
            try std.testing.expectEqualDeep(a.merge(b), b.merge(a));
            for (schedules) |c| {
                try std.testing.expectEqualDeep(a.merge(b).merge(c), a.merge(b.merge(c)));
            }
        }
    }
}

test "schedule waits distinguish runnable work expired deadlines and external pressure" {
    const blocked: Schedule = .{};
    try std.testing.expect(!blocked.due(100));
    try std.testing.expectEqual(@as(?u64, null), blocked.nextWakeup(100));
    try std.testing.expectEqual(@as(u32, 1000), blocked.waitMs(100, 1000));
    const timed: Schedule = .{ .deadline_ms = 150 };
    try std.testing.expect(!timed.due(100));
    try std.testing.expect(timed.due(150));
    try std.testing.expect(timed.due(200));
    try std.testing.expectEqual(@as(u32, 50), timed.waitMs(100, 1000));
    try std.testing.expectEqual(@as(u32, 10), timed.waitMs(100, 10));
    try std.testing.expectEqual(@as(u32, 0), timed.waitMs(200, 1000));
    const ready = timed.merge(.{ .runnable = true });
    try std.testing.expectEqual(@as(?u64, 150), ready.deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), ready.waitMs(100, 1000));
    const distant: Schedule = .{ .deadline_ms = std.math.maxInt(u64) };
    try std.testing.expectEqual(@as(u32, 1000), distant.waitMs(0, 1000));
}
