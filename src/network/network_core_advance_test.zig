const std = @import("std");
const Setup = @import("network_core_test_support.zig").Setup;
const Source = @import("wake_sources.zig").Source;

test "core advance uses supplied time and schedules deferred application shutdown" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    core.service.quiesceApplications();
    const before = core.wakeups(setup.pair.now, .{});
    try std.testing.expect(before.sources[@intFromEnum(Source.gossip)].runnable);
    var tick = setup.pair.now;
    tick.mono_ms += 1;
    const result = core.advance(setup.pair.io(), tick, .{}, .{}, .{});
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(tick, result.transport.now);
    try std.testing.expectEqual(.closed, core.service.applications);
    const after = core.wakeups(tick, .{});
    try std.testing.expect(!after.sources[@intFromEnum(Source.gossip)].runnable);
}

test "core close delivery schedules retirement before it becomes closed" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const core = &setup.client;
    const now = setup.pair.now;
    core.shutdown(now);
    try std.testing.expect(!core.isClosed());
    try setup.pair.pump();
    const closed = core.advance(setup.pair.io(), now, .{}, .{}, .{});
    try std.testing.expect(closed.failure == null);
    var closed_count: usize = 0;
    for (closed.transport_events) |event| closed_count += @intFromBool(event == .closed);
    try std.testing.expectEqual(@as(usize, 1), closed_count);
    try std.testing.expect(core.transport.engine.releasesPending());
    try std.testing.expect(!core.isClosed());
    const pending = core.wakeups(now, .{});
    try std.testing.expect(pending.sources[@intFromEnum(Source.transport_events)].runnable);
    const retired = core.advance(setup.pair.io(), now, .{}, .{}, .{});
    try std.testing.expect(retired.failure == null);
    try std.testing.expectEqual(@as(usize, 0), retired.transport_events.len);
    try std.testing.expect(core.isClosed());
    try std.testing.expect(!core.transport.engine.releasesPending());
}

test "core advance preserves completed events when readiness fails" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    const failed = try setup.pair.dial();
    try std.testing.expect(core.transport.engine.failSend(failed));
    const result = core.advance(setup.pair.io(), setup.pair.now, .{ .failure = error.WaitFailed }, .{}, .{});
    try std.testing.expectEqual(error.WaitFailed, result.failure.?);
    try std.testing.expectEqual(@as(usize, 1), result.transport_events.len);
    try std.testing.expect(result.transport_events[0] == .closed);
}
