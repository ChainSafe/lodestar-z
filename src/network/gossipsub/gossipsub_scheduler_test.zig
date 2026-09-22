const std = @import("std");
const support = @import("test_support.zig");
const Pair = @import("test_pair.zig").Pair;
const Event = @import("gossipsub.zig").Event;
const Budget = @import("turn.zig").Budget;

test "gossip maintenance yields between bounded topics and resumes without repeating them" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topics_per_pump = 4 });
    defer g.deinit();
    for ([_][]const u8{ "beacon_block", "beacon_aggregate_and_proof", "voluntary_exit" }) |name| {
        var wire: [@import("topic.zig").topic_max_len]u8 = undefined;
        try support.subscribe(&g, @import("topic.zig").build(.{ 1, 2, 3, 4 }, name, &wire));
    }
    const Clock = struct {
        elapsed: i96 = 0,
        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.elapsed += 300_000;
            return .{ .nanoseconds = self.elapsed };
        }
    };
    var clock: Clock = .{};
    var vtable = std.Io.Threaded.global_single_threaded.io().vtable.*;
    vtable.now = Clock.now;
    g.metrics_io = .{ .userdata = &clock, .vtable = &vtable };
    const now: @import("../types.zig").Now = .{ .mono_ms = 1, .unix_s = 0 };
    support.heartbeat(&g, now);
    g.maintainTopics(now);
    try std.testing.expectEqual(@as(u64, 1), g.maintenance.topics_serviced);
    try std.testing.expect(g.cycle.isActive());
    for (0..3) |_| g.maintainTopics(now);
    try std.testing.expect(!g.cycle.isActive());
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.topics_serviced);
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.time_yields);
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.mesh.count);
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.gossip.count);
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.retire.count);
    try std.testing.expectEqual(@as(u64, 1), g.maintenance.cycles.count);
}

test "gossip saturated peers rotate after shared call or output exhaustion" {
    for ([_]u16{ 32, 120, 128 }) |peers| {
        try saturatedPeers(peers, .calls);
        try saturatedPeers(peers, .output);
    }
}

fn saturatedPeers(peers: u16, budget: Budget) !void {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .connected_capacity = peers }, .{ .random_seed = 2 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const g = setup.shared.client.gossipsub;
    const stream = setup.clientStream();
    for (1..peers) |i| {
        _ = support.addPeer(g, .{ .index = @intCast(i), .generation = 100 }, .v1_2) orelse return error.TestUnexpectedResult;
    }
    // One writable QUIC stream isolates scheduler fairness from remote flow control.
    for (g.sessions.rows, 0..) |*row, index| {
        g.sessions.setOutbound(@intCast(index), .{ .live = .{ .stream = stream, .version = .v1_2 } });
        row.io.rx_ready = false;
        row.io.write_first = true;
        try std.testing.expectEqual(@as(usize, 0), row.io.tx.control.count);
    }
    if (budget == .output) {
        g.options.calls_per_pump = 4096;
        g.options.output_per_pump = 256;
    }
    g.sessions.cursor = 0;
    var progressed = std.StaticBitSet(128).initEmpty();
    const exhausted_before = g.io_metrics.turns_exhausted[@intFromEnum(budget)];
    const rounds = @divExact(peers, 4);
    for (0..rounds) |_| {
        for (g.sessions.rows) |*row| {
            for (row.io.tx.control.count..64) |_| try std.testing.expect(row.io.tx.inject(&.{0}, setup.shared.pair.now.mono_ms));
        }
        var events: [1]Event = undefined;
        const turn = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now, &events);
        try std.testing.expect(turn.exhausted().contains(budget));
        for (g.sessions.rows, 0..) |row, i| {
            if (row.io.tx.control.count < 64) progressed.set(i);
        }
    }
    try std.testing.expectEqual(@as(usize, peers), progressed.count());
    try std.testing.expectEqual(@as(u64, rounds), g.io_metrics.turns_exhausted[@intFromEnum(budget)] - exhausted_before);
    try std.testing.expect(g.io_metrics.ready_deferred[@intFromEnum(budget)] > 0);
    try std.testing.expectEqual(@as(u64, 0), g.io_metrics.write_would_block);
    for (g.sessions.rows) |row| try std.testing.expect(row.io.write_budget_deferred > 0);
}
