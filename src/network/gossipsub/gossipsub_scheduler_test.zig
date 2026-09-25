const std = @import("std");
const support = @import("test_support.zig");
const Pair = @import("test_pair.zig").Pair;
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
    var progressed = std.StaticBitSet(128).initEmpty();
    const exhausted_before = g.io_metrics.turns_exhausted[@intFromEnum(budget)];
    const rounds = @divExact(peers, 4);
    for (0..rounds) |_| {
        for (g.sessions.rows, 0..) |*row, index| {
            for (row.io.tx.control.count..64) |_| try std.testing.expect(row.io.tx.inject(&.{0}, setup.shared.pair.now.mono_ms));
            g.settle(@intCast(index));
        }
        const turn = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
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

/// Leaves the client's session at the head of the ready list with a frame of three items, one more
/// than a turn's item budget, and three more sessions behind it with output on one writable QUIC
/// stream. Returns the reader.
fn readerAhead(setup: *Pair, writers: *[3]u16) !u16 {
    const g = setup.shared.client.gossipsub;
    const reader = g.sessions.find(setup.shared.handles.client).?;
    const stream = setup.clientStream();
    for (writers, 1..) |*writer, i| writer.* = support.addPeer(g, .{ .index = @intCast(300 + i), .generation = 1 }, .v1_2).?.index;
    for (0..3) |_| _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.ready.len);
    g.options.items_per_pump = 2;
    const protobuf = @import("protobuf.zig");
    var body: [256]u8 = undefined;
    var rpc = protobuf.Writer.init(&body);
    for (0..3) |_| protobuf.writeSubscription(&rpc, true, "/eth2/01020304/beacon_block/ssz_snappy");
    var frame: [260]u8 = undefined;
    try std.testing.expect(g.sessions.receiveHandoff(reader, @import("frame.zig").writeFrame(&frame, rpc.written()), false));
    g.settle(reader);
    for (writers) |index| {
        g.sessions.setOutbound(index, .{ .live = .{ .stream = stream, .version = .v1_2 } });
        g.sendSubscriptions(index);
        try std.testing.expect(g.sessions.rows[index].io.tx.inject(&.{0}, setup.shared.pair.now.mono_ms));
        g.settle(index);
    }
    try std.testing.expectEqual(reader, g.sessions.ready.head);
    return reader;
}

test "gossip turn stopped by the receive item budget leaves its writable sessions waiting until their next visit" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .connected_capacity = 4 }, .{ .random_seed = 2 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const g = setup.shared.client.gossipsub;
    var writers: [3]u16 = undefined;
    _ = try readerAhead(&setup, &writers);
    // The turn starts 2 ms before the second phase bucket of a 12 s slot.
    var clock: @import("../slot_clock.zig").SlotClock = .{ .genesis_unix_ms = 1_000_000, .slot_duration_ms = 12_000 };
    clock.observe(.{ .mono_ms = setup.shared.pair.now.mono_ms, .unix_s = 0, .unix_ms = 1_000_000 + 12_000 + 748 });
    g.slot_clock = &clock;
    const items = @intFromEnum(Budget.items);
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u64, 1), g.io_metrics.stops[items]);
    try std.testing.expectEqualSlices(u64, &.{ 0, 3 }, &g.io_metrics.skipped[items]);
    try std.testing.expectEqual(@as(usize, 3), g.sessions.unserved[items]);
    for (writers) |index| try std.testing.expectEqual(@as(?Budget, .items), g.sessions.rows[index].unserved);
    // Cancelled output stops the wait at once; the others wait 5 ms, until the next turn visits them.
    g.cancelWrites(g.sessions.ref(writers[2]));
    try std.testing.expectEqual(@as(usize, 2), g.sessions.unserved[items]);
    setup.shared.pair.advance(5);
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.unserved[items]);
    try std.testing.expectEqual(@as(u64, 1), g.io_metrics.stops[items]);
    const unserved = &g.occupancy.unserved_ms[items];
    try std.testing.expectEqual(@as(u64, 2 * 2), unserved[0]);
    try std.testing.expectEqual(@as(u64, 2 * 3), unserved[1]);
    for (writers[0..2]) |index| try std.testing.expect(!g.sessions.rows[index].io.tx.pending());
    g.slot_clock = null;
}

test "gossip waiting sessions keep one mark across stops, take the latest stop's budget and drop it with the session" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .connected_capacity = 4 }, .{ .random_seed = 2 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const g = setup.shared.client.gossipsub;
    var writers: [3]u16 = undefined;
    const reader = try readerAhead(&setup, &writers);
    const items = @intFromEnum(Budget.items);
    const calls = @intFromEnum(Budget.calls);
    const waited = struct {
        fn total(spans: []const u64) u64 {
            var sum: u64 = 0;
            for (spans) |ms| sum += ms;
            return sum;
        }
    }.total;
    // An item stop marks all three writers.
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(usize, 3), g.sessions.unserved[items]);
    // With one call per turn, the next turn writes for the first writer and stops on calls: the
    // other two move to calls after their 3 ms under items, and the reader is skipped unmarked.
    g.options.calls_per_pump = 1;
    setup.shared.pair.advance(3);
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u64, 3 * 3), waited(&g.occupancy.unserved_ms[items]));
    try std.testing.expectEqualSlices(usize, &.{ 2, 0, 0, 0, 0, 0, 0 }, &g.sessions.unserved);
    try std.testing.expectEqual(@as(?Budget, null), g.sessions.rows[writers[0]].unserved);
    for (writers[1..]) |index| try std.testing.expectEqual(@as(?Budget, .calls), g.sessions.rows[index].unserved);
    try std.testing.expectEqual(@as(?Budget, null), g.sessions.rows[reader].unserved);
    try std.testing.expectEqualSlices(u64, &.{ 1, 2 }, &g.io_metrics.skipped[calls]);
    // A second call stop skips the last writer again: its one mark keeps counting once.
    setup.shared.pair.advance(4);
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u64, 2 * 4), waited(&g.occupancy.unserved_ms[calls]));
    try std.testing.expectEqual(@as(usize, 1), g.sessions.unserved[calls]);
    try std.testing.expectEqual(@as(u64, 2), g.io_metrics.stops[calls]);
    try std.testing.expectEqualSlices(u64, &.{ 2, 3 }, &g.io_metrics.skipped[calls]);
    // Its connection closes 5 ms later, as `retireConnection` sees it, and its wait ends there.
    setup.shared.pair.advance(5);
    g.last_now_ms = setup.shared.pair.now.mono_ms;
    g.connectionClosed(g.sessions.rows[writers[2]].conn);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.unserved[calls]);
    try std.testing.expectEqual(@as(u64, 2 * 4 + 5), waited(&g.occupancy.unserved_ms[calls]));
    setup.shared.pair.advance(5);
    _ = support.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u64, 2 * 4 + 5), waited(&g.occupancy.unserved_ms[calls]));
    try std.testing.expectEqual(@as(u64, 3 * 3), waited(&g.occupancy.unserved_ms[items]));
}
