const support = @import("test_support.zig");
const std = @import("std");
const Gossipsub = @import("Gossipsub.zig");
const topic_mod = @import("topic.zig");
const test_topic = "/eth2/01020304/beacon_block/ssz_snappy";
const MessageId = Gossipsub.MessageId;
const protobuf = @import("protobuf.zig");
const Now = @import("../types.zig").Now;
const Credits = @import("turn.zig").Credits;
const Progress = @import("turn.zig").Progress;
const snappy = @import("snappy");
const receiveForTest = support.receiveMessage;
const testMessage = support.message;
const IwantOutcome = @import("metrics.zig").IwantOutcome;

fn ids(out: []u8, field: u32, list: []const MessageId) []const u8 {
    var writer = @import("protobuf.zig").Writer.init(out);
    for (list) |*id| writer.bytesField(field, id);
    return writer.written();
}

test "IWANT outcomes separate misses, suppression, the retransmission limit, queued and refused responses" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    g.sessions.rows[peer.index].io.tx.cancelStream(&g.messages.store);
    var known: [3]MessageId = undefined;
    for (&known, 0..) |*id, i| {
        var text: [8]u8 = undefined;
        const payload = try std.fmt.bufPrint(&text, "iwant {d}", .{i});
        _ = try g.publish(test_topic, payload, .{ .mono_ms = 1, .unix_s = 0 });
        id.* = topic_mod.validMessageId(test_topic, payload, .{});
    }
    var body: [256]u8 = undefined;
    const now: @import("../types.zig").Now = .{ .mono_ms = 2, .unix_s = 0 };
    support.control(&g, peer.index, .{ .idontwant = .{ .body = ids(&body, 1, &.{known[2]}) } }, now);
    const unknown: MessageId = @splat(9);
    support.control(&g, peer.index, .{ .iwant = .{ .body = ids(&body, 1, &.{ unknown, known[2], known[0], known[0], known[0], known[0] }) } }, now);
    const tx = &g.sessions.rows[peer.index].io.tx;
    const h = g.messages.history.message(g.messages.history.get(&g.messages.store, known[0]).?);
    for (0..@import("delivery.zig").per_peer_limit) |_| {
        if (tx.data.full()) break;
        _ = tx.queueData(&g.messages.store, h, .forward, .{ .bytes = g.options.tx_peer_bytes }, 2);
    }
    support.control(&g, peer.index, .{ .iwant = .{ .body = ids(&body, 1, &.{known[1]}) } }, now);
    for ([_]IwantOutcome{ .miss, .suppressed, .limited, .queued, .refused }, [_]u64{ 1, 1, 1, 3, 1 }) |outcome, count| {
        try std.testing.expectEqual(count, g.iwant_outcomes[@intFromEnum(outcome)]);
    }
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "gossip counts each consumed message once by topic kind and never on a work retry" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var compressed: [64]u8 = undefined;
    const message: protobuf.Message = .{ .topic = name, .data = compressed[0..try snappy.raw.compress("payload", &compressed)] };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    var turn = @import("turn.zig").Turn.init(&g.options, now, g.msg_scratch);
    turn.sink = g.message_sink;
    turn.large_used = true;
    turn.budget.work = 0;
    var credits = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.credits, g.receiveItem(g.sessions.ref(peer.index), .{ .message = message }, &turn, &credits));
    const counts = g.topic_metrics.get(name);
    try std.testing.expectEqual(@as(u64, 0), counts.received);
    try std.testing.expectEqual(@as(?usize, 1), receiveForTest(&g, peer.index, message, now));
    try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, message, now));
    try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, .{ .topic = name, .data = &.{5} }, now));
    try std.testing.expectEqual(@as(f64, 1), support.invalidDeliveries(&g));
    inbox.full = true;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "refused", 1));
    try std.testing.expectEqual(@as(u64, 1), g.messages.storage_refusals[@intFromEnum(@import("messages.zig").StorageRefusal.processor_capacity)]);
    try std.testing.expectEqual(@as(u64, 4), counts.received);
    try std.testing.expectEqual(@as(u64, 1), counts.duplicate);
    const unsubscribed = "/eth2/01020304/voluntary_exit/ssz_snappy";
    const unknown = "/eth2/01020304/beacon_blocks/ssz_snappy";
    for ([_][]const u8{ unsubscribed, unknown, unknown }) |topic| {
        try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, .{ .topic = topic, .data = message.data }, now));
    }
    try std.testing.expectEqual(@as(u64, 1), g.topic_metrics.get(unsubscribed).received);
    try std.testing.expectEqual(@as(u64, 2), g.topic_metrics.counts[@import("topic_policy.zig").kind_count].received);
    try std.testing.expectEqual(@as(u64, 4), counts.received);
    for (g.topic_metrics.counts) |kind| try std.testing.expectEqual(@as(u64, 0), kind.published);
}
