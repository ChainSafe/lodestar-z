const std = @import("std");
const support = @import("test_support.zig");
const topic_mod = @import("topic.zig");
const IwantOutcome = @import("metrics.zig").IwantOutcome;
const MessageId = topic_mod.MessageId;

const name = "/eth2/01020304/beacon_block/ssz_snappy";

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
        _ = try g.publish(name, payload, .{ .mono_ms = 1, .unix_s = 0 });
        id.* = topic_mod.validMessageId(name, payload, .{});
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
