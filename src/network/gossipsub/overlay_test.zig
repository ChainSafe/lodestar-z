const topic_mod = @import("topic.zig");
const protobuf = @import("protobuf.zig");
const Overlay = @import("overlay.zig").Overlay;
const Set = @import("state.zig").PeerSet;
const std = @import("std");
const c = @import("constants.zig");
const Context = @import("overlay.zig").Context;
const assert = std.debug.assert;
const Fixture = struct {
    g: @import("gossipsub.zig").Gossipsub,
    topic: u16,

    fn init(count: usize) !Fixture {
        var g = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 17 });
        errdefer g.deinit();
        const name = "/eth2/01020304/beacon_block/ssz_snappy";
        assert(g.subscribe(name));
        const topic = g.overlay.findTopic(name).?;
        for (0..count) |index| {
            const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(index), .generation = 1 }, .v1_2).?;
            g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), topic, peer.index, true);
        }
        return .{ .g = g, .topic = topic };
    }
    fn context(self: *Fixture, now: u64) Context {
        return .{ .state = self.g.state, .peers = &self.g.peers, .scores = &self.g.scores, .now = now, .options = &self.g.options, .snapshot = &self.g.cycle.scores };
    }
};

test "gossip policy mesh trimming preserves highest scores and outbound quota" {
    var f = try Fixture.init(16);
    defer f.g.deinit();
    for (0..16) |peer| {
        f.g.overlay.mesh(f.topic).set(peer);
        f.g.scores.graft(@intCast(peer), f.topic, 1);
        if (peer < 4) try std.testing.expect(f.g.scores.setAppScore(@intCast(peer), 100));
    }
    f.g.peers.rows[f.g.state.peers[14].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.state.peers[15].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, c.mesh_d), f.g.overlay.mesh(f.topic).count());
    for (0..4) |peer| try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(peer));
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(14));
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(15));
}

test "gossip policy outbound repair applies inside mesh degree limits" {
    var f = try Fixture.init(10);
    defer f.g.deinit();
    for (0..8) |peer| f.g.overlay.mesh(f.topic).set(peer);
    f.g.peers.rows[f.g.state.peers[8].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.state.peers[9].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 10), f.g.overlay.mesh(f.topic).count());
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(8));
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(9));
}

test "gossip policy mesh queue pressure preserves required action ownership" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    const context = f.context(2);
    const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.overlay.mesh(f.topic).count());
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 1), f.g.overlay.mesh(f.topic).count());
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 2) != null);
    try std.testing.expect(f.g.scores.setAppScore(0, -1));
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.overlay.mesh(f.topic).count());
    try std.testing.expect(f.g.overlay.pending_prunes[f.topic].isSet(0));
    f.g.overlay.expireActions(30_002, 30_000);
    try std.testing.expect(f.g.overlay.retire.isSet(0));
}

test "gossip policy adaptive gossip randomizes recipients and fanout expires" {
    var f = try Fixture.init(64);
    defer f.g.deinit();
    f.g.markDirect(f.g.state.peers[0].conn);
    try std.testing.expect(f.g.scores.setAppScore(1, -10_000));
    var context = f.context(2);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    const recipients = f.g.overlay.gossipRecipients(&context, f.topic, 0.5);
    try std.testing.expectEqual(@as(usize, 31), recipients.count());
    try std.testing.expect(!recipients.isSet(0) and !recipients.isSet(1));
    var high_selected = false;
    for (32..64) |peer| if (recipients.isSet(peer)) {
        high_selected = true;
    };
    try std.testing.expect(high_selected);
    f.g.overlay.setSubscribed(f.topic, false);
    for (f.g.state.peers) |*row| if (row.active) {
        row.outbound = .{ .live = .{ .conn = row.conn, .id = 2, .slot = 0 } };
    };
    const fanout = f.g.overlay.maintainFanout(&context, f.topic, true);
    try std.testing.expectEqual(@as(usize, c.mesh_d), fanout.count());
    try std.testing.expect(!fanout.isSet(0) and !fanout.isSet(1));
    context.now += c.fanout_ttl_ms;
    _ = f.g.overlay.maintainFanout(&context, f.topic, false);
    try std.testing.expectEqual(@as(usize, 0), fanout.count());
}

test "gossip policy review I2 pending PRUNE gates resubscription GRAFT until queue recovery" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    var context = f.context(1);
    f.g.overlay.onGraft(&context, f.topic, 0);
    const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
    f.g.last_now_ms = 1;
    const name = f.g.overlay.topicString(f.topic);
    try std.testing.expect(f.g.unsubscribe(name));
    try std.testing.expect(f.g.overlay.pending_prunes[f.topic].isSet(0));
    context.now = 2;
    f.g.overlay.onGraft(&context, f.topic, 0);
    try std.testing.expectEqual(@as(f64, 2), f.g.scores.behaviour[f.g.state.peers[0].logical.index]);
    try std.testing.expectEqual(@as(u64, 2), f.g.scores.penalties.graft_backoff);
    context.now = 11_001;
    f.g.last_now_ms = context.now;
    try std.testing.expect(f.g.subscribe(name));
    f.g.overlay.onGraft(&context, f.topic, 0);
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    try std.testing.expectEqual(@as(?u64, 1), f.g.overlay.pending_since[0]);
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    try std.testing.expect(!f.g.overlay.pending_prunes[f.topic].isSet(0));
    try std.testing.expectEqual(@as(?u64, null), f.g.overlay.pending_since[0]);
    var expected: [32 + topic_mod.topic_max_len]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    writer.varint(protobuf.pruneRpcSize(name, c.prune_backoff_ms / 1000));
    protobuf.writePruneRpc(&writer, name, c.prune_backoff_ms / 1000);
    const sent = f.g.state.peers[0].io.segment(&f.g.messages.store);
    try std.testing.expectEqualSlices(u8, writer.written(), sent);
    _ = f.g.state.peers[0].io.advance(&f.g.messages.store, sent.len);
    context.now = 71_002;
    f.g.overlay.onGraft(&context, f.topic, 0);
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(0));
    f.g.overlay.expireActions(context.now, 30_000);
    try std.testing.expect(!f.g.overlay.retire.isSet(0));
    f.g.overlay.mesh(f.topic).unset(0);
    f.g.scores.prune(f.g.state.peers[0].logical.index, f.topic, context.now);
    f.g.overlay.retire.set(0);
    f.g.overlay.onGraft(&context, f.topic, 0);
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
}

test "gossip policy delayed PRUNE preserves the effective remote backoff" {
    for ([_]u64{ 501, 2_001 }) |queued_at| {
        var f = try Fixture.init(1);
        defer f.g.deinit();
        var context = f.context(1);
        const logical = f.g.state.peers[0].logical;
        const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
        defer std.testing.allocator.free(bytes);
        @memset(bytes, 0);
        try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
        f.g.overlay.prune(&context, f.topic, 0, 1_000);
        context.now = queued_at;
        f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
        f.g.overlay.maintain(&context, f.topic);
        try std.testing.expect(f.g.overlay.pending_prunes[f.topic].isSet(0));
        try std.testing.expectEqual(@as(u64, 1_001), f.g.peers.backoff(logical, f.topic).until);
        f.g.state.peers[0].io.resetTx(&f.g.messages.store);
        f.g.overlay.maintain(&context, f.topic);
        try std.testing.expect(!f.g.overlay.pending_prunes[f.topic].isSet(0));
        const expired = queued_at >= 1_001;
        const seconds: u64 = if (expired) c.prune_backoff_ms / 1000 else 1;
        const local_until = queued_at + seconds * 1000;
        try std.testing.expectEqual(local_until, f.g.peers.backoff(logical, f.topic).until);
        var expected: [32 + topic_mod.topic_max_len]u8 = undefined;
        var writer = protobuf.Writer.init(&expected);
        const name = f.g.overlay.topicString(f.topic);
        writer.varint(protobuf.pruneRpcSize(name, seconds));
        protobuf.writePruneRpc(&writer, name, seconds);
        const sent = f.g.state.peers[0].io.segment(&f.g.messages.store);
        try std.testing.expectEqualSlices(u8, writer.written(), sent);
        _ = f.g.state.peers[0].io.advance(&f.g.messages.store, sent.len);
        context.now = queued_at + seconds * 1000 - 1;
        f.g.overlay.maintain(&context, f.topic);
        try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
        context.now = local_until + c.backoff_slack_heartbeats * context.options.heartbeat_interval_ms;
        f.g.overlay.maintain(&context, f.topic);
        try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(0));
    }
}

test "gossip policy review I3 bounded shuffle consumes one draw per swap" {
    var f = try Fixture.init(3);
    defer f.g.deinit();
    const context = f.context(1);
    f.g.cycle.takeSnapshot(context.state, context.scores, context.now);
    f.g.overlay.rng = .{ .s = .{ 0, 1, 0, 0 } };
    var expected = f.g.overlay.rng;
    for (0..2) |_| _ = expected.next();
    const recipients = f.g.overlay.gossipRecipients(&context, f.topic, 1);
    try std.testing.expectEqual(@as(usize, 3), recipients.count());
    try std.testing.expectEqualSlices(u64, &expected.s, &f.g.overlay.rng.s);
}

fn maintainFastHeartbeat(g: *@import("gossipsub.zig").Gossipsub, topic: u16, now: u64) void {
    g.overlay.maintain(&.{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .now = now, .options = &g.options }, topic);
}

test "gossip policy final review positive remainder respects rounded remote PRUNE deadline" {
    var g = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 17, .heartbeat_interval_ms = 1 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const topic = g.overlay.findTopic(name).?;
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2, &.{ .identity = .{ .bytes = [_]u8{1} ** 39 }, .address = .unspecified, .direction = .inbound }, .{ .mono_ms = 1, .unix_s = 0 }).admitted.index;
    g.overlay.setSubscription(&g.overlayContext(g.last_now_ms), topic, peer, true);
    const logical = g.state.peers[peer].logical;
    const full = try std.testing.allocator.alloc(u8, g.options.critical_bytes);
    defer std.testing.allocator.free(full);
    @memset(full, 0);
    try std.testing.expect(g.state.peers[peer].io.appendControl(full, true, null, 1) != null);
    g.overlay.prune(&.{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .now = 1, .options = &g.options }, topic, peer, 1000);
    maintainFastHeartbeat(&g, topic, 1000);
    try std.testing.expect(g.overlay.pending_prunes[topic].isSet(peer));
    try std.testing.expectEqual(@as(u64, 1001), g.peers.backoff(logical, topic).until);
    try std.testing.expectEqual(@as(?u64, 1), g.overlay.pending_since[peer]);
    try std.testing.expectEqual(@as(u64, 1), g.peers.backoff(logical, topic).pruned_at);
    g.state.peers[peer].io.resetTx(&g.messages.store);
    maintainFastHeartbeat(&g, topic, 1000);
    try std.testing.expect(!g.overlay.pending_prunes[topic].isSet(peer));
    var expected: [128]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    writer.varint(protobuf.pruneRpcSize(name, 1));
    protobuf.writePruneRpc(&writer, name, 1);
    const sent = g.state.peers[peer].io.segment(&g.messages.store);
    try std.testing.expectEqualSlices(u8, writer.written(), sent);
    _ = g.state.peers[peer].io.advance(&g.messages.store, sent.len);
    maintainFastHeartbeat(&g, topic, 1003);
    try std.testing.expect(!g.overlay.mesh(topic).isSet(peer));
    try std.testing.expectEqual(@as(u64, 2000), g.peers.backoff(logical, topic).until);
    try std.testing.expectEqual(@as(u64, 1), g.peers.backoff(logical, topic).pruned_at);
    maintainFastHeartbeat(&g, topic, 2001);
    try std.testing.expect(!g.overlay.mesh(topic).isSet(peer));
    maintainFastHeartbeat(&g, topic, 2002);
    try std.testing.expect(g.overlay.mesh(topic).isSet(peer));
}

test "overlay unsubscribe and disconnect retire membership and score together" {
    var f = try Fixture.init(2);
    defer f.g.deinit();
    var context = f.context(1);
    for (0..2) |peer| f.g.overlay.onGraft(&context, f.topic, @intCast(peer));
    const first = f.g.state.peers[0].logical.index;
    const second = f.g.state.peers[1].logical.index;
    try std.testing.expect(f.g.scores.topics[@as(usize, first) * c.topics_cap + f.topic].in_mesh);
    try std.testing.expect(f.g.scores.topics[@as(usize, second) * c.topics_cap + f.topic].in_mesh);
    context.now = 60_001;
    f.g.overlay.setSubscription(&context, f.topic, 0, false);
    try std.testing.expect(!f.g.overlay.subscribers(f.topic).isSet(0));
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    try std.testing.expect(!f.g.scores.topics[@as(usize, first) * c.topics_cap + f.topic].in_mesh);
    const penalties = f.g.scores.penalties.message_deficit;
    f.g.overlay.setSubscription(&context, f.topic, 0, false);
    try std.testing.expectEqual(penalties, f.g.scores.penalties.message_deficit);
    f.g.overlay.peerDisconnected(&context, 1);
    try std.testing.expect(!f.g.overlay.subscribers(f.topic).isSet(1));
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(1));
    try std.testing.expect(!f.g.scores.topics[@as(usize, second) * c.topics_cap + f.topic].in_mesh);
    try std.testing.expectEqual(@as(u16, 0), f.g.overlay.pending_count[1]);
}
