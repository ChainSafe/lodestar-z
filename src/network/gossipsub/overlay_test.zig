const topic_mod = @import("topic.zig");
const protobuf = @import("protobuf.zig");
const Overlay = @import("overlay.zig").Overlay;
const Set = @import("sessions.zig").PeerSet;
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
            _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, g.overlay.topicString(topic), true);
        }
        return .{ .g = g, .topic = topic };
    }
    fn context(self: *Fixture, now: u64) Context {
        return .{ .sessions = self.g.sessions, .peers = &self.g.peers, .now = now, .options = &self.g.options, .snapshot = &self.g.cycle.scores };
    }
};

test "gossip policy mesh trimming preserves highest scores and outbound quota" {
    var f = try Fixture.init(16);
    defer f.g.deinit();
    for (0..16) |peer| {
        f.g.overlay.rows[f.topic].mesh.set(peer);
        f.g.peers.scores.graft(@intCast(peer), f.topic, 1);
        if (peer < 4) try std.testing.expect(f.g.peers.scores.setAppScore(@intCast(peer), 100));
    }
    f.g.peers.rows[f.g.sessions.rows[14].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.sessions.rows[15].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, c.mesh_d), f.g.overlay.mesh(f.topic).count());
    for (0..4) |peer| try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(peer));
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(14));
    try std.testing.expect(f.g.overlay.mesh(f.topic).isSet(15));
}

test "gossip policy outbound repair applies inside mesh degree limits" {
    var f = try Fixture.init(10);
    defer f.g.deinit();
    for (0..8) |peer| f.g.overlay.rows[f.topic].mesh.set(peer);
    f.g.peers.rows[f.g.sessions.rows[8].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.sessions.rows[9].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
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
    try std.testing.expect(f.g.sessions.rows[0].io.tx.injectFrame(bytes, true, null, 1) != null);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.overlay.mesh(f.topic).count());
    f.g.sessions.rows[0].io.tx.cancelStream(&f.g.messages.store);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 1), f.g.overlay.mesh(f.topic).count());
    f.g.sessions.rows[0].io.tx.cancelStream(&f.g.messages.store);
    try std.testing.expect(f.g.sessions.rows[0].io.tx.injectFrame(bytes, true, null, 2) != null);
    try std.testing.expect(f.g.peers.scores.setAppScore(0, -1));
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.overlay.mesh(f.topic).count());
    try std.testing.expect(f.g.sessions.rows[0].outbound == .closing);
    try std.testing.expect(!f.g.overlay.gossipRecipients(&context, f.topic, 1).isSet(0));
}

test "gossip partial peer turn queues subscription before outgoing GRAFT" {
    var f = try Fixture.init(2);
    defer f.g.deinit();
    var pair: @import("../test_support.zig").Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    f.g.options.peers_per_pump = 1;
    f.g.sessions.rows[0].io.tx.ready = false;
    const target = &f.g.sessions.rows[1].io.tx;
    try std.testing.expect(target.subscription_dirty.isSet(f.topic));
    f.g.heartbeat_at = 1;
    _ = @import("test_support.zig").pump(&f.g, &pair.client, .{ .mono_ms = 1, .unix_s = 0 }, &.{});
    try std.testing.expectEqual(@as(usize, 1), f.g.sessions.cursor);
    try std.testing.expect(f.g.overlay.inMesh(f.topic, 1));
    try std.testing.expectEqual(@as(usize, 2), target.critical.count);
    for (0..2) |i| {
        const bytes = f.g.writeSegment(f.g.sessions.ref(1));
        var prefix = protobuf.Reader.init(bytes);
        const len = try prefix.varint();
        var rpc = protobuf.RpcReader.init(bytes[bytes.len - len ..]);
        const item = (try rpc.next()).?;
        if (i == 0) {
            try std.testing.expect(item == .subscription and item.subscription.subscribe);
            try std.testing.expectEqualStrings(f.g.overlay.topicString(f.topic), item.subscription.topic);
        } else {
            try std.testing.expectEqualStrings(f.g.overlay.topicString(f.topic), item.graft);
        }
        try std.testing.expect(try rpc.next() == null);
        f.g.advanceWrite(f.g.sessions.ref(1), bytes.len, 1);
    }
}

test "gossip GRAFT admission preserves subscription and mesh state at both queue boundaries" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    const context = f.context(2);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    const tx = &f.g.sessions.rows[0].io.tx;
    const bytes = f.g.msg_scratch[0..tx.critical.bytes.len];
    @memset(bytes, 0);
    try std.testing.expect(tx.injectFrame(bytes, true, null, 1) != null);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expect(tx.subscription_dirty.isSet(f.topic));
    try std.testing.expect(!f.g.overlay.inMesh(f.topic, 0));
    tx.critical.reset();
    const body = protobuf.subscriptionSize(f.g.overlay.topicString(f.topic));
    const subscription_size = protobuf.varintLen(body) + body;
    try std.testing.expect(tx.injectFrame(bytes[0 .. bytes.len - subscription_size], true, null, 1) != null);
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expect(!tx.subscription_dirty.isSet(f.topic));
    try std.testing.expect(!f.g.overlay.inMesh(f.topic, 0));
    try std.testing.expectEqual(@as(usize, 2), tx.critical.count);
    for (0..3) |_| {
        const segment = tx.segment(&f.g.messages.store);
        if (segment.len == 0) break;
        f.g.advanceWrite(f.g.sessions.ref(0), segment.len, 2);
    }
    try std.testing.expect(!tx.pending());
    f.g.overlay.maintain(&context, f.topic);
    try std.testing.expect(f.g.overlay.inMesh(f.topic, 0));
    try std.testing.expectEqual(@as(usize, 1), tx.critical.count);
}

test "gossip policy adaptive gossip randomizes recipients and fanout expires" {
    var f = try Fixture.init(64);
    defer f.g.deinit();
    f.g.markDirect(f.g.sessions.rows[0].conn);
    try std.testing.expect(f.g.peers.scores.setAppScore(1, -10_000));
    var context = f.context(2);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    const recipients = f.g.overlay.gossipRecipients(&context, f.topic, 0.5);
    try std.testing.expectEqual(@as(usize, 31), recipients.count());
    try std.testing.expect(!recipients.isSet(0) and !recipients.isSet(1));
    var high_selected = false;
    for (32..64) |peer| if (recipients.isSet(peer)) {
        high_selected = true;
    };
    try std.testing.expect(high_selected);
    f.g.overlay.setLocal(&context, f.topic, false);
    for (f.g.sessions.rows) |*row| if (row.active) {
        row.outbound = .{ .live = .{ .stream = .{ .conn = row.conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    };
    const fanout = f.g.overlay.maintainFanout(&context, f.topic, true);
    try std.testing.expectEqual(@as(usize, c.mesh_d), fanout.count());
    try std.testing.expect(!fanout.isSet(0) and !fanout.isSet(1));
    context.now += c.fanout_ttl_ms;
    _ = f.g.overlay.maintainFanout(&context, f.topic, false);
    try std.testing.expectEqual(@as(usize, 0), fanout.count());
}

test "gossip PRUNE exhaustion ends eligibility even after queue capacity returns" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    var context = f.context(1);
    f.g.overlay.onGraft(&context, f.topic, 0);
    const io = &f.g.sessions.rows[0].io;
    const full = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
    defer std.testing.allocator.free(full);
    @memset(full, 0);
    try std.testing.expect(io.tx.injectFrame(full, true, null, 1) != null);
    try std.testing.expect(f.g.unsubscribe(f.g.overlay.topicString(f.topic)));
    try std.testing.expect(f.g.sessions.rows[0].outbound == .closing);
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    io.tx.cancelStream(&f.g.messages.store);
    context.now = c.prune_backoff_ms * 2;
    try std.testing.expect(f.g.subscribe(f.g.overlay.topicString(f.topic)));
    f.g.overlay.onGraft(&context, f.topic, 0);
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    try std.testing.expect(!io.tx.pending());
}

test "gossip policy review I3 bounded shuffle consumes one draw per swap" {
    var f = try Fixture.init(3);
    defer f.g.deinit();
    const context = f.context(1);
    f.g.cycle.takeSnapshot(context.sessions, context.peers, context.now);
    f.g.overlay.rng = .{ .s = .{ 0, 1, 0, 0 } };
    var expected = f.g.overlay.rng;
    for (0..2) |_| _ = expected.next();
    const recipients = f.g.overlay.gossipRecipients(&context, f.topic, 1);
    try std.testing.expectEqual(@as(usize, 3), recipients.count());
    try std.testing.expectEqualSlices(u64, &expected.s, &f.g.overlay.rng.s);
}

test "overlay unsubscribe and disconnect retire membership and score together" {
    var f = try Fixture.init(2);
    defer f.g.deinit();
    var context = f.context(1);
    for (0..2) |peer| f.g.overlay.onGraft(&context, f.topic, @intCast(peer));
    const first = f.g.sessions.rows[0].logical.index;
    const second = f.g.sessions.rows[1].logical.index;
    try std.testing.expect(f.g.peers.scores.topics[@as(usize, first) * c.topics_cap + f.topic].in_mesh);
    try std.testing.expect(f.g.peers.scores.topics[@as(usize, second) * c.topics_cap + f.topic].in_mesh);
    context.now = 60_001;
    _ = f.g.overlay.peerSubscription(&context, 0, f.g.overlay.topicString(f.topic), false);
    try std.testing.expect(!f.g.overlay.subscribers(f.topic).isSet(0));
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(0));
    try std.testing.expect(!f.g.peers.scores.topics[@as(usize, first) * c.topics_cap + f.topic].in_mesh);
    const penalties = f.g.peers.scores.penalties.message_deficit;
    _ = f.g.overlay.peerSubscription(&context, 0, f.g.overlay.topicString(f.topic), false);
    try std.testing.expectEqual(penalties, f.g.peers.scores.penalties.message_deficit);
    f.g.overlay.peerDisconnected(&context, 1);
    try std.testing.expect(!f.g.overlay.subscribers(f.topic).isSet(1));
    try std.testing.expect(!f.g.overlay.mesh(f.topic).isSet(1));
    try std.testing.expect(!f.g.peers.scores.topics[@as(usize, second) * c.topics_cap + f.topic].in_mesh);
}

test "gossip policy topic capacity supports two full fork subnet sets" {
    var gossip = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer gossip.deinit();
    const overlay = gossip.overlay;
    var name: [topic_mod.name_max_len]u8 = undefined;
    var buffer: [topic_mod.topic_max_len]u8 = undefined;
    for (0..3) |fork| {
        if (fork == 2) {
            for (&overlay.rows, 0..) |*topic, index| {
                if (topic.active and std.mem.startsWith(u8, overlay.topicString(@intCast(index)), "/eth2/00000000/")) {
                    try std.testing.expect(gossip.unsubscribe(overlay.topicString(@intCast(index))));
                }
            }
        }
        const digest: topic_mod.ForkDigest = .{ @intCast(fork), 0, 0, 0 };
        for ([_]topic_mod.Kind{ .beacon_attestation, .data_column_sidecar, .sync_committee }) |kind| {
            for (0..kind.countMax()) |subnet| {
                const formatted = try std.fmt.bufPrint(&name, "{s}_{d}", .{ @tagName(kind), subnet });
                try std.testing.expect(gossip.subscribe(topic_mod.build(digest, formatted, &buffer)));
            }
        }
        for (std.enums.values(topic_mod.Kind)) |kind| {
            if (kind.countMax() == 1) try std.testing.expect(gossip.subscribe(topic_mod.build(digest, @tagName(kind), &buffer)));
        }
    }
    try std.testing.expect(overlay.findTopic("/eth2/00000000/beacon_block/ssz_snappy") == null);
    try std.testing.expect(overlay.findTopic("/eth2/01000000/beacon_block/ssz_snappy") != null);
    try std.testing.expect(overlay.findTopic("/eth2/02000000/beacon_block/ssz_snappy") != null);
}

test "gossip state intern snapshots an aliased retiring topic string" {
    var overlay = @import("overlay.zig").Overlay.init(1);
    defer overlay.deinit(std.testing.allocator);
    const oversized = [_]u8{'x'} ** (topic_mod.topic_max_len + 1);
    try std.testing.expectEqual(@as(?u16, null), overlay.internVacant(&oversized));
    try std.testing.expectEqual(@as(?u16, null), overlay.internVacant("invalid"));
    const original = "/eth2/00000000/a/ssz_snappy/b/ssz_snappy";
    const shorter = "/eth2/00000000/a/ssz_snappy";
    try std.testing.expectEqual(@as(?u16, 0), overlay.internVacant(original));
    const input = overlay.topicString(0)[0..shorter.len];
    overlay.rows[0].active = false;
    try std.testing.expectEqual(@as(?u16, 0), overlay.internVacant(input));
    try std.testing.expectEqualStrings(shorter, overlay.topicString(0));
    try std.testing.expectEqual(@as(u64, 2), overlay.rows[0].generation);
    const maximum = "/eth2/00000000/sync_committee_contribution_and_proof/ssz_snappy";
    try std.testing.expectEqual(topic_mod.topic_max_len, maximum.len);
    try std.testing.expectEqual(@as(?u16, 1), overlay.internVacant(maximum));
    try std.testing.expectEqualStrings(maximum, overlay.topicString(1));
}
