const std = @import("std");
const t = @import("types.zig");
const enr = @import("enr.zig");
const custody = @import("custody.zig");
const Catalog = @import("catalog.zig").Catalog;
const dialing = @import("dialing.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9001 } };
const local: t.PeerId = .{ .bytes = @splat(0) };
const opts: t.Options = .{ .capacity = 4, .max_peers = 4, .target_peers = 4, .min_outbound = 0, .outbound_reserve = 1 };

fn candidate(tag: u8, sync: u8) !enr.Candidate {
    var secret: [32]u8 = @splat(0);
    secret[31] = tag;
    const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&secret);
    const peer = t.PeerId.fromPublicKey(&key.publicKey());
    return .{ .peer = peer, .node_id = try custody.nodeId(&peer), .sequence = 1, .record_hash = @splat(0), .addresses = .{ address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = sync, .custody_group_count = null };
}
fn admit(c: *Catalog, peer: *const t.PeerId, index: u16, direction: t.Direction, now_ms: u64) t.Admission {
    return c.admit(peer, &local, .{ .index = index, .generation = 1 }, &.{ .direction = direction, .endpoint = address, .now_ms = now_ms });
}

test "peer fold candidate promotion honors established quota and outbound reserve at time zero" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    const discovered = try candidate(1, 0);
    try d.enqueueDiscovered(&c, &discovered, &.{}, &.{}, 0);
    const peer = c.find(&discovered.peer).?;
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 0), c.snapshots(&snapshots));
    try std.testing.expect(c.get(peer) == null);
    for (0..3) |i| {
        const identity: t.PeerId = .{ .bytes = @splat(@intCast(i + 1)) };
        try std.testing.expect(admit(&c, &identity, @intCast(i), .inbound, 0) == .admitted);
    }
    try std.testing.expectEqual(t.Admission.capacity, admit(&c, &discovered.peer, 3, .inbound, 0));
    const accepted = admit(&c, &discovered.peer, 3, .outbound, 0).admitted;
    try std.testing.expectEqual(peer, accepted.peer);
    try std.testing.expect(accepted.fresh);
    d.accepted(&c, peer, .{ .index = 3, .generation = 1 }, 0);
    try std.testing.expectEqual(@as(usize, 4), c.snapshots(&snapshots));
    try std.testing.expectEqual(@as(u64, 0), c.get(peer).?.connected_at_ms);
    try std.testing.expectEqual(@as(u16, 1), c.intent_count);
    try std.testing.expectEqual(@as(u16, 4), c.connectedCount());
}

test "peer fold discovery pressure retires hints while retaining established bans and identity" {
    var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    const first = try candidate(1, 1);
    const second = try candidate(2, 1);
    try d.enqueueDiscovered(&c, &first, &.{}, &.{ .syncnets = 1 }, 0);
    const peer = admit(&c, &first.peer, 0, .inbound, 0).admitted.peer;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    d.accepted(&c, peer, conn, 0);
    _ = c.report(peer, .fatal, 0);
    try std.testing.expect(c.disconnect(peer, conn, .banned, 0));
    try std.testing.expectError(error.Capacity, d.enqueueDiscovered(&c, &second, &.{}, &.{ .syncnets = 1 }, 600_000));
    var events: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&events));
    const rep = c.rowFor(peer).?.reputation;
    try d.enqueueDiscovered(&c, &second, &.{}, &.{ .syncnets = 1 }, 600_000);
    try std.testing.expectEqual(peer, c.find(&first.peer).?);
    try std.testing.expectEqualDeep(rep, c.rowFor(peer).?.reputation);
    try std.testing.expect(!c.intents.isSet(peer.index));
    try std.testing.expectEqual(@as(u16, 1), c.intent_count);
    try std.testing.expectEqual(t.Admission.banned, admit(&c, &first.peer, 0, .inbound, 600_000));
    const second_ref = c.find(&second.peer).?;
    c.rows[second_ref.index].intent.automatic = false;
    c.releaseIntent(second_ref);
    try d.enqueue(&c, &first.peer, &.{address}, true, 600_000);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), d.poll(&c, 600_000, &out));
    try std.testing.expect(d.nextWakeup(&c, 600_000, 1).? >= rep.ban_until_ms);
}

test "peer fold candidate selection revisits every retained intent after demand changes" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    const first = try candidate(1, 1);
    const second = try candidate(2, 2);
    try d.enqueueDiscovered(&c, &first, &.{}, &.{ .syncnets = 1 }, 0);
    try d.enqueueDiscovered(&c, &second, &.{}, &.{ .syncnets = 1 }, 0);
    d.configureSelection(&c, &.{ .syncnets = 1 }, false, &.{}, 0);
    try std.testing.expect(!c.rowFor(c.find(&second.peer).?).?.intent.selected);
    d.configureSelection(&c, &.{ .syncnets = 2 }, false, &.{}, 0);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    try std.testing.expect(out[0].peer.eql(&second.peer));
}

test "peer fold attempt generation advances independently of a retained peer reference" {
    var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    const first = try candidate(1, 1);
    try d.enqueue(&c, &first.peer, &.{address}, true, 0);
    const peer = c.find(&first.peer).?;
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    const stale = out[0].token;
    d.expire(&c, null, 10_000);
    const next = d.nextWakeup(&c, 10_000, 1).?;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, next, &out));
    try std.testing.expectEqual(peer, c.find(&first.peer).?);
    try std.testing.expectEqual(stale.generation + 1, out[0].token.generation);
    try std.testing.expect(!d.dialFailed(&c, stale, next));
    try std.testing.expect(!d.dialStarted(stale, .{ .index = 0, .generation = 1 }));
    try std.testing.expectEqual(@as(u16, 1), d.attempts().total);
}

test "peer fold connected custody makes progress independently of candidate work" {
    var c = try Catalog.initWithIntents(a, opts, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .seed = 1 });
    const groups: u16 = @min(128, @import("preset").NUMBER_OF_COLUMNS);
    const context: t.ForkContext = .{ .fork = .fulu, .custody_groups = groups, .minimum_sampling_groups = groups };
    for (0..8) |i| {
        var hint = try candidate(@intCast(i + 1), 1);
        hint.custody_group_count = groups - 1;
        try d.enqueueDiscovered(&c, &hint, &context, &.{}, 0);
        if (i >= 2) continue;
        const peer = admit(&c, &hint.peer, @intCast(i), .outbound, 0).admitted.peer;
        const conn: t.Handle = .{ .index = @intCast(i), .generation = 1 };
        d.accepted(&c, peer, conn, 0);
        try std.testing.expect(c.updateStatus(peer, conn, &.{ .earliest_available_slot = 0 }, 0));
        try std.testing.expect(c.updateMetadata(peer, conn, &.{ .custody_group_count = groups - 1 }, 0));
        try std.testing.expect(c.get(peer).?.custody_groups == null);
    }
    for (0..64) |_| {
        var budget: u16 = custody.hashes_per_turn;
        const pending = c.advanceCustody(&context, 0, 60_000, &budget);
        try std.testing.expect(budget <= custody.hashes_per_turn);
        for (c.rows[0..2]) |row| {
            const work = row.custody_work.?;
            try std.testing.expect(work.totalHashes() > 0);
            try std.testing.expectEqual(groups, work.sampling_count);
        }
        if (!pending) break;
    }
    for (0..2) |i| {
        const snapshot = c.get(c.reference(i)).?;
        try std.testing.expectEqual(@as(usize, groups - 1), snapshot.custody_groups.?.count());
        try std.testing.expectEqual(@as(usize, groups), snapshot.sampling_groups.?.count());
    }
}

test "peer fold canonical disconnect backs off once even without a dial intent" {
    var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    const hint = try candidate(1, 1);
    const peer = admit(&c, &hint.peer, 0, .inbound, 0).admitted.peer;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(c.disconnect(peer, conn, .health_timeout, 1));
    try std.testing.expect(!c.disconnect(peer, conn, .health_timeout, 2));
    const before = c.rowFor(peer).?.intent;
    try d.enqueueDiscovered(&c, &hint, &.{}, &.{}, 2);
    try std.testing.expectEqual(@as(u64, 1), c.connection_backoffs);
    try std.testing.expectEqual(before.failures, c.rowFor(peer).?.intent.failures);
    try std.testing.expectEqual(before.eligible_at_ms, d.nextWakeup(&c, 2, 1).?);
}

test "peer fold long-lived health disconnect restarts redial backoff" {
    var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
    defer c.deinit(a);
    const hint = try candidate(1, 1);
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = admit(&c, &hint.peer, 0, .inbound, 0).admitted.peer;
    c.rowFor(peer).?.intent.failures = 4;
    try std.testing.expect(c.disconnect(peer, conn, .health_timeout, 300_000));
    try std.testing.expectEqual(@as(u8, 1), c.rowFor(peer).?.intent.failures);
}
