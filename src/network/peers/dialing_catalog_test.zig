const std = @import("std");
const t = @import("types.zig");
const enr = @import("enr.zig");
const custody = @import("custody.zig");
const Catalog = @import("catalog.zig").Catalog;
const dialing = @import("dialing.zig");
const history = @import("dial_history.zig");
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

test "peer fold inbound health close leaves the discovered endpoint history untouched" {
    var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    const hint = try candidate(1, 0);
    try d.enqueueDiscovered(&c, &hint, &.{}, &.{}, 0);
    const key = c.history.endpointKey(&hint.peer, address);
    c.history.recordEndpoint(key, .health, hint.sequence, 0);
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = admit(&c, &hint.peer, 0, .inbound, 0).admitted.peer;
    c.clearHealthStrikes(peer, conn);
    try std.testing.expectEqual(@as(u8, 1), c.history.strikesFor(key, hint.sequence, 1));
    try std.testing.expect(c.disconnect(peer, conn, .health_timeout, 1));
    try std.testing.expectEqual(@as(u8, 1), c.history.strikesFor(key, hint.sequence, 1));
    try std.testing.expectEqual(@as(u8, 1), c.rowFor(peer).?.intent.failures);
    try std.testing.expectEqual(@as(u64, 1), c.connection_backoffs);
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

/// A QUIC-admitted connection whose probes never answer: Control cools the peer down and closes it
/// for health after about 25 s.
fn zombieRound(c: *Catalog, d: *dialing.Dialing, identity: *const t.PeerId, conn: t.Handle, now: *u64) !t.PeerRef {
    now.* = d.nextWakeup(c, now.*, 1).?;
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(c, now.*, &out));
    try std.testing.expect(out[0].peer.eql(identity));
    try std.testing.expect(d.dialStarted(out[0].token, conn));
    const peer = admit(c, identity, conn.index, .outbound, now.*).admitted.peer;
    d.accepted(c, peer, conn, now.*);
    now.* += 25_000;
    try std.testing.expect(c.cooldown(peer, conn, now.*, 60_000));
    now.* += 2_000;
    try std.testing.expect(c.disconnect(peer, conn, .health_timeout, now.*));
    var events: [4]t.Event = undefined;
    _ = c.pollEvents(&events);
    return peer;
}

test "peer fold zombie endpoint is blocked after two health closes across rediscovery and row replacement" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    var zombie = try candidate(1, 0);
    const key = c.history.endpointKey(&zombie.peer, address);
    try d.enqueueDiscovered(&c, &zombie, &.{}, &.{}, 0);
    var now: u64 = 0;
    _ = try zombieRound(&c, &d, &zombie.peer, .{ .index = 0, .generation = 1 }, &now);
    try std.testing.expectEqual(@as(u8, 1), c.history.strikesFor(key, zombie.sequence, now));
    // Once the cooldown lapses, a fresh admission reclaims the row and its backoff with it.
    now += 60_000;
    const first: t.PeerId = .{ .bytes = @splat(9) };
    _ = admit(&c, &first, 4, .inbound, now).admitted;
    try std.testing.expect(c.find(&zombie.peer) == null);
    zombie.sequence = 2;
    try d.enqueueDiscovered(&c, &zombie, &.{}, &.{}, now);
    try std.testing.expectEqual(@as(u8, 1), c.rowFor(c.find(&zombie.peer).?).?.intent.failures);
    const peer = try zombieRound(&c, &d, &zombie.peer, .{ .index = 1, .generation = 1 }, &now);
    try std.testing.expectEqual(@as(u64, 1), d.retries[@intFromEnum(t.DialFailure.health)]);
    try std.testing.expect(c.history.blocked(key, zombie.sequence, now));
    try std.testing.expect(!c.intents.isSet(peer.index));
    try std.testing.expectEqual(@as(?u64, null), d.nextWakeup(&c, now, 1));
    zombie.sequence = 3;
    try std.testing.expectError(error.RecentlyFailed, d.enqueueDiscovered(&c, &zombie, &.{}, &.{}, now));
    now += 60_000;
    const second: t.PeerId = .{ .bytes = @splat(10) };
    _ = admit(&c, &second, 5, .inbound, now).admitted;
    try std.testing.expect(c.find(&zombie.peer) == null);
    zombie.sequence = 4;
    try std.testing.expectError(error.RecentlyFailed, d.enqueueDiscovered(&c, &zombie, &.{}, &.{}, now));
    try d.enqueueDiscovered(&c, &zombie, &.{}, &.{}, now - 60_000 + @import("dial_history.zig").endpoint_memory_ms);
}

/// Dials the discovered peer, lands the connection, and has the remote end it with `rejection`.
fn rejectedRound(c: *Catalog, d: *dialing.Dialing, identity: *const t.PeerId, index: u16, rejection: t.Rejection, now_ms: u64) !void {
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(c, now_ms, &out));
    try std.testing.expect(out[0].peer.eql(identity));
    const conn: t.Handle = .{ .index = index, .generation = 1 };
    try std.testing.expect(d.dialStarted(out[0].token, conn));
    const peer = admit(c, identity, conn.index, .outbound, now_ms).admitted.peer;
    d.accepted(c, peer, conn, now_ms);
    c.settleRejections(peer, conn, false, rejection, now_ms);
    try std.testing.expect(c.disconnect(peer, conn, .remote_goodbye, now_ms));
    var events: [4]t.Event = undefined;
    _ = c.pollEvents(&events);
}

test "peer fold a full peer waits 5, 15 then 60 minutes across row reclamation and fresh records" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    var full = try candidate(1, 0);
    var now: u64 = 0;
    for ([_]u64{ 5, 15, 60, 5 }, 0..) |minutes, round| {
        // Once its memory lapses, the full peer's next rejection starts over.
        if (round == 3) now += history.rejection_memory_ms - 60 * 60_000;
        try d.enqueueDiscovered(&c, &full, &.{}, &.{}, now);
        try rejectedRound(&c, &d, &full.peer, @intCast(round), .too_many_peers, now);
        if (round == 0) {
            for (0..3) |i| {
                const other: t.PeerId = .{ .bytes = @splat(@intCast(20 + i)) };
                try std.testing.expect(admit(&c, &other, @intCast(4 + i), .inbound, now) == .admitted);
            }
            try std.testing.expect(c.find(&full.peer) == null);
        }
        full.sequence += 1;
        const until = now + minutes * 60_000;
        try std.testing.expectError(error.RecentlyRejected, d.enqueueDiscovered(&c, &full, &.{}, &.{}, until - 1));
        now = until;
    }
    try std.testing.expectEqual(@as(u64, 4), d.refused.identity[@intFromEnum(t.Rejection.too_many_peers)]);
    try std.testing.expectEqual(@as(u64, 4), c.rejections[@intFromEnum(t.Rejection.too_many_peers)]);
}

test "peer fold early closes escalate while manual and inbound connections bypass them until a kept connection clears them" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    var gated = try candidate(1, 0);
    var now: u64 = 0;
    var block_end: u64 = 0;
    for ([_]u64{ 1, 15, 60 }, 0..) |minutes, round| {
        now = block_end;
        try d.enqueueDiscovered(&c, &gated, &.{}, &.{}, now);
        try rejectedRound(&c, &d, &gated.peer, @intCast(round), .early_close, now);
        gated.sequence += 1;
        block_end = now + minutes * 60_000;
        try std.testing.expectError(error.RecentlyRejected, d.enqueueDiscovered(&c, &gated, &.{}, &.{}, block_end - 1));
    }
    try d.enqueue(&c, &gated.peer, &.{address}, false, now);
    const due = d.nextWakeup(&c, now, 1).?;
    try std.testing.expect(due < block_end);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, due, &out));
    try std.testing.expect(out[0].peer.eql(&gated.peer));
    try std.testing.expect(d.dialDeferred(&c, out[0].token, due));
    const conn: t.Handle = .{ .index = 7, .generation = 1 };
    const admission = admit(&c, &gated.peer, conn.index, .inbound, due);
    try std.testing.expect(admission == .admitted);
    d.accepted(&c, admission.admitted.peer, conn, due);
    const kept = due + history.kept_connection_ms;
    c.settleRejections(admission.admitted.peer, conn, true, null, kept - 1);
    try std.testing.expectError(error.RecentlyRejected, d.enqueueDiscovered(&c, &gated, &.{}, &.{}, kept - 1));
    c.settleRejections(admission.admitted.peer, conn, false, null, kept);
    try std.testing.expectError(error.RecentlyRejected, d.enqueueDiscovered(&c, &gated, &.{}, &.{}, kept));
    c.settleRejections(admission.admitted.peer, conn, true, null, kept);
    try d.enqueueDiscovered(&c, &gated, &.{}, &.{}, kept);
    try std.testing.expectEqual(@as(u64, 3), c.rejections[@intFromEnum(t.Rejection.early_close)]);
}

test "peer fold a full direct peer waits 5, 15 then 60 minutes while a manual connect dials through" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    const direct = try candidate(1, 0);
    try d.enqueue(&c, &direct.peer, &.{address}, true, 0);
    var now: u64 = 0;
    var until: u64 = 0;
    for ([_]u64{ 5, 15, 60 }, 0..) |minutes, round| {
        now = d.nextWakeup(&c, until, 1).?;
        try std.testing.expectEqual(until, now);
        try rejectedRound(&c, &d, &direct.peer, @intCast(round), .too_many_peers, now);
        try std.testing.expect(c.isDirect(&direct.peer));
        until = now + minutes * 60_000;
    }
    try std.testing.expectEqual(until, d.nextWakeup(&c, now, 1).?);
    try d.enqueue(&c, &direct.peer, &.{address}, false, now);
    const due = d.nextWakeup(&c, now, 1).?;
    try std.testing.expect(due < now + dialing.connect_timeout_ms);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, due, &out));
    try std.testing.expect(out[0].peer.eql(&direct.peer));
}

test "peer fold a direct peer whose rejection the history evicts mid-block waits out the old block" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    const direct = try candidate(1, 0);
    try d.enqueue(&c, &direct.peer, &.{address}, true, 0);
    try rejectedRound(&c, &d, &direct.peer, 0, .too_many_peers, 0);
    const block_end = 5 * 60_000;
    try std.testing.expectEqual(@as(u64, block_end), d.nextWakeup(&c, 0, 1).?);
    // Longer-lived entries fill the rest of the identity's probe window, so the next claim homed
    // on its slot evicts it.
    const key = c.history.identityKey(&direct.peer);
    for (1..history.probe_max) |offset| c.history.recordEndpoint(key +% offset, .peer_id_mismatch, 0, 1);
    _ = c.history.reject(key +% c.history.entries.len, .fault, 1);
    try std.testing.expectEqual(@as(u64, 0), c.history.rejectedUntil(key, 1));
    try std.testing.expectEqual(@as(u64, block_end), d.nextWakeup(&c, 1, 1).?);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), d.poll(&c, block_end - 1, &out));
    try std.testing.expectEqual(@as(u64, block_end), d.nextWakeup(&c, block_end - 1, 1).?);
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, block_end, &out));
    try std.testing.expect(out[0].peer.eql(&direct.peer));
}

const remembered = @import("remembered.zig");
const unix_s: u64 = 1_700_000_000;
/// Replay queues four candidates at once, then one every 250 ms.
const replay_interval_ms: u64 = 250;

fn at(ms: u64) @import("../types.zig").Now {
    return .{ .mono_ms = ms, .unix_s = @intCast(unix_s + ms / 1000) };
}

fn funnel(c: *const Catalog, origin: remembered.Origin) [3]u64 {
    return c.remembered.counters.funnel[@intFromEnum(origin)];
}

fn rememberedAt(c: *Catalog, now_ms: u64) []remembered.Record {
    const records = struct {
        var buffer: [remembered.capacity]remembered.Record = undefined;
    };
    return records.buffer[0..c.remembered.snapshot(remembered.seconds(at(now_ms)), &records.buffer)];
}

/// Dials each discovered candidate and lands its connection at `now_ms`, on connection index i.
fn dialAll(c: *Catalog, d: *dialing.Dialing, candidates: []const enr.Candidate, now_ms: u64) ![8]t.PeerRef {
    var peers: [8]t.PeerRef = undefined;
    for (candidates) |*value| try d.enqueueDiscovered(c, value, &.{}, &.{}, now_ms);
    var out: [8]dialing.DialIntent = undefined;
    try std.testing.expectEqual(candidates.len, d.poll(c, now_ms, out[0..candidates.len]));
    for (out[0..candidates.len]) |intent| {
        var index: u16 = 0;
        while (!candidates[index].peer.eql(&intent.peer)) index += 1;
        const conn: t.Handle = .{ .index = index, .generation = 1 };
        try std.testing.expect(d.dialStarted(intent.token, conn));
        peers[index] = admit(c, &intent.peer, index, .outbound, now_ms).admitted.peer;
        d.accepted(c, peers[index], conn, now_ms);
    }
    return peers;
}

test "remembered qualification takes our dialed endpoint once a ready connection served five minutes" {
    var c = try Catalog.initWithIntents(a, opts, 2, 8, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 1 });
    const dialed = try candidate(1, 0);
    const peer = (try dialAll(&c, &d, &.{dialed}, 0))[0];
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    // A path change moves the connection, not the endpoint our dial proved.
    const moved: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 9002 } };
    try std.testing.expect(c.updateEndpoint(peer, conn, &moved));
    const inbound = try candidate(2, 0);
    const inbound_conn: t.Handle = .{ .index = 1, .generation = 1 };
    const inbound_peer = admit(&c, &inbound.peer, inbound_conn.index, .inbound, 0).admitted.peer;
    for ([_]t.PeerRef{ peer, inbound_peer }, [_]t.Handle{ conn, inbound_conn }) |ref, handle| {
        try std.testing.expect(c.updateStatus(ref, handle, &.{}, 0));
    }
    c.rememberConnected(at(remembered.qualify_ms));
    try std.testing.expectEqual(@as(u16, 0), c.remembered.count);
    for ([_]t.PeerRef{ peer, inbound_peer }, [_]t.Handle{ conn, inbound_conn }) |ref, handle| {
        try std.testing.expect(c.updateMetadata(ref, handle, &.{}, 0));
    }
    c.rememberConnected(at(remembered.qualify_ms - 1));
    try std.testing.expectEqual(@as(u16, 0), c.remembered.count);
    try std.testing.expectEqual([3]u64{ 1, 1, 0 }, funnel(&c, .fresh));
    c.rememberConnected(at(remembered.qualify_ms));
    const qualified: remembered.Record = .{ .peer = dialed.peer, .address = address, .qualified_at_s = unix_s + 300 };
    try std.testing.expectEqualDeep(@as([]const remembered.Record, &.{qualified}), rememberedAt(&c, remembered.qualify_ms));
    c.rememberConnected(at(remembered.qualify_ms + 60_000));
    try std.testing.expectEqual(unix_s + 360, rememberedAt(&c, remembered.qualify_ms + 60_000)[0].qualified_at_s);
    try std.testing.expectEqual([3]u64{ 1, 1, 1 }, funnel(&c, .fresh));
    try std.testing.expectEqual([3]u64{ 0, 0, 0 }, funnel(&c, .remembered));
    // A peer we banned is no longer eligible, so service stops refreshing its record.
    _ = c.report(peer, .fatal, remembered.qualify_ms + 60_000);
    c.rememberConnected(at(remembered.qualify_ms + 120_000));
    try std.testing.expectEqual(unix_s + 360, rememberedAt(&c, remembered.qualify_ms + 120_000)[0].qualified_at_s);
}

test "remembered records refresh at a served close and drop on rejection, health, ban and identity mismatch" {
    const wide: t.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 8, .seed = 1 });
    var candidates: [6]enr.Candidate = undefined;
    var seeds: [6]remembered.Record = undefined;
    for (&candidates, &seeds, 0..) |*value, *seed, i| {
        value.* = try candidate(@intCast(i + 1), 0);
        seed.* = .{ .peer = value.peer, .address = address, .qualified_at_s = unix_s - 60 };
    }
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    const peers = try dialAll(&c, &d, candidates[0..5], 0);
    const now = at(remembered.qualify_ms);
    const conns = [_]t.Handle{ .{ .index = 0, .generation = 1 }, .{ .index = 1, .generation = 1 }, .{ .index = 2, .generation = 1 }, .{ .index = 3, .generation = 1 }, .{ .index = 4, .generation = 1 } };
    // A remote shutdown ends service without rejecting us, so it refreshes the record.
    c.settleRejections(peers[0], conns[0], true, .shutdown, now.mono_ms);
    c.rememberClosed(peers[0], conns[0], true, .remote_goodbye, .shutdown, now);
    // A close that shows the peer ineligible keeps the record as it was.
    c.rememberClosed(peers[1], conns[1], true, .incompatible_fork, null, now);
    c.settleRejections(peers[2], conns[2], true, .too_many_peers, now.mono_ms);
    c.rememberClosed(peers[2], conns[2], true, .remote_goodbye, .too_many_peers, now);
    c.rememberClosed(peers[3], conns[3], true, .health_timeout, null, now);
    try std.testing.expect(c.disconnect(peers[3], conns[3], .health_timeout, now.mono_ms));
    c.rememberClosed(peers[4], conns[4], true, .banned, null, now);
    try std.testing.expect(c.disconnect(peers[4], conns[4], .banned, now.mono_ms));
    // Another identity answered at the sixth peer's endpoint.
    try d.enqueueDiscovered(&c, &candidates[5], &.{}, &.{}, 0);
    var out: [1]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    const handle: t.Handle = .{ .index = 5, .generation = 1 };
    try std.testing.expect(d.dialStarted(out[0].token, handle));
    try std.testing.expect(d.dialClosed(&c, handle, .peer_id_mismatch, 1));
    const records = rememberedAt(&c, remembered.qualify_ms);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    for (records) |value| {
        const expected: u64 = if (value.peer.eql(&candidates[0].peer)) unix_s + 300 else unix_s - 60;
        try std.testing.expect(value.peer.eql(&candidates[0].peer) or value.peer.eql(&candidates[1].peer));
        try std.testing.expectEqual(expected, value.qualified_at_s);
    }
    inline for (.{ .rejection, .health, .banned, .peer_id_mismatch }) |reason| {
        try std.testing.expectEqual(@as(u64, 1), c.remembered.counters.removals[@intFromEnum(@as(remembered.Removal, reason))]);
    }
    try std.testing.expectEqual([3]u64{ 6, 5, 5 }, funnel(&c, .fresh));
}

test "replayed remembered candidates meet the rejection memory, the endpoint history and general demand" {
    const wide: t.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 4, .seed = 1 });
    var seeds: [4]remembered.Record = undefined;
    for (&seeds, 0..) |*seed, i| seed.* = .{
        .peer = .{ .bytes = @splat(@intCast(i + 1)) },
        .address = .{ .ip4 = .{ .octets = .{ 10, @intCast(i + 1), 0, 1 }, .port = 9000 } },
        .qualified_at_s = unix_s,
    };
    const rejected, const failed, const known, const clean = seeds;
    _ = c.history.reject(c.history.identityKey(&rejected.peer), .too_many_peers, 0);
    const key = c.history.endpointKey(&failed.peer, failed.address);
    for (0..2) |_| c.history.recordEndpoint(key, .health, 0, 0);
    _ = admit(&c, &known.peer, 0, .inbound, 0).admitted;
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    try std.testing.expectEqual(@as(usize, 1), d.replayRemembered(&c, &.{}, &.{}, 4, at(0)));
    try std.testing.expect(!c.remembered.replayPending());
    try std.testing.expectEqual([5]u64{ 1, 1, 1, 1, 0 }, c.remembered.counters.replays);
    // Without general demand, selection holds back a candidate that has no ENR coverage.
    d.configureSelection(&c, &.{}, false, &.{}, 0);
    var out: [4]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), d.poll(&c, 0, &out));
    d.configureSelection(&c, &.{}, true, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    try std.testing.expect(out[0].peer.eql(&clean.peer));
    try std.testing.expect(out[0].address.eql(clean.address));
    try std.testing.expectEqual([3]u64{ 1, 0, 0 }, funnel(&c, .remembered));
    // Replay neither loads nor refreshes a record's time.
    try std.testing.expectEqual(unix_s, rememberedAt(&c, 0)[0].qualified_at_s);
}

test "replay queues remembered first attempts at four per second after a burst of four" {
    const wide: t.Options = .{ .capacity = 64, .max_peers = 64, .target_peers = 64, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 64, 64, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 64, .concurrent_max = 64, .seed = 1 });
    var seeds: [40]remembered.Record = undefined;
    for (&seeds, 0..) |*seed, i| seed.* = .{
        .peer = .{ .bytes = @splat(@intCast(i + 1)) },
        .address = .{ .ip4 = .{ .octets = .{ 10, @intCast(i % 7), @intCast(i), 1 }, .port = 9000 } },
        .qualified_at_s = unix_s,
    };
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    const start: u64 = 1_000;
    var started: usize = 0;
    var out: [64]dialing.DialIntent = undefined;
    var now = start;
    while (started < seeds.len) : (now += 50) {
        try std.testing.expect(now <= start + 10_000);
        _ = d.replayRemembered(&c, &.{}, &.{}, out.len, at(now));
        started += d.poll(&c, now, &out);
        try std.testing.expect(started <= 4 + (now - start) / replay_interval_ms);
        if (now == start) try std.testing.expectEqual(@as(usize, 4), started);
        const due = d.replayWakeup(&c, now, out.len);
        if (started < seeds.len) try std.testing.expect(due.? > now and due.? <= now + replay_interval_ms);
    }
    try std.testing.expectEqual(start + (seeds.len - 4) * replay_interval_ms, now - 50);
    try std.testing.expectEqual([3]u64{ seeds.len, 0, 0 }, funnel(&c, .remembered));
    try std.testing.expectEqual(@as(?u64, null), d.replayWakeup(&c, now, out.len));
}

test "replay interleaves remembered first attempts with fresh candidates" {
    const wide: t.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 4, .seed = 1 });
    for (1..3) |tag| try d.enqueueDiscovered(&c, &(try candidate(@intCast(tag), 1)), &.{}, &.{ .syncnets = 1 }, 0);
    var seeds: [2]remembered.Record = undefined;
    for (&seeds, 0..) |*seed, i| seed.* = .{
        .peer = .{ .bytes = @splat(@intCast(i + 20)) },
        .address = .{ .ip4 = .{ .octets = .{ 10, @intCast(i + 1), 0, 1 }, .port = 9000 } },
        .qualified_at_s = unix_s,
    };
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    try std.testing.expectEqual(@as(usize, 2), d.replayRemembered(&c, &.{}, &.{}, 4, at(0)));
    d.configureSelection(&c, &.{ .syncnets = 1 }, true, &.{}, 0);
    var out: [4]dialing.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 4), d.poll(&c, 0, &out));
    for (out, [_]bool{ true, false, true, false }) |intent, replayed| {
        try std.testing.expectEqual(replayed, intent.peer.bytes[0] >= 20 and intent.peer.bytes[1] >= 20);
    }
    try std.testing.expectEqual([3]u64{ 2, 0, 0 }, funnel(&c, .remembered));
    try std.testing.expectEqual([3]u64{ 2, 0, 0 }, funnel(&c, .fresh));
}
