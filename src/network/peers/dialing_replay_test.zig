const std = @import("std");
const Now = @import("../types.zig").Now;
const t = @import("types.zig");
const enr = @import("enr.zig");
const Catalog = @import("catalog.zig").Catalog;
const dialing = @import("dialing.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9001 } };
const local: t.PeerId = .{ .bytes = @splat(0) };
const opts: Catalog.Options = .{ .capacity = 4, .max_peers = 4, .target_peers = 4, .min_outbound = 0, .outbound_reserve = 1 };

const support = @import("dialing_catalog_test_support.zig");
const candidate = support.candidate;
const admit = support.admit;

const remembered = @import("remembered.zig");
const unix_s: u64 = 1_700_000_000;
/// Replay queues four candidates at once, then one every 250 ms.
const replay_interval_ms: u64 = 250;

fn at(ms: u64) @import("../types.zig").Now {
    return Now.fromMilliseconds(.{ .mono_ms = ms, .unix_s = @intCast(unix_s + ms / 1000) });
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
    var out: [8]dialing.Dialing.SelectedDial = undefined;
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
    // A local ban forgets the peer at once, and service no longer requalifies it.
    try std.testing.expectEqual(t.ReputationDecision.ban, c.report(peer, .fatal, remembered.qualify_ms + 60_000).?);
    try std.testing.expectEqual(@as(usize, 0), rememberedAt(&c, remembered.qualify_ms + 60_000).len);
    c.rememberConnected(at(remembered.qualify_ms + 120_000));
    try std.testing.expectEqual(@as(usize, 0), rememberedAt(&c, remembered.qualify_ms + 120_000).len);
}

test "remembered records refresh at a served close and drop on rejection, health, ban and identity mismatch" {
    const wide: Catalog.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 8, .seed = 1 });
    var candidates: [7]enr.Candidate = undefined;
    var seeds: [7]remembered.Record = undefined;
    for (&candidates, &seeds, 0..) |*value, *seed, i| {
        value.* = try candidate(@intCast(i + 1), 0);
        seed.* = .{ .peer = value.peer, .address = address, .qualified_at_s = unix_s - 60 };
    }
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    const peers = try dialAll(&c, &d, candidates[0..6], 0);
    const now = at(remembered.qualify_ms);
    var conns: [6]t.Handle = undefined;
    for (&conns, 0..) |*conn, i| conn.* = .{ .index = @intCast(i), .generation = 1 };
    // A remote shutdown ends service without rejecting us, so it refreshes the record.
    c.settleRejections(peers[0], conns[0], true, .shutdown, now.millis());
    c.rememberClosed(peers[0], conns[0], true, .remote_goodbye, .shutdown, now);
    // A close that shows the peer ineligible keeps the record as it was.
    c.rememberClosed(peers[1], conns[1], true, .incompatible_fork, null, now);
    c.settleRejections(peers[2], conns[2], true, .too_many_peers, now.millis());
    c.rememberClosed(peers[2], conns[2], true, .remote_goodbye, .too_many_peers, now);
    c.rememberClosed(peers[3], conns[3], true, .health_timeout, null, now);
    try std.testing.expect(c.disconnect(peers[3], conns[3], .health_timeout, now.millis()));
    // A ban during an already scheduled close forgets the peer, and the close does not restore it.
    try std.testing.expect(c.markUnavailable(peers[4], conns[4], .count_pruning));
    _ = c.report(peers[4], .fatal, now.millis());
    c.rememberClosed(peers[4], conns[4], true, .count_pruning, null, now);
    try std.testing.expect(c.disconnect(peers[4], conns[4], .count_pruning, now.millis()));
    // A host verdict can ban a peer after its connection closed.
    c.rememberClosed(peers[5], conns[5], true, .transport_closed, null, now);
    try std.testing.expect(c.disconnect(peers[5], conns[5], .transport_closed, now.millis()));
    try std.testing.expectEqual(@as(usize, 4), rememberedAt(&c, remembered.qualify_ms).len);
    try std.testing.expectEqual(t.ReputationDecision.ban, c.report(peers[5], .fatal, now.millis()).?);
    // Another identity answered at the seventh peer's endpoint.
    try d.enqueueDiscovered(&c, &candidates[6], &.{}, &.{}, 0);
    var out: [1]dialing.Dialing.SelectedDial = undefined;
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    const handle: t.Handle = .{ .index = 6, .generation = 1 };
    try std.testing.expect(d.dialStarted(out[0].token, handle));
    try std.testing.expect(d.dialClosed(&c, handle, .peer_id_mismatch, 1));
    const records = rememberedAt(&c, remembered.qualify_ms);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    for (records) |value| {
        const expected: u64 = if (value.peer.eql(&candidates[0].peer)) unix_s + 300 else unix_s - 60;
        try std.testing.expect(value.peer.eql(&candidates[0].peer) or value.peer.eql(&candidates[1].peer));
        try std.testing.expectEqual(expected, value.qualified_at_s);
    }
    try std.testing.expectEqual([3]u64{ 7, 6, 6 }, funnel(&c, .fresh));
}

test "replayed remembered candidates meet the rejection memory, the endpoint history and general demand" {
    const wide: Catalog.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 4, .seed = 1 });
    var seeds: [5]remembered.Record = undefined;
    for (&seeds, 0..) |*seed, i| seed.* = .{
        .peer = .{ .bytes = @splat(@intCast(i + 1)) },
        .address = .{ .ip4 = .{ .octets = .{ 10, @intCast(i + 1), 0, 1 }, .port = 9000 } },
        .qualified_at_s = unix_s,
    };
    const rejected, const failed, const known, const backoff, const clean = seeds;
    _ = c.history.reject(c.history.identityKey(&rejected.peer), .too_many_peers, 0);
    const key = c.history.endpointKey(&failed.peer, failed.address);
    for (0..2) |_| c.history.recordEndpoint(key, .health, 0, 0);
    _ = admit(&c, &known.peer, 0, .inbound, 0).admitted;
    // A connection that just closed leaves the peer's row backing off.
    const closed = admit(&c, &backoff.peer, 1, .inbound, 0).admitted.peer;
    try std.testing.expect(c.disconnect(closed, .{ .index = 1, .generation = 1 }, .transport_closed, 0));
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
    try std.testing.expectEqual(@as(usize, 1), d.replayRemembered(&c, &.{}, &.{}, at(0)));
    try std.testing.expect(c.remembered.nextReplay(unix_s) == null);
    try std.testing.expectEqual([5]u64{ 1, 1, 1, 2, 0 }, c.remembered.counters.replays);
    // Without general demand, selection holds back a candidate that has no ENR coverage.
    d.configureSelection(&c, &.{}, false, &.{}, 0);
    var out: [4]dialing.Dialing.SelectedDial = undefined;
    try std.testing.expectEqual(@as(usize, 0), d.poll(&c, 0, &out));
    d.configureSelection(&c, &.{}, true, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 1), d.poll(&c, 0, &out));
    try std.testing.expect(out[0].peer.eql(&clean.peer));
    try std.testing.expect(out[0].address.eql(clean.address));
    try std.testing.expectEqual([3]u64{ 1, 0, 0 }, funnel(&c, .remembered));
    // Replay neither loads nor refreshes a record's time.
    try std.testing.expectEqual(unix_s, rememberedAt(&c, 0)[0].qualified_at_s);
}

/// Seeds `count` remembered records tagged 1 to `count`, each in its own /24 across five /16s.
fn seedRemembered(c: *Catalog, comptime count: usize) void {
    var seeds: [count]remembered.Record = undefined;
    for (&seeds, 0..) |*seed, i| seed.* = .{
        .peer = .{ .bytes = @splat(@intCast(i + 1)) },
        .address = .{ .ip4 = .{ .octets = .{ 10, @intCast(i % 5), @intCast(i), 1 }, .port = 9000 } },
        .qualified_at_s = unix_s,
    };
    c.remembered.load(&seeds, &local, unix_s, c.random.random());
}

/// The tag of a seeded remembered identity, or null for any other peer.
fn seedTag(peer: *const t.PeerId, count: usize) ?u8 {
    const tag = peer.bytes[0];
    return if (tag >= 1 and tag <= count and std.mem.allEqual(u8, &peer.bytes, tag)) tag else null;
}

test "replay paces remembered first attempts as they start while direct and fresh candidates take the room" {
    const wide: Catalog.Options = .{ .capacity = 64, .max_peers = 64, .target_peers = 64, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 64, 64, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 64, .concurrent_max = 16, .seed = 1 });
    // Direct peers and fresh candidates of equal priority take the room first, and each returns
    // after its backoff; replay queues more as poll starts four per turn.
    for (0..4) |i| try d.enqueue(&c, &.{ .bytes = @splat(@intCast(100 + i)) }, &.{address}, true, 0);
    for (1..9) |tag| try d.enqueueDiscovered(&c, &(try candidate(@intCast(tag), 0)), &.{}, &.{}, 0);
    const seeded = 24;
    seedRemembered(&c, seeded);
    var first_starts: [seeded]u64 = undefined;
    var seen: [seeded + 1]bool = @splat(false);
    var started: usize = 0;
    const Flight = struct { token: dialing.Dialing.Token, until: u64 };
    var flight: [16]?Flight = @splat(null);
    var now: u64 = 0;
    while (started < seeded) : (now += 50) {
        try std.testing.expect(now < 120_000);
        // Every attempt fails 1.5 s after it starts, freeing its slot.
        for (&flight) |*slot| if (slot.*) |attempt| if (now >= attempt.until) {
            try std.testing.expect(d.dialFailed(&c, attempt.token, now));
            slot.* = null;
        };
        var out: [4]dialing.Dialing.SelectedDial = undefined;
        for (out[0..d.poll(&c, now, &out)]) |intent| {
            for (&flight) |*slot| if (slot.* == null) {
                slot.* = .{ .token = intent.token, .until = now + 1_500 };
                break;
            };
            const tag = seedTag(&intent.peer, seeded) orelse continue;
            if (seen[tag]) continue;
            seen[tag] = true;
            first_starts[started] = now;
            started += 1;
        }
        _ = d.replayRemembered(&c, &.{}, &.{}, at(now));
        // At most a burst waits, and the eligibility heap wakes poll for the next paced start.
        var waiting: usize = 0;
        var it = c.intents.iterator(.{});
        while (it.next()) |index| waiting += @intFromBool(c.rows[index].dial.replay == .untried);
        try std.testing.expect(waiting <= remembered.replay_burst);
        if (waiting > 0 and d.attempts().total < 16) try std.testing.expect(@import("dialing_test_support.zig").refreshAndWakeup(&d, &c, now, 4).? <= @max(now, c.remembered.replayDue()));
    }
    // Any run of remembered first attempts fits a burst of four plus one per 250 ms between them.
    for (0..started) |i| for (i..started) |j| {
        try std.testing.expect(j - i + 1 <= remembered.replay_burst + (first_starts[j] - first_starts[i]) / replay_interval_ms);
    };
    try std.testing.expect(d.selected_attempts[@intFromEnum(dialing.Dialing.Source.direct)] > 4);
    try std.testing.expect(funnel(&c, .fresh)[0] > 8);
}

test "replay alternates remembered first attempts with fresh candidates of equal priority" {
    const wide: Catalog.Options = .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 1 };
    var c = try Catalog.initWithIntents(a, wide, 8, 16, 1);
    defer c.deinit(a);
    var d = try dialing.Dialing.init(.{ .capacity = 8, .concurrent_max = 4, .seed = 1 });
    for (1..3) |tag| try d.enqueueDiscovered(&c, &(try candidate(@intCast(tag), 0)), &.{}, &.{}, 0);
    seedRemembered(&c, 4);
    try std.testing.expectEqual(@as(usize, 4), d.replayRemembered(&c, &.{}, &.{}, at(0)));
    d.configureSelection(&c, &.{}, true, &.{}, 0);
    var out: [4]dialing.Dialing.SelectedDial = undefined;
    try std.testing.expectEqual(@as(usize, 4), d.poll(&c, 0, &out));
    for (out, [_]bool{ true, false, true, false }) |intent, replayed| {
        try std.testing.expectEqual(replayed, seedTag(&intent.peer, 4) != null);
    }
    try std.testing.expectEqual([3]u64{ 2, 0, 0 }, funnel(&c, .remembered));
    try std.testing.expectEqual([3]u64{ 2, 0, 0 }, funnel(&c, .fresh));
}

test "remembered candidates replace failed intents for known and new identities" {
    for ([_]bool{ false, true }) |known| {
        var c = try Catalog.initWithIntents(a, opts, 1, 8, 1);
        defer c.deinit(a);
        var d = try dialing.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
        const incoming = try candidate(73, 0);
        var previous: ?t.PeerRef = null;
        if (known) {
            const peer = admit(&c, &incoming.peer, 0, .outbound, 0).admitted.peer;
            try std.testing.expect(c.disconnect(peer, .{ .index = 0, .generation = 1 }, .host, 1));
            var events: [1]t.Event = undefined;
            _ = c.pollEvents(&events);
            previous = peer;
        }
        const retained = try candidate(74, 0);
        try d.enqueueDiscovered(&c, &retained, &.{}, &.{}, 2);
        c.rowFor(c.find(&retained.peer).?).?.dial.failures = 1;
        const seeds = [_]remembered.Record{.{ .peer = incoming.peer, .address = address, .qualified_at_s = unix_s }};
        c.remembered.load(&seeds, &local, unix_s, c.random.random());
        try std.testing.expectEqual(@as(usize, 1), d.replayRemembered(&c, &.{}, &.{}, at(10_000)));
        const accepted = c.find(&incoming.peer).?;
        if (previous) |peer| try std.testing.expectEqual(peer, accepted);
        try std.testing.expectEqual(.untried, c.rowFor(accepted).?.dial.replay);
        try std.testing.expect(c.intents.isSet(accepted.index));
        try std.testing.expect(c.find(&retained.peer) == null);
        try std.testing.expectEqual(@as(u16, 1), c.intent_count);
    }
}
