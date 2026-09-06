const std = @import("std");
const mod = @import("dial_queue.zig");
const t = @import("types.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 1234 } };
test "peer dial queue copies candidates rotates addresses and ignores stale leased tokens" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 2, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 4 },
    );
    defer q.deinit(a);
    var peer: t.PeerId = .{ .bytes = @splat(1) };
    var addresses = [_]t.Address{
        address,
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4321 } },
    };
    try q.enqueue(&peer, &addresses, false, 0);
    try q.enqueue(&peer, &addresses, false, 0);
    peer.bytes[0] = 9;
    addresses[0] = .unspecified;
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    const first = out[0];
    try std.testing.expectEqual(@as(u8, 1), first.peer.bytes[0]);
    try std.testing.expectEqualDeep(address, first.address);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(10_000, &out));
    try std.testing.expect(!q.dialStarted(first.token, .{ .index = 0, .generation = 1 }));
    const due = q.nextWakeup(10_000, 1).?;
    try std.testing.expect(due >= 11_000 and due <= 12_000);
    try std.testing.expectEqual(@as(usize, 1), q.poll(due, &out));
    try std.testing.expectEqual(@as(u16, 4321), out[0].address.port());
    try std.testing.expect(!q.dialFailed(first.token, due));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 2, .generation = 7 }));
    try std.testing.expect(!q.dialFailed(out[0].token, due));
    try std.testing.expect(q.dialClosed(.{ .index = 2, .generation = 7 }, due));
}

test "peer dial queue bounded pressure generation exhaustion and zero output do not spin" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 2, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 9 },
    );
    defer q.deinit(a);
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const third: t.PeerId = .{ .bytes = @splat(3) };
    try q.enqueue(&first, &.{address}, true, 0);
    try q.enqueue(&second, &.{address}, false, 0);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(0, 0));
    var out: [2]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 2));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&second));
    try std.testing.expect(q.isDirect(&first));
    q.removeDirect(&first);
    try std.testing.expect(!q.isDirect(&first));
    try std.testing.expect(q.remove(&first));
    q.rows[token.index].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
}

test "peer dial queue exponential retry remains bounded through repeated failure" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 1, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 10 },
    );
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, false, 0);
    var now: u64 = 0;
    var out: [1]mod.DialIntent = undefined;
    for (0..20) |_| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(now, &out));
        try std.testing.expect(q.dialFailed(out[0].token, now));
        const due = q.nextWakeup(now, 1).?;
        try std.testing.expect(due - now >= 1_000 and due - now <= 60_000);
        now = due;
    }
}

test "peer dial queue polling and failure without native owner preserve started handles" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 1, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 4 },
    );
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, false, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(0, &out);
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 0, .generation = 0 };
    try std.testing.expect(q.dialStarted(token, conn));
    try std.testing.expect(!q.dialFailed(token, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(10_000, &out));
    try std.testing.expectEqualDeep(conn, q.rows[0].conn.?);
    try std.testing.expect(q.rows[0].attempt);
    try std.testing.expect(!q.remove(&peer));
    q.connection(&peer, true, 10_000);
    try std.testing.expectEqualDeep(conn, q.rows[0].conn.?);
    q.accepted(&peer, .{ .index = 1, .generation = 0 }, 10_000);
    try std.testing.expectEqualDeep(conn, q.rows[0].conn.?);
    try std.testing.expect(q.rows[0].connected);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(10_000, 0));
    try std.testing.expect(q.dialClosed(conn, 10_000));
}

test "peer dial queue review cooldown cannot extend a lost acknowledgement lease" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 5 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, false, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(0, &out);
    const expired = out[0].token;
    q.deferPeer(&peer, 1_800_000);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 0));
    q.expire(null, 10_000);
    try std.testing.expect(!q.dialFailed(expired, 10_000));
    try std.testing.expect(!q.dialStarted(expired, .{ .index = 0, .generation = 0 }));
    try std.testing.expectEqual(@as(?u64, 1_800_000), q.nextWakeup(10_000, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(1_799_999, &out));
    try std.testing.expectEqual(@as(usize, 1), q.poll(1_800_000, &out));
}

fn discovered(tag: u8, sync: u8) !@import("enr.zig").Candidate {
    var secret: [32]u8 = @splat(0);
    secret[31] = tag;
    const pair = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&secret);
    const key = pair.publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    return .{ .peer = peer, .node_id = try @import("custody.zig").nodeId(&peer), .sequence = 1, .addresses = .{ address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = sync, .custody_group_count = null };
}

test "peer dial discovered refresh replaces addresses preserves lease history and manual authority" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(token, 1));
    const due = q.nextWakeup(1, 1).?;
    candidate.sequence = 2;
    candidate.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, 2);
    try std.testing.expectEqual(due, q.nextWakeup(2, 1).?);
    try std.testing.expectEqual(@as(usize, 1), q.poll(due, &out));
    try std.testing.expectEqual(@as(u16, 2222), out[0].address.port());
    const live = out[0].token;
    candidate.sequence = 3;
    candidate.addresses[0] = address;
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, due);
    try std.testing.expect(q.dialStarted(live, .{ .index = 1, .generation = 44 }));
    candidate.sequence = 2;
    try std.testing.expectError(error.StaleRecord, q.enqueueDiscovered(&candidate, &.{}, &.{}, due));
    candidate.sequence = 4;
    candidate.syncnets = 16;
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&candidate, &.{}, &.{}, due));
    try std.testing.expect(q.dialClosed(.{ .index = 1, .generation = 44 }, due));
    const peer = (try discovered(2, 0)).peer;
    try q.enqueue(&peer, &.{address}, true, 0);
    candidate = try discovered(2, 1);
    candidate.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 3 }, .port = 3333 } };
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expectEqual(@as(u16, 1234), out[0].address.port());
}

test "peer dial scarce pressure reclaims fixed expired automatic history despite rapid failures" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 2, .seed = 4 });
    defer q.deinit(a);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    var first_candidate = try discovered(1, 0);
    var second_candidate = try discovered(2, 0);
    const scarce = try discovered(3, 1);
    try q.enqueueDiscovered(&first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&second_candidate, &.{}, &wanted, 0);
    var out: [2]mod.DialIntent = undefined;
    var now: u64 = 0;
    for (0..12) |_| {
        const count = q.poll(now, &out);
        try std.testing.expectEqual(@as(usize, 2), count);
        for (out[0..count]) |intent| try std.testing.expect(q.dialFailed(intent.token, now));
        first_candidate.sequence += 1;
        second_candidate.sequence += 1;
        try q.enqueueDiscovered(&first_candidate, &.{}, &wanted, now);
        try q.enqueueDiscovered(&second_candidate, &.{}, &wanted, now);
        try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&scarce, &.{}, &wanted, now));
        now += 60_000;
    }
    try q.enqueueDiscovered(&scarce, &.{}, &wanted, now);
    q.configureSelection(&wanted, false, &.{}, now);
    try std.testing.expectEqual(@as(usize, 1), q.poll(now, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
}

test "peer dial scarce untried candidate resists general flood and fork change" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    const scarce = try discovered(3, 1);
    try q.enqueueDiscovered(&first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&second_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&scarce, &.{}, &wanted, 0);
    for (4..16) |i| {
        const general = try discovered(@intCast(i), 0);
        q.enqueueDiscovered(&general, &.{}, &wanted, 0) catch |err| try std.testing.expectEqual(error.Capacity, err);
    }
    q.configureSelection(&wanted, false, &.{ .digest = @splat(1) }, 0);
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(0, 1));
    q.configureSelection(&wanted, false, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
}

test "peer dial local admission deferral preserves retry history and endpoint" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const alternate: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    try q.enqueue(&peer, &.{ address, alternate }, false, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(0, &out);
    try std.testing.expect(q.dialDeferred(out[0].token, 0));
    try std.testing.expectEqual(@as(u8, 0), q.rows[0].failures);
    try std.testing.expectEqual(@as(?u64, 1000), q.nextWakeup(0, 1));
    _ = q.poll(1000, &out);
    try std.testing.expect(out[0].address.eql(address));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 1, .generation = 2 }));
    try std.testing.expect(!q.dialDeferred(out[0].token, 1000));
    try std.testing.expect(q.dialClosed(.{ .index = 1, .generation = 2 }, 1000));
}

test "peer dial confirmed equal ENR refresh renews provisional hint freshness without history" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const candidate = try discovered(1, 1);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    try q.enqueueDiscovered(&candidate, &.{}, &wanted, 0);
    q.configureSelection(&wanted, false, &.{}, 300_000);
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(300_000, 1));
    try q.enqueueDiscovered(&candidate, &.{}, &wanted, 300_000);
    q.configureSelection(&wanted, false, &.{}, 300_000);
    try std.testing.expectEqual(@as(?u64, 300_000), q.nextWakeup(300_000, 1));
    try std.testing.expectEqual(@as(u64, 600_000), q.rows[0].history_until_ms);
    var conflicting = candidate;
    conflicting.syncnets = 2;
    try std.testing.expectError(error.StaleRecord, q.enqueueDiscovered(&conflicting, &.{}, &wanted, 300_001));
}

test "peer dial review group shrink invalidates all hints while preserving owners and authority" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var candidate = try discovered(1, 1);
    candidate.attnets = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    candidate.custody_group_count = 128;
    var wanted: t.Coverage = .{ .attnets = 1, .syncnets = 1 };
    wanted.custody.set(0);
    try q.enqueueDiscovered(&candidate, &.{}, &wanted, 0);
    q.configureSelection(&wanted, false, &.{}, 0);
    try std.testing.expectEqual(@as(u16, 3), q.rows[0].priority);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(q.dialFailed(out[0].token, 1));
    const eligible = q.rows[0].eligible_at_ms;
    const horizon = q.rows[0].history_until_ms;
    const failures = q.rows[0].failures;
    const context: t.ForkContext = .{ .custody_groups = 64 };
    var budget: u16 = 0;
    try std.testing.expect(!q.advanceCustody(&context, eligible, &budget));
    q.configureSelection(&wanted, false, &context, eligible);
    try std.testing.expectEqual(@as(u16, 0), q.rows[0].priority);
    try std.testing.expectEqual(@as(usize, 0), q.poll(eligible, &out));
    q.configureSelection(&wanted, true, &context, eligible);
    try std.testing.expectEqual(@as(usize, 0), q.poll(eligible, &out));
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(eligible, 1));
    try std.testing.expectEqual(eligible, q.rows[0].eligible_at_ms);
    try std.testing.expectEqual(horizon, q.rows[0].history_until_ms);
    try std.testing.expectEqual(failures, q.rows[0].failures);
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&candidate, &context, &wanted, eligible));
    candidate.sequence = 2;
    candidate.custody_group_count = 64;
    try q.enqueueDiscovered(&candidate, &context, &wanted, eligible);
    q.configureSelection(&wanted, false, &context, eligible);
    try std.testing.expectEqual(@as(u16, 3), q.rows[0].priority);
    try std.testing.expectEqual(@as(usize, 1), q.poll(eligible, &out));
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 2, .generation = 99 };
    try std.testing.expect(q.dialStarted(token, conn));
    const lease = q.rows[0].lease_expires_at_ms;
    const smaller: t.ForkContext = .{ .custody_groups = 32 };
    _ = q.advanceCustody(&smaller, eligible, &budget);
    q.configureSelection(&wanted, true, &smaller, eligible);
    try std.testing.expectEqual(conn, q.rows[0].conn.?);
    try std.testing.expectEqual(lease, q.nextWakeup(eligible, 1).?);
    try std.testing.expectEqual(failures, q.rows[0].failures);
    try std.testing.expectEqual(horizon, q.rows[0].history_until_ms);
    const manual: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 9 }, .port = 9999 } };
    try q.enqueue(&candidate.peer, &.{manual}, true, eligible);
    q.configureSelection(&wanted, true, &smaller, eligible);
    try std.testing.expectEqual(@as(u16, 0), q.rows[0].priority);
    try std.testing.expect(q.isDirect(&candidate.peer));
    try std.testing.expectEqual(conn, q.rows[0].conn.?);
    try std.testing.expectEqual(@as(usize, 0), q.poll(eligible, &out));
    try std.testing.expect(q.dialClosed(conn, eligible));
    const next = q.nextWakeup(eligible, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(next, &out));
    try std.testing.expect(out[0].address.eql(manual));
}

test "peer dial review pressure utility excludes every invalid cached hint" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var old = try discovered(1, 1);
    old.attnets = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    old.custody_group_count = 128;
    const wanted: t.Coverage = .{ .attnets = 1, .syncnets = 1 };
    try q.enqueueDiscovered(&old, &.{}, &wanted, 0);
    const replacement_candidate = try discovered(2, 1);
    try q.enqueueDiscovered(&replacement_candidate, &.{ .custody_groups = 64 }, &wanted, 1);
    try std.testing.expect(q.rows[0].peer.eql(&replacement_candidate.peer));
}

test "peer dial review custody-only full table recovers at fixed horizon with bounded work" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    var scarce = try discovered(3, 0);
    scarce.custody_group_count = 127;
    var wanted: t.Coverage = .{};
    wanted.custody.setRangeValue(.{ .start = 0, .end = 128 }, true);
    try q.enqueueDiscovered(&first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&second_candidate, &.{}, &wanted, 0);
    const reservation = q.memoryPlan().allocated_bytes;
    for (0..10) |i| {
        const now = i * 60_000;
        try q.enqueueDiscovered(&first_candidate, &.{}, &wanted, now);
        try q.enqueueDiscovered(&second_candidate, &.{}, &wanted, now);
        try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&scarce, &.{}, &wanted, now));
        for (q.rows) |row| try std.testing.expect(row.custody_work == null);
    }
    try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&scarce, &.{}, &wanted, 599_999));
    try q.enqueueDiscovered(&scarce, &.{}, &wanted, 600_000);
    try std.testing.expect(q.rows[0].peer.eql(&scarce.peer));
    try std.testing.expectEqual(@as(u16, 0), q.rows[0].custody_work.?.hashes);
    q.configureSelection(&wanted, false, &.{}, 600_000);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), q.poll(600_000, &out));
    var pending = true;
    for (0..64) |_| {
        var budget: u16 = 128;
        const before = q.rows[0].custody_work.?.hashes;
        pending = q.advanceCustody(&.{}, 600_000, &budget);
        const used = q.rows[0].custody_work.?.hashes - before;
        try std.testing.expect(used <= 64);
        try std.testing.expectEqual(@as(u16, 128) - used, budget);
        if (!pending) break;
    }
    try std.testing.expect(!pending);
    try std.testing.expect(q.rows[0].custody_work.?.hashes <= 4096);
    q.configureSelection(&wanted, false, &.{}, 600_000);
    try std.testing.expectEqual(@as(u16, 127), q.rows[0].priority);
    try std.testing.expectEqual(@as(usize, 1), q.poll(600_000, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
    try std.testing.expectEqual(reservation, q.memoryPlan().allocated_bytes);
}
