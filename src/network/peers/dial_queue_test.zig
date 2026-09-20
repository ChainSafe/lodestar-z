const std = @import("std");
const mod = @import("dial_queue.zig");
const t = @import("types.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 1234 } };

test "peer discovery uses the configured custody minimum only for an absent ENR count" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const context: t.ForkContext = .{ .fork = .fulu, .custody_requirement = 4, .minimum_sampling_groups = 8 };
    const wanted: t.Coverage = .{ .custody_groups = .initFull() };
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&candidate, &context, &wanted, 0);
    try std.testing.expectEqual(@as(u64, 4), q.rows[0].custody_work.?.requested);
    var budget: u16 = @import("custody.zig").hashes_per_turn;
    try std.testing.expect(!q.advanceCustody(&context, 0, &budget));
    q.configureSelection(&wanted, false, &context, 0);
    try std.testing.expectEqual(@as(usize, 4), q.rows[0].custody_work.?.groups.count());
    try std.testing.expectEqual(@as(u2, 2), q.rows[0].priority);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    candidate.sequence += 1;
    candidate.custody_group_count = 0;
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&candidate, &context, &wanted, 0));
    candidate.custody_group_count = context.custody_groups + 1;
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&candidate, &context, &wanted, 0));
    candidate.custody_group_count = 1;
    try q.enqueueDiscovered(&candidate, &context, &wanted, 0);
    try std.testing.expectEqual(@as(u64, 1), q.rows[0].custody_work.?.requested);
}

fn peerSnapshot(peer: *const t.PeerId, conn: ?t.Handle) t.Snapshot {
    return .{
        .peer = .{ .index = 0, .generation = 1 },
        .identity = peer.*,
        .connection = conn,
        .direction = .outbound,
        .endpoint = address,
        .relevant = false,
        .status = null,
        .metadata = null,
        .status_at_ms = 0,
        .metadata_at_ms = 0,
        .connected_at_ms = 0,
        .direct = false,
        .score = 0,
        .ban_until_ms = 0,
        .goodbye_until_ms = 0,
    };
}

test "peer dial synchronization resolves connection history and deferral with one lookup" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 8, .seed = 4 });
    defer q.deinit(a);
    for (0..q.rows.len) |i| {
        const peer: t.PeerId = .{ .bytes = @splat(@intCast(i + 1)) };
        try q.enqueue(&peer, &.{address}, true, 0);
    }
    const peer = q.rows[q.rows.len - 1].peer;
    var snapshot = peerSnapshot(&peer, .{ .index = 0, .generation = 1 });
    snapshot.relevant = true;
    snapshot.status_at_ms = 100;
    q.synchronize(&snapshot, 100, 30_000);
    const row = &q.rows[q.rows.len - 1];
    try std.testing.expect(row.connected);
    try std.testing.expectEqual(@as(u64, 30_000), row.eligible_at_ms);
    try std.testing.expectEqual(@as(u64, 100 + mod.history_retention_ms), row.history_until_ms);
    try std.testing.expectEqual(@as(u64, q.rows.len), q.counters.sync_lookup_rows);

    snapshot.connection = null;
    snapshot.relevant = false;
    snapshot.disconnect_reason = .health_timeout;
    q.synchronize(&snapshot, 200, 60_000);
    try std.testing.expect(!row.connected);
    try std.testing.expectEqual(@as(u8, 1), row.failures);
    try std.testing.expectEqual(@as(u64, 1), q.counters.connection_backoffs);
    try std.testing.expectEqual(@as(u64, 60_000), row.eligible_at_ms);
    try std.testing.expectEqual(@as(u64, 200 + mod.history_retention_ms), row.history_until_ms);
    try std.testing.expectEqual(@as(u64, 2 * q.rows.len), q.counters.sync_lookup_rows);
    const random = q.random;
    q.synchronize(&snapshot, 300, 60_000);
    try std.testing.expectEqualDeep(random, q.random);
    try std.testing.expectEqual(@as(u8, 1), row.failures);
    try std.testing.expectEqual(@as(u64, 60_000), row.eligible_at_ms);
    try std.testing.expectEqual(@as(u64, 200 + mod.history_retention_ms), row.history_until_ms);
    try std.testing.expectEqual(@as(u64, 1), q.counters.connection_backoffs);
    try std.testing.expectEqual(@as(u64, 3 * q.rows.len), q.counters.sync_lookup_rows);
}

test "peer dial metrics count each completed attempt once and exclude local deferrals" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(q.dialDeferred(out[0].token, 100));
    try std.testing.expectEqual(@as(u64, 0), q.durations[1].count);
    try std.testing.expectEqual(@as(usize, 1), q.poll(1100, &out));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    q.accepted(&peer, conn, 1250);
    q.accepted(&peer, conn, 1300);
    try std.testing.expectEqual(@as(u64, 1), q.durations[0].count);
    try std.testing.expectEqual(@as(u128, 150), q.durations[0].sum);
    q.disconnected(&peer, 1250, .transport_closed, 1500);
    const due = q.nextWakeup(1500, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(due, &out));
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    try std.testing.expect(q.dialClosed(conn, due + 250));
    try std.testing.expect(!q.dialClosed(conn, due + 300));
    try std.testing.expect(!q.dialFailed(out[0].token, due + 300));
    try std.testing.expectEqual(@as(u64, 1), q.durations[1].count);
    try std.testing.expectEqual(@as(u128, 250), q.durations[1].sum);
}

test "peer dial custody diagnostics count unfinished derivations without mutating retained coverage" {
    const custody = @import("custody.zig");
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = a };
    var q = try mod.DialQueue.init(ledger.allocator(), .{ .capacity = 4, .seed = 4 });
    defer q.deinit(ledger.allocator());
    var wanted: t.Coverage = .{};
    wanted.groups.setRangeValue(.{ .start = 0, .end = 128 }, true);
    for ([_]u16{ 2, 1, 128, 2 }, 0..) |count, index| {
        var candidate = try discovered(@intCast(index + 1), 0);
        candidate.custody_group_count = count;
        try q.enqueueDiscovered(&candidate, &.{}, &wanted, 0);
    }
    try std.testing.expect((try q.rows[1].custody_work.?.step(1)) != null);
    try std.testing.expectEqual(@as(u16, 0), q.rows[2].custody_work.?.hashes);
    try std.testing.expectEqual(@as(usize, 128), q.rows[2].custody_work.?.groups.count());
    q.rows[3].custody_work.?.hashes = custody.hashes_max;
    try std.testing.expectError(error.WorkLimit, q.rows[3].custody_work.?.step(1));
    q.configureSelection(&wanted, false, &.{}, 0);
    for ([_]u16{ 0, 1, 1, 0 }, q.rows) |priority, row| {
        try std.testing.expectEqual(priority, row.priority);
    }

    const works = [4]custody.Derivation{
        q.rows[0].custody_work.?, q.rows[1].custody_work.?,
        q.rows[2].custody_work.?, q.rows[3].custody_work.?,
    };
    const cursor = q.cursor;
    const custody_cursor = q.custody_cursor;
    const random = q.random;
    const calls = ledger.allocation_calls;
    const bytes = ledger.bytes;
    const snapshot = q.resourceSnapshot();
    try std.testing.expectEqual(@as(usize, 1), snapshot.custody_incomplete);
    for (0..4) |_| {
        try std.testing.expectEqualDeep(snapshot, q.resourceSnapshot());
        for (works, q.rows, [_]u16{ 0, 1, 1, 0 }) |work, row, priority| {
            try std.testing.expectEqualDeep(work, row.custody_work.?);
            try std.testing.expectEqual(priority, row.priority);
            try std.testing.expectEqual(priority > 0, row.selected);
        }
        try std.testing.expectEqual(cursor, q.cursor);
        try std.testing.expectEqual(custody_cursor, q.custody_cursor);
        try std.testing.expectEqualDeep(random, q.random);
        try std.testing.expect(!q.selection_dirty);
        try std.testing.expectEqual(@as(?u64, mod.hint_freshness_ms), q.selection_deadline);
        try std.testing.expectEqual(calls, ledger.allocation_calls);
        try std.testing.expectEqual(bytes, ledger.bytes);
    }
}

test "peer dial custody diagnostics retain expired unfinished work without claiming eligibility" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var candidate = try discovered(1, 0);
    candidate.custody_group_count = 1;
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, 0);
    const work = q.rows[0].custody_work.?;
    var budget: u16 = 64;
    try std.testing.expect(!q.advanceCustody(&.{}, mod.hint_freshness_ms, &budget));
    try std.testing.expectEqual(@as(u16, 64), budget);
    try std.testing.expectEqual(@as(usize, 1), q.resourceSnapshot().custody_incomplete);
    try std.testing.expectEqualDeep(work, q.rows[0].custody_work.?);

    try q.enqueueDiscovered(&candidate, &.{}, &.{}, mod.hint_freshness_ms);
    try std.testing.expect(!q.advanceCustody(&.{}, mod.hint_freshness_ms, &budget));
    try std.testing.expectEqual(@as(u16, 63), budget);
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot().custody_incomplete);
    try std.testing.expectEqual(@as(usize, 1), q.rows[0].custody_work.?.groups.count());
}

test "peer dial queue copies candidates rotates addresses and ignores stale leased tokens" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 2, .concurrent_max = 1, .seed = 4 },
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
        .{ .capacity = 2, .concurrent_max = 1, .seed = 9 },
    );
    defer q.deinit(a);
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const third: t.PeerId = .{ .bytes = @splat(3) };
    try q.enqueue(&first, &.{address}, true, 0);
    try q.enqueue(&second, &.{address}, false, 0);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
    try std.testing.expectEqual(@as(?u64, mod.connect_timeout_ms), q.nextWakeup(0, 0));
    var out: [2]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 2));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&second));
    try std.testing.expect(q.isDirect(&first));
    _ = q.removeDirect(&first);
    try std.testing.expect(!q.isDirect(&first));
    q.accepted(&first, .{ .index = 0, .generation = 1 }, 1);
    try std.testing.expect(!q.rows[token.index].occupied);
    q.rows[token.index].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
}

test "peer dial queue exponential retry remains bounded through repeated failure" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 1, .concurrent_max = 1, .seed = 10 },
    );
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, true, 0);
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
        .{ .capacity = 1, .concurrent_max = 1, .seed = 4 },
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
    q.accepted(&peer, .{ .index = 1, .generation = 0 }, 10_000);
    try std.testing.expectEqualDeep(conn, q.rows[0].conn.?);
    try std.testing.expect(q.rows[0].connected);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(10_000, 0));
    try std.testing.expect(q.dialClosed(conn, 10_000));
    try std.testing.expect(q.rows[0].connected);
    try std.testing.expectEqual(@as(u64, 0), q.rows[0].manual_until_ms);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_completed);
    q.disconnected(&peer, 10_000, .transport_closed, 10_001);
    try std.testing.expectEqual(@as(usize, 0), q.poll(20_000, &out));
}

test "peer dial queue review cooldown cannot extend a lost acknowledgement lease" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 5 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(0, &out);
    const expired = out[0].token;
    q.synchronize(&peerSnapshot(&peer, null), 0, 1_800_000);
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
    return .{ .peer = peer, .node_id = try @import("custody.zig").nodeId(&peer), .sequence = 1, .record_hash = @splat(0), .addresses = .{ address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = sync, .custody_group_count = null };
}

test "peer discovery matches rotate without rewarding additional advertised coverage" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const narrow = try discovered(1, 1);
    var broad = try discovered(2, 15);
    broad.attnets = @splat(255);
    broad.custody_group_count = 128;
    const wanted: t.Coverage = .{ .syncnets = 15, .attnets = std.math.maxInt(u64) };
    try q.enqueueDiscovered(&narrow, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&broad, &.{}, &wanted, 0);
    q.configureSelection(&wanted, false, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&narrow.peer));
    try std.testing.expect(q.dialDeferred(out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&broad.peer));
    try std.testing.expect(q.dialDeferred(out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(1_000, &out));
    try std.testing.expect(out[0].peer.eql(&narrow.peer));
}

test "peer discovery breadth cannot evict an untried candidate matching current demand" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const narrow = try discovered(1, 1);
    var broad = try discovered(2, 15);
    broad.attnets = @splat(255);
    const wanted: t.Coverage = .{ .syncnets = 15, .attnets = std.math.maxInt(u64) };
    try q.enqueueDiscovered(&narrow, &.{}, &wanted, 0);
    try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&broad, &.{}, &wanted, 1));
    try std.testing.expect(q.rows[0].peer.eql(&narrow.peer));
    try q.enqueueDiscovered(&broad, &.{}, &wanted, mod.hint_freshness_ms);
    try std.testing.expect(q.rows[0].peer.eql(&broad.peer));
}

test "peer pruning defers automatic redial without blocking explicit intent or recording failures" {
    for ([_]bool{ false, true }) |explicit| {
        var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        defer q.deinit(a);
        const candidate = try discovered(1, 1);
        try q.enqueueDiscovered(&candidate, &.{}, &.{ .syncnets = 1 }, 0);
        const conn: t.Handle = .{ .index = 0, .generation = 1 };
        q.accepted(&candidate.peer, conn, 0);
        var snapshot = peerSnapshot(&candidate.peer, null);
        snapshot.disconnect_reason = .count_pruning;
        snapshot.redial_until_ms = 300_000;
        q.synchronize(&snapshot, 2_000, null);
        try std.testing.expectEqual(@as(u8, 0), q.rows[0].failures);
        try std.testing.expectEqual(@as(u64, 0), q.counters.connection_backoffs);
        try std.testing.expectEqual(@as(u64, 300_000), q.nextWakeup(2_000, 1).?);
        var out: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 0), q.poll(299_999, &out));
        if (explicit) {
            try q.enqueue(&candidate.peer, &.{address}, false, 299_999);
            try std.testing.expectEqual(@as(usize, 1), q.poll(299_999, &out));
        } else {
            try std.testing.expectEqual(@as(usize, 1), q.poll(300_000, &out));
        }
    }
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

test "peer dial equal ENR merges authorized endpoint observations without changing owners or backoff" {
    const d = @import("discv5");
    const adapter = @import("enr.zig");
    const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{1}));
    const record = try adapter.build(&key, 7, &.{
        .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 },
        .ip4 = .{ 10, 1, 0, 1 },
        .quic = 9001,
        .ip6 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1},
        .quic6 = 9002,
    }, &.{});
    const dual = try adapter.decode(&record, &.{});
    var public = dual;
    public.addresses = .{ dual.addresses[1], .unspecified };
    public.address_count = 1;
    const public_source: t.Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 9000 } };
    try std.testing.expect(!@import("discovery.zig").relayAllowed(public_source, dual.addresses[0]));
    try std.testing.expect(@import("discovery.zig").relayAllowed(public_source, public.addresses[0]));

    for (0..4) |mode| {
        var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        defer q.deinit(a);
        try q.enqueueDiscovered(if (mode == 0) &public else &dual, &.{}, &.{}, 0);
        if (mode >= 2) try q.enqueue(&dual.peer, &.{address}, mode == 3, 0);
        q.rows[0].failures = 3;
        q.rows[0].eligible_at_ms = 5000;
        if (mode == 1) q.rows[0].address_index = 1;
        var intents: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), q.poll(5000, &intents));
        try std.testing.expect(q.dialStarted(intents[0].token, .{ .index = 1, .generation = 2 }));
        @memset(q.rows[0].addresses[q.rows[0].address_count..], .unspecified);
        var expected = q.rows[0];
        try q.enqueueDiscovered(if (mode == 0) &dual else &public, &.{}, &.{}, 6000);
        expected.hints_at_ms = 6000;
        if (mode == 0) {
            expected.addresses = .{ dual.addresses[1], dual.addresses[0] };
            expected.address_count = 2;
        }
        try std.testing.expectEqualDeep(expected, q.rows[0]);
        try q.enqueueDiscovered(&public, &.{}, &.{}, 7000);
        expected.hints_at_ms = 7000;
        try std.testing.expectEqualDeep(expected, q.rows[0]);
    }
}

test "peer dial review group shrink invalidates all hints while preserving owners and authority" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var candidate = try discovered(1, 1);
    candidate.attnets = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    candidate.custody_group_count = 128;
    var wanted: t.Coverage = .{ .attnets = 1, .syncnets = 1 };
    wanted.groups.set(0);
    try q.enqueueDiscovered(&candidate, &.{}, &wanted, 0);
    q.configureSelection(&wanted, false, &.{}, 0);
    try std.testing.expectEqual(@as(u16, 2), q.rows[0].priority);
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
    try std.testing.expectEqual(@as(u16, 2), q.rows[0].priority);
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
    wanted.groups.setRangeValue(.{ .start = 0, .end = 128 }, true);
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
    try std.testing.expectEqual(@as(u16, 1), q.rows[0].priority);
    try std.testing.expectEqual(@as(usize, 1), q.poll(600_000, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
    try std.testing.expectEqual(reservation, q.memoryPlan().allocated_bytes);
}

test "peer direct membership enumeration is complete atomic and read only" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const addresses = [_]t.Address{ address, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } } };
    const sentinel: t.PeerId = .{ .bytes = @splat(9) };
    try std.testing.expectEqual(@as(usize, 0), try q.directPeers(&.{}));
    try std.testing.expect(!q.removeDirect(&first));
    try q.enqueue(&first, &addresses, true, 0);
    try q.enqueue(&first, &addresses, true, 0);
    try q.enqueue(&second, &addresses, true, 0);
    q.configureSelection(&.{}, true, &.{}, 0);
    const rows = [2]@TypeOf(q.rows[0]){ q.rows[0], q.rows[1] };
    const before = q;
    var short = [_]t.PeerId{sentinel};
    try std.testing.expectError(error.OutputTooSmall, q.directPeers(&short));
    try std.testing.expectEqualDeep([_]t.PeerId{sentinel}, short);
    var out: [2]t.PeerId = undefined;
    try std.testing.expectEqual(@as(usize, 2), try q.directPeers(&out));
    try std.testing.expectEqualDeep([_]t.PeerId{ first, second }, out);
    try std.testing.expectEqualDeep(before, q);
    try std.testing.expectEqualDeep(rows, q.rows[0..2].*);
    try std.testing.expect(q.removeDirect(&first));
    try std.testing.expect(!q.removeDirect(&first));
    try std.testing.expectEqual(@as(usize, 1), try q.directPeers(&out));
    try std.testing.expect(out[0].eql(&second));
    try std.testing.expect(q.removeDirect(&second));
    try std.testing.expectEqual(@as(usize, 0), try q.directPeers(&.{}));
}

test "peer explicit address updates reject overflow and invalid input without mutation" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    const third: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 3456 } };
    try q.enqueue(&peer, &.{ address, second }, false, 0);
    q.configureSelection(&.{}, true, &.{}, 0);
    const before = q.rows[0];
    const selection = q;
    try std.testing.expectError(error.AddressCapacity, q.enqueue(&peer, &.{third}, true, 10));
    try std.testing.expectEqualDeep(before, q.rows[0]);
    try std.testing.expectEqualDeep(selection.random, q.random);
    try std.testing.expectEqual(selection.selection_dirty, q.selection_dirty);
    try std.testing.expectEqual(selection.selection_deadline, q.selection_deadline);
    try std.testing.expectEqual(selection.cursor, q.cursor);
    try std.testing.expectEqual(selection.custody_cursor, q.custody_cursor);
    try std.testing.expectError(error.InvalidAddress, q.enqueue(&peer, &.{ third, .unspecified }, true, 10));
    try std.testing.expectEqualDeep(before, q.rows[0]);
    try std.testing.expectEqualDeep(selection.random, q.random);
    try std.testing.expectEqual(selection.selection_dirty, q.selection_dirty);
    try std.testing.expectEqual(selection.selection_deadline, q.selection_deadline);
    try std.testing.expectEqual(selection.cursor, q.cursor);
    try std.testing.expectEqual(selection.custody_cursor, q.custody_cursor);
    for ([_]t.Address{ address, second }) |known| {
        try q.enqueue(&peer, &.{known}, false, 10);
        var refreshed = before;
        refreshed.manual_until_ms = 10 + mod.connect_timeout_ms;
        try std.testing.expectEqualDeep(refreshed, q.rows[0]);
    }
}

test "peer discovered conversion replaces addresses while retaining retry history" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&candidate, &.{}, &.{}, 0);
    q.rows[0].failures = 3;
    q.rows[0].eligible_at_ms = 9000;
    const explicit: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 5432 } };
    try q.enqueue(&candidate.peer, &.{ explicit, explicit }, true, 10);
    try std.testing.expect(!q.rows[0].automatic);
    try std.testing.expect(q.rows[0].direct);
    try std.testing.expectEqual(@as(u8, 1), q.rows[0].address_count);
    try std.testing.expectEqualDeep(explicit, q.rows[0].addresses[0]);
    try std.testing.expectEqual(@as(u8, 3), q.rows[0].failures);
    try std.testing.expectEqual(@as(u64, 9000), q.rows[0].eligible_at_ms);
}

test "peer repeated initial address leaves room for a distinct explicit address" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    try q.enqueue(&peer, &.{ address, address }, false, 0);
    try q.enqueue(&peer, &.{second}, true, 1);
    try std.testing.expectEqual(@as(u8, 2), q.rows[0].address_count);
    try std.testing.expectEqualDeep([_]t.Address{ address, second }, q.rows[0].addresses);
}

test "peer retained attempt does not hide canonical connection closure" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 5 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    try q.enqueue(&peer, &.{ address, second }, true, 0);
    var intents: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &intents));
    const token = intents[0].token;
    const attempt: t.Handle = .{ .index = 0, .generation = 4 };
    try std.testing.expect(q.dialStarted(token, attempt));
    q.accepted(&peer, .{ .index = 1, .generation = 7 }, 10);
    try std.testing.expect(q.rows[0].connected);
    const lease = q.rows[0].lease_expires_at_ms;
    var snapshot = peerSnapshot(&peer, null);
    snapshot.connected_at_ms = 10;
    q.synchronize(&snapshot, 20, null);
    try std.testing.expect(!q.rows[0].connected);
    try std.testing.expect(q.rows[0].attempt);
    try std.testing.expectEqual(attempt, q.rows[0].conn.?);
    try std.testing.expectEqual(lease, q.rows[0].lease_expires_at_ms);
    try std.testing.expectEqual(@as(u64, 1), q.counters.connection_backoffs);
    const disconnected = q.rows[0];
    q.synchronize(&snapshot, 20, null);
    try std.testing.expectEqualDeep(disconnected, q.rows[0]);
    try std.testing.expect(!q.dialStarted(token, attempt));
    try std.testing.expect(!q.dialFailed(token, 20));
    try std.testing.expect(q.dialClosed(attempt, 30));
    try std.testing.expect(!q.rows[0].connected);
    try std.testing.expect(!q.rows[0].attempt);
    try std.testing.expect(q.rows[0].conn == null);
    try std.testing.expect(q.rows[0].direct);
    const due = q.nextWakeup(30, 1).?;
    try std.testing.expect(due >= 5020 and due <= 6020);
    try std.testing.expectEqual(@as(usize, 0), q.poll(due - 1, &intents));
    try std.testing.expectEqual(@as(usize, 1), q.poll(due, &intents));
    try std.testing.expectEqual(token.index, intents[0].token.index);
    try std.testing.expectEqual(token.generation + 1, intents[0].token.generation);
    try std.testing.expectEqualDeep(peer, intents[0].peer);
    try std.testing.expectEqualDeep(second, intents[0].address);
}

test "peer dial actual custody gives no utility for connected sampling only groups" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    var candidate = try discovered(1, 0);
    candidate.custody_group_count = 4;
    const context: t.ForkContext = .{ .fork = .fulu, .minimum_sampling_groups = 8 };
    var pair = try @import("custody.zig").SamplingDerivation.init(&candidate.node_id, .{ .groups = 128, .columns = 128 }, 4, 8);
    const derived = (try pair.step(64)).?;
    var wanted: t.Coverage = .{ .groups = derived.sampling.differenceWith(derived.custody) };
    try std.testing.expectEqual(@as(usize, 4), wanted.groups.count());
    try q.enqueueDiscovered(&candidate, &context, &wanted, 0);
    var budget: u16 = 64;
    try std.testing.expect(!q.advanceCustody(&context, 0, &budget));
    q.configureSelection(&wanted, false, &context, 0);
    try std.testing.expectEqual(@as(u16, 0), q.rows[0].priority);
    try std.testing.expect(!q.rows[0].selected);
    try std.testing.expectEqual(@as(u16, 4), @import("policy.zig").utility(&.{ .groups = derived.sampling }, &wanted));
    wanted.groups = derived.custody;
    q.configureSelection(&wanted, false, &context, 0);
    try std.testing.expectEqual(@as(u16, 1), q.rows[0].priority);
    try std.testing.expect(q.rows[0].selected);
}

test "peer manual dial completes once and expires without retaining intent" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    var out: [1]mod.DialIntent = undefined;
    try q.enqueueUntil(&peer, &.{address}, false, 0, 5_000);
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(token, conn));
    q.accepted(&peer, conn, 1);
    q.disconnected(&peer, 1, .transport_closed, 20);
    try std.testing.expectEqual(@as(usize, 0), q.poll(20_000, &out));
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot().occupied);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_completed);
    try q.enqueueUntil(&peer, &.{address}, false, 20_000, 21_000);
    try std.testing.expectEqual(@as(usize, 0), q.poll(21_000, &out));
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot().occupied);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_expired);
    try std.testing.expect(!q.dialFailed(token, 21_000));
}

test "peer manual dial deadlines merge while direct reconnects back off" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueueUntil(&peer, &.{address}, false, 0, 10_000);
    try q.enqueueUntil(&peer, &.{address}, false, 1, 20_000);
    try q.enqueueUntil(&peer, &.{address}, false, 2, 5_000);
    try std.testing.expectEqual(@as(u64, 20_000), q.rows[0].manual_until_ms);
    try q.enqueue(&peer, &.{address}, true, 2);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 2;
    for (0..3) |i| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(now, &out));
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i) };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        q.accepted(&peer, conn, now);
        q.disconnected(&peer, now, .health_timeout, now + 100);
        const due = q.nextWakeup(now + 100, 1).?;
        const minimum = @as(u64, 5_000) << @intCast(i);
        try std.testing.expect(due >= now + 100 + minimum and due <= now + 1_100 + minimum);
        try std.testing.expectEqual(@as(usize, 0), q.poll(due - 1, &out));
        now = due;
    }
    try std.testing.expectEqual(@as(u64, 3), q.counters.connection_backoffs);
    try std.testing.expect(q.isDirect(&peer));
}

test "peer dial simultaneous inbound success does not record the redundant outbound close as failure" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    const outbound: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, outbound));
    q.accepted(&peer, .{ .index = 1, .generation = 1 }, 100);
    try std.testing.expect(q.dialClosed(outbound, 200));
    try std.testing.expectEqual(@as(u8, 0), q.rows[0].failures);
    try std.testing.expectEqual(@as(u64, 0), q.durations[1].count);
}

test "peer explicit dial ranks above discovery coverage" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const candidate = try discovered(1, 15);
    const manual = try discovered(2, 0);
    try q.enqueueDiscovered(&candidate, &.{}, &.{ .syncnets = 15 }, 0);
    try q.enqueue(&manual.peer, &.{address}, false, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expectEqualDeep(manual.peer, out[0].peer);
}

test "peer failed discovery candidate yields its slot after retry backoff" {
    var q = try mod.DialQueue.init(a, .{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    defer q.deinit(a);
    const forged = try discovered(1, 15);
    const replacement = try discovered(2, 0);
    try q.enqueueDiscovered(&forged, &.{}, &.{ .syncnets = 15 }, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(q.dialFailed(out[0].token, 1));
    const retry_at = q.nextWakeup(1, 1).?;
    try q.enqueueDiscovered(&replacement, &.{}, &.{ .syncnets = 15 }, retry_at);
    try std.testing.expectEqual(@as(usize, 1), q.poll(retry_at, &out));
    try std.testing.expectEqualDeep(replacement.peer, out[0].peer);
}
