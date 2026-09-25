const std = @import("std");
const mod = @import("dialing.zig");
const t = @import("types.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 1234 } };

test "peer dial preference gives automatic demand a turn with one or four attempts" {
    for ([_]u16{ 1, 4 }) |concurrency| {
        var q = try mod.Dialing.init(.{ .capacity = 8, .concurrent_max = concurrency, .seed = 4 });
        var catalog = try initCatalog(a, q.options);
        defer catalog.deinit(a);
        const automatic = try discovered(9, 1);
        try q.enqueueDiscovered(&catalog, &automatic, &.{}, &.{ .syncnets = 1 }, 0);
        q.configureSelection(&catalog, &.{ .syncnets = 1 }, true, &.{}, 0);
        for (0..7) |index| {
            const peer: t.PeerId = .{ .bytes = @splat(@as(u8, @intCast(index + 1))) };
            try q.enqueue(&catalog, &peer, &.{address}, index % 2 == 0, 0);
        }
        var out: [1]mod.DialIntent = undefined;
        for (0..concurrency) |_| {
            try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
            try std.testing.expect(!out[0].peer.eql(&automatic.peer));
            try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 0));
        }
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
        try std.testing.expect(out[0].peer.eql(&automatic.peer));
    }
}

test "peer dial local admission refusal retires without failure or address rotation" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{ address, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 1234 } } }, true, 0);
    try std.testing.expect(!q.selectedPeer(&catalog, &peer, 0));
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.selectedPeer(&catalog, &peer, 0));
    try std.testing.expect(!q.selectedPeer(&catalog, &peer, 10_000));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    try std.testing.expectEqual(@as(u16, 1), q.pendingPeers(&catalog, null));
    try std.testing.expectEqual(@as(u16, 0), q.pendingPeers(&catalog, &peer));
    try std.testing.expect(q.deferConnection(&catalog, conn, 100));
    try std.testing.expect(!q.selectedPeer(&catalog, &peer, 100));
    try std.testing.expect(!q.dialClosed(&catalog, conn, .handshake_timeout, 200));
    const row = catalog.rowFor(catalog.find(&peer).?).?;
    try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
    try std.testing.expectEqual(@as(u8, 0), row.intent.address_index);
    try std.testing.expectEqual(@as(u64, 1_100), row.intent.eligible_at_ms);
    try std.testing.expectEqual(@as(u64, 0), q.durations[1].count);
}

test "peer discovery uses the configured custody minimum only for an absent ENR count" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const context: t.ForkContext = .{ .fork = .fulu, .custody_requirement = 4, .minimum_sampling_groups = 8 };
    const wanted: t.Coverage = .{ .custody_groups = .initFull() };
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, 0);
    try std.testing.expectEqual(@as(u64, 4), candidates[0].custody_work.?.custody_count);
    var budget: u16 = @import("custody.zig").hashes_per_turn;
    try std.testing.expect(!catalog.advanceCustody(&context, 0, 60_000, &budget));
    q.configureSelection(&catalog, &wanted, false, &context, 0);
    try std.testing.expectEqual(@as(usize, 4), candidates[0].custody_work.?.walk.groups.count());
    try std.testing.expectEqual(@as(u2, 2), candidates[0].intent.priority);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expectEqual(@as(u64, 1), q.selected_attempts[@intFromEnum(mod.Source.discovery)]);
    candidate.sequence += 1;
    candidate.custody_group_count = 0;
    try q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, 0);
    try std.testing.expectEqual(@as(?u64, 0), candidates[0].intent.hints.?.custody_group_count);
    try std.testing.expect(candidates[0].custody_work == null);
    candidate.custody_group_count = context.custody_groups + 1;
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, 0));
    candidate.sequence += 1;
    candidate.custody_group_count = 1;
    try q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, 0);
    try std.testing.expectEqual(@as(u64, 1), candidates[0].custody_work.?.custody_count);
}

test "peer dial metrics count each completed attempt once and exclude local deferrals" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 100));
    try std.testing.expectEqual(@as(u64, 1), q.selected_attempts[@intFromEnum(mod.Source.direct)]);
    try std.testing.expectEqual(@as(u64, 0), q.durations[1].count);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 1100, &out));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    accept(&q, &catalog, &peer, conn, 1250);
    accept(&q, &catalog, &peer, conn, 1300);
    try std.testing.expectEqual(@as(u64, 1), q.durations[0].count);
    try std.testing.expectEqual(@as(u128, 150), q.durations[0].sum);
    disconnect(&catalog, &peer, 1250, .transport_closed, 1500);
    const due = q.nextWakeup(&catalog, 1500, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &out));
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .handshake_timeout, due + 250));
    try std.testing.expect(!q.dialClosed(&catalog, conn, .handshake_timeout, due + 300));
    try std.testing.expect(!q.dialFailed(&catalog, out[0].token, due + 300));
    try std.testing.expectEqual(@as(u64, 1), q.durations[1].count);
    try std.testing.expectEqual(@as(u128, 250), q.durations[1].sum);
    try std.testing.expectEqual(@as(u64, 3), q.selected_attempts[@intFromEnum(mod.Source.direct)]);
    try std.testing.expectEqual(@as(u64, 0), q.selected_attempts[@intFromEnum(mod.Source.manual)]);
}

test "peer dial outcomes count every retired attempt once and retries count each failure once" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueueUntil(&catalog, &peer, &.{address}, true, 0, 3_600_000);
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    var now: u64 = 0;
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .peer_id_mismatch, now));
    // A retry that ends in a local start deferral or admission refusal leaves no failure to retry again.
    try std.testing.expect(q.dialDeferred(&catalog, try selectNext(&q, &catalog, &now), now));
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .{ .peer_closed = .{ .app = false, .code = 2 } }, now));
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    try std.testing.expect(q.deferConnection(&catalog, conn, now));
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .handshake_timeout, now));
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .dial_unanswered, now));
    _ = try selectNext(&q, &catalog, &now);
    now += 10_000;
    q.expire(&catalog, null, now);
    try std.testing.expect(q.dialFailed(&catalog, try selectNext(&q, &catalog, &now), now));
    // A health close of a dialed connection marks its endpoint, so the next dial is a redial after a health close.
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    accept(&q, &catalog, &peer, conn, now);
    disconnect(&catalog, &peer, now, .health_timeout, now + 100);
    now += 100;
    // An outbound attempt made redundant by an inbound connection is cancelled, not failed.
    try std.testing.expect(q.dialStarted(try selectNext(&q, &catalog, &now), conn));
    accept(&q, &catalog, &peer, .{ .index = 1, .generation = 1 }, now);
    try std.testing.expect(q.dialClosed(&catalog, conn, .handshake_timeout, now));
    for (q.outcomes) |count| try std.testing.expectEqual(@as(u64, 1), count);
    var selected: u64 = 0;
    for (q.selected_attempts) |count| selected += count;
    try std.testing.expectEqual(@as(u64, q.outcomes.len), selected);
    for (q.retries) |count| try std.testing.expectEqual(@as(u64, 1), count);
}

test "peer dial custody diagnostics count unfinished derivations without mutating retained coverage" {
    const custody = @import("custody.zig");
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = a };
    var q = try mod.Dialing.init(.{ .capacity = 4, .seed = 4 });
    var catalog = try initCatalog(ledger.allocator(), q.options);
    defer catalog.deinit(ledger.allocator());
    const candidates = catalog.rows[0..q.options.capacity];
    var wanted: t.Coverage = .{};
    wanted.groups.setRangeValue(.{ .start = 0, .end = 128 }, true);
    for ([_]u16{ 2, 1, 128, 2 }, 0..) |count, index| {
        var candidate = try discovered(@intCast(index + 1), 0);
        candidate.custody_group_count = count;
        try q.enqueueDiscovered(&catalog, &candidate, &.{}, &wanted, 0);
    }
    try std.testing.expect((try candidates[1].custody_work.?.step(1)) != null);
    try std.testing.expectEqual(@as(u16, 0), candidates[2].custody_work.?.walk.hashes);
    try std.testing.expectEqual(@as(usize, 128), candidates[2].custody_work.?.walk.groups.count());
    candidates[3].custody_work.?.walk.hashes = custody.hashes_max;
    try std.testing.expectError(error.WorkLimit, candidates[3].custody_work.?.step(1));
    q.configureSelection(&catalog, &wanted, false, &.{}, 0);
    for ([_]u16{ 0, 1, 1, 0 }, candidates) |priority, row| {
        try std.testing.expectEqual(priority, row.intent.priority);
    }

    const works = [4]custody.SamplingDerivation{
        candidates[0].custody_work.?, candidates[1].custody_work.?,
        candidates[2].custody_work.?, candidates[3].custody_work.?,
    };
    const cursor = q.cursor;
    const custody_cursor = catalog.candidate_custody_cursor;
    const random = q.random;
    const calls = ledger.allocation_calls;
    const bytes = ledger.bytes;
    const snapshot = q.resourceSnapshot(&catalog);
    try std.testing.expectEqual(@as(usize, 1), snapshot.custody_incomplete);
    for (0..4) |_| {
        try std.testing.expectEqualDeep(snapshot, q.resourceSnapshot(&catalog));
        for (works, candidates, [_]u16{ 0, 1, 1, 0 }) |work, row, priority| {
            try std.testing.expectEqualDeep(work, row.custody_work.?);
            try std.testing.expectEqual(priority, row.intent.priority);
            try std.testing.expectEqual(priority > 0, row.intent.selected);
        }
        try std.testing.expectEqual(cursor, q.cursor);
        try std.testing.expectEqual(custody_cursor, catalog.candidate_custody_cursor);
        try std.testing.expectEqualDeep(random, q.random);
        try std.testing.expect(!q.selection_dirty);
        try std.testing.expectEqual(@as(?u64, mod.hint_freshness_ms), q.selection_deadline);
        try std.testing.expectEqual(calls, ledger.allocation_calls);
        try std.testing.expectEqual(bytes, ledger.bytes);
    }
}

test "peer dial custody diagnostics retain expired unfinished work without claiming eligibility" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    var candidate = try discovered(1, 0);
    candidate.custody_group_count = 1;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    const work = candidates[0].custody_work.?;
    var budget: u16 = 64;
    try std.testing.expect(!catalog.advanceCustody(&.{}, mod.hint_freshness_ms, 60_000, &budget));
    try std.testing.expectEqual(@as(u16, 64), budget);
    try std.testing.expectEqual(@as(usize, 1), q.resourceSnapshot(&catalog).custody_incomplete);
    try std.testing.expectEqualDeep(work, candidates[0].custody_work.?);

    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, mod.hint_freshness_ms);
    try std.testing.expect(!catalog.advanceCustody(&.{}, mod.hint_freshness_ms, 60_000, &budget));
    try std.testing.expectEqual(@as(u16, 63), budget);
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot(&catalog).custody_incomplete);
    try std.testing.expectEqual(@as(usize, 1), candidates[0].custody_work.?.walk.groups.count());
}

test "peer dial queue copies candidates rotates addresses and ignores stale leased tokens" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    var peer: t.PeerId = .{ .bytes = @splat(1) };
    var addresses = [_]t.Address{
        address,
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4321 } },
    };
    try q.enqueue(&catalog, &peer, &addresses, false, 0);
    try q.enqueue(&catalog, &peer, &addresses, false, 0);
    peer.bytes[0] = 9;
    addresses[0] = .unspecified;
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    const first = out[0];
    try std.testing.expectEqual(@as(u8, 1), first.peer.bytes[0]);
    try std.testing.expectEqualDeep(address, first.address);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, 0, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 10_000, &out));
    try std.testing.expect(!q.dialStarted(first.token, .{ .index = 0, .generation = 1 }));
    const due = q.nextWakeup(&catalog, 10_000, 1).?;
    try std.testing.expect(due >= 11_000 and due <= 12_000);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &out));
    try std.testing.expectEqual(@as(u16, 4321), out[0].address.port());
    try std.testing.expect(!q.dialFailed(&catalog, first.token, due));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 2, .generation = 7 }));
    try std.testing.expect(!q.dialFailed(&catalog, out[0].token, due));
    try std.testing.expect(q.dialClosed(&catalog, .{ .index = 2, .generation = 7 }, .handshake_timeout, due));
}

test "peer dial queue bounded pressure generation exhaustion and zero output do not spin" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 9 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const third: t.PeerId = .{ .bytes = @splat(3) };
    try q.enqueue(&catalog, &first, &.{address}, true, 0);
    try q.enqueue(&catalog, &second, &.{address}, false, 0);
    try std.testing.expectError(error.Capacity, q.enqueue(&catalog, &third, &.{address}, false, 0));
    try std.testing.expectEqual(@as(?u64, mod.connect_timeout_ms), q.nextWakeup(&catalog, 0, 0));
    var out: [2]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, 0, 2));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(&catalog, token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&second));
    try std.testing.expect(catalog.isDirect(&first));
    _ = catalog.removeDirect(&first);
    try std.testing.expect(!catalog.isDirect(&first));
    accept(&q, &catalog, &first, .{ .index = 0, .generation = 1 }, 1);
    try std.testing.expect(!catalog.intents.isSet(catalog.find(&first).?.index));
    q.active[token.index].generation = std.math.maxInt(u64);
    try q.enqueue(&catalog, &third, &.{address}, false, 0);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 1, &out));
}

test "peer dial queue exponential retry remains bounded through repeated failure" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 10 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, true, 0);
    var now: u64 = 0;
    var out: [1]mod.DialIntent = undefined;
    for (0..20) |_| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, now, &out));
        try std.testing.expect(q.dialFailed(&catalog, out[0].token, now));
        const due = q.nextWakeup(&catalog, now, 1).?;
        try std.testing.expect(due - now >= 1_000 and due - now <= 60_000);
        now = due;
    }
}

test "peer dial queue polling and failure without native owner preserve started handles" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, false, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(&catalog, 0, &out);
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 0, .generation = 0 };
    try std.testing.expect(q.dialStarted(token, conn));
    try std.testing.expect(!q.dialFailed(&catalog, token, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 10_000, &out));
    try std.testing.expectEqualDeep(conn, q.active[0].connection.?);
    try std.testing.expect(candidates[0].attempt != null);
    accept(&q, &catalog, &peer, .{ .index = 1, .generation = 0 }, 10_000);
    try std.testing.expectEqualDeep(conn, q.active[0].connection.?);
    try std.testing.expect(candidates[0].connection != null);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, 10_000, 0));
    try std.testing.expect(q.dialClosed(&catalog, conn, .handshake_timeout, 10_000));
    try std.testing.expect(candidates[0].connection != null);
    try std.testing.expectEqual(@as(u64, 0), candidates[0].intent.manual_until_ms);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_completed);
    disconnect(&catalog, &peer, 10_000, .transport_closed, 10_001);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 20_000, &out));
}

test "peer dial queue review cooldown cannot extend a lost acknowledgement lease" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 5 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(&catalog, 0, &out);
    const expired = out[0].token;
    catalog.rows[catalog.find(&peer).?.index].reputation.goodbye_until_ms = 1_800_000;
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, 0, 0));
    q.expire(&catalog, null, 10_000);
    try std.testing.expect(!q.dialFailed(&catalog, expired, 10_000));
    try std.testing.expect(!q.dialStarted(expired, .{ .index = 0, .generation = 0 }));
    try std.testing.expectEqual(@as(?u64, 1_800_000), q.nextWakeup(&catalog, 10_000, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 1_799_999, &out));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 1_800_000, &out));
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
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const narrow = try discovered(1, 1);
    var broad = try discovered(2, 15);
    broad.attnets = @splat(255);
    broad.custody_group_count = 128;
    const wanted: t.Coverage = .{ .syncnets = 15, .attnets = std.math.maxInt(u64) };
    try q.enqueueDiscovered(&catalog, &narrow, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&catalog, &broad, &.{}, &wanted, 0);
    q.configureSelection(&catalog, &wanted, false, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&narrow.peer));
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&broad.peer));
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 1_000, &out));
    try std.testing.expect(out[0].peer.eql(&narrow.peer));
}

test "peer discovery breadth cannot evict an untried candidate matching current demand" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const narrow = try discovered(1, 1);
    var broad = try discovered(2, 15);
    broad.attnets = @splat(255);
    const wanted: t.Coverage = .{ .syncnets = 15, .attnets = std.math.maxInt(u64) };
    try q.enqueueDiscovered(&catalog, &narrow, &.{}, &wanted, 0);
    try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&catalog, &broad, &.{}, &wanted, 1));
    try std.testing.expect(candidates[0].identity.eql(&narrow.peer));
    try q.enqueueDiscovered(&catalog, &broad, &.{}, &wanted, mod.hint_freshness_ms);
    try std.testing.expect(candidates[0].identity.eql(&broad.peer));
}

test "peer pruning defers automatic redial without blocking explicit intent or recording failures" {
    for ([_]bool{ false, true }) |explicit| {
        var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        var catalog = try initCatalog(a, q.options);
        defer catalog.deinit(a);
        const candidates = catalog.rows[0..q.options.capacity];
        const candidate = try discovered(1, 1);
        try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{ .syncnets = 1 }, 0);
        const conn: t.Handle = .{ .index = 0, .generation = 1 };
        accept(&q, &catalog, &candidate.peer, conn, 0);
        _ = catalog.deferRedial(catalog.find(&candidate.peer).?, conn, 0, 300_000);
        disconnect(&catalog, &candidate.peer, 0, .count_pruning, 2_000);
        try std.testing.expectEqual(@as(u8, 0), candidates[0].intent.failures);
        try std.testing.expectEqual(@as(u64, 0), catalog.connection_backoffs);
        try std.testing.expectEqual(@as(u64, 300_000), q.nextWakeup(&catalog, 2_000, 1).?);
        var out: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 299_999, &out));
        if (explicit) {
            try q.enqueue(&catalog, &candidate.peer, &.{address}, false, 299_999);
            try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 299_999, &out));
        } else {
            try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 300_000, &out));
        }
    }
}

test "peer dial discovered refresh replaces addresses preserves lease history and manual authority" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(&catalog, token, 1));
    const due = q.nextWakeup(&catalog, 1, 1).?;
    candidate.sequence = 2;
    candidate.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 2);
    try std.testing.expectEqual(due, q.nextWakeup(&catalog, 2, 1).?);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &out));
    try std.testing.expectEqual(@as(u16, 2222), out[0].address.port());
    const live = out[0].token;
    candidate.sequence = 3;
    candidate.addresses[0] = address;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, due);
    try std.testing.expect(q.dialStarted(live, .{ .index = 1, .generation = 44 }));
    candidate.sequence = 2;
    try std.testing.expectError(error.StaleRecord, q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, due));
    candidate.sequence = 4;
    candidate.syncnets = 16;
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, due));
    try std.testing.expect(q.dialClosed(&catalog, .{ .index = 1, .generation = 44 }, .handshake_timeout, due));
    const peer = (try discovered(2, 0)).peer;
    try q.enqueue(&catalog, &peer, &.{address}, true, 0);
    candidate = try discovered(2, 1);
    candidate.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 3 }, .port = 3333 } };
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expectEqual(@as(u16, 1234), out[0].address.port());
    const first = (try discovered(1, 0)).peer;
    const history = &catalog.history;
    try std.testing.expectEqual(@as(u8, 1), history.strikesFor(history.endpointKey(&first, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } }), 3, due));
    try std.testing.expectEqual(@as(u8, 1), history.strikesFor(history.endpointKey(&first, address), 1, due));
    try std.testing.expect(!history.blocked(history.endpointKey(&first, address), 3, due));
    const row = catalog.rowFor(catalog.find(&first).?).?;
    try std.testing.expect(row.intent.automatic);
    try std.testing.expect(row.intent.addresses[row.intent.address_index].eql(address));
    try std.testing.expectEqual(@as(u64, 0), q.counters.failed_intents_released);
}

test "peer dial scarce candidate replaces failing automatic rows during their backoff" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 2, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    const scarce = try discovered(3, 1);
    try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&catalog, &second_candidate, &.{}, &wanted, 0);
    var out: [2]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 2), q.poll(&catalog, 0, &out));
    for (out) |intent| try std.testing.expect(q.dialFailed(&catalog, intent.token, 0));
    try q.enqueueDiscovered(&catalog, &scarce, &.{}, &wanted, 1);
    q.configureSelection(&catalog, &wanted, false, &.{}, 1);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 1, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
}

test "peer dial scarce untried candidate resists general flood and fork change" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    const scarce = try discovered(3, 1);
    try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&catalog, &second_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&catalog, &scarce, &.{}, &wanted, 0);
    for (4..16) |i| {
        const general = try discovered(@intCast(i), 0);
        q.enqueueDiscovered(&catalog, &general, &.{}, &wanted, 0) catch |err| try std.testing.expectEqual(error.Capacity, err);
    }
    q.configureSelection(&catalog, &wanted, false, &.{ .digest = @splat(1) }, 0);
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(&catalog, 0, 1));
    q.configureSelection(&catalog, &wanted, false, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
}

test "peer dial local admission deferral preserves retry history and endpoint" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const alternate: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    try q.enqueue(&catalog, &peer, &.{ address, alternate }, false, 0);
    var out: [1]mod.DialIntent = undefined;
    _ = q.poll(&catalog, 0, &out);
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 0));
    try std.testing.expectEqual(@as(u8, 0), candidates[0].intent.failures);
    try std.testing.expectEqual(@as(?u64, 1000), q.nextWakeup(&catalog, 0, 1));
    _ = q.poll(&catalog, 1000, &out);
    try std.testing.expect(out[0].address.eql(address));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 1, .generation = 2 }));
    try std.testing.expect(!q.dialDeferred(&catalog, out[0].token, 1000));
    try std.testing.expect(q.dialClosed(&catalog, .{ .index = 1, .generation = 2 }, .handshake_timeout, 1000));
}

test "peer dial confirmed equal ENR refresh renews provisional hint freshness without history" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const candidate = try discovered(1, 1);
    const wanted: t.Coverage = .{ .syncnets = 1 };
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &wanted, 0);
    q.configureSelection(&catalog, &wanted, false, &.{}, 300_000);
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(&catalog, 300_000, 1));
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &wanted, 300_000);
    q.configureSelection(&catalog, &wanted, false, &.{}, 300_000);
    try std.testing.expectEqual(@as(?u64, 300_000), q.nextWakeup(&catalog, 300_000, 1));
    try std.testing.expectEqual(@as(u64, 600_000), candidates[0].intent.history_until_ms);
    var conflicting = candidate;
    conflicting.syncnets = 2;
    try std.testing.expectError(error.StaleRecord, q.enqueueDiscovered(&catalog, &conflicting, &.{}, &wanted, 300_001));
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
        var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        var catalog = try initCatalog(a, q.options);
        defer catalog.deinit(a);
        const candidates = catalog.rows[0..q.options.capacity];
        try q.enqueueDiscovered(&catalog, if (mode == 0) &public else &dual, &.{}, &.{}, 0);
        if (mode >= 2) try q.enqueue(&catalog, &dual.peer, &.{address}, mode == 3, 0);
        candidates[0].intent.failures = 3;
        candidates[0].intent.eligible_at_ms = 5000;
        if (mode == 1) candidates[0].intent.address_index = 1;
        var intents: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 5000, &intents));
        try std.testing.expect(q.dialStarted(intents[0].token, .{ .index = 1, .generation = 2 }));
        @memset(candidates[0].intent.addresses[candidates[0].intent.address_count..], .unspecified);
        var expected = candidates[0];
        try q.enqueueDiscovered(&catalog, if (mode == 0) &dual else &public, &.{}, &.{}, 6000);
        expected.intent.hints_at_ms = 6000;
        if (mode == 0) {
            expected.intent.addresses = .{ dual.addresses[1], dual.addresses[0] };
            expected.intent.address_count = 2;
        }
        try std.testing.expectEqualDeep(expected, candidates[0]);
        try q.enqueueDiscovered(&catalog, &public, &.{}, &.{}, 7000);
        expected.intent.hints_at_ms = 7000;
        try std.testing.expectEqualDeep(expected, candidates[0]);
    }
}

test "peer dial review group shrink invalidates all hints while preserving owners and authority" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    var candidate = try discovered(1, 1);
    candidate.attnets = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    candidate.custody_group_count = 128;
    var wanted: t.Coverage = .{ .attnets = 1, .syncnets = 1 };
    wanted.groups.set(0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &wanted, 0);
    q.configureSelection(&catalog, &wanted, false, &.{}, 0);
    try std.testing.expectEqual(@as(u16, 2), candidates[0].intent.priority);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 1));
    const eligible = candidates[0].intent.eligible_at_ms;
    const horizon = candidates[0].intent.history_until_ms;
    const failures = candidates[0].intent.failures;
    const context: t.ForkContext = .{ .custody_groups = 64 };
    var budget: u16 = 0;
    try std.testing.expect(!catalog.advanceCustody(&context, eligible, 60_000, &budget));
    q.configureSelection(&catalog, &wanted, false, &context, eligible);
    try std.testing.expectEqual(@as(u16, 0), candidates[0].intent.priority);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, eligible, &out));
    q.configureSelection(&catalog, &wanted, true, &context, eligible);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, eligible, &out));
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(&catalog, eligible, 1));
    try std.testing.expectEqual(eligible, candidates[0].intent.eligible_at_ms);
    try std.testing.expectEqual(horizon, candidates[0].intent.history_until_ms);
    try std.testing.expectEqual(failures, candidates[0].intent.failures);
    try std.testing.expectError(error.InvalidCandidate, q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, eligible));
    candidate.sequence = 2;
    candidate.custody_group_count = 64;
    try q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, eligible);
    q.configureSelection(&catalog, &wanted, false, &context, eligible);
    try std.testing.expectEqual(@as(u16, 2), candidates[0].intent.priority);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, eligible, &out));
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 2, .generation = 99 };
    try std.testing.expect(q.dialStarted(token, conn));
    const lease = q.active[candidates[0].attempt.?].lease_until_ms;
    const smaller: t.ForkContext = .{ .custody_groups = 32 };
    _ = catalog.advanceCustody(&smaller, eligible, 60_000, &budget);
    q.configureSelection(&catalog, &wanted, true, &smaller, eligible);
    try std.testing.expectEqual(conn, q.active[0].connection.?);
    try std.testing.expectEqual(lease, q.nextWakeup(&catalog, eligible, 1).?);
    try std.testing.expectEqual(failures, candidates[0].intent.failures);
    try std.testing.expectEqual(horizon, candidates[0].intent.history_until_ms);
    const manual: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 9 }, .port = 9999 } };
    try q.enqueue(&catalog, &candidate.peer, &.{manual}, true, eligible);
    q.configureSelection(&catalog, &wanted, true, &smaller, eligible);
    try std.testing.expectEqual(@as(u16, 0), candidates[0].intent.priority);
    try std.testing.expect(catalog.isDirect(&candidate.peer));
    try std.testing.expectEqual(conn, q.active[0].connection.?);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, eligible, &out));
    try std.testing.expect(q.dialClosed(&catalog, conn, .handshake_timeout, eligible));
    const next = q.nextWakeup(&catalog, eligible, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, next, &out));
    try std.testing.expect(out[0].address.eql(manual));
}

test "peer dial review pressure utility excludes every invalid cached hint" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    var old = try discovered(1, 1);
    old.attnets = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    old.custody_group_count = 128;
    const wanted: t.Coverage = .{ .attnets = 1, .syncnets = 1 };
    try q.enqueueDiscovered(&catalog, &old, &.{}, &wanted, 0);
    const replacement_candidate = try discovered(2, 1);
    try q.enqueueDiscovered(&catalog, &replacement_candidate, &.{ .custody_groups = 64 }, &wanted, 1);
    try std.testing.expect(candidates[0].identity.eql(&replacement_candidate.peer));
}

test "peer dial review custody-only full table recovers at fixed horizon with bounded work" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    var scarce = try discovered(3, 0);
    scarce.custody_group_count = 127;
    var wanted: t.Coverage = .{};
    wanted.groups.setRangeValue(.{ .start = 0, .end = 128 }, true);
    try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &wanted, 0);
    try q.enqueueDiscovered(&catalog, &second_candidate, &.{}, &wanted, 0);
    for (0..10) |i| {
        const now = i * 60_000;
        try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &wanted, now);
        try q.enqueueDiscovered(&catalog, &second_candidate, &.{}, &wanted, now);
        try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&catalog, &scarce, &.{}, &wanted, now));
        for (candidates) |row| try std.testing.expect(row.custody_work == null);
    }
    try std.testing.expectError(error.Capacity, q.enqueueDiscovered(&catalog, &scarce, &.{}, &wanted, 599_999));
    try q.enqueueDiscovered(&catalog, &scarce, &.{}, &wanted, 600_000);
    try std.testing.expect(candidates[0].identity.eql(&scarce.peer));
    try std.testing.expectEqual(@as(u16, 0), candidates[0].custody_work.?.walk.hashes);
    q.configureSelection(&catalog, &wanted, false, &.{}, 600_000);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 600_000, &out));
    var pending = true;
    for (0..64) |_| {
        var budget: u16 = 128;
        const before = candidates[0].custody_work.?.walk.hashes;
        pending = catalog.advanceCustody(&.{}, 600_000, 60_000, &budget);
        const used = candidates[0].custody_work.?.walk.hashes - before;
        try std.testing.expect(used <= 64);
        try std.testing.expectEqual(@as(u16, 128) - used, budget);
        if (!pending) break;
    }
    try std.testing.expect(!pending);
    try std.testing.expect(candidates[0].custody_work.?.walk.hashes <= 4096);
    q.configureSelection(&catalog, &wanted, false, &.{}, 600_000);
    try std.testing.expectEqual(@as(u16, 1), candidates[0].intent.priority);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 600_000, &out));
    try std.testing.expect(out[0].peer.eql(&scarce.peer));
}

test "peer direct membership enumeration is complete atomic and read only" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const addresses = [_]t.Address{ address, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } } };
    const sentinel: t.PeerId = .{ .bytes = @splat(9) };
    try std.testing.expectEqual(@as(usize, 0), try catalog.directPeers(&.{}));
    try std.testing.expect(!catalog.removeDirect(&first));
    try q.enqueue(&catalog, &first, &addresses, true, 0);
    try q.enqueue(&catalog, &first, &addresses, true, 0);
    try q.enqueue(&catalog, &second, &addresses, true, 0);
    q.configureSelection(&catalog, &.{}, true, &.{}, 0);
    const rows = [2]@TypeOf(candidates[0]){ candidates[0], candidates[1] };
    const before = q;
    var short = [_]t.PeerId{sentinel};
    try std.testing.expectError(error.OutputTooSmall, catalog.directPeers(&short));
    try std.testing.expectEqualDeep([_]t.PeerId{sentinel}, short);
    var out: [2]t.PeerId = undefined;
    try std.testing.expectEqual(@as(usize, 2), try catalog.directPeers(&out));
    try std.testing.expectEqualDeep([_]t.PeerId{ first, second }, out);
    try std.testing.expectEqualDeep(before, q);
    try std.testing.expectEqualDeep(rows, candidates[0..2].*);
    try std.testing.expect(catalog.removeDirect(&first));
    try std.testing.expect(!catalog.removeDirect(&first));
    try std.testing.expectEqual(@as(usize, 1), try catalog.directPeers(&out));
    try std.testing.expect(out[0].eql(&second));
    try std.testing.expect(catalog.removeDirect(&second));
    try std.testing.expectEqual(@as(usize, 0), try catalog.directPeers(&.{}));
}

test "peer explicit address updates reject overflow and invalid input without mutation" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    const third: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 3456 } };
    try q.enqueue(&catalog, &peer, &.{ address, second }, false, 0);
    q.configureSelection(&catalog, &.{}, true, &.{}, 0);
    const before = candidates[0];
    const selection = q;
    const custody_cursor_before = catalog.candidate_custody_cursor;
    try std.testing.expectError(error.AddressCapacity, q.enqueue(&catalog, &peer, &.{third}, true, 10));
    try std.testing.expectEqualDeep(before, candidates[0]);
    try std.testing.expectEqualDeep(selection.random, q.random);
    try std.testing.expectEqual(selection.selection_dirty, q.selection_dirty);
    try std.testing.expectEqual(selection.selection_deadline, q.selection_deadline);
    try std.testing.expectEqual(selection.cursor, q.cursor);
    try std.testing.expectEqual(custody_cursor_before, catalog.candidate_custody_cursor);
    try std.testing.expectError(error.InvalidAddress, q.enqueue(&catalog, &peer, &.{ third, .unspecified }, true, 10));
    try std.testing.expectEqualDeep(before, candidates[0]);
    try std.testing.expectEqualDeep(selection.random, q.random);
    try std.testing.expectEqual(selection.selection_dirty, q.selection_dirty);
    try std.testing.expectEqual(selection.selection_deadline, q.selection_deadline);
    try std.testing.expectEqual(selection.cursor, q.cursor);
    try std.testing.expectEqual(custody_cursor_before, catalog.candidate_custody_cursor);
    for ([_]t.Address{ address, second }) |known| {
        try q.enqueue(&catalog, &peer, &.{known}, false, 10);
        var refreshed = before;
        refreshed.intent.manual_until_ms = 10 + mod.connect_timeout_ms;
        try std.testing.expectEqualDeep(refreshed, candidates[0]);
    }
}

test "peer discovered conversion replaces addresses while retaining retry history" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    candidates[0].intent.failures = 3;
    candidates[0].intent.eligible_at_ms = 9000;
    const explicit: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 5432 } };
    try q.enqueue(&catalog, &candidate.peer, &.{ explicit, explicit }, true, 10);
    try std.testing.expect(!candidates[0].intent.automatic);
    try std.testing.expect(candidates[0].direct);
    try std.testing.expectEqual(@as(u8, 1), candidates[0].intent.address_count);
    try std.testing.expectEqualDeep(explicit, candidates[0].intent.addresses[0]);
    try std.testing.expectEqual(@as(u8, 3), candidates[0].intent.failures);
    try std.testing.expectEqual(@as(u64, 9000), candidates[0].intent.eligible_at_ms);
}

test "peer repeated initial address leaves room for a distinct explicit address" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    try q.enqueue(&catalog, &peer, &.{ address, address }, false, 0);
    try q.enqueue(&catalog, &peer, &.{second}, true, 1);
    try std.testing.expectEqual(@as(u8, 2), candidates[0].intent.address_count);
    try std.testing.expectEqualDeep([_]t.Address{ address, second }, candidates[0].intent.addresses);
}

test "peer retained attempt does not hide canonical connection closure" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 5 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 2345 } };
    try q.enqueue(&catalog, &peer, &.{ address, second }, true, 0);
    var intents: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &intents));
    const token = intents[0].token;
    const attempt: t.Handle = .{ .index = 0, .generation = 4 };
    try std.testing.expect(q.dialStarted(token, attempt));
    accept(&q, &catalog, &peer, .{ .index = 1, .generation = 7 }, 10);
    try std.testing.expect(candidates[0].connection != null);
    const lease = q.active[candidates[0].attempt.?].lease_until_ms;
    disconnect(&catalog, &peer, 10, .transport_closed, 20);
    try std.testing.expect(candidates[0].connection == null);
    try std.testing.expect(candidates[0].attempt != null);
    try std.testing.expectEqual(attempt, q.active[0].connection.?);
    try std.testing.expectEqual(lease, q.active[candidates[0].attempt.?].lease_until_ms);
    try std.testing.expectEqual(@as(u64, 1), catalog.connection_backoffs);
    const disconnected = candidates[0];
    disconnect(&catalog, &peer, 10, .transport_closed, 20);
    try std.testing.expectEqualDeep(disconnected, candidates[0]);
    try std.testing.expect(!q.dialStarted(token, attempt));
    try std.testing.expect(!q.dialFailed(&catalog, token, 20));
    try std.testing.expect(q.dialClosed(&catalog, attempt, .handshake_timeout, 30));
    try std.testing.expect(candidates[0].connection == null);
    try std.testing.expect(candidates[0].attempt == null);
    try std.testing.expect(q.active[0].connection == null);
    try std.testing.expect(candidates[0].direct);
    const due = q.nextWakeup(&catalog, 30, 1).?;
    try std.testing.expect(due >= 5020 and due <= 6020);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, due - 1, &intents));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &intents));
    try std.testing.expectEqual(token.index, intents[0].token.index);
    try std.testing.expectEqual(token.generation + 1, intents[0].token.generation);
    try std.testing.expectEqualDeep(peer, intents[0].peer);
    try std.testing.expectEqualDeep(second, intents[0].address);
}

test "peer dial actual custody gives no utility for connected sampling only groups" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    var candidate = try discovered(1, 0);
    candidate.custody_group_count = 4;
    const context: t.ForkContext = .{ .fork = .fulu, .minimum_sampling_groups = 8 };
    var pair = try @import("custody.zig").SamplingDerivation.init(&candidate.node_id, .{ .groups = 128, .columns = 128 }, 4, 8);
    const derived = (try pair.step(64)).?;
    var wanted: t.Coverage = .{ .groups = derived.sampling.differenceWith(derived.custody) };
    try std.testing.expectEqual(@as(usize, 4), wanted.groups.count());
    try q.enqueueDiscovered(&catalog, &candidate, &context, &wanted, 0);
    var budget: u16 = 64;
    try std.testing.expect(!catalog.advanceCustody(&context, 0, 60_000, &budget));
    q.configureSelection(&catalog, &wanted, false, &context, 0);
    try std.testing.expectEqual(@as(u16, 0), candidates[0].intent.priority);
    try std.testing.expect(!candidates[0].intent.selected);
    try std.testing.expectEqual(@as(u16, 4), @import("policy.zig").utility(&.{ .groups = derived.sampling }, &wanted));
    wanted.groups = derived.custody;
    q.configureSelection(&catalog, &wanted, false, &context, 0);
    try std.testing.expectEqual(@as(u16, 1), candidates[0].intent.priority);
    try std.testing.expect(candidates[0].intent.selected);
}

test "peer manual dial completes once and expires without retaining intent" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    var out: [1]mod.DialIntent = undefined;
    try q.enqueueUntil(&catalog, &peer, &.{address}, false, 0, 5_000);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    const token = out[0].token;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(token, conn));
    accept(&q, &catalog, &peer, conn, 1);
    disconnect(&catalog, &peer, 1, .transport_closed, 20);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 20_000, &out));
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot(&catalog).occupied);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_completed);
    try q.enqueueUntil(&catalog, &peer, &.{address}, false, 20_000, 21_000);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 21_000, &out));
    try std.testing.expectEqual(@as(usize, 0), q.resourceSnapshot(&catalog).occupied);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_expired);
    try std.testing.expect(!q.dialFailed(&catalog, token, 21_000));
}

test "peer manual dial deadlines merge while direct reconnects back off" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueueUntil(&catalog, &peer, &.{address}, false, 0, 10_000);
    try q.enqueueUntil(&catalog, &peer, &.{address}, false, 1, 20_000);
    try q.enqueueUntil(&catalog, &peer, &.{address}, false, 2, 5_000);
    try std.testing.expectEqual(@as(u64, 20_000), candidates[0].intent.manual_until_ms);
    try q.enqueue(&catalog, &peer, &.{address}, true, 2);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 2;
    for (0..3) |i| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, now, &out));
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i) };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        accept(&q, &catalog, &peer, conn, now);
        disconnect(&catalog, &peer, now, .health_timeout, now + 100);
        const due = q.nextWakeup(&catalog, now + 100, 1).?;
        const minimum = @as(u64, 5_000) << @intCast(i);
        try std.testing.expect(due >= now + 100 + minimum and due <= now + 1_100 + minimum);
        try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, due - 1, &out));
        now = due;
    }
    try std.testing.expectEqual(@as(u64, 3), catalog.connection_backoffs);
    try std.testing.expect(catalog.isDirect(&peer));
}

test "peer dial simultaneous inbound success does not record the redundant outbound close as failure" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidates = catalog.rows[0..q.options.capacity];
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, true, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    const outbound: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, outbound));
    accept(&q, &catalog, &peer, .{ .index = 1, .generation = 1 }, 100);
    try std.testing.expect(q.dialClosed(&catalog, outbound, .handshake_timeout, 200));
    try std.testing.expectEqual(@as(u8, 0), candidates[0].intent.failures);
    try std.testing.expectEqual(@as(u64, 0), q.durations[1].count);
}

test "peer explicit dial ranks above discovery coverage" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidate = try discovered(1, 15);
    const manual = try discovered(2, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{ .syncnets = 15 }, 0);
    try q.enqueue(&catalog, &manual.peer, &.{address}, false, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expectEqualDeep(manual.peer, out[0].peer);
}

test "peer failed discovery candidate yields its slot after retry backoff" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const forged = try discovered(1, 15);
    const replacement = try discovered(2, 0);
    try q.enqueueDiscovered(&catalog, &forged, &.{}, &.{ .syncnets = 15 }, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 1));
    const retry_at = q.nextWakeup(&catalog, 1, 1).?;
    try q.enqueueDiscovered(&catalog, &replacement, &.{}, &.{ .syncnets = 15 }, retry_at);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, retry_at, &out));
    try std.testing.expectEqualDeep(replacement.peer, out[0].peer);
}

test "peer dial attempt table admits the configured concurrency up to its ceiling" {
    try std.testing.expectError(error.InvalidOptions, mod.Dialing.init(.{ .capacity = 128, .concurrent_max = mod.attempts_max + 1, .seed = 1 }));
    try std.testing.expectError(error.InvalidOptions, mod.Dialing.init(.{ .capacity = 8, .concurrent_max = 2, .outbound_reserved = 3, .seed = 1 }));
    var q = try mod.Dialing.init(.{ .capacity = mod.attempts_max, .concurrent_max = mod.attempts_max, .seed = 1 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    for (0..mod.attempts_max) |index| {
        var peer: t.PeerId = .{ .bytes = @splat(0) };
        std.mem.writeInt(u16, peer.bytes[0..2], @intCast(index + 1), .little);
        try q.enqueue(&catalog, &peer, &.{address}, false, 0);
    }
    var out: [mod.attempts_max]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, mod.attempts_max), q.poll(&catalog, 0, &out));
    try std.testing.expectEqual(@as(u16, mod.attempts_max), q.attempts().total);
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 0, &out));
}

test "peer dial admission reserve counts only answered attempts" {
    var q = try mod.Dialing.init(.{ .capacity = 4, .concurrent_max = 4, .seed = 1 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    for (0..4) |index| {
        const peer: t.PeerId = .{ .bytes = @splat(@as(u8, @intCast(index + 1))) };
        try q.enqueue(&catalog, &peer, &.{address}, false, 0);
    }
    var out: [4]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 4), q.poll(&catalog, 0, &out));
    for (out, 0..) |intent, index| try std.testing.expect(q.dialStarted(intent.token, .{ .index = @intCast(index), .generation = 1 }));
    try std.testing.expectEqual(@as(u16, 4), q.pendingPeers(&catalog, null));
    try std.testing.expectEqual(@as(u16, 0), q.answeredPeers(&catalog, null));
    q.active[out[0].token.index].answered = true;
    try std.testing.expectEqual(@as(u16, 1), q.answeredPeers(&catalog, null));
    try std.testing.expectEqual(@as(u16, 0), q.answeredPeers(&catalog, &out[0].peer));
}

fn initCatalog(allocator: std.mem.Allocator, options: mod.Options) !@import("catalog.zig").Catalog {
    return @import("catalog.zig").Catalog.initWithIntents(allocator, .{ .capacity = 8, .max_peers = 8, .target_peers = 8, .min_outbound = 0, .outbound_reserve = 0 }, options.capacity, 1024, options.seed);
}
fn selectNext(q: *mod.Dialing, catalog: *@import("catalog.zig").Catalog, now: *u64) !mod.Token {
    var out: [1]mod.DialIntent = undefined;
    now.* = q.nextWakeup(catalog, now.*, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(catalog, now.*, &out));
    return out[0].token;
}
fn accept(q: *mod.Dialing, catalog: *@import("catalog.zig").Catalog, peer: *const t.PeerId, conn: t.Handle, now_ms: u64) void {
    var events: [8]t.Event = undefined;
    _ = catalog.pollEvents(&events);
    const local: t.PeerId = .{ .bytes = @splat(0) };
    const decision = catalog.admit(peer, &local, conn, &.{ .direction = .outbound, .endpoint = address, .now_ms = now_ms });
    const ref = if (decision == .admitted) decision.admitted.peer else catalog.find(peer).?;
    std.debug.assert(std.meta.eql(catalog.rowFor(ref).?.connection, conn));
    q.accepted(catalog, ref, conn, now_ms);
}
fn disconnect(catalog: *@import("catalog.zig").Catalog, peer: *const t.PeerId, connected_at_ms: u64, reason: t.DisconnectReason, now_ms: u64) void {
    const ref = catalog.find(peer).?;
    const row = catalog.rowFor(ref).?;
    std.debug.assert(row.connected_at_ms == connected_at_ms);
    if (row.connection) |conn| std.debug.assert(catalog.disconnect(ref, conn, reason, now_ms));
}

test "peer dial dead discovery endpoints do not return as untried candidates" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 0;
    for (0..2) |i| {
        const due = q.nextWakeup(&catalog, now, 1).?;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &out));
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        now = due + 3_000;
        try std.testing.expect(q.dialClosed(&catalog, conn, .dial_unanswered, now));
    }
    try std.testing.expect(catalog.find(&candidate.peer) == null);
    try std.testing.expectEqual(@as(u64, 1), q.counters.failed_intents_released);
    try std.testing.expectEqual(@as(u64, 2), q.outcomes[@intFromEnum(t.DialOutcome.unanswered)]);
    try std.testing.expectEqual(@as(u64, 1), q.retries[@intFromEnum(t.DialFailure.unanswered)]);
    try std.testing.expectError(error.RecentlyFailed, q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, now));
    try std.testing.expectEqual(@as(u64, 1), q.refused.endpoint);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, now + @import("dial_history.zig").endpoint_memory_ms);
    const row = catalog.rowFor(catalog.find(&candidate.peer).?).?;
    try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
}

test "peer dial failure strikes survive intent replacement" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const first_candidate = try discovered(1, 0);
    const second_candidate = try discovered(2, 0);
    try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 0));
    try q.enqueueDiscovered(&catalog, &second_candidate, &.{}, &.{}, 1);
    try std.testing.expect(catalog.find(&first_candidate.peer) == null);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 1, &out));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 1));
    const retry_at = q.nextWakeup(&catalog, 1, 1).?;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, retry_at, &out));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, retry_at));
    try std.testing.expect(catalog.find(&second_candidate.peer) == null);
    try q.enqueueDiscovered(&catalog, &first_candidate, &.{}, &.{}, retry_at);
    try std.testing.expectEqual(@as(u8, 1), catalog.rowFor(catalog.find(&first_candidate.peer).?).?.intent.failures);
}

test "peer dial retries follow the endpoint history across row eviction" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const mismatched = try discovered(1, 0);
    const silent = try discovered(2, 0);
    const other = try discovered(3, 0);
    var out: [1]mod.DialIntent = undefined;
    try q.enqueueDiscovered(&catalog, &mismatched, &.{}, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 0, .generation = 1 }));
    try std.testing.expect(q.dialClosed(&catalog, .{ .index = 0, .generation = 1 }, .peer_id_mismatch, 100));
    try std.testing.expect(catalog.find(&mismatched.peer) == null);
    try std.testing.expectError(error.RecentlyFailed, q.enqueueDiscovered(&catalog, &mismatched, &.{}, &.{}, 200));
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, 200, &out));
    try q.enqueueDiscovered(&catalog, &silent, &.{}, &.{}, 200);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 200, &out));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 0, .generation = 2 }));
    try std.testing.expect(q.dialClosed(&catalog, .{ .index = 0, .generation = 2 }, .dial_unanswered, 3_200));
    try q.enqueueDiscovered(&catalog, &other, &.{}, &.{}, 3_300);
    try std.testing.expect(catalog.find(&silent.peer) == null);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 3_300, &out));
    try std.testing.expect(out[0].peer.eql(&other.peer));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 3_300));
    try q.enqueueDiscovered(&catalog, &silent, &.{}, &.{}, 3_400);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 3_400, &out));
    try std.testing.expect(out[0].peer.eql(&silent.peer));
    try std.testing.expectEqual(@as(u64, 1), q.retries[@intFromEnum(t.DialFailure.unanswered)]);
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 3_400));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 4_400, &out));
    try std.testing.expect(out[0].peer.eql(&silent.peer));
    var retried: u64 = 0;
    for (q.retries) |count| retried += count;
    try std.testing.expectEqual(@as(u64, 1), retried);
}

test "peer dial counts no retry for the other endpoint of a mismatched peer" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const alternate: t.Address = .{ .ip6 = .{ .octets = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, .port = 2222 } };
    var candidate = try discovered(1, 0);
    candidate.addresses[1] = alternate;
    candidate.address_count = 2;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].address.eql(address));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .peer_id_mismatch, 100));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, q.nextWakeup(&catalog, 100, 1).?, &out));
    try std.testing.expect(out[0].address.eql(alternate));
    for (q.retries) |count| try std.testing.expectEqual(@as(u64, 0), count);
}

test "peer dial counts a redial of a failed endpoint once by that endpoint's failure" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const alternate: t.Address = .{ .ip6 = .{ .octets = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, .port = 2222 } };
    var candidate = try discovered(1, 0);
    candidate.addresses[1] = alternate;
    candidate.address_count = 2;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 0;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    for ([_]t.Address{ address, alternate, address, address, alternate }, 0..) |expected, step| {
        now = q.nextWakeup(&catalog, now, 1).?;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, now, &out));
        try std.testing.expect(out[0].address.eql(expected));
        switch (step) {
            0, 3 => try std.testing.expect(q.dialFailed(&catalog, out[0].token, now)),
            1 => {
                try std.testing.expect(q.dialStarted(out[0].token, conn));
                try std.testing.expect(q.dialClosed(&catalog, conn, .dial_unanswered, now));
            },
            2 => try std.testing.expect(q.dialDeferred(&catalog, out[0].token, now)),
            else => {},
        }
        var retried: u64 = 0;
        for (q.retries) |count| retried += count;
        try std.testing.expectEqual(@as(u64, if (step < 2) 0 else if (step < 4) 1 else 2), retried);
        try std.testing.expectEqual(@as(u64, @intFromBool(step >= 2)), q.retries[@intFromEnum(t.DialFailure.destination_unreachable)]);
    }
    try std.testing.expectEqual(@as(u64, 1), q.retries[@intFromEnum(t.DialFailure.unanswered)]);
}

test "peer dial ranks untried discovery candidates above retried ones" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const retried = try discovered(1, 0);
    const untried = try discovered(2, 0);
    try q.enqueueDiscovered(&catalog, &retried, &.{}, &.{}, 0);
    try q.enqueueDiscovered(&catalog, &untried, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&retried.peer));
    try std.testing.expect(q.dialFailed(&catalog, out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&untried.peer));
    try std.testing.expect(q.dialDeferred(&catalog, out[0].token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 5_000, &out));
    try std.testing.expect(out[0].peer.eql(&untried.peer));
}

test "peer dial peer id mismatch blocks the endpoint even for a newer record" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    try std.testing.expect(q.dialClosed(&catalog, conn, .peer_id_mismatch, 100));
    try std.testing.expect(catalog.find(&candidate.peer) == null);
    try std.testing.expectEqual(@as(u64, 1), q.outcomes[@intFromEnum(t.DialOutcome.peer_id_mismatch)]);
    candidate.sequence = 2;
    try std.testing.expectError(error.RecentlyFailed, q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 100));
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 100 + @import("dial_history.zig").mismatch_memory_ms);
}

test "peer dial local transport closes leave no endpoint strike" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 0;
    for (0..3) |i| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, now, &out));
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        try std.testing.expect(q.dialClosed(&catalog, conn, .host, now));
        now = q.nextWakeup(&catalog, now, 1).?;
    }
    try std.testing.expect(catalog.find(&candidate.peer) != null);
    try std.testing.expectEqual(@as(u64, 3), q.outcomes[@intFromEnum(t.DialOutcome.refused)]);
    try std.testing.expectEqual(@as(u8, 0), catalog.history.strikesFor(catalog.history.endpointKey(&candidate.peer, candidate.addresses[0]), candidate.sequence, now));
}

test "peer dial never returns to the mismatched endpoint of a two-address candidate" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const alternate: t.Address = .{ .ip6 = .{ .octets = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, .port = 2222 } };
    var candidate = try discovered(1, 0);
    candidate.addresses[1] = alternate;
    candidate.address_count = 2;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    var now: u64 = 0;
    for ([_]t.CloseReason{ .peer_id_mismatch, .host, .dial_unanswered, .dial_unanswered }, 0..) |reason, i| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, now, &out));
        try std.testing.expect(out[0].address.eql(if (i == 0) address else alternate));
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        try std.testing.expect(q.dialClosed(&catalog, conn, reason, now));
        if (i < 3) now = q.nextWakeup(&catalog, now, 1).?;
    }
    try std.testing.expect(catalog.find(&candidate.peer) == null);
    try std.testing.expectEqual(@as(u64, 1), q.counters.failed_intents_released);
}

test "peer dial mismatch after a mid-dial refresh blocks the dialed endpoint, not the new one" {
    var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const moved: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    var candidate = try discovered(1, 0);
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].address.eql(address));
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    try std.testing.expect(q.dialStarted(out[0].token, conn));
    candidate.sequence = 2;
    candidate.addresses[0] = moved;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 50);
    try std.testing.expect(q.dialClosed(&catalog, conn, .peer_id_mismatch, 100));
    try std.testing.expectEqual(@as(u64, 0), q.counters.failed_intents_released);
    try std.testing.expect(catalog.history.blocked(catalog.history.endpointKey(&candidate.peer, address), 99, 100));
    candidate.sequence = 3;
    candidate.addresses[0] = address;
    try std.testing.expectError(error.RecentlyFailed, q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 100));
    candidate.addresses[0] = moved;
    try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 100);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, q.nextWakeup(&catalog, 100, 1).?, &out));
    try std.testing.expect(out[0].address.eql(moved));
}

test "peer dial redundant mismatch blocks its endpoint without failing the intent" {
    const alternate: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
    for ([_]u8{ 1, 2 }) |count| {
        var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        var catalog = try initCatalog(a, q.options);
        defer catalog.deinit(a);
        var candidate = try discovered(1, 0);
        candidate.addresses[1] = alternate;
        candidate.address_count = count;
        try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
        var out: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
        try std.testing.expect(out[0].address.eql(address));
        const dial: t.Handle = .{ .index = 0, .generation = 1 };
        try std.testing.expect(q.dialStarted(out[0].token, dial));
        accept(&q, &catalog, &candidate.peer, .{ .index = 1, .generation = 1 }, 10);
        try std.testing.expect(q.dialClosed(&catalog, dial, .peer_id_mismatch, 20));
        try std.testing.expectEqual(@as(u64, 1), q.outcomes[@intFromEnum(t.DialOutcome.cancelled)]);
        try std.testing.expectEqual(@as(u64, 0), q.outcomes[@intFromEnum(t.DialOutcome.peer_id_mismatch)]);
        try std.testing.expect(catalog.history.blocked(catalog.history.endpointKey(&candidate.peer, address), 99, 20));
        const row = catalog.rowFor(catalog.find(&candidate.peer).?).?;
        try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
        try std.testing.expectEqual(@as(u64, 0), row.intent.eligible_at_ms);
        try std.testing.expectEqual(@as(u64, 2 - count), q.counters.failed_intents_released);
        disconnect(&catalog, &candidate.peer, 10, .transport_closed, 30);
        const due = q.nextWakeup(&catalog, 30, 1) orelse 30 + @import("dial_history.zig").endpoint_memory_ms;
        try std.testing.expectEqual(@as(usize, count - 1), q.poll(&catalog, due, &out));
        if (count == 2) try std.testing.expect(out[0].address.eql(alternate));
        for (q.retries) |retried| try std.testing.expectEqual(@as(u64, 0), retried);
    }
}

test "peer dial landed connections keep dial failures until the application exchange clears the dialed endpoint" {
    for ([_]bool{ false, true }) |deferred| {
        var q = try mod.Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 4 });
        var catalog = try initCatalog(a, q.options);
        defer catalog.deinit(a);
        var candidate = try discovered(1, 0);
        try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, 0);
        var out: [1]mod.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
        try std.testing.expect(q.dialFailed(&catalog, out[0].token, 0));
        const due = q.nextWakeup(&catalog, 0, 1).?;
        try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, due, &out));
        try std.testing.expect(out[0].address.eql(address));
        const conn: t.Handle = .{ .index = 0, .generation = 1 };
        try std.testing.expect(q.dialStarted(out[0].token, conn));
        candidate.sequence = 2;
        candidate.addresses[0] = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 2222 } };
        try q.enqueueDiscovered(&catalog, &candidate, &.{}, &.{}, due);
        const dialed = catalog.history.endpointKey(&candidate.peer, address);
        try std.testing.expectEqual(@as(u8, 1), catalog.history.strikesFor(dialed, 1, due));
        if (deferred) {
            try std.testing.expect(q.deferConnection(&catalog, conn, due));
            try std.testing.expectEqual(@as(u8, 1), catalog.history.strikesFor(dialed, 1, due));
            continue;
        }
        accept(&q, &catalog, &candidate.peer, conn, due);
        try std.testing.expectEqual(@as(u8, 1), catalog.history.strikesFor(dialed, 1, due));
        const peer = catalog.find(&candidate.peer).?;
        try std.testing.expect(catalog.updateStatus(peer, conn, &.{}, due));
        try std.testing.expect(catalog.updateMetadata(peer, conn, &.{}, due));
        catalog.clearDialFailures(peer, conn);
        try std.testing.expectEqual(@as(u8, 0), catalog.history.strikesFor(dialed, 1, due));
    }
}

test "peer dial lease expiry and backoff fire from the intent heaps" {
    var q = try mod.Dialing.init(.{ .capacity = 2, .concurrent_max = 1, .seed = 4 });
    var catalog = try initCatalog(a, q.options);
    defer catalog.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&catalog, &peer, &.{address}, false, 0);
    const row = catalog.rowFor(catalog.find(&peer).?).?;
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, 0, &out));
    // An unstarted attempt holds its lease; nothing else is due before it.
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, 0, 1));
    var visits = q.visits;
    for ([_]u64{ 1, 5_000, 9_999 }) |now| {
        q.expire(&catalog, null, now);
        try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, now, &out));
        try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(&catalog, now, 1));
    }
    try std.testing.expectEqual(visits, q.visits);
    q.expire(&catalog, null, 10_000);
    try std.testing.expect(q.visits > visits);
    try std.testing.expectEqual(@as(u64, 1), q.outcomes[@intFromEnum(t.DialOutcome.expired)]);
    try std.testing.expectEqual(@as(?u8, null), row.attempt);
    // The expired lease backs the intent off; its eligibility is the next deadline on the heap.
    const eligible = row.intent.eligible_at_ms;
    try std.testing.expect(eligible > 10_000 and eligible < mod.connect_timeout_ms);
    try std.testing.expectEqual(@as(?u64, eligible), q.nextWakeup(&catalog, 10_000, 1));
    // Without dial room only the manual expiry remains.
    try std.testing.expectEqual(@as(?u64, mod.connect_timeout_ms), q.nextWakeup(&catalog, 10_000, 0));
    visits = q.visits;
    try std.testing.expectEqual(@as(usize, 0), q.poll(&catalog, eligible - 1, &out));
    try std.testing.expectEqual(visits, q.visits);
    try std.testing.expectEqual(@as(usize, 1), q.poll(&catalog, eligible, &out));
    try std.testing.expect(out[0].peer.eql(&peer));
    // The second lease ends at the manual deadline, which releases the intent.
    try std.testing.expectEqual(@as(?u64, eligible + 10_000), q.nextWakeup(&catalog, eligible, 1));
    q.expire(&catalog, null, eligible + 10_000);
    try std.testing.expectEqual(@as(u64, 2), q.outcomes[@intFromEnum(t.DialOutcome.expired)]);
    try std.testing.expectEqual(@as(?u64, mod.connect_timeout_ms), q.nextWakeup(&catalog, eligible + 10_000, 0));
    q.expire(&catalog, null, mod.connect_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1), q.counters.manual_expired);
    try std.testing.expect(catalog.find(&peer) == null);
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(&catalog, mod.connect_timeout_ms, 1));
}
