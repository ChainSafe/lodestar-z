const std = @import("std");
const gossip = @import("gossipsub.zig");
const Gossipsub = gossip.Gossipsub;
const ValidationHandle = gossip.ValidationHandle;
const Allocator = std.mem.Allocator;
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const peers_mod = @import("peer_book.zig");
const storage = @import("message_store.zig");
const engine_mod = @import("../quic/engine.zig");
const Handle = engine_mod.Handle;
const Now = @import("../types.zig").Now;
const support = @import("test_support.zig");
const testMessage = support.message;

test "gossipsub rejects incompatible memory plans and cleans partial startup allocations" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidLimits, support.init(a, .{ .random_seed = 1, .receive_arena_bytes = 65536 }));
    try std.testing.expectError(error.InvalidLimits, support.init(a, .{ .random_seed = 1, .receive_arena_bytes = 1024 * 1024 * 1024 + 4096 }));
    try std.testing.expectError(error.InvalidLimits, support.init(a, .{ .random_seed = 1, .fields_per_pump = 1 }));
    try std.testing.checkAllAllocationFailures(a, testStartup, .{});
}
fn testStartup(a: Allocator) !void {
    var g = try support.init(a, .{ .random_seed = 1, .seen_capacity = 1, .mcache_capacity = 1, .validation_capacity = 1, .body_buffer_bytes = 1, .control_bytes = 1, .critical_bytes = 32 + topic_mod.topic_max_len });
    defer g.deinit();
    const plan = g.memoryPlan();
    try std.testing.expectEqual(@as(usize, 4096), plan.page_bytes);
    try std.testing.expectEqual(g.messages.store.bytes.len, plan.retained_bytes);
    try std.testing.expectEqual(plan.total_bytes, plan.retained_bytes + plan.frame_bytes + plan.compression_bytes + plan.peer_buffer_bytes + plan.metadata_bytes);
}

test "gossipsub resource snapshot starts empty" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const snapshot = g.resourceSnapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.admitted_peers);
    try std.testing.expectEqual(@as(usize, 0), snapshot.queued_descriptors);
    try std.testing.expectEqual(@as(usize, 0), snapshot.store_entries);
    try std.testing.expectEqual(@as(usize, 0), snapshot.pending_validations);
}

test "gossip resolved capacities allocate owner rows and reject stale ceiling handles" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try support.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    try std.testing.expectEqual(@as(usize, 2), g.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 4), g.peers.rows.len);
    try std.testing.expectEqual(@as(usize, 4), g.peers.scores.rows.len);
    try std.testing.expect(!g.sessions.matches(.{ .index = 2, .generation = 0 }));
    try std.testing.expect(!g.peers.matches(.{ .index = 4, .generation = 0 }));
    try std.testing.expectEqual(ledger.bytes, g.memoryPlan().total_bytes - @sizeOf(Gossipsub));
    g.deinit();
    try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
}

test "gossip default owner memory reconciles requested allocations" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    {
        var g = try support.init(ledger.allocator(), .{ .random_seed = 1 });
        defer g.deinit();
        const plan = g.memoryPlan();
        try std.testing.expectEqual(ledger.bytes, plan.total_bytes - @sizeOf(Gossipsub));
    }
    try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
}

test "gossip diagnostics tracks queued age and preserves peaks after owner release" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try support.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.sessions.rows[peer.index].io;
    io.tx.cancelStream(&g.messages.store);
    const message = g.messages.store.put([_]u8{1} ** 20, "t", "abc").?;
    g.messages.store.retainHistory(message);
    g.messages.store.seal(message);
    try std.testing.expectEqual(@import("outbox.zig").QueueResult.queued, io.tx.queueData(&g.messages.store, message, .forward, .{ .bytes = 10 }, 7));
    try std.testing.expect(io.tx.injectFrame("ctrl", true, 9) != null);
    g.last_now_ms = 20;
    const snapshot = g.resourceSnapshot();
    try std.testing.expectEqual(@as(?u64, 13), snapshot.oldest_tx_age_ms);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queued_bytes);
    try std.testing.expectEqual(@as(usize, 3), snapshot.data_bytes_per_row_high_water);
    try std.testing.expectEqual(@as(usize, 4), snapshot.critical_bytes);
    try std.testing.expectEqual(@as(usize, 1), snapshot.held_tx_retains);
    try std.testing.expectEqualDeep(snapshot, g.resourceSnapshot());
    g.connectionClosed(conn);
    g.messages.store.releaseHistory(message);
    const released = g.resourceSnapshot();
    try std.testing.expectEqual(@as(?u64, null), released.oldest_tx_age_ms);
    try std.testing.expectEqual(@as(usize, 0), released.queued_bytes);
    try std.testing.expectEqual(@as(usize, 0), released.held_tx_retains);
    try std.testing.expectEqual(@as(usize, 3), released.data_bytes_per_row_high_water);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queued_bytes);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

test "gossip lifecycle sequence preserves ownership under pressure reconnect and late verdicts" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 91, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1, .validation_capacity = 2, .mcache_capacity = 4, .seen_capacity = 8, .mcache_arena_bytes = constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + storage.page_bytes, .validation_timeout_ms = 100, .validation_tombstone_ms = 200 });
    defer g.deinit();
    var rng = std.Random.DefaultPrng.init(17);
    var conn: Handle = .{ .index = 0, .generation = 1 };
    var source = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    const metadata: peers_mod.Metadata = .{ .identity = g.peers.rows[g.sessions.rows[source.index].logical.index].identity, .address = .unspecified, .direction = .inbound };
    g.markDirect(conn);
    g.sessions.rows[source.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), source.index, name, true);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var handles: [8]?ValidationHandle = @splat(null);
    for (0..512) |step| {
        const now: Now = .{ .mono_ms = step * 17 + 1, .unix_s = 0 };
        g.last_now_ms = now.mono_ms;
        const value = rng.random().uintLessThan(u8, 8);
        const payload = [_]u8{'a' + value};
        switch (rng.random().uintLessThan(u8, 9)) {
            0, 1 => {
                if (try testMessage(&g, source.index, &payload, now.mono_ms)) |count| {
                    if (count == 1) handles[value] = inbox.last().handle;
                    inbox.clear();
                }
            },
            2 => if (handles[value]) |handle| {
                _ = g.report(handle, @enumFromInt(rng.random().uintLessThan(u8, 3)), now);
            },
            3 => {
                _ = g.publish(name, &payload, now) catch |err| switch (err) {
                    error.Duplicate, error.ResourceExhausted => Gossipsub.PublishOutcome{},
                    else => return err,
                };
            },
            4 => g.messages.expire(&g.peers, now.mono_ms),
            5 => {
                g.connectionClosed(conn);
                conn.generation += 1;
                source = g.addPeer(conn, &metadata, now).admitted;
                g.markDirect(conn);
                g.sessions.rows[source.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
                _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), source.index, name, true);
            },
            6 => {
                const subscribed = if (g.overlay.findTopic(name)) |topic| g.overlay.subscribed(topic) else false;
                if (subscribed) {
                    try support.unsubscribe(&g, name);
                } else try support.subscribe(&g, name);
            },
            7 => {
                support.heartbeat(&g, now);
                @import("session_io.zig").finishPump(&g, now);
            },
            8 => for (g.sessions.rows) |*peer| peer.io.tx.cancelStream(&g.messages.store),
            else => unreachable,
        }
        var pending: usize = 0;
        var occupied_pages: usize = 0;
        for (g.messages.store.entries, 0..) |*entry, index| {
            if (!entry.active) continue;
            try std.testing.expect(!entry.provisional);
            occupied_pages += storage.Store.pagesFor(entry.len);
            var validations: usize = 0;
            for (g.messages.validation.entries) |*slot| if (slot.state == .pending and slot.state.pending.message.index == index) {
                try std.testing.expectEqual(entry.generation, slot.state.pending.message.generation);
                validations += 1;
            };
            try std.testing.expectEqual(@as(usize, @intFromBool(entry.validation)), validations);
            pending += validations;
            const history = g.messages.history.get(&g.messages.store, entry.id);
            try std.testing.expectEqual(entry.history, if (history) |record| g.messages.history.message(record).index == index and g.messages.history.message(record).generation == entry.generation else false);
            var retained: u32 = 0;
            for (g.sessions.rows) |*peer| retained += @intCast(peer.io.tx.data.retains(.{ .index = @intCast(index), .generation = entry.generation }));
            try std.testing.expectEqual(entry.tx, retained);
        }
        try std.testing.expectEqual(g.messages.store.next.len, occupied_pages + g.messages.store.free_pages);
        var records_pending: usize = 0;
        var pins: [4]u32 = @splat(0);
        for (g.messages.validation.recent) |*record| {
            records_pending += @intFromBool(record.state == .pending);
            if (!record.pinned) continue;
            try std.testing.expect(g.peers.matches(record.source));
            pins[record.source.index] += 1;
            for (record.duplicates[0..record.duplicate_len]) |*duplicate| {
                try std.testing.expect(g.peers.matches(duplicate.peer));
                pins[duplicate.peer.index] += 1;
            }
        }
        try std.testing.expectEqual(pending, records_pending);
        for (g.peers.rows, pins) |*peer, expected| try std.testing.expectEqual(expected, peer.pins);
    }
}

fn requestOne(g: *Gossipsub, peer: u16, id: *const @import("topic.zig").MessageId) void {
    var body: [32]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&body);
    writer.bytesField(1, id);
    support.control(g, peer, .{ .iwant = .{ .body = writer.written() } }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
}

test "gossip history covers the processor retention allowance and the memory plan accounts for it" {
    const limits: @import("../gossip_limits.zig").Limits = @splat(.{ .items = 4, .bytes = 4096 });
    const total = @import("../gossip_limits.zig").items(&limits);
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(topic_mod.Kind.beacon_block)] = .{ .count = 1, .ssz_max = 1024 };
    for ([_]usize{ 16, total + 1 }, [_]usize{ total, total + 1 }) |floor, expected| {
        var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var g = try support.init(ledger.allocator(), .{ .random_seed = 1, .topic_policy = &.{boundary}, .mcache_capacity = floor, .validation_capacity = total, .processor_limits = limits });
        try std.testing.expectEqual(expected, g.messages.history.entries.len);
        try std.testing.expectEqual(expected, g.resourceSnapshot().history_capacity);
        try std.testing.expectEqual(expected + total, g.messages.store.entries.len);
        try std.testing.expectEqual(ledger.bytes, g.memoryPlan().total_bytes - @sizeOf(Gossipsub));
        g.deinit();
    }
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 16, .validation_capacity = total });
    defer g.deinit();
    try std.testing.expectEqual(@as(usize, 16), g.messages.history.entries.len);
}

test "gossip history at capacity serves IWANT until each message's sixth heartbeat boundary" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 2 * constants.mcache_len });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const history = &g.messages.history;
    var ids: [constants.mcache_len][2]@import("topic.zig").MessageId = undefined;
    for (&ids, 0..) |*window, epoch| {
        if (epoch > 0) support.ageHistory(&g);
        for (window, 0..) |*id, i| {
            var payload: [2]u8 = .{ @intCast(epoch), @intCast(i) };
            _ = try g.publish(name, &payload, .{ .mono_ms = 1 + epoch, .unix_s = 0 });
            id.* = topic_mod.validMessageId(name, &payload, .{});
        }
    }
    try std.testing.expectEqual(history.entries.len, history.count);
    // A full history evicts its oldest message while that message still has a window left.
    _ = try g.publish(name, "one more", .{ .mono_ms = 10, .unix_s = 0 });
    try std.testing.expectEqual(history.entries.len, history.count);
    try std.testing.expect(history.get(&g.messages.store, ids[0][0]) == null);
    const misses = &g.iwant_outcomes[@intFromEnum(@import("metrics.zig").IwantOutcome.miss)];
    const unknown = misses.*;
    requestOne(&g, peer.index, &ids[0][0]);
    try std.testing.expectEqual(unknown + 1, misses.*);
    requestOne(&g, peer.index, &ids[0][1]);
    try std.testing.expectEqual(unknown + 1, misses.*);
    // Each heartbeat boundary retires exactly the window that reached six; the next stays servable.
    for (1..constants.mcache_len) |window| {
        support.ageHistory(&g);
        try std.testing.expect(history.get(&g.messages.store, ids[window - 1][1]) == null);
        requestOne(&g, peer.index, &ids[window - 1][1]);
        try std.testing.expectEqual(unknown + window + 1, misses.*);
        requestOne(&g, peer.index, &ids[window][0]);
        requestOne(&g, peer.index, &ids[window][1]);
        try std.testing.expectEqual(unknown + window + 1, misses.*);
    }
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "gossip retention makes room from its own kind's oldest copy and refuses when queues hold it" {
    const limits: @import("../gossip_limits.zig").Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(topic_mod.Kind.beacon_block)] = .{ .count = 1, .ssz_max = 1024 };
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary}, .validation_capacity = @import("../gossip_limits.zig").items(&limits), .processor_limits = limits });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const kind = @intFromEnum(topic_mod.Kind.beacon_block);
    for (0..4) |i| _ = try g.publish(name, &[_]u8{@intCast(i)}, .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 4), g.messages.store.retained_entries_by_kind[kind]);
    _ = try g.publish(name, "fifth", .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(g.messages.history.get(&g.messages.store, topic_mod.validMessageId(name, &[_]u8{0}, .{})) == null);
    try std.testing.expectEqual(@as(usize, 4), g.messages.history.count);
    // Copies queued to a peer stay retained, so a full allowance refuses the next message.
    var slot = g.messages.history.head;
    for (0..g.messages.history.count) |_| {
        try std.testing.expectEqual(.queued, g.sessions.rows[peer.index].io.tx.queueData(&g.messages.store, g.messages.history.message(slot), .forward, .{ .bytes = g.options.tx_peer_bytes }, 2));
        slot = g.messages.history.entries[slot].next;
    }
    try std.testing.expectError(error.ResourceExhausted, g.publish(name, "sixth", .{ .mono_ms = 3, .unix_s = 0 }));
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[kind]);
    try std.testing.expectEqual(@as(usize, 4), g.messages.history.count);
    g.cancelWrites(g.sessions.ref(peer.index));
}

test "gossip refused retention leaves the history unchanged" {
    const limits_mod = @import("../gossip_limits.zig");
    const block = topic_mod.Kind.beacon_block;
    const exit = topic_mod.Kind.voluntary_exit;
    var limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = storage.page_bytes });
    limits[@intFromEnum(block)].bytes = 2 * storage.page_bytes;
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(block)] = .{ .count = 1, .ssz_max = 6000 };
    boundary.rules[@intFromEnum(exit)] = .{ .count = 1, .ssz_max = 3000 };
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary}, .validation_capacity = limits_mod.items(&limits), .processor_limits = limits });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const history = &g.messages.history;
    var random = std.Random.DefaultPrng.init(3);
    var payloads: [3][5000]u8 = undefined;
    for (&payloads) |*payload| random.random().bytes(payload);
    const cases = [_]struct { name: []const u8, kept: [3][]const u8, queued: usize, refused: []const u8 }{
        // Two one-page blocks fill the two-page allowance; the queued one cannot be reclaimed,
        // so a two-page block must not evict the other.
        .{ .name = "/eth2/01020304/beacon_block/ssz_snappy", .kept = .{ payloads[0][0..1000], payloads[1][0..1000], "" }, .queued = 1, .refused = &payloads[2] },
        // A queued one-page exit fills the one-page allowance; inline exits free no page.
        .{ .name = "/eth2/01020304/voluntary_exit/ssz_snappy", .kept = .{ "inline one", "inline two", payloads[0][1000..2000] }, .queued = 2, .refused = payloads[1][1000..2000] },
    };
    for (cases) |case| {
        var handles: [3]storage.Handle = undefined;
        var kept: usize = 0;
        for (case.kept) |payload| {
            if (payload.len == 0) continue;
            _ = try g.publish(case.name, payload, .{ .mono_ms = 1, .unix_s = 0 });
            handles[kept] = history.message(history.get(&g.messages.store, topic_mod.validMessageId(case.name, payload, .{})).?);
            kept += 1;
        }
        try std.testing.expectEqual(.queued, g.sessions.rows[peer.index].io.tx.queueData(&g.messages.store, handles[case.queued], .forward, .{ .bytes = g.options.tx_peer_bytes }, 1));
        const count = history.count;
        try std.testing.expectError(error.ResourceExhausted, g.publish(case.name, case.refused, .{ .mono_ms = 2, .unix_s = 0 }));
        try std.testing.expectEqual(count, history.count);
        for (handles[0..kept]) |h| try std.testing.expect(history.get(&g.messages.store, g.messages.store.get(h).?.id) != null);
    }
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[@intFromEnum(block)]);
    try std.testing.expectEqual(@as(u64, 1), g.messages.retention_refusals[@intFromEnum(exit)]);
    g.cancelWrites(g.sessions.ref(peer.index));
}
