const std = @import("std");
const local = @import("local_intent.zig");
const gossip = @import("gossipsub.zig");
const topic = @import("topic.zig");
const support = @import("test_support.zig");
const full = @import("topic_policy_test.zig").full;
const name = "/eth2/01020304/beacon_block/ssz_snappy";
const next = "/eth2/01020304/voluntary_exit/ssz_snappy";
const boundaries = [_]@import("topic_policy.zig").Boundary{ full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }), full(.{ 9, 10, 11, 12 }) };
const now: @import("../types.zig").Now = .{ .mono_ms = 100, .unix_s = 0 };

fn options() gossip.Options {
    return .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1, .seen_capacity = 16, .mcache_capacity = 16, .validation_capacity = 8, .topic_policy = &boundaries };
}

fn unavailableExcept(g: *gossip.Gossipsub, count: usize) void {
    for (g.overlay.rows[count..]) |*row| row.generation = std.math.maxInt(u64);
}

fn apply(g: *gossip.Gossipsub, w: *local.Workspace, desired: []const local.Subscription) !bool {
    const changed = try g.prepareSubscriptions(desired, w, now);
    if (changed) g.commitSubscriptions(w);
    return changed;
}

test "local intent exact capacity excess duplicate score and namespace refusal" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try gossip.Gossipsub.init(ledger.allocator(), options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    var names: [513][topic.topic_max_len]u8 = undefined;
    var desired: [513]local.Subscription = undefined;
    for (&desired, 0..) |*entry, i| {
        const digest: u32 = if (i < 256) 0x01020304 else if (i < 512) 0x05060708 else 0x090a0b0c;
        const kind: []const u8 = if (i % 256 < 128) "blob_sidecar" else "data_column_sidecar";
        entry.* = .{ .name = try std.fmt.bufPrint(&names[i], "/eth2/{x:0>8}/{s}_{d}/ssz_snappy", .{ digest, kind, i % 128 }), .params = .{ .weight = 2 } };
    }
    const calls = ledger.allocation_calls;
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    try std.testing.expect(g.overlay.findTopic(desired[0].name) == null);
    try std.testing.expect(try apply(&g, w, desired[0..512]));
    try std.testing.expect(!try apply(&g, w, desired[0..512]));
    const revision = g.peers.scores.revision;
    try std.testing.expectError(error.DuplicateTopic, apply(&g, w, &.{ desired[0], desired[0] }));
    try std.testing.expectError(error.InvalidTopic, apply(&g, w, &.{ desired[0], .{ .name = "invalid", .params = .{} } }));
    try std.testing.expectError(error.InvalidLimits, apply(&g, w, &.{ desired[0], .{ .name = name, .params = .{ .weight = std.math.nan(f64) } } }));
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &.{.{ .name = name, .params = .{} }}));
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    for (0..512) |i| try std.testing.expect(g.overlay.subscribed(@intCast(i)));
    try std.testing.expect(try apply(&g, w, &.{}));
    const deadline = g.overlay.rows[0].retire_after_ms;
    try std.testing.expect(!try g.prepareSubscriptions(&.{}, w, .{ .mono_ms = 200, .unix_s = 0 }));
    try std.testing.expectEqual(deadline, g.overlay.rows[0].retire_after_ms);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
    var generic = try gossip.Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer generic.deinit();
    try std.testing.expectError(error.TopicPolicyRequired, apply(&generic, w, &.{desired[0]}));
    try std.testing.expect(!try apply(&generic, w, &.{}));
}

test "local intent reserves reclaimable desired rows and copies alias before replacement" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 2);
    try g.configureTopic(name, &.{ .weight = 2 });
    try g.configureTopic(next, &.{});
    const aliased = g.overlay.topicString(0);
    const generation = g.overlay.rows[0].generation;
    const replace = "/eth2/05060708/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{ .{ .name = replace, .params = .{ .weight = 3 } }, .{ .name = aliased, .params = .{ .weight = 4 } } }));
    try std.testing.expectEqualStrings(name, g.overlay.topicString(0));
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqualStrings(replace, g.overlay.topicString(1));
    try std.testing.expectEqual(@as(f64, 4), g.peers.scores.topic_params[0].weight);
}

test "local intent separate validation control score backoff and generation pins" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 1);
    try g.configureTopic(name, &.{});
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const logical = g.sessions.rows[peer.index].logical;
    const io = &g.sessions.rows[peer.index].io;
    const desired = [_]local.Subscription{.{ .name = next, .params = .{ .weight = 2 } }};
    const message = g.messages.store.put([_]u8{1} ** 20, name, "payload").?;
    const handle = g.messages.validation.admit(&g.messages.store, &g.peers, message, logical, .{ .index = 0, .generation = 1 }, now.mono_ms);
    g.messages.store.seal(message);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.messages.validation.finish(&g.messages.store, &g.peers, handle, .ignore, now.mono_ms);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.messages.validation.expire(&g.messages.store, &g.peers, std.math.maxInt(u64));
    io.subscription_dirty.set(0);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    io.subscription_dirty.unset(0);
    g.overlay.rows[0].mesh.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].mesh.unset(peer.index);
    g.overlay.rows[0].fanout.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].fanout.unset(peer.index);
    g.overlay.pending_prunes[0].set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.pending_prunes[0].unset(peer.index);
    g.peers.scores.invalid(logical.index, 0);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].retire_after_ms = now.mono_ms;
    const generation = g.overlay.rows[0].generation;
    g.peers.backoffs[logical.index * 512] = .{ .topic_generation = generation, .until = now.mono_ms + 1 };
    const revision = g.peers.scores.revision;
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    try std.testing.expect(g.peers.scores.retainsTopic(0));
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    g.peers.backoffs[logical.index * 512].topic_generation += 1;
    g.overlay.rows[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].generation = generation;
    try std.testing.expect(try apply(&g, w, &desired));
    try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
    try std.testing.expect(!g.peers.scores.retainsTopic(0));
}

test "local intent history survives former row reuse and real retransmission descriptor" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 1);
    _ = try g.publish(name, "history payload", now);
    const id = topic.validMessageId(name, "history payload", .{});
    const retained = g.messages.history.get(&g.messages.store, id).?.message;
    try std.testing.expect(try apply(&g, w, &.{.{ .name = next, .params = .{} }}));
    try std.testing.expectEqualStrings(next, g.overlay.topicString(0));
    const entry = g.messages.store.get(retained).?;
    try std.testing.expectEqualStrings(name, entry.topicString());
    var payload: [64]u8 = undefined;
    const read = try @import("snappy").raw.uncompress(g.messages.store.segment(retained, g.messages.store.cursor(retained)), &payload);
    try std.testing.expectEqualStrings("history payload", payload[0..read]);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const io = &g.sessions.rows[peer.index].io;
    const served = g.messages.serve(io, g.sessions.rows[peer.index].logical, id, g.options.tx_peer_bytes, now.mono_ms);
    try std.testing.expect(served == .known);
    try std.testing.expectEqualStrings(name, served.known.topic);
    try std.testing.expectEqual(.queued, served.known.result);
    try std.testing.expectEqual(retained, io.data[io.data_head].message);
    try std.testing.expectEqualStrings(name, g.messages.store.get(io.data[io.data_head].message).?.topicString());
    try std.testing.expect(io.segment(&g.messages.store).len > 0);
}

test "local intent copies retired row input before another assignment reuses it" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 3);
    try g.configureTopic(name, &.{});
    try g.configureTopic(next, &.{});
    try g.configureTopic("/eth2/01020304/proposer_slashing/ssz_snappy", &.{});
    const input = g.overlay.topicString(1);
    try g.configureTopic("/eth2/05060708/beacon_block/ssz_snappy", &.{});
    try std.testing.expect(!g.overlay.rows[1].active);
    try std.testing.expectEqualStrings(next, input);
    const replacement = "/eth2/090a0b0c/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{
        .{ .name = g.overlay.topicString(0), .params = .{} },
        .{ .name = replacement, .params = .{} },
        .{ .name = input, .params = .{ .weight = 5 } },
    }));
    try std.testing.expectEqualStrings(replacement, g.overlay.topicString(1));
    try std.testing.expectEqualStrings(next, g.overlay.topicString(2));
    try std.testing.expectEqual(@as(f64, 5), g.peers.scores.topic_params[2].weight);
}

test "local intent equal-parameter retirement invalidates primed positive and negative scores" {
    try cachedRetirement(true);
}

test "ordinary equal-parameter retirement invalidates primed positive and negative scores" {
    try cachedRetirement(false);
}

fn cachedRetirement(complete_intent: bool) !void {
    for ([_]bool{ false, true }) |negative| {
        var opts = options();
        opts.retained_score_ms = 1;
        var g = try gossip.Gossipsub.init(std.testing.allocator, opts);
        defer g.deinit();
        const w = try std.testing.allocator.create(local.Workspace);
        defer std.testing.allocator.destroy(w);
        w.* = .{};
        unavailableExcept(&g, 1);
        try std.testing.expect(g.subscribe(name));
        try std.testing.expect(g.unsubscribe(name));
        const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
        const logical = g.sessions.rows[peer.index].logical.index;
        if (negative) g.peers.scores.invalid(logical, 0) else g.peers.scores.deliver(logical, 0);
        const expected: f64 = if (negative) -100 else 1;
        try std.testing.expectEqual(expected, g.peers.scores.score(logical, now.mono_ms));
        try std.testing.expect(!g.peers.scores.dirty[logical]);
        try std.testing.expectEqual(@as(?u64, null), g.peers.scores.nextChange(logical));
        const revision = g.peers.scores.revision;
        const params = g.peers.scores.topic_params[0];
        const generation = g.overlay.rows[0].generation;
        try std.testing.expect(now.mono_ms >= g.overlay.rows[0].retire_after_ms.?);
        if (complete_intent) {
            try std.testing.expect(try apply(&g, w, &.{.{ .name = next, .params = params }}));
        } else {
            g.last_now_ms = now.mono_ms;
            try g.configureTopic(next, &params);
        }
        try std.testing.expectEqualStrings(next, g.overlay.topicString(0));
        try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
        try std.testing.expectEqualDeep(params, g.peers.scores.topic_params[0]);
        try std.testing.expect(!g.peers.scores.retainsTopic(0));
        try std.testing.expect(g.peers.scores.revision > revision);
        try std.testing.expect(g.peers.scores.dirty[logical]);
        try std.testing.expectEqual(@as(f64, 0), g.peers.scores.score(logical, now.mono_ms));
        const retired_revision = g.peers.scores.revision;
        const calculations = g.peers.scores.calculations;
        const refreshed = now.mono_ms + g.peers.scores.params.decay_interval_ms;
        g.peers.scores.refresh(refreshed);
        try std.testing.expectEqual(@as(f64, 0), g.peers.scores.score(logical, refreshed));
        try std.testing.expectEqual(retired_revision, g.peers.scores.revision);
        try std.testing.expectEqual(calculations, g.peers.scores.calculations);
        if (complete_intent) {
            g.peers.scores.invalid(logical, 0);
            try std.testing.expectEqual(@as(f64, -100), g.peers.scores.score(logical, refreshed));
            const current_revision = g.peers.scores.revision;
            const counters = g.peers.scores.topics[@as(usize, logical) * 512];
            try std.testing.expect(!try apply(&g, w, &.{.{ .name = next, .params = params }}));
            try std.testing.expectEqual(current_revision, g.peers.scores.revision);
            try std.testing.expectEqualDeep(counters, g.peers.scores.topics[@as(usize, logical) * 512]);
            try std.testing.expectEqual(@as(f64, -100), g.peers.scores.score(logical, refreshed));
        }
    }
}
