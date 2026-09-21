const std = @import("std");
const local = @import("local_intent.zig");
const gossip = @import("gossipsub.zig");
const topic = @import("topic.zig");
const support = @import("test_support.zig");
const full = @import("topic_fixture.zig").full;
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

fn apply(g: *gossip.Gossipsub, w: *local.Workspace, desired: []const []const u8) !bool {
    var buffer: [64]local.Boundary = undefined;
    const changed = try g.prepareSubscriptions(try @import("topic_fixture.zig").subscriptionsInto(desired, &buffer), w, now, 0);
    if (changed) g.commitSubscriptions(w);
    return changed;
}

test "intent and publication prefer unused rows and reclaim only their selected retirement" {
    for ([_]bool{ false, true }) |subscribe| {
        var opts = options();
        opts.retained_score_ms = 1;
        var g = try gossip.Gossipsub.init(std.testing.allocator, opts);
        defer g.deinit();
        unavailableExcept(&g, 3);
        try support.subscribe(&g, name);
        try support.subscribe(&g, next);
        var workspace: local.Workspace = .{};
        try std.testing.expect(!try apply(&g, &workspace, &.{ name, next }));
        try support.unsubscribe(&g, name);
        try support.unsubscribe(&g, next);
        const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
        const logical = g.sessions.rows[peer.index].logical;
        for (0..2) |index| g.peers.scores.invalid(logical.index, @intCast(index));
        const generations = [2]u64{ g.overlay.rows[0].generation, g.overlay.rows[1].generation };
        const third = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
        if (subscribe) {
            try std.testing.expect(try apply(&g, &workspace, &.{third}));
        } else _ = try g.publish(third, "0123456789", now);
        try std.testing.expectEqual(@as(?u16, 2), g.overlay.findTopic(third));
        for (0..2) |index| {
            try std.testing.expectEqual(generations[index], g.overlay.rows[index].generation);
            try std.testing.expect(g.peers.scores.retainsTopic(@intCast(index)));
        }
        const fourth = "/eth2/05060708/beacon_block/ssz_snappy";
        if (subscribe) {
            try std.testing.expect(try apply(&g, &workspace, &.{ third, fourth }));
        } else _ = try g.publish(fourth, "0123456789", now);
        try std.testing.expectEqual(@as(?u16, 0), g.overlay.findTopic(fourth));
        try std.testing.expectEqual(generations[0] + 1, g.overlay.rows[0].generation);
        try std.testing.expect(!g.peers.scores.retainsTopic(0));
        try std.testing.expectEqualStrings(next, g.overlay.topicString(1));
        try std.testing.expectEqual(generations[1], g.overlay.rows[1].generation);
        try std.testing.expect(g.peers.scores.retainsTopic(1));
    }
}

test "local intent exact capacity excess and namespace refusal" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try gossip.Gossipsub.init(ledger.allocator(), options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    var names: [513][topic.topic_max_len]u8 = undefined;
    var desired: [513][]const u8 = undefined;
    for (&desired, 0..) |*entry, i| {
        const digest: u32 = if (i < 256) 0x01020304 else if (i < 512) 0x05060708 else 0x090a0b0c;
        const kind: []const u8 = if (i % 256 < 128) "blob_sidecar" else "data_column_sidecar";
        entry.* = try std.fmt.bufPrint(&names[i], "/eth2/{x:0>8}/{s}_{d}/ssz_snappy", .{ digest, kind, i % 128 });
    }
    const calls = ledger.allocation_calls;
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    try std.testing.expect(g.overlay.findTopic(desired[0]) == null);
    try std.testing.expect(try apply(&g, w, desired[0..512]));
    try std.testing.expect(!try apply(&g, w, desired[0..512]));
    const revision = g.peers.scores.revision;
    try std.testing.expectError(error.InvalidTopic, apply(&g, w, &.{ desired[0], "invalid" }));
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &.{name}));
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    for (0..512) |i| try std.testing.expect(g.overlay.subscribed(@intCast(i)));
    try std.testing.expect(try apply(&g, w, &.{}));
    const deadline = g.overlay.rows[0].retire_after_ms;
    try std.testing.expect(!try g.prepareSubscriptions(&.{}, w, .{ .mono_ms = 200, .unix_s = 0 }, 0));
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
    g.peers.scores.applyValidatedTopic(support.intern(&g, name).?, .{ .weight = 2 });
    _ = support.intern(&g, next).?;
    const aliased = g.overlay.topicString(0);
    const generation = g.overlay.rows[0].generation;
    const replace = "/eth2/05060708/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{ replace, aliased }));
    try std.testing.expectEqualStrings(name, g.overlay.topicString(0));
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqualStrings(replace, g.overlay.topicString(1));
    try std.testing.expectEqual(@as(f64, 1), g.peers.scores.topic_params[0].weight);
}

test "local intent separate validation control score backoff and generation pins" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 1);
    _ = support.intern(&g, name).?;
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const logical = g.sessions.rows[peer.index].logical;
    const io = &g.sessions.rows[peer.index].io;
    const desired = [_][]const u8{next};
    const message = g.messages.store.put([_]u8{1} ** 20, name, "payload").?;
    var reservation = g.messages.validation.reserve(g.messages.store.get(message).?.id).?;
    const handle = reservation.commit(&g.messages.store, &g.peers, message, logical, .{ .index = 0, .generation = 1 }, now.mono_ms);
    g.messages.store.seal(message);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.messages.validation.finish(&g.messages.store, handle, .ignore, now.mono_ms);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.messages.validation.expire(&g.messages.store, &g.peers, std.math.maxInt(u64));
    io.tx.subscription_dirty.set(0);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    io.tx.subscription_dirty.unset(0);
    g.overlay.rows[0].mesh.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].mesh.unset(peer.index);
    g.overlay.rows[0].fanout.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.overlay.rows[0].fanout.unset(peer.index);

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
    const retained = g.messages.history.message(g.messages.history.get(&g.messages.store, id).?);
    try std.testing.expect(try apply(&g, w, &.{next}));
    try std.testing.expectEqualStrings(next, g.overlay.topicString(0));
    const entry = g.messages.store.get(retained).?;
    try std.testing.expectEqualStrings(name, entry.topicString());
    var payload: [64]u8 = undefined;
    const read = try @import("snappy").raw.uncompress(g.messages.store.segment(retained, g.messages.store.cursor(retained)), &payload);
    try std.testing.expectEqualStrings("history payload", payload[0..read]);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const io = &g.sessions.rows[peer.index].io;
    const served = g.messages.serve(&io.tx, g.sessions.rows[peer.index].logical, id, g.options.tx_peer_bytes, now.mono_ms);
    try std.testing.expect(served == .known);
    try std.testing.expectEqualStrings(name, served.known.topic);
    try std.testing.expectEqual(.queued, served.known.result);
    try std.testing.expectEqual(retained, io.tx.data.first().?.message);
    try std.testing.expectEqualStrings(name, g.messages.store.get(io.tx.data.first().?.message).?.topicString());
    try std.testing.expect(io.tx.segment(&g.messages.store).len > 0);
}

test "local intent copies retired row input before another assignment reuses it" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 3);
    _ = support.intern(&g, name).?;
    _ = support.intern(&g, next).?;
    _ = support.intern(&g, "/eth2/01020304/proposer_slashing/ssz_snappy").?;
    const input = g.overlay.topicString(1);
    _ = support.intern(&g, "/eth2/05060708/beacon_block/ssz_snappy").?;
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), 1);
    try std.testing.expect(!g.overlay.rows[1].active);
    try std.testing.expectEqualStrings(next, input);
    const replacement = "/eth2/090a0b0c/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{
        g.overlay.topicString(0),
        replacement,
        input,
    }));
    try std.testing.expect(g.overlay.findTopic(replacement) != null);
    try std.testing.expect(g.overlay.findTopic(next) != null);
    try std.testing.expectEqual(@as(f64, 1), g.peers.scores.topic_params[g.overlay.findTopic(next).?].weight);
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
        try support.subscribe(&g, name);
        try support.unsubscribe(&g, name);
        const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
        const logical = g.sessions.rows[peer.index].logical.index;
        if (negative) g.peers.scores.invalid(logical, 0) else g.peers.scores.deliverEligible(logical, 0, false);
        const expected: f64 = if (negative) -100 else 1;
        try std.testing.expectEqual(expected, g.peers.score(g.sessions.rows[peer.index].logical, now.mono_ms));
        try std.testing.expect(!g.peers.scores.rows[logical].dirty);
        try std.testing.expectEqual(@as(?u64, null), g.peers.scores.nextChange(logical));
        const revision = g.peers.scores.revision;
        const params = g.peers.scores.topic_params[0];
        const generation = g.overlay.rows[0].generation;
        try std.testing.expect(now.mono_ms >= g.overlay.rows[0].retire_after_ms.?);
        if (complete_intent) {
            try std.testing.expect(try apply(&g, w, &.{next}));
        } else {
            g.last_now_ms = now.mono_ms;
            _ = try g.publish(next, "0123456789", now);
        }
        try std.testing.expectEqualStrings(next, g.overlay.topicString(0));
        try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
        try std.testing.expectEqualDeep(params, g.peers.scores.topic_params[0]);
        try std.testing.expect(!g.peers.scores.retainsTopic(0));
        try std.testing.expect(g.peers.scores.revision > revision);
        try std.testing.expect(g.peers.scores.rows[logical].dirty);
        try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[peer.index].logical, now.mono_ms));
        const retired_revision = g.peers.scores.revision;
        const calculations = g.peers.scores.calculations;
        const refreshed = now.mono_ms + g.peers.scores.params.decay_interval_ms;
        g.peers.scores.refresh(refreshed);
        try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[peer.index].logical, refreshed));
        try std.testing.expectEqual(retired_revision, g.peers.scores.revision);
        try std.testing.expectEqual(calculations, g.peers.scores.calculations);
        if (complete_intent) {
            g.peers.scores.invalid(logical, 0);
            try std.testing.expectEqual(@as(f64, -100), g.peers.score(g.sessions.rows[peer.index].logical, refreshed));
            const current_revision = g.peers.scores.revision;
            const counters = g.peers.scores.topics[@as(usize, logical) * 512];
            try std.testing.expect(!try apply(&g, w, &.{next}));
            try std.testing.expectEqual(current_revision, g.peers.scores.revision);
            try std.testing.expectEqualDeep(counters, g.peers.scores.topics[@as(usize, logical) * 512]);
            try std.testing.expectEqual(@as(f64, -100), g.peers.score(g.sessions.rows[peer.index].logical, refreshed));
        }
    }
}

test "compact intent validates masks and boundary identities before mutation" {
    var allowed = boundaries;
    allowed[0].rules[@intFromEnum(topic.Kind.data_column_sidecar)] = .{};
    var opts = options();
    opts.topic_policy = &allowed;
    var g = try gossip.Gossipsub.init(std.testing.allocator, opts);
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    const sets = @import("topic_fixture.zig").subscriptions(&.{name});
    try std.testing.expectError(error.DuplicateBoundary, g.prepareSubscriptions(&.{ sets[0], sets[0] }, w, now, 0));
    var invalid = sets[0];
    invalid.digest = @splat(255);
    try std.testing.expectError(error.InvalidTopic, g.prepareSubscriptions(&.{invalid}, w, now, 0));
    invalid = sets[0];
    invalid.mask(.sync_committee)[0] = 16;
    invalid.lengths[@intFromEnum(topic.Kind.sync_committee)] = 1;
    try std.testing.expectError(error.InvalidTopic, g.prepareSubscriptions(&.{invalid}, w, now, 0));
    invalid = sets[0];
    invalid.lengths[@intFromEnum(topic.Kind.data_column_sidecar)] = 1;
    try std.testing.expectError(error.InvalidTopic, g.prepareSubscriptions(&.{invalid}, w, now, 0));
    try std.testing.expect(g.overlay.findTopic(name) == null);
    try std.testing.expect(try g.prepareSubscriptions(sets, w, now, 0));
    g.commitSubscriptions(w);
    const generation = g.overlay.rows[0].generation;
    try std.testing.expect(!try g.prepareSubscriptions(sets, w, now, 1));
    g.commitSubscriptions(w);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
}

test "compact intent resubscribes a pinned retained row with its score and generation" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options());
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    unavailableExcept(&g, 1);
    try std.testing.expect(try apply(&g, w, &.{name}));
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const logical = g.sessions.rows[peer.index].logical.index;
    g.peers.scores.invalid(logical, 0);
    try std.testing.expect(try apply(&g, w, &.{}));
    const generation = g.overlay.rows[0].generation;
    const counters = g.peers.scores.topics[@as(usize, logical) * 512];
    g.sessions.rows[peer.index].io.tx.subscription_dirty.set(0);
    try std.testing.expect(try apply(&g, w, &.{name}));
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqualDeep(counters, g.peers.scores.topics[@as(usize, logical) * 512]);
    try std.testing.expect(g.overlay.rows[0].subscribed);
}

test "local intent startup kind scores activate on accepted slots without resetting topic history" {
    var opts = options();
    opts.topic_params = @splat(.{ .params = .{ .weight = 2 }, .mesh_delivery_start_slot = 3 });
    var g = try gossip.Gossipsub.init(std.testing.allocator, opts);
    defer g.deinit();
    const w = try std.testing.allocator.create(local.Workspace);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    const sets = @import("topic_fixture.zig").subscriptions(&.{ name, "/eth2/05060708/beacon_block/ssz_snappy" });
    try std.testing.expect(try g.prepareSubscriptions(sets, w, now, 0));
    g.commitSubscriptions(w);
    try std.testing.expectEqual(@as(f64, 0), g.peers.scores.topic_params[0].mesh_delivery_weight);
    try std.testing.expectEqualDeep(g.peers.scores.topic_params[0], g.peers.scores.topic_params[1]);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const logical = g.sessions.rows[peer.index].logical.index;
    g.peers.scores.invalid(logical, 0);
    const counters = g.peers.scores.topics[@as(usize, logical) * 512];
    const generation = g.overlay.rows[0].generation;
    try std.testing.expectError(error.InvalidTopic, g.prepareSubscriptions(&.{.{ .digest = @splat(255) }}, w, now, 3));
    try std.testing.expectEqual(@as(u64, 0), g.overlay.slot);
    try std.testing.expectEqual(@as(f64, 0), g.peers.scores.topic_params[0].mesh_delivery_threshold);
    try std.testing.expect(!try g.prepareSubscriptions(sets, w, now, 2));
    g.commitSubscriptions(w);
    try std.testing.expect(try g.prepareSubscriptions(sets, w, now, 3));
    g.commitSubscriptions(w);
    try std.testing.expectEqual(@as(f64, -1), g.peers.scores.topic_params[0].mesh_delivery_weight);
    try std.testing.expectEqual(@as(f64, 5), g.peers.scores.topic_params[0].mesh_delivery_threshold);
    try std.testing.expectEqualDeep(g.peers.scores.topic_params[0], g.peers.scores.topic_params[1]);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqualDeep(counters, g.peers.scores.topics[@as(usize, logical) * 512]);
    try std.testing.expect(!try g.prepareSubscriptions(sets, w, now, 4));
    opts.topic_params.?[2].params.weight = std.math.nan(f64);
    try std.testing.expectError(error.InvalidLimits, gossip.Gossipsub.init(std.testing.allocator, opts));
}
