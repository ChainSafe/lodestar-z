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
    for (g.state.topics[count..]) |*row| row.generation = std.math.maxInt(u64);
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
    try std.testing.expect(g.state.findTopic(desired[0].name) == null);
    try std.testing.expect(try apply(&g, w, desired[0..512]));
    try std.testing.expect(!try apply(&g, w, desired[0..512]));
    const revision = g.scores.revision;
    try std.testing.expectError(error.DuplicateTopic, apply(&g, w, &.{ desired[0], desired[0] }));
    try std.testing.expectError(error.InvalidTopic, apply(&g, w, &.{ desired[0], .{ .name = "invalid", .params = .{} } }));
    try std.testing.expectError(error.InvalidLimits, apply(&g, w, &.{ desired[0], .{ .name = name, .params = .{ .weight = std.math.nan(f64) } } }));
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &.{.{ .name = name, .params = .{} }}));
    try std.testing.expectEqual(revision, g.scores.revision);
    for (0..512) |i| try std.testing.expect(g.state.subscribed(@intCast(i)));
    try std.testing.expect(try apply(&g, w, &.{}));
    const deadline = g.state.topics[0].retire_after_ms;
    try std.testing.expect(!try g.prepareSubscriptions(&.{}, w, .{ .mono_ms = 200, .unix_s = 0 }));
    try std.testing.expectEqual(deadline, g.state.topics[0].retire_after_ms);
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
    const aliased = g.state.topicString(0);
    const generation = g.state.topics[0].generation;
    const replace = "/eth2/05060708/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{ .{ .name = replace, .params = .{ .weight = 3 } }, .{ .name = aliased, .params = .{ .weight = 4 } } }));
    try std.testing.expectEqualStrings(name, g.state.topicString(0));
    try std.testing.expectEqual(generation, g.state.topics[0].generation);
    try std.testing.expectEqualStrings(replace, g.state.topicString(1));
    try std.testing.expectEqual(@as(f64, 4), g.scores.topic_params[0].weight);
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
    const logical = g.state.peers[peer.index].logical;
    const io = &g.io.peers[peer.index];
    const desired = [_]local.Subscription{.{ .name = next, .params = .{ .weight = 2 } }};
    const message = g.store.put([_]u8{1} ** 20, name, "payload").?;
    const handle = g.validation.admit(&g.store, &g.peers, message, logical, 0, now.mono_ms);
    g.store.seal(message);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.validation.finish(&g.store, &g.peers, handle, .ignore, now.mono_ms);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.validation.expire(&g.store, &g.peers, std.math.maxInt(u64));
    io.subscription_dirty.set(0);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    io.subscription_dirty.unset(0);
    g.state.topics[0].mesh.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.state.topics[0].mesh.unset(peer.index);
    g.state.topics[0].fanout.set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.state.topics[0].fanout.unset(peer.index);
    g.mesh_policy.pending_prunes[0].set(peer.index);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.mesh_policy.pending_prunes[0].unset(peer.index);
    g.scores.invalid(logical.index, 0);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.state.topics[0].retire_after_ms = now.mono_ms;
    const generation = g.state.topics[0].generation;
    g.peers.backoffs[logical.index * 512] = .{ .topic_generation = generation, .until = now.mono_ms + 1 };
    const revision = g.scores.revision;
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    try std.testing.expect(g.scores.retainsTopic(0));
    try std.testing.expectEqual(revision, g.scores.revision);
    g.peers.backoffs[logical.index * 512].topic_generation += 1;
    g.state.topics[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.TopicCapacity, apply(&g, w, &desired));
    g.state.topics[0].generation = generation;
    try std.testing.expect(try apply(&g, w, &desired));
    try std.testing.expectEqual(generation + 1, g.state.topics[0].generation);
    try std.testing.expect(!g.scores.retainsTopic(0));
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
    const retained = g.mcache.get(&g.store, id).?.message;
    try std.testing.expect(try apply(&g, w, &.{.{ .name = next, .params = .{} }}));
    try std.testing.expectEqualStrings(next, g.state.topicString(0));
    const entry = g.store.get(retained).?;
    try std.testing.expectEqualStrings(name, entry.topicString());
    var payload: [64]u8 = undefined;
    const read = try @import("snappy").raw.uncompress(g.store.segment(retained, g.store.cursor(retained)), &payload);
    try std.testing.expectEqualStrings("history payload", payload[0..read]);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const io = &g.io.peers[peer.index];
    const cached = g.mcache.get(&g.store, id).?;
    try std.testing.expect(g.mcache.iwantAllowed(cached, g.state.peers[peer.index].logical, @import("constants.zig").gossip_retransmission));
    try std.testing.expectEqual(.queued, io.queueData(&g.store, retained, g.options.tx_peer_bytes, now.mono_ms));
    try std.testing.expectEqual(retained, io.data[io.data_head].message);
    try std.testing.expectEqualStrings(name, g.store.get(io.data[io.data_head].message).?.topicString());
    try std.testing.expect(io.segment(&g.store).len > 0);
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
    const input = g.state.topicString(1);
    try g.configureTopic("/eth2/05060708/beacon_block/ssz_snappy", &.{});
    try std.testing.expect(!g.state.topics[1].active);
    try std.testing.expectEqualStrings(next, input);
    const replacement = "/eth2/090a0b0c/beacon_block/ssz_snappy";
    try std.testing.expect(try apply(&g, w, &.{
        .{ .name = g.state.topicString(0), .params = .{} },
        .{ .name = replacement, .params = .{} },
        .{ .name = input, .params = .{ .weight = 5 } },
    }));
    try std.testing.expectEqualStrings(replacement, g.state.topicString(1));
    try std.testing.expectEqualStrings(next, g.state.topicString(2));
    try std.testing.expectEqual(@as(f64, 5), g.scores.topic_params[2].weight);
}
