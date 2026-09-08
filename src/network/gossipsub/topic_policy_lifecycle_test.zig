const std = @import("std");
const p = @import("topic_policy.zig");
const gossip = @import("gossipsub.zig");
const Gossipsub = gossip.Gossipsub;
const GossipPair = @import("gossipsub_test.zig").GossipPair;
const validation = @import("validation.zig");
const support = @import("test_support.zig");
const name = "/eth2/01020304/beacon_block/ssz_snappy";
const unknown = "/eth2/01020304/unknown/ssz_snappy";

fn boundary() p.Boundary {
    var b: p.Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    b.rules[0] = .{ .count = 1, .ssz_min = 10, .ssz_max = 20 };
    return b;
}
fn options(boundaries: []const p.Boundary) gossip.Options {
    var out: gossip.Options = .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1, .seen_capacity = 16, .mcache_capacity = 16, .validation_capacity = 8 };
    out.topic_policy = boundaries;
    return out;
}
fn live(g: *const Gossipsub) usize {
    var count: usize = 0;
    for (g.state.topics) |row| if (row.active) {
        count += 1;
    };
    return count;
}

test "topic policy remembers real inactive subscriptions without event pressure then delivers" {
    var pair: GossipPair = .{};
    try pair.initOpts(.{ .random_seed = 1 }, options(&.{boundary()}));
    defer pair.deinit();
    pair.server_event_capacity = 0;
    try std.testing.expect(pair.client.subscribe(name));
    try std.testing.expect(pair.client.subscribe(unknown));
    for (0..20) |_| try pair.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), live(&pair.server));
    try std.testing.expectEqual(@as(usize, 0), pair.server.decompressed_used);
    try std.testing.expectEqual(@as(u64, 0), pair.server.counters.local_pressure_resets);
    try pair.server.configureTopic(name, &.{ .weight = 2 });
    const t = pair.server.state.findTopic(name).?;
    try std.testing.expectEqual(@as(usize, 1), pair.server.state.subscribers(t).count());
    try std.testing.expect(pair.server.subscribe(name));
    pair.server_event_capacity = 16;
    const result = try pair.server.publishWithOptions(name, "0123456789", .{ .allow_zero_peers = false }, pair.pair.now);
    try std.testing.expectEqual(@as(usize, 1), result.queued);
    var delivered = false;
    for (0..20) |_| {
        try pair.pumpOnce();
        for (pair.clientEvents()) |event| if (event == .message) {
            try std.testing.expectEqualStrings("0123456789", event.message.bytes);
            delivered = true;
        };
    }
    try std.testing.expect(delivered);
    try std.testing.expect(pair.client.unsubscribe(name));
    for (0..20) |_| try pair.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), pair.server.state.subscribers(t).count());
    try std.testing.expect(!pair.server.namespace.?.subscribed(0, 0));
}

test "topic policy incoming lengths precede decode work arena store and validation admission" {
    var g = try Gossipsub.init(std.testing.allocator, options(&.{boundary()}));
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try std.testing.expect(g.subscribe(name));
    var context: validation.Context = .{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .store = &g.store, .history = &g.mcache, .seen = &g.seen, .options = &g.options };
    context.namespace = if (g.namespace) |*ns| ns else null;
    var used: usize = 0;
    var peer_work: usize = 0;
    var work: usize = 10000;
    var large_used = false;
    var arena: [1024]u8 = @splat(0xaa);
    var workspace: validation.Workspace = .{ .arena = &arena, .used = &used, .peer_work = &peer_work, .work = &work, .large_used = &large_used, .event_available = false };
    var compressed: [100]u8 = undefined;
    const payload: [21]u8 = @splat('x');
    for ([_]usize{ 9, 21 }) |size| {
        const len = try @import("snappy").raw.compress(payload[0..size], &compressed);
        try std.testing.expectEqual(validation.Received.ignored, g.validation.receive(&context, &workspace, peer.index, .{ .topic = name, .data = compressed[0..len] }, 1));
        try std.testing.expectEqual(validation.Received.ignored, g.validation.receive(&context, &workspace, peer.index, .{ .topic = name, .data = &.{@intCast(size)} }, 1));
        try std.testing.expectEqual(@as(usize, 0), used);
        try std.testing.expectEqual(@as(usize, 0), peer_work);
        try std.testing.expectEqual(@as(usize, 10000), work);
        try std.testing.expect(!large_used);
        try std.testing.expectEqual(@as(usize, 0), g.store.used_entries);
        for (g.validation.entries) |entry| try std.testing.expect(entry.state == .free);
        try std.testing.expectEqualSlices(u8, &(@as([1024]u8, @splat(0xaa))), &arena);
    }
    workspace.event_available = true;
    for ([_]usize{ 10, 20 }) |size| {
        const len = try @import("snappy").raw.compress(payload[0..size], &compressed);
        const received = g.validation.receive(&context, &workspace, peer.index, .{ .topic = name, .data = compressed[0..len] }, 1);
        try std.testing.expect(received == .admitted);
        try std.testing.expectEqualSlices(u8, payload[0..size], received.admitted.bytes);
        _ = g.report(received.admitted.handle, .ignore, .{ .mono_ms = 2, .unix_s = 0 });
    }
    try std.testing.expect(peer_work > 0);
}

test "topic policy local publication enforces maximum before state but permits below minimum" {
    var g = try Gossipsub.init(std.testing.allocator, options(&.{boundary()}));
    defer g.deinit();
    try std.testing.expectError(error.PayloadTooLarge, g.publish(name, "012345678901234567890", .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectEqual(@as(usize, 0), live(&g));
    try std.testing.expectEqual(@as(usize, 0), g.store.used_entries);
    try std.testing.expectError(error.UnknownTopic, g.publish(unknown, "", .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectError(error.InvalidTopic, g.configureTopic(unknown, &.{}));
    try std.testing.expect(!g.subscribe(unknown));
    try std.testing.expectEqual(@as(usize, 0), live(&g));
    _ = try g.publish(name, "short", .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 1), g.counters.messages_published);
    try std.testing.expectError(error.Duplicate, g.publish(name, "short", .{ .mono_ms = 1, .unix_s = 0 }));
}

test "topic policy physical close clears bits while same connection stream replacement preserves them" {
    var pair: GossipPair = .{};
    try pair.initOpts(.{ .random_seed = 1 }, options(&.{boundary()}));
    defer pair.deinit();
    try std.testing.expect(pair.client.subscribe(name));
    for (0..20) |_| try pair.pumpOnce();
    const index = pair.server.state.findPeer(pair.handles.server).?;
    const ns = &pair.server.namespace.?;
    try std.testing.expect(ns.subscribed(index, 0));
    pair.server.resetInbound(&pair.pair.server, index);
    pair.server.resetOutbound(&pair.pair.server, index);
    try std.testing.expect(ns.subscribed(index, 0));
    pair.server.replaceInbound(&pair.pair.server, index, pair.server_send, .v1_1);
    pair.server.replaceOutbound(&pair.pair.server, index, pair.server_send, .v1_1);
    try std.testing.expect(ns.subscribed(index, 0));
    var stale = pair.handles.server;
    stale.generation += 1;
    pair.server.connectionClosed(stale);
    try std.testing.expect(ns.subscribed(index, 0));
    const other = support.addPeer(&pair.server, .{ .index = 77, .generation = 1 }, .v1_2).?;
    ns.setSubscription(other.index, 0, true);
    pair.server.connectionClosed(pair.handles.server);
    try std.testing.expect(!ns.subscribed(index, 0));
    try std.testing.expect(ns.subscribed(other.index, 0));
    const replacement = support.addPeer(&pair.server, stale, .v1_2).?;
    try std.testing.expectEqual(index, replacement.index);
    try std.testing.expect(!ns.subscribed(index, 0));
    try std.testing.expect(pair.server.subscribe(name));
    const t = pair.server.state.findTopic(name).?;
    try std.testing.expect(!pair.server.state.subscribers(t).isSet(index));
    try std.testing.expect(pair.server.state.subscribers(t).isSet(other.index));
}

test "topic policy real wire receives only bounded SSZ and keeps borrowed payloads stable" {
    var pair: GossipPair = .{};
    try pair.initOpts(.{ .random_seed = 1 }, options(&.{boundary()}));
    defer pair.deinit();
    try std.testing.expect(pair.server.subscribe(name));
    try std.testing.expect(pair.client.subscribe(name));
    for (0..20) |_| try pair.pumpOnce();
    var seen: usize = 0;
    const payload: [21]u8 = @splat('z');
    for ([_]usize{ 9, 10, 20, 21 }) |size| {
        const result = try pair.client.publish(name, payload[0..size], pair.pair.now);
        try std.testing.expectEqual(@as(usize, 1), result.queued);
        for (0..20) |_| {
            try pair.pumpOnce();
            for (pair.serverEvents()) |event| if (event == .message) {
                try std.testing.expect(size == 10 or size == 20);
                seen += 1;
                try std.testing.expectEqualSlices(u8, payload[0..size], event.message.bytes);
                try pair.server.configureTopic(event.message.topic, &.{ .weight = 2 });
                const local: [2]u8 = .{ 'x', @intCast(size) };
                _ = try pair.server.publish(event.message.topic, &local, pair.pair.now);
                try std.testing.expectEqualStrings(name, event.message.topic);
                try std.testing.expectEqualSlices(u8, payload[0..size], event.message.bytes);
                try std.testing.expectEqual(gossip.ReportOutcome{ .applied = .ignore }, pair.server.report(event.message.handle, .ignore, pair.pair.now));
            };
        }
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
}

test "topic policy all 784 names stay separate from retained live topic capacity" {
    const boundaries = @import("topic_policy_test.zig").hoodi();
    var g = try Gossipsub.init(std.testing.allocator, options(&boundaries));
    defer g.deinit();
    var buffer: [@import("topic.zig").topic_max_len]u8 = undefined;
    var names: usize = 0;
    for (&boundaries) |*b| {
        inline for (@typeInfo(p.Kind).@"enum".fields) |field| {
            const kind: p.Kind = @enumFromInt(field.value);
            for (0..b.rules[field.value].count) |subnet| {
                var short: [@import("topic.zig").name_max_len]u8 = undefined;
                const part = if (kind.countMax() == 1) field.name else try std.fmt.bufPrint(&short, field.name ++ "_{d}", .{subnet});
                const topic_name = @import("topic.zig").build(b.digest, part, &buffer);
                try std.testing.expect(g.namespace.?.lookup(topic_name) != null);
                if (names < 512) {
                    try std.testing.expect(g.subscribe(topic_name));
                } else {
                    try std.testing.expectError(error.TopicCapacity, g.configureTopic(topic_name, &.{}));
                    try std.testing.expect(!g.subscribe(topic_name));
                }
                names += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 784), names);
    try std.testing.expectEqual(@as(usize, 512), live(&g));
    for (g.state.topics) |row| {
        try std.testing.expect(row.subscribed);
        try std.testing.expectEqual(@as(u64, 1), row.generation);
    }
}

test "topic policy copied startup allocation prefixes and whole owner memory reconcile" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, startup, .{});
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var boundaries = @import("topic_policy_test.zig").hoodi();
    var g = try Gossipsub.init(ledger.allocator(), options(&boundaries));
    defer g.deinit();
    const ns = &g.namespace.?;
    try std.testing.expectEqual(@as(usize, 2 * 13 * 8), ns.subscriptions.len * 8);
    try std.testing.expectEqual(g.memoryPlan().total_bytes - @sizeOf(Gossipsub), ledger.bytes);
    try std.testing.expect(g.options.topic_policy == null);
    boundaries[0].digest = @splat(0);
    boundaries[0].rules[0].ssz_max = 1;
    try std.testing.expectEqual(@as(u32, 100), ns.lookup("/eth2/d2f1997f/beacon_block/ssz_snappy").?.rule.ssz_max);
    const configured_bytes = ledger.bytes;
    var raw_options = options(&boundaries);
    raw_options.topic_policy = null;
    var raw = try Gossipsub.init(std.testing.allocator, raw_options);
    defer raw.deinit();
    try std.testing.expectEqual(ns.allocatedBytes(), g.memoryPlan().total_bytes - raw.memoryPlan().total_bytes);
    std.debug.print("topic namespace memory: boundaries={d} topics={d} peers={d} descriptor_bytes={d} offset_bytes={d} bitmap_bytes={d} delta={d} owner_requested={d}\n", .{ ns.boundaries.len, ns.topic_count, ns.connected_capacity, ns.boundaries.len * @sizeOf(p.Boundary), ns.offsets.len * @sizeOf([p.kind_count]u16), ns.subscriptions.len * 8, ns.allocatedBytes(), configured_bytes });
}

fn startup(a: std.mem.Allocator) !void {
    const boundaries = @import("topic_policy_test.zig").hoodi();
    var g = try Gossipsub.init(a, options(&boundaries));
    defer g.deinit();
    try std.testing.expectEqual(@as(u16, 784), g.namespace.?.topic_count);
}

test "topic policy remembered ordinals remain independent of retained validation generations" {
    var boundaries: [4]p.Boundary = undefined;
    for (&boundaries, 0..) |*b, i| b.* = @import("topic_policy_test.zig").full(.{ @intCast(i + 1), 2, 3, 4 });
    var g = try Gossipsub.init(std.testing.allocator, options(&boundaries));
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    g.namespace.?.setSubscription(peer.index, 0, true);
    try std.testing.expect(g.subscribe(name));
    const old = g.state.findTopic(name).?;
    const generation = g.state.topics[old].generation;
    const context: validation.Context = .{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .store = &g.store, .history = &g.mcache, .seen = &g.seen, .options = &g.options, .namespace = &g.namespace.? };
    var work: usize = 10000;
    var peer_work: usize = 0;
    var large_used = false;
    const workspace: validation.Workspace = .{ .arena = g.decompressed, .used = &g.decompressed_used, .peer_work = &peer_work, .work = &work, .large_used = &large_used, .event_available = true };
    var compressed: [64]u8 = undefined;
    const len = try @import("snappy").raw.compress("0123456789", &compressed);
    const received = g.validation.receive(&context, &workspace, peer.index, .{ .topic = name, .data = compressed[0..len] }, 1).admitted;
    try std.testing.expect(g.unsubscribe(name));
    g.io.peers[peer.index].subscription_dirty.unset(old);
    var buffer: [@import("topic.zig").topic_max_len]u8 = undefined;
    for (0..511) |i| {
        const next = try std.fmt.bufPrint(&buffer, "/eth2/{x:0>2}020304/data_column_sidecar_{d}/ssz_snappy", .{ i / 128 + 1, i % 128 });
        try std.testing.expect(g.subscribe(next));
    }
    const replacement = "/eth2/04020304/data_column_sidecar_127/ssz_snappy";
    try std.testing.expectError(error.TopicCapacity, g.configureTopic(replacement, &.{}));
    try std.testing.expectEqual(generation, g.state.topics[old].generation);
    try std.testing.expectEqualStrings(name, received.topic);
    try std.testing.expectEqualStrings("0123456789", received.bytes);
    try std.testing.expectEqual(gossip.ReportOutcome{ .applied = .ignore }, g.report(received.handle, .ignore, .{ .mono_ms = 2, .unix_s = 0 }));
    try std.testing.expectError(error.TopicCapacity, g.configureTopic(replacement, &.{}));
    g.validation.expire(&g.store, &g.peers, 100000);
    try g.configureTopic(replacement, &.{});
    try std.testing.expectEqual(old, g.state.findTopic(replacement).?);
    try std.testing.expectEqual(generation + 1, g.state.topics[old].generation);
    try std.testing.expectEqual(@as(usize, 0), g.state.subscribers(old).count());
    try std.testing.expect(g.namespace.?.subscribed(peer.index, 0));
    try std.testing.expectEqualStrings(name, received.topic);
    try std.testing.expectEqualStrings("0123456789", received.bytes);
}
