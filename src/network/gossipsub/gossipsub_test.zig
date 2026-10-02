const support = @import("test_support.zig");
const std = @import("std");
const topic_mod = @import("topic.zig");
const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
const Pair = @import("test_pair.zig").Pair;
const constants_heartbeat = @import("constants.zig").heartbeat_interval_ms;

fn buildTopic(name: []const u8, out: []u8) []const u8 {
    return topic_mod.build(digest, name, out);
}

test "gossipsub peers exchange subscriptions over the mesh streams" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try support.subscribe(setup.shared.client.gossipsub, beacon_block);
    try support.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 20) : (rounds += 1) {
        try setup.pumpOnce();
    }

    // each side now records the other as a subscriber of the topic
    const server_topic = setup.shared.server.gossipsub.overlay.findTopic(beacon_block).?;
    try std.testing.expect(setup.shared.server.gossipsub.overlay.subscribers(server_topic).count() == 1);
}

test "gossipsub forms a mesh through the heartbeat" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try support.subscribe(setup.shared.client.gossipsub, beacon_block);
    try support.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const client_topic = setup.shared.client.gossipsub.overlay.findTopic(beacon_block).?;
    const server_topic = setup.shared.server.gossipsub.overlay.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.gossipsub.overlay.mesh(client_topic).count());
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.gossipsub.overlay.mesh(server_topic).count());
}

test "gossipsub delivers a published message to a mesh peer" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try support.subscribe(setup.shared.client.gossipsub, beacon_block);
    try support.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a signed beacon block payload for the mesh";
    _ = try setup.shared.client.gossipsub.publish(beacon_block, payload, setup.shared.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| {
            try std.testing.expectEqualStrings(beacon_block, m.topic);
            try std.testing.expectEqualStrings(payload, m.bytes);
            _ = setup.shared.server.gossipsub.report(m.handle, .accept, setup.shared.pair.now);
            received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.server.gossipsub.topic_metrics.get(beacon_block).accepted);
}

test "gossipsub subscription cursors synchronize all topics through small critical queues" {
    const topic_capacity = @import("constants.zig").topics_cap;
    const topics = &@import("topic_fixture.zig").churn;
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .topic_policy = topics, .critical_bytes = 256, .control_bytes = 64 }, .{ .random_seed = 1, .topic_policy = topics, .critical_bytes = 256, .control_bytes = 64 });
    defer setup.deinit();
    var buf: [topic_mod.topic_max_len]u8 = undefined;
    for (0..topic_capacity) |i| {
        const topic = try @import("topic_fixture.zig").churnTopic(i, &buf);
        try support.subscribe(setup.shared.client.gossipsub, topic);
        try support.subscribe(setup.shared.server.gossipsub, topic);
    }
    for (0..128) |_| try setup.pumpOnce();
    const peer = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    @import("session_io.zig").resetOutbound(setup.shared.client.gossipsub, &setup.shared.pair.client, peer);
    setup.shared.client.gossipsub.sessions.setOutbound(peer, .pending);
    for (0..128) |_| try setup.pumpOnce();
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expect(support.sessionWakeup(setup.shared.client.gossipsub, setup.shared.pair.now) > setup.shared.pair.now.mono_ms);
}
