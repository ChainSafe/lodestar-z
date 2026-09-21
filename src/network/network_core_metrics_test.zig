const std = @import("std");
const core = @import("network_core.zig");
const metrics = @import("metrics/export.zig");
const policy = @import("gossipsub/topic_policy.zig");
const protocol = @import("reqresp/root.zig").Protocol;

const Fixture = struct {
    node: *core.NetworkCore,
    buffer: []u8,

    fn init(boundaries: []const policy.Boundary) !Fixture {
        const node = try std.testing.allocator.create(core.NetworkCore);
        errdefer std.testing.allocator.destroy(node);
        const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{93}));
        var options = @import("test_support.zig").networkOptions(&key);
        options.core.service.gossipsub.topic_policy = if (boundaries.len > 0) boundaries else null;
        try node.initRaw(std.testing.allocator, std.testing.io, options);
        errdefer node.deinit(std.testing.io);
        const buffer = try std.testing.allocator.alloc(u8, metrics.textCapacity(boundaries));
        return .{ .node = node, .buffer = buffer };
    }

    fn deinit(self: *Fixture) void {
        std.testing.allocator.free(self.buffer);
        self.node.deinit(std.testing.io);
        std.testing.allocator.destroy(self.node);
    }

    fn render(self: *Fixture, running: bool) ![]const u8 {
        var context = metrics.Context.init(self.node, .{ .mono_ms = 2500, .unix_s = 123456 }, running);
        context.expired_executing = if (running) 3 else 0;
        context.oldest_expired_execution_age_ms = if (running) 1500 else 0;
        var writer = std.Io.Writer.fixed(self.buffer);
        try metrics.write(&context, &writer);
        var encoder: metrics.registry.Encoder = .{ .writer = &writer };
        const logs: @import("logging.zig").Stats = .{};
        try logs.write(&encoder);
        return writer.buffered();
    }
};

fn contains(text: []const u8, expected: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, text, expected) != null);
}

fn boundary(digest: [4]u8, epoch: u64) policy.Boundary {
    var value = @import("gossipsub/topic_fixture.zig").full(digest);
    value.fork = .fulu;
    value.epoch = epoch;
    return value;
}

test "metrics read owner counters exactly and preserve totals and capacities after shutdown" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const node = f.node;
    node.counters.dial_started = std.math.maxInt(u64);
    node.peer_manager.requested_connect = 17;
    node.peer_manager.requested_disconnect[0] = 3;
    node.service.reqresp.protocol_counters[@intFromEnum(protocol.status_v1)].outgoing = 4;
    node.service.reqresp.protocol_counters[@intFromEnum(protocol.status_v2)].outgoing = 5;
    node.service.reqresp.protocol_counters[@intFromEnum(protocol.status_v1)].outgoing_time.observe(100);
    node.service.reqresp.protocol_counters[@intFromEnum(protocol.status_v2)].outgoing_time.observe(200);
    node.service.reqresp.counters.withheld_ms_total = 1500;
    node.service.gossipsub.messages.storage_refusals[0] = 11;
    node.peer_manager.selection.dial_budget = 7;
    const original = node.peer_manager.counters;
    const output = try f.render(true);
    try contains(output, "lodestar_native_network_dial_started_total 18446744073709551615\n");
    try contains(output, "# TYPE lodestar_peers_requested_total_to_connect counter\n");
    try contains(output, "lodestar_peers_requested_total_to_connect 17\n");
    try contains(output, "lodestar_native_peer_dials_requested 7\n");
    try contains(output, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n");
    try contains(output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method=\"status\"} 2\n");
    try contains(output, "lodestar_native_reqresp_withheld_seconds_total 1.5\n");
    try contains(output, "lodestar_native_gossip_expired_executing 3\n");
    try contains(output, "lodestar_native_gossip_oldest_expired_execution_age_seconds 1.5\n");
    try contains(output, "lodestar_native_network_metrics_updated_timestamp_seconds 123456\n");
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_peer_manager_starved_bool") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_total_dial_attempts") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "_total_total") == null);
    _ = try f.render(true);
    try std.testing.expectEqualDeep(original, node.peer_manager.counters);
    try std.testing.expectEqual(@as(u64, 17), node.peer_manager.requested_connect);
    const stopped = try f.render(false);
    try contains(stopped, "lodestar_native_network_running 0\n");
    try contains(stopped, "lodestar_native_peer_dials_requested 0\n");
    try contains(stopped, "lodestar_peers_requested_total_to_connect 17\n");
    try contains(stopped, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n");
    try contains(stopped, "lodestar_native_quic_connections_capacity 4\n");
    try contains(stopped, "lodestar_native_gossip_expired_executing 0\n");
}

test "metrics include remote subscriptions without overlay rows and follow local fork boundary visibility" {
    var f = try Fixture.init(&.{ boundary(@splat(0), 100), boundary(@splat(1), 200) });
    defer f.deinit();
    const g = f.node.service.gossipsub;
    const ns = &g.overlay.namespace.?;
    const name = "/eth2/00000000/data_column_sidecar_9/ssz_snappy";
    const current = ns.lookup(name).?.ordinal;
    ns.setSubscription(0, current, true);
    ns.setSubscription(0, current, true);
    try std.testing.expect(g.overlay.findTopic(name) == null);
    try std.testing.expectEqual(@as(usize, 1), g.resourceSnapshot().remote_subscriptions);
    var output = try f.render(true);
    try contains(output, "lodestar_gossip_topic_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 1\n");
    try contains(output, "lodestar_gossip_mesh_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try contains(output, "lodestar_native_gossip_subscriptions_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try contains(output, "lodestar_gossip_topic_peers_by_beacon_attestation_subnet_count{subnet=\"00\",boundary=\"fulu_100\"} 0\n");
    try std.testing.expect(std.mem.indexOf(u8, output, "fulu_200") == null);
    const future = "/eth2/01010101/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(future));
    output = try f.render(true);
    try contains(output, "lodestar_gossip_mesh_peers_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 0\n");
    try contains(output, "lodestar_native_gossip_subscriptions_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 1\n");
    try std.testing.expect(g.unsubscribe(future));
    output = try f.render(true);
    try std.testing.expect(std.mem.indexOf(u8, output, "fulu_200") == null);
    ns.clearPeer(0);
    ns.clearPeer(0);
    output = try f.render(true);
    try contains(output, "lodestar_gossip_topic_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try std.testing.expectEqual(@as(usize, 0), g.resourceSnapshot().remote_subscriptions);
}

test "metrics maximum configured topic domain fits its startup exposition reservation" {
    var boundaries: [policy.boundary_max]policy.Boundary = undefined;
    for (&boundaries, 0..) |*value, index| value.* = boundary(.{ @intCast(index), 0, 0, 0 }, std.math.maxInt(u64) - index);
    var f = try Fixture.init(&boundaries);
    defer f.deinit();
    const g = f.node.service.gossipsub;
    for (boundaries) |value| {
        var name: [@import("gossipsub/topic.zig").topic_max_len]u8 = undefined;
        try std.testing.expect(g.subscribe(@import("gossipsub/topic.zig").build(value.digest, "beacon_block", &name)));
    }
    f.node.counters.dial_started = std.math.maxInt(u64);
    const output = try f.render(true);
    try std.testing.expect(output.len < f.buffer.len);
    try std.testing.expectEqual(@as(usize, 64 * 128), std.mem.count(u8, output, "lodestar_gossip_topic_peers_by_data_column_subnet_count{subnet="));
    try contains(output, "boundary=\"fulu_18446744073709551615\"");
}

test "metrics preserve outgoing queue refusals across session retirement and reuse" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const g = f.node.service.gossipsub;
    const support = @import("gossipsub/test_support.zig");
    const first = support.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    g.sessions.rows[first.index].io.tx.drops[0] = 3;
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 3\n");
    const conn = g.sessions.rows[first.index].conn;
    g.connectionClosed(conn);
    g.connectionClosed(conn);
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 3\n");
    const next = support.addPeer(g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    try std.testing.expectEqual(first.index, next.index);
    g.sessions.rows[next.index].io.tx.drops[0] = 2;
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 5\n");
    g.connectionClosed(g.sessions.rows[next.index].conn);
    try contains(try f.render(false), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 5\n");
}

test "metrics use retained usable coverage and accepted demand until replacement or shutdown" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const manager = &f.node.peer_manager;
    manager.local.fork.custody_groups = 128;
    manager.demand = .{ .attnets = 3, .syncnets = 1, .attestation_target = 2, .sync_target = 1 };
    manager.demand.group_targets[0] = 2;
    const selection = @import("peers/policy.zig");
    var inputs = [_]selection.Input{ .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true }, .{ .coverage = .{ .attnets = 3 }, .reject = .banned } };
    inputs[0].coverage.groups.set(0);
    manager.selection = selection.select(&inputs, &manager.demand, .{ .target_peers = 8, .max_peers = 12 }, 0);
    const output = try f.render(true);
    try contains(output, "lodestar_peer_count_per_sampling_group{groupIndex=\"0\"} 1\n");
    try contains(output, "lodestar_peer_count_per_sampling_group{groupIndex=\"127\"} 0\n");
    try contains(output, "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 3\n");
    try contains(output, "lodestar_native_peers_per_active_subnet_count{type=\"attnets\"} 2\n");
    try contains(output, "lodestar_native_peer_disconnects_requested{reason=\"banned\"} 1\n");
    try contains(try f.render(false), "lodestar_native_peers_per_active_subnet_count{type=\"attnets\"} 0\n");
    try contains(try f.render(true), "lodestar_native_peers_per_active_subnet_count{type=\"attnets\"} 2\n");
    try manager.setDemand(&.{});
    manager.selection = .{};
    try contains(try f.render(true), "lodestar_native_peers_per_active_subnet_count{type=\"attnets\"} 0\n");
}
