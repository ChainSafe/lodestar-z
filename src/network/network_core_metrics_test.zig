const Now = @import("types.zig").Now;
const core_test = @import("network_core_test_support.zig");
const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const NetworkCore = @import("network_core.zig").NetworkCore;
const metrics = @import("metrics/export.zig");
const policy = @import("gossipsub/topic_policy.zig");
const protocol = @import("reqresp/root.zig").Protocol;
const KeyPair = @import("wire/keys.zig").KeyPair;
const logging = @import("logging.zig");
const types = @import("peers/types.zig");
const topic_mod = @import("gossipsub/topic.zig");
const Sockets = @import("udp").Sockets;
const score = @import("gossipsub/score.zig");
const topic_fixture = @import("gossipsub/topic_fixture.zig");
const test_support = @import("quic/test_support.zig");
const time = @import("time.zig");
const Dialing = @import("peers/dialing.zig").Dialing;

const Fixture = struct {
    node: *NetworkCore,
    buffer: []u8,

    fn init(boundaries: []const policy.Boundary) !Fixture {
        return initWith(boundaries, null);
    }

    fn initWith(boundaries: []const policy.Boundary, discovery: ?NetworkCore.DiscoveryOptions) !Fixture {
        const node = try std.testing.allocator.create(NetworkCore);
        errdefer std.testing.allocator.destroy(node);
        const key = try KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{93}));
        var options = core_test.networkOptions(&key);
        if (boundaries.len > 0) options.resolved.core.protocols.gossipsub.topic_policy = boundaries;
        options.startup.discovery = discovery;
        try node.init(std.testing.allocator, std.testing.io, &options.resolved, options.startup);
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
        var context = metrics.Context.init(self.node, Now.fromMilliseconds(.{ .mono_ms = 2500, .unix_s = 123456 }), running);
        context.expired_executing = if (running) 3 else 0;
        var writer = std.Io.Writer.fixed(self.buffer);
        try metrics.write(&context, &writer);
        var encoder: metrics.registry.Encoder = .{ .writer = &writer };
        const logs: logging.Stats = .{};
        try logs.write(&encoder);
        return writer.buffered();
    }
};

fn contains(text: []const u8, expected: []const u8) !void {
    try std.testing.expect(std.mem.find(u8, text, expected) != null);
}

const Series = struct {
    name: []const u8,
    kind: []const u8,
    labels: []const []const u8 = &.{},
};

/// The measurement contract: exactly the native families the durable metrics manifest keeps, which
/// the feat4 scorecard reads. Adding, removing or renaming one needs the same change in that manifest.
const contract = [_]Series{
    // Peers
    .{ .name = "libp2p_peers", .kind = "gauge" },
    .{ .name = "lodestar_native_network_relevant_peers", .kind = "gauge" },
    .{ .name = "lodestar_native_peer_below_target", .kind = "gauge" },
    .{ .name = "lodestar_peers_by_direction_count", .kind = "gauge", .labels = &.{"direction"} },
    .{ .name = "lodestar_peers_by_client_count", .kind = "gauge", .labels = &.{"client"} },
    .{ .name = "lodestar_peer_connection_seconds", .kind = "histogram" },
    .{ .name = "lodestar_peer_connected_total", .kind = "counter", .labels = &.{ "direction", "status" } },
    .{ .name = "lodestar_peer_goodbye_received_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_closes_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_health_failures_total", .kind = "counter", .labels = &.{"probe"} },
    .{ .name = "lodestar_native_peer_rejections_total", .kind = "counter", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_peer_dial_selections_total", .kind = "counter", .labels = &.{"source"} },
    .{ .name = "lodestar_native_peer_dial_outcomes_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_peer_dial_time_seconds", .kind = "histogram", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_peer_dial_retries_total", .kind = "counter", .labels = &.{"previous"} },
    .{ .name = "lodestar_native_dial_recent_failures_refused_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_dial_funnel_total", .kind = "counter", .labels = &.{ "origin", "stage" } },
    .{ .name = "lodestar_native_remembered_peers", .kind = "gauge" },
    .{ .name = "lodestar_native_remembered_peer_seeds_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_remembered_peer_replays_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_peer_outbound_deficit", .kind = "gauge" },
    .{ .name = "lodestar_discovery_subnet_peers_to_connect", .kind = "gauge", .labels = &.{"type"} },
    .{ .name = "lodestar_discovery_custody_group_peers_to_connect", .kind = "gauge" },
    .{ .name = "lodestar_peer_count_per_sampling_group", .kind = "gauge", .labels = &.{"groupIndex"} },
    // Discovery
    .{ .name = "lodestar_discv5_kad_table_size", .kind = "gauge" },
    .{ .name = "lodestar_discv5_active_session_count", .kind = "gauge" },
    .{ .name = "lodestar_native_discovery_lookups_started_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_lookup_finishes_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_discovery_candidates_published_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_candidate_rejections_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_discovery_datagram_rejections_total", .kind = "counter", .labels = &.{ "stage", "reason" } },
    // Gossip
    .{ .name = "gossipsub_mesh_peer_count", .kind = "gauge", .labels = &.{"topicStr"} },
    .{ .name = "gossipsub_topic_peer_count", .kind = "gauge", .labels = &.{"topicStr"} },
    .{ .name = "lodestar_gossip_mesh_peers_by_type_count", .kind = "gauge", .labels = &.{ "type", "boundary" } },
    .{ .name = "lodestar_gossip_mesh_peers_by_beacon_attestation_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_gossip_mesh_peers_by_sync_committee_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_gossip_mesh_peers_by_data_column_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_gossip_topic_peers_by_type_count", .kind = "gauge", .labels = &.{ "type", "boundary" } },
    .{ .name = "lodestar_gossip_topic_peers_by_beacon_attestation_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_gossip_topic_peers_by_sync_committee_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_gossip_topic_peers_by_data_column_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_native_gossip_subscriptions_by_type_count", .kind = "gauge", .labels = &.{ "type", "boundary" } },
    .{ .name = "lodestar_native_gossip_subscriptions_by_beacon_attestation_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_native_gossip_subscriptions_by_sync_committee_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "lodestar_native_gossip_subscriptions_by_data_column_subnet_count", .kind = "gauge", .labels = &.{ "subnet", "boundary" } },
    .{ .name = "gossipsub_accepted_messages_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "gossipsub_rejected_messages_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "gossipsub_ignored_messages_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "gossipsub_msg_forward_count_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "lodestar_native_gossip_data_recipients_total", .kind = "counter", .labels = &.{ "origin", "outcome" } },
    .{ .name = "lodestar_native_gossip_queue_drops_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossip_retention_refusals_total", .kind = "counter", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_gossip_iwant_ids_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "gossipsub_iwant_promise_broken", .kind = "counter" },
    .{ .name = "lodestar_native_gossip_iwant_promises_started_total", .kind = "counter" },
    .{ .name = "lodestar_native_gossip_messages_received_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "lodestar_native_gossip_messages_duplicate_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "lodestar_native_gossip_messages_published_total", .kind = "counter", .labels = &.{"topic"} },
    .{ .name = "lodestar_native_gossip_mesh_changes_total", .kind = "counter", .labels = &.{ "topic", "event", "reason" } },
    .{ .name = "lodestar_native_gossip_behaviour_penalties_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossip_score_peers", .kind = "gauge", .labels = &.{ "scope", "threshold" } },
    .{ .name = "lodestar_native_gossip_score", .kind = "gauge", .labels = &.{ "scope", "stat" } },
    // Gossip processor
    .{ .name = "lodestar_native_gossip_processor_items", .kind = "gauge", .labels = &.{ "kind", "state" } },
    .{ .name = "lodestar_native_gossip_processor_execution_credit_limit", .kind = "gauge", .labels = &.{ "kind", "credit" } },
    .{ .name = "lodestar_native_gossip_processor_refusals_total", .kind = "counter", .labels = &.{ "kind", "reason" } },
    .{ .name = "lodestar_native_gossip_expired_executing", .kind = "gauge" },
    .{ .name = "gossipsub_async_validation_delay_from_first_seen", .kind = "histogram" },
    // ReqResp
    .{ .name = "beacon_reqresp_incoming_requests_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_incoming_requests_error_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_incoming_request_handler_time_seconds", .kind = "histogram", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_outgoing_requests_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_outgoing_requests_error_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_outgoing_requests_error_reason_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "beacon_reqresp_outgoing_request_roundtrip_time_seconds", .kind = "histogram", .labels = &.{"method"} },
    .{ .name = "lodestar_native_reqresp_resources_serving_occupied", .kind = "gauge" },
    .{ .name = "lodestar_native_reqresp_resources_serving_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_reqresp_resources_retiring", .kind = "gauge" },
    .{ .name = "lodestar_native_reqresp_inbound_occupied", .kind = "gauge", .labels = &.{"phase"} },
    .{ .name = "lodestar_native_reqresp_admission_refusals_total", .kind = "counter", .labels = &.{ "method", "reason" } },
    // Transport and UDP
    .{ .name = "lodestar_native_quic_connections_established_total", .kind = "counter", .labels = &.{"direction"} },
    .{ .name = "lodestar_native_quic_connections_closed_total", .kind = "counter", .labels = &.{ "direction", "reason" } },
    .{ .name = "lodestar_native_quic_connections_active", .kind = "gauge" },
    .{ .name = "lodestar_native_quic_connections_handshaking", .kind = "gauge" },
    .{ .name = "lodestar_native_quic_udp_received_bytes_total", .kind = "counter" },
    .{ .name = "lodestar_native_quic_udp_sent_bytes_total", .kind = "counter" },
    .{ .name = "lodestar_native_quic_udp_received_datagrams_total", .kind = "counter" },
    .{ .name = "lodestar_native_quic_udp_sent_datagrams_total", .kind = "counter" },
    .{ .name = "lodestar_native_udp_send_dropped_datagrams_total", .kind = "counter", .labels = &.{ "role", "reason" } },
    .{ .name = "lodestar_native_udp_send_dropped_bytes_total", .kind = "counter", .labels = &.{ "role", "reason" } },
    .{ .name = "lodestar_native_udp_socket_drops_total", .kind = "counter", .labels = &.{ "role", "family" } },
    .{ .name = "lodestar_native_udp_socket_buffer_bytes", .kind = "gauge", .labels = &.{ "role", "family", "direction" } },
    // Owner and resources
    .{ .name = "lodestar_native_network_step_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_network_running", .kind = "gauge" },
    .{ .name = "lodestar_native_network_metrics_updated_timestamp_seconds", .kind = "gauge" },
    .{ .name = "lodestar_native_network_transport_failures_total", .kind = "counter" },
    .{ .name = "lodestar_native_network_readiness_failures_total", .kind = "counter" },
    .{ .name = "lodestar_native_logs_dropped_total", .kind = "counter", .labels = &.{ "level", "scope" } },
    .{ .name = "lodestar_native_gossipsub_storage_refusals_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossipsub_pending_validations", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_validation_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_queued_bytes", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_delivery_descriptors_available", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_delivery_descriptors_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_receive_pages", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_receive_page_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_gossipsub_store_pages", .kind = "gauge" },
};

fn hasSeries(output: []const u8, series: Series) bool {
    var buffer: [256]u8 = undefined;
    const type_line = std.fmt.bufPrint(&buffer, "# TYPE {s} {s}\n", .{ series.name, series.kind }) catch return false;
    if (std.mem.find(u8, output, type_line) == null) return false;
    const labels = sampleLabels(output, series.name, std.mem.eql(u8, series.kind, "histogram")) orelse return false;
    for (series.labels) |label| if (!hasLabel(labels, label)) return false;
    return true;
}

fn sampleLabels(output: []const u8, name: []const u8, histogram: bool) ?[]const u8 {
    const suffix = if (histogram) "_bucket" else "";
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, name)) continue;
        const rest = line[name.len..];
        if (!std.mem.startsWith(u8, rest, suffix)) continue;
        const after = rest[suffix.len..];
        if (std.mem.startsWith(u8, after, " ")) return "";
        if (std.mem.startsWith(u8, after, "{")) return after[0 .. std.mem.findScalar(u8, after, '}') orelse after.len];
    }
    return null;
}

fn hasLabel(labels: []const u8, label: []const u8) bool {
    var start: usize = 0;
    while (std.mem.findPos(u8, labels, start, label)) |at| {
        const opens = at > 0 and (labels[at - 1] == '{' or labels[at - 1] == ',');
        if (opens and std.mem.startsWith(u8, labels[at + label.len ..], "=\"")) return true;
        start = at + 1;
    }
    return false;
}

fn boundary(digest: [4]u8, epoch: u64) policy.Boundary {
    var value = topic_fixture.full(digest);
    value.fork = .fulu;
    value.epoch = epoch;
    return value;
}

test "metrics read owner counters exactly and preserve totals and capacities after shutdown" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const node = f.node;
    node.counters.transport_failures = std.math.maxInt(u64);
    node.peer_manager.control.counters.closed[0] = 17;
    node.protocols.reqresp.protocol_counters[@intFromEnum(protocol.status_v1)].outgoing = 4;
    node.protocols.reqresp.protocol_counters[@intFromEnum(protocol.status_v2)].outgoing = 5;
    node.protocols.reqresp.protocol_counters[@intFromEnum(protocol.status_v1)].outgoing_time.observe(100);
    node.protocols.reqresp.protocol_counters[@intFromEnum(protocol.status_v2)].outgoing_time.observe(200);
    node.protocols.gossipsub.messages.storage_refusals[0] = 11;
    node.peer_manager.selection.deficits.outbound = 7;
    const original = node.peer_manager.counters;
    const output = try f.render(true);
    try contains(output, "lodestar_native_network_transport_failures_total 18446744073709551615\n");
    const closed = @tagName(@as(types.DisconnectReason, @enumFromInt(0)));
    var line: [128]u8 = undefined;
    const closes = try std.fmt.bufPrint(&line, "lodestar_native_peer_closes_total{{reason=\"{s}\"}} 17\n", .{closed});
    try contains(output, closes);
    try contains(output, "lodestar_native_peer_outbound_deficit 7\n");
    try contains(output, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n");
    try contains(output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method=\"status\"} 2\n");
    try contains(output, "lodestar_native_gossip_expired_executing 3\n");
    try contains(output, "lodestar_native_network_metrics_updated_timestamp_seconds 123456\n");
    try std.testing.expect(std.mem.find(u8, output, "lodestar_peer_manager_starved_bool") == null);
    try std.testing.expect(std.mem.find(u8, output, "lodestar_discovery_total_dial_attempts") == null);
    try std.testing.expect(std.mem.find(u8, output, "_total_total") == null);
    _ = try f.render(true);
    try std.testing.expectEqualDeep(original, node.peer_manager.counters);
    const stopped = try f.render(false);
    try contains(stopped, "lodestar_native_network_running 0\n");
    try contains(stopped, "lodestar_native_peer_outbound_deficit 0\n");
    try contains(stopped, closes);
    try contains(stopped, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n");
    try contains(stopped, "lodestar_native_gossip_expired_executing 0\n");
}

test "metrics include remote subscriptions on inactive topics and follow local fork boundary visibility" {
    var f = try Fixture.init(&.{ boundary(@splat(0), 100), boundary(@splat(1), 200) });
    defer f.deinit();
    const g = f.node.protocols.gossipsub;
    const peer = gossip_test.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const context = g.overlayContext(g.last_now_ms);
    const name = "/eth2/00000000/data_column_sidecar_9/ssz_snappy";
    _ = g.overlay.peerSubscription(&context, peer.index, name, true);
    _ = g.overlay.peerSubscription(&context, peer.index, name, true);
    try std.testing.expect(g.overlay.findTopic(name) == null);
    try std.testing.expectEqual(@as(usize, 1), g.resourceSnapshot().remote_subscriptions);
    var output = try f.render(true);
    try contains(output, "lodestar_gossip_topic_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 1\n");
    try contains(output, "lodestar_gossip_mesh_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try contains(output, "lodestar_native_gossip_subscriptions_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try contains(output, "lodestar_gossip_topic_peers_by_beacon_attestation_subnet_count{subnet=\"00\",boundary=\"fulu_100\"} 0\n");
    try std.testing.expect(std.mem.find(u8, output, "fulu_200") == null);
    const future = "/eth2/01010101/beacon_block/ssz_snappy";
    try gossip_test.subscribe(g, future);
    output = try f.render(true);
    try contains(output, "lodestar_gossip_mesh_peers_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 0\n");
    try contains(output, "lodestar_native_gossip_subscriptions_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 1\n");
    try gossip_test.unsubscribe(g, future);
    output = try f.render(true);
    try std.testing.expect(std.mem.find(u8, output, "fulu_200") == null);
    const connection = g.sessions.rows[peer.index].conn;
    g.connectionClosed(connection);
    g.connectionClosed(connection);
    output = try f.render(true);
    try contains(output, "lodestar_gossip_topic_peers_by_data_column_subnet_count{subnet=\"9\",boundary=\"fulu_100\"} 0\n");
    try std.testing.expectEqual(@as(usize, 0), g.resourceSnapshot().remote_subscriptions);
}

test "metrics maximum configured topic domain fits its startup exposition reservation" {
    var boundaries: [policy.boundary_max]policy.Boundary = undefined;
    for (&boundaries, 0..) |*value, index| value.* = boundary(.{ @intCast(index), 0, 0, 0 }, std.math.maxInt(u64) - index);
    var f = try Fixture.init(&boundaries);
    defer f.deinit();
    const g = f.node.protocols.gossipsub;
    for (boundaries) |value| {
        var name: [topic_mod.topic_max_len]u8 = undefined;
        try gossip_test.subscribe(g, topic_mod.build(value.digest, "beacon_block", &name));
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
    const g = f.node.protocols.gossipsub;
    const first = gossip_test.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    g.sessions.rows[first.index].io.tx.drops[0] = 3;
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 3\n");
    const conn = g.sessions.rows[first.index].conn;
    g.connectionClosed(conn);
    g.connectionClosed(conn);
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 3\n");
    const next = gossip_test.addPeer(g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    try std.testing.expectEqual(first.index, next.index);
    g.sessions.rows[next.index].io.tx.drops[0] = 2;
    try contains(try f.render(true), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 5\n");
    g.connectionClosed(g.sessions.rows[next.index].conn);
    try contains(try f.render(false), "lodestar_native_gossip_queue_drops_total{reason=\"data_descriptors\"} 5\n");
}

test "metrics render retained usable coverage and suppress deficits when stopped" {
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
    try contains(try f.render(false), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 0\n");
    try contains(try f.render(true), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 3\n");
}

test "metrics follow demand replacement and owner shutdown" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const demand: types.Demand = .{ .attnets = 3, .attestation_target = 2 };
    try core_test.updateDemand(f.node, &demand, f.node.last_now);
    var result = f.node.advance(std.testing.io, .{ .now = f.node.last_now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(result.failure == null);
    try contains(try f.render(f.node.phase() == .running), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 4\n");

    try core_test.updateDemand(f.node, &.{}, f.node.last_now);
    result = f.node.advance(std.testing.io, .{ .now = f.node.last_now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(result.failure == null);
    try contains(try f.render(f.node.phase() == .running), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 0\n");

    try core_test.updateDemand(f.node, &demand, f.node.last_now);
    result = f.node.advance(std.testing.io, .{ .now = f.node.last_now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(result.failure == null);
    try contains(try f.render(f.node.phase() == .running), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 4\n");
    f.node.shutdown(f.node.last_now);
    result = f.node.advance(std.testing.io, .{ .now = f.node.last_now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(result.failure == null);
    try std.testing.expect(f.node.isClosed());
    try contains(try f.render(f.node.phase() == .running), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 0\n");
}

test "metrics render exactly the measurement contract families with their types and labels" {
    var f = try Fixture.initWith(&.{boundary(@splat(0), 100)}, .{ .bind = .{ .ip4 = .loopback(0) } });
    defer f.deinit();
    // A connected gossip peer gives the score statistics a population to sample.
    _ = gossip_test.addPeer(f.node.protocols.gossipsub, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const output = try f.render(true);
    var missing: usize = 0;
    for (contract) |series| {
        if (hasSeries(output, series)) continue;
        std.debug.print("measurement contract series missing or mistyped: {s} ({s})\n", .{ series.name, series.kind });
        missing += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), missing);
    var extra: usize = 0;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "# TYPE ")) continue;
        const name = line["# TYPE ".len..std.mem.findScalarLast(u8, line, ' ').?];
        for (contract) |series| {
            if (std.mem.eql(u8, series.name, name)) break;
        } else {
            std.debug.print("family outside the measurement contract: {s}\n", .{name});
            extra += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), extra);
}

test "metrics report the kernel's buffer sizes and drops for every UDP socket" {
    var f = try Fixture.initWith(&.{}, .{ .bind = .{ .ip4 = .loopback(0) } });
    defer f.deinit();
    const output = try f.render(true);
    const roles = [_]struct { []const u8, *Sockets }{
        .{ "quic", &f.node.transport.sockets },
        .{ "discovery", &f.node.discovery.?.transport.sockets },
    };
    var line: [160]u8 = undefined;
    for (roles) |role| {
        const reported = role[1].buffers[0].?;
        try std.testing.expect(reported.receive.? > 0 and reported.send.? > 0);
        try contains(output, try std.fmt.bufPrint(&line, "lodestar_native_udp_socket_buffer_bytes{{role=\"{s}\",family=\"ip4\",direction=\"receive\"}} {d}\n", .{ role[0], reported.receive.? }));
        try contains(output, try std.fmt.bufPrint(&line, "lodestar_native_udp_socket_buffer_bytes{{role=\"{s}\",family=\"ip4\",direction=\"send\"}} {d}\n", .{ role[0], reported.send.? }));
        // Linux kernels without SO_MEMINFO report no drop count.
        if (role[1].drops()[0] != null) try contains(output, try std.fmt.bufPrint(&line, "lodestar_native_udp_socket_drops_total{{role=\"{s}\",family=\"ip4\"}} 0\n", .{role[0]}));
    }
    try std.testing.expect(std.mem.find(u8, output, "family=\"ip6\"") == null);
    f.node.discovery.?.transport.sockets.buffers[0].?.receive = null;
    const unknown = try f.render(true);
    try std.testing.expect(std.mem.find(u8, unknown, "role=\"discovery\",family=\"ip4\",direction=\"receive\"") == null);
    try contains(unknown, "role=\"discovery\",family=\"ip4\",direction=\"send\"");
}

test "metrics label redials after a health close in the dial retries contract series" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    f.node.peer_manager.dialing.retries[@intFromEnum(types.DialFailure.health)] = 2;
    try contains(try f.render(true), "lodestar_native_peer_dial_retries_total{previous=\"health\"} 2\n");
}

test "metrics export dial time by outcome in seconds through shutdown" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const dialing = &f.node.peer_manager.dialing;
    const connected = @intFromEnum(types.DialOutcome.connected);
    dialing.durations[connected].observe(180);
    dialing.outcomes[connected] = 1;
    for ([_]bool{ true, false }) |running| {
        const output = try f.render(running);
        try contains(output, "# TYPE lodestar_native_peer_dial_time_seconds histogram\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_bucket{outcome=\"connected\",le=\"0.1\"} 0\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_bucket{outcome=\"connected\",le=\"0.25\"} 1\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_bucket{outcome=\"connected\",le=\"+Inf\"} 1\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_sum{outcome=\"connected\"} 0.18\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_count{outcome=\"connected\"} 1\n");
        try contains(output, "lodestar_native_peer_dial_time_seconds_count{outcome=\"expired\"} 0\n");
    }
}

test "metrics export cumulative discovery lookups and datagram rejections" {
    var f = try Fixture.initWith(&.{}, .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{ .session_capacity = 8, .challenge_capacity = 8, .call_capacity = 8 } });
    defer f.deinit();
    const coordinator = f.node.discovery.?;
    coordinator.counters.lookups_started = 5;
    const d = @import("discv5");
    coordinator.datagram_rejections[@intFromEnum(d.types.RejectReason.invalid_handshake)] = 3;
    _ = coordinator.consume(&.{ .datagram = .{ .rejected = .record_admission_limited } }, &.{}, &.{});
    _ = coordinator.consume(&.{ .datagram = .{ .rejected = .admission_limited } }, &.{}, &.{});
    const output = try f.render(true);
    try contains(output, "lodestar_native_discovery_lookups_started_total 5\n");
    try contains(output, "lodestar_native_discovery_datagram_rejections_total{stage=\"handshake\",reason=\"invalid_handshake\"} 3\n");
    try contains(output, "lodestar_native_discovery_datagram_rejections_total{stage=\"record\",reason=\"record_admission_limited\"} 1\n");
    try contains(output, "lodestar_native_discovery_datagram_rejections_total{stage=\"admission\",reason=\"admission_limited\"} 1\n");
    try contains(output, "lodestar_native_discovery_datagram_rejections_total{stage=\"record\",reason=\"invalid_record\"} 0\n");
    try contains(try f.render(false), "lodestar_native_discovery_lookups_started_total 5\n");
}

test "metrics export stock per-topic gossipsub peer gauges under full topic strings" {
    var f = try Fixture.init(&.{ boundary(@splat(0), 100), boundary(@splat(1), 200) });
    defer f.deinit();
    const g = f.node.protocols.gossipsub;
    const peer = gossip_test.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const context = g.overlayContext(g.last_now_ms);
    const column = "/eth2/00000000/data_column_sidecar_9/ssz_snappy";
    _ = g.overlay.peerSubscription(&context, peer.index, column, true);
    var output = try f.render(true);
    try contains(output, "# TYPE gossipsub_topic_peer_count gauge\n");
    try contains(output, "gossipsub_topic_peer_count{topicStr=\"" ++ column ++ "\"} 1\n");
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"" ++ column ++ "\"} 0\n");
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"/eth2/00000000/beacon_attestation_63/ssz_snappy\"} 0\n");
    try std.testing.expectEqual(@as(usize, 333), std.mem.count(u8, output, "gossipsub_topic_peer_count{topicStr=\"/eth2/00000000/"));
    try std.testing.expect(std.mem.find(u8, output, "/eth2/01010101/") == null);
    const future = "/eth2/01010101/beacon_block/ssz_snappy";
    try gossip_test.subscribe(g, future);
    output = try f.render(true);
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"" ++ future ++ "\"} 0\n");
}

test "metrics export gossip score populations only while running and omit empty statistics" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const g = f.node.protocols.gossipsub;
    _ = gossip_test.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    gossip_test.penalize(g, g.sessions.rows[0].conn, 7);
    const running = try f.render(true);
    try contains(running, "lodestar_native_gossip_score_peers{scope=\"connected\",threshold=\"all\"} 1\n");
    try contains(running, "lodestar_native_gossip_score_peers{scope=\"connected\",threshold=\"nonnegative\"} 0\n");
    try contains(running, "lodestar_native_gossip_score_peers{scope=\"mesh\",threshold=\"all\"} 0\n");
    try contains(running, "lodestar_native_gossip_score{scope=\"connected\",stat=\"max\"} -10\n");
    try std.testing.expect(std.mem.find(u8, running, "lodestar_native_gossip_score{scope=\"mesh\"") == null);
    const stopped = try f.render(false);
    try contains(stopped, "lodestar_native_gossip_score_peers{scope=\"connected\",threshold=\"all\"} 0\n");
    try contains(stopped, "# TYPE lodestar_native_gossip_score gauge\n");
    try std.testing.expect(std.mem.find(u8, stopped, "lodestar_native_gossip_score{") == null);
}

test "metrics export gossip message, mesh change, penalty and promise counters through shutdown" {
    var f = try Fixture.init(&.{boundary(@splat(0), 100)});
    defer f.deinit();
    const g = f.node.protocols.gossipsub;
    const name = "/eth2/00000000/beacon_block/ssz_snappy";
    try gossip_test.subscribe(g, name);
    const peer = gossip_test.addPeer(g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = g.overlay.peerSubscription(&g.overlayContext(0), peer.index, name, true).?;
    g.overlay.onGraft(&g.overlayContext(0), topic, peer.index);
    const counts = &g.topic_metrics.counts[@intFromEnum(policy.Kind.beacon_block)];
    counts.received = 5;
    counts.duplicate = 2;
    g.topic_metrics.counts[policy.kind_count].published = std.math.maxInt(u64);
    g.peers.scores.penalties[@intFromEnum(score.Penalty.graft_flood)] = 6;
    g.recovery.armed = 9;
    const expected = [_][]const u8{
        "lodestar_native_gossip_messages_received_total{topic=\"beacon_block\"} 5\n",
        "lodestar_native_gossip_messages_duplicate_total{topic=\"beacon_block\"} 2\n",
        "lodestar_native_gossip_messages_published_total{topic=\"unknown\"} 18446744073709551615\n",
        "lodestar_native_gossip_messages_received_total{topic=\"data_column_sidecar\"} 0\n",
        "lodestar_native_gossip_mesh_changes_total{topic=\"beacon_block\",event=\"join\",reason=\"remote_graft\"} 1\n",
        "lodestar_native_gossip_mesh_changes_total{topic=\"unknown\",event=\"leave\",reason=\"refused_graft\"} 0\n",
        "lodestar_native_gossip_behaviour_penalties_total{reason=\"graft_flood\"} 6\n",
        "lodestar_native_gossip_behaviour_penalties_total{reason=\"large_frame_timeout\"} 0\n",
        "lodestar_native_gossip_iwant_promises_started_total 9\n",
    };
    const running = try f.render(true);
    for (expected) |line| try contains(running, line);
    try std.testing.expectEqual(@as(usize, (policy.kind_count + 1) * 12), std.mem.count(u8, running, "lodestar_native_gossip_mesh_changes_total{"));
    g.connectionClosed(g.sessions.rows[peer.index].conn);
    const stopped = try f.render(false);
    for (expected) |line| try contains(stopped, line);
    try contains(stopped, "lodestar_native_gossip_mesh_changes_total{topic=\"beacon_block\",event=\"leave\",reason=\"session_end\"} 1\n");
}

test "stopped metrics report all delivery descriptors available with zero occupancy" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const pool = f.node.protocols.gossipsub.sessions.deliveries;
    const capacity = pool.available;
    pool.available -= 1;
    defer pool.available = capacity;
    var line: [128]u8 = undefined;
    const running = try f.render(true);
    try contains(running, try std.fmt.bufPrint(&line, "lodestar_native_gossipsub_delivery_descriptors_available {d}\n", .{capacity - 1}));
    const stopped = try f.render(false);
    try contains(stopped, try std.fmt.bufPrint(&line, "lodestar_native_gossipsub_delivery_descriptors_capacity {d}\n", .{capacity}));
    try contains(stopped, try std.fmt.bufPrint(&line, "lodestar_native_gossipsub_delivery_descriptors_available {d}\n", .{capacity}));
    try contains(stopped, "lodestar_native_gossipsub_queued_bytes 0\n");
    try std.testing.expectEqual(capacity - 1, pool.available);
}

test "metrics expose local UDP send drops by role and pressure without clearing at stop" {
    var f = try Fixture.initWith(&.{}, .{ .bind = .{ .ip4 = .loopback(0) } });
    defer f.deinit();
    f.node.transport.send_drops.add(.would_block, 17);
    f.node.transport.send_drops.add(.would_block, 19);
    f.node.discovery.?.transport.send_drops.add(.system_resources, 23);
    for ([_]bool{ true, false }) |running| {
        const output = try f.render(running);
        try contains(output, "lodestar_native_udp_send_dropped_datagrams_total{role=\"quic\",reason=\"would_block\"} 2\n");
        try contains(output, "lodestar_native_udp_send_dropped_bytes_total{role=\"quic\",reason=\"would_block\"} 36\n");
        try contains(output, "lodestar_native_udp_send_dropped_datagrams_total{role=\"discovery\",reason=\"system_resources\"} 1\n");
        try contains(output, "lodestar_native_udp_send_dropped_bytes_total{role=\"discovery\",reason=\"system_resources\"} 23\n");
        try contains(output, "lodestar_native_udp_send_dropped_datagrams_total{role=\"quic\",reason=\"system_resources\"} 0\n");
        try contains(output, "lodestar_native_udp_send_dropped_datagrams_total{role=\"discovery\",reason=\"would_block\"} 0\n");
    }
}

test "core metrics aggregate subnets and count distinct mesh peers" {
    const full = @import("gossipsub/topic_fixture.zig").full;
    const pair = try std.testing.allocator.create(core_test.Setup);
    defer std.testing.allocator.destroy(pair);
    pair.* = .{};
    var opts = core_test.resolvedOptions();
    opts.core.protocols.gossipsub.topic_policy = &.{full(@splat(0))};
    try pair.initOwnersWithOptions(&.{}, opts);
    defer pair.deinit();
    var a_intent = core_test.intent(&pair.client, &.{});
    a_intent.subscriptions = topic_fixture.subscriptions(&.{ "/eth2/00000000/beacon_block/ssz_snappy", "/eth2/00000000/blob_sidecar_0/ssz_snappy", "/eth2/00000000/blob_sidecar_1/ssz_snappy" });
    var b_intent = core_test.intent(&pair.server, &.{});
    b_intent.subscriptions = a_intent.subscriptions;
    try std.testing.expect(try pair.client.applyIntent(&a_intent, pair.client.last_now));
    try std.testing.expect(try pair.server.applyIntent(&b_intent, pair.server.last_now));
    try pair.client.connectUntil(&pair.server.peerId(), &.{test_support.server_address}, pair.client.last_now, time.milliseconds(pair.client.last_now.millis() +| Dialing.connect_timeout_ms));
    const start = pair.client.last_now.millis();
    var mesh_count: usize = 0;
    for (0..3000) |_| {
        try pair.step(1);
        pair.pair.advance(10);
        if (pair.client.last_now.millis() - start > 10_000) break;
        mesh_count = pair.client.protocols.gossipsub.resourceSnapshot().mesh_members;
        if (mesh_count == 3) break;
    }
    const context = metrics.Context.init(&pair.client, pair.client.last_now, true);
    try std.testing.expectEqual(@as(usize, 3), mesh_count);
    try std.testing.expectEqual(@as(usize, 1), context.population.count);
}
