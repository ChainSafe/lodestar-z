const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const core = @import("network_core.zig");
const metrics = @import("metrics/export.zig");
const policy = @import("gossipsub/topic_policy.zig");
const protocol = @import("reqresp/root.zig").Protocol;

const Fixture = struct {
    node: *core.NetworkCore,
    buffer: []u8,

    fn init(boundaries: []const policy.Boundary) !Fixture {
        return initWith(boundaries, null);
    }

    fn initWith(boundaries: []const policy.Boundary, discovery: ?core.DiscoveryOptions) !Fixture {
        return initClock(boundaries, discovery, null);
    }

    fn initClock(boundaries: []const policy.Boundary, discovery: ?core.DiscoveryOptions, slot_clock: ?core.SlotClock) !Fixture {
        const node = try std.testing.allocator.create(core.NetworkCore);
        errdefer std.testing.allocator.destroy(node);
        const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{93}));
        var options = @import("test_support.zig").networkOptions(&key);
        options.resolved.core.service.gossipsub.topic_policy = if (boundaries.len > 0) boundaries else null;
        options.startup.discovery = discovery;
        options.startup.slot_clock = slot_clock;
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

const Series = struct {
    name: []const u8,
    kind: []const u8,
    labels: []const []const u8 = &.{},
};

/// The measurement contract: series read by the feat4-vs-stable comparison and the next
/// production review. Removing or renaming one needs the same change in that comparison.
const contract = [_]Series{
    // Owner loop
    .{ .name = "lodestar_native_network_step_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_network_readiness_calls_total", .kind = "counter" },
    .{ .name = "lodestar_native_network_readiness_nonzero_waits_total", .kind = "counter" },
    .{ .name = "lodestar_native_network_due_now_turns_total", .kind = "counter", .labels = &.{"source"} },
    .{ .name = "lodestar_native_network_wait_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_quic_connection_visits_total", .kind = "counter", .labels = &.{"phase"} },
    .{ .name = "lodestar_native_network_discovery_only_turns_total", .kind = "counter" },
    .{ .name = "lodestar_native_quic_udp_received_datagrams_total", .kind = "counter" },
    .{ .name = "lodestar_native_quic_udp_sent_datagrams_total", .kind = "counter" },
    .{ .name = "lodestar_native_udp_socket_buffer_bytes", .kind = "gauge", .labels = &.{ "role", "family", "direction" } },
    // Peers
    .{ .name = "libp2p_peers", .kind = "gauge" },
    .{ .name = "lodestar_native_peer_below_target", .kind = "gauge" },
    .{ .name = "lodestar_peers_by_direction_count", .kind = "gauge", .labels = &.{"direction"} },
    .{ .name = "lodestar_peers_by_client_count", .kind = "gauge", .labels = &.{"client"} },
    .{ .name = "lodestar_native_peers_by_client_direction", .kind = "gauge", .labels = &.{ "client", "direction" } },
    .{ .name = "lodestar_peer_connected_total", .kind = "counter", .labels = &.{ "direction", "status" } },
    .{ .name = "lodestar_peer_goodbye_sent_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_peer_goodbye_received_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_closes_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_closes_by_client_total", .kind = "counter", .labels = &.{ "client", "reason" } },
    .{ .name = "lodestar_native_peer_health_failures_total", .kind = "counter", .labels = &.{"probe"} },
    .{ .name = "lodestar_native_quic_connections_established_total", .kind = "counter", .labels = &.{"direction"} },
    .{ .name = "lodestar_native_quic_connections_closed_total", .kind = "counter", .labels = &.{ "direction", "reason" } },
    .{ .name = "lodestar_native_quic_connections_dialing", .kind = "gauge" },
    .{ .name = "lodestar_native_peer_dial_selections_total", .kind = "counter", .labels = &.{"source"} },
    .{ .name = "lodestar_native_peer_dial_outcomes_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_peer_dial_retries_total", .kind = "counter", .labels = &.{"previous"} },
    .{ .name = "lodestar_native_dial_failed_intents_released_total", .kind = "counter" },
    .{ .name = "lodestar_native_dial_recent_failures_refused_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_peer_rejections_total", .kind = "counter", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_peer_dial_funnel_total", .kind = "counter", .labels = &.{ "origin", "stage" } },
    .{ .name = "lodestar_native_remembered_peers", .kind = "gauge" },
    .{ .name = "lodestar_native_remembered_peer_seeds_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_remembered_peer_replays_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_remembered_peer_removals_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_remembered_peer_snapshot_records_total", .kind = "counter" },
    // discv5
    .{ .name = "lodestar_discv5_active_session_count", .kind = "gauge" },
    .{ .name = "lodestar_discv5_kad_table_size", .kind = "gauge" },
    .{ .name = "lodestar_discv5_lookup_count", .kind = "gauge" },
    .{ .name = "lodestar_native_discovery_lookup_active", .kind = "gauge" },
    .{ .name = "lodestar_native_discovery_session_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_discovery_lookups_started_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_queries_started_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_query_timeouts_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_lookup_finishes_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_discovery_admission_total", .kind = "counter", .labels = &.{ "stage", "outcome" } },
    .{ .name = "lodestar_native_discovery_datagrams_accepted_total", .kind = "counter" },
    .{ .name = "lodestar_native_discovery_datagram_rejections_total", .kind = "counter", .labels = &.{ "stage", "reason" } },
    // Gossip
    .{ .name = "gossipsub_mesh_peer_count", .kind = "gauge", .labels = &.{"topicStr"} },
    .{ .name = "gossipsub_topic_peer_count", .kind = "gauge", .labels = &.{"topicStr"} },
    .{ .name = "lodestar_gossip_mesh_peers_by_type_count", .kind = "gauge", .labels = &.{ "type", "boundary" } },
    .{ .name = "lodestar_gossip_topic_peers_by_type_count", .kind = "gauge", .labels = &.{ "type", "boundary" } },
    .{ .name = "lodestar_native_gossip_queue_drops_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossip_data_recipients_total", .kind = "counter", .labels = &.{ "origin", "outcome" } },
    .{ .name = "lodestar_native_gossip_data_recipients_by_kind_total", .kind = "counter", .labels = &.{ "kind", "phase_bps", "outcome" } },
    .{ .name = "lodestar_native_gossip_descriptor_refusal_queued_bytes", .kind = "histogram", .labels = &.{"last_write"} },
    .{ .name = "lodestar_native_gossip_descriptor_refusal_oldest_seconds", .kind = "histogram", .labels = &.{"last_write"} },
    .{ .name = "lodestar_native_gossip_descriptor_refusal_blocked_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_turn_stops_total", .kind = "counter", .labels = &.{"budget"} },
    .{ .name = "lodestar_native_gossip_turn_stop_skipped_peers_total", .kind = "counter", .labels = &.{ "budget", "output" } },
    .{ .name = "lodestar_native_gossip_turn_stop_unserved_seconds_total", .kind = "counter", .labels = &.{ "budget", "phase_bps" } },
    .{ .name = "lodestar_native_gossip_data_drops_total", .kind = "counter", .labels = &.{ "origin", "reason", "client" } },
    .{ .name = "lodestar_native_gossip_data_drops_by_slot_phase_total", .kind = "counter", .labels = &.{"phase_bps"} },
    .{ .name = "lodestar_native_gossip_data_write_seconds", .kind = "histogram", .labels = &.{"origin"} },
    .{ .name = "lodestar_native_gossipsub_queued_local_descriptors", .kind = "gauge" },
    .{ .name = "lodestar_native_gossip_data_admission_queued", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_data_admission_oldest_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_apply_verdicts", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_apply_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_apply_spacing_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_apply_forward_recipients", .kind = "histogram", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_gossip_apply_forward_bytes", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_apply_service_frames", .kind = "histogram" },
    .{ .name = "lodestar_native_gossip_outbox_observed_seconds_total", .kind = "counter", .labels = &.{"phase_bps"} },
    .{ .name = "lodestar_native_gossip_outbox_descriptor_seconds_total", .kind = "counter", .labels = &.{"phase_bps"} },
    .{ .name = "lodestar_native_gossip_outbox_full_peer_seconds_total", .kind = "counter", .labels = &.{"phase_bps"} },
    .{ .name = "lodestar_native_gossip_iwant_ids_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_gossip_graft_received_total", .kind = "counter", .labels = &.{"outcome"} },
    .{ .name = "lodestar_native_gossip_prune_sent_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossip_mesh_peer_seconds_total", .kind = "counter", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_gossipsub_history_capacity", .kind = "gauge" },
    .{ .name = "lodestar_native_gossip_history_evictions_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "lodestar_native_gossip_retention_refusals_total", .kind = "counter", .labels = &.{"kind"} },
    // ReqResp
    .{ .name = "beacon_reqresp_outgoing_requests_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_outgoing_requests_error_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_outgoing_requests_error_reason_total", .kind = "counter", .labels = &.{"reason"} },
    .{ .name = "beacon_reqresp_incoming_requests_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "beacon_reqresp_incoming_requests_error_total", .kind = "counter", .labels = &.{"method"} },
    .{ .name = "lodestar_native_reqresp_inbound_occupied", .kind = "gauge", .labels = &.{"phase"} },
    .{ .name = "lodestar_native_reqresp_resources_serving_occupied", .kind = "gauge" },
    .{ .name = "lodestar_native_reqresp_resources_serving_capacity", .kind = "gauge" },
    // Bridge
    .{ .name = "lodestar_native_network_host_applies_total", .kind = "counter", .labels = &.{"cause"} },
    .{ .name = "lodestar_native_gossip_processor_items", .kind = "gauge", .labels = &.{ "kind", "state" } },
    .{ .name = "lodestar_native_gossip_processor_refusals_total", .kind = "counter", .labels = &.{ "kind", "reason" } },
    .{ .name = "lodestar_native_gossip_admission_lag_seconds", .kind = "histogram", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_bridge_call_seconds", .kind = "histogram", .labels = &.{"entry"} },
    .{ .name = "lodestar_native_bridge_lock_wait_seconds", .kind = "histogram", .labels = &.{"entry"} },
    .{ .name = "lodestar_native_bridge_owner_lock_wait_seconds", .kind = "histogram", .labels = &.{"phase"} },
    .{ .name = "lodestar_native_bridge_lock_hold_seconds", .kind = "histogram", .labels = &.{"phase"} },
    .{ .name = "lodestar_native_bridge_notify_total", .kind = "counter" },
    .{ .name = "lodestar_native_bridge_notify_seconds", .kind = "histogram" },
    .{ .name = "lodestar_native_bridge_notify_chain", .kind = "histogram" },
    .{ .name = "lodestar_native_bridge_js_pings_total", .kind = "counter", .labels = &.{"entry"} },
    .{ .name = "lodestar_native_bridge_delivered_items_total", .kind = "counter", .labels = &.{"kind"} },
    .{ .name = "lodestar_native_publication_queue_seconds", .kind = "histogram" },
};

fn hasSeries(output: []const u8, series: Series) bool {
    var buffer: [256]u8 = undefined;
    const type_line = std.fmt.bufPrint(&buffer, "# TYPE {s} {s}\n", .{ series.name, series.kind }) catch return false;
    if (std.mem.indexOf(u8, output, type_line) == null) return false;
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
        if (std.mem.startsWith(u8, after, "{")) return after[0 .. std.mem.indexOfScalar(u8, after, '}') orelse after.len];
    }
    return null;
}

fn hasLabel(labels: []const u8, label: []const u8) bool {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, labels, start, label)) |at| {
        const opens = at > 0 and (labels[at - 1] == '{' or labels[at - 1] == ',');
        if (opens and std.mem.startsWith(u8, labels[at + label.len ..], "=\"")) return true;
        start = at + 1;
    }
    return false;
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
    try gossip_test.subscribe(g, future);
    output = try f.render(true);
    try contains(output, "lodestar_gossip_mesh_peers_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 0\n");
    try contains(output, "lodestar_native_gossip_subscriptions_by_type_count{type=\"beacon_block\",boundary=\"fulu_200\"} 1\n");
    try gossip_test.unsubscribe(g, future);
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
        try gossip_test.subscribe(g, @import("gossipsub/topic.zig").build(value.digest, "beacon_block", &name));
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

test "metrics render every measurement contract series with its type and labels" {
    var f = try Fixture.initWith(&.{boundary(@splat(0), 100)}, .{ .bind = .{ .ip4 = .loopback(0) } });
    defer f.deinit();
    const output = try f.render(true);
    var missing: usize = 0;
    for (contract) |series| {
        if (hasSeries(output, series)) continue;
        std.debug.print("measurement contract series missing or mistyped: {s} ({s})\n", .{ series.name, series.kind });
        missing += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), missing);
}

test "metrics report the kernel's buffer sizes and drops for every UDP socket" {
    var f = try Fixture.initWith(&.{}, .{ .bind = .{ .ip4 = .loopback(0) } });
    defer f.deinit();
    const output = try f.render(true);
    const roles = [_]struct { []const u8, *@import("udp").Sockets }{
        .{ "quic", &f.node.transport.udp.sockets },
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
    try std.testing.expect(std.mem.indexOf(u8, output, "family=\"ip6\"") == null);
    f.node.discovery.?.transport.sockets.buffers[0].?.receive = null;
    const unknown = try f.render(true);
    try std.testing.expect(std.mem.indexOf(u8, unknown, "role=\"discovery\",family=\"ip4\",direction=\"receive\"") == null);
    try contains(unknown, "role=\"discovery\",family=\"ip4\",direction=\"send\"");
}

test "metrics label redials after a health close in the dial retries contract series" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    f.node.peer_manager.dialing.retries[@intFromEnum(@import("peers/types.zig").DialFailure.health)] = 2;
    try contains(try f.render(true), "lodestar_native_peer_dial_retries_total{previous=\"health\"} 2\n");
}

test "metrics owner loop series start at zero after initialization" {
    var f = try Fixture.init(&.{});
    defer f.deinit();
    const output = try f.render(true);
    try contains(output, "lodestar_native_network_step_seconds_count 0\n");
    try contains(output, "lodestar_native_network_wait_seconds_count 0\n");
    try contains(output, "lodestar_native_network_due_now_turns_total{source=\"host\"} 0\n");
}

fn initOwner(node: *core.NetworkCore) !void {
    const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{94}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .beacon_node, .seed = 7, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    try node.init(std.testing.allocator, std.testing.io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = @import("managed_test_support.zig").localState(.{}),
        .slot = 100,
    });
}

test "metrics attribute zero-wait owner turns to every due source and record the chosen wait" {
    const node = try std.testing.allocator.create(core.NetworkCore);
    defer std.testing.allocator.destroy(node);
    try initOwner(node);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    for (0..8) |_| try std.testing.expect(node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms)).failure == null);
    const host = @intFromEnum(@import("wake_sources.zig").Source.host);
    try std.testing.expectEqual(@as(u64, 8), node.due_now_turns[host]);
    try std.testing.expectEqual(@as(u64, 8), node.wait_duration.buckets[0]);
    try std.testing.expect(node.nextWakeup(now, .{}).? > now.mono_ms);
    const settled = node.due_now_turns;
    try std.testing.expect(node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 2)).failure == null);
    try std.testing.expectEqualDeep(settled, node.due_now_turns);
    try std.testing.expectEqual(@as(u64, 9), node.wait_duration.count);
    try std.testing.expectEqual(@as(u64, 8), node.wait_duration.buckets[0]);
    const buffer = try std.testing.allocator.alloc(u8, metrics.textCapacity(&.{}));
    defer std.testing.allocator.free(buffer);
    var context = metrics.Context.init(node, now, true);
    var writer = std.Io.Writer.fixed(buffer);
    try metrics.write(&context, &writer);
    const output = writer.buffered();
    try contains(output, "lodestar_native_network_due_now_turns_total{source=\"host\"} 8\n");
    try contains(output, "lodestar_native_network_wait_seconds_bucket{le=\"0\"} 8\n");
    try contains(output, "lodestar_native_network_wait_seconds_count 9\n");
}

test "metrics export cumulative discovery lookups, session capacity and datagram rejections" {
    var f = try Fixture.initWith(&.{}, .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{ .session_capacity = 8, .challenge_capacity = 8, .call_capacity = 8 } });
    defer f.deinit();
    const coordinator = &f.node.discovery.?.coordinator;
    coordinator.counters.lookups_started = 5;
    coordinator.datagram_rejections[@intFromEnum(@import("discv5").types.RejectReason.invalid_handshake)] = 3;
    const output = try f.render(true);
    try contains(output, "# TYPE lodestar_discv5_lookup_count gauge\nlodestar_discv5_lookup_count 5\n");
    try contains(output, "lodestar_native_discovery_lookup_active 0\n");
    try contains(output, "lodestar_native_discovery_session_capacity 8\n");
    try contains(output, "lodestar_native_discovery_datagram_rejections_total{stage=\"handshake\",reason=\"invalid_handshake\"} 3\n");
    try contains(try f.render(false), "lodestar_discv5_lookup_count 5\n");
}

test "metrics export stock per-topic gossipsub peer gauges under full topic strings" {
    var f = try Fixture.init(&.{ boundary(@splat(0), 100), boundary(@splat(1), 200) });
    defer f.deinit();
    const g = f.node.service.gossipsub;
    const ns = &g.overlay.namespace.?;
    const column = "/eth2/00000000/data_column_sidecar_9/ssz_snappy";
    ns.setSubscription(0, ns.lookup(column).?.ordinal, true);
    var output = try f.render(true);
    try contains(output, "# TYPE gossipsub_topic_peer_count gauge\n");
    try contains(output, "gossipsub_topic_peer_count{topicStr=\"" ++ column ++ "\"} 1\n");
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"" ++ column ++ "\"} 0\n");
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"/eth2/00000000/beacon_attestation_63/ssz_snappy\"} 0\n");
    try std.testing.expectEqual(@as(usize, 333), std.mem.count(u8, output, "gossipsub_topic_peer_count{topicStr=\"/eth2/00000000/"));
    try std.testing.expect(std.mem.indexOf(u8, output, "/eth2/01010101/") == null);
    const future = "/eth2/01010101/beacon_block/ssz_snappy";
    try gossip_test.subscribe(g, future);
    output = try f.render(true);
    try contains(output, "gossipsub_mesh_peer_count{topicStr=\"" ++ future ++ "\"} 0\n");
}

test "metrics count a zero-wait owner turn once under each of its two due sources" {
    const node = try std.testing.allocator.create(core.NetworkCore);
    defer std.testing.allocator.destroy(node);
    try initOwner(node);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    for (0..8) |_| try std.testing.expect(node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms)).failure == null);
    try std.testing.expect(node.nextWakeup(now, .{}).? > now.mono_ms);
    const remote = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{95}));
    const remote_key = remote.publicKey();
    const peer = @import("wire/peer_id.zig").PeerId.fromPublicKey(&remote_key);
    // The node binds IPv4 only, so this dial fails before sending a datagram.
    try node.connectUntil(&peer, &.{.{ .ip6 = .{ .octets = .{0} ** 15 ++ .{1}, .port = 9000 } }}, now, now.mono_ms + 60_000);
    const before = node.due_now_turns;
    const waits = node.wait_duration.buckets[0];
    try std.testing.expect(node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 100)).failure == null);
    try std.testing.expectEqual(waits + 1, node.wait_duration.buckets[0]);
    const Source = @import("wake_sources.zig").Source;
    for (before, node.due_now_turns, 0..) |previous, current, index| {
        const due = index == @intFromEnum(Source.dial) or index == @intFromEnum(Source.peer_policy);
        try std.testing.expectEqual(previous + @intFromBool(due), current);
    }
}

test "metrics count each host apply once under its cause" {
    const node = try std.testing.allocator.create(core.NetworkCore);
    defer std.testing.allocator.destroy(node);
    try initOwner(node);
    defer node.deinit(std.testing.io);
    const Host = struct {
        applies: usize = 0,
        fn apply(context: *anyopaque, _: *core.NetworkCore, _: @import("types.zig").Now) core.HostProgress {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.applies += 1;
            return .{ .more = self.applies == 1 };
        }
    };
    var host: Host = .{};
    const now = try @import("transport.zig").currentTime(std.testing.io);
    try std.testing.expect(node.step(std.testing.io, now, .{}, .{ .context = &host, .apply = Host.apply, .deadline_ms = now.mono_ms }).failure == null);
    try std.testing.expect(node.tick_ns > 0);
    try std.testing.expect(node.step(std.testing.io, now, .{}, .{ .context = &host, .apply = Host.apply }).failure == null);
    try std.testing.expectEqual(@as(usize, 2), host.applies);
    const HostCause = core.HostCause;
    try std.testing.expectEqual(@as(u64, 0), node.host_applies[@intFromEnum(HostCause.readiness)]);
    try std.testing.expectEqual(@as(u64, 1), node.host_applies[@intFromEnum(HostCause.due)]);
    try std.testing.expectEqual(@as(u64, 1), node.host_applies[@intFromEnum(HostCause.more)]);
    const buffer = try std.testing.allocator.alloc(u8, metrics.textCapacity(&.{}));
    defer std.testing.allocator.free(buffer);
    var context = metrics.Context.init(node, now, true);
    var writer = std.Io.Writer.fixed(buffer);
    try metrics.write(&context, &writer);
    try contains(writer.buffered(), "lodestar_native_network_host_applies_total{cause=\"more\"} 1\n");
    try contains(writer.buffered(), "lodestar_native_bridge_call_seconds_count{entry=\"publish_gossip\"} 0\n");
}

test "metrics phases come from the owner's slot clock, which each clock read updates" {
    const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{94}));
    var options = @import("test_support.zig").networkOptions(&key);
    const node = try std.testing.allocator.create(core.NetworkCore);
    defer std.testing.allocator.destroy(node);
    options.startup.slot_clock = .{ .genesis_unix_ms = 0, .slot_duration_ms = 0 };
    try std.testing.expectError(error.InvalidOptions, node.init(std.testing.allocator, std.testing.io, &options.resolved, options.startup));
    options.startup.slot_clock = .{ .genesis_unix_ms = 0, .slot_duration_ms = 12_000 };
    try node.init(std.testing.allocator, std.testing.io, &options.resolved, options.startup);
    defer node.deinit(std.testing.io);
    try std.testing.expectEqual(&node.slot_clock.?, node.service.gossipsub.slot_clock.?);
    const wall = node.last_now.unix_ms.?;
    try std.testing.expectEqual(@as(?u16, @intCast(wall % 12_000 * 10_000 / 12_000)), node.slot_clock.?.phaseBps(node.last_now.mono_ms));
}

test "metrics bucket a pressured publication by the phase of the owner's slot clock" {
    var f = try Fixture.initClock(&.{}, null, .{ .genesis_unix_ms = 1_606_824_023_000, .slot_duration_ms = 12_000 });
    defer f.deinit();
    const node = f.node;
    const g = node.service.gossipsub;
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    const conn: @import("types.zig").Handle = .{ .index = 0, .generation = 1 };
    const now = node.last_now;
    _ = try node.publishGossipWithOptions(topic, "filler", .{}, now);
    const peer = gossip_test.addPeer(g, conn, .v1_2).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, topic, true);
    g.markDirect(conn);
    const filler = g.messages.history.message(g.messages.history.get(&g.messages.store, @import("gossipsub/topic.zig").validMessageId(topic, "filler", g.options.message_id_policy)).?);
    const tx = &g.sessions.rows[peer.index].io.tx;
    for (0..@import("gossipsub/delivery.zig").per_peer_limit) |_| {
        const origin: @import("gossipsub/delivery.zig").Origin = if (tx.data.full()) .publication else .forward;
        try std.testing.expectEqual(.queued, tx.queueData(&g.messages.store, filler, origin, .{ .bytes = g.options.tx_peer_bytes }, now.mono_ms));
    }
    const outcome = try node.publishGossipWithOptions(topic, "pressured", .{}, now);
    try std.testing.expectEqual(@as(u16, 1), outcome.pressured);
    const bucket = core.SlotClock.bucket(node.slot_clock.?.phaseBps(now.mono_ms).?);
    const output = try f.render(true);
    var line: [128]u8 = undefined;
    for (@import("slot_clock.zig").bucket_labels, 0..) |label, index| {
        try contains(output, try std.fmt.bufPrint(&line, "lodestar_native_gossip_data_drops_by_slot_phase_total{{phase_bps=\"{s}\"}} {d}\n", .{ label, @intFromBool(index == bucket) }));
    }
    g.connectionClosed(conn);
}
