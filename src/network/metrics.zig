const std = @import("std");
const network = @import("network_core.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const topic_metrics = @import("gossipsub/metrics.zig");
const peer_types = @import("peers/types.zig");
const Writer = std.Io.Writer;
const prom = @import("metrics_prometheus.zig");
const scalar = prom.scalar;
const family = prom.family;
const sample = prom.sample;
const counterFields = prom.counterFields;

pub const interval_ms = 1_000;
pub const text_capacity = 256 * 1024;
const Client = enum { Lighthouse, Nimbus, Teku, Prysm, Lodestar, Grandine, Unknown };
const client_count = @typeInfo(Client).@"enum".fields.len;
const Topic = struct {
    digest: [4]u8,
    kind: gossip.topic_policy.Kind,
    subnet: u16,
    mesh: usize,
    subscribers: usize,
};

fn clientKind(agent: []const u8) Client {
    const prefix = agent[0 .. std.mem.indexOfScalar(u8, agent, '/') orelse agent.len];
    inline for (@typeInfo(Client).@"enum".fields) |field| {
        if (std.ascii.eqlIgnoreCase(prefix, field.name)) return @enumFromInt(field.value);
    }
    if (std.ascii.eqlIgnoreCase(prefix, "js-libp2p")) return .Lodestar;
    return .Unknown;
}

/// Only the network owner collects live state. Readers copy this pointer-free snapshot
/// under the runtime mutex; labels never contain remote-controlled free-form text.
pub const Snapshot = struct {
    runtime: network.Counters = .{},
    transport: @import("quic/api.zig").Counters = .{},
    requests: rr.Counters = .{},
    udp: @import("udp.zig").Counters = .{},
    outgoing_error_reasons: [rr.reqresp.metrics.error_reason_count]u64 = @splat(0),
    validation_time: topic_metrics.ValidationTime = .{},
    scores: @import("metrics_score.zig").Snapshot = .{},
    protocols: [rr.Protocol.count]rr.reqresp.ProtocolCounters = @splat(.{}),
    gossip_counts: gossip.Gossipsub.Counters = .{},
    gossip_topics: topic_metrics.Topics = .{},
    gossip_resources: ?gossip.ResourceSnapshot = null,
    closed: [@typeInfo(peer_types.DisconnectReason).@"enum".fields.len]u64 = @splat(0),
    peers: usize = 0,
    relevant: usize = 0,
    target: usize = 0,
    clients: [client_count]usize = @splat(0),
    directions: [2]usize = @splat(0),
    mesh_clients: [client_count]usize = @splat(0),
    topics: [gossip.constants.topics_cap]Topic = undefined,
    topic_count: usize = 0,
    discovery_enabled: bool = false,
    discovery_sessions: usize = 0,
    discovery_peers: usize = 0,
    discovery_lookups: usize = 0,
    sampled_ms: u64 = 0,
    running: bool = false,

    pub fn collect(self: *Snapshot, owner: *const network.NetworkCore, now_ms: u64) void {
        self.* = .{ .sampled_ms = now_ms, .running = true };
        const core = &owner.core;
        const g = &core.service.gossipsub.inner;
        self.runtime = owner.counters;
        self.transport = owner.transport.engine.counters;
        self.requests = core.service.reqresp.inner.counters;
        self.udp = owner.transport.udp.counters;
        self.outgoing_error_reasons = core.service.reqresp.inner.outgoing_error_reasons;
        self.validation_time = g.validation_time;
        self.protocols = core.service.reqresp.inner.protocol_counters;
        self.gossip_counts = g.counters;
        self.gossip_topics = g.topic_metrics;
        self.gossip_resources = g.resourceSnapshot();
        self.closed = core.control.counters.closed;
        self.target = core.catalog.options.target_peers;
        for (core.catalog.rows) |*row| {
            if (row.connection == null) continue;
            self.peers += 1;
            self.relevant += @intFromBool(row.status != null);
            const client = rowClient(&row.identify);
            self.clients[@intFromEnum(client)] += 1;
            self.directions[if (row.direction == .inbound) @as(usize, 0) else 1] += 1;
        }
        var mesh_peers = gossip.state.PeerSet.initEmpty();
        for (&g.state.topics) |*row| {
            if (!row.active) continue;
            mesh_peers.setUnion(row.mesh);
            const parsed = gossip.topic.parse(row.string[0..row.string_len]) orelse continue;
            var configured = std.mem.eql(u8, &parsed.digest, &core.local.fork.digest);
            if (g.namespace) |*namespace| for (namespace.boundaries) |*boundary| {
                if (std.mem.eql(u8, &parsed.digest, &boundary.digest)) {
                    configured = true;
                    break;
                }
            };
            if (!configured) continue;
            const known = topic_metrics.Topic.parse(parsed.name) orelse continue;
            const subnet = if (known.kind == .blob_sidecar) 0 else known.subnet;
            var found = false;
            for (self.topics[0..self.topic_count]) |*entry| {
                if (entry.kind == known.kind and entry.subnet == subnet and std.mem.eql(u8, &entry.digest, &parsed.digest)) {
                    entry.mesh += row.mesh.count();
                    entry.subscribers += row.subscribers.count();
                    found = true;
                    break;
                }
            }
            if (found) continue;
            std.debug.assert(self.topic_count < self.topics.len);
            self.topics[self.topic_count] = .{ .digest = parsed.digest, .kind = known.kind, .subnet = subnet, .mesh = row.mesh.count(), .subscribers = row.subscribers.count() };
            self.topic_count += 1;
        }
        for (g.state.peers, 0..) |*row, index| {
            if (!row.active) continue;
            self.scores.observe(g.scores.snapshot(row.logical.index, now_ms), &g.scores.params);
            if (!mesh_peers.isSet(index)) continue;
            var client: Client = .Unknown;
            for (core.catalog.rows) |*peer| {
                if (peer.connection) |connection| if (std.meta.eql(connection, row.conn)) {
                    client = rowClient(&peer.identify);
                    break;
                };
            }
            self.mesh_clients[@intFromEnum(client)] += 1;
        }
        if (owner.discovery) |discovery| {
            self.discovery_enabled = true;
            self.discovery_sessions = discovery.engine.channel.sessions.sessionCount();
            self.discovery_peers = discovery.engine.peerCount();
            self.discovery_lookups = @intFromBool(discovery.coordinator.lookup_active);
        }
    }

    pub fn stop(self: *Snapshot) void {
        self.running = false;
        self.scores = .{};
        self.peers = 0;
        self.relevant = 0;
        self.clients = @splat(0);
        self.directions = @splat(0);
        self.mesh_clients = @splat(0);
        self.topic_count = 0;
        self.gossip_resources = null;
        self.discovery_sessions = 0;
        self.discovery_peers = 0;
        self.discovery_lookups = 0;
    }

    pub fn write(self: *const Snapshot, w: *Writer) Writer.Error!void {
        try scalar(w, "libp2p_peers", .gauge, "Authenticated connected peers", self.peers);
        try scalar(w, "lodestar_native_network_relevant_peers", .gauge, "Peers with compatible Status", self.relevant);
        try scalar(w, "lodestar_peer_manager_starved_bool", .gauge, "Connected peers below target while running", @intFromBool(self.running and self.peers < self.target));
        try scalar(w, "lodestar_peer_manager_outbound_peers_ratio", .gauge, "Fraction of connected peers that are outbound", if (self.peers == 0) @as(f64, 0) else @as(f64, @floatFromInt(self.directions[1])) / @as(f64, @floatFromInt(self.peers)));
        try family(w, "lodestar_peers_by_direction_count", .gauge, "Connected peers by direction");
        for ([_][]const u8{ "inbound", "outbound" }, self.directions) |direction, count| try sample(w, "lodestar_peers_by_direction_count", "direction", direction, count);
        inline for (.{ .{ "lodestar_peers_by_client_count", "clients" }, .{ "lodestar_gossip_mesh_peers_by_client_count", "mesh_clients" } }) |metric| {
            try family(w, metric[0], .gauge, "Connected peers by client");
            inline for (@typeInfo(Client).@"enum".fields) |field| try sample(w, metric[0], "client", field.name, @field(self, metric[1])[field.value]);
        }
        try self.writeTopics(w);
        try self.writeRequests(w);
        try self.writeRequestTimes(w);
        try self.writeGossip(w);
        try self.writeScores(w);
        try scalar(w, "lodestar_discovery_total_dial_attempts", .counter, "Started native QUIC dials", self.runtime.dial_started);
        if (self.discovery_enabled) {
            try scalar(w, "lodestar_discv5_active_session_count", .gauge, "Stored discovery sessions", self.discovery_sessions);
            try scalar(w, "lodestar_discv5_kad_table_size", .gauge, "Discovery routing table entries", self.discovery_peers);
            try scalar(w, "lodestar_discv5_lookup_count", .gauge, "Active foreground discovery lookups", self.discovery_lookups);
        }
        try scalar(w, "lodestar_native_network_metrics_snapshot_monotonic_seconds", .gauge, "Monotonic time of the last owner snapshot", @as(f64, @floatFromInt(self.sampled_ms)) / 1000);
        try scalar(w, "lodestar_native_network_running", .gauge, "Network owner is running", @intFromBool(self.running));
        try counterFields(w, "lodestar_native_network_", &self.runtime);
        try counterFields(w, "lodestar_native_quic_", &self.transport);
        inline for (.{
            .{ "received_bytes", "Complete QUIC UDP payload bytes received, excluding truncated datagrams" },
            .{ "sent_bytes", "QUIC UDP payload bytes sent, including successful prefixes of failed batches" },
            .{ "received_datagrams", "QUIC UDP datagrams received, including truncated datagrams" },
            .{ "sent_datagrams", "QUIC UDP datagrams sent" },
            .{ "truncated_datagrams", "Oversized QUIC UDP datagrams discarded on receive" },
        }) |metric| try scalar(w, "lodestar_native_quic_udp_" ++ metric[0] ++ "_total", .counter, metric[1], @field(self.udp, metric[0]));
        try counterFields(w, "lodestar_native_reqresp_", &self.requests);
        try counterFields(w, "lodestar_native_gossipsub_", &self.gossip_counts);
        if (self.gossip_resources) |*resources| {
            inline for (@typeInfo(gossip.ResourceSnapshot).@"struct".fields) |field| {
                if (comptime @typeInfo(field.type) == .optional) {
                    if (@field(resources, field.name)) |value| {
                        if (comptime std.mem.endsWith(u8, field.name, "_ms")) {
                            try scalar(w, "lodestar_native_gossipsub_" ++ field.name[0 .. field.name.len - 3] ++ "_seconds", .gauge, "Native gossip " ++ field.name ++ " in seconds", @as(f64, @floatFromInt(value)) / 1000);
                        } else try scalar(w, "lodestar_native_gossipsub_" ++ field.name, .gauge, "Native gossip " ++ field.name, value);
                    }
                } else try scalar(w, "lodestar_native_gossipsub_" ++ field.name, .gauge, "Native gossip " ++ field.name, @field(resources, field.name));
            }
        }
        try family(w, "lodestar_native_peer_closes_total", .counter, "Peer closes initiated by native peer control");
        inline for (@typeInfo(peer_types.DisconnectReason).@"enum".fields) |field| try sample(w, "lodestar_native_peer_closes_total", "reason", field.name, self.closed[field.value]);
    }

    fn writeTopics(self: *const Snapshot, w: *Writer) Writer.Error!void {
        inline for (.{ .{ "mesh", "mesh" }, .{ "topic", "subscribers" } }) |metric| {
            const prefix = "lodestar_gossip_" ++ metric[0] ++ "_peers_by_";
            inline for (.{ "type", "beacon_attestation_subnet", "sync_committee_subnet", "data_column_subnet" }) |suffix| {
                try family(w, prefix ++ suffix ++ "_count", .gauge, "Peer memberships in active native topics; boundary is the fork digest");
            }
            for (self.topics[0..self.topic_count]) |*entry| {
                const boundary = std.fmt.bytesToHex(entry.digest, .lower);
                const value = @field(entry, metric[1]);
                switch (entry.kind) {
                    .beacon_attestation => try w.print(prefix ++ "beacon_attestation_subnet_count{{subnet=\"{d:0>2}\",boundary=\"{s}\"}} {d}\n", .{ entry.subnet, boundary, value }),
                    .sync_committee => try w.print(prefix ++ "sync_committee_subnet_count{{subnet=\"{d}\",boundary=\"{s}\"}} {d}\n", .{ entry.subnet, boundary, value }),
                    .data_column_sidecar => try w.print(prefix ++ "data_column_subnet_count{{subnet=\"{d}\",boundary=\"{s}\"}} {d}\n", .{ entry.subnet, boundary, value }),
                    else => try w.print(prefix ++ "type_count{{type=\"{s}\",boundary=\"{s}\"}} {d}\n", .{ @tagName(entry.kind), boundary, value }),
                }
            }
        }
    }

    fn writeRequests(self: *const Snapshot, w: *Writer) Writer.Error!void {
        inline for (.{
            .{ "beacon_reqresp_outgoing_requests_total", "outgoing", "Started outgoing native requests, including control methods" },
            .{ "beacon_reqresp_incoming_requests_total", "incoming", "Accepted incoming native request streams, including control methods" },
            .{ "beacon_reqresp_outgoing_requests_error_total", "outgoing_errors", "Outgoing requests with a terminal native failure" },
            .{ "beacon_reqresp_incoming_requests_error_total", "incoming_errors", "Incoming requests with a terminal native failure" },
            .{ "beacon_reqresp_rate_limiter_errors_total", "rate_limited", "Requests refused by native admission quotas or identity capacity" },
        }) |metric| {
            try family(w, metric[0], .counter, metric[2]);
            for (rr.protocol.methods, 0..) |method, index| {
                if (!firstMethod(index)) continue;
                var count: u64 = 0;
                for (rr.protocol.methods, &self.protocols) |candidate, *values| {
                    if (std.mem.eql(u8, candidate, method)) count +|= @field(values, metric[1]);
                }
                try sample(w, metric[0], "method", method, count);
            }
        }
    }

    fn writeRequestTimes(self: *const Snapshot, w: *Writer) Writer.Error!void {
        inline for (.{
            .{ "beacon_reqresp_outgoing_request_roundtrip_time_seconds", "outgoing_time", "Outgoing request duration from stream creation through native completion or failure" },
            .{ "beacon_reqresp_incoming_request_handler_time_seconds", "incoming_time", "Incoming request duration from accepted stream through native completion or failure" },
        }) |metric| {
            try family(w, metric[0], .histogram, metric[2]);
            for (rr.protocol.methods, 0..) |method, index| {
                if (!firstMethod(index)) continue;
                var aggregate: @TypeOf(@field(self.protocols[0], metric[1])) = .{};
                for (rr.protocol.methods, &self.protocols) |candidate, *values| {
                    if (std.mem.eql(u8, candidate, method)) aggregate.merge(&@field(values, metric[1]));
                }
                try prom.histogram(w, metric[0], "method", method, &aggregate);
            }
        }
        try family(w, "beacon_reqresp_outgoing_requests_error_reason_total", .counter, "Terminal outgoing native failures using host request error labels");
        inline for (@typeInfo(rr.reqresp.metrics.ErrorReason).@"enum".fields) |field| {
            try sample(w, "beacon_reqresp_outgoing_requests_error_reason_total", "reason", field.name, self.outgoing_error_reasons[field.value]);
        }
    }

    fn writeScores(self: *const Snapshot, w: *Writer) Writer.Error!void {
        try scalar(w, "lodestar_gossip_score_avg_min_max_min", .gauge, "Minimum connected gossip peer score", self.scores.min);
        try scalar(w, "lodestar_gossip_score_avg_min_max_max", .gauge, "Maximum connected gossip peer score", self.scores.max);
        try scalar(w, "lodestar_gossip_score_avg_min_max_avg", .gauge, "Average connected gossip peer score", self.scores.average());
        try scalar(w, "lodestar_native_gossip_scored_peers", .gauge, "Connected gossip peers included in score gauges", self.scores.count);
        try family(w, "lodestar_gossip_peer_score_by_threshold_count", .gauge, "Connected gossip peers at or above configured score thresholds");
        inline for (.{ "graylist", "publish", "gossip", "mesh" }) |threshold| {
            try sample(w, "lodestar_gossip_peer_score_by_threshold_count", "threshold", threshold, @field(self.scores, threshold));
        }
    }

    fn writeGossip(self: *const Snapshot, w: *Writer) Writer.Error!void {
        try scalar(w, "gossipsub_rpc_recv_count_total", .counter, "Complete received gossip RPCs", self.gossip_counts.rpcs_received);
        try family(w, "gossipsub_async_validation_delay_from_first_seen", .histogram, "Seconds from native gossip admission until an applied validation verdict");
        try prom.histogram(w, "gossipsub_async_validation_delay_from_first_seen", null, "", &self.validation_time);
        inline for (.{
            .{ "gossipsub_accepted_messages_total", "accepted" },
            .{ "gossipsub_rejected_messages_total", "rejected" },
            .{ "gossipsub_ignored_messages_total", "ignored" },
            .{ "gossipsub_msg_publish_count_total", "published" },
            .{ "gossipsub_msg_publish_peers_total", "published_peers" },
            .{ "gossipsub_msg_forward_count_total", "forwarded" },
            .{ "gossipsub_msg_forward_peers_total", "forwarded_peers" },
            .{ "gossipsub_pre_validation_valid_total", "admitted" },
            .{ "gossipsub_pre_validation_duplicate_total", "duplicates" },
        }) |metric| {
            try family(w, metric[0], .counter, "Native gossip " ++ metric[1] ++ "; peer copies count successful queue admissions");
            inline for (@typeInfo(gossip.topic_policy.Kind).@"enum".fields) |field| {
                try sample(w, metric[0], "topic", field.name, @field(self.gossip_topics.counts[field.value], metric[1]));
            }
            try sample(w, metric[0], "topic", "unknown", @field(self.gossip_topics.counts[gossip.topic_policy.kind_count], metric[1]));
        }
    }
};

fn firstMethod(index: usize) bool {
    std.debug.assert(index < rr.Protocol.count);
    for (rr.protocol.methods[0..index]) |previous| if (std.mem.eql(u8, rr.protocol.methods[index], previous)) return false;
    return true;
}

fn rowClient(identify: *const ?@import("identify/root.zig").Metadata) Client {
    if (identify.*) |*metadata| if (metadata.agent) |*agent| return clientKind(agent.slice());
    return .Unknown;
}

test "metrics format exact counters, merge protocol versions and bound maximum output" {
    var snapshot: Snapshot = .{};
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing = 4;
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing = 5;
    snapshot.runtime.dial_started = std.math.maxInt(u64);
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing_time.observe(100);
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing_time.observe(300);
    snapshot.requests.withheld_ms_total = 1500;
    snapshot.topic_count = snapshot.topics.len;
    for (&snapshot.topics, 0..) |*entry, index| entry.* = .{ .digest = .{ 1, 2, @intCast(index / 256), @truncate(index) }, .kind = .data_column_sidecar, .subnet = 127, .mesh = 4096, .subscribers = 4096 };
    const buffer = try std.testing.allocator.alloc(u8, text_capacity);
    defer std.testing.allocator.free(buffer);
    var writer: Writer = .fixed(buffer);
    try snapshot.write(&writer);
    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_total_dial_attempts 18446744073709551615\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"}"));
    try std.testing.expectEqual(Client.Lighthouse, clientKind("lighthouse/v1.2.3"));
    try std.testing.expectEqual(Client.Lodestar, clientKind("js-libp2p/1"));
    try std.testing.expectEqual(Client.Unknown, clientKind("attacker\"\nmetric 1"));
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_bucket{method=\"status\",le=\"0.1\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method=\"status\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_withheld_seconds_total 1.5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "_total_total") == null);
    snapshot.stop();
    try std.testing.expectEqual(@as(usize, 0), snapshot.topic_count);
    try std.testing.expectEqual(std.math.maxInt(u64), snapshot.runtime.dial_started);
}
