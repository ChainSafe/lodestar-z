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
const peer_client = @import("peers/client.zig");
const goodbye = @import("peers/goodbye.zig");
const discovery_metrics = @import("peers/discovery.zig");
const peer_io = @import("gossipsub/peer_io.zig");
const score_metrics = @import("metrics_score.zig");

pub const interval_ms = 1_000;
pub const text_capacity = 512 * 1024;
const Client = peer_client.Client;
const client_count = @typeInfo(Client).@"enum".fields.len;
const Topic = struct {
    digest: [4]u8,
    kind: gossip.topic_policy.Kind,
    subnet: u16,
    mesh: usize,
    subscribers: usize,
};

fn clientKind(agent: []const u8) Client {
    return peer_client.kind(agent);
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
    scores: score_metrics.Snapshot = .{},
    peer_policy: @import("metrics_peer_policy.zig").Snapshot = .{},
    peer_population: @import("metrics_peers.zig").Snapshot = .{},
    connections: @import("quic/metrics.zig").Counters = .{},
    transport_resources: ?@import("quic/engine.zig").Engine.Resources = null,
    dial_resources: ?@import("peers/dial_queue.zig").DialQueue.Resources = null,
    dial_time: [2]@import("peers/dial_queue.zig").DialTime = @splat(.{}),
    lookup_time: discovery_metrics.LookupTime = .{},
    lookup_finishes: [@typeInfo(@import("discv5").Lookup.FinishReason).@"enum".fields.len]u64 = @splat(0),
    discovery_pending_revalidations: usize = 0,
    discovery_waiting_queries: usize = 0,
    discovery_candidate_idle_ms: ?u64 = null,
    identify_started: u64 = 0,
    identify_deferred: u64 = 0,
    identify_failures: [@typeInfo(@import("identify/root.zig").Failure).@"enum".fields.len]u64 = @splat(0),
    protocols: [rr.Protocol.count]rr.reqresp.ProtocolCounters = @splat(.{}),
    gossip_counts: gossip.Gossipsub.Counters = .{},
    gossip_topics: topic_metrics.Topics = .{},
    gossip_rpc: topic_metrics.Rpc = .{},
    gossip_recovery: topic_metrics.Recovery = .{},
    gossip_seen: usize = 0,
    gossip_fast_hits: u64 = 0,
    gossip_decoded: u64 = 0,
    gossip_recent: usize = 0,
    gossip_delivery_evictions: u64 = 0,
    gossip_history: usize = 0,
    gossip_resources: ?gossip.ResourceSnapshot = null,
    closed: [@typeInfo(peer_types.DisconnectReason).@"enum".fields.len]u64 = @splat(0),
    closed_by_client: [client_count][@typeInfo(peer_types.DisconnectReason).@"enum".fields.len]u64 = @splat(@splat(0)),
    peer_events: @import("peers/control_metrics.zig").Counters = .{},
    dial: @import("peers/dial_queue.zig").DialQueue.Counters = .{},
    discovery_counts: discovery_metrics.Counters = .{},
    discovery_rejections: [discovery_metrics.rejection_count]u64 = @splat(0),
    gossip_queue_drops: [peer_io.drop_reason_count]u64 = @splat(0),
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
        self.connections = owner.transport.engine.connection_metrics;
        self.transport_resources = owner.transport.engine.resourceSnapshot();
        self.dial_resources = core.dial_queue.resourceSnapshot();
        self.dial_time = core.dial_queue.durations;
        self.requests = core.service.reqresp.inner.counters;
        self.udp = owner.transport.udp.counters;
        self.outgoing_error_reasons = core.service.reqresp.inner.outgoing_error_reasons;
        self.validation_time = g.validation_time;
        self.protocols = core.service.reqresp.inner.protocol_counters;
        self.gossip_counts = g.counters;
        self.gossip_topics = g.topic_metrics;
        self.gossip_rpc = g.rpc_metrics;
        self.gossip_recovery = g.recovery.metrics;
        self.gossip_seen = g.messages.seen.count;
        self.gossip_fast_hits = g.messages.validation.fast_hits;
        self.gossip_decoded = g.messages.validation.decoded_messages;
        self.gossip_recent = 0;
        for (g.messages.validation.recent) |*record| self.gossip_recent += @intFromBool(record.state != .free);
        self.gossip_delivery_evictions = g.messages.validation.delivery_evictions;
        self.gossip_history = g.messages.history.count;
        self.gossip_resources = g.resourceSnapshot();
        self.closed = core.control.counters.closed;
        self.identify_started = core.control.counters.identify_started;
        self.identify_deferred = core.control.counters.identify_deferred;
        self.identify_failures = core.control.counters.identify_failures;
        self.closed_by_client = core.control.counters.closed_by_client;
        self.peer_events = core.control.counters.events;
        self.dial = core.dial_queue.counters;
        for (g.state.peers) |*session| {
            const io = &session.io;
            for (&self.gossip_queue_drops, io.drops) |*total, value| total.* +|= value;
        }
        self.target = core.catalog.options.target_peers;
        self.peer_policy.collect(&core.selection, &core.demand, core.current_slot, core.local.fork.custody_groups);
        for (core.control.schedules) |*schedule| {
            self.peer_policy.managed_connections += @intFromBool(schedule.peer != null);
        }
        for (core.catalog.rows) |*row| {
            self.peer_policy.catalog_entries += @intFromBool(row.occupied);
            if (row.connection == null) continue;
            self.peers += 1;
            self.peer_population.observe(row, now_ms);
            self.relevant += @intFromBool(row.status != null);
            const client = rowClient(&row.identify);
            self.clients[@intFromEnum(client)] += 1;
            self.directions[if (row.direction == .inbound) @as(usize, 0) else 1] += 1;
        }
        var mesh_peers = gossip.state.PeerSet.initEmpty();
        var meshes: [score_metrics.kind_count]gossip.state.PeerSet = @splat(.initEmpty());
        var score_kinds: score_metrics.TopicKinds = @splat(null);
        for (&g.state.registry.rows, 0..) |*row, topic_index| {
            if (!row.active) continue;
            mesh_peers.setUnion(row.mesh);
            const parsed = gossip.topic.parse(row.string[0..row.string_len]) orelse continue;
            const label = topic_metrics.Topic.parse(parsed.name);
            const kind: u8 = if (label) |known| @intFromEnum(known.kind) else gossip.topic_policy.kind_count;
            score_kinds[topic_index] = kind;
            meshes[kind].setUnion(row.mesh);
            var configured = std.mem.eql(u8, &parsed.digest, &core.local.fork.digest);
            if (g.state.registry.namespace) |*namespace| for (namespace.boundaries) |*boundary| {
                if (std.mem.eql(u8, &parsed.digest, &boundary.digest)) {
                    configured = true;
                    break;
                }
            };
            if (!configured) continue;
            const known = label orelse continue;
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
            var breakdown: gossip.score.Breakdown = undefined;
            const score = g.scores.snapshotWeights(row.logical.index, now_ms, &breakdown);
            self.scores.observe(score, &g.scores.params);
            self.scores.observeWeights(&breakdown, &score_kinds);
            for (&meshes, &self.scores.mesh_scores) |*mesh, *range| {
                if (mesh.isSet(index)) range.observe(score);
            }
            var client: Client = .Unknown;
            for (core.catalog.rows) |*peer| {
                if (peer.connection) |connection| if (std.meta.eql(connection, row.conn)) {
                    client = rowClient(&peer.identify);
                    break;
                };
            }
            self.peer_population.gossip_scores[@intFromEnum(client)].observe(score);
            if (!mesh_peers.isSet(index)) continue;
            self.mesh_clients[@intFromEnum(client)] += 1;
        }
        self.scores.calls = g.scores.calls;
        self.scores.runs = g.scores.calculations;
        self.scores.cache_delta = g.scores.cache_delta;
        self.scores.penalties = g.scores.penalties;
        if (owner.discovery) |discovery| {
            self.discovery_counts = discovery.coordinator.counters;
            self.discovery_rejections = discovery.coordinator.rejections;
            self.discovery_enabled = true;
            self.discovery_sessions = discovery.engine.channel.sessions.sessionCount();
            self.discovery_peers = discovery.engine.peerCount();
            self.discovery_lookups = @intFromBool(discovery.coordinator.lookup != null);
            self.lookup_time = discovery.coordinator.lookup_time;
            self.lookup_finishes = discovery.coordinator.lookup_finishes;
            self.discovery_pending_revalidations = discovery.engine.routing.pendingCount();
            self.discovery_waiting_queries = if (discovery.coordinator.lookup) |*lookup|
                lookup.waitingCount()
            else
                0;
            if (discovery.coordinator.last_candidate_ms) |last|
                self.discovery_candidate_idle_ms = now_ms -| last;
        }
    }

    pub fn stop(self: *Snapshot) void {
        self.running = false;
        self.scores = .{ .calls = self.scores.calls, .runs = self.scores.runs, .cache_delta = self.scores.cache_delta, .penalties = self.scores.penalties };
        self.peer_population = .{};
        self.peer_policy = .{};
        if (self.transport_resources) |*resources| resources.* = .{ .capacity = resources.capacity, .active = 0, .handshaking = 0, .dialing = 0, .outbound = 0 };
        if (self.dial_resources) |*resources| resources.* = .{ .capacity = resources.capacity };
        self.peers = 0;
        self.relevant = 0;
        self.clients = @splat(0);
        self.directions = @splat(0);
        self.mesh_clients = @splat(0);
        self.topic_count = 0;
        self.gossip_resources = null;
        self.gossip_seen = 0;
        self.gossip_history = 0;
        self.discovery_sessions = 0;
        self.discovery_peers = 0;
        self.discovery_lookups = 0;
        self.discovery_pending_revalidations = 0;
        self.discovery_waiting_queries = 0;
        self.discovery_candidate_idle_ms = null;
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
        try self.peer_population.write(w);
        try self.peer_events.write(w);
        try self.peer_policy.write(w);
        try self.connections.write(w);
        try self.writePeeringProgress(w);
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
        try counterFields(w, "lodestar_native_dial_", &self.dial);
        try counterFields(w, "lodestar_native_discovery_", &self.discovery_counts);
        try family(w, "lodestar_native_discovery_candidate_rejections_total", .counter, "Authenticated discovery candidates rejected by reason");
        inline for (@typeInfo(discovery_metrics.Rejection).@"enum".fields) |field| try sample(w, "lodestar_native_discovery_candidate_rejections_total", "reason", field.name, self.discovery_rejections[field.value]);
        try family(w, "lodestar_native_gossip_queue_drops_total", .counter, "Gossip queue admissions refused by resource limit, including mesh control");
        inline for (@typeInfo(peer_io.DropReason).@"enum".fields) |field| try sample(w, "lodestar_native_gossip_queue_drops_total", "reason", field.name, self.gossip_queue_drops[field.value]);
        try scalar(w, "lodestar_native_gossip_data_descriptors_per_peer", .gauge, "Bounded outgoing data descriptors per gossip peer", peer_io.data_capacity);
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
        try family(w, "lodestar_native_peer_closes_by_client_total", .counter, "Peer closes by identified client and local reason");
        inline for (@typeInfo(Client).@"enum".fields) |client| {
            inline for (@typeInfo(peer_types.DisconnectReason).@"enum".fields) |reason| {
                try w.print("lodestar_native_peer_closes_by_client_total{{client=\"" ++ client.name ++ "\",reason=\"" ++ reason.name ++ "\"}} {d}\n", .{self.closed_by_client[client.value][reason.value]});
            }
        }
        try family(w, "lodestar_native_peer_goodbyes_total", .counter, "Received Ethereum Goodbye reasons; unknown wire codes share one label");
        inline for (@typeInfo(goodbye.Reason).@"enum".fields) |reason| try sample(w, "lodestar_native_peer_goodbyes_total", "reason", reason.name, self.peer_events.goodbyes[reason.value]);
    }

    fn writePeeringProgress(self: *const Snapshot, w: *Writer) Writer.Error!void {
        try scalar(w, "lodestar_native_peer_identify_started_total", .counter, "Started Identify exchanges", self.identify_started);
        try scalar(w, "lodestar_native_peer_identify_deferred_total", .counter, "Identify starts deferred by local pressure", self.identify_deferred);
        try family(w, "lodestar_native_peer_identify_failures_total", .counter, "Identify failures by bounded protocol reason");
        inline for (@typeInfo(@import("identify/root.zig").Failure).@"enum".fields) |field|
            try sample(w, "lodestar_native_peer_identify_failures_total", "reason", field.name, self.identify_failures[field.value]);
        if (self.transport_resources) |*resources| {
            inline for (@typeInfo(@TypeOf(resources.*)).@"struct".fields) |field|
                try scalar(w, "lodestar_native_quic_connections_" ++ field.name, .gauge, "Native QUIC connection slots " ++ field.name, @field(resources, field.name));
        }
        if (self.dial_resources) |*resources| {
            inline for (@typeInfo(@TypeOf(resources.*)).@"struct".fields) |field|
                try scalar(w, "lodestar_native_dial_" ++ field.name, .gauge, "Native dial queue rows " ++ field.name, @field(resources, field.name));
        }
        try family(w, "lodestar_discovery_dial_time_seconds", .histogram, "Time from selecting a dial through authenticated connection or terminal failure; cancellations excluded");
        inline for (.{ "success", "error" }, 0..) |status, index|
            try prom.histogram(w, "lodestar_discovery_dial_time_seconds", "status", status, &self.dial_time[index]);
        if (!self.discovery_enabled) return;
        try family(w, "lodestar_discovery_find_node_query_time_seconds", .histogram, "Time to finish a foreground FINDNODE walk; cancelled walks excluded");
        try prom.histogram(w, "lodestar_discovery_find_node_query_time_seconds", null, "", &self.lookup_time);
        try family(w, "lodestar_native_discovery_lookup_finishes_total", .counter, "Completed foreground discovery walks by finish reason; cancellations excluded");
        inline for (@typeInfo(@import("discv5").Lookup.FinishReason).@"enum".fields) |field| {
            if (comptime !std.mem.eql(u8, field.name, "cancelled"))
                try sample(w, "lodestar_native_discovery_lookup_finishes_total", "reason", field.name, self.lookup_finishes[field.value]);
        }
        try scalar(w, "lodestar_native_discovery_pending_revalidations", .gauge, "Routing buckets waiting for incumbent revalidation", self.discovery_pending_revalidations);
        try scalar(w, "lodestar_native_discovery_waiting_queries", .gauge, "Foreground FINDNODE calls awaiting responses", self.discovery_waiting_queries);
        if (self.discovery_candidate_idle_ms) |elapsed|
            try scalar(w, "lodestar_native_discovery_candidate_idle_seconds", .gauge, "Time since the last candidate publication while running; absent before first publication", @as(f64, @floatFromInt(elapsed)) / 1000);
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
            .{ "beacon_reqresp_outgoing_requests_error_total", "outgoing_errors", "Outgoing requests with a terminal native failure, excluding local cancellation" },
            .{ "lodestar_native_reqresp_outgoing_cancelled_total", "outgoing_cancelled", "Outgoing requests cancelled by the local owner" },
            .{ "lodestar_native_reqresp_incoming_cancelled_total", "incoming_cancelled", "Incoming requests cancelled by the local owner" },
            .{ "lodestar_native_reqresp_request_write_stops_total", "request_write_stops", "Peer stops of the request write direction that retain response processing" },
            .{ "lodestar_native_reqresp_response_finish_stops_total", "response_finish_stops", "Peer stops of response FIN after complete response chunks were written" },
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
        try self.scores.write(w);
        try scalar(w, "lodestar_gossip_score_avg_min_max_min", .gauge, "Minimum connected gossip peer score", self.scores.values.min);
        try scalar(w, "lodestar_gossip_score_avg_min_max_max", .gauge, "Maximum connected gossip peer score", self.scores.values.max);
        try scalar(w, "lodestar_gossip_score_avg_min_max_avg", .gauge, "Average connected gossip peer score", self.scores.average());
        try scalar(w, "lodestar_native_gossip_scored_peers", .gauge, "Connected gossip peers included in score gauges", self.scores.values.count);
        try family(w, "lodestar_gossip_peer_score_by_threshold_count", .gauge, "Connected gossip peers at or above configured score thresholds");
        inline for (.{ "graylist", "publish", "gossip", "mesh" }) |threshold| {
            try sample(w, "lodestar_gossip_peer_score_by_threshold_count", "threshold", threshold, @field(self.scores, threshold));
        }
    }

    fn writeGossip(self: *const Snapshot, w: *Writer) Writer.Error!void {
        try self.gossip_rpc.write(w);
        try scalar(w, "gossipsub_fast_message_id_hits_total", .counter, "Exact compressed fingerprints avoiding repeated decompression", self.gossip_fast_hits);
        try scalar(w, "gossipsub_message_decode_total", .counter, "Snappy body decode attempts", self.gossip_decoded);
        try scalar(w, "gossipsub_delivery_attribution_evictions_total", .counter, "Resolved delivery records replaced before their attribution deadline", self.gossip_delivery_evictions);
        try self.gossip_recovery.write(w);
        try scalar(w, "gossipsub_rpc_recv_err_count_total", .counter, "Malformed incoming RPC frames or protobuf items", self.gossip_counts.malformed_rpcs);
        try scalar(w, "gossipsub_iwant_promise_broken", .counter, "Randomly sampled IWANT batch promises that expired without their sampled message", self.gossip_counts.broken_promises);
        try scalar(w, "gossipsub_mcache_size", .gauge, "Stored message history entries", self.gossip_history);
        try family(w, "gossipsub_cache_size", .gauge, "Native bounded cache entry counts");
        try sample(w, "gossipsub_cache_size", "cache", "seenCache", self.gossip_seen);
        try sample(w, "gossipsub_cache_size", "cache", "mcache", self.gossip_history);
        try sample(w, "gossipsub_cache_size", "cache", "deliveryCache", self.gossip_recent);
        try sample(w, "gossipsub_cache_size", "cache", "gossipTracer.promises", if (self.gossip_resources) |r| r.promises else @as(usize, 0));
        try scalar(w, "gossipsub_rpc_recv_count_total", .counter, "Complete received gossip RPCs", self.gossip_counts.rpcs_received);
        try family(w, "gossipsub_async_validation_delay_from_first_seen", .histogram, "Seconds from native gossip admission until an applied validation verdict");
        try prom.histogram(w, "gossipsub_async_validation_delay_from_first_seen", null, "", &self.validation_time);
        inline for (.{
            .{ "gossipsub_accepted_messages_total", "accepted" },
            .{ "gossipsub_rejected_messages_total", "rejected" },
            .{ "gossipsub_ignored_messages_total", "ignored" },
            .{ "gossipsub_msg_publish_count_total", "published" },
            .{ "gossipsub_msg_publish_peers_total", "published_peers" },
            .{ "gossipsub_msg_publish_bytes_total", "published_bytes", "Compressed publication bytes summed over successfully queued peer copies" },
            .{ "gossipsub_msg_received_prevalidation_total", "prevalidation", "Decoded publication items before admission, including deferred and refused items" },
            .{ "gossipsub_ihave_rcv_msgids_total", "ihave_ids", "Examined valid IHAVE IDs within processing limits" },
            .{ "gossipsub_ihave_rcv_not_seen_msgids_total", "ihave_unseen", "Examined IHAVE IDs absent from seen and pending validation caches" },
            .{ "gossipsub_iwant_rcv_msgids_total", "iwant_ids", "Examined valid unsuppressed IWANT IDs present in message history" },
            .{ "gossipsub_msg_forward_count_total", "forwarded" },
            .{ "gossipsub_msg_forward_peers_total", "forwarded_peers" },
            .{ "gossipsub_pre_validation_valid_total", "admitted" },
            .{ "gossipsub_pre_validation_duplicate_total", "duplicates" },
        }) |metric| {
            try family(w, metric[0], .counter, if (metric.len == 3) metric[2] else "Native gossip " ++ metric[1] ++ "; peer copies count successful queue admissions");
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
    return peer_client.fromIdentify(identify);
}

test "metrics format exact counters, merge protocol versions and bound maximum output" {
    var snapshot: Snapshot = .{};
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing = 4;
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing = 5;
    snapshot.protocols[@intFromEnum(rr.Protocol.metadata_v3)].request_write_stops = 7;
    snapshot.protocols[@intFromEnum(rr.Protocol.ping_v1)].response_finish_stops = 3;
    snapshot.runtime.dial_started = std.math.maxInt(u64);
    snapshot.discovery_enabled = true;
    snapshot.discovery_candidate_idle_ms = 1500;
    snapshot.lookup_time.observe(5000);
    snapshot.dial_time[1].observe(100);
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing_time.observe(100);
    snapshot.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing_time.observe(300);
    snapshot.requests.withheld_ms_total = 1500;
    for (&snapshot.scores.weights) |*ranges| for (ranges) |*range| {
        range.observe(-1e40);
        range.observe(1e40);
    };
    for (&snapshot.scores.global) |*range| range.observe(-1e40);
    for (&snapshot.scores.mesh_scores) |*range| range.observe(1e40);
    snapshot.closed_by_client[@intFromEnum(Client.Lighthouse)][@intFromEnum(peer_types.DisconnectReason.remote_goodbye)] = 13;
    snapshot.peer_events.goodbyes[@intFromEnum(goodbye.Reason.too_many_peers)] = 11;
    snapshot.gossip_queue_drops[@intFromEnum(peer_io.DropReason.data_bytes)] = 17;
    snapshot.discovery_rejections[@intFromEnum(discovery_metrics.Rejection.incompatible_fork)] = 19;
    snapshot.peer_policy.group_count = 128;
    snapshot.peer_policy.wanted = .{ .attnets = std.math.maxInt(u64), .syncnets = 15 };
    snapshot.topic_count = snapshot.topics.len;
    for (&snapshot.topics, 0..) |*entry, index| entry.* = .{ .digest = .{ 1, 2, @intCast(index / 256), @truncate(index) }, .kind = .data_column_sidecar, .subnet = 127, .mesh = 4096, .subscribers = 4096 };
    const buffer = try std.testing.allocator.alloc(u8, text_capacity);
    defer std.testing.allocator.free(buffer);
    var writer: Writer = .fixed(buffer);
    try snapshot.write(&writer);
    const log_stats: @import("logging.zig").Stats = .{};
    try log_stats.write(&writer);
    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_request_write_stops_total{method=\"metadata\"} 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_response_finish_stops_total{method=\"ping\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_total_dial_attempts 18446744073709551615\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"}"));
    try std.testing.expectEqual(Client.Lighthouse, clientKind("lighthouse/v1.2.3"));
    try std.testing.expectEqual(Client.Lodestar, clientKind("js-libp2p/1"));
    try std.testing.expectEqual(Client.Unknown, clientKind("attacker\"\nmetric 1"));
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_bucket{method=\"status\",le=\"0.1\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method=\"status\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_withheld_seconds_total 1.5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "_total_total") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_dial_time_seconds_bucket{status=\"error\",le=\"0.1\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_discovery_candidate_idle_seconds 1.5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_closes_by_client_total{client=\"Lighthouse\",reason=\"remote_goodbye\"} 13\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_goodbyes_total{reason=\"too_many_peers\"} 11\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_gossip_queue_drops_total{reason=\"data_bytes\"} 17\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_discovery_candidate_rejections_total{reason=\"incompatible_fork\"} 19\n") != null);
    snapshot.stop();
    try std.testing.expectEqual(@as(usize, 0), snapshot.topic_count);
    try std.testing.expectEqual(std.math.maxInt(u64), snapshot.runtime.dial_started);
    try std.testing.expectEqual(@as(u64, 1), snapshot.lookup_time.count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.dial_time[1].count);
    try std.testing.expect(snapshot.discovery_candidate_idle_ms == null);
}
