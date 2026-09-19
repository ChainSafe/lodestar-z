const std = @import("std");
const engine = @import("../quic/engine.zig");
const network = @import("../network_core.zig");
const rr = @import("../reqresp/root.zig");
const gossip = @import("../gossipsub/root.zig");
const topic_metrics = @import("../gossipsub/metrics.zig");
const peer_types = @import("../peers/types.zig");
const Writer = std.Io.Writer;
const peer_client = @import("../peers/client.zig");
const goodbye = @import("../peers/goodbye.zig");
const discovery_metrics = @import("../peers/discovery.zig");
const outbox = @import("../gossipsub/outbox.zig");
const score_metrics = @import("scores.zig");
const control = @import("../peers/control.zig");
const messages_mod = @import("../gossipsub/messages.zig");

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

pub const GossipCapacity = struct {
    receive_page_capacity: usize = 0,
    connected_capacity: usize = 0,
    retained_capacity: usize = 0,
    validation_capacity: usize = 0,
    delivery_descriptors_capacity: usize = 0,
};

pub const GossipHighWater = struct {
    receive_pages_high_water: usize = 0,
    data_bytes_per_row_high_water: usize = 0,
    data_descriptors_per_row_high_water: usize = 0,
    control_bytes_per_row_high_water: usize = 0,
    control_frames_per_row_high_water: usize = 0,
    critical_bytes_per_row_high_water: usize = 0,
    critical_frames_per_row_high_water: usize = 0,
};

pub const GossipResources = struct {
    receive_pages: usize = 0,
    control_frames: usize = 0,
    control_bytes: usize = 0,
    critical_frames: usize = 0,
    critical_bytes: usize = 0,
    oldest_tx_age_ms: ?u64 = null,
    inbound_streams: usize = 0,
    outbound_streams: usize = 0,
    subscription_pending_peers: usize = 0,
    delivery_descriptors_available: usize = 0,
    delivery_descriptors_reserved: usize = 0,
    admitted_peers: usize = 0,
    remote_subscriptions: usize = 0,
    mesh_members: usize = 0,
    queued_descriptors: usize = 0,
    queued_bytes: usize = 0,
    held_frames: usize = 0,
    held_tx_retains: usize = 0,
    store_entries: usize = 0,
    store_pages: usize = 0,
    pending_validations: usize = 0,
    promises: usize = 0,
};
comptime {
    for (std.meta.fields(gossip.ResourceSnapshot)) |field| {
        const owners = @as(u8, @intFromBool(@hasField(GossipCapacity, field.name))) +
            @intFromBool(@hasField(GossipHighWater, field.name)) +
            @intFromBool(@hasField(GossipResources, field.name));
        std.debug.assert(owners == 1);
    }
}

pub const RequestCapacity = struct {
    outbound_capacity: usize = 0,
    inbound_capacity: usize = 0,
    outbound_control_reserved: usize = 0,
    inbound_control_reserved: usize = 0,
    serving_capacity: usize = 0,
};
pub const RequestResources = struct {
    outbound_occupied: usize = 0,
    inbound_occupied: usize = 0,
    inbound_phases: [rr.reqresp.metrics.inbound_phase_count]usize = @splat(0),
    pending_events: usize = 0,
    pending_terminals: usize = 0,
    held_chunks: usize = 0,
    withheld_chunks: usize = 0,
    oldest_withheld_age_ms: ?u64 = null,
    serving_occupied: usize = 0,
    retiring: usize = 0,
};
pub const ControlCapacity = struct {
    operation_capacity: usize = 0,
    response_capacity: usize = 0,
};
pub const ControlResources = struct {
    operations: usize = 0,
    responses: usize = 0,
    cancelled_operations: usize = 0,
    closing: usize = 0,
};
comptime {
    for (.{ .{ rr.ReqResp.Resources, RequestCapacity, RequestResources }, .{ control.Control.Resources, ControlCapacity, ControlResources } }) |group| {
        for (std.meta.fields(group[0])) |field| {
            std.debug.assert(@hasField(group[1], field.name) != @hasField(group[2], field.name));
        }
    }
}

pub const Live = struct {
    scores: score_metrics.Snapshot = .{},
    peer_policy: @import("peer_policy.zig").Snapshot = .{},
    peer_population: @import("peers.zig").Snapshot = .{},
    discovery_pending_revalidations: usize = 0,
    discovery_waiting_queries: usize = 0,
    discovery_candidate_idle_ms: ?u64 = null,
    gossip_seen: usize = 0,
    gossip_recent: usize = 0,
    gossip_history: usize = 0,
    gossip_resources: ?GossipResources = null,
    peers: usize = 0,
    relevant: usize = 0,
    mesh_clients: [client_count]usize = @splat(0),
    topics: [gossip.constants.topics_cap]Topic = undefined,
    topic_count: usize = 0,
    discovery_sessions: usize = 0,
    discovery_peers: usize = 0,
    discovery_lookups: usize = 0,
    running: bool = false,
    transport_resources: struct { active: usize = 0, handshaking: usize = 0, dialing: usize = 0, outbound: usize = 0 } = .{},
    request_resources: RequestResources = .{},
    control_resources: ControlResources = .{},
    dial_resources: struct { occupied: usize = 0, attempts: usize = 0, connected: usize = 0, automatic: usize = 0, custody_incomplete: usize = 0 } = .{},
};

pub const Configuration = struct {
    gossip_capacity: ?GossipCapacity = null,
    target: usize = 0,
    discovery_enabled: bool = false,
    transport_capacity: ?usize = null,
    dial_capacity: ?usize = null,
    request_capacity: ?RequestCapacity = null,
    control_capacity: ?ControlCapacity = null,
};

pub const Totals = struct {
    gossip_high_water: ?GossipHighWater = null,
    runtime: network.Counters = .{},
    transport: engine.Counters = .{},
    negotiations: @import("../router.zig").Counters = .{},
    requests: rr.Counters = .{},
    udp: @import("../udp.zig").Counters = .{},
    outgoing_error_reasons: [rr.reqresp.metrics.error_reason_count]u64 = @splat(0),
    validation_time: topic_metrics.ValidationTime = .{},
    peer_work: @import("../peer_manager.zig").PeerManager.Counters = .{},
    connections: engine.ConnectionCounters = .{},
    dial_time: [2]@import("../peers/dial_queue.zig").DialTime = @splat(.{}),
    lookup_time: discovery_metrics.LookupTime = .{},
    lookup_finishes: [@typeInfo(@import("discv5").Lookup.FinishReason).@"enum".fields.len]u64 = @splat(0),
    identify_started: u64 = 0,
    identify_deferred: u64 = 0,
    identify_failures: [@typeInfo(@import("../identify/root.zig").Failure).@"enum".fields.len]u64 = @splat(0),
    protocols: [rr.Protocol.count]rr.reqresp.ProtocolCounters = @splat(.{}),
    gossip_counts: gossip.Gossipsub.Counters = .{},
    gossip_topics: topic_metrics.Topics = .{},
    gossip_rpc: topic_metrics.Rpc = .{},
    gossip_recovery: topic_metrics.Recovery = .{},
    gossip_fast_hits: u64 = 0,
    gossip_decoded: u64 = 0,
    gossip_delivery_evictions: u64 = 0,
    gossip_storage_refusals: messages_mod.StorageRefusals = @splat(0),
    closed: [@typeInfo(peer_types.DisconnectReason).@"enum".fields.len]u64 = @splat(0),
    closed_by_client: [client_count][@typeInfo(peer_types.DisconnectReason).@"enum".fields.len]u64 = @splat(@splat(0)),
    peer_events: @import("../peers/control_metrics.zig").Counters = .{},
    dial: @import("../peers/dial_queue.zig").DialQueue.Counters = .{},
    discovery_counts: discovery_metrics.Counters = .{},
    discovery_rejections: [discovery_metrics.rejection_count]u64 = @splat(0),
    discovery_admission: @import("discv5").admission.Counts = @splat(@splat(0)),
    gossip_queue_drops: [outbox.drop_reason_count]u64 = @splat(0),
    scores: score_metrics.Totals = .{},
};

/// Only the network owner collects live state. Readers copy this pointer-free snapshot
/// under the runtime mutex; labels never contain remote-controlled free-form text.
pub const Snapshot = struct {
    totals: Totals = .{},
    live: Live = .{},
    config: Configuration = .{},
    sampled_ms: u64 = 0,

    pub fn collect(self: *Snapshot, owner: *const network.NetworkCore, now_ms: u64) void {
        self.* = .{ .sampled_ms = now_ms, .live = .{ .running = true } };
        self.collectOwner(owner);
        self.collectPeers(owner, now_ms);
        self.collectDiscovery(owner, now_ms);
    }

    fn collectOwner(self: *Snapshot, owner: *const network.NetworkCore) void {
        const core = &owner.peer_manager;
        const g = owner.service.gossipsub;
        self.totals.runtime = owner.counters;
        self.totals.transport = owner.transport.engine.counters;
        self.totals.negotiations = owner.service.router.counters;
        self.totals.connections = owner.transport.engine.connection_metrics;
        const transport_resources = owner.transport.engine.resourceSnapshot();
        self.config.transport_capacity = transport_resources.capacity;
        inline for (std.meta.fields(@TypeOf(self.live.transport_resources))) |field| {
            @field(self.live.transport_resources, field.name) = @field(transport_resources, field.name);
        }
        const dial_resources = core.dial_queue.resourceSnapshot();
        self.config.dial_capacity = dial_resources.capacity;
        inline for (std.meta.fields(@TypeOf(self.live.dial_resources))) |field| {
            @field(self.live.dial_resources, field.name) = @field(dial_resources, field.name);
        }
        self.totals.dial_time = core.dial_queue.durations;
        self.totals.requests = owner.service.reqresp.counters;
        const request_resources = owner.service.reqresp.resourceSnapshot();
        const control_resources = core.control.resourceSnapshot();
        self.collectRequestResources(&request_resources, &control_resources);
        self.totals.udp = owner.transport.udp.counters;
        self.totals.outgoing_error_reasons = owner.service.reqresp.outgoing_error_reasons;
        self.totals.validation_time = g.validation_time;
        self.totals.protocols = owner.service.reqresp.protocol_counters;
        self.totals.gossip_counts = g.counters;
        self.totals.gossip_topics = g.topic_metrics;
        self.totals.gossip_rpc = g.rpc_metrics;
        self.totals.gossip_recovery = g.recovery.metrics;
        const messages = g.messages.stats();
        self.live.gossip_seen = messages.seen;
        self.totals.gossip_fast_hits = messages.fast_hits;
        self.totals.gossip_decoded = messages.decoded;
        self.live.gossip_recent = messages.recent;
        self.totals.gossip_delivery_evictions = messages.delivery_evictions;
        self.totals.gossip_storage_refusals = messages.storage_refusals;
        self.live.gossip_history = messages.history;
        const resources = g.resourceSnapshot();
        self.collectGossipResources(&resources);
        self.totals.closed = core.control.counters.closed;
        self.totals.identify_started = core.control.counters.identify_started;
        self.totals.identify_deferred = core.control.counters.identify_deferred;
        self.totals.identify_failures = core.control.counters.identify_failures;
        self.totals.closed_by_client = core.control.counters.closed_by_client;
        self.totals.peer_events = core.control.counters.events;
        self.totals.peer_work = core.counters;
        self.totals.dial = core.dial_queue.counters;
        for (g.sessions.rows) |*session| {
            const io = &session.io;
            for (&self.totals.gossip_queue_drops, io.tx.drops) |*total, value| total.* +|= value;
        }
        self.totals.scores.calls = g.peers.scores.calls;
        self.totals.scores.runs = g.peers.scores.calculations;
        self.totals.scores.cache_delta = g.peers.scores.cache_delta;
        self.totals.scores.penalties = g.peers.scores.penalties;
    }

    fn collectRequestResources(self: *Snapshot, requests: *const rr.ReqResp.Resources, controls: *const control.Control.Resources) void {
        self.config.request_capacity = .{};
        self.config.control_capacity = .{};
        inline for (std.meta.fields(RequestCapacity)) |field| @field(self.config.request_capacity.?, field.name) = @field(requests, field.name);
        inline for (std.meta.fields(RequestResources)) |field| @field(self.live.request_resources, field.name) = @field(requests, field.name);
        inline for (std.meta.fields(ControlCapacity)) |field| @field(self.config.control_capacity.?, field.name) = @field(controls, field.name);
        inline for (std.meta.fields(ControlResources)) |field| @field(self.live.control_resources, field.name) = @field(controls, field.name);
    }

    fn collectGossipResources(self: *Snapshot, resources: *const gossip.ResourceSnapshot) void {
        self.config.gossip_capacity = .{};
        self.totals.gossip_high_water = .{};
        self.live.gossip_resources = .{};
        inline for (std.meta.fields(GossipCapacity)) |field| {
            @field(self.config.gossip_capacity.?, field.name) = @field(resources, field.name);
        }
        inline for (std.meta.fields(GossipHighWater)) |field| {
            @field(self.totals.gossip_high_water.?, field.name) = @field(resources, field.name);
        }
        inline for (std.meta.fields(GossipResources)) |field| {
            @field(self.live.gossip_resources.?, field.name) = @field(resources, field.name);
        }
    }

    fn collectPeers(self: *Snapshot, owner: *const network.NetworkCore, now_ms: u64) void {
        const core = &owner.peer_manager;
        const g = owner.service.gossipsub;
        self.config.target = core.catalog.options.target_peers;
        self.live.peer_policy.collect(&core.selection, &core.demand, core.current_slot, core.local.fork.custody_groups);
        for (core.control.schedules) |*schedule| {
            self.live.peer_policy.managed_connections += @intFromBool(schedule.peer != null);
        }
        var clients: @import("peers.zig").ConnectionClients = .{};
        for (core.catalog.rows) |*row| {
            self.live.peer_policy.catalog_entries += @intFromBool(row.occupied);
            if (row.connection == null) continue;
            self.live.peers += 1;
            const client = peer_client.fromIdentify(&row.identify);
            clients.put(row.connection.?, client);
            self.live.peer_population.observe(row, client, now_ms);
            self.live.relevant += @intFromBool(row.status != null);
        }
        var mesh_peers = gossip.sessions.PeerSet.initEmpty();
        var meshes: [score_metrics.kind_count]gossip.sessions.PeerSet = @splat(.initEmpty());
        var score_kinds: score_metrics.TopicKinds = @splat(null);
        self.collectTopics(owner, &mesh_peers, &meshes, &score_kinds);
        for (g.sessions.rows, 0..) |*row, index| {
            if (!row.active) continue;
            var breakdown: gossip.score.Breakdown = undefined;
            const score = g.peers.snapshotWeights(row.logical, now_ms, &breakdown);
            self.live.scores.observe(score, &g.peers.scores.params);
            self.live.scores.observeWeights(&breakdown, &score_kinds);
            for (&meshes, &self.live.scores.mesh_scores) |*mesh, *range| {
                if (mesh.isSet(index)) range.observe(score);
            }
            const client = clients.get(row.conn);
            self.live.peer_population.gossip_scores[@intFromEnum(client)].observe(score);
            if (!mesh_peers.isSet(index)) continue;
            self.live.mesh_clients[@intFromEnum(client)] += 1;
        }
    }

    fn collectTopics(
        self: *Snapshot,
        owner: *const network.NetworkCore,
        mesh_peers: *gossip.sessions.PeerSet,
        meshes: *[score_metrics.kind_count]gossip.sessions.PeerSet,
        score_kinds: *score_metrics.TopicKinds,
    ) void {
        const core = &owner.peer_manager;
        const g = owner.service.gossipsub;
        for (&g.overlay.rows, 0..) |*row, topic_index| {
            if (!row.active) continue;
            mesh_peers.setUnion(row.mesh);
            const parsed = gossip.topic.parse(row.string[0..row.string_len]) orelse continue;
            const label = gossip.topic.Name.parse(parsed.name);
            const kind: u8 = if (label) |known| @intFromEnum(known.kind) else gossip.topic_policy.kind_count;
            score_kinds[topic_index] = kind;
            meshes[kind].setUnion(row.mesh);
            var configured = std.mem.eql(u8, &parsed.digest, &core.local.fork.digest);
            if (g.overlay.namespace) |*namespace| for (namespace.boundaries) |*boundary| {
                if (std.mem.eql(u8, &parsed.digest, &boundary.digest)) {
                    configured = true;
                    break;
                }
            };
            if (!configured) continue;
            const known = label orelse continue;
            const subnet = if (known.kind == .blob_sidecar) 0 else known.subnet;
            var found = false;
            for (self.live.topics[0..self.live.topic_count]) |*entry| {
                if (entry.kind == known.kind and entry.subnet == subnet and std.mem.eql(u8, &entry.digest, &parsed.digest)) {
                    entry.mesh += row.mesh.count();
                    entry.subscribers += row.subscribers.count();
                    found = true;
                    break;
                }
            }
            if (found) continue;
            std.debug.assert(self.live.topic_count < self.live.topics.len);
            self.live.topics[self.live.topic_count] = .{ .digest = parsed.digest, .kind = known.kind, .subnet = subnet, .mesh = row.mesh.count(), .subscribers = row.subscribers.count() };
            self.live.topic_count += 1;
        }
    }

    fn collectDiscovery(self: *Snapshot, owner: *const network.NetworkCore, now_ms: u64) void {
        if (owner.discovery) |discovery| {
            self.totals.discovery_counts = discovery.coordinator.counters;
            self.totals.discovery_rejections = discovery.coordinator.rejections;
            self.totals.discovery_admission = discovery.transport.engine.channel.admission.counts;
            self.config.discovery_enabled = true;
            self.live.discovery_sessions = discovery.transport.engine.channel.sessions.sessionCount();
            self.live.discovery_peers = discovery.transport.engine.peerCount();
            self.live.discovery_lookups = @intFromBool(discovery.coordinator.lookup != null);
            self.totals.lookup_time = discovery.coordinator.lookup_time;
            self.totals.lookup_finishes = discovery.coordinator.lookup_finishes;
            self.live.discovery_pending_revalidations = discovery.transport.engine.routing.pendingCount();
            self.live.discovery_waiting_queries = if (discovery.coordinator.lookup) |*lookup|
                lookup.waitingCount()
            else
                0;
            if (discovery.coordinator.last_candidate_ms) |last|
                self.live.discovery_candidate_idle_ms = now_ms -| last;
        }
    }

    pub fn stop(self: *Snapshot) void {
        self.live = .{};
    }

    pub fn write(self: *const Snapshot, writer: *Writer) @import("registry.zig").Error!void {
        try @import("collectors.zig").registry.write(self, writer);
    }
};

test "metrics format exact counters, merge protocol versions and bound maximum output" {
    var snapshot: Snapshot = .{};
    var resources = std.mem.zeroes(gossip.ResourceSnapshot);
    resources.oldest_tx_age_ms = std.math.maxInt(u64);
    snapshot.collectGossipResources(&resources);
    snapshot.config.transport_capacity = 1024;
    snapshot.config.dial_capacity = 4096;
    snapshot.collectRequestResources(&.{
        .outbound_capacity = 16,
        .inbound_capacity = 32,
        .held_chunks = 2,
        .withheld_chunks = 3,
        .oldest_withheld_age_ms = 1500,
    }, &.{ .operation_capacity = 8, .response_capacity = 12, .operations = 4 });
    snapshot.totals.peer_work.rejected = 7;
    snapshot.totals.gossip_storage_refusals[@intFromEnum(messages_mod.StorageRefusal.peer_validations)] = 11;
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing = 4;
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing = 5;
    const refused_reason = @intFromEnum(rr.reqresp.metrics.AdmissionRefusal.server_capacity);
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v1)].admission_refusals[refused_reason] = 2;
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v2)].admission_refusals[refused_reason] = 3;
    snapshot.live.request_resources.inbound_phases[@intFromEnum(rr.reqresp.metrics.InboundPhase.receiving_request)] = 7;
    snapshot.live.request_resources.inbound_phases[@intFromEnum(rr.reqresp.metrics.InboundPhase.waiting_host)] = 2;
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.metadata_v3)].request_write_stops = 7;
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.ping_v1)].response_finish_stops = 3;
    snapshot.totals.runtime.dial_started = std.math.maxInt(u64);
    snapshot.config.discovery_enabled = true;
    snapshot.live.discovery_candidate_idle_ms = 1500;
    snapshot.totals.lookup_time.observe(5000);
    snapshot.totals.dial_time[1].observe(100);
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v1)].outgoing_time.observe(100);
    snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v2)].outgoing_time.observe(300);
    snapshot.totals.requests.withheld_ms_total = 1500;
    snapshot.totals.requests.error_responses_sent = 3;
    snapshot.totals.requests.malformed = 2;
    snapshot.totals.requests.timeouts = 7;
    snapshot.totals.peer_work.candidate_syncs = 2;
    snapshot.totals.peer_work.candidate_rows = 32;
    snapshot.totals.peer_work.candidate_lookup_rows = 8;
    snapshot.totals.peer_work.catalog_deadline_rows = 64;
    snapshot.totals.dial.sync_lookup_rows = 96;
    for (&snapshot.live.scores.weights) |*ranges| for (ranges) |*range| {
        range.observe(-1e40);
        range.observe(1e40);
    };
    for (&snapshot.live.scores.global) |*range| range.observe(-1e40);
    for (&snapshot.live.scores.mesh_scores) |*range| range.observe(1e40);
    snapshot.totals.closed_by_client[@intFromEnum(Client.Lighthouse)][@intFromEnum(peer_types.DisconnectReason.remote_goodbye)] = 13;
    snapshot.totals.peer_events.goodbyes[@intFromEnum(goodbye.Reason.too_many_peers)] = 11;
    snapshot.totals.gossip_queue_drops[@intFromEnum(outbox.DropReason.data_bytes)] = 17;
    snapshot.totals.discovery_rejections[@intFromEnum(discovery_metrics.Rejection.incompatible_fork)] = 19;
    const discovery_admission = @import("discv5").admission;
    snapshot.totals.discovery_admission[@intFromEnum(discovery_admission.Stage.handshake)][@intFromEnum(discovery_admission.Outcome.source_limit)] = 23;
    snapshot.live.peer_policy.group_count = 128;
    snapshot.live.peer_policy.wanted = .{ .attnets = std.math.maxInt(u64), .syncnets = 15 };
    snapshot.live.topic_count = snapshot.live.topics.len;
    for (&snapshot.live.topics, 0..) |*entry, index| entry.* = .{ .digest = .{ 1, 2, @intCast(index / 256), @truncate(index) }, .kind = .data_column_sidecar, .subnet = 127, .mesh = 4096, .subscribers = 4096 };
    const buffer = try std.testing.allocator.alloc(u8, text_capacity);
    defer std.testing.allocator.free(buffer);
    var writer: Writer = .fixed(buffer);
    const log_stats: @import("../logging.zig").Stats = .{};
    try write(&snapshot, &log_stats, &writer);
    const output = writer.buffered();
    for ([_][]const u8{
        "lodestar_native_reqresp_resources_outbound_capacity 16\n",
        "lodestar_native_reqresp_resources_inbound_capacity 32\n",
        "lodestar_native_reqresp_resources_held_chunks 2\n",
        "lodestar_native_reqresp_resources_withheld_chunks 3\n",
        "lodestar_native_reqresp_resources_oldest_withheld_age_seconds 1.5\n",
        "lodestar_native_control_operation_capacity 8\n",
        "lodestar_native_control_operations 4\n",
        "lodestar_native_peer_processing_total{operation=\"rejected\"} 7\n",
        "lodestar_native_gossipsub_storage_refusals_total{reason=\"peer_validations\"} 11\n",
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
    var lines = std.mem.splitScalar(u8, output, '\n');
    var current_family: []const u8 = "";
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "# TYPE ")) {
            current_family = line[7..std.mem.lastIndexOfScalar(u8, line, ' ').?];
        } else if (line.len > 0 and line[0] != '#') {
            const end = std.mem.indexOfAny(u8, line, "{ ").?;
            const name = line[0..end];
            try std.testing.expect(std.mem.startsWith(u8, name, current_family));
            const suffix = name[current_family.len..];
            try std.testing.expect(suffix.len == 0 or std.mem.eql(u8, suffix, "_bucket") or
                std.mem.eql(u8, suffix, "_count") or std.mem.eql(u8, suffix, "_sum"));
        }
    }
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"} 9\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_admission_refusals_total{method=\"status\",reason=\"server_capacity\"} 5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_inbound_occupied{phase=\"receiving_request\"} 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_inbound_occupied{phase=\"waiting_host\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_request_write_stops_total{method=\"metadata\"} 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_response_finish_stops_total{method=\"ping\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_total_dial_attempts 18446744073709551615\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "beacon_reqresp_outgoing_requests_total{method=\"status\"}"));
    try std.testing.expectEqual(Client.Lighthouse, peer_client.kind("lighthouse/v1.2.3"));
    try std.testing.expectEqual(Client.Lodestar, peer_client.kind("js-libp2p/1"));
    try std.testing.expectEqual(Client.Unknown, peer_client.kind("attacker\"\nmetric 1"));
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_bucket{method=\"status\",le=\"0.1\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method=\"status\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_withheld_seconds_total 1.5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_error_responses_sent_total 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_malformed_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_reqresp_timeouts_total 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "_total_total") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_discovery_dial_time_seconds_bucket{status=\"error\",le=\"0.1\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_discovery_candidate_idle_seconds 1.5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_closes_by_client_total{client=\"Lighthouse\",reason=\"remote_goodbye\"} 13\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_goodbyes_total{reason=\"too_many_peers\"} 11\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_gossip_queue_drops_total{reason=\"data_bytes\"} 17\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_discovery_candidate_rejections_total{reason=\"incompatible_fork\"} 19\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_discovery_admission_total{stage=\"handshake\",outcome=\"source_limit\"} 23\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_processing_total{operation=\"candidate_syncs\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_processing_total{operation=\"candidate_rows\"} 32\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_processing_total{operation=\"candidate_lookup_rows\"} 8\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_processing_total{operation=\"catalog_deadline_rows\"} 64\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "lodestar_native_peer_processing_total{operation=\"dial_sync_lookup_rows\"} 96\n") != null);
    try std.testing.expectEqual(@as(usize, 13), std.mem.count(u8, output, "lodestar_native_peer_processing_total{operation="));
    snapshot.live.gossip_recent = 7;
    snapshot.stop();
    try std.testing.expectEqual(@as([rr.reqresp.metrics.inbound_phase_count]usize, @splat(0)), snapshot.live.request_resources.inbound_phases);
    try std.testing.expectEqual(@as(u64, 2), snapshot.totals.protocols[@intFromEnum(rr.Protocol.status_v1)].admission_refusals[refused_reason]);
    try std.testing.expectEqual(@as(usize, 0), snapshot.live.gossip_recent);
    try std.testing.expectEqual(@as(usize, 0), snapshot.live.topic_count);
    try std.testing.expectEqual(std.math.maxInt(u64), snapshot.totals.runtime.dial_started);
    try std.testing.expectEqual(@as(u64, 1), snapshot.totals.lookup_time.count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.totals.dial_time[1].count);
    try std.testing.expectEqual(@as(u64, 64), snapshot.totals.peer_work.catalog_deadline_rows);
    try std.testing.expectEqual(@as(u64, 96), snapshot.totals.dial.sync_lookup_rows);
    try std.testing.expect(snapshot.live.discovery_candidate_idle_ms == null);
}

pub fn write(snapshot: *const Snapshot, logs: *const @import("../logging.zig").Stats, writer: *Writer) @import("registry.zig").Error!void {
    var encoder: @import("registry.zig").Encoder = .{ .writer = writer };
    try @import("collectors.zig").registry.collect(snapshot, &encoder);
    try logs.write(&encoder);
}

test "metrics shutdown clears live state and retains all cumulative and configuration groups" {
    var snapshot: Snapshot = .{};
    snapshot.sampled_ms = 1234;
    snapshot.config = .{
        .target = 16,
        .discovery_enabled = true,
        .transport_capacity = 32,
        .dial_capacity = 48,
    };
    snapshot.totals.runtime.dial_started = 7;
    snapshot.totals.lookup_time.observe(5000);
    snapshot.totals.scores.calls = 9;
    snapshot.totals.scores.cache_delta.observe(10);
    snapshot.live.running = true;
    snapshot.live.peers = 3;
    snapshot.live.discovery_sessions = 2;
    snapshot.live.discovery_candidate_idle_ms = 100;
    snapshot.live.transport_resources.active = 3;
    snapshot.live.dial_resources.attempts = 1;
    snapshot.live.scores.observe(-10, &.{});
    var resources = std.mem.zeroes(gossip.ResourceSnapshot);
    resources.connected_capacity = 32;
    resources.queued_bytes = 5;
    resources.control_bytes_per_row_high_water = 8;
    snapshot.collectGossipResources(&resources);
    const totals = snapshot.totals;
    const config = snapshot.config;
    snapshot.stop();
    const empty: Live = .{};
    inline for (std.meta.fields(Live)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "topics")) {
            try std.testing.expectEqualDeep(@field(empty, field.name), @field(snapshot.live, field.name));
        }
    }
    try std.testing.expectEqualDeep(totals, snapshot.totals);
    try std.testing.expectEqualDeep(config, snapshot.config);
    try std.testing.expectEqual(@as(u64, 1234), snapshot.sampled_ms);
    snapshot.stop();
    try std.testing.expectEqualDeep(totals, snapshot.totals);
}
