const std = @import("std");
const types = @import("../types.zig");
const rr = @import("../reqresp/root.zig");
const gossip = @import("../gossipsub/root.zig");
const peer_types = @import("../peers/types.zig");
const prom = @import("registry.zig");
const peer_client = @import("../peers/client.zig");
const goodbye = @import("../peers/goodbye.zig");
const discovery_metrics = @import("../peers/discovery.zig");
const outbox = @import("../gossipsub/outbox.zig");

const Context = @import("context.zig").Context;
const Client = peer_client.Client;
pub const registry = prom.Registry(Context, .{
    writePeers,
    writeTopics,
    writeRequests,
    writeRequestTimes,
    writeGossip,
    writeGossipScores,
    writeGossipExecution,
    writePopulation,
    writePeerEvents,
    writePeerPolicy,
    writeConnections,
    writeTransportConnections,
    writeRuntime,
    writeNativeCounters,
    writeSockets,
    writeGossipResources,
    writeRequestResources,
    writePeerCloses,
    writeRememberedPeers,
    writeDiscoveryProgress,
    writeGossipTopics,
    writeBridge,
});

fn writePeers(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "libp2p_peers",
        .kind = .gauge,
        .help = "Authenticated connected peers",
    }, self.peer_count);
    try w.scalar(.{
        .name = "lodestar_native_network_relevant_peers",
        .kind = .gauge,
        .help = "Peers with compatible Status",
    }, self.relevant);
    try w.scalar(.{
        .name = "lodestar_native_peer_below_target",
        .kind = .gauge,
        .help = "Connected peers below target while running",
    }, @intFromBool(self.running and self.peer_count < self.owner.peer_manager.catalog.options.target_peers));
    const directions = try w.family(.{
        .name = "lodestar_peers_by_direction_count",
        .kind = .gauge,
        .help = "Connected peers by direction",
        .labels = &.{"direction"},
    });
    for ([_][]const u8{ "inbound", "outbound" }, self.population.directionCounts()) |direction, count| try directions.sample(.{direction}, count);
    const clients = try w.family(.{
        .name = "lodestar_peers_by_client_count",
        .kind = .gauge,
        .help = "Connected peers by client",
        .labels = &.{"client"},
    });
    inline for (std.meta.fields(Client)) |field| try clients.sample(.{field.name}, self.population.clientCount(@enumFromInt(field.value)));
}

fn writeRuntime(self: *const Context, w: *prom.Encoder) prom.Error!void {
    if (self.owner.discovery) |discovery| {
        try w.scalar(.{ .name = "lodestar_discv5_active_session_count", .kind = .gauge, .help = "Stored discovery sessions" }, self.live(discovery.transport.engine.channel.sessions.sessionCount()));
        try w.scalar(.{ .name = "lodestar_discv5_kad_table_size", .kind = .gauge, .help = "Discovery routing table entries" }, self.live(discovery.transport.engine.peerCount()));
    }
    try w.scalar(.{ .name = "lodestar_native_network_metrics_updated_timestamp_seconds", .kind = .gauge, .help = "Unix time at which the owner last collected this metrics export", .unit = .seconds }, self.now.unix_s);
    try w.scalar(.{ .name = "lodestar_native_network_running", .kind = .gauge, .help = "Network owner is running" }, @intFromBool(self.running));
    try w.scalar(.{ .name = "lodestar_native_network_transport_failures_total", .kind = .counter, .help = "Failed owner clock reads and transport receive steps" }, self.owner.counters.transport_failures);
    try w.scalar(.{ .name = "lodestar_native_network_readiness_failures_total", .kind = .counter, .help = "Failed owner readiness polls" }, self.owner.counters.readiness_failures);
    const steps = try w.histograms(.{ .name = "lodestar_native_network_step_seconds", .kind = .histogram, .help = "Network step duration after native readiness polling, covering transport, protocols and discovery", .unit = .seconds }, @import("timing.zig").Duration);
    try steps.histogram(.{}, &self.owner.step_duration);
}

fn writeNativeCounters(self: *const Context, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "received_bytes", "Complete QUIC UDP payload bytes received, excluding truncated datagrams" },
        .{ "sent_bytes", "QUIC UDP payload bytes sent, including successful prefixes of failed batches" },
        .{ "received_datagrams", "QUIC UDP datagrams received, including truncated datagrams" },
        .{ "sent_datagrams", "QUIC UDP datagrams sent" },
    }) |metric| try w.scalar(.{
        .name = "lodestar_native_quic_udp_" ++ metric[0] ++ "_total",
        .kind = .counter,
        .help = metric[1],
    }, @field(self.owner.transport.udp.counters, metric[0]));
    const udp = @import("udp");
    const discovery_drops = if (self.owner.discovery) |d| d.transport.send_drops else udp.SendDrops{};
    inline for (.{ "datagrams", "bytes" }) |measure| {
        const dropped = try w.family(.{
            .name = "lodestar_native_udp_send_dropped_" ++ measure ++ "_total",
            .kind = .counter,
            .help = "UDP " ++ measure ++ " discarded before kernel acceptance due to temporary local send pressure",
            .labels = &.{ "role", "reason" },
        });
        inline for (std.meta.fields(udp.SendPressure)) |reason| {
            try dropped.sample(.{ "quic", reason.name }, @field(self.owner.transport.udp.send_drops, measure)[reason.value]);
            try dropped.sample(.{ "discovery", reason.name }, @field(discovery_drops, measure)[reason.value]);
        }
    }
    const refused = try w.family(.{
        .name = "lodestar_native_dial_recent_failures_refused_total",
        .kind = .counter,
        .help = "Discovered candidates refused because every endpoint recently failed, or because the identity recently rejected us, by that rejection",
        .labels = &.{"reason"},
    });
    const refusals = &self.owner.peer_manager.dialing.refused;
    try refused.sample(.{"endpoint"}, refusals.endpoint);
    inline for (std.meta.fields(peer_types.Rejection)) |field| try refused.sample(.{field.name}, refusals.identity[field.value]);
    const discovery_counts = if (self.owner.discovery) |d| d.coordinator.counters else discovery_metrics.Counters{};
    const rejections = if (self.owner.discovery) |d| d.coordinator.rejections else @as([discovery_metrics.rejection_count]u64, @splat(0));
    const datagram_rejections = if (self.owner.discovery) |d| d.coordinator.datagram_rejections else @as([discovery_metrics.datagram_rejection_count]u64, @splat(0));
    try w.scalar(.{ .name = "lodestar_native_discovery_lookups_started_total", .kind = .counter, .help = "Foreground discovery lookups started" }, discovery_counts.lookups_started);
    try w.scalar(.{ .name = "lodestar_native_discovery_candidates_published_total", .kind = .counter, .help = "Authenticated discovery candidates handed to peer selection" }, discovery_counts.candidates_published);
    try w.enums(.{
        .name = "lodestar_native_discovery_candidate_rejections_total",
        .kind = .counter,
        .help = "Authenticated discovery candidates rejected by reason",
        .labels = &.{"reason"},
    }, discovery_metrics.Rejection, &rejections);
    const rejected = try w.family(.{
        .name = "lodestar_native_discovery_datagram_rejections_total",
        .kind = .counter,
        .help = "Received discovery datagrams rejected by processing stage and reason",
        .labels = &.{ "stage", "reason" },
    });
    inline for (std.meta.fields(@import("discv5").types.RejectReason)) |field| {
        try rejected.sample(.{ comptime rejectStage(@enumFromInt(field.value)), field.name }, datagram_rejections[field.value]);
    }
    var drops = self.owner.service.gossipsub.retired_queue_drops;
    for (self.owner.service.gossipsub.sessions.rows) |*row| for (&drops, row.io.tx.drops) |*total, value| {
        total.* +|= value;
    };
    try w.enums(.{
        .name = "lodestar_native_gossip_queue_drops_total",
        .kind = .counter,
        .help = "Gossip queue admissions refused by resource limit, including mesh control",
        .labels = &.{"reason"},
    }, outbox.DropReason, &drops);
}

fn writeSockets(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const Sockets = @import("udp").Sockets;
    const roles = [_]struct { []const u8, ?*const Sockets }{
        .{ "quic", &self.owner.transport.udp.sockets },
        .{ "discovery", if (self.owner.discovery) |d| &d.transport.sockets else null },
    };
    const families = [_][]const u8{ "ip4", "ip6" };
    const buffers = try w.family(.{
        .name = "lodestar_native_udp_socket_buffer_bytes",
        .kind = .gauge,
        .help = "UDP socket buffer size as the kernel reports it; Linux reports double the size it grants",
        .labels = &.{ "role", "family", "direction" },
    });
    for (roles) |role| for ((role[1] orelse continue).buffers, families) |reported, family| {
        const sizes = reported orelse continue;
        if (sizes.receive) |bytes| try buffers.sample(.{ role[0], family, "receive" }, bytes);
        if (sizes.send) |bytes| try buffers.sample(.{ role[0], family, "send" }, bytes);
    };
    const drops = try w.family(.{
        .name = "lodestar_native_udp_socket_drops_total",
        .kind = .counter,
        .help = "Datagrams the kernel dropped at the socket, mostly on a full receive buffer; Linux only",
        .labels = &.{ "role", "family" },
    });
    for (roles, self.socket_drops) |role, counts| for (counts, families) |count, family| {
        try drops.sample(.{ role[0], family }, count orelse continue);
    };
}

fn writeGossipResources(self: *const Context, w: *prom.Encoder) prom.Error!void {
    var resources = self.owner.service.gossipsub.resourceSnapshot();
    if (!self.running) {
        resources.receive_pages = 0;
        resources.pending_validations = 0;
        resources.delivery_descriptors_available = resources.delivery_descriptors_capacity;
        resources.queued_bytes = 0;
        resources.store_pages = 0;
    }
    inline for (.{
        .{ "receive_pages", "Receive pages holding partial inbound frames" },
        .{ "receive_page_capacity", "Receive pages the pool holds" },
        .{ "validation_capacity", "Messages the validation table holds" },
        .{ "pending_validations", "Admitted messages awaiting a verdict" },
        .{ "delivery_descriptors_capacity", "Outgoing data descriptors the shared pool holds" },
        .{ "delivery_descriptors_available", "Outgoing data descriptors free in the shared pool" },
        .{ "queued_bytes", "Compressed bytes queued to peers as data frames" },
        .{ "store_pages", "Message store pages in use" },
    }) |field| try w.scalar(.{
        .name = "lodestar_native_gossipsub_" ++ field[0],
        .kind = .gauge,
        .help = field[1],
    }, @field(resources, field[0]));
}
fn writeRequestResources(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const requests = self.owner.service.reqresp.resourceSnapshot();
    try w.scalar(.{ .name = "lodestar_native_reqresp_resources_serving_capacity", .kind = .gauge, .help = "Incoming requests the host may serve at once" }, requests.serving_capacity);
    try w.scalar(.{ .name = "lodestar_native_reqresp_resources_serving_occupied", .kind = .gauge, .help = "Incoming requests the host is serving" }, self.live(requests.serving_occupied));
    try w.scalar(.{ .name = "lodestar_native_reqresp_resources_retiring", .kind = .gauge, .help = "Serving resources awaiting host retirement" }, self.live(requests.retiring));
}

fn writePeerCloses(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try w.enums(.{
        .name = "lodestar_native_peer_closes_total",
        .kind = .counter,
        .help = "Peer closes initiated by native peer control",
        .labels = &.{"reason"},
    }, peer_types.DisconnectReason, &self.owner.peer_manager.control.counters.closed);
    try w.enums(.{
        .name = "lodestar_native_peer_rejections_total",
        .kind = .counter,
        .help = "Remote rejections recorded against peer identities by kind: a received Goodbye, or a remote close of our dial or its refusal of our Status before the Status and Metadata exchange completed",
        .labels = &.{"kind"},
    }, peer_types.Rejection, &self.owner.peer_manager.catalog.rejections);
    try w.enums(.{
        .name = "lodestar_native_peer_health_failures_total",
        .kind = .counter,
        .help = "Failed Status, Metadata and Ping probes; a streak of failures disconnects at its limit and a refused probe at once",
        .labels = &.{"probe"},
    }, @import("../peers/control.zig").HealthProbe, &self.owner.peer_manager.control.counters.health_failures);
}

fn writeRememberedPeers(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const remembered = @import("../peers/remembered.zig");
    const memory = &self.owner.peer_manager.catalog.remembered;
    try w.scalar(.{
        .name = "lodestar_native_remembered_peers",
        .kind = .gauge,
        .help = "Remembered peers held for the host to persist",
    }, memory.count);
    try w.enums(.{
        .name = "lodestar_native_remembered_peer_seeds_total",
        .kind = .counter,
        .help = "Remembered peers passed at startup: loaded, or dropped as expired, duplicate or invalid",
        .labels = &.{"outcome"},
    }, remembered.Seed, &memory.counters.seeds);
    try w.enums(.{
        .name = "lodestar_native_remembered_peer_replays_total",
        .kind = .counter,
        .help = "Loaded remembered peers visited by replay: queued as a candidate, already connected or a candidate, refused by the identity's rejection memory or the endpoint's failure history, or without candidate room",
        .labels = &.{"outcome"},
    }, remembered.Replay, &memory.counters.replays);
    const funnel = try w.family(.{
        .name = "lodestar_native_peer_dial_funnel_total",
        .kind = .counter,
        .help = "Automatic dials by candidate origin, remembered or fresh from discovery, and stage: started, connected, and kept five minutes with a completed Status and Metadata exchange",
        .labels = &.{ "origin", "stage" },
    });
    inline for (std.meta.fields(remembered.Origin)) |origin| {
        inline for (std.meta.fields(remembered.Stage)) |stage| {
            try funnel.sample(.{ origin.name, stage.name }, memory.counters.funnel[origin.value][stage.value]);
        }
    }
}

fn writeTransportConnections(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const transport = self.owner.transport.engine.resourceSnapshot();
    try w.scalar(.{ .name = "lodestar_native_quic_connections_active", .kind = .gauge, .help = "Live QUIC connections, handshaking or established" }, self.live(transport.active));
    try w.scalar(.{ .name = "lodestar_native_quic_connections_handshaking", .kind = .gauge, .help = "QUIC connections still handshaking" }, self.live(transport.handshaking));
}

fn writeDiscoveryProgress(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try w.enums(.{ .name = "lodestar_native_peer_dial_selections_total", .kind = .counter, .help = "Selected peer connection attempts by initiating demand, including immediate errors and local start deferrals", .labels = &.{"source"} }, @import("../peers/dialing.zig").Source, &self.owner.peer_manager.dialing.selected_attempts);
    try w.enums(.{ .name = "lodestar_native_peer_dial_outcomes_total", .kind = .counter, .help = "Finished connection attempts by outcome; closes before admission map the transport close reason", .labels = &.{"outcome"} }, peer_types.DialOutcome, &self.owner.peer_manager.dialing.outcomes);
    const dialing = @import("../peers/dialing.zig");
    const times = try w.histograms(.{
        .name = "lodestar_native_peer_dial_time_seconds",
        .kind = .histogram,
        .help = "Selected connection attempts from selection to outcome, including local start deferrals; a connected attempt ends at connection admission, before Status and Metadata",
        .labels = &.{"outcome"},
        .unit = .seconds,
    }, dialing.DialTime);
    inline for (std.meta.fields(peer_types.DialOutcome)) |field| try times.histogram(.{field.name}, &self.owner.peer_manager.dialing.durations[field.value]);
    try w.enums(.{ .name = "lodestar_native_peer_dial_retries_total", .kind = .counter, .help = "Redials of an endpoint by its previous failure", .labels = &.{"previous"} }, peer_types.DialFailure, &self.owner.peer_manager.dialing.retries);
    const discovery = self.owner.discovery orelse return;
    const lookup_finishes = try w.family(.{
        .name = "lodestar_native_discovery_lookup_finishes_total",
        .kind = .counter,
        .help = "Completed foreground discovery walks by finish reason; cancellations excluded",
        .labels = &.{"reason"},
    });
    inline for (@typeInfo(@import("discv5").Lookup.FinishReason).@"enum".fields) |field| {
        if (comptime !std.mem.eql(u8, field.name, "cancelled"))
            try lookup_finishes.sample(.{field.name}, discovery.coordinator.lookup_finishes[field.value]);
    }
}

fn writeTopics(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try @import("topics.zig").write(self, w);
}

fn writeRequests(self: *const Context, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "beacon_reqresp_outgoing_requests_total", "outgoing", "Started outgoing native requests, including control methods" },
        .{ "beacon_reqresp_incoming_requests_total", "incoming", "Accepted incoming native request streams, including control methods" },
        .{ "beacon_reqresp_outgoing_requests_error_total", "outgoing_errors", "Outgoing requests with a terminal native failure, excluding local cancellation" },
        .{ "beacon_reqresp_incoming_requests_error_total", "incoming_errors", "Incoming requests with a terminal native failure" },
    }) |metric| {
        const requests = try w.family(.{
            .name = metric[0],
            .kind = .counter,
            .help = metric[2],
            .labels = &.{"method"},
        });
        for (rr.protocol.methods, 0..) |method, index| {
            if (!firstMethod(index)) continue;
            var count: u64 = 0;
            for (rr.protocol.methods, &self.owner.service.reqresp.protocol_counters) |candidate, *values| {
                if (std.mem.eql(u8, candidate, method)) count +|= @field(values, metric[1]);
            }
            try requests.sample(.{method}, count);
        }
    }
    const refusals = try w.family(.{
        .name = "lodestar_native_reqresp_admission_refusals_total",
        .kind = .counter,
        .help = "Incoming request admission refusals counted once at the decision",
        .labels = &.{ "method", "reason" },
    });
    for (rr.protocol.methods, 0..) |method, index| {
        if (!firstMethod(index)) continue;
        inline for (std.meta.fields(rr.reqresp.metrics.AdmissionRefusal)) |reason| {
            var count: u64 = 0;
            for (rr.protocol.methods, &self.owner.service.reqresp.protocol_counters) |candidate, *values| {
                if (std.mem.eql(u8, candidate, method)) count +|= values.admission_refusals[reason.value];
            }
            try refusals.sample(.{ method, reason.name }, count);
        }
    }
    try w.enums(.{
        .name = "lodestar_native_reqresp_inbound_occupied",
        .kind = .gauge,
        .help = "Occupied incoming request slots by current phase, including terminal owners awaiting recycling",
        .labels = &.{"phase"},
    }, rr.reqresp.metrics.InboundPhase, &self.live(self.owner.service.reqresp.resourceSnapshot().inbound_phases));
}

fn writeRequestTimes(self: *const Context, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "beacon_reqresp_outgoing_request_roundtrip_time_seconds", "outgoing_time", "Outgoing request duration from stream creation through native completion or failure" },
        .{ "beacon_reqresp_incoming_request_handler_time_seconds", "incoming_time", "Incoming request duration from accepted stream through native completion or failure" },
    }) |metric| {
        const durations = try w.histograms(.{
            .name = metric[0],
            .kind = .histogram,
            .help = metric[2],
            .labels = &.{"method"},
            .unit = .seconds,
        }, @TypeOf(@field(self.owner.service.reqresp.protocol_counters[0], metric[1])));
        for (rr.protocol.methods, 0..) |method, index| {
            if (!firstMethod(index)) continue;
            var aggregate: @TypeOf(@field(self.owner.service.reqresp.protocol_counters[0], metric[1])) = .{};
            for (rr.protocol.methods, &self.owner.service.reqresp.protocol_counters) |candidate, *values| {
                if (std.mem.eql(u8, candidate, method)) aggregate.merge(&@field(values, metric[1]));
            }
            try durations.histogram(.{method}, &aggregate);
        }
    }
    try w.enums(.{
        .name = "beacon_reqresp_outgoing_requests_error_reason_total",
        .kind = .counter,
        .help = "Terminal outgoing native failures using host request error labels",
        .labels = &.{"reason"},
    }, rr.reqresp.metrics.ErrorReason, &self.owner.service.reqresp.outgoing_error_reasons);
}

fn writeBridge(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const bridge = @import("bridge.zig");
    try bridge.write(self.bridge orelse &bridge.empty, self.running, w);
}

fn writeGossipExecution(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_native_gossip_expired_executing",
        .kind = .gauge,
        .help = "Delivered gossip validations still awaiting host completion after their verdict deadlines",
    }, self.expired_executing);
}

fn writeGossip(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const g = self.owner.service.gossipsub;
    try w.enums(.{
        .name = "lodestar_native_gossipsub_storage_refusals_total",
        .kind = .counter,
        .help = "Gossip storage admission attempts refused by bounded resource reason",
        .labels = &.{"reason"},
    }, @import("../gossipsub/messages.zig").StorageRefusal, &g.messages.storage_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_retention_refusals_total",
        .kind = .counter,
        .help = "Accepted or published messages neither cached nor forwarded because their kind's retention allowance stayed full",
        .labels = &.{"kind"},
    }, gossip.topic.Kind, &g.messages.retention_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_iwant_ids_total",
        .kind = .counter,
        .help = "Examined valid IWANT IDs by outcome: absent from history, or present and then suppressed by IDONTWANT, over the retransmission limit, queued, or refused for queue pressure",
        .labels = &.{"outcome"},
    }, @import("../gossipsub/metrics.zig").IwantOutcome, &g.iwant_outcomes);
    try w.scalar(.{
        .name = "gossipsub_iwant_promise_broken",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises that expired without their sampled message",
    }, g.counters.broken_promises);
    try w.scalar(.{
        .name = "lodestar_native_gossip_iwant_promises_started_total",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises armed when the request's send completed with its sample outstanding; local cancellation can remove one before it expires",
    }, g.recovery.armed);
    try w.enums(.{
        .name = "lodestar_native_gossip_behaviour_penalties_total",
        .kind = .counter,
        .help = "Behaviour penalty units applied to peers by protocol violation",
        .labels = &.{"reason"},
    }, gossip.score.Penalty, &g.peers.scores.penalties);
    try g.overlay.mesh_changes.write(w);
    try g.delivery_metrics.write(w);
    const validation_time = try w.histograms(.{
        .name = "gossipsub_async_validation_delay_from_first_seen",
        .kind = .histogram,
        .help = "Seconds from native gossip admission until an applied validation verdict",
        .labels = &.{},
        .unit = .seconds,
    }, @TypeOf(g.validation_time));
    try validation_time.histogram(.{}, &g.validation_time);
}

fn writeGossipScores(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const ScorePopulations = @import("../gossipsub/metrics.zig").ScorePopulations;
    const g = self.owner.service.gossipsub;
    const populations: ScorePopulations = if (self.running) .collect(&g.peers, g.overlay, g.sessions, self.now.mono_ms) else .{};
    try populations.write(w);
}

fn writeGossipTopics(self: *const Context, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "lodestar_native_gossip_messages_received_total", "received", "Decoded gossip messages consumed from peers by topic kind, including ignored, invalid, duplicate and storage-refused messages" },
        .{ "lodestar_native_gossip_messages_duplicate_total", "duplicate", "Received gossip messages already seen or awaiting validation by topic kind" },
        .{ "lodestar_native_gossip_messages_published_total", "published", "Local publications admitted to gossip history by topic kind, including those without recipients" },
        .{ "gossipsub_accepted_messages_total", "accepted", "Applied accept verdicts by topic kind" },
        .{ "gossipsub_rejected_messages_total", "rejected", "Applied reject verdicts by topic kind" },
        .{ "gossipsub_ignored_messages_total", "ignored", "Applied ignore verdicts by topic kind" },
        .{ "gossipsub_msg_forward_count_total", "forwarded", "Accepted messages handed to forwarding by topic kind" },
    }) |metric| {
        const messages = try w.family(.{ .name = metric[0], .kind = .counter, .help = metric[2], .labels = &.{"topic"} });
        inline for (@typeInfo(gossip.topic_policy.Kind).@"enum".fields) |field| {
            try messages.sample(.{field.name}, @field(self.owner.service.gossipsub.topic_metrics.counts[field.value], metric[1]));
        }
        try messages.sample(.{"unknown"}, @field(self.owner.service.gossipsub.topic_metrics.counts[gossip.topic_policy.kind_count], metric[1]));
    }
}
fn writeConnections(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const counters = &self.owner.transport.engine.connection_metrics;
    try w.enums(.{
        .name = "lodestar_native_quic_connections_established_total",
        .kind = .counter,
        .help = "QUIC connections with authenticated expected identities by direction",
        .labels = &.{"direction"},
    }, types.Direction, &counters.established);
    const closed = try w.family(.{
        .name = "lodestar_native_quic_connections_closed_total",
        .kind = .counter,
        .help = "QUIC closes including pre-admission failures; wire error codes share bounded reason labels",
        .labels = &.{ "direction", "reason" },
    });
    inline for (@typeInfo(types.Direction).@"enum".fields) |direction| {
        inline for (@typeInfo(types.CloseReason).@"union".fields, 0..) |reason, index| {
            try closed.sample(.{ direction.name, reason.name }, counters.closed[direction.value][index]);
        }
    }
}

fn rejectStage(reason: @import("discv5").types.RejectReason) []const u8 {
    return switch (reason) {
        .oversized_datagram => "receive",
        .admission_limited => "admission",
        .malformed_packet => "packet",
        .unexpected_handshake, .invalid_handshake, .unexpected_challenge => "handshake",
        .invalid_record => "record",
        .malformed_message, .request_too_large => "message",
        .unsolicited_response, .invalid_response, .duplicate_response => "response",
    };
}

fn firstMethod(index: usize) bool {
    std.debug.assert(index < rr.Protocol.count);
    for (rr.protocol.methods[0..index]) |previous| if (std.mem.eql(u8, rr.protocol.methods[index], previous)) return false;
    return true;
}

fn writePopulation(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try self.population.write(w);
}
fn writePeerEvents(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try self.owner.peer_manager.control.counters.events.write(w);
}
fn writePeerPolicy(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try @import("peer_policy.zig").write(&self.owner.peer_manager, self.running, w);
}
