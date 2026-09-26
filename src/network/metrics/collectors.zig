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
    writeGossipExecution,
    writeScores,
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
    writeMaintenance,
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
    try w.counters("lodestar_native_reqresp_", &self.owner.service.reqresp.counters);
    try w.counters("lodestar_native_gossipsub_", &self.owner.service.gossipsub.counters);
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
    try w.scalar(.{ .name = "lodestar_native_gossip_data_descriptors_per_peer", .kind = .gauge, .help = "Bounded outgoing data descriptors per gossip peer" }, outbox.data_capacity);
    const resources = self.owner.service.gossipsub.resourceSnapshot();
    try writeResourceFields("lodestar_native_gossipsub_", "Native gossip ", &resources, self.running, w);
}

fn writeRequestResources(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const requests = self.owner.service.reqresp.resourceSnapshot();
    try writeResourceFields("lodestar_native_reqresp_resources_", "Native request resources ", &requests, self.running, w);
}

fn writeResourceFields(comptime prefix: []const u8, comptime description: []const u8, resources: anytype, running: bool, w: *prom.Encoder) prom.Error!void {
    inline for (std.meta.fields(@TypeOf(resources.*))) |field| {
        if (comptime std.mem.eql(u8, field.name, "inbound_phases")) continue;
        const persistent = comptime std.mem.endsWith(u8, field.name, "_capacity") or std.mem.endsWith(u8, field.name, "_high_water") or std.mem.endsWith(u8, field.name, "_control_reserved");
        const current = if (running or persistent) @field(resources, field.name) else std.mem.zeroes(field.type);
        if (comptime @typeInfo(field.type) == .optional) {
            if (current) |value| {
                if (comptime std.mem.endsWith(u8, field.name, "_ms")) {
                    try w.scalar(.{
                        .name = prefix ++ field.name[0 .. field.name.len - 3] ++ "_seconds",
                        .kind = .gauge,
                        .help = description ++ field.name ++ " in seconds",
                        .unit = .seconds,
                    }, @as(f64, @floatFromInt(value)) / 1000);
                } else try w.scalar(.{
                    .name = prefix ++ field.name,
                    .kind = .gauge,
                    .help = description ++ field.name,
                }, value);
            }
        } else try w.scalar(.{
            .name = prefix ++ field.name,
            .kind = .gauge,
            .help = description ++ field.name,
        }, current);
    }
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
        .help = "Remote rejections recorded against peer identities by kind: a received Goodbye, or a remote close of our dial before the Status and Metadata exchange completed",
        .labels = &.{"kind"},
    }, peer_types.Rejection, &self.owner.peer_manager.catalog.rejections);
    try w.enums(.{
        .name = "lodestar_native_peer_health_failures_total",
        .kind = .counter,
        .help = "Failed Status, Metadata and Ping probes counted toward a health disconnect",
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
        .{ "lodestar_native_reqresp_outgoing_cancelled_total", "outgoing_cancelled", "Outgoing requests cancelled by the local owner" },
        .{ "lodestar_native_reqresp_incoming_cancelled_total", "incoming_cancelled", "Incoming requests cancelled by the local owner" },
        .{ "lodestar_native_reqresp_request_write_stops_total", "request_write_stops", "Peer stops of the request write direction that retain response processing" },
        .{ "lodestar_native_reqresp_response_finish_stops_total", "response_finish_stops", "Peer stops of response FIN after complete response chunks were written" },
        .{ "beacon_reqresp_incoming_requests_error_total", "incoming_errors", "Incoming requests with a terminal native failure" },
        .{ "beacon_reqresp_rate_limiter_errors_total", "rate_limited", "Requests refused by protocol concurrency limits, decoded work quotas or identity capacity" },
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

fn writeScores(self: *const Context, w: *prom.Encoder) prom.Error!void {
    try self.scores.write(w);
    try @import("scores.zig").writeTotals(&self.owner.service.gossipsub.peers.scores, w);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_min",
        .kind = .gauge,
        .help = "Minimum connected gossip peer score",
    }, self.scores.values.min);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_max",
        .kind = .gauge,
        .help = "Maximum connected gossip peer score",
    }, self.scores.values.max);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_avg",
        .kind = .gauge,
        .help = "Average connected gossip peer score",
    }, self.scores.average());
    try w.scalar(.{
        .name = "lodestar_native_gossip_scored_peers",
        .kind = .gauge,
        .help = "Connected gossip peers included in score gauges",
    }, self.scores.values.count);
    const thresholds = try w.family(.{
        .name = "lodestar_gossip_peer_score_by_threshold_count",
        .kind = .gauge,
        .help = "Connected gossip peers at or above configured score thresholds; mesh uses zero",
        .labels = &.{"threshold"},
    });
    inline for (.{ "graylist", "publish", "gossip", "mesh" }) |threshold| {
        try thresholds.sample(.{threshold}, @field(self.scores, threshold));
    }
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
    try w.scalar(.{
        .name = "lodestar_native_gossip_oldest_expired_execution_age_seconds",
        .kind = .gauge,
        .help = "Seconds past the earliest verdict deadline among delivered validations awaiting host completion; zero when none",
        .unit = .seconds,
    }, @as(f64, @floatFromInt(self.oldest_expired_execution_age_ms)) / 1000);
}

fn writeGossip(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const caches_now = self.owner.service.gossipsub.messages.stats();
    try w.enums(.{
        .name = "lodestar_native_gossipsub_storage_refusals_total",
        .kind = .counter,
        .help = "Gossip storage admission attempts refused by bounded resource reason",
        .labels = &.{"reason"},
    }, @import("../gossipsub/messages.zig").StorageRefusal, &self.owner.service.gossipsub.messages.storage_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_retention_refusals_total",
        .kind = .counter,
        .help = "Accepted or published messages neither cached nor forwarded because their kind's retention allowance stayed full",
        .labels = &.{"kind"},
    }, gossip.topic.Kind, &self.owner.service.gossipsub.messages.retention_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_history_evictions_total",
        .kind = .counter,
        .help = "Message history evictions: six windows passed, the history was full, the kind's retention allowance was full, or the store needed the room",
        .labels = &.{"reason"},
    }, gossip.mcache.Eviction, &self.owner.service.gossipsub.messages.history.evictions);
    try self.owner.service.gossipsub.rpc_metrics.write(w);
    try self.owner.service.gossipsub.io_metrics.write(w);
    try self.owner.service.gossipsub.delivery_metrics.write(w);
    try self.owner.service.gossipsub.apply_metrics.write(w);
    try w.scalar(.{ .name = "lodestar_native_gossip_history_entries_visited_total", .kind = .counter, .help = "History entries examined while selecting advertised message IDs" }, self.owner.service.gossipsub.messages.history.gossip_entries_visited);
    try w.scalar(.{
        .name = "gossipsub_fast_message_id_hits_total",
        .kind = .counter,
        .help = "Exact compressed fingerprints avoiding repeated decompression",
    }, self.owner.service.gossipsub.messages.fast_hits);
    try w.scalar(.{
        .name = "gossipsub_message_decode_total",
        .kind = .counter,
        .help = "Snappy body decode attempts",
    }, self.owner.service.gossipsub.messages.decoded_messages);
    try w.scalar(.{
        .name = "gossipsub_delivery_attribution_evictions_total",
        .kind = .counter,
        .help = "Resolved delivery records replaced before their attribution deadline",
    }, self.owner.service.gossipsub.messages.validation.delivery_evictions);
    try self.owner.service.gossipsub.recovery.metrics.write(w);
    try w.scalar(.{
        .name = "gossipsub_rpc_recv_err_count_total",
        .kind = .counter,
        .help = "Malformed incoming RPC frames or protobuf items",
    }, self.owner.service.gossipsub.counters.malformed_rpcs);
    try w.scalar(.{
        .name = "gossipsub_iwant_promise_broken",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises that expired without their sampled message",
    }, self.owner.service.gossipsub.counters.broken_promises);
    try w.scalar(.{
        .name = "gossipsub_mcache_size",
        .kind = .gauge,
        .help = "Stored message history entries",
    }, self.live(caches_now.history));
    const caches = try w.family(.{
        .name = "gossipsub_cache_size",
        .kind = .gauge,
        .help = "Native bounded cache entry counts",
        .labels = &.{"cache"},
    });
    try caches.sample(.{"seenCache"}, self.live(caches_now.seen));
    try caches.sample(.{"mcache"}, self.live(caches_now.history));
    try caches.sample(.{"deliveryCache"}, self.live(caches_now.recent));
    try caches.sample(.{"gossipTracer.promises"}, self.live(self.owner.service.gossipsub.recovery.len));
    try w.scalar(.{
        .name = "gossipsub_rpc_recv_count_total",
        .kind = .counter,
        .help = "Complete received gossip RPCs",
    }, self.owner.service.gossipsub.counters.rpcs_received);
    const validation_time = try w.histograms(.{
        .name = "gossipsub_async_validation_delay_from_first_seen",
        .kind = .histogram,
        .help = "Seconds from native gossip admission until an applied validation verdict",
        .labels = &.{},
        .unit = .seconds,
    }, @TypeOf(self.owner.service.gossipsub.validation_time));
    try validation_time.histogram(.{}, &self.owner.service.gossipsub.validation_time);
}

fn writeGossipTopics(self: *const Context, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "gossipsub_accepted_messages_total", "accepted" },
        .{ "gossipsub_rejected_messages_total", "rejected" },
        .{ "gossipsub_ignored_messages_total", "ignored" },
        .{ "gossipsub_msg_publish_count_total", "published" },
        .{ "gossipsub_msg_publish_peers_total", "published_peers" },
        .{ "gossipsub_msg_publish_bytes_total", "published_bytes", "Compressed publication bytes summed over successfully queued peer copies" },
        .{ "gossipsub_msg_received_prevalidation_total", "prevalidation", "Decoded publication items before admission, including deferred and refused items" },
        .{ "gossipsub_ihave_rcv_msgids_total", "ihave_ids", "Examined valid IHAVE IDs within processing limits" },
        .{ "gossipsub_ihave_rcv_not_seen_msgids_total", "ihave_unseen", "Unique eligible IHAVE IDs selected for an IWANT attempt after deduplication, outstanding-request and known-message filtering" },
        .{ "gossipsub_iwant_rcv_msgids_total", "iwant_ids", "Examined valid unsuppressed IWANT IDs present in message history" },
        .{ "gossipsub_msg_forward_count_total", "forwarded" },
        .{ "gossipsub_msg_forward_peers_total", "forwarded_peers" },
        .{ "gossipsub_pre_validation_valid_total", "admitted" },
        .{ "gossipsub_pre_validation_duplicate_total", "duplicates" },
    }) |metric| {
        const messages = try w.family(.{
            .name = metric[0],
            .kind = .counter,
            .help = if (metric.len == 3) metric[2] else "Native gossip " ++ metric[1] ++ "; peer copies count successful queue admissions",
            .labels = &.{"topic"},
        });
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

fn writeMaintenance(self: *const Context, w: *prom.Encoder) prom.Error!void {
    const g = self.owner.service.gossipsub;
    try g.overlay.metrics.write(w);
    inline for (.{
        .{ "gossipsub_heartbeat_duration_seconds", "cycles", "Elapsed duration of a completed gossip maintenance cycle, including time between slices" },
        .{ "lodestar_native_gossip_heartbeat_lateness_seconds", "lateness", "Delay from the scheduled heartbeat deadline until it is serviced" },
    }) |metric| {
        const histogram = try w.histograms(.{ .name = metric[0], .kind = .histogram, .help = metric[2], .unit = .seconds }, @import("timing.zig").Duration);
        try histogram.histogram(.{}, &@field(g.maintenance, metric[1]));
    }
    const slices = try w.histograms(.{ .name = "lodestar_native_gossip_maintenance_slice_seconds", .kind = .histogram, .help = "Elapsed time inside uninterrupted maintenance regions, including OS preemption; excludes time between slices", .unit = .seconds, .labels = &.{"phase"} }, @import("timing.zig").Duration);
    inline for (.{ "setup", "topics" }) |phase| try slices.histogram(.{phase}, &@field(g.maintenance, phase));
    const work = try w.histograms(.{ .name = "lodestar_native_gossip_maintenance_work_seconds", .kind = .histogram, .help = "Subphase duration within topic maintenance slices, including OS preemption", .unit = .seconds, .labels = &.{"phase"} }, @import("timing.zig").Duration);
    inline for (.{ "mesh", "gossip", "retire", "history" }) |phase| try work.histogram(.{phase}, &@field(g.maintenance, phase));
    try w.counters("lodestar_native_gossip_maintenance_", &.{ .topics_serviced = g.maintenance.topics_serviced, .time_yields = g.maintenance.time_yields });
    try w.scalar(.{ .name = "lodestar_native_gossip_maintenance_active", .kind = .gauge, .help = "A gossip maintenance cycle is unfinished" }, @intFromBool(self.running and g.cycle.isActive()));
    try w.scalar(.{ .name = "lodestar_native_gossip_maintenance_completed_timestamp_seconds", .kind = .gauge, .help = "Unix time of the last completed gossip maintenance cycle; zero before the first completion", .unit = .seconds }, g.maintenance.completed_unix_s);
}
