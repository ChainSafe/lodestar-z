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

const Snapshot = @import("snapshot.zig").Snapshot;
const Client = peer_client.Client;
pub const registry = prom.Registry(Snapshot, .{
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
    writePeerProcessing,
    writeConnections,
    writePeeringProgress,
    writeRuntime,
    writeNativeCounters,
    writeGossipResources,
    writeRequestResources,
    writePeerCloses,
    writeDiscoveryProgress,
    writeGossipTopics,
});

fn writePeers(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "libp2p_peers",
        .kind = .gauge,
        .help = "Authenticated connected peers",
    }, self.live.peers);
    try w.scalar(.{
        .name = "lodestar_native_network_relevant_peers",
        .kind = .gauge,
        .help = "Peers with compatible Status",
    }, self.live.relevant);
    try w.scalar(.{
        .name = "lodestar_peer_manager_starved_bool",
        .kind = .gauge,
        .help = "Connected peers below target while running",
    }, @intFromBool(self.live.running and self.live.peers < self.config.target));
    try w.scalar(.{
        .name = "lodestar_peer_manager_outbound_peers_ratio",
        .kind = .gauge,
        .help = "Fraction of connected peers that are outbound",
    }, if (self.live.peers == 0) @as(f64, 0) else @as(f64, @floatFromInt(self.live.peer_population.directionCount(.outbound))) / @as(f64, @floatFromInt(self.live.peers)));
    const directions = try w.family(.{
        .name = "lodestar_peers_by_direction_count",
        .kind = .gauge,
        .help = "Connected peers by direction",
        .labels = &.{"direction"},
    });
    for ([_][]const u8{ "inbound", "outbound" }, self.live.peer_population.directionCounts()) |direction, count| try directions.sample(.{direction}, count);
    inline for (.{ .{ "lodestar_peers_by_client_count", "clients", "Connected peers by client" }, .{ "lodestar_gossip_mesh_peers_by_client_count", "mesh_clients", "Peers in at least one gossip mesh by client" } }) |metric| {
        const clients = try w.family(.{
            .name = metric[0],
            .kind = .gauge,
            .help = metric[2],
            .labels = &.{"client"},
        });
        inline for (std.meta.fields(Client)) |field| {
            const count = if (comptime std.mem.eql(u8, metric[1], "clients"))
                self.live.peer_population.clientCount(@enumFromInt(field.value))
            else
                self.live.mesh_clients[field.value];
            try clients.sample(.{field.name}, count);
        }
    }
}

fn writeRuntime(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_discovery_total_dial_attempts",
        .kind = .counter,
        .help = "Started native QUIC dials",
    }, self.totals.runtime.dial_started);
    if (self.config.discovery_enabled) {
        try w.scalar(.{
            .name = "lodestar_discv5_active_session_count",
            .kind = .gauge,
            .help = "Stored discovery sessions",
        }, self.live.discovery_sessions);
        try w.scalar(.{
            .name = "lodestar_discv5_kad_table_size",
            .kind = .gauge,
            .help = "Discovery routing table entries",
        }, self.live.discovery_peers);
        try w.scalar(.{
            .name = "lodestar_discv5_lookup_count",
            .kind = .gauge,
            .help = "Active foreground discovery lookups",
        }, self.live.discovery_lookups);
    }
    try w.scalar(.{
        .name = "lodestar_native_network_metrics_snapshot_monotonic_seconds",
        .kind = .gauge,
        .help = "Monotonic time of the last owner snapshot",
        .unit = .seconds,
    }, @as(f64, @floatFromInt(self.sampled_ms)) / 1000);
    try w.scalar(.{
        .name = "lodestar_native_network_running",
        .kind = .gauge,
        .help = "Network owner is running",
    }, @intFromBool(self.live.running));
    try w.counters("lodestar_native_network_", &self.totals.runtime);
    try w.counters("lodestar_native_quic_", &self.totals.transport);
}

fn writeNativeCounters(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_native_negotiation_refused_total",
        .kind = .counter,
        .help = "Inbound streams refused at negotiation capacity",
    }, self.totals.negotiations.refused);
    try w.enums(.{
        .name = "lodestar_native_negotiation_failed_total",
        .kind = .counter,
        .help = "Inbound negotiation failures",
        .labels = &.{"reason"},
    }, @import("../negotiate.zig").Failure, &self.totals.negotiations.inbound_failures);
    inline for (.{
        .{ "received_bytes", "Complete QUIC UDP payload bytes received, excluding truncated datagrams" },
        .{ "sent_bytes", "QUIC UDP payload bytes sent, including successful prefixes of failed batches" },
        .{ "received_datagrams", "QUIC UDP datagrams received, including truncated datagrams" },
        .{ "sent_datagrams", "QUIC UDP datagrams sent" },
        .{ "truncated_datagrams", "Oversized QUIC UDP datagrams discarded on receive" },
    }) |metric| try w.scalar(.{
        .name = "lodestar_native_quic_udp_" ++ metric[0] ++ "_total",
        .kind = .counter,
        .help = metric[1],
    }, @field(self.totals.udp, metric[0]));
    try w.counters("lodestar_native_reqresp_", &self.totals.requests);
    try w.counters("lodestar_native_gossipsub_", &self.totals.gossip_counts);
    try w.counters("lodestar_native_dial_", &self.totals.dial);
    try w.counters("lodestar_native_discovery_", &self.totals.discovery_counts);
    try w.enums(.{
        .name = "lodestar_native_discovery_candidate_rejections_total",
        .kind = .counter,
        .help = "Authenticated discovery candidates rejected by reason",
        .labels = &.{"reason"},
    }, discovery_metrics.Rejection, &self.totals.discovery_rejections);
    const admission = @import("discv5").admission;
    const discovery_admission = try w.family(.{
        .name = "lodestar_native_discovery_admission_total",
        .kind = .counter,
        .help = "Discovery packet, expected response, challenge, handshake and record verification admission outcomes",
        .labels = &.{ "stage", "outcome" },
    });
    inline for (std.meta.fields(admission.Stage)) |stage| {
        inline for (std.meta.fields(admission.Outcome)) |outcome| {
            try discovery_admission.sample(.{ stage.name, outcome.name }, self.totals.discovery_admission[stage.value][outcome.value]);
        }
    }
    try w.enums(.{
        .name = "lodestar_native_gossip_queue_drops_total",
        .kind = .counter,
        .help = "Gossip queue admissions refused by resource limit, including mesh control",
        .labels = &.{"reason"},
    }, outbox.DropReason, &self.totals.gossip_queue_drops);
}

fn writeGossipResources(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_native_gossip_data_descriptors_per_peer",
        .kind = .gauge,
        .help = "Bounded outgoing data descriptors per gossip peer",
    }, outbox.data_capacity);
    if (self.config.gossip_capacity) |*resources| try writeResourceFields("lodestar_native_gossipsub_", "Native gossip ", resources, w);
    if (self.totals.gossip_high_water) |*resources| try writeResourceFields("lodestar_native_gossipsub_", "Native gossip ", resources, w);
    if (self.live.gossip_resources) |*resources| try writeResourceFields("lodestar_native_gossipsub_", "Native gossip ", resources, w);
}

fn writeRequestResources(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    if (self.config.request_capacity) |*resources| try writeResourceFields("lodestar_native_reqresp_resources_", "Native request resources ", resources, w);
    try writeResourceFields("lodestar_native_reqresp_resources_", "Native request resources ", &self.live.request_resources, w);
    if (self.config.control_capacity) |*resources| try writeResourceFields("lodestar_native_control_", "Native peer control ", resources, w);
    try writeResourceFields("lodestar_native_control_", "Native peer control ", &self.live.control_resources, w);
}

fn writeResourceFields(comptime prefix: []const u8, comptime description: []const u8, resources: anytype, w: *prom.Encoder) prom.Error!void {
    inline for (std.meta.fields(@TypeOf(resources.*))) |field| {
        if (comptime std.mem.eql(u8, field.name, "inbound_phases")) continue;
        if (comptime @typeInfo(field.type) == .optional) {
            if (@field(resources, field.name)) |value| {
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
        }, @field(resources, field.name));
    }
}

fn writePeerCloses(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.enums(.{
        .name = "lodestar_native_peer_closes_total",
        .kind = .counter,
        .help = "Peer closes initiated by native peer control",
        .labels = &.{"reason"},
    }, peer_types.DisconnectReason, &self.totals.closed);
    const closes_by_client = try w.family(.{
        .name = "lodestar_native_peer_closes_by_client_total",
        .kind = .counter,
        .help = "Peer closes by identified client and local reason",
        .labels = &.{ "client", "reason" },
    });
    inline for (@typeInfo(Client).@"enum".fields) |client| {
        inline for (@typeInfo(peer_types.DisconnectReason).@"enum".fields) |reason| {
            try closes_by_client.sample(.{ client.name, reason.name }, self.totals.closed_by_client[client.value][reason.value]);
        }
    }
    try w.enums(.{
        .name = "lodestar_native_peer_goodbyes_total",
        .kind = .counter,
        .help = "Received Ethereum Goodbye reasons; unknown wire codes share one label",
        .labels = &.{"reason"},
    }, goodbye.Reason, &self.totals.peer_events.goodbyes);
}

fn writePeerProcessing(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    const processing = try w.family(.{
        .name = "lodestar_native_peer_processing_total",
        .kind = .counter,
        .help = "Peer policy decisions and processing work by bounded operation",
        .labels = &.{"operation"},
    });
    inline for (std.meta.fields(@TypeOf(self.totals.peer_work))) |field| {
        try processing.sample(.{field.name}, @field(self.totals.peer_work, field.name));
    }
    try processing.sample(.{"dial_sync_lookup_rows"}, self.totals.dial.sync_lookup_rows);
}

fn writePeeringProgress(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_native_peer_identify_started_total",
        .kind = .counter,
        .help = "Started Identify exchanges",
    }, self.totals.identify_started);
    try w.scalar(.{
        .name = "lodestar_native_peer_identify_deferred_total",
        .kind = .counter,
        .help = "Identify starts deferred by local pressure",
    }, self.totals.identify_deferred);
    try w.enums(.{
        .name = "lodestar_native_peer_identify_failures_total",
        .kind = .counter,
        .help = "Identify failures by bounded protocol reason",
        .labels = &.{"reason"},
    }, @import("../identify/root.zig").Failure, &self.totals.identify_failures);
    if (self.config.transport_capacity) |capacity| {
        try w.scalar(.{
            .name = "lodestar_native_quic_connections_capacity",
            .kind = .gauge,
            .help = "Native QUIC connection slots capacity",
        }, capacity);
        const resources = &self.live.transport_resources;
        inline for (std.meta.fields(@TypeOf(resources.*))) |field|
            try w.scalar(.{
                .name = "lodestar_native_quic_connections_" ++ field.name,
                .kind = .gauge,
                .help = "Native QUIC connection slots " ++ field.name,
            }, @field(resources, field.name));
    }
    if (self.config.dial_capacity) |capacity| {
        try w.scalar(.{
            .name = "lodestar_native_dial_capacity",
            .kind = .gauge,
            .help = "Native dial queue rows capacity",
        }, capacity);
        const resources = &self.live.dial_resources;
        inline for (std.meta.fields(@TypeOf(resources.*))) |field|
            try w.scalar(.{
                .name = "lodestar_native_dial_" ++ field.name,
                .kind = .gauge,
                .help = "Native dial queue rows " ++ field.name,
            }, @field(resources, field.name));
    }
}

fn writeDiscoveryProgress(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    const dial_time = try w.histograms(.{
        .name = "lodestar_discovery_dial_time_seconds",
        .kind = .histogram,
        .help = "Time from selecting a dial through authenticated connection or terminal failure; cancellations excluded",
        .labels = &.{"status"},
        .unit = .seconds,
    }, @TypeOf(self.totals.dial_time[0]));
    inline for (.{ "success", "error" }, 0..) |status, index|
        try dial_time.histogram(.{status}, &self.totals.dial_time[index]);
    if (!self.config.discovery_enabled) return;
    const lookup_time = try w.histograms(.{
        .name = "lodestar_discovery_find_node_query_time_seconds",
        .kind = .histogram,
        .help = "Time to finish a foreground FINDNODE walk; cancelled walks excluded",
        .labels = &.{},
        .unit = .seconds,
    }, @TypeOf(self.totals.lookup_time));
    try lookup_time.histogram(.{}, &self.totals.lookup_time);
    const lookup_finishes = try w.family(.{
        .name = "lodestar_native_discovery_lookup_finishes_total",
        .kind = .counter,
        .help = "Completed foreground discovery walks by finish reason; cancellations excluded",
        .labels = &.{"reason"},
    });
    inline for (@typeInfo(@import("discv5").Lookup.FinishReason).@"enum".fields) |field| {
        if (comptime !std.mem.eql(u8, field.name, "cancelled"))
            try lookup_finishes.sample(.{field.name}, self.totals.lookup_finishes[field.value]);
    }
    try w.scalar(.{
        .name = "lodestar_native_discovery_pending_revalidations",
        .kind = .gauge,
        .help = "Routing buckets waiting for incumbent revalidation",
    }, self.live.discovery_pending_revalidations);
    try w.scalar(.{
        .name = "lodestar_native_discovery_waiting_queries",
        .kind = .gauge,
        .help = "Foreground FINDNODE calls awaiting responses",
    }, self.live.discovery_waiting_queries);
    if (self.live.discovery_candidate_idle_ms) |elapsed|
        try w.scalar(.{
            .name = "lodestar_native_discovery_candidate_idle_seconds",
            .kind = .gauge,
            .help = "Time since the last candidate publication while running; absent before first publication",
            .unit = .seconds,
        }, @as(f64, @floatFromInt(elapsed)) / 1000);
}

fn writeTopics(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    inline for (.{ .{ "mesh", "mesh" }, .{ "topic", "subscribers" } }) |metric| {
        const prefix = "lodestar_gossip_" ++ metric[0] ++ "_peers_by_";
        inline for (.{ "type", "beacon_attestation_subnet", "sync_committee_subnet", "data_column_subnet" }) |suffix| {
            const memberships = try w.family(.{
                .name = prefix ++ suffix ++ "_count",
                .kind = .gauge,
                .help = "Peer memberships in active native topics; boundary is the fork digest",
                .labels = &.{ if (std.mem.eql(u8, suffix, "type")) "type" else "subnet", "boundary" },
            });
            for (self.live.topics[0..self.live.topic_count]) |*entry| {
                const entry_suffix = switch (entry.kind) {
                    .beacon_attestation => "beacon_attestation_subnet",
                    .sync_committee => "sync_committee_subnet",
                    .data_column_sidecar => "data_column_subnet",
                    else => "type",
                };
                if (!std.mem.eql(u8, suffix, entry_suffix)) continue;
                const boundary = std.fmt.bytesToHex(entry.digest, .lower);
                const value = @field(entry, metric[1]);
                var subnet_buffer: [5]u8 = undefined;
                const label = switch (entry.kind) {
                    .beacon_attestation => std.fmt.bufPrint(&subnet_buffer, "{d:0>2}", .{entry.subnet}) catch unreachable,
                    .sync_committee, .data_column_sidecar => std.fmt.bufPrint(&subnet_buffer, "{d}", .{entry.subnet}) catch unreachable,
                    else => @tagName(entry.kind),
                };
                try memberships.sample(.{ label, &boundary }, value);
            }
        }
    }
}

fn writeRequests(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
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
            for (rr.protocol.methods, &self.totals.protocols) |candidate, *values| {
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
            for (rr.protocol.methods, &self.totals.protocols) |candidate, *values| {
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
    }, rr.reqresp.metrics.InboundPhase, &self.live.request_resources.inbound_phases);
}

fn writeRequestTimes(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
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
        }, @TypeOf(@field(self.totals.protocols[0], metric[1])));
        for (rr.protocol.methods, 0..) |method, index| {
            if (!firstMethod(index)) continue;
            var aggregate: @TypeOf(@field(self.totals.protocols[0], metric[1])) = .{};
            for (rr.protocol.methods, &self.totals.protocols) |candidate, *values| {
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
    }, rr.reqresp.metrics.ErrorReason, &self.totals.outgoing_error_reasons);
}

fn writeScores(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try self.live.scores.write(w);
    try self.totals.scores.write(w);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_min",
        .kind = .gauge,
        .help = "Minimum connected gossip peer score",
    }, self.live.scores.values.min);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_max",
        .kind = .gauge,
        .help = "Maximum connected gossip peer score",
    }, self.live.scores.values.max);
    try w.scalar(.{
        .name = "lodestar_gossip_score_avg_min_max_avg",
        .kind = .gauge,
        .help = "Average connected gossip peer score",
    }, self.live.scores.average());
    try w.scalar(.{
        .name = "lodestar_native_gossip_scored_peers",
        .kind = .gauge,
        .help = "Connected gossip peers included in score gauges",
    }, self.live.scores.values.count);
    const thresholds = try w.family(.{
        .name = "lodestar_gossip_peer_score_by_threshold_count",
        .kind = .gauge,
        .help = "Connected gossip peers at or above configured score thresholds; mesh uses zero",
        .labels = &.{"threshold"},
    });
    inline for (.{ "graylist", "publish", "gossip", "mesh" }) |threshold| {
        try thresholds.sample(.{threshold}, @field(self.live.scores, threshold));
    }
}

fn writeGossipExecution(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.scalar(.{
        .name = "lodestar_native_gossip_expired_executing",
        .kind = .gauge,
        .help = "Delivered gossip validations still awaiting host completion after their verdict deadlines",
    }, self.live.gossip_expired_executing);
    try w.scalar(.{
        .name = "lodestar_native_gossip_oldest_expired_execution_age_seconds",
        .kind = .gauge,
        .help = "Seconds past the earliest verdict deadline among delivered validations awaiting host completion; zero when none",
        .unit = .seconds,
    }, @as(f64, @floatFromInt(self.live.gossip_oldest_expired_execution_age_ms)) / 1000);
}

fn writeGossip(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try w.enums(.{
        .name = "lodestar_native_gossipsub_storage_refusals_total",
        .kind = .counter,
        .help = "Gossip storage admission attempts refused by bounded resource reason",
        .labels = &.{"reason"},
    }, @import("../gossipsub/messages.zig").StorageRefusal, &self.totals.gossip_storage_refusals);
    try self.totals.gossip_rpc.write(w);
    try w.scalar(.{
        .name = "gossipsub_fast_message_id_hits_total",
        .kind = .counter,
        .help = "Exact compressed fingerprints avoiding repeated decompression",
    }, self.totals.gossip_fast_hits);
    try w.scalar(.{
        .name = "gossipsub_message_decode_total",
        .kind = .counter,
        .help = "Snappy body decode attempts",
    }, self.totals.gossip_decoded);
    try w.scalar(.{
        .name = "gossipsub_delivery_attribution_evictions_total",
        .kind = .counter,
        .help = "Resolved delivery records replaced before their attribution deadline",
    }, self.totals.gossip_delivery_evictions);
    try self.totals.gossip_recovery.write(w);
    try w.scalar(.{
        .name = "gossipsub_rpc_recv_err_count_total",
        .kind = .counter,
        .help = "Malformed incoming RPC frames or protobuf items",
    }, self.totals.gossip_counts.malformed_rpcs);
    try w.scalar(.{
        .name = "gossipsub_iwant_promise_broken",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises that expired without their sampled message",
    }, self.totals.gossip_counts.broken_promises);
    try w.scalar(.{
        .name = "gossipsub_mcache_size",
        .kind = .gauge,
        .help = "Stored message history entries",
    }, self.live.gossip_history);
    const caches = try w.family(.{
        .name = "gossipsub_cache_size",
        .kind = .gauge,
        .help = "Native bounded cache entry counts",
        .labels = &.{"cache"},
    });
    try caches.sample(.{"seenCache"}, self.live.gossip_seen);
    try caches.sample(.{"mcache"}, self.live.gossip_history);
    try caches.sample(.{"deliveryCache"}, self.live.gossip_recent);
    try caches.sample(.{"gossipTracer.promises"}, if (self.live.gossip_resources) |r| r.promises else @as(usize, 0));
    try w.scalar(.{
        .name = "gossipsub_rpc_recv_count_total",
        .kind = .counter,
        .help = "Complete received gossip RPCs",
    }, self.totals.gossip_counts.rpcs_received);
    const validation_time = try w.histograms(.{
        .name = "gossipsub_async_validation_delay_from_first_seen",
        .kind = .histogram,
        .help = "Seconds from native gossip admission until an applied validation verdict",
        .labels = &.{},
        .unit = .seconds,
    }, @TypeOf(self.totals.validation_time));
    try validation_time.histogram(.{}, &self.totals.validation_time);
}

fn writeGossipTopics(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
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
            try messages.sample(.{field.name}, @field(self.totals.gossip_topics.counts[field.value], metric[1]));
        }
        try messages.sample(.{"unknown"}, @field(self.totals.gossip_topics.counts[gossip.topic_policy.kind_count], metric[1]));
    }
}
fn writeConnections(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    const counters = &self.totals.connections;
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

fn firstMethod(index: usize) bool {
    std.debug.assert(index < rr.Protocol.count);
    for (rr.protocol.methods[0..index]) |previous| if (std.mem.eql(u8, rr.protocol.methods[index], previous)) return false;
    return true;
}

fn writePopulation(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try self.live.peer_population.write(w);
}
fn writePeerEvents(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try self.totals.peer_events.write(w);
}
fn writePeerPolicy(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
    try self.live.peer_policy.write(w);
}
