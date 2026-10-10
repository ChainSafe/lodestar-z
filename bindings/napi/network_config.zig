const std = @import("std");
const napi = @import("zapi:zapi").napi;
const n = @import("network");
const d = @import("discv5");
const Value = napi.Value;
const decode = @import("network_js_input.zig");
const t = n.peers.types;
const enr_max = d.wire.constants.enr_size_max;
const bootstrap_max = n.peers.Discovery.bootstrap_max;
const BeaconConfig = @import("config").BeaconConfig;

pub const Config = struct {
    secret: [32]u8,
    bind: n.udp.Sockets.Bindings,
    local: t.LocalState,
    schedule: n.control_values.ForkSchedule,
    chain: n.chain.Config,
    discovery_bind: ?n.udp.Sockets.Bindings,
    discovery_sequence: u64,
    advertisement: ?n.advertisement.Hints,
    fixed: n.advertisement.Endpoints,
    bootstrap: [bootstrap_max]struct { bytes: [enr_max]u8, len: u16 },
    bootstrap_count: u8,
    slot: u64,
    gossip: n.configuration.GossipOverrides,
    processor_limits: n.gossip_processor.limits.Limits = undefined,
    execution_limits: ?n.gossip_processor.limits.Limits = null,
    allowlist: [32][16]u8,
    allowlist_count: u8,

    pub fn wipe(self: *Config) void {
        std.crypto.secureZero(u8, &self.secret);
    }
};

fn optionalBigint(value: Value) !?u64 {
    return if (try value.typeof() == .null) null else try decode.bigint(value);
}
pub fn bindings(value: Value) !n.udp.Sockets.Bindings {
    if (!try value.isArray()) return .single(try decode.endpoint(value));
    const count = try decode.array(value, 2);
    if (count == 0) return error.InvalidNetworkConfig;
    const first = try decode.endpoint(try value.getElement(0));
    if (count == 1) return .single(first);
    const second = try decode.endpoint(try value.getElement(1));
    if (std.meta.activeTag(first) == std.meta.activeTag(second)) return error.InvalidNetworkConfig;
    return .{ .dual = .{
        .ip4 = if (first == .ip4) first.ip4 else second.ip4,
        .ip6 = if (first == .ip6) first.ip6 else second.ip6,
    } };
}

pub fn parse(value: Value, beacon: *const BeaconConfig, out: *Config) !void {
    out.* = .{
        .secret = @splat(0),
        .bind = undefined,
        .local = .{},
        .schedule = .{},
        .chain = undefined,
        .discovery_bind = null,
        .discovery_sequence = 0,
        .advertisement = null,
        .fixed = .{},
        .bootstrap = undefined,
        .bootstrap_count = 0,
        .slot = 0,
        .gossip = undefined,
        .allowlist = undefined,
        .allowlist_count = 0,
    };
    errdefer out.wipe();
    out.secret = try decode.fixed(32, try decode.get(value, "identitySecretKey"));
    out.bind = try bindings(try decode.get(value, "bind"));
    out.slot = try decode.bigint(try decode.get(value, "initialSlot"));
    try parseLocal(try decode.get(value, "local"), &out.local);
    out.chain = try n.chain.Config.init(beacon, try decode.boolean(try decode.get(value, "serveLightClients")));
    const update = try out.chain.update(out.local, null, out.slot);
    out.local = update.local;
    out.schedule = update.schedule;
    const discovery = try decode.get(value, "discovery");
    if (try discovery.typeof() != .null) {
        try decode.object(discovery, &.{ "bind", "sequenceNumber", "bootstrapEnrs", "advertisement", "fixed" });
        out.discovery_bind = try bindings(try decode.get(discovery, "bind"));
        out.discovery_sequence = try decode.bigint(try decode.get(discovery, "sequenceNumber"));
        const bootstrap = try decode.get(discovery, "bootstrapEnrs");
        out.bootstrap_count = @intCast(try decode.array(bootstrap, bootstrap_max));
        for (0..out.bootstrap_count) |i| {
            const entry = try bootstrap.getElement(@intCast(i));
            const view = try decode.byteView(entry);
            if (view.len == 0 or view.len > enr_max) return error.InvalidNetworkBytes;
            @memcpy(out.bootstrap[i].bytes[0..view.len], view);
            out.bootstrap[i].len = @intCast(view.len);
        }
        const hints = try decode.get(discovery, "advertisement");
        if (try hints.typeof() != .null) {
            try decode.object(hints, &.{ "ip4", "ip6", "udp", "udp6" });
            const endpoints = (try parseEndpoints(hints)).?;
            out.advertisement = .{ .ip4 = endpoints.ip4, .ip6 = endpoints.ip6, .udp = endpoints.udp, .udp6 = endpoints.udp6 };
        }
        out.fixed = (try parseEndpoints(try decode.get(discovery, "fixed"))) orelse return error.InvalidNetworkConfig;
        if (out.fixed.ip6) |ip| if (n.Address.isIp4Mapped(ip)) return error.InvalidNetworkConfig;
        inline for (.{ out.fixed.udp, out.fixed.udp6, out.fixed.quic, out.fixed.quic6 }) |port| if (port == 0) return error.InvalidNetworkInteger;
    }
    try parseGossip(value, out);
}

fn parseGossipLimits(value: Value, items_max: u32, bytes_max: u32) !n.gossip_processor.limits.Limits {
    try decode.completeObject(value, &topic_kind_names);
    var limits: n.gossip_processor.limits.Limits = undefined;
    inline for (std.meta.fields(n.gossip_processor.limits.Kind), 0..) |field, index| {
        const entry = try decode.get(value, field.name);
        try decode.completeObject(entry, &.{ "items", "bytes" });
        limits[index] = .{
            .items = @intCast(try decode.integer(try decode.get(entry, "items"), items_max)),
            .bytes = @intCast(try decode.integer(try decode.get(entry, "bytes"), bytes_max)),
        };
    }
    return limits;
}

fn parseGossip(value: Value, out: *Config) !void {
    out.gossip = .{};
    const policy = try decode.get(value, "gossipPolicy");
    try decode.object(policy, &.{ "iwantFollowupMs", "idontwantMinDataSize", "heartbeatIntervalMs", "validationTimeoutMs", "validationTombstoneMs", "pressureTimeoutMs", "txTimeoutMs", "activeSendTimeoutMs", "activeSendItems", "largeFrameTimeoutMs", "receiveBufferBytes", "seenTtlMs", "retainedScoreMs", "opportunisticGraftIntervalMs", "gossipFactor", "ipAllowlist", "score", "processor", "execution" });
    const processor = try decode.get(policy, "processor");
    {
        const limits_mod = n.gossip_processor.limits;
        const limits = parseGossipLimits(processor, limits_mod.capacity_max, 256 * 1024 * 1024) catch return error.InvalidGossipProcessorLimits;
        try limits_mod.validate(&limits);
        out.processor_limits = limits;
        out.gossip.payload_limits = limits;
    }
    const execution = try decode.get(policy, "execution");
    if (try execution.typeof() != .undefined) {
        out.execution_limits = parseGossipLimits(execution, 16384, 1024 * 1024 * 1024) catch return error.InvalidGossipExecutionLimits;
    }
    out.gossip.iwant_followup_ms = try decode.bigint(try decode.get(policy, "iwantFollowupMs"));
    out.gossip.idontwant_min_data_size = @as(usize, @intCast(try decode.integer(try decode.get(policy, "idontwantMinDataSize"), n.gossipsub.constants.GOSSIP_MAX_SIZE)));
    out.gossip.heartbeat_interval_ms = try decode.bigint(try decode.get(policy, "heartbeatIntervalMs"));
    out.gossip.validation_timeout_ms = try decode.bigint(try decode.get(policy, "validationTimeoutMs"));
    out.gossip.validation_tombstone_ms = try decode.bigint(try decode.get(policy, "validationTombstoneMs"));
    out.gossip.pressure_timeout_ms = try decode.bigint(try decode.get(policy, "pressureTimeoutMs"));
    out.gossip.tx_timeout_ms = try decode.bigint(try decode.get(policy, "txTimeoutMs"));
    out.gossip.active_send_timeout_ms = try decode.bigint(try decode.get(policy, "activeSendTimeoutMs"));
    const active_items = try decode.get(policy, "activeSendItems");
    var item_limits: @FieldType(n.gossipsub.Gossipsub.Options, "active_send_items") = undefined;
    try decode.completeObject(active_items, &topic_kind_names);
    inline for (std.meta.fields(n.gossipsub.topic.Kind), 0..) |field, index| {
        item_limits[index] = @intCast(try decode.integer(try decode.get(active_items, field.name), n.gossipsub.constants.peers_cap));
    }
    out.gossip.active_send_items = item_limits;
    out.gossip.receive_arena_bytes = @intCast(try decode.integer(try decode.get(policy, "receiveBufferBytes"), 1024 * 1024 * 1024));
    out.gossip.large_frame_timeout_ms = try decode.bigint(try decode.get(policy, "largeFrameTimeoutMs"));
    out.gossip.seen_ttl_ms = try decode.bigint(try decode.get(policy, "seenTtlMs"));
    out.gossip.retained_score_ms = try decode.bigint(try decode.get(policy, "retainedScoreMs"));
    out.gossip.opportunistic_graft_interval_ms = try decode.bigint(try decode.get(policy, "opportunisticGraftIntervalMs"));
    out.gossip.message_id_policy = .{ .phase0_digest = out.chain.phase0_digest };
    out.gossip.gossip_factor = try decode.number(try decode.get(policy, "gossipFactor"));
    const allowlist = try decode.get(policy, "ipAllowlist");
    out.allowlist_count = @intCast(try decode.array(allowlist, out.allowlist.len));
    for (0..out.allowlist_count) |i| out.allowlist[i] = try decode.fixed(16, try allowlist.getElement(@intCast(i)));
    const score = try decode.get(policy, "score");
    try decode.object(score, &.{ "ipColocationWeight", "ipColocationThreshold", "behaviourWeight", "behaviourThreshold", "behaviourDecay", "topicCap", "decayIntervalMs", "decayToZero", "gossipThreshold", "publishThreshold", "graylistThreshold", "opportunisticGraftThreshold", "topics" });
    var params: n.gossipsub.score.Params = .{};
    params.ip_colocation_weight = try decode.number(try decode.get(score, "ipColocationWeight"));
    params.ip_colocation_threshold = @intCast(try decode.integer(try decode.get(score, "ipColocationThreshold"), 65535));
    params.behaviour_weight = try decode.number(try decode.get(score, "behaviourWeight"));
    params.behaviour_threshold = try decode.number(try decode.get(score, "behaviourThreshold"));
    params.behaviour_decay = try decode.number(try decode.get(score, "behaviourDecay"));
    params.topic_cap = try decode.number(try decode.get(score, "topicCap"));
    params.decay_interval_ms = try decode.bigint(try decode.get(score, "decayIntervalMs"));
    params.decay_to_zero = try decode.number(try decode.get(score, "decayToZero"));
    params.gossip_threshold = try decode.number(try decode.get(score, "gossipThreshold"));
    params.publish_threshold = try decode.number(try decode.get(score, "publishThreshold"));
    params.graylist_threshold = try decode.number(try decode.get(score, "graylistThreshold"));
    params.opportunistic_graft_threshold = try decode.number(try decode.get(score, "opportunisticGraftThreshold"));
    const topics = try decode.get(score, "topics");
    try decode.completeObject(topics, &topic_kind_names);
    var policies: [n.gossipsub.topic_policy.kind_count]n.gossipsub.score.TopicPolicy = undefined;
    inline for (std.meta.fields(n.gossipsub.topic.Kind), 0..) |field, i| {
        const topic = try decode.get(topics, field.name);
        try parseTopicParams(topic, &policies[i].params);
        policies[i].mesh_delivery_start_slot = try decode.bigint(try decode.get(topic, "meshDeliveryStartSlot"));
    }
    out.gossip.topic_params = policies;
    out.gossip.initial_slot = out.slot;
    params.topic.weight = 0;
    out.gossip.score_params = params;
}

pub const topic_kind_names = blk: {
    var names: [n.gossipsub.topic_policy.kind_count][]const u8 = undefined;
    for (std.meta.fieldNames(n.gossipsub.topic.Kind), 0..) |name, i| names[i] = name;
    break :blk names;
};

pub fn parseStatus(status: Value, out: *t.Status) !void {
    try decode.object(status, &.{ "finalizedRoot", "finalizedEpoch", "headRoot", "headSlot", "earliestAvailableSlot" });
    out.fork_digest = @splat(0);
    out.finalized_root = try decode.fixed(32, try decode.get(status, "finalizedRoot"));
    out.finalized_epoch = try decode.bigint(try decode.get(status, "finalizedEpoch"));
    out.head_root = try decode.fixed(32, try decode.get(status, "headRoot"));
    out.head_slot = try decode.bigint(try decode.get(status, "headSlot"));
    out.earliest_available_slot = try optionalBigint(try decode.get(status, "earliestAvailableSlot"));
}

pub fn parseLocal(local: Value, out: *t.LocalState) !void {
    try decode.object(local, &.{ "status", "metadata" });
    try parseStatus(try decode.get(local, "status"), &out.status);
    const metadata = try decode.get(local, "metadata");
    try decode.object(metadata, &.{ "sequenceNumber", "attnets", "syncnets", "custodyGroupCount" });
    out.*.metadata.seq_number = try decode.bigint(try decode.get(metadata, "sequenceNumber"));
    out.*.metadata.attnets = try decode.fixed(8, try decode.get(metadata, "attnets"));
    out.*.metadata.syncnets = @intCast(try decode.integer(try decode.get(metadata, "syncnets"), 15));
    out.*.metadata.custody_group_count = try optionalBigint(try decode.get(metadata, "custodyGroupCount"));
    out.fork = .{};
}

pub fn parseTopicParams(topic: Value, out: *n.gossipsub.score.TopicParams) !void {
    try decode.completeObject(topic, &.{ "meshDeliveryStartSlot", "weight", "timeInMeshWeight", "timeInMeshCap", "timeInMeshQuantumMs", "firstDeliveryWeight", "firstDeliveryCap", "firstDeliveryDecay", "meshDeliveryWeight", "meshDeliveryThreshold", "meshDeliveryCap", "meshDeliveryDecay", "meshDeliveryActivationMs", "meshDeliveryWindowMs", "meshFailureWeight", "meshFailureDecay", "invalidWeight", "invalidDecay" });
    out.*.weight = try decode.number(try decode.get(topic, "weight"));
    out.*.time_in_mesh_weight = try decode.number(try decode.get(topic, "timeInMeshWeight"));
    out.*.time_in_mesh_cap = try decode.number(try decode.get(topic, "timeInMeshCap"));
    out.*.time_in_mesh_quantum_ms = try decode.bigint(try decode.get(topic, "timeInMeshQuantumMs"));
    out.*.first_delivery_weight = try decode.number(try decode.get(topic, "firstDeliveryWeight"));
    out.*.first_delivery_cap = try decode.number(try decode.get(topic, "firstDeliveryCap"));
    out.*.first_delivery_decay = try decode.number(try decode.get(topic, "firstDeliveryDecay"));
    out.*.mesh_delivery_weight = try decode.number(try decode.get(topic, "meshDeliveryWeight"));
    out.*.mesh_delivery_threshold = try decode.number(try decode.get(topic, "meshDeliveryThreshold"));
    out.*.mesh_delivery_cap = try decode.number(try decode.get(topic, "meshDeliveryCap"));
    out.*.mesh_delivery_decay = try decode.number(try decode.get(topic, "meshDeliveryDecay"));
    out.*.mesh_delivery_activation_ms = try decode.bigint(try decode.get(topic, "meshDeliveryActivationMs"));
    out.*.mesh_delivery_window_ms = try decode.bigint(try decode.get(topic, "meshDeliveryWindowMs"));
    out.*.mesh_failure_weight = try decode.number(try decode.get(topic, "meshFailureWeight"));
    out.*.mesh_failure_decay = try decode.number(try decode.get(topic, "meshFailureDecay"));
    out.*.invalid_weight = try decode.number(try decode.get(topic, "invalidWeight"));
    out.*.invalid_decay = try decode.number(try decode.get(topic, "invalidDecay"));
}

pub fn parseEndpoints(ad: Value) !?n.advertisement.Endpoints {
    if (try ad.typeof() != .null) {
        try decode.object(ad, &.{ "ip4", "ip6", "udp", "udp6", "quic", "quic6" });
        var result: n.advertisement.Endpoints = .{};
        inline for (.{ "ip4", "ip6" }) |key| {
            if (try ad.hasNamedProperty(key)) @field(result, key) = try decode.fixed(if (std.mem.eql(u8, key, "ip4")) 4 else 16, try decode.get(ad, key));
        }
        inline for (.{ "udp", "udp6", "quic", "quic6" }) |key| {
            if (try ad.hasNamedProperty(key)) {
                const port = try decode.integer(try decode.get(ad, key), 65535);
                @field(result, key) = @intCast(port);
            }
        }
        return result;
    }
    return null;
}
