const std = @import("std");
const napi = @import("zapi:zapi").napi;
const n = @import("network");
const d = @import("discv5");
const Value = napi.Value;
const t = n.peers.types;
const enr_max = d.wire.constants.enr_size_max;
const bootstrap_max = d.types.bootstrap_max;

pub const Config = struct {
    profile: n.configuration.Profile,
    secret: [32]u8,
    bind: n.udp.Bindings,
    local: t.LocalState,
    schedule: n.network_core.ForkSchedule,
    chain: n.chain.Plan,
    discovery_bind: ?n.udp.Bindings,
    discovery_sequence: u64,
    advertisement: ?n.network_core.AdvertisementEndpoints,
    bootstrap: [bootstrap_max]struct { bytes: [enr_max]u8, len: u16 },
    bootstrap_count: u8,
    slot: u64,
    gossip: n.configuration.GossipOverrides,
    allowlist: [32][16]u8,
    allowlist_count: u8,

    pub fn wipe(self: *Config) void {
        std.crypto.secureZero(u8, &self.secret);
    }
};

pub fn object(value: Value, comptime names: []const []const u8) !void {
    if (try value.typeof() != .object or try value.isArray()) return error.InvalidNetworkConfig;
    const keys = try value.getAllPropertyNames(.own_only, .all_properties, .numbers_to_strings);
    const count = try keys.getArrayLength();
    if (count > names.len) return error.InvalidNetworkConfig;
    for (0..count) |i| {
        const key = try keys.getElement(@intCast(i));
        if (try key.typeof() != .string) return error.InvalidNetworkConfig;
        var buf: [80]u8 = undefined;
        const name = try key.getValueStringUtf8(&buf);
        var known = false;
        inline for (names) |allowed| {
            if (std.mem.eql(u8, name, allowed)) known = true;
        }
        if (!known) return error.InvalidNetworkConfig;
    }
}
pub fn get(value: Value, comptime name: [:0]const u8) !Value {
    return value.getNamedProperty(name);
}
pub fn integer(value: Value, max: u64) !u64 {
    if (try value.typeof() != .number) return error.InvalidNetworkInteger;
    const numeric = try value.getValueDouble();
    if (!std.math.isFinite(numeric) or numeric < 0 or numeric > 9007199254740991 or numeric != @trunc(numeric) or numeric > @as(f64, @floatFromInt(max))) return error.InvalidNetworkInteger;
    return @intFromFloat(numeric);
}
pub fn bigint(value: Value) !u64 {
    if (try value.typeof() != .bigint) return error.InvalidNetworkInteger;
    var lossless = false;
    const result = try value.getValueBigintUint64(&lossless);
    if (!lossless) return error.InvalidNetworkInteger;
    return result;
}
fn optionalBigint(value: Value) !?u64 {
    return if (try value.typeof() == .null) null else try bigint(value);
}
pub fn boolean(value: Value) !bool {
    if (try value.typeof() != .boolean) return error.InvalidNetworkConfig;
    return value.getValueBool();
}
pub fn number(value: Value) !f64 {
    if (try value.typeof() != .number) return error.InvalidNetworkConfig;
    const result = try value.getValueDouble();
    if (!std.math.isFinite(result)) return error.InvalidNetworkConfig;
    return result;
}
pub fn bytes(value: Value, out: []u8) !void {
    if (!try value.isTypedarray()) return error.InvalidNetworkBytes;
    const info = try value.getTypedarrayInfo();
    if (info.array_type != .uint8 or info.length != out.len or try info.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    @memcpy(out, info.data);
}
pub fn fixed(comptime len: usize, value: Value) ![len]u8 {
    var out: [len]u8 = undefined;
    try bytes(value, &out);
    return out;
}
pub fn array(value: Value, max: usize) !u32 {
    if (!try value.isArray()) return error.InvalidNetworkConfig;
    const count = try value.getArrayLength();
    if (count > max) return error.InvalidNetworkConfig;
    const env: napi.Env = .{ .env = value.env };
    for (0..count) |i| {
        var buffer: [11]u8 = undefined;
        const index = try std.fmt.bufPrint(&buffer, "{d}", .{i});
        if (!try value.hasOwnProperty(try env.createStringUtf8(index))) return error.InvalidNetworkConfig;
    }
    return count;
}
pub fn fork(value: Value) !t.ForkSeq {
    if (try value.typeof() != .string) return error.InvalidNetworkConfig;
    var buf: [32]u8 = undefined;
    const name = try value.getValueStringUtf8(&buf);
    return std.meta.stringToEnum(t.ForkSeq, name) orelse error.InvalidNetworkConfig;
}
pub fn endpoint(value: Value) !std.Io.net.IpAddress {
    try object(value, &.{ "family", "address", "port" });
    const family = try integer(try get(value, "family"), 6);
    const port: u16 = @intCast(try integer(try get(value, "port"), 65535));
    return switch (family) {
        4 => .{ .ip4 = .{ .bytes = try fixed(4, try get(value, "address")), .port = port } },
        6 => blk: {
            const octets = try fixed(16, try get(value, "address"));
            if (n.Address.isIp4Mapped(octets)) return error.InvalidNetworkConfig;
            break :blk .{ .ip6 = .{ .bytes = octets, .port = port } };
        },
        else => error.InvalidNetworkConfig,
    };
}

pub fn bindings(value: Value) !n.udp.Bindings {
    if (!try value.isArray()) return .single(try endpoint(value));
    const count = try array(value, 2);
    if (count == 0) return error.InvalidNetworkConfig;
    const first = try endpoint(try value.getElement(0));
    if (count == 1) return .single(first);
    const second = try endpoint(try value.getElement(1));
    if (std.meta.activeTag(first) == std.meta.activeTag(second)) return error.InvalidNetworkConfig;
    return .{ .dual = .{
        .ip4 = if (first == .ip4) first.ip4 else second.ip4,
        .ip6 = if (first == .ip6) first.ip6 else second.ip6,
    } };
}

pub fn parse(value: Value, out: *Config) !void {
    out.* = .{
        .profile = .small,
        .secret = @splat(0),
        .bind = undefined,
        .local = .{},
        .schedule = .{},
        .chain = undefined,
        .discovery_bind = null,
        .discovery_sequence = 0,
        .advertisement = null,
        .bootstrap = undefined,
        .bootstrap_count = 0,
        .slot = 0,
        .gossip = undefined,
        .allowlist = undefined,
        .allowlist_count = 0,
    };
    errdefer out.wipe();
    const profile = try get(value, "profile");
    if (try profile.typeof() != .string) return error.InvalidNetworkConfig;
    var buf: [32]u8 = undefined;
    const name = try profile.getValueStringUtf8(&buf);
    out.profile = if (std.mem.eql(u8, name, "small")) .small else if (std.mem.eql(u8, name, "beaconNode")) .beacon_node else return error.InvalidNetworkConfig;
    out.secret = try fixed(32, try get(value, "identitySecretKey"));
    out.bind = try bindings(try get(value, "bind"));
    out.slot = try bigint(try get(value, "initialSlot"));
    try parseLocal(try get(value, "local"), &out.local);
    out.chain = try n.chain.Plan.init(&@import("config.zig").state.config, try boolean(try get(value, "serveLightClients")));
    const update = try out.chain.update(out.local, null, out.slot);
    out.local = update.local;
    out.schedule = update.schedule;
    const discovery = try get(value, "discovery");
    if (try discovery.typeof() != .null) {
        try object(discovery, &.{ "bind", "sequenceNumber", "bootstrapEnrs", "advertisement" });
        out.discovery_bind = try bindings(try get(discovery, "bind"));
        out.discovery_sequence = try bigint(try get(discovery, "sequenceNumber"));
        const bootstrap = try get(discovery, "bootstrapEnrs");
        out.bootstrap_count = @intCast(try array(bootstrap, bootstrap_max));
        for (0..out.bootstrap_count) |i| {
            const entry = try bootstrap.getElement(@intCast(i));
            if (!try entry.isTypedarray()) return error.InvalidNetworkBytes;
            const info = try entry.getTypedarrayInfo();
            if (info.array_type != .uint8 or info.length == 0 or info.length > enr_max or try info.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
            @memcpy(out.bootstrap[i].bytes[0..info.length], info.data);
            out.bootstrap[i].len = @intCast(info.length);
        }
        out.advertisement = try parseEndpoints(try get(discovery, "advertisement"));
    }
    try parseGossip(value, out);
}

fn parseGossip(value: Value, out: *Config) !void {
    out.gossip = .{ .observe_subscriptions = false };
    const policy = try get(value, "gossipPolicy");
    try object(policy, &.{ "iwantFollowupMs", "idontwantMinDataSize", "heartbeatIntervalMs", "validationTimeoutMs", "validationTombstoneMs", "pressureTimeoutMs", "txTimeoutMs", "largeFrameTimeoutMs", "seenTtlMs", "retainedScoreMs", "opportunisticGraftIntervalMs", "gossipFactor", "ipAllowlist", "score", "processor" });
    const processor = try get(policy, "processor");
    if (try processor.typeof() != .undefined) {
        const limits_mod = n.gossip_processor.limits_mod;
        const count = try array(processor, limits_mod.kind_count);
        if (count != limits_mod.kind_count) return error.InvalidGossipProcessorLimits;
        var limits: limits_mod.Limits = undefined;
        for (&limits, 0..) |*limit, i| {
            const value_limit = try processor.getElement(@intCast(i));
            try completeObject(value_limit, &.{ "items", "bytes" });
            limit.* = .{
                .items = @intCast(try integer(try get(value_limit, "items"), limits_mod.capacity_max)),
                .bytes = @intCast(try integer(try get(value_limit, "bytes"), 256 * 1024 * 1024)),
            };
        }
        try limits_mod.validate(&limits);
        out.gossip.processor_limits = limits;
        out.gossip.validation_capacity = limits_mod.items(&limits);
        out.gossip.mcache_arena_bytes = @max(2 * limits_mod.bytes(&limits), n.gossipsub.constants.maxCompressedLen(n.gossipsub.constants.MAX_PAYLOAD_SIZE) + 4096);
    }
    out.gossip.iwant_followup_ms = try bigint(try get(policy, "iwantFollowupMs"));
    out.gossip.idontwant_min_data_size = @as(usize, @intCast(try integer(try get(policy, "idontwantMinDataSize"), n.gossipsub.constants.GOSSIP_MAX_SIZE)));
    out.gossip.heartbeat_interval_ms = try bigint(try get(policy, "heartbeatIntervalMs"));
    out.gossip.validation_timeout_ms = try bigint(try get(policy, "validationTimeoutMs"));
    out.gossip.validation_tombstone_ms = try bigint(try get(policy, "validationTombstoneMs"));
    out.gossip.pressure_timeout_ms = try bigint(try get(policy, "pressureTimeoutMs"));
    out.gossip.tx_timeout_ms = try bigint(try get(policy, "txTimeoutMs"));
    out.gossip.large_frame_timeout_ms = try bigint(try get(policy, "largeFrameTimeoutMs"));
    out.gossip.seen_ttl_ms = try bigint(try get(policy, "seenTtlMs"));
    out.gossip.retained_score_ms = try bigint(try get(policy, "retainedScoreMs"));
    out.gossip.opportunistic_graft_interval_ms = try bigint(try get(policy, "opportunisticGraftIntervalMs"));
    out.gossip.message_id_policy = .{ .phase0_digest = out.chain.phase0_digest };
    out.gossip.gossip_factor = try number(try get(policy, "gossipFactor"));
    const allowlist = try get(policy, "ipAllowlist");
    out.allowlist_count = @intCast(try array(allowlist, out.allowlist.len));
    for (0..out.allowlist_count) |i| out.allowlist[i] = try fixed(16, try allowlist.getElement(@intCast(i)));
    const score = try get(policy, "score");
    try object(score, &.{ "appWeight", "ipColocationWeight", "ipColocationThreshold", "behaviourWeight", "behaviourThreshold", "behaviourDecay", "topicCap", "decayIntervalMs", "decayToZero", "gossipThreshold", "publishThreshold", "graylistThreshold", "opportunisticGraftThreshold", "topics" });
    var params: n.gossipsub.score.Params = .{};
    params.app_weight = try number(try get(score, "appWeight"));
    params.ip_colocation_weight = try number(try get(score, "ipColocationWeight"));
    params.ip_colocation_threshold = @intCast(try integer(try get(score, "ipColocationThreshold"), 65535));
    params.behaviour_weight = try number(try get(score, "behaviourWeight"));
    params.behaviour_threshold = try number(try get(score, "behaviourThreshold"));
    params.behaviour_decay = try number(try get(score, "behaviourDecay"));
    params.topic_cap = try number(try get(score, "topicCap"));
    params.decay_interval_ms = try bigint(try get(score, "decayIntervalMs"));
    params.decay_to_zero = try number(try get(score, "decayToZero"));
    params.gossip_threshold = try number(try get(score, "gossipThreshold"));
    params.publish_threshold = try number(try get(score, "publishThreshold"));
    params.graylist_threshold = try number(try get(score, "graylistThreshold"));
    params.opportunistic_graft_threshold = try number(try get(score, "opportunisticGraftThreshold"));
    const topics = try get(score, "topics");
    try completeObject(topics, &topic_kind_names);
    var policies: [n.gossipsub.topic_policy.kind_count]n.gossipsub.score.TopicPolicy = undefined;
    inline for (std.meta.fields(n.gossipsub.topic.Kind), 0..) |field, i| {
        const topic = try get(topics, field.name);
        try parseTopicParams(topic, &policies[i].params);
        policies[i].mesh_delivery_start_slot = try bigint(try get(topic, "meshDeliveryStartSlot"));
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

pub fn completeObject(value: Value, comptime names: []const []const u8) !void {
    try object(value, names);
    const keys = try value.getAllPropertyNames(.own_only, .all_properties, .numbers_to_strings);
    if (try keys.getArrayLength() != names.len) return error.InvalidNetworkConfig;
}

pub fn parseStatus(status: Value, out: *t.Status) !void {
    try object(status, &.{ "finalizedRoot", "finalizedEpoch", "headRoot", "headSlot", "earliestAvailableSlot" });
    out.fork_digest = @splat(0);
    out.finalized_root = try fixed(32, try get(status, "finalizedRoot"));
    out.finalized_epoch = try bigint(try get(status, "finalizedEpoch"));
    out.head_root = try fixed(32, try get(status, "headRoot"));
    out.head_slot = try bigint(try get(status, "headSlot"));
    out.earliest_available_slot = try optionalBigint(try get(status, "earliestAvailableSlot"));
}

pub fn parseLocal(local: Value, out: *t.LocalState) !void {
    try object(local, &.{ "status", "metadata" });
    try parseStatus(try get(local, "status"), &out.status);
    const metadata = try get(local, "metadata");
    try object(metadata, &.{ "sequenceNumber", "attnets", "syncnets", "custodyGroupCount" });
    out.*.metadata.seq_number = try bigint(try get(metadata, "sequenceNumber"));
    out.*.metadata.attnets = try fixed(8, try get(metadata, "attnets"));
    out.*.metadata.syncnets = @intCast(try integer(try get(metadata, "syncnets"), 15));
    out.*.metadata.custody_group_count = try optionalBigint(try get(metadata, "custodyGroupCount"));
    out.fork = .{};
}

pub fn parseTopicParams(topic: Value, out: *n.gossipsub.score.TopicParams) !void {
    try completeObject(topic, &.{ "meshDeliveryStartSlot", "weight", "timeInMeshWeight", "timeInMeshCap", "timeInMeshQuantumMs", "firstDeliveryWeight", "firstDeliveryCap", "firstDeliveryDecay", "meshDeliveryWeight", "meshDeliveryThreshold", "meshDeliveryCap", "meshDeliveryDecay", "meshDeliveryActivationMs", "meshDeliveryWindowMs", "meshFailureWeight", "meshFailureDecay", "invalidWeight", "invalidDecay" });
    out.*.weight = try number(try get(topic, "weight"));
    out.*.time_in_mesh_weight = try number(try get(topic, "timeInMeshWeight"));
    out.*.time_in_mesh_cap = try number(try get(topic, "timeInMeshCap"));
    out.*.time_in_mesh_quantum_ms = try bigint(try get(topic, "timeInMeshQuantumMs"));
    out.*.first_delivery_weight = try number(try get(topic, "firstDeliveryWeight"));
    out.*.first_delivery_cap = try number(try get(topic, "firstDeliveryCap"));
    out.*.first_delivery_decay = try number(try get(topic, "firstDeliveryDecay"));
    out.*.mesh_delivery_weight = try number(try get(topic, "meshDeliveryWeight"));
    out.*.mesh_delivery_threshold = try number(try get(topic, "meshDeliveryThreshold"));
    out.*.mesh_delivery_cap = try number(try get(topic, "meshDeliveryCap"));
    out.*.mesh_delivery_decay = try number(try get(topic, "meshDeliveryDecay"));
    out.*.mesh_delivery_activation_ms = try bigint(try get(topic, "meshDeliveryActivationMs"));
    out.*.mesh_delivery_window_ms = try bigint(try get(topic, "meshDeliveryWindowMs"));
    out.*.mesh_failure_weight = try number(try get(topic, "meshFailureWeight"));
    out.*.mesh_failure_decay = try number(try get(topic, "meshFailureDecay"));
    out.*.invalid_weight = try number(try get(topic, "invalidWeight"));
    out.*.invalid_decay = try number(try get(topic, "invalidDecay"));
}

pub fn parseEndpoints(ad: Value) !?n.network_core.AdvertisementEndpoints {
    if (try ad.typeof() != .null) {
        try object(ad, &.{ "ip4", "ip6", "udp", "udp6", "quic", "quic6" });
        var result: n.network_core.AdvertisementEndpoints = .{};
        inline for (.{ "ip4", "ip6" }) |key| {
            if (try ad.hasNamedProperty(key)) @field(result, key) = try fixed(if (std.mem.eql(u8, key, "ip4")) 4 else 16, try get(ad, key));
        }
        if (result.ip6) |ip| if (n.Address.isIp4Mapped(ip)) return error.InvalidNetworkConfig;
        inline for (.{ "udp", "udp6", "quic", "quic6" }) |key| {
            if (try ad.hasNamedProperty(key)) {
                const port = try integer(try get(ad, key), 65535);
                if (port == 0) return error.InvalidNetworkInteger;
                @field(result, key) = @intCast(port);
            }
        }
        return result;
    }
    return null;
}
