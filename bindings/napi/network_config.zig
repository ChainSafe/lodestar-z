const std = @import("std");
const napi = @import("zapi:zapi").napi;
const n = @import("network");
const d = @import("discv5");
const Value = napi.Value;
const t = n.peers.types;
const enr_max = d.wire.constants.enr_size_max;
const bootstrap_max = d.Maintenance.bootstrap_max;

pub const Config = struct {
    profile: n.configuration.Profile,
    secret: [32]u8,
    bind: std.Io.net.IpAddress,
    local: t.LocalState,
    schedule: n.network_core.ForkSchedule,
    forks: [64]n.reqresp.ForkEntry,
    fork_count: u8,
    discovery_bind: ?std.Io.net.IpAddress,
    discovery_sequence: u64,
    advertisement: ?n.network_core.AdvertisementEndpoints,
    bootstrap: [bootstrap_max]struct { bytes: [enr_max]u8, len: u16 },
    bootstrap_count: u8,
    slot: u64,
    gossip: n.gossipsub.Options,
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
fn get(value: Value, comptime name: [:0]const u8) !Value {
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
fn boolean(value: Value) !bool {
    if (try value.typeof() != .boolean) return error.InvalidNetworkConfig;
    return value.getValueBool();
}
fn number(value: Value) !f64 {
    if (try value.typeof() != .number) return error.InvalidNetworkConfig;
    const result = try value.getValueDouble();
    if (!std.math.isFinite(result)) return error.InvalidNetworkConfig;
    return result;
}
fn bytes(value: Value, out: []u8) !void {
    if (!try value.isTypedarray()) return error.InvalidNetworkBytes;
    const info = try value.getTypedarrayInfo();
    if (info.array_type != .uint8 or info.length != out.len or try info.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    @memcpy(out, info.data);
}
fn fixed(comptime len: usize, value: Value) ![len]u8 {
    var out: [len]u8 = undefined;
    try bytes(value, &out);
    return out;
}
fn array(value: Value, max: usize) !u32 {
    if (!try value.isArray()) return error.InvalidNetworkConfig;
    const count = try value.getArrayLength();
    if (count > max) return error.InvalidNetworkConfig;
    return count;
}
fn fork(value: Value) !t.ForkSeq {
    if (try value.typeof() != .string) return error.InvalidNetworkConfig;
    var buf: [32]u8 = undefined;
    const name = try value.getValueStringUtf8(&buf);
    inline for (.{ "phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu", "gloas" }) |tag| {
        if (std.mem.eql(u8, name, tag)) return @field(t.ForkSeq, tag);
    }
    return error.InvalidNetworkConfig;
}
fn endpoint(value: Value) !std.Io.net.IpAddress {
    try object(value, &.{ "family", "address", "port" });
    const family = try integer(try get(value, "family"), 6);
    const port: u16 = @intCast(try integer(try get(value, "port"), 65535));
    return switch (family) {
        4 => .{ .ip4 = .{ .bytes = try fixed(4, try get(value, "address")), .port = port } },
        6 => .{ .ip6 = .{ .bytes = try fixed(16, try get(value, "address")), .port = port } },
        else => error.InvalidNetworkConfig,
    };
}

pub fn parse(value: Value, out: *Config) !void {
    out.* = .{
        .profile = .small,
        .secret = @splat(0),
        .bind = undefined,
        .local = .{},
        .schedule = .{},
        .forks = undefined,
        .fork_count = 0,
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
    try object(value, &.{ "profile", "identitySecretKey", "bind", "local", "forkSchedule", "requestForks", "discovery", "initialSlot", "gossipPolicy" });
    const profile = try get(value, "profile");
    if (try profile.typeof() != .string) return error.InvalidNetworkConfig;
    var buf: [32]u8 = undefined;
    const name = try profile.getValueStringUtf8(&buf);
    out.profile = if (std.mem.eql(u8, name, "small")) .small else if (std.mem.eql(u8, name, "beaconNode")) .beacon_node else return error.InvalidNetworkConfig;
    out.secret = try fixed(32, try get(value, "identitySecretKey"));
    out.bind = try endpoint(try get(value, "bind"));
    out.slot = try bigint(try get(value, "initialSlot"));
    const local = try get(value, "local");
    try object(local, &.{ "status", "metadata", "fork" });
    const status = try get(local, "status");
    try object(status, &.{ "forkDigest", "finalizedRoot", "finalizedEpoch", "headRoot", "headSlot", "earliestAvailableSlot" });
    out.local.status.fork_digest = try fixed(4, try get(status, "forkDigest"));
    out.local.status.finalized_root = try fixed(32, try get(status, "finalizedRoot"));
    out.local.status.finalized_epoch = try bigint(try get(status, "finalizedEpoch"));
    out.local.status.head_root = try fixed(32, try get(status, "headRoot"));
    out.local.status.head_slot = try bigint(try get(status, "headSlot"));
    out.local.status.earliest_available_slot = try optionalBigint(try get(status, "earliestAvailableSlot"));
    const metadata = try get(local, "metadata");
    try object(metadata, &.{ "sequenceNumber", "attnets", "syncnets", "custodyGroupCount" });
    out.local.metadata.seq_number = try bigint(try get(metadata, "sequenceNumber"));
    out.local.metadata.attnets = try fixed(8, try get(metadata, "attnets"));
    out.local.metadata.syncnets = @intCast(try integer(try get(metadata, "syncnets"), 15));
    out.local.metadata.custody_group_count = try optionalBigint(try get(metadata, "custodyGroupCount"));
    const context = try get(local, "fork");
    try object(context, &.{ "fork", "digest", "custodyGroups" });
    out.local.fork.fork = try fork(try get(context, "fork"));
    out.local.fork.digest = try fixed(4, try get(context, "digest"));
    out.local.fork.custody_groups = @intCast(try integer(try get(context, "custodyGroups"), 128));
    const schedule = try get(value, "forkSchedule");
    try object(schedule, &.{ "fuluScheduled", "nextVersion", "nextEpoch", "nextDigest" });
    out.schedule.fulu_scheduled = try boolean(try get(schedule, "fuluScheduled"));
    out.schedule.next_version = try fixed(4, try get(schedule, "nextVersion"));
    out.schedule.next_epoch = try bigint(try get(schedule, "nextEpoch"));
    out.schedule.next_digest = try fixed(4, try get(schedule, "nextDigest"));
    out.local.fork.validate() catch return error.InvalidNetworkConfig;
    var checked: t.LocalState = undefined;
    n.peers.control_wire.copyLocal(&checked, &out.local) catch return error.InvalidNetworkConfig;
    const forks = try get(value, "requestForks");
    out.fork_count = @intCast(try array(forks, out.forks.len));
    for (0..out.fork_count) |i| {
        const entry = try forks.getElement(@intCast(i));
        try object(entry, &.{ "digest", "fork" });
        out.forks[i] = .{ .digest = try fixed(4, try get(entry, "digest")), .fork = try fork(try get(entry, "fork")) };
        for (out.forks[0..i]) |previous| {
            if (std.mem.eql(u8, &previous.digest, &out.forks[i].digest)) return error.InvalidNetworkConfig;
        }
    }
    const discovery = try get(value, "discovery");
    if (try discovery.typeof() != .null) {
        try object(discovery, &.{ "bind", "sequenceNumber", "bootstrapEnrs", "advertisement" });
        out.discovery_bind = try endpoint(try get(discovery, "bind"));
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
        const ad = try get(discovery, "advertisement");
        if (try ad.typeof() != .null) {
            try object(ad, &.{ "ip4", "ip6", "udp", "udp6", "quic", "quic6" });
            var result: n.network_core.AdvertisementEndpoints = .{};
            inline for (.{ "ip4", "ip6" }) |key| {
                if (try ad.hasNamedProperty(key)) @field(result, key) = try fixed(if (std.mem.eql(u8, key, "ip4")) 4 else 16, try get(ad, key));
            }
            inline for (.{ "udp", "udp6", "quic", "quic6" }) |key| {
                if (try ad.hasNamedProperty(key)) {
                    const port = try integer(try get(ad, key), 65535);
                    if (port == 0) return error.InvalidNetworkInteger;
                    @field(result, key) = @intCast(port);
                }
            }
            out.advertisement = result;
        }
    }
    const resolved = n.configuration.resolve(.{ .profile = out.profile, .seed = 1, .forks = out.forks[0..out.fork_count] }) catch return error.InvalidNetworkConfig;
    out.gossip = resolved.core.service.gossipsub;
    const policy = try get(value, "gossipPolicy");
    try object(policy, &.{ "phase0Digest", "heartbeatIntervalMs", "validationTimeoutMs", "validationTombstoneMs", "pressureTimeoutMs", "txTimeoutMs", "largeFrameTimeoutMs", "seenTtlMs", "retainedScoreMs", "opportunisticGraftIntervalMs", "gossipFactor", "ipAllowlist", "score" });
    out.gossip.heartbeat_interval_ms = try bigint(try get(policy, "heartbeatIntervalMs"));
    out.gossip.validation_timeout_ms = try bigint(try get(policy, "validationTimeoutMs"));
    out.gossip.validation_tombstone_ms = try bigint(try get(policy, "validationTombstoneMs"));
    out.gossip.pressure_timeout_ms = try bigint(try get(policy, "pressureTimeoutMs"));
    out.gossip.tx_timeout_ms = try bigint(try get(policy, "txTimeoutMs"));
    out.gossip.large_frame_timeout_ms = try bigint(try get(policy, "largeFrameTimeoutMs"));
    out.gossip.seen_ttl_ms = try bigint(try get(policy, "seenTtlMs"));
    out.gossip.retained_score_ms = try bigint(try get(policy, "retainedScoreMs"));
    out.gossip.opportunistic_graft_interval_ms = try bigint(try get(policy, "opportunisticGraftIntervalMs"));
    const phase0 = try get(policy, "phase0Digest");
    out.gossip.message_id_policy.phase0_digest = if (try phase0.typeof() == .null) null else try fixed(4, phase0);
    out.gossip.gossip_factor = try number(try get(policy, "gossipFactor"));
    const allowlist = try get(policy, "ipAllowlist");
    out.allowlist_count = @intCast(try array(allowlist, out.allowlist.len));
    for (0..out.allowlist_count) |i| out.allowlist[i] = try fixed(16, try allowlist.getElement(@intCast(i)));
    const score = try get(policy, "score");
    try object(score, &.{ "appWeight", "ipColocationWeight", "ipColocationThreshold", "behaviourWeight", "behaviourThreshold", "behaviourDecay", "topicCap", "decayIntervalMs", "decayToZero", "gossipThreshold", "publishThreshold", "graylistThreshold", "opportunisticGraftThreshold", "defaultTopic" });
    out.gossip.score_params.app_weight = try number(try get(score, "appWeight"));
    out.gossip.score_params.ip_colocation_weight = try number(try get(score, "ipColocationWeight"));
    out.gossip.score_params.ip_colocation_threshold = @intCast(try integer(try get(score, "ipColocationThreshold"), 65535));
    out.gossip.score_params.behaviour_weight = try number(try get(score, "behaviourWeight"));
    out.gossip.score_params.behaviour_threshold = try number(try get(score, "behaviourThreshold"));
    out.gossip.score_params.behaviour_decay = try number(try get(score, "behaviourDecay"));
    out.gossip.score_params.topic_cap = try number(try get(score, "topicCap"));
    out.gossip.score_params.decay_interval_ms = try bigint(try get(score, "decayIntervalMs"));
    out.gossip.score_params.decay_to_zero = try number(try get(score, "decayToZero"));
    out.gossip.score_params.gossip_threshold = try number(try get(score, "gossipThreshold"));
    out.gossip.score_params.publish_threshold = try number(try get(score, "publishThreshold"));
    out.gossip.score_params.graylist_threshold = try number(try get(score, "graylistThreshold"));
    out.gossip.score_params.opportunistic_graft_threshold = try number(try get(score, "opportunisticGraftThreshold"));
    const topic = try get(score, "defaultTopic");
    try object(topic, &.{ "weight", "timeInMeshWeight", "timeInMeshCap", "timeInMeshQuantumMs", "firstDeliveryWeight", "firstDeliveryCap", "firstDeliveryDecay", "meshDeliveryWeight", "meshDeliveryThreshold", "meshDeliveryCap", "meshDeliveryDecay", "meshDeliveryActivationMs", "meshDeliveryWindowMs", "meshFailureWeight", "meshFailureDecay", "invalidWeight", "invalidDecay" });
    out.gossip.score_params.topic.weight = try number(try get(topic, "weight"));
    out.gossip.score_params.topic.time_in_mesh_weight = try number(try get(topic, "timeInMeshWeight"));
    out.gossip.score_params.topic.time_in_mesh_cap = try number(try get(topic, "timeInMeshCap"));
    out.gossip.score_params.topic.time_in_mesh_quantum_ms = try bigint(try get(topic, "timeInMeshQuantumMs"));
    out.gossip.score_params.topic.first_delivery_weight = try number(try get(topic, "firstDeliveryWeight"));
    out.gossip.score_params.topic.first_delivery_cap = try number(try get(topic, "firstDeliveryCap"));
    out.gossip.score_params.topic.first_delivery_decay = try number(try get(topic, "firstDeliveryDecay"));
    out.gossip.score_params.topic.mesh_delivery_weight = try number(try get(topic, "meshDeliveryWeight"));
    out.gossip.score_params.topic.mesh_delivery_threshold = try number(try get(topic, "meshDeliveryThreshold"));
    out.gossip.score_params.topic.mesh_delivery_cap = try number(try get(topic, "meshDeliveryCap"));
    out.gossip.score_params.topic.mesh_delivery_decay = try number(try get(topic, "meshDeliveryDecay"));
    out.gossip.score_params.topic.mesh_delivery_activation_ms = try bigint(try get(topic, "meshDeliveryActivationMs"));
    out.gossip.score_params.topic.mesh_delivery_window_ms = try bigint(try get(topic, "meshDeliveryWindowMs"));
    out.gossip.score_params.topic.mesh_failure_weight = try number(try get(topic, "meshFailureWeight"));
    out.gossip.score_params.topic.mesh_failure_decay = try number(try get(topic, "meshFailureDecay"));
    out.gossip.score_params.topic.invalid_weight = try number(try get(topic, "invalidWeight"));
    out.gossip.score_params.topic.invalid_decay = try number(try get(topic, "invalidDecay"));
    var options = resolved.core;
    options.service.gossipsub = out.gossip;
    n.configuration.validate(resolved.limits, options) catch return error.InvalidNetworkConfig;
}
