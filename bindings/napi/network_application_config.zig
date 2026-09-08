const std = @import("std");
const n = @import("network");
const cfg = @import("network_config.zig");
const Value = @import("zapi:zapi").napi.Value;
const policy = n.reqresp.request_policy;

pub const Config = struct {
    resources: Resources,
    request: policy.Config,
    blobs: [64]policy.BlobLimit,
    agent: [256]u8,
    agent_len: u16,
    version: [64]u8,
    version_len: u8,
    capabilities: n.capabilities.Directional,

    pub fn resolve(self: *const Config, common: *const cfg.Config, seed: u64) !n.configuration.Request {
        var base = try n.configuration.resolve(.{ .profile = common.profile, .seed = seed, .forks = common.forks[0..common.fork_count] });
        const r = &self.resources;
        if (r.nativeBudgetBytes <= @sizeOf(n.NetworkCore)) return error.NetworkNativeBudgetExceeded;
        base.limits.connections_max = r.connectionCapacity;
        base.limits.handshaking_max = r.handshakingCapacity;
        base.limits.dialing_max = r.dialingCapacity;
        base.limits.receive_budget_bytes = r.receiveBudgetBytes;
        base.core.peers = .{ .capacity = r.peerCapacity, .target_peers = r.targetPeers, .max_peers = r.maxPeers, .min_outbound = r.minOutbound, .outbound_reserve = r.outboundReserve, .engine_capacity = r.connectionCapacity };
        base.core.dial.engine_dialing_max = r.dialingCapacity;
        base.core.dial.concurrent_max = @min(base.core.dial.concurrent_max, r.dialingCapacity);
        base.core.service.reqresp.peers = r.connectionCapacity;
        base.core.service.reqresp.request_policy = self.request;
        base.core.service.gossipsub = common.gossip;
        base.core.service.gossipsub.random_seed = seed;
        base.core.service.gossipsub.connected_capacity = r.maxPeers;
        base.core.service.gossipsub.retained_capacity = r.peerCapacity;
        base.core.service.gossipsub.retained_outbound_reserve = r.outboundReserve;
        base.core.service.gossipsub.ip_allowlist = common.allowlist[0..common.allowlist_count];
        base.core.service.gossipsub.topic_policy = common.topic_boundaries[0..common.topic_boundary_count];
        base.core.service.router.identify = true;
        base.core.service.router.capabilities = self.capabilities;
        base.core.service.identify.?.agent = self.agent[0..self.agent_len];
        base.core.service.identify.?.protocol_version = self.version[0..self.version_len];
        const request: n.configuration.Request = .{ .profile = common.profile, .seed = seed, .forks = common.forks[0..common.fork_count], .limits = base.limits, .peers = base.core.peers, .dial = base.core.dial, .reqresp = base.core.service.reqresp, .gossip = base.core.service.gossipsub, .router = base.core.service.router, .identify = base.core.service.identify, .control = base.core.control, .byte_limit = r.nativeBudgetBytes - @sizeOf(n.NetworkCore) };
        _ = try n.configuration.resolve(request);
        return request;
    }
};
pub const Resources = struct {
    peerCapacity: u16,
    targetPeers: u16,
    maxPeers: u16,
    minOutbound: u16,
    outboundReserve: u16,
    connectionCapacity: u16,
    handshakingCapacity: u16,
    dialingCapacity: u16,
    receiveBudgetBytes: u64,
    nativeBudgetBytes: usize,
    bridgeBudgetBytes: usize,
};

pub fn text(value: Value, out: []u8) !usize {
    if (try value.typeof() != .string) return error.InvalidNetworkConfig;
    const napi = @import("zapi:zapi").napi;
    var len: usize = 0;
    try napi.status.check(napi.c.napi_get_value_string_utf8(value.env, value.value, null, 0, &len));
    if (len > out.len) return error.InvalidNetworkConfig;
    var buffer: [1025]u8 = undefined;
    if (len + 1 > buffer.len) return error.InvalidNetworkConfig;
    const copied = try value.getValueStringUtf8(buffer[0 .. len + 1]);
    if (copied.len != len or !std.unicode.utf8ValidateSlice(copied)) return error.InvalidNetworkConfig;
    @memcpy(out[0..len], copied);
    return len;
}
pub fn capabilities(value: Value) !n.capabilities.Directional {
    try cfg.completeObject(value, &.{ "receive", "request" });
    var result: n.capabilities.Directional = undefined;
    inline for (.{ "receive", "request" }) |name| {
        const list = try cfg.get(value, name);
        const count = try cfg.array(list, n.capabilities.protocol_count);
        var set: n.capabilities.Set = .initEmpty();
        for (0..count) |i| {
            var bytes: [128]u8 = undefined;
            const len = try text(try list.getElement(@intCast(i)), &bytes);
            const protocol = n.router.Protocol.fromId(bytes[0..len]) orelse return error.InvalidCapabilities;
            if (set.contains(protocol)) return error.InvalidCapabilities;
            set.insert(protocol);
        }
        @field(result, name) = set;
    }
    return result;
}
pub fn validateCapabilities(active: n.capabilities.Directional, local: *const n.peers.types.LocalState) !void {
    if (local.metadata.custody_group_count == null) return error.MissingCustodyAdvertisement;
    const required = n.capabilities.withIdentify(try n.capabilities.forFork(local.fork.fork, false, &.{ .v1_2, .v1_1, .v1_0 }));
    inline for (.{ "receive", "request" }) |direction| {
        const set = @field(active, direction);
        const expected = @field(required, direction);
        for (0..n.reqresp.Protocol.count) |i| {
            const protocol: n.reqresp.Protocol = @enumFromInt(i);
            if (protocol.isControl() and expected.contains(.{ .reqresp = protocol }) and !set.contains(.{ .reqresp = protocol })) return error.InvalidCapabilities;
        }
        if (!set.contains(.identify)) return error.InvalidCapabilities;
    }
}
pub fn parse(value: Value, common: *cfg.Config, out: *Config) !void {
    try cfg.completeObject(value, &.{ "profile", "identitySecretKey", "bind", "local", "forkSchedule", "requestForks", "discovery", "initialSlot", "gossipPolicy", "topicPolicy", "resources", "requestPolicy", "identify", "capabilities" });
    try cfg.parseCommon(value, common);
    errdefer common.wipe();
    if (common.topic_boundary_count == 0) return error.TopicPolicyRequired;
    const resources = try cfg.get(value, "resources");
    try cfg.completeObject(resources, &.{ "peerCapacity", "targetPeers", "maxPeers", "minOutbound", "outboundReserve", "connectionCapacity", "handshakingCapacity", "dialingCapacity", "receiveBudgetBytes", "nativeBudgetBytes", "bridgeBudgetBytes" });
    inline for (@typeInfo(Resources).@"struct".fields) |field| {
        const max: u64 = if (std.mem.eql(u8, field.name, "receiveBudgetBytes")) 9007199254740991 else if (std.mem.endsWith(u8, field.name, "Bytes")) 1024 * 1024 * 1024 else if (std.mem.eql(u8, field.name, "peerCapacity") or std.mem.eql(u8, field.name, "outboundReserve")) 4096 else 256;
        @field(out.resources, field.name) = @intCast(try cfg.integer(try cfg.get(resources, field.name), max));
    }
    if (out.resources.nativeBudgetBytes == 0 or out.resources.bridgeBudgetBytes == 0) return error.InvalidNetworkInteger;
    const input = try cfg.get(value, "requestPolicy");
    try cfg.completeObject(input, &.{ "denebStartSlot", "blocksPreDeneb", "blocksDeneb", "blobIdentifiersDeneb", "blobIdentifiersElectra", "numberOfColumns", "columnChunks", "blobSchedule", "hostIntegerMax" });
    out.request.deneb_start_slot = try cfg.optionalBigint(try cfg.get(input, "denebStartSlot"));
    out.request.host_integer_max = try cfg.optionalBigint(try cfg.get(input, "hostIntegerMax"));
    inline for (.{ .{ "blocksPreDeneb", "blocks_pre_deneb" }, .{ "blocksDeneb", "blocks_deneb" }, .{ "blobIdentifiersDeneb", "blob_identifiers_deneb" }, .{ "blobIdentifiersElectra", "blob_identifiers_electra" }, .{ "columnChunks", "column_chunks" }, .{ "numberOfColumns", "number_of_columns" } }) |pair| {
        @field(out.request, pair[1]) = @intCast(try cfg.integer(try cfg.get(input, pair[0]), std.math.maxInt(@TypeOf(@field(out.request, pair[1])))));
    }
    const blobs = try cfg.get(input, "blobSchedule");
    const count = try cfg.array(blobs, 64);
    for (out.blobs[0..count], 0..) |*blob, i| {
        const entry = try blobs.getElement(@intCast(i));
        try cfg.completeObject(entry, &.{ "startSlot", "maxBlobs" });
        blob.* = .{ .start_slot = try cfg.bigint(try cfg.get(entry, "startSlot")), .max_blobs = @intCast(try cfg.integer(try cfg.get(entry, "maxBlobs"), std.math.maxInt(u32))) };
    }
    out.request.blob_schedule = out.blobs[0..count];
    _ = try policy.Policy.init(&out.request);
    const identify = try cfg.get(value, "identify");
    try cfg.completeObject(identify, &.{ "agentVersion", "protocolVersion" });
    out.agent_len = @intCast(try text(try cfg.get(identify, "agentVersion"), &out.agent));
    out.version_len = @intCast(try text(try cfg.get(identify, "protocolVersion"), &out.version));
    out.capabilities = try capabilities(try cfg.get(value, "capabilities"));
    try validateCapabilities(out.capabilities, &common.local);
    _ = try out.resolve(common, 1);
}

pub const Intent = struct {
    value: n.network_core.LocalIntent,
    names: [512][n.gossipsub.topic.topic_max_len]u8,
    subscriptions: [512]n.gossipsub.local_intent.Subscription,
};
pub fn parseIntent(value: Value, out: *Intent, max_peers: u16) !void {
    try cfg.completeObject(value, &.{ "update", "demand", "subscriptions" });
    const update = try cfg.get(value, "update");
    try cfg.completeObject(update, &.{ "local", "schedule", "endpoints", "capabilities" });
    try cfg.parseLocal(try cfg.get(update, "local"), &out.value.update.local);
    try cfg.parseSchedule(try cfg.get(update, "schedule"), &out.value.update.schedule);
    out.value.update.endpoints = try cfg.parseEndpoints(try cfg.get(update, "endpoints"));
    out.value.update.capabilities = try capabilities(try cfg.get(update, "capabilities"));
    try validateCapabilities(out.value.update.capabilities, &out.value.update.local);
    const demand = try cfg.get(value, "demand");
    try cfg.completeObject(demand, &.{ "attnets", "syncnets", "groupTargets", "attestationTarget", "syncTarget", "expiresAtSlot" });
    const attnets = try cfg.fixed(8, try cfg.get(demand, "attnets"));
    out.value.demand.attnets = std.mem.readInt(u64, &attnets, .little);
    out.value.demand.syncnets = @intCast(try cfg.integer(try cfg.get(demand, "syncnets"), 15));
    out.value.demand.attestation_target = @intCast(try cfg.integer(try cfg.get(demand, "attestationTarget"), max_peers));
    out.value.demand.sync_target = @intCast(try cfg.integer(try cfg.get(demand, "syncTarget"), max_peers));
    out.value.demand.expires_at_slot = try cfg.bigint(try cfg.get(demand, "expiresAtSlot"));
    const targets = try cfg.get(demand, "groupTargets");
    if (try cfg.array(targets, 128) != 128) return error.InvalidDemand;
    for (&out.value.demand.group_targets, 0..) |*target, i| target.* = @intCast(try cfg.integer(try targets.getElement(@intCast(i)), max_peers));
    try out.value.demand.validate(&out.value.update.local.fork, max_peers);
    const subscriptions = try cfg.get(value, "subscriptions");
    const count = try cfg.array(subscriptions, 512);
    for (out.subscriptions[0..count], 0..) |*subscription, i| {
        const entry = try subscriptions.getElement(@intCast(i));
        try cfg.completeObject(entry, &.{ "name", "params" });
        const len = try text(try cfg.get(entry, "name"), &out.names[i]);
        subscription.name = out.names[i][0..len];
        try cfg.parseTopicParams(try cfg.get(entry, "params"), &subscription.params);
    }
    out.value.subscriptions = out.subscriptions[0..count];
}
