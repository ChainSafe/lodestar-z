const std = @import("std");
const n = @import("network");
const cfg = @import("network_config.zig");
const Value = @import("zapi:zapi").napi.Value;

pub const Config = struct {
    resources: Resources,
    agent: [256]u8,
    agent_len: u16,
    version: [64]u8,
    version_len: u8,

    pub fn buildRequest(self: *const Config, common: *const cfg.Config, seed: u64) !n.configuration.Request {
        const r = &self.resources;
        if (r.nativeBudgetBytes <= @sizeOf(n.NetworkCore)) return error.NetworkNativeBudgetExceeded;
        var gossip_options = common.gossip;
        gossip_options.ip_allowlist = common.allowlist[0..common.allowlist_count];
        gossip_options.topic_policy = common.chain.topics[0..common.chain.supported_count];
        return .{
            .profile = common.profile,
            .seed = seed,
            .forks = common.chain.forks[0..common.chain.supported_count],
            .limits = .{ .connections_max = r.connectionCapacity, .handshaking_max = r.handshakingCapacity, .dialing_max = r.dialingCapacity, .receive_budget_bytes = r.receiveBudgetBytes },
            .peers = .{ .capacity = r.peerCapacity, .target_peers = r.targetPeers, .max_peers = r.maxPeers, .min_outbound = r.minOutbound, .outbound_reserve = r.outboundReserve },
            .application_requests_max = 32,
            .admission_policy = common.chain.requestPolicy(),
            .gossip = gossip_options,
            .router = .{ .identify = true, .capabilities = (try common.chain.update(common.local, null, common.slot)).capabilities },
            .identify = .{ .agent = self.agent[0..self.agent_len], .protocol_version = self.version[0..self.version_len] },
            .byte_limit = r.nativeBudgetBytes - @sizeOf(n.NetworkCore),
        };
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

const resource_maxima: Resources = .{
    .peerCapacity = n.gossipsub.constants.retained_peers_cap,
    .targetPeers = 256,
    .maxPeers = 256,
    .minOutbound = 256,
    .outboundReserve = n.gossipsub.constants.retained_peers_cap,
    .connectionCapacity = 256,
    .handshakingCapacity = 256,
    .dialingCapacity = 256,
    .receiveBudgetBytes = 9007199254740991,
    .nativeBudgetBytes = 1024 * 1024 * 1024,
    .bridgeBudgetBytes = 1024 * 1024 * 1024,
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
pub fn parse(value: Value, common: *cfg.Config, out: *Config) !void {
    try cfg.completeObject(value, &.{ "profile", "identitySecretKey", "bind", "local", "discovery", "initialSlot", "gossipPolicy", "resources", "identify", "serveLightClients" });
    try cfg.parse(value, common);
    errdefer common.wipe();
    const resources = try cfg.get(value, "resources");
    try cfg.completeObject(resources, &.{ "peerCapacity", "targetPeers", "maxPeers", "minOutbound", "outboundReserve", "connectionCapacity", "handshakingCapacity", "dialingCapacity", "receiveBudgetBytes", "nativeBudgetBytes", "bridgeBudgetBytes" });
    inline for (@typeInfo(Resources).@"struct".fields) |field| {
        const max: u64 = @field(resource_maxima, field.name);
        @field(out.resources, field.name) = @intCast(try cfg.integer(try cfg.get(resources, field.name), max));
    }
    if (out.resources.nativeBudgetBytes == 0 or out.resources.bridgeBudgetBytes == 0) return error.InvalidNetworkInteger;
    const identify = try cfg.get(value, "identify");
    try cfg.completeObject(identify, &.{ "agentVersion", "protocolVersion" });
    out.agent_len = @intCast(try text(try cfg.get(identify, "agentVersion"), &out.agent));
    out.version_len = @intCast(try text(try cfg.get(identify, "protocolVersion"), &out.version));
}

pub const Intent = struct {
    value: n.network_core.LocalIntent,
    subscriptions: [n.gossipsub.topic_policy.boundary_max]n.gossipsub.local_intent.Boundary,
};
pub fn parseIntent(value: Value, out: *Intent, max_peers: u16) !void {
    try cfg.completeObject(value, &.{ "update", "demand", "subscriptions" });
    const update = try cfg.get(value, "update");
    try cfg.completeObject(update, &.{ "local", "endpoints" });
    try cfg.parseLocal(try cfg.get(update, "local"), &out.value.update.local);
    out.value.update.schedule = .{};
    out.value.update.capabilities = .{ .receive = .initEmpty(), .request = .initEmpty() };
    out.value.update.endpoints = try cfg.parseEndpoints(try cfg.get(update, "endpoints"));
    const demand = try cfg.get(value, "demand");
    try cfg.completeObject(demand, &.{ "attnets", "syncnets", "groupTargets", "custodyGroupTargets", "attestationTarget", "syncTarget", "expiresAtSlot" });
    const attnets = try cfg.fixed(8, try cfg.get(demand, "attnets"));
    out.value.demand.attnets = std.mem.readInt(u64, &attnets, .little);
    out.value.demand.syncnets = @intCast(try cfg.integer(try cfg.get(demand, "syncnets"), 15));
    out.value.demand.attestation_target = @intCast(try cfg.integer(try cfg.get(demand, "attestationTarget"), max_peers));
    out.value.demand.sync_target = @intCast(try cfg.integer(try cfg.get(demand, "syncTarget"), max_peers));
    out.value.demand.expires_at_slot = try cfg.bigint(try cfg.get(demand, "expiresAtSlot"));
    try targets(try cfg.get(demand, "groupTargets"), &out.value.demand.group_targets, max_peers);
    try targets(try cfg.get(demand, "custodyGroupTargets"), &out.value.demand.custody_group_targets, max_peers);
    const subscriptions = try cfg.get(value, "subscriptions");
    const count = try cfg.array(subscriptions, n.gossipsub.topic_policy.boundary_max);
    for (out.subscriptions[0..count], 0..) |*subscription, i| {
        const entry = try subscriptions.getElement(@intCast(i));
        try cfg.completeObject(entry, &.{ "digest", "subnets" });
        subscription.* = .{ .digest = try cfg.fixed(4, try cfg.get(entry, "digest")) };
        const subnets = try cfg.get(entry, "subnets");
        try cfg.object(subnets, &cfg.topic_kind_names);
        inline for (std.meta.fields(n.gossipsub.topic.Kind), 0..) |field, k| {
            if (try subnets.hasNamedProperty(field.name)) {
                const input = try cfg.get(subnets, field.name);
                if (!try input.isTypedarray()) return error.InvalidNetworkBytes;
                const info = try input.getTypedarrayInfo();
                const mask = subscription.mask(@enumFromInt(k));
                if (info.array_type != .uint8 or info.length > mask.len or try info.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
                @memcpy(mask[0..info.length], info.data);
                subscription.lengths[k] = @intCast(info.length);
            }
        }
    }
    out.value.subscriptions = out.subscriptions[0..count];
}

fn targets(value: Value, out: *[128]u16, max_peers: u16) !void {
    if (!try value.isTypedarray()) return error.InvalidNetworkBytes;
    const info = try value.getTypedarrayInfo();
    if (info.array_type != .uint16 or info.length > out.len or try info.arraybuffer.isDetachedArrayBuffer()) return error.InvalidNetworkBytes;
    @memset(out, 0);
    @memcpy(std.mem.sliceAsBytes(out[0..info.length]), info.data);
    for (out) |target| if (target > max_peers) return error.InvalidNetworkInteger;
}
