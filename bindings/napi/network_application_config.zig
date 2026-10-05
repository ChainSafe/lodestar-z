const std = @import("std");
const n = @import("network");
const cfg = @import("network_config.zig");
const Value = @import("zapi:zapi").napi.Value;
const decode = @import("network_js_input.zig");
const config = @import("config.zig");
const network_logs = @import("network_logs.zig");

pub const Config = struct {
    resources: Resources,
    agent: [256]u8,
    agent_len: u16,
    version: [64]u8,
    version_len: u8,
    /// The network identity remembered peers are checked against, and snapshots carry.
    genesis_root: [32]u8,
    remembered: [n.peers.remembered.capacity]n.peers.remembered.Record,
    remembered_count: u16,
    /// The threshold native records are kept at, or null for none, until the host selects another.
    log_level: ?std.log.Level,

    pub fn buildOptions(self: *const Config, common: *const cfg.Config, seed: u64) !n.configuration.Options {
        const r = &self.resources;
        if (r.nativeBudgetBytes <= @sizeOf(n.NetworkCore)) return error.NetworkNativeBudgetExceeded;
        var gossip_options = common.gossip;
        gossip_options.ip_allowlist = common.allowlist[0..common.allowlist_count];
        gossip_options.topic_policy = common.chain.topics[0..common.chain.boundary_count];
        return .{
            .profile = common.profile,
            .seed = seed,
            .forks = common.chain.forks[0..common.chain.boundary_count],
            .limits = .{ .connections_max = r.connectionCapacity, .handshaking_max = r.handshakingCapacity, .dialing_max = r.dialingCapacity, .receive_budget_bytes = r.receiveBudgetBytes },
            .peers = .{ .capacity = r.peerCapacity, .target_peers = r.targetPeers, .max_peers = r.maxPeers, .min_outbound = r.minOutbound, .outbound_reserve = r.outboundReserve },
            .application_requests_max = 32,
            .admission_policy = common.chain.requestPolicy(),
            .gossip = gossip_options,
            .router = .{ .capabilities = (try common.chain.update(common.local, null, common.slot)).capabilities },
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
    .dialingCapacity = n.peers.Dialing.attempts_max,
    .receiveBudgetBytes = 9007199254740991,
    .nativeBudgetBytes = 1024 * 1024 * 1024,
    .bridgeBudgetBytes = 1024 * 1024 * 1024,
};

const required = .{ "profile", "identitySecretKey", "bind", "local", "discovery", "initialSlot", "gossipPolicy", "resources", "identify", "serveLightClients", "logLevel" };

pub fn parse(value: Value, common: *cfg.Config, out: *Config) !void {
    const remembered = try value.hasNamedProperty("rememberedPeers");
    if (remembered) try decode.completeObject(value, &(required ++ .{"rememberedPeers"})) else try decode.completeObject(value, &required);
    try cfg.parse(value, common);
    errdefer common.wipe();
    const resources = try decode.get(value, "resources");
    try decode.completeObject(resources, &.{ "peerCapacity", "targetPeers", "maxPeers", "minOutbound", "outboundReserve", "connectionCapacity", "handshakingCapacity", "dialingCapacity", "receiveBudgetBytes", "nativeBudgetBytes", "bridgeBudgetBytes" });
    inline for (@typeInfo(Resources).@"struct".fields) |field| {
        const max: u64 = @field(resource_maxima, field.name);
        @field(out.resources, field.name) = @intCast(try decode.integer(try decode.get(resources, field.name), max));
    }
    if (out.resources.nativeBudgetBytes == 0 or out.resources.bridgeBudgetBytes == 0) return error.InvalidNetworkInteger;
    const identify = try decode.get(value, "identify");
    try decode.completeObject(identify, &.{ "agentVersion", "protocolVersion" });
    out.agent_len = @intCast(try decode.text(try decode.get(identify, "agentVersion"), &out.agent));
    out.version_len = @intCast(try decode.text(try decode.get(identify, "protocolVersion"), &out.version));
    out.genesis_root = config.state.config.genesis_validator_root;
    out.log_level = try network_logs.level(try decode.get(value, "logLevel"));
    out.remembered_count = 0;
    if (remembered) try parseRemembered(try decode.get(value, "rememberedPeers"), out);
}

/// Copies the host's remembered peers. Null or undefined means none. A container from another
/// network, more than `capacity` peers, or a malformed peer rejects the configuration; the network
/// owner drops expired and duplicate peers.
fn parseRemembered(value: Value, out: *Config) !void {
    const kind = try value.typeof();
    if (kind == .null or kind == .undefined) return;
    try decode.completeObject(value, &.{ "genesisValidatorsRoot", "peers" });
    const root = try decode.fixed(32, try decode.get(value, "genesisValidatorsRoot"));
    if (!std.mem.eql(u8, &root, &out.genesis_root)) return error.InvalidRememberedPeersNetwork;
    const peers = try decode.get(value, "peers");
    const count = try decode.array(peers, n.peers.remembered.capacity);
    for (out.remembered[0..count], 0..) |*record, i| {
        const entry = try peers.getElement(@intCast(i));
        try decode.completeObject(entry, &.{ "peerId", "endpoint", "qualifiedAtUnixS" });
        const address: n.Address = switch (try decode.endpoint(try decode.get(entry, "endpoint"))) {
            .ip4 => |ip| .{ .ip4 = .{ .octets = ip.bytes, .port = ip.port } },
            .ip6 => |ip| .{ .ip6 = .{ .octets = ip.bytes, .port = ip.port } },
        };
        if (!address.isUsable()) return error.InvalidNetworkConfig;
        record.* = .{
            .peer = try decode.peerIdFrom(try decode.get(entry, "peerId")),
            .address = address,
            .qualified_at_s = try decode.integer(try decode.get(entry, "qualifiedAtUnixS"), 9007199254740991),
        };
    }
    out.remembered_count = @intCast(count);
}

pub const Intent = struct {
    value: n.NetworkCore.LocalIntent,
    subscriptions: [n.gossipsub.topic_policy.boundary_max]n.gossipsub.local_intent.Boundary,
};
pub fn parseIntent(value: Value, out: *Intent, max_peers: u16) !void {
    try decode.completeObject(value, &.{ "update", "demand", "subscriptions" });
    const update = try decode.get(value, "update");
    try decode.completeObject(update, &.{"local"});
    try cfg.parseLocal(try decode.get(update, "local"), &out.value.update.local);
    out.value.update.schedule = .{};
    out.value.update.capabilities = .{ .receive = .initEmpty(), .request = .initEmpty() };
    out.value.update.endpoints = null;
    const demand = try decode.get(value, "demand");
    try decode.completeObject(demand, &.{ "attnets", "syncnets", "groupTargets", "custodyGroupTargets", "attestationTarget", "syncTarget" });
    const attnets = try decode.fixed(8, try decode.get(demand, "attnets"));
    out.value.demand.attnets = std.mem.readInt(u64, &attnets, .little);
    out.value.demand.syncnets = @intCast(try decode.integer(try decode.get(demand, "syncnets"), 15));
    out.value.demand.attestation_target = @intCast(try decode.integer(try decode.get(demand, "attestationTarget"), max_peers));
    out.value.demand.sync_target = @intCast(try decode.integer(try decode.get(demand, "syncTarget"), max_peers));
    try targets(try decode.get(demand, "groupTargets"), &out.value.demand.group_targets, max_peers);
    try targets(try decode.get(demand, "custodyGroupTargets"), &out.value.demand.custody_group_targets, max_peers);
    const subscriptions = try decode.get(value, "subscriptions");
    const count = try decode.array(subscriptions, n.gossipsub.topic_policy.boundary_max);
    for (out.subscriptions[0..count], 0..) |*subscription, i| {
        const entry = try subscriptions.getElement(@intCast(i));
        try decode.completeObject(entry, &.{ "digest", "subnets" });
        subscription.* = .{ .digest = try decode.fixed(4, try decode.get(entry, "digest")) };
        const subnets = try decode.get(entry, "subnets");
        try decode.object(subnets, &cfg.topic_kind_names);
        inline for (std.meta.fields(n.gossipsub.topic.Kind), 0..) |field, k| {
            if (try subnets.hasNamedProperty(field.name)) {
                const input = try decode.get(subnets, field.name);
                const view = try decode.byteView(input);
                const mask = subscription.mask(@enumFromInt(k));
                if (view.len > mask.len) return error.InvalidNetworkBytes;
                @memcpy(mask[0..view.len], view);
                subscription.lengths[k] = @intCast(view.len);
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
