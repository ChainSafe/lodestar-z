const std = @import("std");
const n = @import("network");
const cfg = @import("network_config.zig");
const Value = @import("zapi:zapi").napi.Value;
const decode = @import("network_js_input.zig");
const BeaconConfig = @import("config").BeaconConfig;
const network_logs = @import("network_logs.zig");

pub const Config = struct {
    resources: Resources,
    trace_gossip: bool = false,
    trace_turns: bool = false,
    xray: ?struct { endpoint: n.xray.Endpoint, wait_for_attach: bool } = null,
    transport: Transport = .{},
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
        const capture_bytes = if (self.xray != null) n.xray.Probe.allocatedBytesFor(r.connectionCapacity) else 0;
        if (r.nativeBudgetBytes <= @sizeOf(n.NetworkCore) + capture_bytes) return error.NetworkNativeBudgetExceeded;
        var gossip_options = common.gossip;
        gossip_options.ip_allowlist = common.allowlist[0..common.allowlist_count];
        gossip_options.topic_policy = common.chain.topics[0..common.chain.boundary_count];
        return .{
            .seed = seed,
            .forks = common.chain.forks[0..common.chain.boundary_count],
            .limits = .{ .connections_max = r.connectionCapacity, .handshaking_max = r.handshakingCapacity, .dialing_max = r.dialingCapacity, .receive_budget_bytes = r.receiveBudgetBytes, .initial_congestion_window_packets = self.transport.initialCongestionWindowPackets },
            .work_limits = .{ .receive_per_turn_max = self.transport.receiveDatagramsPerTurn },
            .peers = .{ .capacity = r.peerCapacity, .target_peers = r.targetPeers, .max_peers = r.maxPeers, .min_outbound = r.minOutbound, .outbound_reserve = r.outboundReserve },
            .application_requests_max = 32,
            .admission_policy = common.chain.requestPolicy(),
            .gossip = gossip_options,
            .router = .{ .capabilities = (try common.chain.update(common.local, null, common.slot)).capabilities },
            .identify = .{ .agent = self.agent[0..self.agent_len], .protocol_version = self.version[0..self.version_len] },
            .byte_limit = r.nativeBudgetBytes - @sizeOf(n.NetworkCore) - capture_bytes,
        };
    }
};
const Transport = struct {
    initialCongestionWindowPackets: u16 = 10,
    receiveDatagramsPerTurn: u16 = 32,
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

const resource_maxima = .{
    .receiveBudgetBytes = 9007199254740991,
    .nativeBudgetBytes = 2 * 1024 * 1024 * 1024,
    .bridgeBudgetBytes = 1024 * 1024 * 1024,
};

const required = .{ "beaconConfig", "activeValidatorCount", "identitySecretKey", "bind", "local", "discovery", "genesisTime", "resources", "identify", "serveLightClients", "logLevel" };

pub fn parse(value: Value, beacon: *const BeaconConfig, common: *cfg.Config, out: *Config) !void {
    const remembered = try value.hasNamedProperty("rememberedPeers");
    try decode.object(value, &(required ++ .{ "gossipPolicy", "subscriptions", "rememberedPeers", "transport", "traceGossip", "traceTurns", "xray" }));
    inline for (required) |name| _ = try decode.get(value, name);
    out.trace_gossip = if (try value.hasNamedProperty("traceGossip")) try decode.boolean(try decode.get(value, "traceGossip")) else false;
    out.trace_turns = if (try value.hasNamedProperty("traceTurns")) try decode.boolean(try decode.get(value, "traceTurns")) else false;
    out.xray = null;
    if (try value.hasNamedProperty("xray")) {
        const xray = try decode.get(value, "xray");
        try decode.completeObject(xray, &.{ "address", "waitForAttach" });
        var address: [256]u8 = undefined;
        const length = try decode.text(try decode.get(xray, "address"), &address);
        out.xray = .{
            .endpoint = n.xray.Endpoint.parse(address[0..length]) catch return error.InvalidXrayAddress,
            .wait_for_attach = try decode.boolean(try decode.get(xray, "waitForAttach")),
        };
    }
    out.transport = .{};
    if (try value.hasNamedProperty("transport")) {
        const transport = try decode.get(value, "transport");
        try decode.completeObject(transport, &.{ "initialCongestionWindowPackets", "receiveDatagramsPerTurn" });
        out.transport.initialCongestionWindowPackets = @intCast(try decode.integer(try decode.get(transport, "initialCongestionWindowPackets"), 64));
        out.transport.receiveDatagramsPerTurn = @intCast(try decode.integer(try decode.get(transport, "receiveDatagramsPerTurn"), n.Transport.receive_per_turn_max));
    }
    try cfg.parse(value, beacon, common);
    errdefer common.wipe();
    const resources = try decode.get(value, "resources");
    try decode.object(resources, &.{ "targetPeers", "maxPeers", "receiveBudgetBytes", "nativeBudgetBytes", "bridgeBudgetBytes" });
    const target: u16 = @intCast(try decode.integer(try decode.get(resources, "targetPeers"), 256));
    const max: u16 = @intCast(try decode.integer(try decode.get(resources, "maxPeers"), 256));
    out.resources = .{
        .targetPeers = target,
        .maxPeers = max,
        .peerCapacity = @max(64, 2 * max),
        .minOutbound = @max(1, target / 4),
        .outboundReserve = @min(32, target),
        .connectionCapacity = @min(256, max + 32),
        .handshakingCapacity = 32,
        .dialingCapacity = 32,
        .receiveBudgetBytes = 512 * 1024 * 1024,
        .nativeBudgetBytes = 2 * 1024 * 1024 * 1024,
        .bridgeBudgetBytes = 512 * 1024 * 1024,
    };
    inline for (.{ "receiveBudgetBytes", "nativeBudgetBytes", "bridgeBudgetBytes" }) |field| {
        if (try resources.hasNamedProperty(field)) @field(out.resources, field) = @intCast(try decode.integer(try decode.get(resources, field), @field(resource_maxima, field)));
    }
    if (out.resources.nativeBudgetBytes == 0 or out.resources.bridgeBudgetBytes == 0) return error.InvalidNetworkInteger;
    const identify = try decode.get(value, "identify");
    try decode.completeObject(identify, &.{ "agentVersion", "protocolVersion" });
    out.agent_len = @intCast(try decode.text(try decode.get(identify, "agentVersion"), &out.agent));
    out.version_len = @intCast(try decode.text(try decode.get(identify, "protocolVersion"), &out.version));
    out.genesis_root = beacon.genesis_validator_root;
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

pub const Intent = n.application_state.Update;
pub fn parseIntent(value: Value, out: *Intent) !void {
    try decode.object(value, &.{ "status", "coreTopics", "custodyGroupCount", "attesters", "syncCommittees" });
    out.* = .{};
    if (try value.hasNamedProperty("status")) {
        var status: n.local_state.Status = undefined;
        try cfg.parseStatus(try decode.get(value, "status"), &status);
        out.status = status;
    }
    if (try value.hasNamedProperty("coreTopics")) out.core_topics = try decode.boolean(try decode.get(value, "coreTopics"));
    if (try value.hasNamedProperty("custodyGroupCount")) out.custody_group_count = try decode.bigint(try decode.get(value, "custodyGroupCount"));
    if (try value.hasNamedProperty("attesters")) {
        const rows = try decode.get(value, "attesters");
        out.attester_count = @intCast(try decode.array(rows, n.application_state.duty_batch_max));
        for (out.attesters[0..out.attester_count], 0..) |*row, i| {
            const entry = try rows.getElement(@intCast(i));
            try decode.completeObject(entry, &.{ "slot", "subnets", "aggregators" });
            row.* = .{
                .slot = try decode.integer(try decode.get(entry, "slot"), 9007199254740990),
                .subnets = try decode.bigint(try decode.get(entry, "subnets")),
                .aggregators = try decode.bigint(try decode.get(entry, "aggregators")),
            };
        }
    }
    if (try value.hasNamedProperty("syncCommittees")) {
        const rows = try decode.get(value, "syncCommittees");
        const count = try decode.array(rows, 4);
        for (0..count) |i| {
            const entry = try rows.getElement(@intCast(i));
            try decode.completeObject(entry, &.{ "subnet", "untilSlot" });
            const subnet = try decode.integer(try decode.get(entry, "subnet"), 3);
            const slot = try decode.integer(try decode.get(entry, "untilSlot"), 9007199254740990);
            out.sync_until[subnet] = @max(out.sync_until[subnet] orelse 0, slot);
        }
    }
}
