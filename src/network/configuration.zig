const std = @import("std");
const Protocols = @import("protocols.zig").Protocols;
const peer_manager = @import("peer_manager.zig");
const Engine = @import("quic/Engine.zig");
const Transport = @import("transport.zig").Transport;
const udp = @import("udp");
const rr = @import("reqresp/ReqResp.zig");
const gossip = @import("gossipsub/options.zig");
const c = @import("gossipsub/constants.zig");
const peers = @import("peers/root.zig");
const Router = @import("router.zig").Router;
const identify_mod = @import("identify/root.zig");
const ForkEntry = @import("types.zig").ForkEntry;
const request_policy = @import("reqresp/request_policy.zig");
const receive_pool = @import("gossipsub/receive_pool.zig");

pub const Profile = enum { small, beacon_node };
pub const ReqRespOverrides = struct {
    outbound_max: ?u16 = null,
    serving_max: ?u16 = null,
    serving_per_peer_max: ?u8 = null,
    outbound_per_connection_max: ?u8 = null,
    inbound_per_connection_max: ?u8 = null,
    inbound_application_per_connection_max: ?u8 = null,
    progress_timeout_ms: ?u64 = null,
    host_timeout_ms: ?u64 = null,
    quota_timeout_ms: ?u64 = null,
    work_per_pump_max: ?u16 = null,
};
pub const GossipOverrides = struct {
    topic_policy: ?@FieldType(gossip.Options, "topic_policy") = null,
    message_id_policy: ?@FieldType(gossip.Options, "message_id_policy") = null,
    iwant_followup_ms: ?u64 = null,
    idontwant_min_data_size: ?usize = null,
    heartbeat_interval_ms: ?u64 = null,
    seen_capacity: ?usize = null,
    mcache_capacity: ?usize = null,
    mcache_arena_bytes: ?usize = null,
    /// Derives validation capacity and payload storage before explicit capacity overrides.
    payload_limits: ?@FieldType(gossip.Options, "payload_limits") = null,
    validation_capacity: ?usize = null,
    validation_timeout_ms: ?u64 = null,
    validation_tombstone_ms: ?u64 = null,
    pressure_timeout_ms: ?u64 = null,
    tx_timeout_ms: ?u64 = null,
    active_send_timeout_ms: ?u64 = null,
    active_send_items: ?@FieldType(gossip.Options, "active_send_items") = null,
    control_bytes: ?usize = null,
    critical_bytes: ?usize = null,
    tx_peer_bytes: ?usize = null,
    tx_local_descriptors: ?usize = null,
    tx_local_bytes: ?usize = null,
    peers_per_pump: ?usize = null,
    topics_per_pump: ?usize = null,
    items_per_peer: ?usize = null,
    items_per_pump: ?usize = null,
    input_per_peer: ?usize = null,
    input_per_pump: ?usize = null,
    output_per_peer: ?usize = null,
    output_per_pump: ?usize = null,
    fields_per_peer: ?usize = null,
    fields_per_pump: ?usize = null,
    work_per_pump: ?usize = null,
    calls_per_peer: ?usize = null,
    calls_per_pump: ?usize = null,
    decompress_per_peer_bytes: ?usize = null,
    large_frame_timeout_ms: ?u64 = null,
    body_buffer_bytes: ?usize = null,
    receive_arena_bytes: ?usize = null,
    seen_ttl_ms: ?u64 = null,
    gossip_factor: ?f64 = null,
    retained_score_ms: ?u64 = null,
    ip_allowlist: ?@FieldType(gossip.Options, "ip_allowlist") = null,
    score_params: ?@FieldType(gossip.Options, "score_params") = null,
    topic_params: ?@FieldType(gossip.Options, "topic_params") = null,
    initial_slot: ?u64 = null,
    opportunistic_graft_interval_ms: ?u64 = null,
};
pub const IdentifyOverrides = struct {
    inbound_max: ?u16 = null,
    outbound_max: ?u16 = null,
    agent: ?[]const u8 = null,
    protocol_version: ?[]const u8 = null,
    addresses: ?@FieldType(identify_mod.Handler.Options, "addresses") = null,
};
pub const RouterOverrides = struct {
    capabilities: ?@FieldType(Router.Options, "capabilities") = null,
    negotiations_max: ?u16 = null,
    outbound_reserved: ??u16 = null,
    inbound_per_connection_max: ?u16 = null,
    meshsub_versions: ?@FieldType(Router.Options, "meshsub_versions") = null,
};

/// Req/resp, gossip and router fields override profile defaults; shared capacities are derived.
pub const Options = struct {
    profile: Profile = .beacon_node,
    seed: u64,
    forks: []const ForkEntry,
    limits: ?Engine.Limits = null,
    work_limits: Transport.WorkLimits = .{},
    socket_buffers: SocketBuffers = .{},
    peers: ?peers.Catalog.Options = null,
    dial: ?peers.Dialing.Options = null,
    reqresp: ReqRespOverrides = .{},
    gossip: GossipOverrides = .{},
    router: RouterOverrides = .{},
    identify: IdentifyOverrides = .{},
    application_requests_max: ?u16 = null,
    admission_policy: request_policy.Config,
    control: ?peers.Control.Options = null,
    byte_limit: ?usize = null,
};
/// NetworkCore's peer policy and protocol options.
pub const Core = struct {
    peers: peers.Catalog.Options = .{},
    protocols: Protocols.Options,
    control: peers.Control.Options = .{},
    dial: peers.Dialing.Options,
    metadata_freshness_ms: u64 = 60_000,

    /// The part of the options peer policy owns.
    pub fn peerManager(self: *const Core) peer_manager.Options {
        return .{ .peers = self.peers, .control = self.control, .dial = self.dial, .metadata_freshness_ms = self.metadata_freshness_ms };
    }
};
pub const Resolved = struct {
    limits: Engine.Limits,
    work_limits: Transport.WorkLimits,
    socket_buffers: SocketBuffers,
    core: Core,
    byte_limit: usize,
};

const outbound_reserved_max: u16 = 4;

pub fn resolve(options: Options) !Resolved {
    try options.work_limits.validate();
    try options.socket_buffers.validate();
    const small = options.profile == .small;
    var limits: Engine.Limits = options.limits orelse .{
        .connections_max = if (small) 16 else 128,
        .handshaking_max = if (small) 8 else 32,
        .dialing_max = if (small) 4 else 32,
        .receive_budget_bytes = if (small) 64 * 1024 * 1024 else 512 * 1024 * 1024,
    };
    const peer_options: peers.Catalog.Options = options.peers orelse .{
        .capacity = if (small) 64 else 512,
        .outbound_reserve = if (small) 4 else 32,
        .target_peers = if (small) 8 else 64,
        .max_peers = if (small) 12 else 96,
        .min_outbound = if (small) 2 else 16,
    };
    try peer_options.validate();
    if (peer_options.target_peers >= peer_options.max_peers) return error.InvalidOptions;
    const dial_options = options.dial orelse peers.Dialing.Options{
        .capacity = if (small) 32 else 256,
        .concurrent_max = limits.dialing_max,
        .outbound_reserved = @min(outbound_reserved_max, limits.dialing_max, peer_options.max_peers - peer_options.target_peers),
        .seed = options.seed,
    };
    try peers.Dialing.validateOptions(dial_options);
    if (dial_options.concurrent_max != limits.dialing_max) return error.InvalidOptions;
    limits.outbound_reserved = dial_options.outbound_reserved;
    limits.outbound_max = limits.connections_max;
    var requests: rr.Options = .{
        .forks = options.forks,
        .connections = limits.connections_max,
        .outbound_max = peer_options.max_peers + @as(u16, if (small) 6 else 56),
        .serving_max = peer_options.max_peers + @as(u16, if (small) 6 else 56),
        .outbound_control_reserved = peer_options.max_peers,
        .serving_control_reserved = peer_options.max_peers,
        .outbound_per_connection_max = if (small) 4 else 8,
        .inbound_per_connection_max = if (small) 8 else 16,
        .inbound_application_per_connection_max = if (small) 4 else 8,
        .admission = undefined,
    };
    applyOverrides(&requests, options.reqresp);
    if (requests.serving_max < requests.serving_control_reserved) return error.InvalidOptions;
    if (options.application_requests_max) |maximum| {
        if (maximum == 0 or requests.serving_max < requests.serving_control_reserved or requests.outbound_max < requests.outbound_control_reserved) return error.InvalidOptions;
        requests.serving_max = requests.serving_control_reserved + @min(maximum, requests.serving_max - requests.serving_control_reserved);
        requests.outbound_max = requests.outbound_control_reserved + @min(maximum, requests.outbound_max - requests.outbound_control_reserved);
    }

    requests.admission = try rr.Options.Admission.defaults(&options.admission_policy, peer_options.capacity, peer_options.max_peers, requests.serving_max - requests.serving_control_reserved);
    var identify: identify_mod.Handler.Options = .{ .inbound_max = if (small) 2 else 4, .outbound_max = if (small) 2 else 4 };
    applyOverrides(&identify, options.identify);
    var router_options: Router.Options = .{
        .negotiations_max = peer_options.max_peers + @as(u16, if (small) 30 else 248),
        .outbound_control_reserved = requests.outbound_control_reserved,
        .outbound_reserved = peer_options.max_peers + @as(u16, if (small) 8 else 64),
        .inbound_connections = limits.connections_max,
        .inbound_per_connection_max = @as(u16, requests.inbound_per_connection_max) + rr.outbound_stream_headroom,
    };
    applyOverrides(&router_options, options.router);
    var gossip_options: gossip.Options = .{
        .random_seed = options.seed,
        .connected_capacity = peer_options.max_peers,
        .connection_slots = limits.connections_max,
        .retained_capacity = peer_options.capacity,
        .retained_outbound_reserve = peer_options.outbound_reserve,
    };
    if (small) {
        gossip_options.seen_capacity = 4096;
        gossip_options.mcache_capacity = 256;
        gossip_options.validation_capacity = 64;
        gossip_options.mcache_arena_bytes = gossip.mcache_arena_bytes_min;
        gossip_options.receive_arena_bytes = std.mem.alignForward(usize, c.GOSSIP_MAX_SIZE, receive_pool.page_bytes);
    }
    if (options.gossip.payload_limits) |payload_limits| {
        if (payload_limits) |*limits_by_kind| try gossip_options.setPayloadLimits(limits_by_kind);
    }
    applyOverrides(&gossip_options, options.gossip);
    const result: Resolved = .{
        .limits = limits,
        .work_limits = options.work_limits,
        .socket_buffers = options.socket_buffers,
        .byte_limit = options.byte_limit orelse if (small) 256 * 1024 * 1024 else 512 * 1024 * 1024,
        .core = .{
            .peers = peer_options,
            .dial = dial_options,
            .control = options.control orelse .{},
            .protocols = .{
                .identify = identify,
                .router = router_options,
                .reqresp = requests,
                .gossipsub = gossip_options,
            },
        },
    };
    try validate(result.limits, result.core);
    if (result.core.protocols.reqresp.outbound_control_reserved == 0 or result.core.protocols.reqresp.serving_control_reserved == 0 or
        result.limits.connections_max > c.peers_cap)
        return error.InvalidOptions;
    return result;
}

pub fn validate(limits: Engine.Limits, options: Core) !void {
    try limits.validate();
    try peer_manager.PeerManager.validateOptions(options.peerManager());
    try Protocols.validateOptions(options.protocols);
    if (options.peers.max_peers > limits.connections_max or
        options.protocols.reqresp.connections < limits.connections_max or
        options.protocols.gossipsub.connection_slots < limits.connections_max or
        options.dial.concurrent_max != limits.dialing_max or
        options.dial.outbound_reserved != limits.outbound_reserved or
        limits.outbound_max != limits.connections_max or
        options.protocols.reqresp.serving_control_reserved < options.peers.max_peers or
        options.protocols.reqresp.outbound_control_reserved < options.peers.max_peers or
        options.protocols.router.outbound_control_reserved < options.protocols.reqresp.outbound_control_reserved)
        return error.InvalidOptions;
}

fn applyOverrides(options: anytype, overrides: anytype) void {
    inline for (std.meta.fields(@TypeOf(overrides))) |field| {
        if (@field(overrides, field.name)) |value| @field(options, field.name) = value;
    }
}

test {
    _ = @import("configuration_test.zig");
}

const mib = 1024 * 1024;

/// Kernel buffer sizes requested for each UDP socket role. The kernel default of 208 KiB holds
/// about 20 ms of traffic at 8,000 datagrams/s, so a longer owner pause drops datagrams. Linux
/// caps a request at net.core.rmem_max or wmem_max and doubles it: at a 16 MiB rmem_max, the QUIC
/// receive buffer holds about 14,560 datagrams at a truesize of 2,304 bytes.
pub const SocketBuffers = struct {
    quic: udp.Sockets.Buffers = .{ .receive = 16 * mib, .send = 4 * mib },
    discovery: udp.Sockets.Buffers = .{ .receive = 2 * mib, .send = 1 * mib },

    pub fn validate(self: SocketBuffers) error{InvalidLimits}!void {
        if (!self.quic.valid() or !self.discovery.valid()) return error.InvalidLimits;
    }
};
