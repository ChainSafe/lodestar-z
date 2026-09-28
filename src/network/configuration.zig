const std = @import("std");
const service = @import("service.zig");
const peer_manager = @import("peer_manager.zig");
const engine = @import("quic/engine.zig");
const transport = @import("transport.zig");
const udp = @import("udp.zig");
const rr = @import("reqresp/reqresp.zig");
const gossip = @import("gossipsub/options.zig");
const c = @import("gossipsub/constants.zig");
const peers = @import("peers/types.zig");
const dial = @import("peers/dialing.zig");
const router = @import("router.zig");

pub const Profile = enum { small, beacon_node };
pub const ReqRespOverrides = Overrides(rr.Options, &.{ "peers", "forks", "request_fork", "outbound_control_reserved", "inbound_control_reserved", "admission" });
pub const GossipOverrides = Overrides(gossip.Options, &.{ "connected_capacity", "connection_slots", "retained_capacity", "retained_outbound_reserve", "random_seed" });
pub const IdentifyOverrides = Overrides(@import("identify/root.zig").Options, &.{});
pub const RouterOverrides = Overrides(router.Options, &.{ "outbound_control_reserved", "inbound_connections" });

/// Req/resp, gossip and router fields override profile defaults; shared capacities are derived.
pub const Request = struct {
    profile: Profile = .beacon_node,
    seed: u64,
    forks: []const rr.ForkEntry,
    limits: ?engine.Limits = null,
    work_limits: transport.WorkLimits = .{},
    socket_buffers: udp.SocketBuffers = .{},
    peers: ?peers.Options = null,
    dial: ?dial.Options = null,
    reqresp: ReqRespOverrides = .{},
    gossip: GossipOverrides = .{},
    router: RouterOverrides = .{},
    identify: IdentifyOverrides = .{},
    application_requests_max: ?u16 = null,
    admission_policy: @import("reqresp/request_policy.zig").Config,
    control: ?@import("peers/control.zig").Options = null,
    byte_limit: ?usize = null,
};
/// NetworkCore's peer policy and protocol options.
pub const Core = struct {
    peers: peers.Options = .{},
    service: service.Options,
    control: @import("peers/control.zig").Options = .{},
    dial: dial.Options,
    metadata_freshness_ms: u64 = 60_000,

    /// The part of the options peer policy owns.
    pub fn peerManager(self: *const Core) peer_manager.Options {
        return .{ .peers = self.peers, .control = self.control, .dial = self.dial, .metadata_freshness_ms = self.metadata_freshness_ms };
    }
};
pub const Resolved = struct {
    limits: engine.Limits,
    work_limits: transport.WorkLimits,
    socket_buffers: udp.SocketBuffers,
    core: Core,
    byte_limit: usize,
};

const outbound_reserved_max: u16 = 4;

pub fn resolve(request: Request) !Resolved {
    try request.work_limits.validate();
    try request.socket_buffers.validate();
    const small = request.profile == .small;
    var limits: engine.Limits = request.limits orelse .{
        .connections_max = if (small) 16 else 128,
        .handshaking_max = if (small) 8 else 32,
        .dialing_max = if (small) 4 else 32,
        .receive_budget_bytes = if (small) 64 * 1024 * 1024 else 512 * 1024 * 1024,
    };
    const peer_options: peers.Options = request.peers orelse .{
        .capacity = if (small) 64 else 512,
        .outbound_reserve = if (small) 4 else 32,
        .target_peers = if (small) 8 else 64,
        .max_peers = if (small) 12 else 96,
        .min_outbound = if (small) 2 else 16,
    };
    try peer_options.validate();
    if (peer_options.target_peers >= peer_options.max_peers) return error.InvalidOptions;
    const dial_options = request.dial orelse dial.Options{
        .capacity = if (small) 32 else 256,
        .concurrent_max = limits.dialing_max,
        .outbound_reserved = @min(outbound_reserved_max, limits.dialing_max, peer_options.max_peers - peer_options.target_peers),
        .seed = request.seed,
    };
    try dial.Dialing.validateOptions(dial_options);
    if (dial_options.concurrent_max != limits.dialing_max) return error.InvalidOptions;
    limits.outbound_reserved = dial_options.outbound_reserved;
    limits.outbound_max = limits.connections_max;
    var requests: rr.Options = .{
        .forks = request.forks,
        .peers = limits.connections_max,
        .outbound_max = peer_options.max_peers + @as(u16, if (small) 6 else 56),
        .inbound_max = peer_options.max_peers + @as(u16, if (small) 6 else 56),
        .outbound_control_reserved = peer_options.max_peers,
        .inbound_control_reserved = peer_options.max_peers,
        .outbound_per_peer_max = if (small) 4 else 8,
        .inbound_per_peer_max = if (small) 8 else 16,
        .inbound_application_per_peer_max = if (small) 4 else 8,
        .admission = undefined,
    };
    applyOverrides(&requests, request.reqresp);
    if (requests.inbound_max < requests.inbound_control_reserved) return error.InvalidOptions;
    if (request.application_requests_max) |maximum| {
        if (maximum == 0 or requests.inbound_max < requests.inbound_control_reserved or requests.outbound_max < requests.outbound_control_reserved) return error.InvalidOptions;
        requests.inbound_max = requests.inbound_control_reserved + @min(maximum, requests.inbound_max - requests.inbound_control_reserved);
        requests.outbound_max = requests.outbound_control_reserved + @min(maximum, requests.outbound_max - requests.outbound_control_reserved);
    }

    requests.admission = try rr.AdmissionOptions.defaults(&request.admission_policy, peer_options.capacity, peer_options.max_peers, requests.inbound_max - requests.inbound_control_reserved);
    var identify: @import("identify/root.zig").Options = .{ .inbound_max = if (small) 2 else 4, .outbound_max = if (small) 2 else 4 };
    applyOverrides(&identify, request.identify);
    var protocols: router.Options = .{
        .negotiations_max = peer_options.max_peers + @as(u16, if (small) 30 else 248),
        .outbound_control_reserved = requests.outbound_control_reserved,
        .outbound_reserved = peer_options.max_peers + @as(u16, if (small) 8 else 64),
        .inbound_connections = limits.connections_max,
        .inbound_per_connection_max = @as(u16, requests.inbound_per_peer_max) + rr.outbound_stream_headroom,
    };
    applyOverrides(&protocols, request.router);
    var gossip_options: gossip.Options = .{
        .random_seed = request.seed,
        .connected_capacity = peer_options.max_peers,
        .connection_slots = limits.connections_max,
        .retained_capacity = peer_options.capacity,
        .retained_outbound_reserve = peer_options.outbound_reserve,
    };
    if (small) {
        gossip_options.seen_capacity = 4096;
        gossip_options.mcache_capacity = 256;
        gossip_options.validation_capacity = 64;
        gossip_options.mcache_arena_bytes = c.maxCompressedLen(c.MAX_PAYLOAD_SIZE) + @import("gossipsub/message_store.zig").page_bytes;
        gossip_options.receive_arena_bytes = std.mem.alignForward(usize, c.GOSSIP_MAX_SIZE, @import("gossipsub/receive_pool.zig").page_bytes);
    }
    applyOverrides(&gossip_options, request.gossip);
    const result: Resolved = .{
        .limits = limits,
        .work_limits = request.work_limits,
        .socket_buffers = request.socket_buffers,
        .byte_limit = request.byte_limit orelse if (small) 96 * 1024 * 1024 else 384 * 1024 * 1024,
        .core = .{
            .peers = peer_options,
            .dial = dial_options,
            .control = request.control orelse .{},
            .service = .{
                .identify = identify,
                .router = protocols,
                .reqresp = requests,
                .gossipsub = gossip_options,
            },
        },
    };
    try validate(result.limits, result.core);
    if (result.core.service.reqresp.outbound_control_reserved == 0 or result.core.service.reqresp.inbound_control_reserved == 0 or
        result.limits.connections_max > c.peers_cap)
        return error.InvalidOptions;
    return result;
}

pub fn validate(limits: engine.Limits, options: Core) !void {
    _ = try engine.Engine.validateLimits(limits);
    try peer_manager.PeerManager.validateOptions(options.peerManager());
    try service.Service.validateOptions(options.service);
    if (options.peers.max_peers > limits.connections_max or
        options.service.reqresp.peers < limits.connections_max or
        options.service.gossipsub.connection_slots < limits.connections_max or
        options.dial.concurrent_max != limits.dialing_max or
        options.dial.outbound_reserved != limits.outbound_reserved or
        limits.outbound_max != limits.connections_max or
        options.service.reqresp.inbound_control_reserved < options.peers.max_peers or
        options.service.reqresp.outbound_control_reserved < options.peers.max_peers or
        options.service.router.outbound_control_reserved < options.service.reqresp.outbound_control_reserved)
        return error.InvalidOptions;
}

fn Overrides(comptime Options: type, comptime derived: []const []const u8) type {
    const fields = std.meta.fields(Options);
    var names: [fields.len - derived.len][:0]const u8 = undefined;
    var types: [names.len]type = undefined;
    var attrs: [names.len]std.builtin.Type.StructField.Attributes = undefined;
    var count: usize = 0;
    for (fields) |field| {
        var shared = false;
        for (derived) |name| shared = shared or std.mem.eql(u8, name, field.name);
        if (shared) continue;
        const optional = ?field.type;
        names[count] = field.name;
        types[count] = optional;
        attrs[count] = .{ .default_value_ptr = &@as(optional, null) };
        count += 1;
    }
    std.debug.assert(count == names.len);
    return @Struct(.auto, null, &names, &types, &attrs);
}

fn applyOverrides(options: anytype, overrides: anytype) void {
    inline for (std.meta.fields(@TypeOf(overrides))) |field| {
        if (@field(overrides, field.name)) |value| @field(options, field.name) = value;
    }
}

test {
    _ = @import("configuration_test.zig");
}
