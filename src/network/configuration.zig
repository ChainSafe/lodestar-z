const std = @import("std");
const core = @import("core.zig");
const engine = @import("quic/engine.zig");
const rr = @import("reqresp/reqresp.zig");
const gossip = @import("gossipsub/options.zig");
const c = @import("gossipsub/constants.zig");
const peers = @import("peers/types.zig");
const dial = @import("peers/dial_queue.zig");
const router = @import("router.zig");

pub const Profile = enum { small, beacon_node };
pub const Request = struct {
    profile: Profile = .beacon_node,
    seed: u64,
    forks: []const rr.ForkEntry,
    limits: ?engine.Limits = null,
    peers: ?peers.Options = null,
    dial: ?dial.Options = null,
    reqresp: ?rr.Options = null,
    gossip: ?gossip.Options = null,
    router: ?router.Options = null,
    control: ?@import("peers/control.zig").Options = null,
    byte_limit: ?usize = null,
};
pub const Resolved = struct {
    limits: engine.Limits,
    core: core.Options,
    byte_limit: usize,
};

pub fn resolve(request: Request) !Resolved {
    const small = request.profile == .small;
    const limits: engine.Limits = request.limits orelse .{
        .connections_max = if (small) 16 else 128,
        .handshaking_max = if (small) 8 else 32,
        .dialing_max = if (small) 4 else 16,
        .receive_budget_bytes = if (small) 64 * 1024 * 1024 else 512 * 1024 * 1024,
    };
    const peer_options: peers.Options = request.peers orelse .{
        .capacity = if (small) 64 else 512,
        .outbound_reserve = if (small) 4 else 32,
        .target_peers = if (small) 8 else 64,
        .max_peers = if (small) 12 else 96,
        .min_outbound = if (small) 2 else 16,
        .engine_capacity = limits.connections_max,
    };
    const reserved: u16 = if (small) 2 else 8;
    var gossip_options: gossip.Options = .{
        .random_seed = request.seed,
        .connected_capacity = peer_options.max_peers,
        .retained_capacity = peer_options.capacity,
        .retained_outbound_reserve = peer_options.outbound_reserve,
    };
    if (small) {
        gossip_options.seen_capacity = 4096;
        gossip_options.mcache_capacity = 256;
        gossip_options.validation_capacity = 64;
        gossip_options.mcache_arena_bytes = c.maxCompressedLen(c.MAX_PAYLOAD_SIZE) + @import("gossipsub/message_store.zig").page_bytes;
        gossip_options.decompressed_arena_bytes = c.MAX_PAYLOAD_SIZE + @import("gossipsub/topic.zig").topic_max_len;
        gossip_options.large_pool_count = 1;
    }
    const result: Resolved = .{
        .limits = limits,
        .byte_limit = request.byte_limit orelse if (small) 80 * 1024 * 1024 else 256 * 1024 * 1024,
        .core = .{
            .peers = peer_options,
            .dial = request.dial orelse .{ .capacity = if (small) 32 else 256, .concurrent_max = @min(4, limits.dialing_max), .engine_dialing_max = limits.dialing_max, .seed = request.seed },
            .control = request.control orelse .{ .operations_max = if (small) 4 else 16 },
            .service = .{
                .router = request.router orelse .{ .negotiations_max = if (small) 32 else 256, .outbound_control_reserved = reserved },
                .reqresp = request.reqresp orelse .{
                    .forks = request.forks,
                    .peers = limits.connections_max,
                    .outbound_max = if (small) 8 else 64,
                    .inbound_max = if (small) 8 else 64,
                    .outbound_control_reserved = reserved,
                    .inbound_control_reserved = reserved,
                    .outbound_per_peer_max = if (small) 4 else 8,
                    .inbound_per_peer_max = if (small) 8 else 16,
                    .inbound_application_per_peer_max = if (small) 4 else 8,
                },
                .gossipsub = request.gossip orelse gossip_options,
            },
        },
    };
    try validate(result.limits, result.core);
    if (result.core.service.reqresp.outbound_control_reserved == 0 or result.core.service.reqresp.inbound_control_reserved == 0 or
        result.core.service.gossipsub.connected_capacity < result.core.peers.max_peers or result.limits.connections_max > c.peers_cap)
        return error.InvalidOptions;
    return result;
}

pub fn validate(limits: engine.Limits, options: core.Options) !void {
    _ = try engine.Engine.validateLimits(limits);
    try options.peers.validate();
    const r = options.service.reqresp;
    if (options.peers.engine_capacity != limits.connections_max or
        options.dial.engine_dialing_max != limits.dialing_max or options.dial.concurrent_max > limits.dialing_max or
        r.peers < limits.connections_max or options.dial.concurrent_max == 0 or options.dial.concurrent_max > 4 or options.dial.capacity < options.dial.concurrent_max or
        options.control.operations_max == 0 or options.control.operations_max > 1024 or
        r.peers == 0 or r.peers > @import("reqresp/constants.zig").slots_ceiling or r.inbound_per_peer_max == 0 or
        r.outbound_per_peer_max > @import("quic/limits.zig").peer_streams_bidi - rr.outbound_stream_headroom or r.inbound_application_per_peer_max > r.inbound_per_peer_max or
        options.dial.capacity == 0 or options.dial.capacity > 4096 or
        options.service.router.negotiations_max == 0 or options.service.router.negotiations_max > @import("negotiate.zig").negotiations_max_ceiling or
        r.inbound_max == 0 or r.outbound_max == 0 or r.inbound_max > @import("reqresp/constants.zig").slots_ceiling or r.outbound_max > @import("reqresp/constants.zig").slots_ceiling or
        r.inbound_control_reserved > r.inbound_max or r.outbound_control_reserved > r.outbound_max or
        options.service.router.outbound_control_reserved < r.outbound_control_reserved or
        options.service.router.outbound_control_reserved > options.service.router.negotiations_max or
        r.inbound_application_per_peer_max > r.inbound_max - r.inbound_control_reserved or
        r.outbound_per_peer_max > r.outbound_max - r.outbound_control_reserved)
        return error.InvalidOptions;
    try gossip.validate(&options.service.gossipsub);
}

test "managed configuration resolves shared capacities and rejects explicit conflicts" {
    const small = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    try std.testing.expectEqual(small.limits.connections_max, small.core.peers.engine_capacity);
    try std.testing.expectEqual(small.limits.connections_max, small.core.service.reqresp.peers);
    try std.testing.expectEqual(small.core.peers.max_peers, small.core.service.gossipsub.connected_capacity);
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .peers = .{} }));
    const beacon = try resolve(.{ .seed = 1, .forks = &.{} });
    try std.testing.expectEqual(@as(u16, 64), beacon.core.peers.target_peers);
    try std.testing.expectEqual(@as(u16, 96), beacon.core.peers.max_peers);
    try std.testing.expect(small.byte_limit < beacon.byte_limit);
}

test "managed configuration rejects inconsistent capacity sections before owners" {
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    var options = resolved.core;
    options.service.reqresp.inbound_control_reserved = options.service.reqresp.inbound_max + 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.service.router.outbound_control_reserved = 0;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.service.gossipsub.retained_capacity = options.service.gossipsub.connected_capacity - 1;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    options = resolved.core;
    options.service.gossipsub.retained_outbound_reserve = options.service.gossipsub.retained_capacity;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    options = resolved.core;
    options.service.gossipsub.connected_capacity = 0;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    var limits = resolved.limits;
    limits.dialing_max += 1;
    try std.testing.expectError(error.InvalidOptions, validate(limits, resolved.core));
}
