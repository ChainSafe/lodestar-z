const std = @import("std");
const core = @import("managed.zig");
const engine = @import("quic/engine.zig");
const transport = @import("transport.zig");
const rr = @import("reqresp/reqresp.zig");
const gossip = @import("gossipsub/options.zig");
const c = @import("gossipsub/constants.zig");
const peers = @import("peers/types.zig");
const dial = @import("peers/dial_queue.zig");
const router = @import("router.zig");

pub const Profile = enum { small, beacon_node };
pub const ReqRespOverrides = Overrides(rr.Options, &.{ "peers", "forks", "outbound_control_reserved" });
pub const GossipOverrides = Overrides(gossip.Options, &.{ "connected_capacity", "retained_capacity", "retained_outbound_reserve", "random_seed" });
pub const IdentifyOverrides = Overrides(@import("identify/root.zig").Options, &.{});
pub const RouterOverrides = Overrides(router.Options, &.{"outbound_control_reserved"});

/// Req/resp, gossip and router fields override profile defaults; shared capacities are derived.
pub const Request = struct {
    profile: Profile = .beacon_node,
    seed: u64,
    forks: []const rr.ForkEntry,
    limits: ?engine.Limits = null,
    work_limits: transport.WorkLimits = .{},
    peers: ?peers.Options = null,
    dial: ?dial.Options = null,
    reqresp: ReqRespOverrides = .{},
    gossip: GossipOverrides = .{},
    router: RouterOverrides = .{},
    identify: IdentifyOverrides = .{},
    admission_policy: ?@import("reqresp/request_policy.zig").Config = null,
    control: ?@import("peers/control.zig").Options = null,
    byte_limit: ?usize = null,
};
pub const Resolved = struct {
    limits: engine.Limits,
    work_limits: transport.WorkLimits,
    core: core.Options,
    byte_limit: usize,
};

pub fn resolve(request: Request) !Resolved {
    try request.work_limits.validate();
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
    };
    try peer_options.validate();
    const reserved: u16 = if (small) 2 else 8;
    var requests: rr.Options = .{
        .forks = request.forks,
        .peers = limits.connections_max,
        .outbound_max = peer_options.max_peers + @as(u16, if (small) 6 else 56),
        .inbound_max = if (small) 8 else 64,
        .outbound_control_reserved = peer_options.max_peers,
        .inbound_control_reserved = reserved,
        .outbound_per_peer_max = if (small) 4 else 8,
        .inbound_per_peer_max = if (small) 8 else 16,
        .inbound_application_per_peer_max = if (small) 4 else 8,
    };
    applyOverrides(&requests, request.reqresp);
    if (request.admission_policy) |policy_config| {
        if (requests.admission != null) return error.InvalidOptions;
        requests.admission = try rr.AdmissionOptions.defaults(&policy_config, peer_options.capacity, requests.inbound_max);
    }
    var identify: @import("identify/root.zig").Options = .{ .inbound_max = if (small) 2 else 4, .outbound_max = if (small) 2 else 4 };
    applyOverrides(&identify, request.identify);
    var protocols: router.Options = .{
        .negotiations_max = peer_options.max_peers + @as(u16, if (small) 30 else 248),
        .outbound_control_reserved = requests.outbound_control_reserved,
        .outbound_reserved = peer_options.max_peers + @as(u16, if (small) 8 else 64),
    };
    applyOverrides(&protocols, request.router);
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
        gossip_options.receive_arena_bytes = std.mem.alignForward(usize, c.GOSSIP_MAX_SIZE, @import("gossipsub/receive_pool.zig").page_bytes);
    }
    applyOverrides(&gossip_options, request.gossip);
    const result: Resolved = .{
        .limits = limits,
        .work_limits = request.work_limits,
        .byte_limit = request.byte_limit orelse if (small) 80 * 1024 * 1024 else 256 * 1024 * 1024,
        .core = .{
            .peers = peer_options,
            .dial = request.dial orelse .{ .capacity = if (small) 32 else 256, .concurrent_max = @min(4, limits.dialing_max), .seed = request.seed },
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

pub fn validate(limits: engine.Limits, options: core.Options) !void {
    _ = try engine.Engine.validateLimits(limits);
    try core.validateOptions(options);
    if (options.peers.max_peers > limits.connections_max or
        options.service.reqresp.peers < limits.connections_max or
        options.dial.concurrent_max > limits.dialing_max or
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

test "managed configuration resolves shared capacities from their owners" {
    const small = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    try std.testing.expectEqual(small.limits.connections_max, small.core.service.reqresp.peers);
    try std.testing.expectEqual(small.core.peers.max_peers, small.core.service.gossipsub.connected_capacity);
    try std.testing.expectEqual(small.core.peers.max_peers, small.core.service.reqresp.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 18), small.core.service.reqresp.outbound_max);
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .peers = .{} }));
    const beacon = try resolve(.{ .seed = 1, .forks = &.{} });
    try std.testing.expectEqual(@as(u16, 64), beacon.core.peers.target_peers);
    try std.testing.expectEqual(@as(u16, 96), beacon.core.peers.max_peers);
    try std.testing.expectEqual(@as(u16, 96), beacon.core.service.router.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 152), beacon.core.service.reqresp.outbound_max);
    try std.testing.expect(small.byte_limit < beacon.byte_limit);
}

test "managed configuration overrides preserve profile defaults and derive shared fields" {
    const forks: []const rr.ForkEntry = &.{.{ .digest = @splat(1), .fork = .fulu }};
    const resolved = try resolve(.{
        .profile = .small,
        .seed = 17,
        .forks = forks,
        .limits = .{ .connections_max = 8, .handshaking_max = 4, .dialing_max = 2 },
        .peers = .{ .capacity = 24, .outbound_reserve = 3, .max_peers = 6, .target_peers = 4, .min_outbound = 1 },
        .reqresp = .{ .inbound_control_reserved = 1, .work_per_pump_max = 7 },
        .gossip = .{ .validation_capacity = 16 },
        .router = .{ .negotiations_max = 20 },
    });
    const service = &resolved.core.service;
    try std.testing.expectEqual(@as(u16, 8), service.reqresp.peers);
    try std.testing.expectEqualSlices(rr.ForkEntry, forks, service.reqresp.forks);
    try std.testing.expectEqual(@as(u16, 12), service.reqresp.outbound_max);
    try std.testing.expectEqual(@as(u16, 7), service.reqresp.work_per_pump_max);
    try std.testing.expectEqual(@as(u16, 1), service.reqresp.inbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 6), service.router.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 20), service.router.negotiations_max);
    try std.testing.expectEqual(@as(u16, 6), service.gossipsub.connected_capacity);
    try std.testing.expectEqual(@as(u16, 24), service.gossipsub.retained_capacity);
    try std.testing.expectEqual(@as(u16, 3), service.gossipsub.retained_outbound_reserve);
    try std.testing.expectEqual(@as(?u64, 17), service.gossipsub.random_seed);
    try std.testing.expectEqual(@as(usize, 16), service.gossipsub.validation_capacity);
    try std.testing.expectEqual(@as(usize, 256), service.gossipsub.mcache_capacity);
    try std.testing.expectEqual(@as(u16, 2), resolved.core.dial.concurrent_max);
}

test "managed configuration rejects inconsistent capacity sections before owners" {
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    var options = resolved.core;
    options.service.router.outbound_control_reserved += 1;
    try validate(resolved.limits, options);
    options = resolved.core;
    options.service.reqresp.inbound_control_reserved = options.service.reqresp.inbound_max + 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.service.router.outbound_control_reserved = 0;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.service.reqresp.outbound_control_reserved = options.peers.max_peers - 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.service.reqresp.peers = resolved.limits.connections_max - 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.peers.max_peers = resolved.limits.connections_max + 1;
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
    limits.dialing_max = resolved.core.dial.concurrent_max - 1;
    try std.testing.expectError(error.InvalidOptions, validate(limits, resolved.core));
}

test "managed configuration rejects zero request work override" {
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .work_per_pump_max = 0 } }));
}

test "managed configuration rejects zero control timer from complete section" {
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .control = .{ .ping_inbound_ms = 0 } }));
}

test "managed configuration validates router and score overrides" {
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .router = .{ .meshsub = false } }));
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .gossip = .{ .score_params = .{ .decay_interval_ms = 0 } } }));
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .outbound_max = 12 } }));
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .router = .{ .negotiations_max = 2 } }));
}

test "managed runtime request admission derives retained capacity quotas and control reservation" {
    const base = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    var admission_options = try rr.AdmissionOptions.defaults(&@import("reqresp/policy_fixture.zig").config(), base.core.peers.capacity, base.core.service.reqresp.inbound_max);
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .admission = admission_options } });
    const admission = resolved.core.service.reqresp.admission.?.limits;
    try std.testing.expectEqual(resolved.core.peers.capacity, admission.identities);
    const ForkSeq = @import("config").ForkSeq;
    const Protocol = @import("reqresp/protocol.zig").Protocol;
    try std.testing.expectEqual(@as(u32, 128), admission.peer[@intFromEnum(ForkSeq.fulu)][@intFromEnum(Protocol.blocks_by_root_v2)].tokens);
    try std.testing.expectEqual(@as(u32, 1024), admission.peer[@intFromEnum(ForkSeq.phase0)][@intFromEnum(Protocol.blocks_by_root_v2)].tokens);
    try std.testing.expectEqual(@as(u32, resolved.core.service.reqresp.inbound_max), admission.global[@intFromEnum(ForkSeq.fulu)][@intFromEnum(Protocol.ping_v1)].tokens);
    admission_options.limits.global[0][0].tokens = 0;
    try std.testing.expectError(error.InvalidQuota, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .admission = admission_options } }));
}

test "managed runtime request admission memory plan measures both retained profiles" {
    for ([_]Profile{ .small, .beacon_node }) |profile| {
        const base = try resolve(.{ .profile = profile, .seed = 1, .forks = &.{} });
        const admission = try rr.AdmissionOptions.defaults(&@import("reqresp/policy_fixture.zig").config(), base.core.peers.capacity, base.core.service.reqresp.inbound_max);
        const resolved = try resolve(.{ .profile = profile, .seed = 1, .forks = &.{}, .reqresp = .{ .admission = admission } });
        var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var handler = try @import("reqresp/reqresp.zig").ReqResp.init(allocator.allocator(), resolved.core.service.reqresp);
        defer handler.deinit();
        const plan = handler.memoryPlan();
        try std.testing.expectEqual(allocator.allocated_bytes, plan.total_bytes - plan.facade_bytes);
        std.debug.print("request admission memory {s}: retained={d} admission={d} facade={d} slots={d} io={d} output_limiter={d} sinks={d} total={d}\n", .{ @tagName(profile), resolved.core.peers.capacity, plan.admission_bytes, plan.facade_bytes, plan.slot_bytes, plan.io_bytes, plan.limiter_bytes, plan.request_sink_bytes, plan.total_bytes });
    }
}

test "managed configuration preserves independent transport work limits" {
    const limits: transport.WorkLimits = .{ .send_per_step_max = 3, .receive_per_step_max = 2, .work_per_step_max = 7 };
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .work_limits = limits });
    try std.testing.expectEqual(limits, resolved.work_limits);
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .work_limits = .{ .send_per_step_max = 0 } }));
}

test "resolved admission and Identify overrides use final profile capacities" {
    const resolved = try resolve(.{
        .profile = .small,
        .seed = 91,
        .forks = &.{},
        .reqresp = .{ .inbound_max = 256 },
        .admission_policy = @import("reqresp/policy_fixture.zig").config(),
        .identify = .{ .agent = "resolved-agent", .protocol_version = "resolved-version" },
    });
    const requests = resolved.core.service.reqresp;
    const quotas = requests.admission.?.limits;
    try std.testing.expectEqual(resolved.core.peers.capacity, quotas.identities);
    try std.testing.expectEqual(@as(u32, 256), quotas.global[@intFromEnum(@import("config").ForkSeq.fulu)][@intFromEnum(@import("reqresp/protocol.zig").Protocol.ping_v1)].tokens);
    const identify = resolved.core.service.identify.?;
    try std.testing.expectEqual(@as(u16, 2), identify.inbound_max);
    try std.testing.expectEqualStrings("resolved-agent", identify.agent);
    try std.testing.expectEqualStrings("resolved-version", identify.protocol_version);
}
