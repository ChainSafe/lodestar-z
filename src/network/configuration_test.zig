const Profile = @import("configuration.zig").Profile;
const policy_fixture = @import("reqresp/policy_fixture.zig");
const resolve = @import("configuration.zig").resolve;
const rr = @import("reqresp/ReqResp.zig");
const std = @import("std");
const Transport = @import("transport.zig").Transport;
const udp = @import("udp");
const validate = @import("configuration.zig").validate;
const protocol = @import("reqresp/protocol.zig");
const config = @import("config");
const PeerId = @import("wire/peer_id.zig").PeerId;
const ForkEntry = @import("types.zig").ForkEntry;
const configuration = @import("configuration.zig");

test "configuration resolves dial concurrency independently of peer headroom" {
    for ([_]u16{ 1, 2, 10 }) |headroom| {
        const resolved = try resolve(.{
            .seed = 1,
            .forks = &.{},
            .limits = .{ .connections_max = 242, .handshaking_max = 32, .dialing_max = 32 },
            .peers = .{ .capacity = 512, .target_peers = 200, .max_peers = 200 + headroom, .min_outbound = 50 },
            .admission_policy = policy_fixture.config(),
        });
        const reserved = @min(headroom, 4);
        try std.testing.expectEqual(@as(u16, 32), resolved.core.dial.concurrent_max);
        try std.testing.expectEqual(@as(u16, 32), resolved.limits.dialing_max);
        try std.testing.expectEqual(reserved, resolved.core.dial.outbound_reserved);
        try std.testing.expectEqual(reserved, resolved.limits.outbound_reserved);
        try std.testing.expectEqual(@as(?u16, 242), resolved.limits.outbound_max);
        try std.testing.expectEqual(200 + headroom, resolved.core.protocols.reqresp.serving_control_reserved);
    }
    const beacon = try resolve(.{ .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    try std.testing.expectEqual(@as(u16, 32), beacon.core.dial.concurrent_max);
    try std.testing.expectError(error.InvalidOptions, resolve(.{
        .seed = 1,
        .forks = &.{},
        .limits = .{ .dialing_max = 16 },
        .dial = .{ .seed = 1, .concurrent_max = 8 },
        .admission_policy = policy_fixture.config(),
    }));
    try std.testing.expectError(error.InvalidOptions, resolve(.{
        .seed = 1,
        .forks = &.{},
        .limits = .{ .dialing_max = 65 },
        .admission_policy = policy_fixture.config(),
    }));
    try std.testing.expectError(error.InvalidOptions, resolve(.{
        .seed = 1,
        .forks = &.{},
        .peers = .{ .target_peers = 96, .max_peers = 96 },
        .admission_policy = policy_fixture.config(),
    }));
}

test "configuration control admission quotas permit the full two hundred peer workload" {
    const resolved = try resolve(.{
        .seed = 1,
        .forks = &.{},
        .peers = .{ .capacity = 512, .target_peers = 190, .max_peers = 200, .min_outbound = 50 },
        .limits = .{ .connections_max = 232 },
        .application_requests_max = 32,
        .admission_policy = policy_fixture.config(),
    });
    const requests = resolved.core.protocols.reqresp;
    const quotas = requests.admission.limits;
    const admission = @import("reqresp/admission.zig");
    var starts = try admission.Limiter.init(std.testing.allocator, requests.admission.limits);
    defer starts.deinit(std.testing.allocator);
    for (std.enums.values(protocol.Protocol)) |which| {
        if (!which.isControl()) continue;
        const quota = quotas.peer[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(which)];
        try std.testing.expectEqual(quota.tokens * 200, quotas.global[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(which)].tokens);
        for (0..200) |index| {
            var identity: PeerId = .{ .bytes = @splat(0) };
            std.mem.writeInt(u16, identity.bytes[0..2], @intCast(index), .little);
            try std.testing.expectEqual(admission.Decision.allowed, starts.take(&identity, which, quota.tokens, .fulu, 0));
            try std.testing.expectEqual(admission.Decision.peer_quota, starts.take(&identity, which, 1, .fulu, 0));
        }
    }
}

test "configuration resolves shared capacities from their owners" {
    const small = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    try std.testing.expectEqual(small.limits.connections_max, small.core.protocols.reqresp.connections);
    try std.testing.expectEqual(small.core.peers.max_peers, small.core.protocols.gossipsub.connected_capacity);
    try std.testing.expectEqual(small.core.peers.max_peers, small.core.protocols.reqresp.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 18), small.core.protocols.reqresp.outbound_max);
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .peers = .{}, .admission_policy = policy_fixture.config() }));
    const beacon = try resolve(.{ .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    try std.testing.expectEqual(@as(u16, 64), beacon.core.peers.target_peers);
    try std.testing.expectEqual(@as(u16, 96), beacon.core.peers.max_peers);
    try std.testing.expectEqual(@as(u16, 96), beacon.core.protocols.router.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 152), beacon.core.protocols.reqresp.outbound_max);
    try std.testing.expect(small.byte_limit < beacon.byte_limit);
}

test "configuration overrides preserve profile defaults and derive shared fields" {
    const forks: []const ForkEntry = &.{.{ .digest = @splat(1), .fork = .fulu }};
    const resolved = try resolve(.{
        .profile = .small,
        .seed = 17,
        .forks = forks,
        .limits = .{ .connections_max = 8, .handshaking_max = 4, .dialing_max = 2 },
        .peers = .{ .capacity = 24, .outbound_reserve = 3, .max_peers = 6, .target_peers = 4, .min_outbound = 1 },
        .reqresp = .{ .work_per_pump_max = 7 },
        .gossip = .{ .validation_capacity = 16 },
        .router = .{ .negotiations_max = 20 },
        .admission_policy = policy_fixture.config(),
    });
    const protocols = &resolved.core.protocols;
    try std.testing.expectEqual(@as(u16, 8), protocols.reqresp.connections);
    try std.testing.expectEqualSlices(ForkEntry, forks, protocols.reqresp.forks);
    try std.testing.expectEqual(@as(u16, 12), protocols.reqresp.outbound_max);
    try std.testing.expectEqual(@as(u16, 7), protocols.reqresp.work_per_pump_max);
    try std.testing.expectEqual(resolved.core.peers.max_peers, protocols.reqresp.serving_control_reserved);
    try std.testing.expectEqual(@as(u16, 6), protocols.router.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 20), protocols.router.negotiations_max);
    try std.testing.expectEqual(@as(u16, 6), protocols.gossipsub.connected_capacity);
    try std.testing.expectEqual(@as(u16, 24), protocols.gossipsub.retained_capacity);
    try std.testing.expectEqual(@as(u16, 3), protocols.gossipsub.retained_outbound_reserve);
    try std.testing.expectEqual(@as(?u64, 17), protocols.gossipsub.random_seed);
    try std.testing.expectEqual(@as(usize, 16), protocols.gossipsub.validation_capacity);
    try std.testing.expectEqual(@as(usize, 256), protocols.gossipsub.mcache_capacity);
    try std.testing.expectEqual(@as(u16, 2), resolved.core.dial.concurrent_max);
}

test "configuration rejects inconsistent capacity sections before owners" {
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    var options = resolved.core;
    options.protocols.router.outbound_control_reserved += 1;
    try validate(resolved.limits, options);
    options = resolved.core;
    options.protocols.reqresp.serving_control_reserved = options.protocols.reqresp.serving_max + 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.router.outbound_control_reserved = 0;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.reqresp.outbound_control_reserved = options.peers.max_peers - 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.reqresp.connections = resolved.limits.connections_max - 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.peers.max_peers = resolved.limits.connections_max + 1;
    try std.testing.expectError(error.InvalidOptions, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.gossipsub.retained_capacity = options.protocols.gossipsub.connected_capacity - 1;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.gossipsub.retained_outbound_reserve = options.protocols.gossipsub.retained_capacity;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    options = resolved.core;
    options.protocols.gossipsub.connected_capacity = 0;
    try std.testing.expectError(error.InvalidLimits, validate(resolved.limits, options));
    var limits = resolved.limits;
    limits.dialing_max = resolved.core.dial.concurrent_max - 1;
    try std.testing.expectError(error.InvalidLimits, validate(limits, resolved.core));
}

test "configuration rejects zero request work override" {
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .work_per_pump_max = 0 }, .admission_policy = policy_fixture.config() }));
}

test "configuration rejects zero control timer from complete section" {
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .control = .{ .ping_inbound_ms = 0 }, .admission_policy = policy_fixture.config() }));
}

test "configuration validates router and score overrides" {
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .gossip = .{ .score_params = .{ .decay_interval_ms = 0 } }, .admission_policy = policy_fixture.config() }));
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .reqresp = .{ .outbound_max = 12 }, .admission_policy = policy_fixture.config() }));
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .router = .{ .negotiations_max = 2 }, .admission_policy = policy_fixture.config() }));
}

test "configuration request admission derives retained capacity quotas and control reservation" {
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    const admission = resolved.core.protocols.reqresp.admission.limits;
    try std.testing.expectEqual(resolved.core.peers.capacity, admission.identities);
    const ForkSeq = @import("config").ForkSeq;
    const Protocol = @import("reqresp/protocol.zig").Protocol;
    try std.testing.expectEqual(@as(u32, 128), admission.peer[@intFromEnum(ForkSeq.fulu)][@intFromEnum(Protocol.blocks_by_root_v2)].tokens);
    try std.testing.expectEqual(@as(u32, 1024), admission.peer[@intFromEnum(ForkSeq.phase0)][@intFromEnum(Protocol.blocks_by_root_v2)].tokens);
    try std.testing.expectEqual(@as(u32, resolved.core.peers.max_peers) * admission.peer[@intFromEnum(ForkSeq.fulu)][@intFromEnum(Protocol.ping_v1)].tokens, admission.global[@intFromEnum(ForkSeq.fulu)][@intFromEnum(Protocol.ping_v1)].tokens);
}

test "configuration request admission memory plan measures both retained profiles" {
    for ([_]Profile{ .small, .beacon_node }) |profile| {
        const resolved = try resolve(.{ .profile = profile, .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
        var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var handler = try rr.init(allocator.allocator(), resolved.core.protocols.reqresp);
        defer handler.deinit();
        const plan = handler.memoryPlan();
        try std.testing.expectEqual(allocator.allocated_bytes, plan.total_bytes - plan.facade_bytes);
        std.debug.print("request admission memory {s}: retained={d} admission={d} facade={d} slots={d} io={d} sinks={d} total={d}\n", .{ @tagName(profile), resolved.core.peers.capacity, plan.admission_bytes, plan.facade_bytes, plan.slot_bytes, plan.io_bytes, plan.request_sink_bytes, plan.total_bytes });
    }
}

test "configuration preserves independent transport work limits" {
    const limits: Transport.WorkLimits = .{ .send_per_turn_max = 3, .receive_per_turn_max = 2, .burst_per_connection = 2 };
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .work_limits = limits, .admission_policy = policy_fixture.config() });
    try std.testing.expectEqual(limits, resolved.work_limits);
    try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .work_limits = .{ .send_per_turn_max = 0 }, .admission_policy = policy_fixture.config() }));
}

test "configuration carries bounded UDP socket buffer requests" {
    const resolved = try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = policy_fixture.config() });
    const mib = 1024 * 1024;
    try std.testing.expectEqual(udp.Sockets.Buffers{ .receive = 16 * mib, .send = 4 * mib }, resolved.socket_buffers.quic);
    try std.testing.expectEqual(udp.Sockets.Buffers{ .receive = 2 * mib, .send = 1 * mib }, resolved.socket_buffers.discovery);
    const bounds: configuration.SocketBuffers = .{
        .quic = .{ .receive = udp.Sockets.Buffers.bytes_max, .send = udp.Sockets.Buffers.bytes_min },
        .discovery = .{ .receive = udp.Sockets.Buffers.bytes_min, .send = udp.Sockets.Buffers.bytes_max },
    };
    try std.testing.expectEqual(bounds, (try resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .socket_buffers = bounds, .admission_policy = policy_fixture.config() })).socket_buffers);
    const invalid = [_]configuration.SocketBuffers{
        .{ .quic = .{ .receive = udp.Sockets.Buffers.bytes_min - 1, .send = udp.Sockets.Buffers.bytes_min } },
        .{ .quic = .{ .receive = udp.Sockets.Buffers.bytes_min, .send = udp.Sockets.Buffers.bytes_max + 1 } },
        .{ .discovery = .{ .receive = udp.Sockets.Buffers.bytes_max + 1, .send = udp.Sockets.Buffers.bytes_min } },
        .{ .discovery = .{ .receive = udp.Sockets.Buffers.bytes_min, .send = udp.Sockets.Buffers.bytes_min - 1 } },
    };
    for (invalid) |socket_buffers| {
        try std.testing.expectError(error.InvalidLimits, resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .socket_buffers = socket_buffers, .admission_policy = policy_fixture.config() }));
    }
}

test "resolved admission and Identify overrides use final profile capacities" {
    const resolved = try resolve(.{
        .profile = .small,
        .seed = 91,
        .forks = &.{},
        .reqresp = .{ .serving_max = 256 },
        .admission_policy = policy_fixture.config(),
        .identify = .{ .agent = "resolved-agent", .protocol_version = "resolved-version" },
    });
    const requests = resolved.core.protocols.reqresp;
    const quotas = requests.admission.limits;
    try std.testing.expectEqual(resolved.core.peers.capacity, quotas.identities);
    try std.testing.expectEqual(@as(u32, resolved.core.peers.max_peers) * quotas.peer[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(protocol.Protocol.ping_v1)].tokens, quotas.global[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(protocol.Protocol.ping_v1)].tokens);
    const identify = resolved.core.protocols.identify;
    try std.testing.expectEqual(@as(u16, 2), identify.inbound_max);
    try std.testing.expectEqualStrings("resolved-agent", identify.agent);
    try std.testing.expectEqualStrings("resolved-version", identify.protocol_version);
}

test "application request limits preserve control capacity and size admission from final limits" {
    for ([_]Profile{ .small, .beacon_node }) |profile| {
        const resolved = try resolve(.{
            .profile = profile,
            .seed = 91,
            .forks = &.{},
            .application_requests_max = 32,
            .admission_policy = policy_fixture.config(),
        });
        const requests = resolved.core.protocols.reqresp;
        const application_max: u16 = if (profile == .small) 6 else 32;
        try std.testing.expectEqual(application_max, requests.serving_max - requests.serving_control_reserved);
        try std.testing.expectEqual(application_max, requests.outbound_max - requests.outbound_control_reserved);
        try std.testing.expectEqual(resolved.core.peers.max_peers, requests.outbound_control_reserved);
        const ping = requests.admission.limits.global[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(protocol.Protocol.ping_v1)];
        try std.testing.expectEqual(@as(u32, resolved.core.peers.max_peers) * requests.admission.limits.peer[@intFromEnum(config.ForkSeq.fulu)][@intFromEnum(protocol.Protocol.ping_v1)].tokens, ping.tokens);
    }
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .seed = 1, .forks = &.{}, .application_requests_max = 0, .admission_policy = policy_fixture.config() }));
    try std.testing.expectError(error.InvalidOptions, resolve(.{ .seed = 1, .forks = &.{}, .application_requests_max = 32, .reqresp = .{ .serving_max = 1 }, .admission_policy = policy_fixture.config() }));
}

test "configuration rejects invalid complete sections" {
    const forks: []const ForkEntry = &.{.{ .digest = @splat(0), .fork = .phase0 }};
    inline for (.{ error.InvalidOptions, error.InvalidOptions, error.InvalidOptions, error.InvalidLimits, error.InvalidLimits, error.InvalidOptions }, 0..) |expected, section| {
        var request: configuration.Options = .{ .profile = .small, .seed = 1, .forks = forks, .admission_policy = policy_fixture.config() };
        switch (section) {
            0 => request.reqresp.work_per_pump_max = 0,
            1 => request.control = .{ .ping_inbound_ms = 0 },
            2 => request.dial = .{ .seed = 1, .concurrent_max = 0 },
            3 => request.gossip.score_params = .{ .decay_interval_ms = 0 },
            4 => request.limits = .{ .handshaking_max = 0 },
            5 => request.peers = .{ .capacity = 0 },
            else => unreachable,
        }
        try std.testing.expectError(expected, resolve(request));
    }
}
