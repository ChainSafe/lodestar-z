const std = @import("std");
const rr = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const routing = @import("../router.zig");
const support = @import("../test_support.zig");

const reservedOptions = @import("control_fixture.zig").reservedOptions;

test "reqresp decoder captures configured root byte bounds before reading a body" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var options = reservedOptions();
    options.policy.?.blob_identifiers_deneb = 2;
    options.policy.?.blob_identifiers_electra = 3;
    options.request_fork = .deneb;
    var requests = try rr.ReqResp.init(std.testing.allocator, options);
    defer requests.deinit();
    defer requests.shutdown(&pair.server, &router);
    const first = try requests.accept(&pair.server, try inboundStream(&pair, handles.client), .{
        .protocol = .{ .reqresp = .blob_sidecars_by_root_v1 },
        .leftover = &.{},
        .fin = false,
    }, pair.now);
    requests.setRequestFork(.electra);
    const second = try requests.accept(&pair.server, try inboundStream(&pair, handles.client), .{
        .protocol = .{ .reqresp = .blob_sidecars_by_root_v1 },
        .leftover = &.{},
        .fin = false,
    }, pair.now);
    const older = &requests.inbound[first.index].request.io.decoder;
    const newer = &requests.inbound[second.index].request.io.decoder;
    try std.testing.expectError(error.LengthOutOfBounds, older.feed(&.{120}));
    try std.testing.expectEqual(@as(usize, 0), older.written);
    const prefix = try newer.feed(&.{120});
    try std.testing.expectEqual(@as(usize, 1), prefix.consumed);
    try std.testing.expect(!prefix.done);
    try std.testing.expectEqual(@as(usize, 0), newer.written);
}

test "reqresp partitions compact outbound control storage without consuming application capacity" {
    const options = reservedOptions();
    var requests = try rr.ReqResp.init(std.testing.allocator, options);
    defer requests.deinit();
    for (0..options.outbound_control_reserved) |index| {
        try std.testing.expectEqual(@as(?u16, @intCast(index)), requests.availableOutboundFor(.status_v2));
        const slot = &requests.outbound[index];
        try std.testing.expectEqual(rr.control_scratch_length, slot.request.io.scratch.len);
        try std.testing.expectEqual(rr.control_read_buffer_length, slot.request.io.read_buffer.len);
        slot.request.completion = .active;
        slot.request.protocol = .status_v2;
    }
    try std.testing.expectEqual(@as(?u16, null), requests.availableOutboundFor(.ping_v1));
    try std.testing.expectEqual(@as(?u16, options.outbound_control_reserved), requests.availableOutboundFor(.blocks_by_root_v2));
    for (requests.outbound[options.outbound_control_reserved..]) |*slot| {
        try std.testing.expectEqual(rr.scratch_length, slot.request.io.scratch.len);
        try std.testing.expectEqual(rr.read_buffer_length, slot.request.io.read_buffer.len);
    }
    const controls = options.outbound_control_reserved + options.inbound_control_reserved;
    const applications = options.outbound_max + options.inbound_max - controls;
    try std.testing.expectEqual(@as(usize, controls) * (rr.control_scratch_length + rr.control_read_buffer_length) +
        @as(usize, applications) * (rr.scratch_length + rr.read_buffer_length), requests.memoryPlan().io_bytes);
}

test "reqresp compact control admission rejects oversized handoffs before claiming a slot" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var requests = try rr.ReqResp.init(std.testing.allocator, reservedOptions());
    defer requests.deinit();
    defer requests.shutdown(&pair.server, &router);
    const stream = try inboundStream(&pair, handles.client);
    var bytes: [rr.control_read_buffer_length + 1]u8 = @splat(0);
    try std.testing.expectError(error.InvalidHandoff, requests.accept(&pair.server, stream, .{
        .protocol = .{ .reqresp = .ping_v1 },
        .leftover = &bytes,
        .fin = false,
    }, pair.now));
    try std.testing.expectEqual(@as(usize, 0), requests.active().inbound);
    const handle = try requests.accept(&pair.server, stream, .{ .protocol = .{ .reqresp = .ping_v1 }, .leftover = &.{}, .fin = false }, pair.now);
    try std.testing.expectEqual(@as(u16, 0), handle.index);
}

test "reqresp control capacity protects outbound slots and retains terminal owners" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var requests = try rr.ReqResp.init(std.testing.allocator, reservedOptions());
    defer requests.deinit();
    const size = protocol.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, size * 3);
    defer {
        requests.shutdown(&pair.client, &router);
        std.testing.allocator.free(sinks);
    }
    const first = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sinks[0..size],
        .{},
        pair.now,
    );
    _ = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_range_v2,
        &([_]u8{0} ** 8 ++ [_]u8{1} ++ [_]u8{0} ** 15),
        sinks[size..][0..size],
        .{},
        pair.now,
    );
    try std.testing.expectError(
        error.SlotsExhausted,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[size * 2 ..],
            .{},
            pair.now,
        ),
    );
    var pong: [8]u8 = undefined;
    const ping = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .ping_v1,
        &([_]u8{0} ** 8),
        &pong,
        .{},
        pair.now,
    );
    try std.testing.expectEqual(.outbound, ping.direction);
    try std.testing.expect(requests.cancel(first));
    requests.cleanupPending(&pair.client, &router);
    try std.testing.expectError(
        error.SlotsExhausted,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[size * 2 ..],
            .{},
            pair.now,
        ),
    );
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &events }).application);
    try std.testing.expectEqual(first, events[0].failed.request);
    try std.testing.expectError(
        error.SlotsExhausted,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[size * 2 ..],
            .{},
            pair.now,
        ),
    );
    _ = requests.pump(&pair.client, &router, pair.now, .{ .application = &.{} }).application;
    _ = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sinks[size * 2 ..],
        .{},
        pair.now,
    );
}

test "router control capacity protects outbound negotiations from unknown inbound" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options: routing.Options = .{ .negotiations_max = 4 };
    options.outbound_control_reserved = 2;
    var router = try routing.Router.init(std.testing.allocator, options);
    defer router.deinit();
    const first = try router.beginOutbound(
        &pair.client,
        handles.client,
        .{ .reqresp = .blocks_by_root_v2 },
        pair.now,
    );
    defer router.cancel(&pair.client, first);
    const second = try router.beginMeshsub(&pair.client, handles.client, pair.now);
    defer router.cancel(&pair.client, second);
    try std.testing.expectError(
        error.NegotiationTableFull,
        router.beginMeshsub(&pair.client, handles.client, pair.now),
    );
    try std.testing.expectError(
        error.NegotiationTableFull,
        router.negotiator.acceptInbound(first, pair.now),
    );
    const ping = try router.beginOutbound(
        &pair.client,
        handles.client,
        .{ .reqresp = .ping_v1 },
        pair.now,
    );
    defer router.cancel(&pair.client, ping);
}

test "reqresp control capacity bounds application requests per peer across protocols" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var options: rr.Options = .{ .policy = @import("policy_fixture.zig").config(), .outbound_max = 4, .inbound_max = 4, .forks = &.{} };
    options.outbound_per_peer_max = 2;
    var requests = try rr.ReqResp.init(std.testing.allocator, options);
    defer requests.deinit();
    const size = protocol.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 3 * size);
    defer {
        requests.shutdown(&pair.client, &router);
        std.testing.allocator.free(sinks);
    }
    const first = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sinks[0..size],
        .{},
        pair.now,
    );
    _ = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_range_v2,
        &([_]u8{0} ** 8 ++ [_]u8{1} ++ [_]u8{0} ** 15),
        sinks[size..][0..size],
        .{},
        pair.now,
    );
    try std.testing.expectError(
        error.TooManyRequests,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[2 * size ..],
            .{},
            pair.now,
        ),
    );
    var pong: [8]u8 = undefined;
    _ = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .ping_v1,
        &([_]u8{0} ** 8),
        &pong,
        .{},
        pair.now,
    );
    try std.testing.expect(requests.cancel(first));
    var events: [1]rr.Event = undefined;
    _ = requests.pump(&pair.client, &router, pair.now, .{ .application = &.{} }).application;
    try std.testing.expectError(
        error.TooManyRequests,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[2 * size ..],
            .{},
            pair.now,
        ),
    );
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &events }).application);
    try std.testing.expectEqual(first, events[0].failed.request);
    try std.testing.expectError(
        error.TooManyRequests,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_root_v2,
            &.{},
            sinks[2 * size ..],
            .{},
            pair.now,
        ),
    );
    _ = requests.pump(&pair.client, &router, pair.now, .{ .application = &.{} }).application;
    _ = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sinks[2 * size ..],
        .{},
        pair.now,
    );
}

const service_mod = @import("../service.zig");
const engine_mod = @import("../quic/engine.zig");

fn inboundStream(pair: *support.Pair, conn: engine_mod.Handle) !engine_mod.StreamHandle {
    const stream = try pair.client.openStream(conn);
    try std.testing.expectEqual(1, try pair.client.write(stream, &.{0}, false));
    try pair.pump();
    var events: [16]engine_mod.Event = undefined;
    for (pair.events(&pair.server, &events)) |event| {
        if (event == .stream_opened) return event.stream_opened;
    }
    return error.TestUnexpectedResult;
}

test "reqresp control capacity raw and service inbound admission select the same reserved sink" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = reservedOptions();
    options.inbound_per_peer_max = 4;
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options, .automatic_gossip_admission = false, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } });
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    const ordinary: routing.Selection = .{
        .protocol = .{ .reqresp = .blocks_by_root_v2 },
        .leftover = &.{},
        .fin = false,
    };
    const first = (server.reqresp.accept(&pair.server, try inboundStream(&pair, handles.client), ordinary, pair.now) catch null).?;
    const second = (server.reqresp.accept(&pair.server, try inboundStream(&pair, handles.client), ordinary, pair.now) catch null).?;
    try std.testing.expect(first.index != second.index);
    const blocked = try inboundStream(&pair, handles.client);
    defer pair.server.closeStream(blocked, 0);
    try std.testing.expectEqual(
        null,
        (server.reqresp.accept(&pair.server, blocked, ordinary, pair.now) catch null),
    );
    try std.testing.expectError(
        error.SlotsExhausted,
        server.reqresp.accept(&pair.server, blocked, ordinary, pair.now),
    );
    const status = (server.reqresp.accept(&pair.server, try inboundStream(&pair, handles.client), .{ .protocol = .{ .reqresp = .status_v1 }, .leftover = &.{}, .fin = false }, pair.now) catch null).?;
    try std.testing.expect(status.index != first.index and status.index != second.index);
    try std.testing.expectEqual(
        server.reqresp.inboundSink(status.index).ptr,
        server.reqresp.inbound[status.index].request.io.sink.ptr,
    );
}

test "reqresp admission refusals distinguish capacity and concurrency without failing admitted work" {
    const Case = struct {
        slots: u16,
        peer_limit: u8,
        application_limit: u8 = 0,
        held: u8 = 2,
        accepted: protocol.Protocol = .ping_v1,
        refused: protocol.Protocol = .ping_v1,
        reason: rr.metrics.AdmissionRefusal,
        failure: rr.AcceptError,
    };
    const cases = [_]Case{
        .{ .slots = 2, .peer_limit = 4, .reason = .server_capacity, .failure = error.SlotsExhausted },
        .{ .slots = 4, .peer_limit = 2, .reason = .peer_capacity, .failure = error.PeerSlotsExhausted },
        .{ .slots = 4, .peer_limit = 4, .application_limit = 1, .held = 1, .accepted = .blocks_by_root_v2, .refused = .blocks_by_range_v2, .reason = .peer_capacity, .failure = error.PeerSlotsExhausted },
        .{ .slots = 4, .peer_limit = 4, .reason = .protocol_concurrency, .failure = error.TooManyRequests },
    };
    for (cases) |case| {
        var pair: support.Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        const handles = try support.connectPair(&pair);
        var router = try routing.Router.init(std.testing.allocator, .{});
        defer router.deinit();
        var requests = try rr.ReqResp.init(std.testing.allocator, .{
            .outbound_max = 1,
            .inbound_max = case.slots,
            .inbound_per_peer_max = case.peer_limit,
            .inbound_application_per_peer_max = case.application_limit,
            .forks = &.{},
        });
        defer requests.deinit();
        defer requests.shutdown(&pair.server, &router);
        for (0..case.held) |_| {
            _ = try requests.accept(&pair.server, try inboundStream(&pair, handles.client), .{
                .protocol = .{ .reqresp = case.accepted },
                .leftover = &.{},
                .fin = false,
            }, pair.now);
        }
        const stream = try inboundStream(&pair, handles.client);
        defer pair.server.closeStream(stream, 0);
        try std.testing.expectError(case.failure, requests.accept(&pair.server, stream, .{
            .protocol = .{ .reqresp = case.refused },
            .leftover = &.{},
            .fin = false,
        }, pair.now));
        const counts = requests.protocol_counters[@intFromEnum(case.refused)];
        try std.testing.expectEqual(@as(u64, 1), counts.admission_refusals[@intFromEnum(case.reason)]);
        try std.testing.expectEqual(@as(u64, 1), @reduce(.Add, @as(@Vector(rr.metrics.admission_refusal_count, u64), counts.admission_refusals)));
        try std.testing.expectEqual(@as(u64, @intFromBool(case.reason == .protocol_concurrency)), counts.rate_limited);
        try std.testing.expectEqual(@as(u64, 0), requests.counters.failures);
        const resources = requests.resourceSnapshot();
        try std.testing.expectEqual(@as(usize, case.held), resources.inbound_occupied);
        try std.testing.expectEqual(@as(usize, case.held), resources.inbound_phases[@intFromEnum(rr.metrics.InboundPhase.receiving_request)]);
        for (requests.inbound[0..case.held]) |*slot| try std.testing.expect(slot.request.running());
    }
}

test "reqresp control capacity validates headroom and cleans every allocation prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailures, .{});
    var options = reservedOptions();
    options.outbound_control_reserved = 5;
    try std.testing.expectError(
        error.InvalidOptions,
        rr.ReqResp.init(std.testing.allocator, options),
    );
    options = reservedOptions();
    options.inbound_control_reserved = 5;
    try std.testing.expectError(
        error.InvalidOptions,
        rr.ReqResp.init(std.testing.allocator, options),
    );
    options = reservedOptions();
    options.outbound_per_peer_max = 3;
    try std.testing.expectError(
        error.InvalidOptions,
        rr.ReqResp.init(std.testing.allocator, options),
    );
    options = reservedOptions();
    options.inbound_application_per_peer_max = 3;
    try std.testing.expectError(error.InvalidOptions, rr.ReqResp.init(std.testing.allocator, options));
    options.inbound_max = 16;
    options.inbound_per_peer_max = 2;
    try std.testing.expectError(error.InvalidOptions, rr.ReqResp.init(std.testing.allocator, options));
    options = reservedOptions();
    options.outbound_max = 64;
    options.outbound_per_peer_max = 61;
    try std.testing.expectError(
        error.InvalidOptions,
        rr.ReqResp.init(std.testing.allocator, options),
    );
    options.outbound_per_peer_max = 60;
    var valid = try rr.ReqResp.init(std.testing.allocator, options);
    defer valid.deinit();
    try std.testing.expectError(
        error.InvalidLimits,
        routing.Router.init(
            std.testing.allocator,
            .{ .negotiations_max = 4, .outbound_control_reserved = 5 },
        ),
    );
}

test "reqresp control capacity zero defaults retain all ordinary slots and admission rollback" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var requests = try rr.ReqResp.init(
        std.testing.allocator,
        .{ .outbound_max = 4, .inbound_max = 4, .forks = &.{}, .policy = @import("policy_fixture.zig").config() },
    );
    defer requests.deinit();
    var router = try routing.Router.init(std.testing.allocator, .{ .negotiations_max = 4 });
    defer router.deinit();
    const size = protocol.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 4 * size);
    defer {
        requests.shutdown(&pair.client, &router);
        std.testing.allocator.free(sinks);
    }
    const dead = engine_mod.Handle{
        .index = handles.client.index,
        .generation = handles.client.generation + 1,
    };
    try std.testing.expectError(
        error.StaleHandle,
        requests.request(
            &pair.client,
            &router,
            dead,
            .blocks_by_root_v2,
            &.{},
            sinks[0..size],
            .{},
            pair.now,
        ),
    );
    const roots = [_]protocol.Protocol{ .blocks_by_root_v2, .blocks_by_root_v2 };
    for (roots, 0..) |which, index| {
        _ = try requests.request(
            &pair.client,
            &router,
            handles.client,
            which,
            &.{},
            sinks[index * size ..][0..size],
            .{},
            pair.now,
        );
    }
    for (2..4) |index| {
        _ = try requests.request(
            &pair.client,
            &router,
            handles.client,
            .blocks_by_range_v2,
            &([_]u8{0} ** 8 ++ [_]u8{1} ++ [_]u8{0} ** 15),
            sinks[index * size ..][0..size],
            .{},
            pair.now,
        );
    }
    try std.testing.expectEqual(4, requests.active().outbound);
    var pong: [8]u8 = undefined;
    try std.testing.expectError(
        error.SlotsExhausted,
        requests.request(
            &pair.client,
            &router,
            handles.client,
            .ping_v1,
            &([_]u8{0} ** 8),
            &pong,
            .{},
            pair.now,
        ),
    );
    try std.testing.expectError(
        error.NegotiationTableFull,
        router.beginOutbound(&pair.client, handles.client, .{ .reqresp = .ping_v1 }, pair.now),
    );
    requests.shutdown(&pair.client, &router);
    try std.testing.expectEqual(0, router.negotiator.active());
    var events: [4]rr.Event = undefined;
    try std.testing.expectEqual(4, requests.pump(&pair.client, &router, pair.now, .{ .application = &events }).application);
    for (events) |event| try std.testing.expectEqual(rr.Failure.cancelled, event.failed.reason);
}

test "router control capacity counts pending and reported negotiations until recycle" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(
        std.testing.allocator,
        .{ .negotiations_max = 2, .outbound_control_reserved = 1 },
    );
    defer router.deinit();
    _ = try router.beginMeshsub(&pair.client, handles.client, pair.now);
    pair.advance(10_000);
    try std.testing.expectEqual(0, router.pump(&pair.client, pair.now, &.{}));
    try std.testing.expectEqual(0, router.negotiator.active());
    try std.testing.expectError(
        error.NegotiationTableFull,
        router.beginMeshsub(&pair.client, handles.client, pair.now),
    );
    var output: [1]routing.Outcome = undefined;
    try std.testing.expectEqual(1, router.pump(&pair.client, pair.now, &output));
    try std.testing.expectEqual(
        @import("../negotiate.zig").Failure.timeout,
        output[0].result.failed,
    );
    try std.testing.expectError(
        error.NegotiationTableFull,
        router.beginMeshsub(&pair.client, handles.client, pair.now),
    );
    const ping = try router.beginOutbound(
        &pair.client,
        handles.client,
        .{ .reqresp = .ping_v1 },
        pair.now,
    );
    defer router.cancel(&pair.client, ping);
    _ = router.pump(&pair.client, pair.now, &.{});
    const ordinary = try router.beginMeshsub(&pair.client, handles.client, pair.now);
    defer router.cancel(&pair.client, ordinary);
}

test "reqresp control capacity retains peer and global response quotas" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = reservedOptions();
    var quotas = @import("limiter.zig").defaultQuotas();
    quotas[@intFromEnum(protocol.Protocol.ping_v1)] = .{ .tokens = 1, .period_ms = 5_000 };
    options.quotas = quotas;
    options.global_quotas = quotas;
    var client = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options, .automatic_gossip_admission = false, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } });
    defer client.deinit();
    defer client.reqresp.shutdown(&pair.client, &client.router);
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options, .automatic_gossip_admission = false, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } });
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    const ping = [_]u8{42} ++ [_]u8{0} ** 7;
    var pongs: [2][8]u8 = undefined;
    for (&pongs) |*pong| {
        _ = try client.request(&pair.client, handles.client, .ping_v1, &ping, pong, .{}, pair.now);
    }
    var requests_received: usize = 0;
    var chunks_received: usize = 0;
    for (0..32) |_| {
        try pair.pump();
        var transport: [16]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        var output: [1]rr.Event = undefined;
        const client_active = pair.client.takeActivity(&activity);
        const received = client.process(&pair.client, pair.events(&pair.client, &transport), activity[0..client_active], pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..received.control]) |event| if (event == .chunk) {
            try std.testing.expectEqualSlices(u8, &ping, event.chunk.bytes);
            try std.testing.expect(client.reqresp.consume(event.chunk.request));
            chunks_received += 1;
        };
        const server_active = pair.server.takeActivity(&activity);
        const incoming = server.process(&pair.server, pair.events(&pair.server, &transport), activity[0..server_active], pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..incoming.control]) |event| switch (event) {
            .request => |request| {
                try server.reqresp.respond(request.request, &ping, null, pair.now);
                requests_received += 1;
            },
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            else => {},
        };
    }
    try std.testing.expectEqual(2, requests_received);
    try std.testing.expectEqual(1, chunks_received);
    try std.testing.expectEqual(1, server.reqresp.counters.withheld_chunks);
    try std.testing.expectEqual(
        pair.now.mono_ms + 5_000,
        server.reqresp.nextWakeup(pair.now, .{ .application = 0, .control = 0 }),
    );
}

fn allocationFailures(allocator: std.mem.Allocator) !void {
    var options = reservedOptions();
    options.outbound_per_peer_max = 2;
    var service = try service_mod.Service.init(allocator, .{
        .automatic_gossip_admission = false,
        .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 },
        .reqresp = options,
        .router = .{ .negotiations_max = 4, .outbound_control_reserved = 2 },
    });
    defer service.deinit();
    const plan = service.reqresp.memoryPlan();
    try std.testing.expectEqual(plan.facade_bytes + plan.slot_bytes + plan.io_bytes +
        plan.limiter_bytes + plan.request_sink_bytes, plan.total_bytes);
}

test "reqresp reserved physical sinks admit full native control wave and recycle by generation" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = reservedOptions();
    options.inbound_per_peer_max = 4;
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options, .automatic_gossip_admission = false, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } });
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    var wave: [4]rr.RequestHandle = undefined;
    for ([_]protocol.Protocol{ .status_v1, .ping_v1, .metadata_v3, .goodbye_v1 }, 0..) |which, i| {
        wave[i] = (server.reqresp.accept(&pair.server, try inboundStream(&pair, handles.client), .{ .protocol = .{ .reqresp = which }, .leftover = &.{}, .fin = false }, pair.now) catch null).?;
        try std.testing.expectEqual(@as(u16, @intCast(i)), wave[i].index);
        try std.testing.expectEqual(server.reqresp.inboundSink(wave[i].index).ptr, server.reqresp.inbound[wave[i].index].request.io.sink.ptr);
        try std.testing.expect(server.reqresp.inboundSink(wave[i].index).len >= which.info().request_max);
    }
    try std.testing.expect(server.reqresp.cancel(wave[0]));
    var events: [4]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), server.reqresp.pump(&pair.server, &server.router, pair.now, .{ .control = &events }).control);
    try std.testing.expectEqual(wave[0], events[0].failed.request);
    try std.testing.expectEqual(@as(usize, 0), server.reqresp.pump(&pair.server, &server.router, pair.now, .{ .control = &events }).control);
    try std.testing.expect(server.reqresp.inboundSlot(wave[0]) == null);
    try std.testing.expectEqual(@as(?u16, null), server.reqresp.availableInboundFor(.blocks_by_range_v2));
    const replacement = (server.reqresp.accept(&pair.server, try inboundStream(&pair, handles.client), .{ .protocol = .{ .reqresp = .status_v1 }, .leftover = &.{}, .fin = false }, pair.now) catch null).?;
    try std.testing.expectEqual(wave[0].index, replacement.index);
    try std.testing.expectEqual(wave[0].generation + 1, replacement.generation);
}
