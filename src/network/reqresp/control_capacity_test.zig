const std = @import("std");
const rr = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const routing = @import("../router.zig");
const support = @import("../test_support.zig");

pub fn reservedOptions() rr.Options {
    var options: rr.Options = .{ .outbound_max = 4, .inbound_max = 4, .forks = &.{} };
    options.outbound_control_reserved = 2;
    options.inbound_control_reserved = 2;
    return options;
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
        &([_]u8{0} ** 24),
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
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, &events));
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
    _ = requests.pump(&pair.client, &router, pair.now, &.{});
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
        router.negotiator.acceptInbound(first, router.supported, pair.now),
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
    var options: rr.Options = .{ .outbound_max = 4, .inbound_max = 4, .forks = &.{} };
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
        &([_]u8{0} ** 24),
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
    _ = requests.pump(&pair.client, &router, pair.now, &.{});
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
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, &events));
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
    _ = requests.pump(&pair.client, &router, pair.now, &.{});
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

const service_mod = @import("service.zig");
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
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options });
    defer server.deinit();
    defer server.shutdown(&pair.server);
    const ordinary: routing.Selection = .{
        .protocol = .{ .reqresp = .blocks_by_root_v2 },
        .leftover = &.{},
        .fin = false,
    };
    const first = server.acceptNegotiated(
        &pair.server,
        try inboundStream(&pair, handles.client),
        ordinary,
        pair.now,
    ).?;
    const second = server.acceptNegotiated(
        &pair.server,
        try inboundStream(&pair, handles.client),
        ordinary,
        pair.now,
    ).?;
    try std.testing.expect(first.index != second.index);
    const blocked = try inboundStream(&pair, handles.client);
    defer pair.server.closeStream(blocked, 0);
    try std.testing.expectEqual(
        null,
        server.acceptNegotiated(&pair.server, blocked, ordinary, pair.now),
    );
    const raw_sink = try std.testing.allocator.alloc(u8, protocol.requestMaxAll());
    defer std.testing.allocator.free(raw_sink);
    try std.testing.expectError(
        error.SlotsExhausted,
        server.inner.accept(&pair.server, blocked, ordinary, raw_sink, pair.now),
    );
    const status = server.acceptNegotiated(
        &pair.server,
        try inboundStream(&pair, handles.client),
        .{ .protocol = .{ .reqresp = .status_v1 }, .leftover = &.{}, .fin = false },
        pair.now,
    ).?;
    try std.testing.expect(status.index != first.index and status.index != second.index);
    try std.testing.expectEqual(
        server.sink_arena.ptr + @as(usize, status.index) * server.sink_size,
        server.inner.inbound[status.index].io.sink.ptr,
    );
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
        .{ .outbound_max = 4, .inbound_max = 4, .forks = &.{} },
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
            &([_]u8{0} ** 24),
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
    try std.testing.expectEqual(4, requests.pump(&pair.client, &router, pair.now, &events));
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
    var client = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options });
    defer client.deinit();
    defer client.shutdown(&pair.client);
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options });
    defer server.deinit();
    defer server.shutdown(&pair.server);
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
        const client_active = pair.client.driverView().takeActivity(&activity);
        const received = client.processPartitioned(
            &pair.client,
            pair.events(&pair.client, &transport),
            activity[0..client_active],
            pair.now,
            &.{},
            &output,
        );
        for (output[0..received.control]) |event| if (event == .chunk) {
            try std.testing.expectEqualSlices(u8, &ping, event.chunk.bytes);
            try std.testing.expect(client.consume(event.chunk.request, pair.now));
            chunks_received += 1;
        };
        const server_active = pair.server.driverView().takeActivity(&activity);
        const incoming = server.processPartitioned(
            &pair.server,
            pair.events(&pair.server, &transport),
            activity[0..server_active],
            pair.now,
            &.{},
            &output,
        );
        for (output[0..incoming.control]) |event| switch (event) {
            .request => |request| {
                try server.respond(request.request, &ping, null, pair.now);
                requests_received += 1;
            },
            .chunk_sent => |sent| _ = server.finish(sent.request, pair.now),
            else => {},
        };
    }
    try std.testing.expectEqual(2, requests_received);
    try std.testing.expectEqual(1, chunks_received);
    try std.testing.expectEqual(1, server.counters().withheld_chunks);
    try std.testing.expectEqual(
        pair.now.mono_ms + 5_000,
        server.inner.nextWakeupPartitioned(pair.now, 0, 0),
    );
}

fn allocationFailures(allocator: std.mem.Allocator) !void {
    var options = reservedOptions();
    options.outbound_per_peer_max = 2;
    var service = try service_mod.Service.init(allocator, .{
        .reqresp = options,
        .negotiations_max = 4,
        .outbound_control_reserved = 2,
    });
    defer service.deinit();
    const plan = service.memoryPlan();
    try std.testing.expectEqual(plan.facade_bytes + plan.slot_bytes + plan.io_bytes +
        plan.limiter_bytes + plan.request_sink_bytes, plan.total_bytes);
}
