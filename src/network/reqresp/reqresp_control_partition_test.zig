const std = @import("std");
const rr = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const routing = @import("../router.zig");
const support = @import("../quic/test_support.zig");
const service_mod = @import("../service.zig");
const Engine = @import("../quic/Engine.zig");
const reservedOptions = @import("control_fixture.zig").reservedOptions;

test "reqresp drain retains blocked terminals across control and application partitions" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var requests = try rr.ReqResp.init(std.testing.allocator, try reservedOptions());
    defer requests.deinit();
    const size = protocol.Protocol.blocks_by_root_v2.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, 2 * size);
    defer {
        requests.shutdown(&pair.client, &router);
        std.testing.allocator.free(sink);
    }
    const application = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sink[0..size],
        .{},
        pair.now,
    );
    var pong: [8]u8 = undefined;
    const control = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .ping_v1,
        &([_]u8{0} ** 8),
        &pong,
        .{},
        pair.now,
    );
    const application_second = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .blocks_by_root_v2,
        &.{},
        sink[size..],
        .{},
        pair.now,
    );
    var pong_second: [8]u8 = undefined;
    const control_second = try requests.request(
        &pair.client,
        &router,
        handles.client,
        .ping_v1,
        &([_]u8{0} ** 8),
        &pong_second,
        .{},
        pair.now,
    );
    try std.testing.expect(requests.cancel(application_second));
    try std.testing.expect(requests.cancel(control_second));
    try std.testing.expect(requests.cancel(application));
    try std.testing.expect(requests.cancel(control));
    try std.testing.expectEqual(
        rr.OutputCounts{ .application = 0, .control = 0 },
        requests.pump(&pair.client, &router, pair.now, .{ .application = &.{}, .control = &.{} }),
    );
    try std.testing.expectEqual(0, router.negotiator.active());
    // Each partition delivers its terminals in the order they were latched.
    var output: [1]rr.Event = undefined;
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &.{}, .control = &output }).control);
    try std.testing.expectEqual(control_second, output[0].failed.request);
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &.{}, .control = &output }).control);
    try std.testing.expectEqual(control, output[0].failed.request);
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &output, .control = &.{} }).application);
    try std.testing.expectEqual(application_second, output[0].failed.request);
    try std.testing.expectEqual(1, requests.pump(&pair.client, &router, pair.now, .{ .application = &output, .control = &.{} }).application);
    try std.testing.expectEqual(application, output[0].failed.request);
    _ = requests.pump(&pair.client, &router, pair.now, .{ .application = &.{}, .control = &.{} });
    try std.testing.expectEqual(0, requests.active().outbound);
}

test "reqresp service retains request and chunk bytes through control progress" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = try reservedOptions();
    options.forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .deneb }};
    var client = try @import("../service_test_support.zig").initService(std.testing.allocator, .{ .reqresp = options, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } }, &pair.client);
    defer client.deinit();
    var server = try @import("../service_test_support.zig").initService(std.testing.allocator, .{ .reqresp = options, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } }, &pair.server);
    defer server.deinit();
    defer server.reqresp.shutdown(&pair.server, &server.router);
    const sink = try std.testing.allocator.alloc(
        u8,
        protocol.Protocol.blocks_by_root_v2.info().response_max,
    );
    defer {
        client.reqresp.shutdown(&pair.client, &client.router);
        std.testing.allocator.free(sink);
    }
    const root = [_]u8{0xa5} ** 32;
    const app = try client.request(
        &pair.client,
        handles.client,
        .blocks_by_root_v2,
        &root,
        sink,
        .{ .expected_chunks = 1 },
        pair.now,
    );
    const ping_bytes = [_]u8{42} ++ [_]u8{0} ** 7;
    var pong: [8]u8 = undefined;
    _ = try client.request(
        &pair.client,
        handles.client,
        .ping_v1,
        &ping_bytes,
        &pong,
        .{},
        pair.now,
    );
    var got_pong = false;
    var transport: [16]Engine.Event = undefined;
    var output: [1]rr.Event = undefined;
    for (0..24) |_| {
        try pair.pump();
        const received = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..received.control]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &ping_bytes, chunk.bytes);
                try std.testing.expect(client.reqresp.consume(chunk.request, pair.now));
                got_pong = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        const incoming = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..incoming.control]) |event| switch (event) {
            .request => |request| {
                try std.testing.expectEqual(protocol.Protocol.ping_v1, request.protocol);
                try server.reqresp.respond(request.request, &ping_bytes, null, pair.now);
            },
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(got_pong);
    try std.testing.expectEqual(
        1,
        server.reqresp.pump(&pair.server, &server.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    const request = output[0].request;
    try std.testing.expectEqualSlices(u8, &root, request.bytes);
    const block = [_]u8{0x5a} ** @import("consensus_types").deneb.SignedBeaconBlock.min_size;
    try server.reqresp.respond(request.request, &block, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .deneb }, pair.now);
    for (0..16) |_| {
        try pair.pump();
        _ = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .application = &.{}, .control = &output });
        const count = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .control = &output }).control;
        for (output[0..count]) |event| {
            if (event == .chunk_sent) _ = server.reqresp.finish(event.chunk_sent.request, pair.now);
        }
    }
    try std.testing.expect(client.reqresp.outbound[app.index].request.pendingEvent() != null);
    try std.testing.expectEqualSlices(u8, &block, sink[0..block.len]);
    try std.testing.expectEqual(
        pair.now.mono_ms + 10_000,
        client.reqresp.nextWakeup(pair.now, .{ .application = 0, .control = 1 }),
    );
    try std.testing.expectEqual(
        pair.now.mono_ms,
        client.reqresp.nextWakeup(pair.now, .{ .application = 1, .control = 0 }),
    );
    try std.testing.expect(client.reqresp.cancel(app));
    _ = client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &.{}, .control = &.{} });
    try std.testing.expectEqual(
        1,
        client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    try std.testing.expectEqualSlices(u8, &block, output[0].chunk.bytes);
    try std.testing.expectEqual(app, output[0].chunk.request);
    try std.testing.expectEqual(
        1,
        client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    try std.testing.expectEqual(app, output[0].failed.request);
}
