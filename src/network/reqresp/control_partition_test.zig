const std = @import("std");
const rr = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const routing = @import("../router.zig");
const support = @import("../test_support.zig");
const service_mod = @import("service.zig");
const engine_mod = @import("../quic/engine.zig");
const reservedOptions = @import("control_capacity_test.zig").reservedOptions;

const Counts = struct { application: usize, control: usize };
fn drain(
    requests: *rr.ReqResp,
    pair: *support.Pair,
    router: *routing.Router,
    application: []rr.Event,
    control: []rr.Event,
) Counts {
    const counts = requests.pumpPartitioned(&pair.client, router, pair.now, application, control);
    return .{ .application = counts.application, .control = counts.control };
}

test "reqresp partitioned drain retains blocked terminals and skips mixed over-limit head" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var requests = try rr.ReqResp.init(std.testing.allocator, reservedOptions());
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
        Counts{ .application = 0, .control = 0 },
        drain(&requests, &pair, &router, &.{}, &.{}),
    );
    try std.testing.expectEqual(0, router.negotiator.active());
    var output: [1]rr.Event = undefined;
    try std.testing.expectEqual(1, drain(&requests, &pair, &router, &.{}, &output).control);
    try std.testing.expectEqual(control, output[0].failed.request);
    try std.testing.expectEqual(1, drain(&requests, &pair, &router, &.{}, &output).control);
    try std.testing.expectEqual(control_second, output[0].failed.request);
    try std.testing.expectEqual(1, drain(&requests, &pair, &router, &output, &.{}).application);
    try std.testing.expectEqual(application, output[0].failed.request);
    try std.testing.expectEqual(1, drain(&requests, &pair, &router, &output, &.{}).application);
    try std.testing.expectEqual(application_second, output[0].failed.request);
    _ = drain(&requests, &pair, &router, &.{}, &.{});
    try std.testing.expectEqual(0, requests.active().outbound);
    requests.pushOverLimit(.{ .peer = handles.client, .protocol = .blocks_by_root_v2 });
    requests.pushOverLimit(.{ .peer = handles.client, .protocol = .ping_v1 });
    requests.pushOverLimit(.{ .peer = handles.client, .protocol = .blocks_by_range_v2 });
    requests.pushOverLimit(.{ .peer = handles.client, .protocol = .metadata_v1 });
    for ([_]protocol.Protocol{ .ping_v1, .metadata_v1 }) |which| {
        try std.testing.expectEqual(1, drain(&requests, &pair, &router, &.{}, &output).control);
        try std.testing.expectEqual(which, output[0].over_limit.protocol);
    }
    try std.testing.expectEqual(2, requests.over_limit_len);
    try std.testing.expectEqual(null, requests.nextWakeupPartitioned(pair.now, 0, 1));
    try std.testing.expectEqual(pair.now.mono_ms, requests.nextWakeupPartitioned(pair.now, 1, 0));
    for ([_]protocol.Protocol{ .blocks_by_root_v2, .blocks_by_range_v2 }) |which| {
        try std.testing.expectEqual(1, drain(&requests, &pair, &router, &output, &.{}).application);
        try std.testing.expectEqual(which, output[0].over_limit.protocol);
    }
    try std.testing.expectEqual(0, requests.over_limit_len);
}

test "reqresp partitioned service retains request and chunk bytes through control progress" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = reservedOptions();
    options.forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .deneb }};
    var client = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options });
    defer client.deinit();
    var server = try service_mod.Service.init(std.testing.allocator, .{ .reqresp = options });
    defer server.deinit();
    defer server.shutdown(&pair.server);
    const sink = try std.testing.allocator.alloc(
        u8,
        protocol.Protocol.blocks_by_root_v2.info().response_max,
    );
    defer {
        client.shutdown(&pair.client);
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
    var transport: [16]engine_mod.Event = undefined;
    var activity: [128]engine_mod.Handle = undefined;
    var output: [1]rr.Event = undefined;
    for (0..24) |_| {
        try pair.pump();
        const client_active = pair.client.driverView().takeActivity(&activity);
        const received = client.processPartitioned(
            &pair.client,
            pair.events(&pair.client, &transport),
            activity[0..client_active],
            pair.now,
            &.{},
            &output,
        );
        for (output[0..received.control]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &ping_bytes, chunk.bytes);
                try std.testing.expect(client.handler.consume(chunk.request, pair.now));
                got_pong = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
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
                try std.testing.expectEqual(protocol.Protocol.ping_v1, request.protocol);
                try server.handler.respond(request.request, &ping_bytes, null, pair.now);
            },
            .chunk_sent => |sent| _ = server.handler.finish(sent.request, pair.now),
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(got_pong);
    try std.testing.expectEqual(
        1,
        server.pumpPartitioned(
            &pair.server,
            pair.now,
            &output,
            &.{},
        ).application,
    );
    const request = output[0].request;
    try std.testing.expectEqualSlices(u8, &root, request.bytes);
    const block = [_]u8{0x5a} ** @import("consensus_types").phase0.SignedBeaconBlock.min_size;
    try server.handler.respond(request.request, &block, .deneb, pair.now);
    for (0..16) |_| {
        try pair.pump();
        const client_active = pair.client.driverView().takeActivity(&activity);
        _ = client.processPartitioned(
            &pair.client,
            pair.events(&pair.client, &transport),
            activity[0..client_active],
            pair.now,
            &.{},
            &output,
        );
        const server_active = pair.server.driverView().takeActivity(&activity);
        const count = server.process(
            &pair.server,
            pair.events(&pair.server, &transport),
            activity[0..server_active],
            pair.now,
            &output,
        );
        for (output[0..count]) |event| {
            if (event == .chunk_sent) _ = server.handler.finish(event.chunk_sent.request, pair.now);
        }
    }
    try std.testing.expect(client.handler.inner.outbound[app.index].pending_event != null);
    try std.testing.expectEqualSlices(u8, &block, sink[0..block.len]);
    try std.testing.expectEqual(
        pair.now.mono_ms + 60_000,
        client.handler.inner.nextWakeupPartitioned(pair.now, 0, 1),
    );
    try std.testing.expectEqual(
        pair.now.mono_ms,
        client.handler.inner.nextWakeupPartitioned(pair.now, 1, 0),
    );
    try std.testing.expect(client.handler.cancel(app));
    _ = client.pumpPartitioned(&pair.client, pair.now, &.{}, &.{});
    try std.testing.expectEqual(
        1,
        client.pumpPartitioned(
            &pair.client,
            pair.now,
            &output,
            &.{},
        ).application,
    );
    try std.testing.expectEqualSlices(u8, &block, output[0].chunk.bytes);
    try std.testing.expectEqual(app, output[0].chunk.request);
    try std.testing.expectEqual(
        1,
        client.pumpPartitioned(
            &pair.client,
            pair.now,
            &output,
            &.{},
        ).application,
    );
    try std.testing.expectEqual(app, output[0].failed.request);
}
