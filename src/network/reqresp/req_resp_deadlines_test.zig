const std = @import("std");
const schedule_test_support = @import("../schedule_test_support.zig");
const ct = @import("consensus_types");
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("ReqResp.zig");
const harness = @import("test_pair.zig");
const Engine = @import("../quic/Engine.zig");
const Router = @import("../router.zig").Router;
const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const Pair = harness.Pair;
const deneb_digest = harness.deneb_digest;
const statusBytes = harness.statusBytes;
const requestBlocks = harness.requestBlocks;
const firstFailure = harness.firstFailure;
const waitForRequest = harness.waitForRequest;

test "reqresp fails a request whose peer stops making progress" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 2_000, .host_timeout_ms = 2_000 });
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_1: [ct.phase0.Status.fixed_size]u8 = undefined;
    request_storage_1 = statusBytes(5);
    _ = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .status_v1, &request_storage_1, &sink, .{ .timeouts = .{ .response = .fromMilliseconds(2000) } }, setup.shared.pair.now);
    try waitForRequest(&setup);

    setup.shared.pair.advance(1_000);
    try setup.pumpOnce();
    try std.testing.expect(firstFailure(setup.clientEvents()) == null);
    setup.shared.pair.advance(1_500);
    var client_failure: ?reqresp.Failure = null;
    var server_failure: ?reqresp.Failure = null;
    var rounds: usize = 0;
    while (rounds < 10 and (client_failure == null or server_failure == null)) : (rounds += 1) {
        try setup.pumpOnce();
        if (firstFailure(setup.clientEvents())) |failure| client_failure = failure;
        if (firstFailure(setup.serverEvents())) |failure| server_failure = failure;
    }
    try std.testing.expect(client_failure != null and client_failure.? == .timeout);
    try std.testing.expect(server_failure != null);
    try std.testing.expect(server_failure.? == .host_timeout or server_failure.? == .stream_closed);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.shared.client.reqresp.pendingCounts().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.pendingCounts().inbound);
    const counts = &setup.shared.client.reqresp.protocol_counters[@intFromEnum(Protocol.status_v1)];
    try std.testing.expectEqual(@as(u64, 1), counts.outgoing_time.count);
    try std.testing.expect(counts.outgoing_time.sum >= 2500);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.reqresp.outgoing_error_reasons[@intFromEnum(reqresp.metrics.ErrorReason.REQUEST_ERROR_RESP_TIMEOUT)]);
}

test "reqresp negotiated handoff starts a fresh progress interval" {
    var setup: Pair = .{};
    try setup.init(.{ .progress_timeout_ms = 1000 }, .{});
    defer setup.deinit();
    _ = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &.{} }).control;
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .ping_v1, &bytes, &sink, .{}, setup.shared.pair.now);
    var ready = false;
    for (0..30) |_| {
        try setup.shared.pair.pump();
        var storage: [16]Engine.Event = undefined;
        setup.shared.server.router.transportEvents(&setup.shared.pair.server, setup.shared.pair.events(&setup.shared.pair.server, &storage), setup.shared.pair.now);
        var outcomes: [8]Router.Outcome = undefined;
        setup.forwardEvents();
        _ = setup.shared.server.router.pump(&setup.shared.pair.server, setup.shared.pair.now, &outcomes);
        setup.forwardEvents();
        const count = setup.shared.client.router.pump(&setup.shared.pair.client, setup.shared.pair.now, &outcomes);
        if (count == 0) continue;
        try std.testing.expectEqual(@as(usize, 1), count);
        setup.shared.pair.advance(2000);
        try std.testing.expect(setup.shared.client.reqresp.negotiated(&setup.shared.pair.client, outcomes[0], setup.shared.pair.now));
        try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.millis()), schedule_test_support.wakeupMilliseconds(setup.shared.client.reqresp.schedule(.{ .control = 1 }), setup.shared.pair.now.millis()));
        ready = true;
        break;
    }
    try std.testing.expect(ready);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
    try std.testing.expect(setup.shared.client.reqresp.cancel(handle, setup.shared.pair.now));
}

test "reqresp admission wait expires as local policy and not peer timeout" {
    var admission = try reqresp.Options.Admission.defaults(&@import("policy_fixture.zig").config(), 128, 128, 8);
    for (&admission.limits.peer) |*quotas| quotas[@intFromEnum(Protocol.ping_v1)] = .{ .tokens = 1, .period_ms = 5000 };
    var setup: Pair = .{};
    try setup.init(.{}, .{ .quota_timeout_ms = 1000, .admission = admission });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sinks: [2][8]u8 = undefined;
    for (&sinks) |*sink| _ = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .ping_v1, &bytes, sink, .{}, setup.shared.pair.now);
    var requested: u32 = 0;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.shared.server.reqresp.respond(incoming.request, &bytes, null, setup.shared.pair.now);
                requested += 1;
            },
            else => {},
        };
    }
    try std.testing.expectEqual(@as(u32, 1), requested);
    var ready: usize = 0;
    for (setup.shared.server.reqresp.inbound) |*slot| ready += @intFromBool(slot.request.running() and slot.state == .ready);
    try std.testing.expectEqual(@as(usize, 1), ready);
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.millis() + 1000), schedule_test_support.wakeupMilliseconds(setup.shared.server.reqresp.schedule(.{ .control = 0 }), setup.shared.pair.now.millis()));
    setup.shared.pair.advance(1000);
    var events: [4]Event = undefined;
    const count = setup.shared.server.reqresp.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .control = &events }).control;
    var expired = false;
    for (events[0..count]) |event| if (event == .failed) {
        try std.testing.expect(event.failed.reason == .quota_timeout);
        try std.testing.expect(setup.shared.server.reqresp.peerFault(event) == null);
        expired = true;
    };
    try std.testing.expect(expired);
}

test "reqresp blocked response writes expire and do not advertise ready local work" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 2000 });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .ping_v1, &bytes, &sink, .{}, setup.shared.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    const stream = setup.shared.server.reqresp.inbound[incoming.index].request.stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.shared.pair.server.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    try setup.shared.server.reqresp.respond(incoming, &bytes, null, setup.shared.pair.now);
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.millis()), schedule_test_support.wakeupMilliseconds(setup.shared.server.reqresp.schedule(.{ .control = 0 }), setup.shared.pair.now.millis()));
    const due = setup.shared.pair.now.millis() + 2000;
    for (0..3) |_| {
        setup.shared.pair.advance(500);
        _ = setup.shared.server.reqresp.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .control = &.{} }).control;
        try std.testing.expectEqual(@as(?u64, due), schedule_test_support.wakeupMilliseconds(setup.shared.server.reqresp.schedule(.{ .control = 0 }), setup.shared.pair.now.millis()));
    }
    setup.shared.pair.advance(500);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.reqresp.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .control = &events }).control);
    try std.testing.expect(events[0].failed.reason == .timeout);
    try std.testing.expect(!setup.shared.pair.server.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
}

test "reqresp absolute response deadline captures the live phase" {
    var setup: Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    setup.shared.pair.now.monotonic.raw.nanoseconds += 900_000;
    const started_ms = setup.shared.pair.now.millis();
    const request = statusBytes(5);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .status_v1, &request, &sink, .{
        .timeouts = .{ .negotiation = .fromMilliseconds(5_000), .request = .fromMilliseconds(5_000), .response = .fromNanoseconds(500_000) },
    }, setup.shared.pair.now);
    try waitForRequest(&setup);
    const due = setup.shared.client.reqresp.outbound[handle.index].deadline().?;
    try std.testing.expectEqual(started_ms + 2, due);
    setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due - 1);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
    setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due);
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
    try std.testing.expectEqual(.timeout, events[0].failed.reason);
    try std.testing.expectEqual(.response, events[0].failed.phase.?);
}

test "reqresp absolute request phase expires under real stream backpressure" {
    var setup: Pair = .{};
    try setup.init(.{ .progress_timeout_ms = 2_000 }, .{});
    defer setup.deinit();
    setup.shared.pair.now.monotonic.raw.nanoseconds += 900_000;
    _ = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &.{} }).control;
    const request = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.shared.client.reqresp.request(
        &setup.shared.pair.client,
        &setup.shared.client.router,
        setup.shared.handles.client,
        .ping_v1,
        &request,
        &sink,
        .{ .timeouts = .{ .negotiation = .fromMilliseconds(5000), .request = .fromNanoseconds(2_000_500_000), .response = .fromMilliseconds(10000) } },
        setup.shared.pair.now,
    );
    var negotiated = false;
    for (0..50) |_| {
        try setup.shared.pair.pump();
        var storage: [16]Engine.Event = undefined;
        for (setup.shared.pair.events(&setup.shared.pair.server, &storage)) |event| switch (event) {
            .stream_opened => |stream| try setup.shared.server.router.negotiator.acceptInbound(
                &setup.shared.pair.server,
                stream,
                setup.shared.pair.now,
            ),
            else => {},
        };
        var outcomes: [8]Router.Outcome = undefined;
        setup.forwardEvents();
        const listened = setup.shared.server.router.pump(&setup.shared.pair.server, setup.shared.pair.now, &outcomes);
        for (outcomes[0..listened]) |outcome| try std.testing.expect(outcome.result == .ready);
        setup.forwardEvents();
        const dialed = setup.shared.client.router.pump(&setup.shared.pair.client, setup.shared.pair.now, &outcomes);
        for (outcomes[0..dialed]) |outcome| {
            try std.testing.expect(outcome.result == .ready);
            negotiated = setup.shared.client.reqresp.negotiated(&setup.shared.pair.client, outcome, setup.shared.pair.now);
        }
        if (negotiated) break;
    }
    try std.testing.expect(negotiated);
    const stream = setup.shared.client.reqresp.outbound[handle.index].request.stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.shared.pair.client.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    const deadline_ms = setup.shared.client.reqresp.outbound[handle.index].deadline();
    try std.testing.expectEqual(setup.shared.pair.now.millis() + 2002, deadline_ms.?);
    var events: [8]Event = undefined;
    _ = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events });
    try setup.shared.pair.flush(&setup.shared.pair.client);
    var stale = stream;
    stale.conn.generation += 1;
    setup.shared.client.reqresp.streamReady(setup.shared.pair.client.route(stream).?, stale);
    for (0..3) |_| {
        setup.shared.pair.advance(500);
        try std.testing.expectEqual(
            @as(usize, 0),
            setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control,
        );
        try std.testing.expectEqual(deadline_ms, setup.shared.client.reqresp.outbound[handle.index].deadline());
        try std.testing.expect(!setup.shared.pair.client.backlog());
    }
    setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(deadline_ms.?);
    try std.testing.expectEqual(
        @as(usize, 1),
        setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control,
    );
    try std.testing.expect(events[0].failed.reason == .timeout);
    try std.testing.expectEqual(.request, events[0].failed.phase.?);
    try std.testing.expect(
        !setup.shared.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id),
    );
}

test "reqresp sub-millisecond negotiation timeout agrees with the router deadline" {
    for ([_]bool{ false, true }) |router_first| {
        var setup: Pair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        setup.shared.pair.now.monotonic.raw.nanoseconds += 900_000;
        const started_ms = setup.shared.pair.now.millis();
        const request = statusBytes(5);
        var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
        const handle = try setup.shared.client.reqresp.request(
            &setup.shared.pair.client,
            &setup.shared.client.router,
            setup.shared.handles.client,
            .status_v1,
            &request,
            &sink,
            .{ .timeouts = .{ .negotiation = .fromNanoseconds(500_000) } },
            setup.shared.pair.now,
        );
        var outcomes: [1]Router.Outcome = undefined;
        var events: [1]Event = undefined;
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(started_ms + 1);
        if (router_first) try std.testing.expectEqual(@as(usize, 0), setup.shared.client.router.pump(&setup.shared.pair.client, setup.shared.pair.now, &outcomes));
        try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(started_ms + 2);
        if (router_first) {
            try std.testing.expectEqual(@as(usize, 1), setup.shared.client.router.pump(&setup.shared.pair.client, setup.shared.pair.now, &outcomes));
            try std.testing.expectEqual(.timeout, outcomes[0].result.failed);
            try std.testing.expect(setup.shared.client.reqresp.negotiated(&setup.shared.pair.client, outcomes[0], setup.shared.pair.now));
        }
        try std.testing.expectEqual(@as(usize, 1), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
        try std.testing.expectEqual(handle, events[0].failed.request);
        try std.testing.expectEqual(.timeout, events[0].failed.reason);
        try std.testing.expectEqual(.negotiation, events[0].failed.phase.?);
    }
}

test "reqresp absolute negotiation timeout phase survives terminal cleanup" {
    for ([_]u64{ 50, 20_000 }) |duration| {
        var setup: Pair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const request = statusBytes(5);
        var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
        const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .status_v1, &request, &sink, .{ .timeouts = .{ .negotiation = .fromMilliseconds(@intCast(duration)), .request = .fromMilliseconds(5000), .response = .fromMilliseconds(10000) } }, setup.shared.pair.now);
        const stream = setup.shared.client.reqresp.outbound[handle.index].request.stream;
        try std.testing.expectEqual(@as(usize, 1), setup.shared.client.router.negotiator.active());
        const due = setup.shared.pair.now.millis() + duration;
        var events: [1]Event = undefined;
        _ = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control;
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due - 1);
        try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due);
        try std.testing.expectEqual(@as(usize, 1), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
        try std.testing.expectEqual(handle, events[0].failed.request);
        try std.testing.expectEqual(.timeout, events[0].failed.reason);
        try std.testing.expectEqual(.negotiation, events[0].failed.phase.?);
        try std.testing.expectEqual(@as(usize, 0), setup.shared.client.router.negotiator.active());
        try std.testing.expect(!setup.shared.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    }
}

test "reqresp absolute response includes paused host time without renewing at chunks or consume" {
    for ([_]bool{ false, true }) |consume| {
        var setup: Pair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
        defer std.testing.allocator.free(sink);
        const block = [_]u8{7} ** 4000;
        const roots = [_]u8{0} ** 64;
        const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .blocks_by_root_v2, &roots, sink, .{ .timeouts = .{ .negotiation = .fromMilliseconds(5000), .request = .fromMilliseconds(5000), .response = .fromMilliseconds(1000) } }, setup.shared.pair.now);
        var held = false;
        for (0..80) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| if (event == .request) try setup.shared.server.reqresp.respond(event.request.request, &block, .{ .digest = deneb_digest, .fork = .deneb }, setup.shared.pair.now);
            for (setup.clientEvents()) |event| if (event == .chunk) {
                held = true;
            };
            if (held) break;
        }
        try std.testing.expect(held);
        const due = setup.shared.client.reqresp.outbound[handle.index].deadline().?;
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due - 1);
        if (consume) try std.testing.expect(setup.shared.client.reqresp.consume(handle, setup.shared.pair.now));
        try std.testing.expectEqual(@as(?u64, due), setup.shared.client.reqresp.outbound[handle.index].deadline());
        var events: [1]Event = undefined;
        try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .application = &events }).application);
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due);
        try std.testing.expectEqual(@as(usize, 1), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .application = &events }).application);
        try std.testing.expectEqual(if (consume) std.meta.Tag(reqresp.Failure).timeout else .host_timeout, std.meta.activeTag(events[0].failed.reason));
        try std.testing.expectEqual(.response, events[0].failed.phase.?);
    }
}

test "reqresp absolute response expires despite continuous wire progress" {
    for ([_]u64{ 100, 10_000 }) |duration| {
        var setup: Pair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const request = statusBytes(5);
        var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
        const options: reqresp.RequestOptions = if (duration == 100) .{ .timeouts = .{ .response = .fromMilliseconds(@intCast(duration)) } } else .{};
        const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .status_v1, &request, &sink, options, setup.shared.pair.now);
        try waitForRequest(&setup);
        const due = setup.shared.client.reqresp.outbound[handle.index].deadline().?;
        const stream = setup.shared.server.reqresp.inbound[0].request.stream;
        var wire: [codec.frame_scratch_max]u8 = undefined;
        const encoded = try codec.encodeChunk(0, null, &request, &wire);
        try std.testing.expect(encoded.len > 10);
        var events: [1]Event = undefined;
        for (0..9) |i| {
            setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due - 90 + i * 10);
            try std.testing.expectEqual(@as(usize, 1), try setup.shared.pair.server.write(stream, encoded[i .. i + 1], false));
            try setup.shared.pair.pump();
            @import("../protocols_test_support.zig").forward(&setup.shared.pair, &setup.shared.pair.client, .{ .reqresp = &setup.shared.client.reqresp });
            try std.testing.expectEqual(@as(usize, 0), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
            try std.testing.expectEqual(@as(?u64, due), setup.shared.client.reqresp.outbound[handle.index].deadline());
        }
        setup.shared.pair.now.monotonic = @import("../time.zig").milliseconds(due);
        const count = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control;
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expectEqual(.timeout, events[0].failed.reason);
        try std.testing.expectEqual(.response, events[0].failed.phase.?);
    }
}

test "reqresp partial response writes cannot renew the chunk deadline" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 2000 });
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_range_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    var request: [24]u8 = undefined;
    _ = try requestBlocks(&setup, &request, 1, sink);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    const slot = &setup.shared.server.reqresp.inbound[incoming.index];
    const payload = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(payload);
    var random = std.Random.DefaultPrng.init(1);
    random.random().bytes(payload);
    try setup.shared.server.reqresp.respond(incoming, payload, .{ .digest = deneb_digest, .fork = .deneb }, setup.shared.pair.now);
    const due = slot.deadline(&setup.shared.server.reqresp).?;
    const before = try setup.shared.pair.server.streamCapacity(slot.request.stream);
    setup.shared.pair.advance(500);
    _ = setup.shared.server.reqresp.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{});
    try std.testing.expect((try setup.shared.pair.server.streamCapacity(slot.request.stream)) < before);
    try std.testing.expect(slot.request.io.writing);
    try std.testing.expectEqual(due, slot.deadline(&setup.shared.server.reqresp).?);
    setup.shared.pair.advance(1500);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.reqresp.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &events }).application);
    try std.testing.expect(events[0].failed.reason == .timeout);
}
