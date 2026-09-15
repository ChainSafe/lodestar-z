const std = @import("std");
const ct = @import("consensus_types");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");
const engine_mod = @import("../quic/engine.zig");
const harness = @import("test_pair.zig");

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const statusBytes = harness.statusBytes;

const Pair = harness.Pair;

fn roundTrip(setup: *Pair, seed: u8) !void {
    const request_ssz = statusBytes(seed);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try setup.client.request(
        &setup.pair.client,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        &sink,
        .{},
        setup.pair.now,
    );
    const reply = statusBytes(seed +% 1);
    var done = false;
    var rounds: usize = 0;
    while (rounds < 40 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.status_v1, incoming.protocol);
                try setup.server.reqresp.respond(incoming.request, &reply, null, setup.pair.now);
            },
            .chunk_sent => |sent| try std.testing.expect(setup.server.reqresp.finish(sent.request, setup.pair.now)),
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &reply, chunk.bytes);
                try std.testing.expect(setup.client.reqresp.consume(chunk.request, setup.pair.now));
            },
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
}

test "service round trips a status request through the collapsed host loop" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .inbound_max = 4 }, .{ .outbound_max = 4, .inbound_max = 4 });
    defer setup.deinit();

    try roundTrip(&setup, 5);
    try std.testing.expectEqual(@as(u16, 0), setup.client.reqresp.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.reqresp.active().inbound);
}

test "service reclaims inbound sinks across more requests than it has slots" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.status_v1)] = .{ .tokens = 1_000, .period_ms = 1_000 };
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .inbound_max = 4, .quotas = quotas }, .{ .outbound_max = 4, .inbound_max = 4, .quotas = quotas });
    defer setup.deinit();

    var seed: u8 = 0;
    while (seed < 12) : (seed += 1) try roundTrip(&setup, seed);
    try std.testing.expectEqual(@as(u64, 12), setup.server.reqresp.counters.requests_served);
    try std.testing.expectEqual(@as(u16, 0), setup.server.reqresp.active().inbound);
}

test "service fails in-flight requests when the connection closes" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .inbound_max = 4 }, .{ .outbound_max = 4, .inbound_max = 4 });
    defer setup.deinit();

    const request_ssz = statusBytes(1);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try setup.client.request(
        &setup.pair.client,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        &sink,
        .{},
        setup.pair.now,
    );
    var seen = false;
    var rounds: usize = 0;
    while (rounds < 12 and !seen) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) seen = true;
        }
    }
    try std.testing.expect(seen);

    try std.testing.expect(setup.pair.client.close(setup.handles.client, 0));
    var client_failed = false;
    var server_failed = false;
    rounds = 0;
    while (rounds < 20 and !(client_failed and server_failed)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) client_failed = true;
        }
        for (setup.serverEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) server_failed = true;
        }
    }
    try std.testing.expect(client_failed);
    try std.testing.expect(server_failed);
    try std.testing.expectEqual(@as(u16, 0), setup.server.reqresp.active().inbound);
}

test "service control wakeup includes earlier Router negotiation after application quiescence" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .inbound_max = 4 }, .{ .outbound_max = 4, .inbound_max = 4 });
    defer setup.deinit();
    setup.client.quiesceApplications();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, setup.handles.client, .ping_v1, &bytes, &sink, .{ .progress_timeout_ms = 60_000 }, setup.pair.now);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .control = &.{} }).control;
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms + 10_000), setup.client.nextWakeup(setup.pair.now, .{ .control = 0 }));
    try std.testing.expect(setup.client.reqresp.cancel(handle));
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .control = &.{} }).control;
    try std.testing.expectEqual(@as(?u64, null), setup.client.nextWakeup(setup.pair.now, .{ .control = 0 }));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .control = &events }).control);
    try std.testing.expect(events[0].failed.reason == .cancelled);
}

test "service preserves drained native activity across a partial request sweep" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .inbound_max = 4 }, .{ .outbound_max = 4, .inbound_max = 4 });
    defer setup.deinit();
    const bytes = [_]u8{9} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    var incoming: ?reqresp.RequestHandle = null;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .request) {
            incoming = event.request.request;
        };
        if (incoming != null) break;
    }
    try std.testing.expect(incoming != null);
    const stream = setup.server.reqresp.inbound[incoming.?.index].lifecycle.stream;
    setup.client.reqresp.options.work_per_pump_max = 1;
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .control = &.{} }).control;
    const codec = @import("codec.zig");
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, null, &bytes, &wire);
    try std.testing.expectEqual(encoded.len, try setup.pair.server.write(stream, encoded, false));
    try setup.pair.pump();
    var activity: [128]engine_mod.Handle = undefined;
    const active = setup.pair.client.takeActivity(&activity);
    try std.testing.expect(active > 0);
    var events: [1]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{}, activity[0..active], setup.pair.now, .{ .control = &events }).control;
    var received = false;
    for (0..10) |_| {
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, .{ .control = 1 }));
        const count = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .control = &events }).control;
        if (count == 1) {
            try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
}
