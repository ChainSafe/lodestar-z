const std = @import("std");
const rr = @import("reqresp.zig");
const codec = @import("codec.zig");
const Protocol = @import("protocol.zig").Protocol;
const Pair = @import("test_pair.zig").Pair;
const Server = @import("server.zig").Server;

fn incoming(setup: *Pair) *Server {
    for (setup.server.reqresp.inbound) |*slot| if (slot.lifecycle.occupied()) return slot;
    unreachable;
}

test "reqresp complete incoming transfer deadline survives partial bytes and missing FIN" {
    for ([_]bool{ false, true }) |complete_body| {
        var setup: Pair = .{};
        try setup.init(.{}, .{ .progress_timeout_ms = 100, .host_timeout_ms = 1000 });
        defer setup.deinit();
        const stream = try setup.openRaw(.ping_v1);
        try setup.awaitRawSelection(stream, .ping_v1);
        setup.server_event_capacity = 0;
        const slot = incoming(&setup);
        const started = slot.lifecycle.started_ms;
        const deadline = started + 100;
        var storage: [codec.encodedLengthMax(8) + 1]u8 = undefined;
        const encoded = try codec.encodeRequest(&(@as([8]u8, @splat(0))), &storage);
        var sent: usize = 0;
        for ([_]u64{ 25, 50, 75, 99 }) |elapsed| {
            setup.pair.now.mono_ms = started + elapsed;
            const end = if (complete_body) encoded.len else sent + 1;
            if (end > sent) try std.testing.expectEqual(end - sent, try setup.pair.client.write(stream, encoded[sent..end], false));
            sent = end;
            try setup.pumpOnce();
            try std.testing.expect(slot.lifecycle.running());
            try std.testing.expectEqual(@as(?u64, deadline), slot.deadline(&setup.server.reqresp));
        }
        try std.testing.expect(slot.progress_ms > started);
        setup.pair.now.mono_ms = deadline;
        try setup.pumpOnce();
        try std.testing.expectEqual(rr.Failure.timeout, slot.lifecycle.terminalEvent().?.failed.reason);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.timeouts);
        try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.requests_served);
        for (0..3) |_| try setup.pumpOnce();
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.timeouts);
        setup.server_event_capacity = 16;
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(usize, 1), setup.serverEvents().len);
        try std.testing.expectEqual(rr.Failure.timeout, setup.serverEvents()[0].failed.reason);
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(u16, 0), setup.server.reqresp.active().inbound);
    }
}

test "reqresp incoming transfer completed at the boundary starts the host deadline" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 100, .host_timeout_ms = 1000 });
    defer setup.deinit();
    const stream = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(stream, .ping_v1);
    const slot = incoming(&setup);
    const started = slot.lifecycle.started_ms;
    var storage: [codec.encodedLengthMax(8) + 1]u8 = undefined;
    const encoded = try codec.encodeRequest(&(@as([8]u8, @splat(0))), &storage);
    setup.pair.now.mono_ms = started + 99;
    try std.testing.expectEqual(encoded.len, try setup.pair.client.write(stream, encoded, true));
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 1), setup.serverEvents().len);
    try std.testing.expect(setup.serverEvents()[0] == .request);
    const handle = setup.serverEvents()[0].request.request;
    try std.testing.expectEqual(@as(?u64, started + 1099), slot.deadline(&setup.server.reqresp));
    setup.pair.now.mono_ms = started + 100;
    try setup.pumpOnce();
    try std.testing.expect(slot.lifecycle.running());
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.timeouts);
    try std.testing.expect(setup.server.reqresp.finish(handle, setup.pair.now));
    for (0..20) |_| {
        try setup.pumpOnce();
        if (setup.serverEvents().len > 0) break;
    }
    try std.testing.expectEqual(@as(u32, 0), setup.serverEvents()[0].served.chunks);
    try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.requests_served);
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.error_responses_sent);
}

test "reqresp rejected wire requests retain diagnostics and count terminal outcomes once" {
    const Case = enum { varint, truncated, trailing };
    for (std.enums.values(Case)) |case| {
        var setup: Pair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const stream = try setup.openRaw(.ping_v1);
        try setup.awaitRawSelection(stream, .ping_v1);
        setup.server_event_capacity = 0;
        const slot = incoming(&setup);
        var storage: [codec.encodedLengthMax(8) + 1]u8 = undefined;
        const encoded = try codec.encodeRequest(&(@as([8]u8, @splat(0))), &storage);
        const bytes: []const u8 = switch (case) {
            .varint => &(@as([11]u8, @splat(0x80))),
            .truncated => encoded[0..3],
            .trailing => extra: {
                storage[encoded.len] = 0;
                break :extra storage[0 .. encoded.len + 1];
            },
        };
        const expected: codec.Error = switch (case) {
            .varint => error.VarintTooLong,
            .truncated => error.Truncated,
            .trailing => error.TooManyBytes,
        };
        try std.testing.expectEqual(bytes.len, try setup.pair.client.write(stream, bytes, true));
        for (0..20) |_| {
            try setup.pumpOnce();
            if (slot.lifecycle.terminalEvent() != null) break;
        }
        try std.testing.expectEqual(expected, slot.rejection.?);
        try std.testing.expectEqual(@as(u32, 0), slot.lifecycle.terminalEvent().?.served.chunks);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.malformed);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.error_responses_sent);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.requests_served);
        try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.failures);
        try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.protocol_counters[@intFromEnum(Protocol.ping_v1)].incoming_errors);
        for (0..3) |_| try setup.pumpOnce();
        setup.server_event_capacity = 16;
        try setup.pumpOnce();
        try std.testing.expect(setup.serverEvents()[0] == .served);
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(u16, 0), setup.server.reqresp.active().inbound);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.malformed);
        try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.error_responses_sent);
    }
}

test "reqresp malformed request remains visible when its error reply cannot be sent" {
    var quotas = @import("limiter.zig").defaultQuotas();
    quotas[@intFromEnum(Protocol.ping_v1)] = .{ .tokens = 1, .period_ms = 5000 };
    var setup: Pair = .{};
    try setup.init(.{}, .{ .quotas = quotas, .quota_timeout_ms = 100 });
    defer setup.deinit();
    const stream = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(stream, .ping_v1);
    setup.server_event_capacity = 0;
    const slot = incoming(&setup);
    try std.testing.expect(setup.server.reqresp.limiter.take(slot.lifecycle.conn, .ping_v1, 1, setup.pair.now.mono_ms));
    const bytes = [_]u8{0x80} ** 11;
    try std.testing.expectEqual(bytes.len, try setup.pair.client.write(stream, &bytes, true));
    for (0..20) |_| {
        try setup.pumpOnce();
        if (slot.state == .withheld) break;
    }
    try std.testing.expectEqual(.withheld, slot.state);
    try std.testing.expectEqual(error.VarintTooLong, slot.rejection.?);
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.malformed);
    setup.pair.advance(100);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expectEqual(rr.Failure.quota_timeout, slot.lifecycle.terminalEvent().?.failed.reason);
    try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.counters.malformed);
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.error_responses_sent);
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.requests_served);
    try std.testing.expectEqual(@as(u64, 1), setup.server.reqresp.protocol_counters[@intFromEnum(Protocol.ping_v1)].incoming_errors);
    try std.testing.expectEqual(@as(u64, 0), setup.server.reqresp.counters.timeouts);
}

test "reqresp router negotiation timeout contributes once to aggregate timeout counters" {
    var setup: Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.reqresp.request(&setup.pair.client, &setup.client.router, setup.handles.client, .ping_v1, &bytes, &sink, .{ .absolute_timeouts = .{ .negotiation_ms = 100 } }, setup.pair.now);
    setup.pair.advance(100);
    var outcomes: [1]@import("../router.zig").Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.router.pump(&setup.pair.client, setup.pair.now, &outcomes));
    try std.testing.expectEqual(.timeout, outcomes[0].result.failed);
    try std.testing.expect(setup.client.reqresp.negotiated(outcomes[0], setup.pair.now));
    try std.testing.expect(!setup.client.reqresp.negotiated(outcomes[0], setup.pair.now));
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.reqresp.pump(&setup.pair.client, &setup.client.router, setup.pair.now, .{ .control = &events }).control);
    try std.testing.expectEqual(handle, events[0].failed.request);
    try std.testing.expectEqual(rr.Failure.timeout, events[0].failed.reason);
    try std.testing.expectEqual(.negotiation, events[0].failed.phase.?);
    for (0..3) |_| _ = setup.client.reqresp.pump(&setup.pair.client, &setup.client.router, setup.pair.now, .{ .control = &events });
    try std.testing.expectEqual(@as(u64, 1), setup.client.reqresp.counters.timeouts);
    try std.testing.expectEqual(@as(u64, 1), setup.client.reqresp.counters.failures);
    try std.testing.expectEqual(@as(u64, 1), setup.client.reqresp.outgoing_error_reasons[@intFromEnum(rr.metrics.ErrorReason.REQUEST_ERROR_DIAL_TIMEOUT)]);
}
