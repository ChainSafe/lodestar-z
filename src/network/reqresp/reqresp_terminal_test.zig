const std = @import("std");
const rr = @import("reqresp.zig");
const codec = @import("codec.zig");
const Protocol = @import("protocol.zig").Protocol;
const Pair = @import("test_pair.zig").Pair;
const Server = @import("server.zig").Server;

fn incoming(setup: *Pair) *Server {
    for (setup.shared.server.reqresp.inbound) |*slot| if (slot.request.occupied()) return slot;
    unreachable;
}

test "reqresp complete incoming transfer deadline survives partial bytes and missing FIN" {
    for ([_]Protocol{ .ping_v1, .blocks_by_root_v2 }) |which| {
        for ([_]bool{ false, true }) |complete_body| {
            var setup: Pair = .{};
            try setup.init(.{}, .{ .progress_timeout_ms = 100, .host_timeout_ms = 1000 });
            defer setup.deinit();
            const stream = try setup.openRaw(which);
            try setup.awaitRawSelection(stream, which);
            setup.server_event_capacity = 0;
            const slot = incoming(&setup);
            const started = slot.request.started_ms;
            const deadline = started + 100;
            var storage: [codec.encodedLengthMax(32) + 1]u8 = undefined;
            const body = [_]u8{0} ** 32;
            const encoded = try codec.encodeRequest(body[0..if (which == .ping_v1) 8 else 32], &storage);
            var sent: usize = 0;
            for ([_]u64{ 25, 50, 75, 99 }) |elapsed| {
                setup.shared.pair.now.mono_ms = started + elapsed;
                const end = if (complete_body) encoded.len else sent + 1;
                if (end > sent) try std.testing.expectEqual(end - sent, try setup.shared.pair.client.write(stream, encoded[sent..end], false));
                sent = end;
                try setup.pumpOnce();
                try std.testing.expect(slot.request.running());
                try std.testing.expectEqual(@as(?u64, deadline), slot.deadline(&setup.shared.server.reqresp));
            }
            try std.testing.expect(slot.progress_ms > started);
            setup.shared.pair.now.mono_ms = deadline;
            try setup.pumpOnce();
            try std.testing.expectEqual(rr.Failure.timeout, slot.request.terminalEvent().?.failed.reason);
            for (0..3) |_| try setup.pumpOnce();
            setup.server_event_capacity = 16;
            try setup.pumpOnce();
            try std.testing.expectEqual(@as(usize, 1), setup.serverEvents().len);
            try std.testing.expectEqual(rr.Failure.timeout, setup.serverEvents()[0].failed.reason);
            const fault = setup.shared.server.reqresp.peerFault(setup.serverEvents()[0]);
            if (which.isControl()) {
                try std.testing.expect(fault == null);
            } else {
                try std.testing.expectEqual(.non_completion, fault.?.kind);
            }
            try setup.pumpOnce();
            try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.active().inbound);
        }
    }
}

test "reqresp incoming transfer completed at the boundary starts the host deadline" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 100, .host_timeout_ms = 1000 });
    defer setup.deinit();
    const stream = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(stream, .ping_v1);
    const slot = incoming(&setup);
    const started = slot.request.started_ms;
    var storage: [codec.encodedLengthMax(8) + 1]u8 = undefined;
    const encoded = try codec.encodeRequest(&(@as([8]u8, @splat(0))), &storage);
    setup.shared.pair.now.mono_ms = started + 99;
    try std.testing.expectEqual(encoded.len, try setup.shared.pair.client.write(stream, encoded, true));
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 1), setup.serverEvents().len);
    try std.testing.expect(setup.serverEvents()[0] == .request);
    const handle = setup.serverEvents()[0].request.request;
    try std.testing.expectEqual(@as(?u64, started + 1099), slot.deadline(&setup.shared.server.reqresp));
    setup.shared.pair.now.mono_ms = started + 100;
    try setup.pumpOnce();
    try std.testing.expect(slot.request.running());
    try std.testing.expect(setup.shared.server.reqresp.finish(handle, setup.shared.pair.now));
    for (0..20) |_| {
        try setup.pumpOnce();
        if (setup.serverEvents().len > 0) break;
    }
    try std.testing.expectEqual(@as(u32, 0), setup.serverEvents()[0].served.chunks);
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
        try std.testing.expectEqual(bytes.len, try setup.shared.pair.client.write(stream, bytes, true));
        for (0..20) |_| {
            try setup.pumpOnce();
            if (slot.request.terminalEvent() != null) break;
        }
        try std.testing.expectEqual(expected, slot.rejection.?);
        try std.testing.expectEqual(@as(u32, 0), slot.request.terminalEvent().?.served.chunks);
        try std.testing.expectEqual(@as(u64, 0), setup.shared.server.reqresp.protocol_counters[@intFromEnum(Protocol.ping_v1)].incoming_errors);
        for (0..3) |_| try setup.pumpOnce();
        setup.server_event_capacity = 16;
        try setup.pumpOnce();
        try std.testing.expect(setup.serverEvents()[0] == .served);
        const fault = setup.shared.server.reqresp.peerFault(setup.serverEvents()[0]).?;
        try std.testing.expectEqual(.protocol, fault.kind);
        try std.testing.expect(fault.identity.eql(&slot.identity));
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.active().inbound);
    }
}

test "reqresp router negotiation timeout contributes once to aggregate timeout counters" {
    var setup: Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, .ping_v1, &bytes, &sink, .{ .absolute_timeouts = .{ .negotiation_ms = 100 } }, setup.shared.pair.now);
    setup.shared.pair.advance(100);
    var outcomes: [1]@import("../router.zig").Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.router.pump(&setup.shared.pair.client, setup.shared.pair.now, &outcomes));
    try std.testing.expectEqual(.timeout, outcomes[0].result.failed);
    try std.testing.expect(setup.shared.client.reqresp.negotiated(&setup.shared.pair.client, outcomes[0], setup.shared.pair.now));
    try std.testing.expect(!setup.shared.client.reqresp.negotiated(&setup.shared.pair.client, outcomes[0], setup.shared.pair.now));
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control);
    try std.testing.expectEqual(handle, events[0].failed.request);
    try std.testing.expectEqual(rr.Failure.timeout, events[0].failed.reason);
    try std.testing.expectEqual(.negotiation, events[0].failed.phase.?);
    for (0..3) |_| _ = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events });
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.reqresp.outgoing_error_reasons[@intFromEnum(rr.metrics.ErrorReason.REQUEST_ERROR_DIAL_TIMEOUT)]);
}
