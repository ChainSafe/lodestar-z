const std = @import("std");
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const rr = @import("reqresp.zig");
const harness = @import("test_pair.zig");
const engine = @import("../quic/engine.zig");
const router = @import("../router.zig");

const Pair = harness.Pair;
const Request = struct { handle: rr.RequestHandle, remote: engine.StreamHandle };

fn negotiate(pair: *Pair, method: protocol.Protocol, bytes: []const u8, sink: []u8, options: rr.RequestOptions) !Request {
    const handle = try pair.shared.client.reqresp.request(&pair.shared.pair.client, &pair.shared.client.router, pair.shared.handles.client, method, bytes, sink, options, pair.shared.pair.now);
    var remote: ?engine.StreamHandle = null;
    for (0..10) |_| {
        try pair.shared.pair.pump();
        var events: [16]engine.Event = undefined;
        for (pair.shared.pair.events(&pair.shared.pair.server, &events)) |event| switch (event) {
            .stream_opened => |stream| try pair.shared.server.router.negotiator.acceptInbound(stream, pair.shared.pair.now),
            else => {},
        };
        var outcomes: [8]router.Outcome = undefined;
        const clients = pair.shared.client.router.pump(&pair.shared.pair.client, pair.shared.pair.now, &outcomes);
        for (outcomes[0..clients]) |outcome| try std.testing.expect(pair.shared.client.reqresp.negotiated(outcome, pair.shared.pair.now));
        const servers = pair.shared.server.router.pump(&pair.shared.pair.server, pair.shared.pair.now, &outcomes);
        for (outcomes[0..servers]) |outcome| switch (outcome.result) {
            .ready => remote = outcome.stream,
            else => return error.TestUnexpectedResult,
        };
        if (remote != null and pair.shared.client.reqresp.outbound[handle.index].phase == .request) break;
    }
    try std.testing.expect(remote != null);
    try std.testing.expectEqual(.request, pair.shared.client.reqresp.outbound[handle.index].phase);
    return .{ .handle = handle, .remote = remote.? };
}

fn pump(pair: *Pair) ![]const rr.Event {
    try pair.shared.pair.pump();
    pair.shared.client.reqresp.cleanupPending(&pair.shared.pair.client, &pair.shared.client.router);
    var activity: [128]engine.Handle = undefined;
    const count = pair.shared.pair.client.takeActivity(&activity);
    for (activity[0..count]) |conn| pair.shared.client.reqresp.connectionActivity(conn);
    const counts = pair.shared.client.reqresp.pump(&pair.shared.pair.client, &pair.shared.client.router, pair.shared.pair.now, .{ .application = pair.client_events[0..16], .control = pair.client_events[16..] });
    std.mem.copyForwards(rr.Event, pair.client_events[counts.application..], pair.client_events[16..][0..counts.control]);
    pair.client_count = counts.application + counts.control;
    return pair.clientEvents();
}

fn reply(pair: *Pair, request: Request, result: u8, bytes: []const u8, fin: bool) !void {
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(result, null, bytes, &wire);
    try std.testing.expectEqual(encoded.len, try pair.shared.pair.server.write(request.remote, encoded, fin));
}

fn expectDone(pair: *Pair, request: Request, expected: []const u8) !void {
    var chunks: u32 = 0;
    var done = false;
    for (0..16) |_| {
        for (try pump(pair)) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, expected, chunk.bytes);
                chunks += 1;
                try std.testing.expect(pair.shared.client.reqresp.consume(chunk.request));
            },
            .done => |event_done| {
                try std.testing.expectEqual(@as(u32, 1), event_done.chunks);
                done = true;
            },
            .failed => |failed| {
                std.debug.print("unexpected failure {any} detail={s}\n", .{ failed, pair.shared.client.reqresp.outbound[request.handle.index].request.failure_detail });
                return error.TestUnexpectedResult;
            },
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(u32, 1), chunks);
    pair.shared.client.reqresp.cleanupPending(&pair.shared.pair.client, &pair.shared.client.router);
    try std.testing.expect(pair.shared.client.reqresp.outboundSlot(request.handle) == null);
    try std.testing.expect(!pair.shared.pair.client.registry.slots[pair.shared.handles.client.index].table.matches(
        pair.shared.client.reqresp.outbound[request.handle.index].request.stream.slot,
        pair.shared.client.reqresp.outbound[request.handle.index].request.stream.id,
    ));
}

fn expectFailure(pair: *Pair, expected: rr.Failure) !void {
    var failure: ?rr.Failure = null;
    for (0..8) |_| {
        for (try pump(pair)) |event| switch (event) {
            .failed => |failed| failure = failed.reason,
            .chunk, .done => return error.TestUnexpectedResult,
            else => {},
        };
        if (failure != null) break;
    }
    try std.testing.expect(failure != null);
    try std.testing.expectEqualDeep(expected, failure.?);
}

test "reqresp recovers only complete Goodbye bytes retained by a closed authenticated connection" {
    for ([_]bool{ false, true }) |truncated| {
        var pair: Pair = .{};
        const quotas = @import("admission_fixture.zig").quotas(100, 1000);
        try pair.init(.{}, .{ .admission = .{ .policy = @import("policy_fixture.zig").config(), .limits = .{ .identities = 2, .peer = quotas, .global = quotas } } });
        defer pair.deinit();
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, 129, .little);
        var sink: [8]u8 = undefined;
        const request = try negotiate(&pair, .goodbye_v1, &payload, &sink, .{});
        _ = try pair.shared.server.reqresp.accept(&pair.shared.pair.server, request.remote, .{ .protocol = .{ .reqresp = .goodbye_v1 }, .leftover = &.{}, .fin = false }, pair.shared.pair.now);
        var wire: [128]u8 = undefined;
        const encoded = try codec.encodeRequest(&payload, &wire);
        const bytes = encoded[0 .. encoded.len - @intFromBool(truncated)];
        try std.testing.expectEqual(bytes.len, try pair.shared.pair.client.write(pair.shared.client.reqresp.outbound[request.handle.index].request.stream, bytes, true));
        try pair.shared.pair.pump();
        try std.testing.expect(pair.shared.pair.client.close(pair.shared.handles.client, 0));
        try pair.shared.pair.pump();
        try std.testing.expectEqual(.closed, pair.shared.pair.server.registry.slots[pair.shared.handles.server.index].state);
        const result = pair.shared.server.reqresp.closingGoodbye(&pair.shared.pair.server, pair.shared.handles.server, pair.shared.pair.now);
        try std.testing.expectEqual(if (truncated) @as(?u64, null) else @as(?u64, 129), result);
        try std.testing.expectEqual(@as(u64, @intFromBool(!truncated)), pair.shared.server.reqresp.counters.goodbyes_recovered_on_close);
        try std.testing.expectEqual(@as(u64, @intFromBool(truncated)), pair.shared.server.reqresp.counters.goodbyes_incomplete_on_close);
        try std.testing.expect(pair.shared.server.reqresp.closingGoodbye(&pair.shared.pair.server, pair.shared.handles.server, pair.shared.pair.now) == null);
        pair.shared.server.reqresp.connectionClosed(pair.shared.handles.server);
    }
}

test "reqresp response FIN stops complete written chunks but do not hide an empty stopped response" {
    for ([_]bool{ false, true }) |send_chunk| {
        var pair: Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        const payload = [_]u8{7} ** 8;
        var sink: [8]u8 = undefined;
        const request = try pair.shared.client.reqresp.request(&pair.shared.pair.client, &pair.shared.client.router, pair.shared.handles.client, .ping_v1, &payload, &sink, .{}, pair.shared.pair.now);
        var incoming: ?rr.RequestHandle = null;
        var sent = false;
        for (0..32) |_| {
            try pair.pumpOnce();
            for (pair.serverEvents()) |event| switch (event) {
                .request => |value| {
                    incoming = value.request;
                    if (send_chunk) try pair.shared.server.reqresp.respond(value.request, &payload, null, pair.shared.pair.now);
                },
                .chunk_sent => sent = true,
                .failed => return error.TestUnexpectedResult,
                else => {},
            };
            if (incoming != null and (!send_chunk or sent)) break;
        }
        try std.testing.expect(incoming != null);
        const stream = pair.shared.client.reqresp.outbound[request.index].request.stream;
        pair.shared.pair.client.shutdown(stream, .read, 0);
        try pair.shared.pair.pump();
        try std.testing.expect(pair.shared.server.reqresp.finish(incoming.?, pair.shared.pair.now));
        var terminal = false;
        for (0..8) |_| {
            var events: [8]rr.Event = undefined;
            const count = pair.shared.server.reqresp.pump(&pair.shared.pair.server, &pair.shared.server.router, pair.shared.pair.now, .{ .control = &events }).control;
            for (events[0..count]) |event| switch (event) {
                .served => |value| {
                    try std.testing.expect(send_chunk);
                    try std.testing.expectEqual(@as(u32, 1), value.chunks);
                    terminal = true;
                },
                .failed => |value| {
                    try std.testing.expect(!send_chunk);
                    try std.testing.expectEqual(rr.Failure.stream_closed, value.reason);
                    terminal = true;
                },
                else => {},
            };
            if (terminal) break;
        }
        try std.testing.expect(terminal);
        try std.testing.expectEqual(@as(u64, @intFromBool(send_chunk)), pair.shared.server.reqresp.protocol_counters[@intFromEnum(protocol.Protocol.ping_v1)].response_finish_stops);
    }
}

test "reqresp dispatches a complete Goodbye before FIN and keeps other request framing strict" {
    const Case = enum { goodbye, ping, truncated, trailing };
    for (std.enums.values(Case)) |case| {
        var pair: Pair = .{};
        try pair.init(.{ .outbound_max = 1 }, .{ .inbound_max = 1 });
        defer pair.deinit();
        const method: protocol.Protocol = if (case == .ping) .ping_v1 else .goodbye_v1;
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, 129, .little);
        var sink: [8]u8 = undefined;
        const request = try negotiate(&pair, method, &payload, &sink, .{});
        _ = try pair.shared.server.reqresp.accept(&pair.shared.pair.server, request.remote, .{ .protocol = .{ .reqresp = method }, .leftover = &.{}, .fin = false }, pair.shared.pair.now);
        const local = pair.shared.client.reqresp.outbound[request.handle.index].request.stream;
        var wire: [128]u8 = undefined;
        const encoded = try codec.encodeRequest(&payload, &wire);
        var len = encoded.len;
        if (case == .truncated) len -= 1;
        if (case == .trailing) {
            wire[len] = 0;
            len += 1;
        }
        try std.testing.expectEqual(len, try pair.shared.pair.client.write(local, wire[0..len], false));
        var requests: usize = 0;
        for (0..8) |_| {
            try pair.shared.pair.pump();
            pair.shared.server.reqresp.connectionActivity(pair.shared.handles.server);
            const count = pair.shared.server.reqresp.pump(&pair.shared.pair.server, &pair.shared.server.router, pair.shared.pair.now, .{ .control = &pair.server_events }).control;
            for (pair.server_events[0..count]) |event| if (event == .request) {
                try std.testing.expectEqualSlices(u8, &payload, event.request.bytes);
                requests += 1;
            };
        }
        try std.testing.expectEqual(@as(usize, @intFromBool(case == .goodbye)), requests);
        if (case == .trailing) {
            try std.testing.expectError(error.StreamStopped, pair.shared.pair.client.write(local, &.{}, true));
        } else {
            _ = try pair.shared.pair.client.write(local, &.{}, true);
        }
        for (0..8) |_| {
            try pair.shared.pair.pump();
            pair.shared.server.reqresp.connectionActivity(pair.shared.handles.server);
            const count = pair.shared.server.reqresp.pump(&pair.shared.pair.server, &pair.shared.server.router, pair.shared.pair.now, .{ .control = &pair.server_events }).control;
            for (pair.server_events[0..count]) |event| if (event == .request) {
                try std.testing.expectEqualSlices(u8, &payload, event.request.bytes);
                requests += 1;
            };
        }
        try std.testing.expectEqual(@as(usize, @intFromBool(case == .goodbye or case == .ping)), requests);
    }
}

test "reqresp half close preserves early metadata and nonempty request responses" {
    for ([_]protocol.Protocol{ .metadata_v1, .metadata_v2, .metadata_v3, .ping_v1 }) |method| {
        for ([_]bool{ false, true }) |stop| {
            for ([_]bool{ false, true }) |buffered| {
                errdefer std.debug.print("half close case method={s} stop={any} buffered={any}\n", .{ @tagName(method), stop, buffered });
                var pair: Pair = .{};
                try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
                defer pair.deinit();
                const bytes = [_]u8{7} ** 25;
                var sink: [25]u8 = undefined;
                const request = try negotiate(&pair, method, bytes[0..method.info().request_min], &sink, .{});
                const response = bytes[0..method.info().response_min];
                try reply(&pair, request, 0, response, true);
                if (stop) pair.shared.pair.server.shutdown(request.remote, .read, 0);
                if (buffered) {
                    try pair.shared.pair.pump();
                    const slot = &pair.shared.client.reqresp.outbound[request.handle.index];
                    const input = try slot.request.io.read(&pair.shared.pair.client, slot.request.stream);
                    try std.testing.expect(input.bytes.len > 0 and input.fin);
                }
                try expectDone(&pair, request, response);
                try std.testing.expectEqual(@as(u64, @intFromBool(stop)), pair.shared.client.reqresp.protocol_counters[@intFromEnum(method)].request_write_stops);
            }
        }
    }
}

test "reqresp half close accepts a later response and releases the request buffer" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    const bytes = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    const request = try negotiate(&pair, .ping_v1, &bytes, &sink, .{});
    pair.shared.pair.server.shutdown(request.remote, .read, 0);
    for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    const slot = &pair.shared.client.reqresp.outbound[request.handle.index];
    try std.testing.expectEqual(.response, slot.phase);
    try std.testing.expectEqual(@as(usize, 0), slot.request.io.payload.len);
    try std.testing.expect(!slot.request.io.writing and slot.request.io.outbox.idle());
    pair.shared.pair.advance(100);
    try reply(&pair, request, 0, &bytes, true);
    try expectDone(&pair, request, &bytes);
}

test "reqresp half close still reports peer errors malformed responses and response resets" {
    const Case = enum { peer_error, malformed, truncated, reset };
    for (std.enums.values(Case)) |case| {
        var pair: Pair = .{};
        try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
        defer pair.deinit();
        var sink: [25]u8 = undefined;
        const request = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
        const expected: rr.Failure = switch (case) {
            .peer_error => value: {
                try reply(&pair, request, 2, "busy", true);
                break :value .{ .peer_error = .{ .code = 2, .message_len = 4 } };
            },
            .malformed => value: {
                try reply(&pair, request, 0, "short", true);
                break :value .{ .invalid_response = error.LengthOutOfBounds };
            },
            .truncated => value: {
                _ = try pair.shared.pair.server.write(request.remote, &.{0}, true);
                break :value .{ .invalid_response = error.Truncated };
            },
            .reset => value: {
                pair.shared.pair.server.shutdown(request.remote, .write, 7);
                break :value .stream_closed;
            },
        };
        pair.shared.pair.server.shutdown(request.remote, .read, 0);
        try expectFailure(&pair, expected);
    }
}

test "reqresp half close without a response retains the absolute response deadline" {
    for ([_]u64{ 100, 10_000 }) |duration| {
        var pair: Pair = .{};
        try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
        defer pair.deinit();
        var sink: [25]u8 = undefined;
        const request = try negotiate(&pair, .metadata_v3, &.{}, &sink, if (duration == 100)
            .{ .absolute_timeouts = .{ .response_ms = duration } }
        else
            .{});
        pair.shared.pair.server.shutdown(request.remote, .read, 0);
        for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
        try std.testing.expectEqual(.response, pair.shared.client.reqresp.outbound[request.handle.index].phase);
        pair.shared.pair.advance(duration - 1);
        try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
        pair.shared.pair.advance(1);
        try expectFailure(&pair, .timeout);
        try std.testing.expectEqual(@as(u64, 1), pair.shared.client.reqresp.outgoing_error_reasons[@intFromEnum(@import("metrics.zig").ErrorReason.REQUEST_ERROR_RESP_TIMEOUT)]);
    }
}

test "reqresp half close cancellation frees the only slot for a subsequent request" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    var sink: [25]u8 = undefined;
    const first = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    pair.shared.pair.server.shutdown(first.remote, .read, 0);
    for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    try std.testing.expect(pair.shared.client.reqresp.cancel(first.handle));
    try expectFailure(&pair, .cancelled);
    pair.shared.client.reqresp.cleanupPending(&pair.shared.pair.client, &pair.shared.client.router);
    try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    const second = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    try std.testing.expectEqual(first.handle.index, second.handle.index);
    try std.testing.expect(second.handle.generation > first.handle.generation);
    const bytes = [_]u8{0} ** 25;
    try reply(&pair, second, 0, &bytes, true);
    pair.shared.pair.server.shutdown(second.remote, .read, 0);
    try expectDone(&pair, second, &bytes);
}

test "reqresp half close preserves context and successive response chunks" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    const sink = try std.testing.allocator.alloc(u8, protocol.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const roots = [_]u8{7} ** 64;
    const request = try negotiate(&pair, .blocks_by_root_v2, &roots, sink, .{});
    pair.shared.pair.server.shutdown(request.remote, .read, 0);
    const block = [_]u8{7} ** 4000;
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, harness.deneb_digest, &block, &wire);
    var chunks: u32 = 0;
    var done = false;
    for (0..2) |index| {
        try std.testing.expectEqual(encoded.len, try pair.shared.pair.server.write(request.remote, encoded, index == 1));
        for (0..8) |_| {
            for (try pump(&pair)) |event| switch (event) {
                .chunk => |chunk| {
                    try std.testing.expectEqual(.deneb, chunk.fork.?);
                    try std.testing.expectEqualSlices(u8, &block, chunk.bytes);
                    chunks += 1;
                    try std.testing.expect(pair.shared.client.reqresp.consume(chunk.request));
                },
                .failed => return error.TestUnexpectedResult,
                else => {},
            };
            if (chunks == index + 1) break;
        }
        try std.testing.expectEqual(@as(u32, @intCast(index + 1)), chunks);
    }
    for (0..8) |_| {
        for (try pump(&pair)) |event| switch (event) {
            .done => |finished| {
                try std.testing.expectEqual(@as(u32, 2), finished.chunks);
                done = true;
            },
            .chunk, .failed => return error.TestUnexpectedResult,
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(u64, 1), pair.shared.client.reqresp.protocol_counters[@intFromEnum(protocol.Protocol.blocks_by_root_v2)].request_write_stops);
}

test "reqresp half close does not hide a retired stream without response EOF" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    var sink: [25]u8 = undefined;
    const request = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    pair.shared.pair.client.closeStream(pair.shared.client.reqresp.outbound[request.handle.index].request.stream, 0);
    try expectFailure(&pair, .stream_closed);
    try std.testing.expectEqual(@as(u64, 0), pair.shared.client.reqresp.protocol_counters[@intFromEnum(protocol.Protocol.metadata_v3)].request_write_stops);
}
