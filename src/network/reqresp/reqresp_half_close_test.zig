const std = @import("std");
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const rr = @import("reqresp.zig");
const harness = @import("reqresp_test.zig");
const engine = @import("../quic/engine.zig");
const router = @import("../router.zig");

const Pair = harness.ReqRespPair;
const Request = struct { handle: rr.RequestHandle, remote: engine.StreamHandle };

fn negotiate(pair: *Pair, method: protocol.Protocol, bytes: []const u8, sink: []u8, options: rr.RequestOptions) !Request {
    const handle = try pair.client.request(&pair.pair.client, &pair.client_neg, pair.handles.client, method, bytes, sink, options, pair.pair.now);
    var remote: ?engine.StreamHandle = null;
    for (0..10) |_| {
        try pair.pair.pump();
        var events: [16]engine.Event = undefined;
        for (pair.pair.events(&pair.pair.server, &events)) |event| switch (event) {
            .stream_opened => |stream| try pair.server_neg.negotiator.acceptInbound(stream, &protocol.ids, pair.pair.now),
            else => {},
        };
        var outcomes: [8]router.Outcome = undefined;
        const clients = pair.client_neg.pump(&pair.pair.client, pair.pair.now, &outcomes);
        for (outcomes[0..clients]) |outcome| try std.testing.expect(pair.client.negotiated(outcome, pair.pair.now));
        const servers = pair.server_neg.pump(&pair.pair.server, pair.pair.now, &outcomes);
        for (outcomes[0..servers]) |outcome| switch (outcome.result) {
            .ready => remote = outcome.stream,
            else => return error.TestUnexpectedResult,
        };
        if (remote != null and pair.client.outbound[handle.index].state == .sending_request) break;
    }
    try std.testing.expect(remote != null);
    try std.testing.expectEqual(.sending_request, pair.client.outbound[handle.index].state);
    return .{ .handle = handle, .remote = remote.? };
}

fn pump(pair: *Pair) ![]const rr.Event {
    try pair.pair.pump();
    pair.client.cleanupPending(&pair.pair.client, &pair.client_neg);
    var activity: [128]engine.Handle = undefined;
    const count = pair.pair.client.driverView().takeActivity(&activity);
    for (activity[0..count]) |conn| pair.client.connectionActivity(conn);
    pair.client_count = pair.client.pump(&pair.pair.client, &pair.client_neg, pair.pair.now, &pair.client_events);
    return pair.clientEvents();
}

fn reply(pair: *Pair, request: Request, result: u8, bytes: []const u8, fin: bool) !void {
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(result, null, bytes, &wire);
    try std.testing.expectEqual(encoded.len, try pair.pair.server.write(request.remote, encoded, fin));
}

fn expectDone(pair: *Pair, request: Request, expected: []const u8) !void {
    var chunks: u32 = 0;
    var done = false;
    for (0..16) |_| {
        for (try pump(pair)) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, expected, chunk.bytes);
                chunks += 1;
                try std.testing.expect(pair.client.consume(chunk.request, pair.pair.now));
            },
            .done => |event_done| {
                try std.testing.expectEqual(@as(u32, 1), event_done.chunks);
                done = true;
            },
            .failed => |failed| {
                std.debug.print("unexpected failure {any} detail={s}\n", .{ failed, pair.client.outbound[request.handle.index].io.failure_detail });
                return error.TestUnexpectedResult;
            },
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(u32, 1), chunks);
    pair.client.cleanupPending(&pair.pair.client, &pair.client_neg);
    try std.testing.expect(pair.client.outboundSlot(request.handle) == null);
    try std.testing.expect(!pair.pair.client.registry.slots[pair.handles.client.index].table.matches(
        pair.client.outbound[request.handle.index].stream.slot,
        pair.client.outbound[request.handle.index].stream.id,
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
                if (stop) pair.pair.server.shutdown(request.remote, .read, 0);
                if (buffered) {
                    try pair.pair.pump();
                    const slot = &pair.client.outbound[request.handle.index];
                    const input = try slot.io.read(&pair.pair.client, slot.stream);
                    try std.testing.expect(input.bytes.len > 0 and input.fin);
                }
                try expectDone(&pair, request, response);
                try std.testing.expectEqual(@as(u64, @intFromBool(stop)), pair.client.protocol_counters[@intFromEnum(method)].request_write_stops);
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
    pair.pair.server.shutdown(request.remote, .read, 0);
    for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    const slot = &pair.client.outbound[request.handle.index];
    try std.testing.expectEqual(.awaiting, slot.state);
    try std.testing.expectEqual(@as(usize, 0), slot.request_ssz.len);
    try std.testing.expect(!slot.io.writing and slot.io.outbox.idle());
    pair.pair.advance(100);
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
                _ = try pair.pair.server.write(request.remote, &.{0}, true);
                break :value .{ .invalid_response = error.Truncated };
            },
            .reset => value: {
                pair.pair.server.shutdown(request.remote, .write, 7);
                break :value .stream_closed;
            },
        };
        pair.pair.server.shutdown(request.remote, .read, 0);
        try expectFailure(&pair, expected);
    }
}

test "reqresp half close without a response retains progress and absolute deadlines" {
    for ([_]bool{ false, true }) |absolute| {
        var pair: Pair = .{};
        try pair.init(.{ .outbound_max = 1, .inbound_max = 1, .progress_timeout_ms = 100 }, .{});
        defer pair.deinit();
        var sink: [25]u8 = undefined;
        const request = try negotiate(&pair, .metadata_v3, &.{}, &sink, if (absolute)
            .{ .absolute_timeouts = .{ .negotiation_ms = 200, .request_ms = 300, .response_ms = 100 } }
        else
            .{});
        pair.pair.server.shutdown(request.remote, .read, 0);
        for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
        try std.testing.expectEqual(.awaiting, pair.client.outbound[request.handle.index].state);
        pair.pair.advance(99);
        try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
        pair.pair.advance(1);
        try expectFailure(&pair, .timeout);
        try std.testing.expectEqual(@as(u64, 1), pair.client.outgoing_error_reasons[@intFromEnum(@import("metrics.zig").ErrorReason.REQUEST_ERROR_RESP_TIMEOUT)]);
    }
}

test "reqresp half close cancellation frees the only slot for a subsequent request" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    var sink: [25]u8 = undefined;
    const first = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    pair.pair.server.shutdown(first.remote, .read, 0);
    for (0..4) |_| try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    try std.testing.expect(pair.client.cancel(first.handle));
    try expectFailure(&pair, .cancelled);
    pair.client.cleanupPending(&pair.pair.client, &pair.client_neg);
    try std.testing.expectEqual(@as(usize, 0), (try pump(&pair)).len);
    const second = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    try std.testing.expectEqual(first.handle.index, second.handle.index);
    try std.testing.expect(second.handle.generation > first.handle.generation);
    const bytes = [_]u8{0} ** 25;
    try reply(&pair, second, 0, &bytes, true);
    pair.pair.server.shutdown(second.remote, .read, 0);
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
    pair.pair.server.shutdown(request.remote, .read, 0);
    const block = [_]u8{7} ** 4000;
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, harness.deneb_digest, &block, &wire);
    var chunks: u32 = 0;
    var done = false;
    for (0..2) |index| {
        try std.testing.expectEqual(encoded.len, try pair.pair.server.write(request.remote, encoded, index == 1));
        for (0..8) |_| {
            for (try pump(&pair)) |event| switch (event) {
                .chunk => |chunk| {
                    try std.testing.expectEqual(.deneb, chunk.fork.?);
                    try std.testing.expectEqualSlices(u8, &block, chunk.bytes);
                    chunks += 1;
                    try std.testing.expect(pair.client.consume(chunk.request, pair.pair.now));
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
    try std.testing.expectEqual(@as(u64, 1), pair.client.protocol_counters[@intFromEnum(protocol.Protocol.blocks_by_root_v2)].request_write_stops);
}

test "reqresp half close does not hide a retired stream without response EOF" {
    var pair: Pair = .{};
    try pair.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer pair.deinit();
    var sink: [25]u8 = undefined;
    const request = try negotiate(&pair, .metadata_v3, &.{}, &sink, .{});
    pair.pair.client.closeStream(pair.client.outbound[request.handle.index].stream, 0);
    try expectFailure(&pair, .stream_closed);
    try std.testing.expectEqual(@as(u64, 0), pair.client.protocol_counters[@intFromEnum(protocol.Protocol.metadata_v3)].request_write_stops);
}
