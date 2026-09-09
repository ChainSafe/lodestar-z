const std = @import("std");
const ct = @import("consensus_types");
const codec = @import("codec.zig");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");
const harness = @import("reqresp_test.zig");
const engine_mod = @import("../quic/engine.zig");
const multistream = @import("../wire/multistream.zig");
const negotiate = @import("../router.zig");

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const ReqRespPair = harness.ReqRespPair;
const deneb_digest = harness.deneb_digest;
const fulu_digest = harness.fulu_digest;
const statusBytes = harness.statusBytes;

fn requestStatus(setup: *ReqRespPair, request_ssz: *[ct.phase0.Status.fixed_size]u8, sink: []u8) !reqresp.RequestHandle {
    request_ssz.* = statusBytes(5);
    return setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .status_v1,
        request_ssz,
        sink,
        .{},
        setup.pair.now,
    );
}

fn requestBlocks(setup: *ReqRespPair, request_ssz: *[24]u8, count: u64, sink: []u8) !reqresp.RequestHandle {
    const Request = ct.phase0.BeaconBlocksByRangeRequest;
    const request = Request.Type{ .start_slot = 1, .count = count, .step = 1 };
    _ = Request.serializeIntoBytes(&request, request_ssz);
    return setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .blocks_by_range_v2,
        request_ssz,
        sink,
        .{},
        setup.pair.now,
    );
}

fn firstFailure(events: []const Event) ?reqresp.Failure {
    for (events) |event| {
        if (event == .failed) return event.failed.reason;
    }
    return null;
}

fn waitForRequest(setup: *ReqRespPair) !void {
    var request_seen = false;
    var rounds: usize = 0;
    while (rounds < 10 and !request_seen) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) request_seen = true;
        }
    }
    try std.testing.expect(request_seen);
}

test "reqresp fails a request whose peer stops making progress" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .progress_timeout_ms = 2_000 }, .{ .progress_timeout_ms = 2_000, .host_timeout_ms = 2_000 });
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_1: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_1, &sink);
    try waitForRequest(&setup);

    setup.pair.advance(1_000);
    try setup.pumpOnce();
    try std.testing.expect(firstFailure(setup.clientEvents()) == null);
    setup.pair.advance(1_500);
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
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.timeouts);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
    const counts = &setup.client.protocol_counters[@intFromEnum(Protocol.status_v1)];
    try std.testing.expectEqual(@as(u64, 1), counts.outgoing_time.count);
    try std.testing.expect(counts.outgoing_time.sum_ms >= 2500);
    try std.testing.expectEqual(@as(u64, 1), setup.client.outgoing_error_reasons[@intFromEnum(reqresp.metrics.ErrorReason.REQUEST_ERROR_RESP_TIMEOUT)]);
}

test "reqresp delivers error chunks with the peer's code and message" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_2: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_2, &sink);
    var client_failure: ?reqresp.Failure = null;
    var served: ?u32 = null;
    var rounds: usize = 0;
    while (rounds < 30 and (client_failure == null or served == null)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respondError(incoming.request, 3, "unavailable", setup.pair.now);
                try std.testing.expectError(
                    error.Busy,
                    setup.server.respond(incoming.request, &sink, null, setup.pair.now),
                );
            },
            .served => |finished| served = finished.chunks,
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .failed => |failure| {
                client_failure = failure.reason;
                try std.testing.expectEqualStrings(
                    "unavailable",
                    setup.client.errorMessage(failure.request),
                );
            },
            .chunk => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(?u32, 0), served);
    const reason = client_failure orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 3), reason.peer_error.code);
    try std.testing.expectEqual(@as(u8, 11), reason.peer_error.message_len);

    var request_storage_3: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_3, &sink);
    client_failure = null;
    rounds = 0;
    while (rounds < 30 and client_failure == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respondError(incoming.request, 5, "", setup.pair.now);
            },
            else => {},
        };
        if (firstFailure(setup.clientEvents())) |failure| client_failure = failure;
    }
    const reserved = client_failure orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(codec.Error.ReservedResult, reserved.invalid_response);
}

test "reqresp finishes after the last allowed chunk without waiting for the peer" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_4: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_4, &sink);
    const reply = statusBytes(2);
    var done = false;
    var rounds: usize = 0;
    while (rounds < 30 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &reply, null, setup.pair.now);
            },
            .chunk_sent => |progress| {
                try std.testing.expectError(
                    error.TooManyChunks,
                    setup.server.respond(progress.request, &reply, null, setup.pair.now),
                );
            },
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now)),
            .done => |finished| {
                try std.testing.expectEqual(@as(u32, 1), finished.chunks);
                done = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(u16, 1), setup.server.active().inbound);
}

test "reqresp fails a response whose context bytes name an unknown fork" {
    var setup: ReqRespPair = .{};
    const only_deneb = [_]reqresp.ForkEntry{.{ .digest = deneb_digest, .fork = .deneb }};
    try setup.init(.{ .forks = &only_deneb }, .{});
    defer setup.deinit();

    const size = Protocol.blocks_by_range_v2.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(sink);
    var request_storage_5: [24]u8 = undefined;
    _ = try requestBlocks(&setup, &request_storage_5, 1, sink);
    const block = [_]u8{7} ** 4_000;
    var failure: ?reqresp.Failure = null;
    var rounds: usize = 0;
    while (rounds < 40 and failure == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &block, .{ .digest = fulu_digest, .fork = .fulu }, setup.pair.now);
            },
            .chunk_sent => |progress| try std.testing.expect(setup.server.finish(progress.request, setup.pair.now)),
            else => {},
        };
        if (firstFailure(setup.clientEvents())) |reason| failure = reason;
    }
    const reason = failure orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(fulu_digest, reason.unknown_context);
}

test "reqresp bounds concurrent requests per protocol on both sides" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const size = Protocol.blocks_by_range_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 3 * size);
    defer std.testing.allocator.free(sinks);
    var request_storage_6: [24]u8 = undefined;
    const first = try requestBlocks(&setup, &request_storage_6, 1, sinks[0..size]);
    var request_storage_7: [24]u8 = undefined;
    _ = try requestBlocks(&setup, &request_storage_7, 1, sinks[size .. 2 * size]);
    var request_storage_8: [24]u8 = undefined;
    const third = requestBlocks(&setup, &request_storage_8, 1, sinks[2 * size ..]);
    try std.testing.expectError(error.TooManyRequests, third);
    var pings: [8]u8 = undefined;
    _ = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .ping_v1,
        &[_]u8{1} ** 8,
        &pings,
        .{},
        setup.pair.now,
    );

    _ = try setup.client_neg.beginOutbound(
        &setup.pair.client,
        setup.handles.client,
        .{ .reqresp = .blocks_by_range_v2 },
        setup.pair.now,
    );
    var over_limit = false;
    var served_first = false;
    var rounds: usize = 0;
    while (rounds < 40 and !(over_limit and served_first)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .over_limit => |excess| {
                try std.testing.expectEqual(Protocol.blocks_by_range_v2, excess.protocol);
                over_limit = true;
            },
            .request => |incoming| {
                if (incoming.protocol == .blocks_by_range_v2 and !served_first) {
                    try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
                    served_first = true;
                }
            },
            else => {},
        };
    }
    try std.testing.expect(over_limit);
    try std.testing.expect(setup.unclaimed >= 1);
    var done = false;
    rounds = 0;
    while (rounds < 40 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| {
            if (event == .done and std.meta.eql(event.done.request, first)) done = true;
        }
    }
    try std.testing.expect(done);
    try setup.pumpOnce();
    var request_storage_9: [24]u8 = undefined;
    _ = try requestBlocks(&setup, &request_storage_9, 1, sinks[2 * size ..]);
}

test "reqresp withholds chunks while the peer's bucket is empty" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.ping_v1)] = .{ .tokens = 1, .period_ms = 3_000 };
    var setup: ReqRespPair = .{};
    try setup.init(.{ .quotas = quotas }, .{ .quotas = quotas });
    defer setup.deinit();

    var sinks: [2][8]u8 = undefined;
    const ping = [_]u8{9} ** 8;
    for (&sinks) |*sink| {
        _ = try setup.client.request(
            &setup.pair.client,
            &setup.client_neg,
            setup.handles.client,
            .ping_v1,
            &ping,
            sink,
            .{},
            setup.pair.now,
        );
    }
    var completed: u32 = 0;
    var rounds: usize = 0;
    while (rounds < 20) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &ping, null, setup.pair.now);
                try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
            },
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now)),
            .done => completed += 1,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(u32, 1), completed);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.withheld_chunks);

    const waiting = setup.server.resourceSnapshot();
    setup.server.options.work_per_pump_max = 1;
    _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    const eligible = setup.server.limiter.nextToken(setup.handles.server, .ping_v1, setup.pair.now.mono_ms);
    try std.testing.expect(eligible.? > setup.pair.now.mono_ms);
    try std.testing.expectEqual(eligible, setup.server.nextWakeup(setup.pair.now, 1));
    try std.testing.expectEqual(@as(usize, 1), waiting.withheld_chunks);
    try std.testing.expect(waiting.oldest_withheld_age_ms != null);
    setup.pair.advance(3_000);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 1));
    setup.server.options.work_per_pump_max = 32;
    rounds = 0;
    while (rounds < 20 and completed < 2) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now)),
            .done => completed += 1,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(u32, 2), completed);
    try std.testing.expect(setup.server.counters.withheld_ms_total >= 3_000);
    try std.testing.expectEqual(@as(usize, 0), setup.server.resourceSnapshot().withheld_chunks);
    try std.testing.expectEqual(@as(?u64, null), setup.server.resourceSnapshot().oldest_withheld_age_ms);
    try std.testing.expectEqual(@as(usize, 1), waiting.withheld_chunks);
}

test "reqresp holds the next chunk until the host consumes the previous one" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const size = Protocol.blocks_by_range_v2.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(sink);
    var request_storage_10: [24]u8 = undefined;
    _ = try requestBlocks(&setup, &request_storage_10, 2, sink);
    const blocks = [2][3_000]u8{ [_]u8{1} ** 3_000, [_]u8{2} ** 3_000 };
    var held: ?reqresp.RequestHandle = null;
    var chunks: u32 = 0;
    var served = false;
    var rounds: usize = 0;
    while (rounds < 40 and !(served and chunks == 1)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &blocks[0], .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
            },
            .chunk_sent => |progress| {
                if (progress.chunks == 1) {
                    try setup.server.respond(progress.request, &blocks[1], .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
                } else {
                    try std.testing.expect(setup.server.finish(progress.request, setup.pair.now));
                }
            },
            .served => served = true,
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                chunks += 1;
                held = chunk.request;
                try std.testing.expectEqualSlices(u8, &blocks[0], chunk.bytes);
            },
            .done, .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(served);
    try std.testing.expectEqual(@as(u32, 1), chunks);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) {
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(usize, 0), setup.clientEvents().len);
    }
    try std.testing.expect(setup.client.consume(held.?, setup.pair.now));
    var done = false;
    rounds = 0;
    while (rounds < 20 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                chunks += 1;
                try std.testing.expectEqualSlices(u8, &blocks[1], chunk.bytes);
                try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
            },
            .done => |finished| {
                try std.testing.expectEqual(@as(u32, 2), finished.chunks);
                done = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(u32, 2), chunks);
}

test "reqresp fails every request on a connection that closes" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_11: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_11, &sink);
    try waitForRequest(&setup);
    try std.testing.expect(setup.pair.client.close(setup.handles.client, 0));
    var client_failure: ?reqresp.Failure = null;
    var server_failure: ?reqresp.Failure = null;
    var rounds: usize = 0;
    while (rounds < 20 and (client_failure == null or server_failure == null)) : (rounds += 1) {
        try setup.pumpOnce();
        if (firstFailure(setup.clientEvents())) |failure| client_failure = failure;
        if (firstFailure(setup.serverEvents())) |failure| server_failure = failure;
    }
    try std.testing.expect(client_failure != null and client_failure.? == .connection_closed);
    try std.testing.expect(server_failure != null and server_failure.? == .connection_closed);
}

test "reqresp exhausts outbound slots and per-peer inbound slots" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1 }, .{ .inbound_per_peer_max = 1 });
    defer setup.deinit();

    var sinks: [2][ct.phase0.Status.fixed_size]u8 = undefined;
    var request_storage_12: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &request_storage_12, &sinks[0]);
    var request_storage_13: [ct.phase0.Status.fixed_size]u8 = undefined;
    try std.testing.expectError(error.SlotsExhausted, requestStatus(&setup, &request_storage_13, &sinks[1]));
    try waitForRequest(&setup);

    _ = try setup.client_neg.beginOutbound(
        &setup.pair.client,
        setup.handles.client,
        .{ .reqresp = .ping_v1 },
        setup.pair.now,
    );
    var rejected = false;
    var rounds: usize = 0;
    while (rounds < 10 and !rejected) : (rounds += 1) {
        setup.pumpOnce() catch |err| {
            try std.testing.expectEqual(error.PeerSlotsExhausted, err);
            rejected = true;
        };
    }
    try std.testing.expect(rejected);
}

test "reqresp answers a malformed request with an invalid request error" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const raw = try setup.client_neg.beginOutbound(
        &setup.pair.client,
        setup.handles.client,
        .{ .reqresp = .status_v1 },
        setup.pair.now,
    );
    var ready = false;
    var rounds: usize = 0;
    while (rounds < 10 and !ready) : (rounds += 1) {
        try setup.pair.pump();
        var storage: [8]engine_mod.Event = undefined;
        for (setup.pair.events(&setup.pair.server, &storage)) |event| {
            if (event == .stream_opened) {
                const stream = event.stream_opened;
                try setup.server_neg.negotiator.acceptInbound(stream, &protocol.ids, setup.pair.now);
            }
        }
        var outcomes: [4]negotiate.Outcome = undefined;
        const count = setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes);
        for (outcomes[0..count]) |outcome| {
            if (outcome.result == .ready) ready = true;
        }
        const listened = setup.server_neg.pump(&setup.pair.server, setup.pair.now, &outcomes);
        for (outcomes[0..listened]) |outcome| switch (outcome.result) {
            .ready => |accepted| _ = try setup.server.accept(
                &setup.pair.server,
                outcome.stream,
                accepted,
                setup.requestSink(),
                setup.pair.now,
            ),
            else => return error.TestUnexpectedResult,
        };
    }
    try std.testing.expect(ready);
    const garbage = [_]u8{0x80} ** 11;
    try std.testing.expectEqual(garbage.len, try setup.pair.client.write(raw, &garbage, true));
    var served: ?u32 = null;
    rounds = 0;
    while (rounds < 20 and served == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .served => |finished| served = finished.chunks,
            .request => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(?u32, 0), served);
    var sink: [codec.error_message_max]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    var decoder = codec.Decoder.initResponse(.{ .min = 84, .max = 84 }, false, &sink, &scratch);
    var buffer: [256]u8 = undefined;
    rounds = 0;
    while (rounds < 10 and !decoder.isDone()) : (rounds += 1) {
        try setup.pair.pump();
        const read = try setup.pair.client.read(raw, &buffer);
        if (read.len > 0) _ = try decoder.feed(buffer[0..read.len]);
    }
    try std.testing.expect(decoder.isDone());
    try std.testing.expectEqual(@as(u8, 1), decoder.result());
    try std.testing.expectEqualStrings("invalid request", decoder.payload());
}

const RawReply = fn (*ReqRespPair, engine_mod.StreamHandle) anyerror!void;

fn pumpRawServer(setup: *ReqRespPair, comptime reply: RawReply) !usize {
    try setup.pair.pump();
    const now = setup.pair.now;
    var storage: [16]engine_mod.Event = undefined;
    for (setup.pair.events(&setup.pair.server, &storage)) |event| switch (event) {
        .stream_opened => |stream| try setup.server_neg.negotiator.acceptInbound(stream, &protocol.ids, now),
        else => {},
    };
    var leftover: usize = 0;
    var outcomes: [8]negotiate.Outcome = undefined;
    const dialed = setup.client_neg.pump(&setup.pair.client, now, &outcomes);
    for (outcomes[0..dialed]) |outcome| {
        if (outcome.result == .ready) leftover += outcome.result.ready.leftover.len;
        try std.testing.expect(setup.client.negotiated(outcome, now));
    }
    const listened = setup.server_neg.pump(&setup.pair.server, now, &outcomes);
    for (outcomes[0..listened]) |outcome| switch (outcome.result) {
        .ready => try reply(setup, outcome.stream),
        else => return error.TestUnexpectedResult,
    };
    setup.client_count = setup.client.pump(&setup.pair.client, &setup.client_neg, now, &setup.client_events);
    try setup.pair.pump();
    return leftover;
}

fn replyMetadataEarly(setup: *ReqRespPair, stream: engine_mod.StreamHandle) !void {
    var out: [256]u8 = undefined;
    const metadata = [_]u8{5} ** ct.altair.MetaDataV2.fixed_size;
    const chunk = try codec.encodeChunk(0, null, &metadata, &out);
    try std.testing.expectEqual(chunk.len, try setup.pair.server.write(stream, chunk, true));
}

fn expectSingleChunk(setup: *ReqRespPair, comptime reply: RawReply, expected: []const u8) !usize {
    var leftover: usize = 0;
    var done = false;
    var rounds: usize = 0;
    while (rounds < 20 and !done) : (rounds += 1) {
        leftover += try pumpRawServer(setup, reply);
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, expected, chunk.bytes);
                try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
            },
            .done => |finished| {
                try std.testing.expectEqual(@as(u32, 1), finished.chunks);
                done = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
    return leftover;
}

test "reqresp decodes response bytes that arrive with the multistream echo" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var sink: [ct.altair.MetaDataV2.fixed_size]u8 = undefined;
    _ = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .metadata_v2,
        "",
        &sink,
        .{},
        setup.pair.now,
    );
    const expected = [_]u8{5} ** ct.altair.MetaDataV2.fixed_size;
    const leftover = try expectSingleChunk(&setup, replyMetadataEarly, &expected);
    try std.testing.expect(leftover > 0);
}

test "reqresp serves a request whose body and fin arrive with the proposal" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const stream = try setup.pair.client.openStream(setup.handles.client);
    const dialer = try multistream.Dialer.init(Protocol.status_v1.id());
    var message: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&message);
    const request_ssz = statusBytes(9);
    const encoded = try codec.encodeRequest(&request_ssz, message[hello.len..]);
    const total = hello.len + encoded.len;
    const written = try setup.pair.client.write(stream, message[0..total], true);
    try std.testing.expectEqual(total, written);

    const reply = statusBytes(3);
    var served = false;
    var rounds: usize = 0;
    while (rounds < 20 and !served) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.status_v1, incoming.protocol);
                try std.testing.expectEqualSlices(u8, &request_ssz, incoming.bytes);
                try setup.server.respond(incoming.request, &reply, null, setup.pair.now);
            },
            .chunk_sent => |sent| try std.testing.expect(setup.server.finish(sent.request, setup.pair.now)),
            .served => |finished| {
                try std.testing.expectEqual(@as(u32, 1), finished.chunks);
                served = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(served);
}

test "reqresp retires a consumed terminal stream without FIN or event space" {
    var pair: ReqRespPair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var request_bytes: [8]u8 = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const h = try pair.client.request(
        &pair.pair.client,
        &pair.client_neg,
        pair.handles.client,
        .ping_v1,
        &request_bytes,
        &sink,
        .{},
        pair.pair.now,
    );
    var consumed = false;
    for (0..50) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| switch (event) {
            .request => |r| try pair.server.respond(r.request, &request_bytes, null, pair.pair.now),
            else => {},
        };
        for (pair.clientEvents()) |event| switch (event) {
            .chunk => |r| {
                consumed = pair.client.consume(r.request, pair.pair.now);
            },
            else => {},
        };
        if (consumed) break;
    }
    try std.testing.expect(consumed);
    const stream = pair.client.outbound[h.index].stream;
    var out: [8]Event = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        pair.client.pump(&pair.pair.client, &pair.client_neg, pair.pair.now, &.{}),
    );
    try std.testing.expect(
        !pair.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id),
    );
    _ = pair.client.pump(&pair.pair.client, &pair.client_neg, pair.pair.now, &out);
    _ = pair.client.pump(&pair.pair.client, &pair.client_neg, pair.pair.now, &out);
    try std.testing.expectEqual(@as(u16, 0), pair.client.active().outbound);
    try std.testing.expect(
        !pair.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id),
    );
}

test "reqresp retains all 256 bytes of a peer error" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const request = [_]u8{0} ** 8;
    const message = [_]u8{'e'} ** 256;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .ping_v1,
        &request,
        &sink,
        .{},
        setup.pair.now,
    );
    for (0..50) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |r| try setup.server.respondError(r.request, 1, &message, setup.pair.now),
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .failed => |failed| {
                try std.testing.expectEqual(@as(u16, 256), failed.reason.peer_error.message_len);
                try std.testing.expectEqualSlices(
                    u8,
                    &message,
                    setup.client.errorMessage(failed.request),
                );
                return;
            },
            else => {},
        };
    }
    return error.TestUnexpectedResult;
}

test "reqresp blocked outbound writes expire without refreshing progress" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .progress_timeout_ms = 2_000 }, .{});
    defer setup.deinit();
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    const request = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .ping_v1,
        &request,
        &sink,
        .{},
        setup.pair.now,
    );
    var negotiated = false;
    for (0..50) |_| {
        try setup.pair.pump();
        var storage: [16]engine_mod.Event = undefined;
        for (setup.pair.events(&setup.pair.server, &storage)) |event| switch (event) {
            .stream_opened => |stream| try setup.server_neg.negotiator.acceptInbound(
                stream,
                &protocol.ids,
                setup.pair.now,
            ),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const listened = setup.server_neg.pump(&setup.pair.server, setup.pair.now, &outcomes);
        for (outcomes[0..listened]) |outcome| try std.testing.expect(outcome.result == .ready);
        const dialed = setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes);
        for (outcomes[0..dialed]) |outcome| {
            try std.testing.expect(outcome.result == .ready);
            negotiated = setup.client.negotiated(outcome, setup.pair.now);
        }
        if (negotiated) break;
    }
    try std.testing.expect(negotiated);
    const stream = setup.client.outbound[handle.index].stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.pair.client.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    const progress_ms = setup.client.outbound[handle.index].progress_ms;
    var events: [8]Event = undefined;
    for (0..3) |_| {
        setup.pair.advance(500);
        try std.testing.expectEqual(
            @as(usize, 0),
            setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events),
        );
        try std.testing.expectEqual(progress_ms, setup.client.outbound[handle.index].progress_ms);
    }
    setup.pair.advance(500);
    try std.testing.expectEqual(
        @as(usize, 1),
        setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events),
    );
    try std.testing.expect(events[0].failed.reason == .timeout);
    try std.testing.expect(
        !setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id),
    );
}

test "reqresp preserves pending chunk and reports connection closure without output space" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    try setup.server.respond(incoming, &bytes, null, setup.pair.now);
    var held = false;
    for (0..30) |_| {
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
        try setup.pair.pump();
        _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
        if (setup.client.outbound[handle.index].pending_event != null) {
            held = true;
            break;
        }
    }
    try std.testing.expect(held);
    const stream = setup.client.outbound[handle.index].stream;
    setup.client.connectionClosed(setup.handles.client);
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expect(!setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expect(events[0].failed.reason == .connection_closed);
    try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
}

fn finishAfterNotification(delay_ms: u64) !void {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    try setup.server.respond(incoming, &bytes, null, setup.pair.now);
    var pending = false;
    for (0..30) |_| {
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
        try setup.pair.pump();
        if (setup.server.inbound[incoming.index].pending_event != null) {
            pending = true;
            break;
        }
    }
    try std.testing.expect(pending);
    try std.testing.expect(setup.server.finish(incoming, setup.pair.now));
    try std.testing.expect(!setup.server.finish(incoming, setup.pair.now));
    setup.pair.advance(delay_ms);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
    try std.testing.expect(events[0] == .chunk_sent);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 1));
    const next = setup.server.nextWakeup(setup.pair.now, 1).?;
    setup.pair.advance(next - setup.pair.now.mono_ms);
    try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
    try std.testing.expect(events[0] == .served);
}

test "reqresp finish survives a flushed chunk awaiting notification" {
    try finishAfterNotification(0);
}

test "reqresp finishing starts peer time after a legal host capacity wait" {
    try finishAfterNotification(20_000);
}

test "reqresp accepts legal empty by root content" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, "", sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request;
    try std.testing.expectEqual(@as(usize, 0), incoming.bytes.len);
    try std.testing.expectEqual(Protocol.blocks_by_root_v2, incoming.protocol);
}

test "reqresp cancellation removes Router ownership before output delivery" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    const stream = setup.client.outbound[handle.index].stream;
    setup.client.options.work_per_pump_max = 1;
    try std.testing.expect(setup.client.cancel(handle));
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 0));
    try std.testing.expect(!setup.client.cancel(handle));
    try std.testing.expectEqual(@as(usize, 1), setup.client.resourceSnapshot().outbound_occupied);
    try std.testing.expectEqual(@as(usize, 1), setup.client.resourceSnapshot().pending_terminals);
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expect(!setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    var outcomes: [8]negotiate.Outcome = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expect(events[0].failed.reason == .cancelled);
    try std.testing.expect(!setup.client.cancel(handle));
    try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqual(@as(u64, 0), setup.client.counters.failures);
    try std.testing.expectEqual(@as(u64, 1), setup.client.protocol_counters[@intFromEnum(Protocol.ping_v1)].outgoing_cancelled);
    try std.testing.expectEqual(@as(u64, 0), setup.client.protocol_counters[@intFromEnum(Protocol.ping_v1)].outgoing_errors);
    try std.testing.expectEqual(@as(usize, 0), setup.client.resourceSnapshot().outbound_occupied);
    try std.testing.expectEqual(@as(usize, 0), setup.client.resourceSnapshot().pending_terminals);
}

test "reqresp caller cardinality rejects invalid bounds before opening a stream" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const options = [_]reqresp.RequestOptions{
        .{ .expected_chunks = 2 }, .{ .progress_timeout_ms = 0 },
    };
    for (options) |invalid| {
        try std.testing.expectError(error.InvalidRequestOptions, setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, invalid, setup.pair.now));
    }
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectEqual(@as(u64, 0), setup.client.counters.requests_sent);
}

test "reqresp narrowed chunks retire without FIN and held chunks use host deadline" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .progress_timeout_ms = 1000 }, .{});
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const reply = try std.testing.allocator.alloc(u8, ct.deneb.SignedBeaconBlock.min_size);
    defer std.testing.allocator.free(reply);
    @memset(reply, 0);
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, "", sink, .{ .expected_chunks = 1 }, setup.pair.now);
    var held = false;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| try setup.server.respond(incoming.request, reply, .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now),
            else => {},
        };
        for (setup.clientEvents()) |event| if (event == .chunk) {
            held = true;
        };
        if (held) break;
    }
    try std.testing.expect(held);
    setup.pair.advance(2000);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expect(setup.client.consume(handle, setup.pair.now));
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    const stream = setup.client.outbound[handle.index].stream;
    try std.testing.expect(!setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqual(@as(u32, 1), events[0].done.chunks);
}

test "reqresp wakeup distinguishes host and quota waits and bounds idle scans" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .host_timeout_ms = 2000 });
    defer setup.deinit();
    setup.client.options.work_per_pump_max = 1;
    for (0..16) |_| _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), setup.client.nextWakeup(setup.pair.now, 1));
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    setup.client.options.work_per_pump_max = 32;
    try waitForRequest(&setup);
    const due = setup.pair.now.mono_ms + 2000;
    try std.testing.expectEqual(@as(?u64, due), setup.server.nextWakeup(setup.pair.now, 1));
    setup.pair.advance(2000);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
    try std.testing.expect(events[0].failed.reason == .host_timeout);
}

test "reqresp validates transport capacity and copies its fork table" {
    var forks = [_]reqresp.ForkEntry{.{ .digest = deneb_digest, .fork = .deneb }};
    var rr = try reqresp.ReqResp.init(std.testing.allocator, .{ .peers = 1, .forks = &forks });
    defer rr.deinit();
    forks[0].digest = fulu_digest;
    try std.testing.expectEqual(@as(?@import("config").ForkSeq, .deneb), rr.forkFor(deneb_digest));
    try std.testing.expectEqual(@as(?@import("config").ForkSeq, null), rr.forkFor(fulu_digest));
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    try std.testing.expectError(error.InvalidCapacity, rr.attach(&setup.pair.client));
    try std.testing.expectError(error.InvalidOptions, reqresp.ReqResp.init(std.testing.allocator, .{ .peers = 1025, .forks = &.{} }));
    const plan = rr.memoryPlan();
    try std.testing.expectEqual(plan.total_bytes, plan.facade_bytes + plan.slot_bytes + plan.io_bytes + plan.limiter_bytes + plan.request_sink_bytes);
    try std.testing.expect(plan.io_bytes > 0 and plan.slot_bytes > 0 and plan.limiter_bytes > 0);
}

test "reqresp cancellation releases read held chunk and response write states once" {
    for ([_]bool{ false, true }) |hold_chunk| {
        var setup: ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const bytes = [_]u8{0} ** 8;
        var sink: [8]u8 = undefined;
        const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
        try waitForRequest(&setup);
        const incoming = setup.serverEvents()[0].request.request;
        try setup.server.respond(incoming, &bytes, null, setup.pair.now);
        if (hold_chunk) {
            var held = false;
            for (0..30) |_| {
                try setup.pumpOnce();
                for (setup.clientEvents()) |event| if (event == .chunk) {
                    held = true;
                };
                if (held) break;
            }
            try std.testing.expect(held);
        }
        const stream = setup.client.outbound[handle.index].stream;
        const server_stream = setup.server.inbound[incoming.index].stream;
        try std.testing.expect(setup.client.cancel(handle));
        try std.testing.expect(setup.server.cancel(incoming));
        setup.client.shutdown(&setup.pair.client, &setup.client_neg);
        setup.server.shutdown(&setup.pair.server, &setup.server_neg);
        try std.testing.expect(!setup.client.cancel(handle));
        try std.testing.expect(!setup.server.cancel(incoming));
        try std.testing.expect(!setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
        try std.testing.expect(!setup.pair.server.registry.slots[server_stream.conn.index].table.matches(server_stream.slot, server_stream.id));
        var events: [1]Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        try std.testing.expect(events[0].failed.reason == .cancelled);
        try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
        try std.testing.expect(events[0].failed.reason == .cancelled);
        try std.testing.expectEqual(@as(u64, 0), setup.client.counters.failures);
        try std.testing.expectEqual(@as(u64, 0), setup.server.counters.failures);
    }
}

test "reqresp terminal notification rotates fairly and exhausted generations never wrap" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 2 }, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sinks: [2][8]u8 = undefined;
    var handles: [2]reqresp.RequestHandle = undefined;
    for (&handles, 0..) |*handle, index| handle.* = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sinks[index], .{}, setup.pair.now);
    setup.client.shutdown(&setup.pair.client, &setup.client_neg);
    var seen = [_]bool{false} ** 2;
    var events: [1]Event = undefined;
    for (0..2) |_| {
        try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        const index = events[0].failed.request.index;
        try std.testing.expect(!seen[index]);
        seen[index] = true;
    }
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    for (setup.client.outbound) |*slot| slot.generation = std.math.maxInt(u32);
    try std.testing.expectError(error.SlotsExhausted, setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sinks[0], .{}, setup.pair.now));
}

test "reqresp negotiated handoff starts a fresh progress interval" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .progress_timeout_ms = 1000 }, .{});
    defer setup.deinit();
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    var ready = false;
    for (0..30) |_| {
        try setup.pair.pump();
        var storage: [16]engine_mod.Event = undefined;
        setup.server_neg.transportEvents(&setup.pair.server, setup.pair.events(&setup.pair.server, &storage), setup.pair.now);
        var outcomes: [8]negotiate.Outcome = undefined;
        _ = setup.server_neg.pump(&setup.pair.server, setup.pair.now, &outcomes);
        const count = setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes);
        if (count == 0) continue;
        try std.testing.expectEqual(@as(usize, 1), count);
        setup.pair.advance(2000);
        try std.testing.expect(setup.client.negotiated(outcomes[0], setup.pair.now));
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 1));
        ready = true;
        break;
    }
    try std.testing.expect(ready);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqual(@as(u64, 0), setup.client.counters.timeouts);
    try std.testing.expect(setup.client.cancel(handle));
}

test "reqresp terminal pressure quiesces without capacity and wakes when host unblocks" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try std.testing.expect(setup.client.cancel(handle));
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 0));
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), setup.client.nextWakeup(setup.pair.now, 0));
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 1));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expect(events[0].failed.reason == .cancelled);
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), setup.client.nextWakeup(setup.pair.now, 0));
}

test "reqresp quota delay expires as local policy and not peer timeout" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.ping_v1)] = .{ .tokens = 1, .period_ms = 5000 };
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .quotas = quotas, .quota_timeout_ms = 1000 });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sinks: [2][8]u8 = undefined;
    for (&sinks) |*sink| _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, sink, .{}, setup.pair.now);
    var requested: u32 = 0;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &bytes, null, setup.pair.now);
                requested += 1;
            },
            else => {},
        };
        if (requested == 2) break;
    }
    try std.testing.expectEqual(@as(u32, 2), requested);
    _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    for (0..4) |_| _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms + 1000), setup.server.nextWakeup(setup.pair.now, 0));
    setup.pair.advance(1000);
    var events: [4]Event = undefined;
    const count = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events);
    var expired = false;
    for (events[0..count]) |event| if (event == .failed) {
        try std.testing.expect(event.failed.reason == .quota_timeout);
        expired = true;
    };
    try std.testing.expect(expired);
    try std.testing.expectEqual(@as(u64, 0), setup.server.counters.timeouts);
}

test "reqresp blocked response writes expire and do not advertise ready local work" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 2000 });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    const stream = setup.server.inbound[incoming.index].stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.pair.server.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    try setup.server.respond(incoming, &bytes, null, setup.pair.now);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 0));
    const due = setup.pair.now.mono_ms + 2000;
    for (0..3) |_| {
        setup.pair.advance(500);
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
        try std.testing.expectEqual(@as(?u64, due), setup.server.nextWakeup(setup.pair.now, 0));
    }
    setup.pair.advance(500);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
    try std.testing.expect(events[0].failed.reason == .timeout);
    try std.testing.expect(!setup.pair.server.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id));
}

test "reqresp host consume retains buffered work behind a partial cursor" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, "", sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const stream = setup.server.inbound[setup.serverEvents()[0].request.request.index].stream;
    const first = [_]u8{1} ** 3000;
    const second = [_]u8{2} ** 3000;
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const a = try codec.encodeChunk(0, deneb_digest, &first, &wire);
    const b = try codec.encodeChunk(0, deneb_digest, &second, wire[a.len..]);
    const length = a.len + b.len;
    try std.testing.expectEqual(length, try setup.pair.server.write(stream, wire[0..length], false));
    try setup.pair.pump();
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqualSlices(u8, &first, events[0].chunk.bytes);
    setup.client.options.work_per_pump_max = 1;
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    try std.testing.expect(setup.client.consume(handle, setup.pair.now));
    var received = false;
    for (0..3) |_| {
        const due = setup.client.nextWakeup(setup.pair.now, 1);
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), due);
        const count = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events);
        if (count == 1) {
            try std.testing.expectEqualSlices(u8, &second, events[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
}

test "reqresp host response retains write work behind a partial cursor" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .outbound_max = 1, .inbound_max = 2 });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    setup.server.options.work_per_pump_max = 1;
    for (0..2) |_| _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    try setup.server.respond(incoming, &bytes, null, setup.pair.now);
    var events: [1]Event = undefined;
    var sent = false;
    for (0..10) |_| {
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 1));
        const count = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events);
        if (count == 1) {
            try std.testing.expect(events[0] == .chunk_sent);
            sent = true;
            break;
        }
    }
    try std.testing.expect(sent);
    try std.testing.expect(setup.server.finish(incoming, setup.pair.now));
    var done = false;
    for (0..4) |_| {
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 1));
        if (setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events) == 1) {
            try std.testing.expect(events[0] == .served);
            done = true;
            break;
        }
    }
    try std.testing.expect(done);
}

test "reqresp native bytes arriving behind cursor remain ready after activity drain" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer setup.deinit();
    const bytes = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const stream = setup.server.inbound[setup.serverEvents()[0].request.request.index].stream;
    setup.client.options.work_per_pump_max = 1;
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, null, &bytes, &wire);
    try std.testing.expectEqual(encoded.len, try setup.pair.server.write(stream, encoded, false));
    try setup.pair.pump();
    var activity: [128]engine_mod.Handle = undefined;
    const count = setup.pair.client.driverView().takeActivity(&activity);
    try std.testing.expect(count > 0);
    for (activity[0..count]) |conn| setup.client.connectionActivity(conn);
    var events: [1]Event = undefined;
    var received = false;
    for (0..3) |_| {
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 1));
        const emitted = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events);
        if (emitted == 1) {
            try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
}

test "reqresp native write credit behind cursor resumes from activity" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .outbound_max = 1, .inbound_max = 2 });
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    const stream = setup.server.inbound[incoming.index].stream;
    const client_stream = setup.client.outbound[handle.index].stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.pair.server.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    try setup.server.respond(incoming, &bytes, null, setup.pair.now);
    setup.server.options.work_per_pump_max = 1;
    for (0..2) |_| _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    var drain: [65536]u8 = undefined;
    var writable = false;
    for (0..512) |_| {
        try setup.pair.pump();
        _ = try setup.pair.client.read(client_stream, &drain);
        try setup.pair.pump();
        if (try setup.pair.server.streamCapacity(stream) > 0) {
            writable = true;
            break;
        }
    }
    try std.testing.expect(writable);
    var activity: [128]engine_mod.Handle = undefined;
    const count = setup.pair.server.driverView().takeActivity(&activity);
    try std.testing.expect(count > 0);
    for (activity[0..count]) |conn| setup.server.connectionActivity(conn);
    var events: [1]Event = undefined;
    var sent = false;
    for (0..10) |_| {
        try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.server.nextWakeup(setup.pair.now, 1));
        const emitted = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events);
        if (emitted == 1) {
            try std.testing.expect(events[0] == .chunk_sent);
            sent = true;
            break;
        }
    }
    try std.testing.expect(sent);
}

test "reqresp activity checks generation and quiets after a bounded tiny sweep" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer setup.deinit();
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    setup.client.options.work_per_pump_max = 1;
    const deadline = setup.client.nextWakeup(setup.pair.now, 0);
    try std.testing.expect(deadline.? > setup.pair.now.mono_ms);
    var stale = setup.handles.client;
    stale.generation += 1;
    setup.client.connectionActivity(stale);
    try std.testing.expectEqual(deadline, setup.client.nextWakeup(setup.pair.now, 0));
    setup.client.connectionActivity(setup.handles.client);
    for (0..4) |_| {
        if (setup.client.nextWakeup(setup.pair.now, 0) != setup.pair.now.mono_ms) break;
        _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    }
    try std.testing.expectEqual(deadline, setup.client.nextWakeup(setup.pair.now, 0));
}

test "reqresp partial beacon scans preserve host waits and elapsed deadlines" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{ .outbound_max = 64, .inbound_max = 64, .host_timeout_ms = 2000 });
    defer setup.deinit();
    for (0..8) |_| {
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
        try std.testing.expectEqual(@as(?u64, null), setup.server.nextWakeup(setup.pair.now, 0));
    }
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    try waitForRequest(&setup);
    const incoming = setup.serverEvents()[0].request.request;
    const due = setup.server.inbound[incoming.index].progress_ms + 2000;
    for (0..4) |_| {
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
        try std.testing.expectEqual(@as(?u64, due), setup.server.nextWakeup(setup.pair.now, 1));
    }
    setup.pair.advance(2000);
    var events: [1]Event = undefined;
    var failed = false;
    for (0..4) |_| {
        try std.testing.expect(setup.server.nextWakeup(setup.pair.now, 1).? <= setup.pair.now.mono_ms);
        if (setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events) == 1) {
            try std.testing.expect(events[0].failed.reason == .host_timeout);
            failed = true;
            break;
        }
    }
    try std.testing.expect(failed);
    _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &.{});
    try std.testing.expectEqual(@as(?u64, null), setup.server.nextWakeup(setup.pair.now, 1));
}

test "reqresp request write preserves already readable native response" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1, .inbound_max = 1 }, .{});
    defer setup.deinit();
    const bytes = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .ping_v1, &bytes, &sink, .{}, setup.pair.now);
    var server_stream: ?engine_mod.StreamHandle = null;
    for (0..10) |_| {
        try setup.pair.pump();
        var native_events: [16]engine_mod.Event = undefined;
        for (setup.pair.events(&setup.pair.server, &native_events)) |event| switch (event) {
            .stream_opened => |stream| try setup.server_neg.negotiator.acceptInbound(stream, &protocol.ids, setup.pair.now),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const client_count = setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes);
        for (outcomes[0..client_count]) |outcome| try std.testing.expect(setup.client.negotiated(outcome, setup.pair.now));
        const server_count = setup.server_neg.pump(&setup.pair.server, setup.pair.now, &outcomes);
        for (outcomes[0..server_count]) |outcome| switch (outcome.result) {
            .ready => server_stream = outcome.stream,
            else => return error.TestUnexpectedResult,
        };
        if (server_stream != null and setup.client.outbound[handle.index].state == .sending_request) break;
    }
    try std.testing.expect(server_stream != null);
    try std.testing.expectEqual(.sending_request, setup.client.outbound[handle.index].state);
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, null, &bytes, &wire);
    try std.testing.expectEqual(encoded.len, try setup.pair.server.write(server_stream.?, encoded, false));
    try setup.pair.pump();
    var activity: [128]engine_mod.Handle = undefined;
    const count = setup.pair.client.driverView().takeActivity(&activity);
    try std.testing.expect(count > 0);
    for (activity[0..count]) |conn| setup.client.connectionActivity(conn);
    for (0..4) |_| {
        _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
        if (setup.client.outbound[handle.index].state == .awaiting) break;
    }
    try std.testing.expectEqual(.awaiting, setup.client.outbound[handle.index].state);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), setup.client.nextWakeup(setup.pair.now, 1));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
}

test "reqresp explicit BPO context validates without consuming the serving slot" {
    const first: reqresp.ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
    const second: reqresp.ForkEntry = .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu };
    const invalid = [_]?reqresp.ForkEntry{
        null,
        .{ .digest = .{ 9, 9, 9, 9 }, .fork = .fulu },
        .{ .digest = second.digest, .fork = .deneb },
    };
    for ([_]reqresp.ForkEntry{ first, second }) |selected| {
        for (invalid) |context| {
            var setup: ReqRespPair = .{};
            try setup.init(.{ .forks = &.{selected} }, .{ .forks = &.{ first, second } });
            defer setup.deinit();
            const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_range_v2.info().response_max);
            defer std.testing.allocator.free(sink);
            var request: [24]u8 = undefined;
            _ = try requestBlocks(&setup, &request, 1, sink);
            const block = [_]u8{7} ** 4_000;
            var chunks: u32 = 0;
            var done = false;
            for (0..80) |_| {
                try setup.pumpOnce();
                for (setup.serverEvents()) |event| switch (event) {
                    .request => |incoming| {
                        try std.testing.expectError(error.UnknownFork, setup.server.respond(incoming.request, &block, context, setup.pair.now));
                        try setup.server.respond(incoming.request, &block, selected, setup.pair.now);
                    },
                    .chunk_sent => |progress| try std.testing.expect(setup.server.finish(progress.request, setup.pair.now)),
                    .failed => return error.TestUnexpectedResult,
                    else => {},
                };
                for (setup.clientEvents()) |event| switch (event) {
                    .chunk => |chunk| {
                        try std.testing.expectEqual(selected.fork, chunk.fork.?);
                        try std.testing.expectEqualSlices(u8, &block, chunk.bytes);
                        chunks += 1;
                        try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
                    },
                    .done => done = true,
                    .failed => return error.TestUnexpectedResult,
                    else => {},
                };
                if (done) break;
            }
            try std.testing.expect(done);
            try std.testing.expectEqual(@as(u32, 1), chunks);
        }
    }
}

test "reqresp rejects duplicate digests before allocating" {
    const first: reqresp.ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    for ([_]@import("config").ForkSeq{ .fulu, .deneb }) |fork| {
        try std.testing.expectError(error.InvalidOptions, reqresp.ReqResp.init(failing.allocator(), .{
            .forks = &.{ first, .{ .digest = first.digest, .fork = fork } },
        }));
    }
}

test "reqresp request admission host capacity cancellation and quota error write failure retain debt" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{
        .request_policy = @import("request_policy_test.zig").fixture(),
        .admission = .{ .identities = 1, .peer = @import("admission_test.zig").quotas(1, 86_400_000), .global = @import("admission_test.zig").quotas(100, 86_400_000) },
    });
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    setup.server_event_capacity = 0;
    const outbound = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, &.{}, sink, .{}, setup.pair.now);
    for (0..50) |_| {
        try setup.pumpOnce();
        if (setup.server.counters.admitted == 1) break;
    }
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.admitted);
    try std.testing.expectEqual(@as(usize, 0), setup.server_count);
    const first = &setup.server.inbound[0];
    const incoming = first.handle(0);
    try std.testing.expect(first.pending_event.? == .request);
    try std.testing.expect(setup.server.cancel(incoming));
    try std.testing.expect(setup.client.cancel(outbound));
    setup.server_event_capacity = 16;
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
    _ = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, &.{}, sink, .{}, setup.pair.now);
    var refused = false;
    for (0..50) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| try std.testing.expect(event != .request);
        if (setup.server.counters.peer_refusals == 1) {
            refused = true;
            break;
        }
    }
    try std.testing.expect(refused);
    const replacement = &setup.server.inbound[0];
    try std.testing.expect(replacement.generation > incoming.generation);
    try std.testing.expectEqualSlices(u8, "rate limited", replacement.pending_ssz);
    setup.pair.server.closeStream(replacement.stream, 0);
    var failed = false;
    for (0..20) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            try std.testing.expect(event != .request);
            if (event == .failed) failed = true;
        }
        if (failed) break;
    }
    try std.testing.expect(failed);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
    try std.testing.expectEqual(@as(u128, 1), setup.server.counters.charged_work);
    try std.testing.expectEqual(@as(usize, 0), setup.server.resourceSnapshot().pending_events);
}

test "reqresp absolute response deadline captures the live phase" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const request = statusBytes(5);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .status_v1, &request, &sink, .{
        .absolute_timeouts = .{ .negotiation_ms = 5_000, .request_ms = 5_000, .response_ms = 100 },
    }, setup.pair.now);
    try waitForRequest(&setup);
    const due = setup.client.outbound[handle.index].deadline(&setup.client).?;
    setup.pair.now.mono_ms = due - 1;
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    setup.pair.now.mono_ms = due;
    try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
    try std.testing.expectEqual(.timeout, events[0].failed.reason);
    try std.testing.expectEqual(.response, events[0].failed.phase.?);
}

test "reqresp absolute request phase expires under real stream backpressure" {
    var setup: ReqRespPair = .{};
    try setup.init(.{ .progress_timeout_ms = 2_000 }, .{});
    defer setup.deinit();
    _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &.{});
    const request = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .ping_v1,
        &request,
        &sink,
        .{ .absolute_timeouts = .{ .negotiation_ms = 5000, .request_ms = 2000, .response_ms = 10000 } },
        setup.pair.now,
    );
    var negotiated = false;
    for (0..50) |_| {
        try setup.pair.pump();
        var storage: [16]engine_mod.Event = undefined;
        for (setup.pair.events(&setup.pair.server, &storage)) |event| switch (event) {
            .stream_opened => |stream| try setup.server_neg.negotiator.acceptInbound(
                stream,
                &protocol.ids,
                setup.pair.now,
            ),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const listened = setup.server_neg.pump(&setup.pair.server, setup.pair.now, &outcomes);
        for (outcomes[0..listened]) |outcome| try std.testing.expect(outcome.result == .ready);
        const dialed = setup.client_neg.pump(&setup.pair.client, setup.pair.now, &outcomes);
        for (outcomes[0..dialed]) |outcome| {
            try std.testing.expect(outcome.result == .ready);
            negotiated = setup.client.negotiated(outcome, setup.pair.now);
        }
        if (negotiated) break;
    }
    try std.testing.expect(negotiated);
    const stream = setup.client.outbound[handle.index].stream;
    const padding = [_]u8{0} ** 65536;
    var blocked = false;
    for (0..1024) |_| {
        _ = setup.pair.client.write(stream, &padding, false) catch |err| switch (err) {
            error.WouldBlock => {
                blocked = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);
    const progress_ms = setup.client.outbound[handle.index].progress_ms;
    var events: [8]Event = undefined;
    for (0..3) |_| {
        setup.pair.advance(500);
        try std.testing.expectEqual(
            @as(usize, 0),
            setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events),
        );
        try std.testing.expectEqual(progress_ms, setup.client.outbound[handle.index].progress_ms);
    }
    setup.pair.advance(500);
    try std.testing.expectEqual(
        @as(usize, 1),
        setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events),
    );
    try std.testing.expect(events[0].failed.reason == .timeout);
    try std.testing.expectEqual(.request, events[0].failed.phase.?);
    try std.testing.expect(
        !setup.pair.client.registry.slots[stream.conn.index].table.matches(stream.slot, stream.id),
    );
}

test "reqresp absolute negotiation timeout phase survives terminal cleanup" {
    for ([_]u64{ 50, 20_000 }) |duration| {
        var setup: ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const request = statusBytes(5);
        var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
        const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .status_v1, &request, &sink, .{ .absolute_timeouts = .{ .negotiation_ms = duration, .request_ms = 5000, .response_ms = 10000 } }, setup.pair.now);
        const due = setup.pair.now.mono_ms + duration;
        var events: [1]Event = undefined;
        _ = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events);
        setup.pair.now.mono_ms = due - 1;
        try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        setup.pair.now.mono_ms = due;
        try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        try std.testing.expectEqual(handle, events[0].failed.request);
        try std.testing.expectEqual(.timeout, events[0].failed.reason);
        try std.testing.expectEqual(.negotiation, events[0].failed.phase.?);
    }
}

test "reqresp absolute policies validate all durations before stream admission" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const request = statusBytes(5);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    inline for (.{ "negotiation_ms", "request_ms", "response_ms" }) |field| {
        for ([_]u64{ 0, 60001, std.math.maxInt(u64) }) |invalid| {
            var policy: reqresp.AbsoluteTimeouts = .{ .negotiation_ms = 1, .request_ms = 1, .response_ms = 1 };
            @field(policy, field) = invalid;
            try std.testing.expectError(error.InvalidRequestOptions, setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .status_v1, &request, &sink, .{ .absolute_timeouts = policy }, setup.pair.now));
        }
    }
    try std.testing.expectError(error.InvalidRequestOptions, setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .status_v1, &request, &sink, .{ .absolute_timeouts = .{ .negotiation_ms = 1, .request_ms = 1, .response_ms = 1 }, .progress_timeout_ms = 1 }, setup.pair.now));
    try std.testing.expectEqual(@as(u64, 0), setup.client.counters.requests_sent);
    try std.testing.expectEqual(@as(usize, 0), setup.client_neg.negotiator.active());
}

test "reqresp absolute response includes paused host time without renewing at chunks or consume" {
    for ([_]bool{ false, true }) |consume| {
        var setup: ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
        defer std.testing.allocator.free(sink);
        const block = [_]u8{7} ** 4000;
        const roots = [_]u8{0} ** 64;
        const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .blocks_by_root_v2, &roots, sink, .{ .absolute_timeouts = .{ .negotiation_ms = 5000, .request_ms = 5000, .response_ms = 1000 } }, setup.pair.now);
        var held = false;
        for (0..80) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| if (event == .request) try setup.server.respond(event.request.request, &block, .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
            for (setup.clientEvents()) |event| if (event == .chunk) {
                held = true;
            };
            if (held) break;
        }
        try std.testing.expect(held);
        const due = setup.client.outbound[handle.index].deadline(&setup.client).?;
        setup.pair.now.mono_ms = due - 1;
        if (consume) try std.testing.expect(setup.client.consume(handle, setup.pair.now));
        try std.testing.expectEqual(@as(?u64, due), setup.client.outbound[handle.index].deadline(&setup.client));
        var events: [1]Event = undefined;
        try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        setup.pair.now.mono_ms = due;
        try std.testing.expectEqual(@as(usize, 1), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
        try std.testing.expectEqual(if (consume) std.meta.Tag(reqresp.Failure).timeout else .host_timeout, std.meta.activeTag(events[0].failed.reason));
        try std.testing.expectEqual(.response, events[0].failed.phase.?);
    }
}

test "reqresp absolute response expires despite continuous wire progress while legacy renews" {
    for ([_]bool{ false, true }) |absolute| {
        var setup: ReqRespPair = .{};
        try setup.init(.{ .progress_timeout_ms = 100 }, .{});
        defer setup.deinit();
        const request = statusBytes(5);
        var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
        const options: reqresp.RequestOptions = if (absolute) .{ .absolute_timeouts = .{ .negotiation_ms = 5000, .request_ms = 5000, .response_ms = 100 } } else .{};
        const handle = try setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, .status_v1, &request, &sink, options, setup.pair.now);
        try waitForRequest(&setup);
        const due = setup.client.outbound[handle.index].deadline(&setup.client).?;
        const stream = setup.server.inbound[0].stream;
        var wire: [codec.frame_scratch_max]u8 = undefined;
        const encoded = try codec.encodeChunk(0, null, &request, &wire);
        try std.testing.expect(encoded.len > 10);
        var events: [1]Event = undefined;
        for (0..9) |i| {
            setup.pair.now.mono_ms = due - 90 + i * 10;
            try std.testing.expectEqual(@as(usize, 1), try setup.pair.server.write(stream, encoded[i .. i + 1], false));
            try setup.pair.pump();
            setup.client.connectionActivity(setup.handles.client);
            try std.testing.expectEqual(@as(usize, 0), setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events));
            if (absolute) try std.testing.expectEqual(@as(?u64, due), setup.client.outbound[handle.index].deadline(&setup.client));
        }
        setup.pair.now.mono_ms = due;
        const count = setup.client.pump(&setup.pair.client, &setup.client_neg, setup.pair.now, &events);
        if (absolute) {
            try std.testing.expectEqual(@as(usize, 1), count);
            try std.testing.expectEqual(.timeout, events[0].failed.reason);
            try std.testing.expectEqual(.response, events[0].failed.phase.?);
        } else {
            try std.testing.expectEqual(@as(usize, 0), count);
            try std.testing.expect(setup.client.outbound[handle.index].deadline(&setup.client).? > due);
        }
    }
}

test "reqresp canonical cancel supersedes accepted unfinished finish and error" {
    for ([_]bool{ false, true }) |error_response| {
        var setup: ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        var request: [24]u8 = undefined;
        const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_range_v2.info().response_max);
        defer std.testing.allocator.free(sink);
        _ = try requestBlocks(&setup, &request, 2, sink);
        try waitForRequest(&setup);
        const handle = setup.serverEvents()[0].request.request;
        const response = [_]u8{7} ** 4000;
        try setup.server.respond(handle, &response, .{ .digest = deneb_digest, .fork = .deneb }, setup.pair.now);
        var sent = false;
        for (0..20) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| if (event == .chunk_sent) {
                try std.testing.expectEqual(handle, event.chunk_sent.request);
                try std.testing.expectEqual(@as(u32, 1), event.chunk_sent.chunks);
                sent = true;
            };
            if (sent) break;
        }
        try std.testing.expect(sent);
        if (error_response) {
            try setup.server.respondError(handle, 139, "unfinished", setup.pair.now);
        } else try std.testing.expect(setup.server.finish(handle, setup.pair.now));
        const slot = setup.server.inboundSlot(handle).?;
        try std.testing.expectEqual(@as(@TypeOf(slot.state), if (error_response) .writing_chunk else .finishing), slot.state);
        try std.testing.expect(slot.terminal == null);
        try std.testing.expectEqual(@as(u32, 1), slot.chunks);
        try std.testing.expect(setup.server.cancel(handle));
        try std.testing.expectEqual(.cancelled, slot.terminal.?.failed.reason);
        try std.testing.expectEqual(@as(u32, 1), slot.chunks);
        try std.testing.expect(!setup.server.cancel(handle));
        setup.server.cleanupPending(&setup.pair.server, &setup.server_neg);
        var events: [1]Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events));
        try std.testing.expectEqual(handle, events[0].failed.request);
        try std.testing.expectEqual(.cancelled, events[0].failed.reason);
        _ = setup.server.pump(&setup.pair.server, &setup.server_neg, setup.pair.now, &events);
        try std.testing.expect(setup.server.inboundSlot(handle) == null);
    }
}
