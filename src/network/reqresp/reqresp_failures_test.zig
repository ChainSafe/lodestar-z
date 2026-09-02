const std = @import("std");
const ct = @import("consensus_types");
const codec = @import("codec.zig");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");
const harness = @import("reqresp_test.zig");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const ReqRespPair = harness.ReqRespPair;

const deneb_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xa9 };
const fulu_digest = [4]u8{ 0x2f, 0x2f, 0x2f, 0x2f };

fn statusBytes(seed: u8) [ct.phase0.Status.fixed_size]u8 {
    const status = ct.phase0.Status.Type{
        .fork_digest = deneb_digest,
        .finalized_root = [_]u8{seed} ** 32,
        .finalized_epoch = seed,
        .head_root = [_]u8{seed +% 1} ** 32,
        .head_slot = @as(u64, seed) * 32,
    };
    var bytes: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = ct.phase0.Status.serializeIntoBytes(&status, &bytes);
    return bytes;
}

fn requestStatus(setup: *ReqRespPair, sink: []u8) !reqresp.RequestHandle {
    const request_ssz = statusBytes(5);
    return setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        sink,
        .{},
        setup.pair.now,
    );
}

fn requestBlocks(setup: *ReqRespPair, count: u64, sink: []u8) !reqresp.RequestHandle {
    const Request = ct.phase0.BeaconBlocksByRangeRequest;
    const request = Request.Type{ .start_slot = 1, .count = count, .step = 1 };
    var request_ssz: [24]u8 = undefined;
    _ = Request.serializeIntoBytes(&request, &request_ssz);
    return setup.client.request(
        &setup.pair.client,
        &setup.client_neg,
        setup.handles.client,
        .blocks_by_range_v2,
        &request_ssz,
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
    try setup.init(.{ .progress_timeout_ms = 2_000 }, .{ .progress_timeout_ms = 2_000 });
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &sink);
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
    try std.testing.expect(server_failure.? == .timeout or server_failure.? == .stream_closed);
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.timeouts);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
}

test "reqresp delivers error chunks with the peer's code and message" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try requestStatus(&setup, &sink);
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

    _ = try requestStatus(&setup, &sink);
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
    _ = try requestStatus(&setup, &sink);
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
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request)),
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
    _ = try requestBlocks(&setup, 1, sink);
    const block = [_]u8{7} ** 4_000;
    var failure: ?reqresp.Failure = null;
    var rounds: usize = 0;
    while (rounds < 40 and failure == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &block, .fulu, setup.pair.now);
            },
            .chunk_sent => |progress| try std.testing.expect(setup.server.finish(progress.request)),
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
    const first = try requestBlocks(&setup, 1, sinks[0..size]);
    _ = try requestBlocks(&setup, 1, sinks[size .. 2 * size]);
    const third = requestBlocks(&setup, 1, sinks[2 * size ..]);
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
        Protocol.blocks_by_range_v2.id(),
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
                    try std.testing.expect(setup.server.finish(incoming.request));
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
    _ = try requestBlocks(&setup, 1, sinks[2 * size ..]);
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
                try std.testing.expect(setup.server.finish(incoming.request));
            },
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request)),
            .done => completed += 1,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(u32, 1), completed);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.withheld_chunks);

    setup.pair.advance(3_000);
    rounds = 0;
    while (rounds < 20 and completed < 2) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(setup.client.consume(chunk.request)),
            .done => completed += 1,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expectEqual(@as(u32, 2), completed);
    try std.testing.expect(setup.server.counters.withheld_ms_total >= 3_000);
}

test "reqresp holds the next chunk until the host consumes the previous one" {
    var setup: ReqRespPair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();

    const size = Protocol.blocks_by_range_v2.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(sink);
    _ = try requestBlocks(&setup, 2, sink);
    const blocks = [2][3_000]u8{ [_]u8{1} ** 3_000, [_]u8{2} ** 3_000 };
    var held: ?reqresp.RequestHandle = null;
    var chunks: u32 = 0;
    var served = false;
    var rounds: usize = 0;
    while (rounds < 40 and !(served and chunks == 1)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try setup.server.respond(incoming.request, &blocks[0], .deneb, setup.pair.now);
            },
            .chunk_sent => |progress| {
                if (progress.chunks == 1) {
                    try setup.server.respond(progress.request, &blocks[1], .deneb, setup.pair.now);
                } else {
                    try std.testing.expect(setup.server.finish(progress.request));
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
    try std.testing.expect(setup.client.consume(held.?));
    var done = false;
    rounds = 0;
    while (rounds < 20 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                chunks += 1;
                try std.testing.expectEqualSlices(u8, &blocks[1], chunk.bytes);
                try std.testing.expect(setup.client.consume(chunk.request));
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
    _ = try requestStatus(&setup, &sink);
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
    _ = try requestStatus(&setup, &sinks[0]);
    try std.testing.expectError(error.SlotsExhausted, requestStatus(&setup, &sinks[1]));
    try waitForRequest(&setup);

    _ = try setup.client_neg.beginOutbound(
        &setup.pair.client,
        setup.handles.client,
        Protocol.ping_v1.id(),
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
        Protocol.status_v1.id(),
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
                try setup.server_neg.acceptInbound(stream, &protocol.ids, setup.pair.now);
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
                outcome.stream,
                accepted.protocol_index,
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
