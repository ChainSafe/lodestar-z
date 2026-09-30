const std = @import("std");
const CallTable = @import("CallTable.zig");
const crypto = @import("identity/crypto.zig");
const Transport = @import("Transport.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const Lookup = @import("Lookup.zig");
const Maintenance = @import("Maintenance.zig");
const lookup_batch = @import("lookup_batch.zig");
const message = @import("wire/message.zig");
const RoutingTable = @import("RoutingTable.zig");
const Sockets = @import("udp").Sockets;
const SessionStore = @import("SessionStore.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

const address4 = test_support.address4;
const endpoint = test_support.endpoint;
const fakeRecord = test_support.fakeRecord;
const installSession = test_support.installSession;
const keyPair = test_support.keyPair;

const net = std.Io.net;

test "transport rejects invalid polling and missing expiry storage" {
    var instance: Transport = undefined;
    var sockets = try Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    try std.testing.expectError(error.InvalidPollInterval, instance.init(std.testing.allocator, sockets, undefined, undefined, .{ .poll_interval_ms = 0 }));
    try std.testing.expectError(error.MissingExpiryStorage, instance.step(undefined, &.{}));
}

test "transport refuses exhausted packet admission before entropy or decoding" {
    var pair: Pair = undefined;
    try pair.init(1_000, false);
    defer pair.deinit();
    const limits = @import("admission.zig");
    for (0..limits.packet_global_quota.burst) |i| {
        const source = address4(192, 0, 2, @intCast(i), 9_000);
        try std.testing.expect(pair.transport_a.engine.channel.admission.allow(.packet, &source, 0));
    }
    const Clock = struct {
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .{ .nanoseconds = 0 };
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.now = Clock.now;
    const base: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var host = @import("udp").testing.FaultIo{ .entropy = .{} };
    host.init(base);
    defer host.deinit();
    try pair.transport_b.sockets.sendTo(std.testing.io, pair.transport_a.localAddress(), &([_]u8{0} ** 63), 1_280);
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(types.RejectReason.admission_limited, result.datagram.rejected);
    try std.testing.expectEqual(@as(usize, 0), host.entropy_calls);
    try std.testing.expectEqual(@as(usize, 0), host.send_calls);
}

test "maintenance retains a routing incumbent that answers through Transport" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();
    try pair.fillBucket();
    const now_ms = try Transport.monotonicMilliseconds(std.testing.io);
    var controller: Maintenance = undefined;
    try controller.init(now_ms, .{}, .ip4);
    defer controller.cancel(&pair.transport_a.engine);
    try std.testing.expectEqual(@as(?u64, 0), controller.nextDeadlineMs(&pair.transport_a.engine));
    var out: [1_280]u8 = undefined;
    const started = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{1}), now_ms, &test_support.sealEntropy(10))).?;
    try pair.transport_a.transmit(std.testing.io, started.peer.address, out[0..started.call.packet_length]);
    var expired: [4]CallTable.Expired = undefined;
    const answered = try pair.transport_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);
    const completed = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .response);
    try std.testing.expect(try controller.onEvent(&pair.transport_a.engine, &completed.event, completed.now_ms));
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.routing.pendingCount());
    try std.testing.expect(pair.transport_a.engine.routing.contains(&pair.record_b.node_id));
    try std.testing.expect(!pair.transport_a.engine.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
}

test "maintenance bounds local replacement probe retries without blocking transport receive" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();
    try pair.fillBucket();
    var controller: Maintenance = undefined;
    try controller.init(0, .{}, .ip4);
    defer controller.cancel(&pair.transport_a.engine);
    var out: [1_280]u8 = undefined;
    const started = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{1}), 0, &test_support.sealEntropy(10))).?;
    try std.testing.expect(controller.onFailure(&pair.transport_a.engine, started.call.handle, 0, .local));
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
    try std.testing.expectEqual(@as(usize, 1), pair.transport_a.engine.routing.pendingCount());
    for (0..32) |_| try std.testing.expect((try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{2}), 999, &test_support.sealEntropy(11))) == null);
    const oversized = [_]u8{0xff} ** 1_281;
    try pair.transport_b.sockets.primary().send(std.testing.io, &pair.transport_a.sockets.primary().address, &oversized);
    var expired: [4]CallTable.Expired = undefined;
    const received = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(types.RejectReason.oversized_datagram, received.datagram.rejected);
    try std.testing.expect(received.failure == null);
    const retry = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{2}), 1_000, &test_support.sealEntropy(11))).?;
    try std.testing.expect(controller.onFailure(&pair.transport_a.engine, retry.call.handle, 1_000, .local));
    try std.testing.expect(controller.pending == null);
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.routing.pendingCount());
    try std.testing.expect(pair.transport_a.engine.routing.contains(&started.peer.node_id));
    try std.testing.expect(!pair.transport_a.engine.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
}

test "maintenance replaces an expired incumbent but preserves later authenticated liveness" {
    for ([_]bool{ false, true }) |authenticated_later| {
        var pair: Pair = undefined;
        try pair.init(1, true);
        defer pair.deinit();
        try pair.fillBucket();
        var controller: Maintenance = undefined;
        try controller.init(0, .{}, .ip4);
        defer controller.cancel(&pair.transport_a.engine);
        var out: [1_280]u8 = undefined;
        const started = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{1}), 0, &test_support.sealEntropy(10))).?;
        if (authenticated_later) _ = try pair.transport_a.engine.confirmPeer(&started.peer, &pair.record_b, std.math.maxInt(u64));
        var expired: [4]CallTable.Expired = undefined;
        const result = pair.transport_a.engine.tick(1, &expired);
        try std.testing.expectEqual(@as(usize, 1), result.calls);
        try std.testing.expect(controller.onFailure(&pair.transport_a.engine, expired[0].handle, 1, .expired));
        try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.routing.pendingCount());
        try std.testing.expectEqual(authenticated_later, pair.transport_a.engine.routing.contains(&pair.record_b.node_id));
        try std.testing.expectEqual(!authenticated_later, pair.transport_a.engine.routing.contains(&pair.candidate_id));
        try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
    }
}

test "transport completes a cold call through challenge and handshake" {
    var pair: Pair = undefined;
    try pair.init(1_000, false);
    defer pair.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x42}),
        .enr_sequence = pair.record_a.sequence,
    } };
    const handle = try pair.transport_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    var expired: [4]CallTable.Expired = undefined;
    try std.testing.expect((try pair.transport_b.step(std.testing.io, &expired)).event == .none);
    try std.testing.expect((try pair.transport_a.step(std.testing.io, &expired)).event == .none);
    const request_step = try pair.transport_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), request_step.progress.standard_responses);
    const response_step = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expect(response_step.event == .response);
    try std.testing.expectEqual(handle, response_step.event.response.matched.handle);
    try std.testing.expect(response_step.event.response.matched.response == .pong);
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
}

test "transport leaves TALK response policy with the application" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();

    const request_id = try message.RequestId.init(&.{0x43});
    const request = message.Message{ .talk_request = .{
        .request_id = request_id,
        .protocol = "test",
        .request = "request",
    } };
    const handle = try pair.transport_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    var expired: [4]CallTable.Expired = undefined;
    const received = try pair.transport_b.step(std.testing.io, &expired);
    try std.testing.expect(received.event == .request);
    try std.testing.expect(received.event.request.message == .talk_request);
    try std.testing.expectEqual(@as(u8, 0), received.progress.standard_responses);

    const response = message.Message{ .talk_response = .{
        .request_id = request_id,
        .response = "response",
    } };
    try pair.transport_b.sendResponse(
        std.testing.io,
        endpoint(&pair.record_a),
        &response,
    );
    const completed = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .response);
    try std.testing.expectEqual(handle, completed.event.response.matched.handle);
    try std.testing.expectEqualStrings(
        "response",
        completed.event.response.matched.response.talk_response.response,
    );
}

test "transport releases a malformed datagram before the next step" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();

    try pair.transport_b.sockets.sendTo(
        std.testing.io,
        pair.transport_a.localAddress(),
        &.{0xff},
        @import("wire/constants.zig").packet_size_max,
    );
    var expired: [4]CallTable.Expired = undefined;
    const rejected = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expect(rejected.datagram == .rejected);
    try std.testing.expectEqual(types.RejectReason.malformed_packet, rejected.datagram.rejected);

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x44}),
        .enr_sequence = pair.record_b.sequence,
    } };
    const handle = try pair.transport_b.startCall(
        std.testing.io,
        endpoint(&pair.record_a),
        &pair.record_a,
        &request,
    );
    const answered = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);
    const completed = try pair.transport_b.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .response);
    try std.testing.expectEqual(handle, completed.event.response.matched.handle);
}

test "transport returns call expiries when rejecting a malformed datagram" {
    var pair: Pair = undefined;
    try pair.init(1, true);
    defer pair.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x45}),
        .enr_sequence = pair.record_a.sequence,
    } };
    const handle = try pair.transport_a.startCall(
        std.testing.io,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    try std.Io.sleep(std.testing.io, .fromMilliseconds(2), .awake);
    try pair.transport_b.sockets.sendTo(
        std.testing.io,
        pair.transport_a.localAddress(),
        &.{0xff},
        @import("wire/constants.zig").packet_size_max,
    );

    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(?Transport.Error, null), result.failure);
    try std.testing.expect(result.datagram == .rejected);
    try std.testing.expectEqual(types.RejectReason.malformed_packet, result.datagram.rejected);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(handle, expired[0].handle);
}

test "transport drops replies its destination refuses and keeps the step's expiries" {
    for ([_]bool{ false, true }) |established| {
        var pair: Pair = undefined;
        try pair.init(1_000, established);
        defer pair.deinit();
        const request = message.Message{ .ping = .{
            .request_id = try message.RequestId.init(&.{0x48}),
            .enr_sequence = pair.record_a.sequence,
        } };
        var output: [1_280]u8 = undefined;
        const expiring = try pair.transport_a.engine.startCall(
            &output,
            endpoint(&pair.record_b),
            &pair.record_b,
            &request,
            0,
            &test_support.sealEntropy(0x33),
        );
        _ = try pair.transport_b.startCall(std.testing.io, endpoint(&pair.record_a), &pair.record_a, &request);
        // A challenge answers the cold request and a PONG the established one.
        var host = @import("udp").testing.FaultIo{ .send = .{ .socket = pair.transport_a.sockets.primary().handle } };
        host.init(std.testing.io);
        defer host.deinit();
        var expired: [4]CallTable.Expired = undefined;
        const result = try pair.transport_a.step(host.io(), &expired);
        try std.testing.expectEqual(@as(?Transport.Error, null), result.failure);
        try std.testing.expect(result.datagram == .accepted);
        try std.testing.expect(result.event == .none);
        try std.testing.expectEqual(@as(u8, 0), result.progress.standard_responses);
        try std.testing.expectEqual(@as(usize, 1), host.send_calls);
        try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
        try std.testing.expectEqual(expiring.handle, expired[0].handle);
    }
}

test "transport fails a call whose handshake is not sent so maintenance keeps the incumbent" {
    // A refusal fails only the call; local resource pressure also reports a local step failure.
    for ([_]std.Io.net.Socket.SendError{ error.AddressFamilyUnsupported, error.SystemResources }) |send_failure| {
        var pair: Pair = undefined;
        try pair.init(1_000, false);
        defer pair.deinit();
        try pair.fillBucket();
        const incumbent = pair.transport_a.engine.peerRecord(&pair.record_b.node_id).?;
        const now_ms = try Transport.monotonicMilliseconds(std.testing.io);
        var controller: Maintenance = undefined;
        try controller.init(now_ms, .{}, .ip4);
        defer controller.cancel(&pair.transport_a.engine);
        var out: [1_280]u8 = undefined;
        const started = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{1}), now_ms, &test_support.sealEntropy(10))).?;
        try std.testing.expectEqual(endpoint(&pair.record_b), started.peer);
        try pair.transport_a.transmit(std.testing.io, started.peer.address, out[0..started.call.packet_length]);
        var expired: [4]CallTable.Expired = undefined;
        const challenged = try pair.transport_b.step(std.testing.io, &expired);
        try std.testing.expect(challenged.failure == null and challenged.datagram == .accepted);
        var host = @import("udp").testing.FaultIo{ .send = .{ .socket = pair.transport_a.sockets.primary().handle }, .send_failure = send_failure };
        host.init(std.testing.io);
        defer host.deinit();
        const unsent = try pair.transport_a.step(host.io(), &expired);
        try std.testing.expectEqual(if (send_failure == error.SystemResources) @as(?Transport.Error, error.SystemResources) else null, unsent.failure);
        const dropped = &pair.transport_a.send_drops;
        const pressure = @intFromEnum(@import("udp").SendPressure.system_resources);
        try std.testing.expectEqual(@as(u64, @intFromBool(send_failure == error.SystemResources)), dropped.datagrams[pressure]);
        try std.testing.expectEqual(send_failure == error.SystemResources, dropped.bytes[pressure] > 0);
        try std.testing.expectEqual(@as(usize, 1), host.send_calls);
        try std.testing.expect(unsent.event == .failed);
        try std.testing.expectEqual(started.call.handle, unsent.event.failed.handle);
        try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
        try std.testing.expect(try controller.onEvent(&pair.transport_a.engine, &unsent.event, unsent.now_ms));
        try std.testing.expect(pair.transport_a.engine.routing.contains(&pair.record_b.node_id));
        try std.testing.expect(!pair.transport_a.engine.routing.contains(&pair.candidate_id));
        try std.testing.expectEqual(@as(usize, 1), pair.transport_a.engine.routing.pendingCount());
        try std.testing.expectEqual(incumbent.last_verified_ms, pair.transport_a.engine.peerRecord(&pair.record_b.node_id).?.last_verified_ms);
        // A local failure retries the probe after its interval, and the failed call never expires.
        const retry_ms = controller.nextDeadlineMs(&pair.transport_a.engine).?;
        try std.testing.expect(retry_ms > unsent.now_ms);
        const retry = (try controller.startNext(&pair.transport_a.engine, &out, try .init(&.{2}), retry_ms, &test_support.sealEntropy(11))).?;
        try std.testing.expectEqual(started.peer, retry.peer);
        const later = pair.transport_a.engine.tick(retry_ms + 2_000, &expired);
        try std.testing.expectEqual(@as(usize, 1), later.calls);
        try std.testing.expectEqual(retry.call.handle, expired[0].handle);
    }
}

test "transport completes a caller-owned lookup across multiple peers" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.transport_a.engine.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(&operation_candidates, network.record_a.node_id, network.record_c.node_id, seeds, .dual);

    var cursor: lookup_batch.Cursor = .{};
    var expired: [4]CallTable.Expired = undefined;
    const first = try lookup_batch.step(
        &network.transport_a,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), first.progress.started);
    try std.testing.expectEqual(@as(usize, 0), first.transport.calls_expired);

    const from_b = try network.transport_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), from_b.progress.standard_responses);
    const second = try lookup_batch.step(
        &network.transport_a,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), second.progress.responses);
    try std.testing.expectEqual(@as(u16, 1), second.progress.started);
    try std.testing.expectEqual(@as(?u16, 0), second.consumed);

    const from_c = try network.transport_c.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), from_c.progress.standard_responses);
    const completed = try lookup_batch.step(
        &network.transport_a,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), completed.progress.responses);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), network.transport_a.engine.calls.count());
    try std.testing.expect(network.transport_a.engine.routing.contains(&network.record_c.node_id));

    var records: [Lookup.result_max]enr.Record = undefined;
    const results = operation.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(network.record_c.node_id, results[0].node_id);
    try std.testing.expectEqual(network.record_b.node_id, results[1].node_id);
}

test "lookup expiry is consumed without hiding an unrelated call expiry" {
    var network: LookupNetwork = undefined;
    try network.init(1);
    defer network.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x24}),
        .enr_sequence = network.record_a.sequence,
    } };
    var output: [1_280]u8 = undefined;
    const caller = try network.transport_a.engine.startCall(
        &output,
        endpoint(&network.record_c),
        &network.record_c,
        &request,
        0,
        &test_support.sealEntropy(10),
    );
    const caller_handle = caller.handle;
    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.transport_a.engine.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(&operation_candidates, network.record_a.node_id, network.record_c.node_id, seeds, .dual);

    defer operation.cancel(&network.transport_a.engine);
    _ = (try operation.startNext(
        &network.transport_a.engine,
        &output,
        try message.RequestId.init(&.{0x25}),
        0,
        &test_support.sealEntropy(20),
    )).?;

    var cursor: lookup_batch.Cursor = .{};
    var expired: [4]CallTable.Expired = undefined;
    const result = try lookup_batch.step(
        &network.transport_a,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 0), result.progress.started);
    try std.testing.expectEqual(@as(u16, 1), result.progress.failures);
    try std.testing.expectEqual(@as(usize, 1), result.transport.calls_expired);
    try std.testing.expectEqual(caller_handle, expired[0].handle);
    try std.testing.expect(operation.isFinished());
    try std.testing.expectEqual(@as(usize, 0), network.transport_a.engine.calls.count());
}

test "lookup step preserves an unrelated response event" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x25}),
        .enr_sequence = network.record_a.sequence,
    } };
    const caller_handle = try network.transport_a.startCall(
        std.testing.io,
        endpoint(&network.record_c),
        &network.record_c,
        &request,
    );
    var cursor: lookup_batch.Cursor = .{};
    var expired: [4]CallTable.Expired = undefined;
    const answered = try network.transport_c.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.progress.standard_responses);

    var seed_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds = network.transport_a.engine.closestNodes(&network.record_c.node_id, &seed_buffer);
    var operation: Lookup = undefined;
    var operation_candidates: Lookup.Candidates = undefined;
    try operation.init(&operation_candidates, network.record_a.node_id, network.record_c.node_id, seeds, .dual);
    defer operation.cancel(&network.transport_a.engine);

    const result = try lookup_batch.step(
        &network.transport_a,
        std.testing.io,
        &.{&operation},
        &cursor,
        &expired,
    );
    try std.testing.expectEqual(@as(u16, 1), result.progress.started);
    try std.testing.expectEqual(@as(u16, 0), result.progress.responses);
    try std.testing.expect(result.consumed == null);
    try std.testing.expect(result.transport.event == .response);
    try std.testing.expectEqual(
        caller_handle,
        result.transport.event.response.matched.handle,
    );
}

test "two caller-owned lookups share one transport" {
    var network: LookupNetwork = undefined;
    try network.init(1_000);
    defer network.deinit();

    const peer_c = endpoint(&network.record_c);
    _ = try network.transport_a.engine.confirmPeer(&peer_c, &network.record_c, 0);
    var seeds_b_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds_b = network.transport_a.engine.closestNodes(
        &network.record_b.node_id,
        &seeds_b_buffer,
    );
    var operation_b: Lookup = undefined;
    var operation_b_candidates: Lookup.Candidates = undefined;
    try operation_b.init(
        &operation_b_candidates,
        network.record_a.node_id,
        network.record_b.node_id,
        seeds_b,
        .dual,
    );
    defer operation_b.cancel(&network.transport_a.engine);
    var seeds_c_buffer: [Lookup.result_max]RoutingTable.Entry = undefined;
    const seeds_c = network.transport_a.engine.closestNodes(
        &network.record_c.node_id,
        &seeds_c_buffer,
    );
    var operation_c: Lookup = undefined;
    var operation_c_candidates: Lookup.Candidates = undefined;
    try operation_c.init(
        &operation_c_candidates,
        network.record_a.node_id,
        network.record_c.node_id,
        seeds_c,
        .dual,
    );
    defer operation_c.cancel(&network.transport_a.engine);

    var cursor: lookup_batch.Cursor = .{};
    var expired: [4]CallTable.Expired = undefined;
    var responses_b: usize = 0;
    var responses_c: usize = 0;
    for (0..32) |_| {
        if (operation_b.isFinished() and operation_c.isFinished()) break;
        const result = try lookup_batch.step(
            &network.transport_a,
            std.testing.io,
            &.{ &operation_b, &operation_c },
            &cursor,
            &expired,
        );
        try std.testing.expect(result.transport.event != .response or result.consumed != null);
        if (result.consumed) |index| switch (index) {
            0 => responses_b += 1,
            1 => responses_c += 1,
            else => return error.TestUnexpectedResult,
        };
        _ = try network.transport_b.step(std.testing.io, &expired);
        _ = try network.transport_c.step(std.testing.io, &expired);
    }
    try std.testing.expect(operation_b.isFinished());
    try std.testing.expect(operation_c.isFinished());
    try std.testing.expectEqual(@as(usize, 2), responses_b);
    try std.testing.expectEqual(@as(usize, 2), responses_c);
    try std.testing.expectEqual(@as(usize, 0), network.transport_a.engine.calls.count());

    var records: [Lookup.result_max]enr.Record = undefined;
    const results_b = operation_b.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results_b.len);
    try std.testing.expectEqual(network.record_b.node_id, results_b[0].node_id);
    const results_c = operation_c.results(&records);
    try std.testing.expectEqual(@as(usize, 2), results_c.len);
    try std.testing.expectEqual(network.record_c.node_id, results_c[0].node_id);
}

const Pair = struct {
    record_a: enr.Record,
    record_b: enr.Record,
    transport_a: Transport,
    transport_b: Transport,
    candidate_id: types.NodeId,

    fn init(self: *Pair, request_timeout_ms: u64, install_session: bool) !void {
        const loopback = net.IpAddress{ .ip4 = .loopback(0) };
        self.transport_a.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport_a.sockets.close(std.testing.io);
        self.transport_b.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport_b.sockets.close(std.testing.io);

        const key_a = try keyPair(0x11);
        const key_b = try keyPair(0x22);
        self.record_a = try enr.Record.create(&key_a, 1, self.transport_a.localAddress());
        self.record_b = try enr.Record.create(&key_b, 1, self.transport_b.localAddress());
        const config = Engine.Config{
            .session_capacity = 4,
            .challenge_capacity = 4,
            .call_capacity = 4,
            .request_timeout_ms = request_timeout_ms,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        };
        try self.transport_a.init(std.testing.allocator, self.transport_a.sockets, key_a, self.record_a, .{ .engine = config, .poll_interval_ms = 10 });
        errdefer self.transport_a.engine.deinit(std.testing.allocator);
        try self.transport_b.init(std.testing.allocator, self.transport_b.sockets, key_b, self.record_b, .{ .engine = config, .poll_interval_ms = 10 });
        errdefer self.transport_b.engine.deinit(std.testing.allocator);

        if (install_session) {
            const peer_a = endpoint(&self.record_a);
            const peer_b = endpoint(&self.record_b);
            const session_key = [_]u8{0x55} ** 16;
            const active = SessionStore.Session{
                .read_key = session_key,
                .write_key = session_key,
            };
            self.transport_a.engine.channel.sessions.install(peer_b, &active, 0);
            self.transport_b.engine.channel.sessions.install(peer_a, &active, 0);
        }
    }

    fn deinit(self: *Pair) void {
        self.transport_b.deinit(std.testing.allocator, std.testing.io);
        self.transport_a.deinit(std.testing.allocator, std.testing.io);
    }

    fn fillBucket(self: *Pair) !void {
        const incumbent_peer = endpoint(&self.record_b);
        try std.testing.expect(types.logDistance(
            &self.record_a.node_id,
            &self.record_b.node_id,
        ) > 8);
        try std.testing.expectEqual(
            RoutingTable.PutResult.inserted,
            try self.transport_a.engine.confirmPeer(&incumbent_peer, &self.record_b, 0),
        );
        for (1..RoutingTable.bucket_size) |index| {
            const node_id = variantNodeId(self.record_b.node_id, @intCast(index));
            const address = address4(10, @intCast(index), 0, 1, @intCast(10_000 + index));
            var record = fakeRecord(node_id, address, 0);
            const peer = types.Endpoint{ .node_id = node_id, .address = address };
            try std.testing.expectEqual(
                RoutingTable.PutResult.inserted,
                try self.transport_a.engine.confirmPeer(&peer, &record, @intCast(index)),
            );
        }
        self.candidate_id = variantNodeId(self.record_b.node_id, RoutingTable.bucket_size);
        const candidate_address = address4(10, 200, 0, 1, 10_200);
        var candidate_record = fakeRecord(self.candidate_id, candidate_address, 0);
        const candidate_peer = types.Endpoint{
            .node_id = self.candidate_id,
            .address = candidate_address,
        };
        const pending = try self.transport_a.engine.confirmPeer(&candidate_peer, &candidate_record, 20);
        switch (pending) {
            .pending => |node_id| try std.testing.expectEqualSlices(
                u8,
                &self.record_b.node_id,
                &node_id,
            ),
            else => return error.TestUnexpectedResult,
        }
    }
};

const LookupNetwork = struct {
    record_a: enr.Record,
    record_b: enr.Record,
    record_c: enr.Record,
    transport_a: Transport,
    transport_b: Transport,
    transport_c: Transport,

    fn init(self: *LookupNetwork, request_timeout_ms: u64) !void {
        const loopback = net.IpAddress{ .ip4 = .loopback(0) };
        self.transport_a.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport_a.sockets.close(std.testing.io);
        self.transport_b.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport_b.sockets.close(std.testing.io);
        self.transport_c.sockets = try Sockets.bind(std.testing.io, .single(loopback));
        errdefer self.transport_c.sockets.close(std.testing.io);

        const key_a = try keyPair(0x11);
        const key_b = try keyPair(0x22);
        const key_c = try keyPair(0x33);
        self.record_a = try enr.Record.create(&key_a, 1, self.transport_a.localAddress());
        self.record_b = try enr.Record.create(&key_b, 1, self.transport_b.localAddress());
        self.record_c = try enr.Record.create(&key_c, 1, self.transport_c.localAddress());
        const config = Engine.Config{
            .session_capacity = 4,
            .challenge_capacity = 4,
            .call_capacity = 4,
            .request_timeout_ms = request_timeout_ms,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        };
        try self.transport_a.init(std.testing.allocator, self.transport_a.sockets, key_a, self.record_a, .{ .engine = config, .poll_interval_ms = 10 });
        errdefer self.transport_a.engine.deinit(std.testing.allocator);
        try self.transport_b.init(std.testing.allocator, self.transport_b.sockets, key_b, self.record_b, .{ .engine = config, .poll_interval_ms = 10 });
        errdefer self.transport_b.engine.deinit(std.testing.allocator);
        try self.transport_c.init(std.testing.allocator, self.transport_c.sockets, key_c, self.record_c, .{ .engine = config, .poll_interval_ms = 10 });
        errdefer self.transport_c.engine.deinit(std.testing.allocator);

        installSession(&self.transport_a.engine, endpoint(&self.record_b), 0x51);
        installSession(&self.transport_b.engine, endpoint(&self.record_a), 0x51);
        installSession(&self.transport_a.engine, endpoint(&self.record_c), 0x52);
        installSession(&self.transport_c.engine, endpoint(&self.record_a), 0x52);

        const peer_b = endpoint(&self.record_b);
        const peer_c = endpoint(&self.record_c);
        _ = try self.transport_a.engine.confirmPeer(&peer_b, &self.record_b, 0);
        _ = try self.transport_b.engine.confirmPeer(&peer_c, &self.record_c, 0);
    }

    fn deinit(self: *LookupNetwork) void {
        self.transport_c.deinit(std.testing.allocator, std.testing.io);
        self.transport_b.deinit(std.testing.allocator, std.testing.io);
        self.transport_a.deinit(std.testing.allocator, std.testing.io);
    }
};

fn variantNodeId(base: types.NodeId, salt: u8) types.NodeId {
    var result = base;
    result[31] ^= salt;
    return result;
}

test "transport reports truncation alongside already produced expiries" {
    var pair: Pair = undefined;
    try pair.init(1_000, true);
    defer pair.deinit();
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x45}),
        .enr_sequence = pair.record_a.sequence,
    } };
    var output: [1_280]u8 = undefined;
    const started = try pair.transport_a.engine.startCall(
        &output,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
        0,
        &test_support.sealEntropy(0x33),
    );
    const destination = pair.transport_a.sockets.primary().address;
    const oversized = [_]u8{0xff} ** 1_281;
    try pair.transport_b.sockets.primary().send(std.testing.io, &destination, &oversized);
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(?Transport.Error, null), result.failure);
    try std.testing.expect(result.datagram == .rejected);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(started.handle, expired[0].handle);
    const next = try pair.transport_a.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "transport preserves expiry delivery when the host cannot receive" {
    var pair: Pair = undefined;
    try pair.init(100, true);
    defer pair.deinit();
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x46}),
        .enr_sequence = pair.record_a.sequence,
    } };
    var output: [1_280]u8 = undefined;
    const started = try pair.transport_a.engine.startCall(
        &output,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
        0,
        &test_support.sealEntropy(0x33),
    );
    var host = PollFailure{ .now_ms = 100 };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(error.ConcurrencyUnavailable, result.failure.?);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(started.handle, expired[0].handle);
    const next = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "transport polls no later than a pending call deadline" {
    var pair: Pair = undefined;
    try pair.init(105, true);
    defer pair.deinit();
    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x47}),
        .enr_sequence = pair.record_a.sequence,
    } };
    var output: [1_280]u8 = undefined;
    _ = try pair.transport_a.engine.startCall(
        &output,
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
        0,
        &test_support.sealEntropy(0x33),
    );
    var host = PollFailure{ .now_ms = 100 };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(error.ConcurrencyUnavailable, result.failure.?);
    try std.testing.expectEqual(@as(i96, 5), host.poll_ms.?);
    _ = try pair.transport_a.stepUntil(host.io(), &expired, 102);
    try std.testing.expectEqual(@as(i96, 2), host.poll_ms.?);
}

const PollFailure = struct {
    now_ms: u64,
    poll_ms: ?i96 = null,

    fn io(self: *PollFailure) std.Io {
        const vtable = comptime blk: {
            var value = std.Io.failing.vtable.*;
            value.now = now;
            value.batchAwaitConcurrent = receive;
            break :blk value;
        };
        return .{ .userdata = self, .vtable = &vtable };
    }

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *PollFailure = @ptrCast(@alignCast(context.?));
        return .{ .nanoseconds = @as(i96, self.now_ms) * std.time.ns_per_ms };
    }

    fn receive(context: ?*anyopaque, _: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self: *PollFailure = @ptrCast(@alignCast(context.?));
        self.poll_ms = timeout.duration.raw.toMilliseconds();
        return error.ConcurrencyUnavailable;
    }
};

test "transport cancels a discovery call dropped by local pressure without recording a remote timeout" {
    var pair: Pair = undefined;
    try pair.init(1_000, false);
    defer pair.deinit();
    var faults: @import("udp").testing.FaultIo = .{ .send = .{}, .send_failure = error.SystemResources };
    faults.init(std.testing.io);
    defer faults.deinit();
    const request: message.Message = .{ .ping = .{ .request_id = try .init(&.{1}), .enr_sequence = pair.record_a.sequence } };
    try std.testing.expectError(error.SystemResources, pair.transport_a.startCall(faults.io(), endpoint(&pair.record_b), &pair.record_b, &request));
    try std.testing.expectEqual(@as(usize, 1), faults.send_calls);
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
    const pressure = @intFromEnum(@import("udp").SendPressure.system_resources);
    try std.testing.expectEqual(@as(u64, 1), pair.transport_a.send_drops.datagrams[pressure]);
    try std.testing.expect(pair.transport_a.send_drops.bytes[pressure] > 0);
    var expired: [4]CallTable.Expired = undefined;
    const now = try Transport.monotonicMilliseconds(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.tick(now + 2_000, &expired).calls);
}

test "discovery ready steps expire calls with no eligible socket and preserve late arrivals" {
    var pair: Pair = undefined;
    try pair.init(1, true);
    defer pair.deinit();
    var output: [1280]u8 = undefined;
    const started = try pair.transport_a.engine.startCall(&output, endpoint(&pair.record_b), &pair.record_b, &.{ .ping = .{
        .request_id = try .init(&.{0x55}),
        .enr_sequence = pair.record_a.sequence,
    } }, 0, &test_support.sealEntropy(0x33));
    var faults: @import("udp").testing.FaultIo = .{ .receive = .{} };
    faults.init(std.testing.io);
    defer faults.deinit();
    var eligible: [2]bool = @splat(false);
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.stepReady(faults.io(), &expired, &eligible);
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(started.handle, expired[0].handle);
    try std.testing.expectEqual(@as(usize, 0), faults.receive_calls);
    try pair.transport_b.sockets.sendTo(std.testing.io, pair.transport_a.localAddress(), &.{0xff}, 1280);
    const late = try pair.transport_a.stepReady(faults.io(), &expired, &eligible);
    try std.testing.expect(late.datagram == .timeout and late.failure == null);
    try std.testing.expectEqual(@as(usize, 0), faults.receive_calls);
    eligible = .{ true, false };
    const next = try pair.transport_a.stepReady(std.testing.io, &expired, &eligible);
    try std.testing.expect(next.datagram == .rejected and next.failure == null);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "discovery ready steps retain one family mask through the drain" {
    const key = try keyPair(0x66);
    var sockets = try Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    var owned = true;
    defer if (owned) sockets.close(std.testing.io);
    const record = try enr.Record.create(&key, 1, sockets.localAddress());
    var transport: Transport = undefined;
    try transport.init(std.testing.allocator, sockets, key, record, .{});
    owned = false;
    defer transport.deinit(std.testing.allocator, std.testing.io);
    const addresses = transport.sockets.localAddresses();
    for (addresses) |address| try transport.sockets.sendTo(std.testing.io, address.?, &.{0xff}, 1280);
    var faults: @import("udp").testing.FaultIo = .{ .receive = .{ .socket = transport.sockets.values[1].?.handle } };
    faults.init(std.testing.io);
    defer faults.deinit();
    var eligible: [2]bool = .{ true, false };
    var expired: [4]CallTable.Expired = undefined;
    const first = try transport.stepReady(faults.io(), &expired, &eligible);
    try std.testing.expect(first.datagram == .rejected and first.failure == null);
    const empty = try transport.stepReady(faults.io(), &expired, &eligible);
    try std.testing.expect(empty.datagram == .timeout and empty.failure == null);
    try std.testing.expectEqual([2]bool{ false, false }, eligible);
    const reads = faults.receive_calls;
    _ = try transport.stepReady(faults.io(), &expired, &eligible);
    try std.testing.expectEqual(reads, faults.receive_calls);
    eligible = .{ false, true };
    const next = try transport.stepReady(std.testing.io, &expired, &eligible);
    try std.testing.expect(next.datagram == .rejected and next.failure == null);
}
