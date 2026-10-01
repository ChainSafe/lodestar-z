const std = @import("std");
const CallTable = @import("CallTable.zig");
const Transport = @import("Transport.zig");
const Maintenance = @import("Maintenance.zig");
const message = @import("wire/message.zig");
const Sockets = @import("udp").Sockets;
const test_support = @import("test_support.zig");
const Pair = @import("transport_test_support.zig").Pair;
const types = @import("types.zig");
const address4 = test_support.address4;
const endpoint = test_support.endpoint;

test "transport rejects invalid polling and missing expiry storage" {
    var instance: Transport = undefined;
    var host: test_support.ManualIo = .{};
    var sockets = try Sockets.bind(host.io(), .{ .ip4 = .loopback(0) });
    defer sockets.close(host.io());
    try std.testing.expectError(error.InvalidPollInterval, instance.init(std.testing.allocator, sockets, undefined, undefined, .{ .poll_interval_ms = 0 }));
    try std.testing.expectError(error.MissingExpiryStorage, instance.step(undefined, &.{}));
}

test "transport refuses exhausted packet admission before entropy or decoding" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 1_000, false);
    defer pair.deinit();
    const limits = @import("Admission.zig");
    for (0..limits.packet_global_quota.burst) |i| {
        const source = address4(192, 0, 2, @intCast(i), 9_000);
        try std.testing.expect(pair.transport_a.engine.channel.admission.allow(.packet, &source, 0));
    }
    setup_io.datagram = .{ .from = pair.transport_b.localAddress(), .bytes = &([_]u8{0} ** 63) };
    var host = @import("fault_io"){ .base = setup_io.io(), .entropy = .{} };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(types.RejectReason.admission_limited, result.datagram.rejected);
    try std.testing.expectEqual(@as(usize, 0), host.entropy_calls);
    try std.testing.expectEqual(@as(usize, 0), host.send_calls);
}

test "maintenance bounds local replacement probe retries without blocking transport receive" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 1_000, true);
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
    setup_io.now_ms = 999;
    setup_io.datagram = .{ .from = pair.transport_b.localAddress(), .bytes = &.{0xff}, .truncated = true };
    var expired: [4]CallTable.Expired = undefined;
    const received = try pair.transport_a.step(setup_io.io(), &expired);
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

test "transport returns call expiries when rejecting a malformed datagram" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 1, true);
    defer pair.deinit();

    const request = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x45}),
        .enr_sequence = pair.record_a.sequence,
    } };
    var host: test_support.ManualIo = .{};
    const handle = try pair.transport_a.startCall(
        host.io(),
        endpoint(&pair.record_b),
        &pair.record_b,
        &request,
    );
    host.receive_advance_ms = 1;
    host.datagram = .{ .from = pair.transport_b.localAddress(), .bytes = &.{0xff} };

    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(?Transport.Error, null), result.failure);
    try std.testing.expect(result.datagram == .rejected);
    try std.testing.expectEqual(types.RejectReason.malformed_packet, result.datagram.rejected);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(handle, expired[0].handle);
    try std.testing.expectEqual(@as(u64, 1), result.now_ms);
    const next = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "transport reports truncation alongside already produced expiries" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 1_000, true);
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
    var host: test_support.ManualIo = .{
        .now_ms = 1_000,
        .datagram = .{ .from = pair.transport_b.localAddress(), .bytes = &.{0xff}, .truncated = true },
    };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(?Transport.Error, null), result.failure);
    try std.testing.expect(result.datagram == .rejected);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(started.handle, expired[0].handle);
    const next = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "transport preserves expiry delivery when the host cannot receive" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 100, true);
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
    var host: test_support.ManualIo = .{ .now_ms = 100, .receive_failure = error.ConcurrencyUnavailable };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(error.ConcurrencyUnavailable, result.failure.?);
    try std.testing.expectEqual(Transport.FailureStage.receive, result.failure_stage);
    try std.testing.expectEqual(@as(usize, 1), result.calls_expired);
    try std.testing.expectEqual(started.handle, expired[0].handle);
    const next = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(@as(usize, 0), next.calls_expired);
}

test "transport polls no later than a pending call deadline" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 105, true);
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
    var host: test_support.ManualIo = .{ .now_ms = 100, .receive_failure = error.ConcurrencyUnavailable };
    var expired: [4]CallTable.Expired = undefined;
    const result = try pair.transport_a.step(host.io(), &expired);
    try std.testing.expectEqual(error.ConcurrencyUnavailable, result.failure.?);
    try std.testing.expectEqual(Transport.FailureStage.receive, result.failure_stage);
    try std.testing.expectEqual(@as(i96, 5), host.poll_ms.?);
    _ = try pair.transport_a.stepUntil(host.io(), &expired, 102);
    try std.testing.expectEqual(@as(i96, 2), host.poll_ms.?);
}

test "transport cancels a discovery call dropped by local pressure without recording a remote timeout" {
    var setup_io: test_support.ManualIo = .{};
    var pair: Pair = undefined;
    try pair.init(setup_io.io(), 1_000, false);
    defer pair.deinit();
    var faults: @import("fault_io") = .{ .base = setup_io.io(), .send = .{}, .send_failure = error.SystemResources };
    const request: message.Message = .{ .ping = .{ .request_id = try .init(&.{1}), .enr_sequence = pair.record_a.sequence } };
    try std.testing.expectError(error.SystemResources, pair.transport_a.startCall(faults.io(), endpoint(&pair.record_b), &pair.record_b, &request));
    try std.testing.expectEqual(@as(usize, 1), faults.send_calls);
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.calls.count());
    const pressure = @intFromEnum(@import("udp").Sockets.SendDrops.Reason.system_resources);
    try std.testing.expectEqual(@as(u64, 1), pair.transport_a.send_drops.datagrams[pressure]);
    try std.testing.expect(pair.transport_a.send_drops.bytes[pressure] > 0);
    var expired: [4]CallTable.Expired = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.transport_a.engine.tick(2_000, &expired).calls);
}
