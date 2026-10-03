const std = @import("std");
const Transport = @import("transport.zig").Transport;
const Engine = @import("quic/Engine.zig");
const support = @import("transport_test_support.zig");
const Node = support.Node;
const quic_test = @import("quic/test_support.zig");
const FaultIo = @import("fault_io");

test "transport bounds an idle step by the requested wait" {
    var node: Node = .{};
    try node.init(6);
    defer node.deinit();

    var events: [4]Engine.Event = undefined;
    const started = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const result = try support.step(&node.transport, std.testing.io, &events, .{ .wait_max_ms = 5 });
    const elapsed = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - started;
    try std.testing.expect(elapsed < 200);
    try std.testing.expectEqual(@as(usize, 0), result.events);
    try std.testing.expect(!result.backlog);
    try std.testing.expect(node.transport.nextDeadlineNs() == null);

    const floored = try support.step(&node.transport, std.testing.io, &events, .{ .wait_max_ms = 0 });
    try std.testing.expectEqual(@as(u32, 0), floored.datagrams_received);
}

test "transport progress early clock failure does not begin or publish a turn" {
    var node: Node = .{};
    try node.init(39);
    defer node.deinit();
    const now = try Transport.currentTime(std.testing.io);
    const failed = try node.transport.engine.dial(&quic_test.server_address, node.transport.peerId(), now);
    try std.testing.expect(node.transport.engine.failSend(failed));
    var faults: FaultIo = .{ .clock = .{} };
    const io = faults.io();
    var events: [4]Engine.Event = undefined;
    const result = @import("transport_driver.zig").step(&node.transport, io, &events, .{ .wait_max_ms = 0 });
    try std.testing.expectEqual(error.ClockOutOfRange, result.failure.?);
    try std.testing.expectEqual(@as(u64, 0), result.progress.now.mono_ms);
    try std.testing.expectEqual(@as(usize, 0), result.progress.events);
    try std.testing.expectEqual(@as(u32, 0), result.progress.datagrams_sent);
    try std.testing.expect(node.transport.engine.eventsPending());
    const next = @import("transport_driver.zig").step(&node.transport, std.testing.io, &events, .{ .wait_max_ms = 0 });
    try std.testing.expectEqual(@as(usize, 1), next.progress.events);
    try std.testing.expectEqual(failed, events[0].closed.conn);
}

test "transport driver keeps receive progress when the post-wait clock read fails" {
    var node: Node = .{};
    try node.init(40);
    defer node.deinit();
    try node.transport.sockets.primary().send(std.testing.io, &node.transport.sockets.primary().address, "invalid");
    var vtable = std.testing.io.vtable.*;
    vtable.now = ReceiveClockFault.clock;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    ReceiveClockFault.calls = 0;
    const result = @import("transport_driver.zig").step(&node.transport, io, &.{}, .{ .wait_max_ms = 0 });
    try std.testing.expectEqual(error.ClockOutOfRange, result.failure.?);
    try std.testing.expectEqual(@as(u32, 1), result.progress.datagrams_received);
    try std.testing.expectEqual(@as(u32, 1), result.progress.datagrams_dropped);
    try std.testing.expect(result.progress.now.mono_ms > 0);
}

const ReceiveClockFault = struct {
    threadlocal var calls: usize = 0;
    fn clock(userdata: ?*anyopaque, value: std.Io.Clock) std.Io.Timestamp {
        calls += 1;
        if (calls > 2) return .{ .nanoseconds = -1 };
        return std.testing.io.vtable.now(userdata, value);
    }
};
