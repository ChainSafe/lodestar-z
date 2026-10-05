const std = @import("std");
const Setup = @import("network_core_test_support.zig").Setup;
const Source = @import("wake_sources.zig").Source;
const types = @import("types.zig");
const Dialing = @import("peers/dialing.zig").Dialing;
const time = @import("time.zig");
const NetworkCore = @import("network_core.zig").NetworkCore;
const test_support = @import("quic/test_support.zig");
const fault_io = @import("fault_io");
const wait = @import("wait.zig");

test "core connection deadlines preserve fractions through millisecond expiry" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    var now = setup.pair.now;
    now.monotonic.raw.nanoseconds += 900_000;
    const identity = setup.server.peerId();
    const addresses = [_]types.Address{setup.server.transport.localAddress()};
    try std.testing.expectError(error.InvalidDeadline, core.connectUntil(&identity, &addresses, now, now.monotonic));
    const deadline = now.monotonic.addDuration(.{ .clock = .awake, .raw = .fromNanoseconds(500_000) });
    try core.connectUntil(&identity, &addresses, now, deadline);
    const catalog = &core.peer_manager.catalog;
    const peer = catalog.find(&identity).?;
    var close: [Dialing.attempts_max]types.Handle = undefined;
    const due_ms = now.millis() + 2;
    try std.testing.expectEqual(due_ms, catalog.rowFor(peer).?.dial.manual_until_ms);
    now.monotonic = time.milliseconds(due_ms - 1);
    try std.testing.expectEqual(@as(usize, 0), core.peer_manager.expireDials(now, &close).len);
    try std.testing.expectEqual(due_ms, catalog.rowFor(peer).?.dial.manual_until_ms);
    try std.testing.expectError(error.InvalidDeadline, core.connectUntil(&identity, &addresses, now, setup.pair.now.monotonic));
    now.monotonic = time.milliseconds(due_ms);
    try std.testing.expectEqual(@as(usize, 0), core.peer_manager.expireDials(now, &close).len);
    try std.testing.expect(catalog.find(&identity) == null);
}

test "core advance uses supplied time and schedules deferred application shutdown" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    core.protocols.quiesceApplications();
    const before = core.wakeups(setup.pair.now, .{});
    try std.testing.expect(before.sources[@intFromEnum(Source.gossip)].runnable);
    var tick = setup.pair.now;
    tick.monotonic = time.milliseconds(tick.millis() + 1);
    const result = core.advance(setup.pair.io(), .{ .now = tick, .readiness = .{} }, .{}, .{});
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(tick, result.transport.now);
    try std.testing.expectEqual(.closed, core.protocols.applications);
    const after = core.wakeups(tick, .{});
    try std.testing.expect(!after.sources[@intFromEnum(Source.gossip)].runnable);
}

test "core close delivery schedules retirement before it becomes closed" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const core = &setup.client;
    const now = setup.pair.now;
    core.shutdown(now);
    try std.testing.expect(!core.isClosed());
    try setup.pair.pump();
    const closed = core.advance(setup.pair.io(), .{ .now = now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(closed.failure == null);
    var closed_count: usize = 0;
    for (closed.transport_events) |event| closed_count += @intFromBool(event == .closed);
    try std.testing.expectEqual(@as(usize, 1), closed_count);
    try std.testing.expect(core.transport.engine.releasesPending());
    try std.testing.expect(!core.isClosed());
    const pending = core.wakeups(now, .{});
    try std.testing.expect(pending.sources[@intFromEnum(Source.transport_events)].runnable);
    const retired = core.advance(setup.pair.io(), .{ .now = now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(retired.failure == null);
    try std.testing.expectEqual(@as(usize, 0), retired.transport_events.len);
    try std.testing.expect(core.isClosed());
    try std.testing.expect(!core.transport.engine.releasesPending());
}

test "core advance preserves completed events when readiness fails" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    const failed = try setup.pair.dial();
    try std.testing.expect(core.transport.engine.failSend(failed));
    const result = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{ .failure = error.WaitFailed } }, .{}, .{});
    try std.testing.expectEqual(error.WaitFailed, result.failure.?);
    try std.testing.expectEqual(@as(usize, 1), result.transport_events.len);
    try std.testing.expect(result.transport_events[0] == .closed);
}

test "core shutdown drains a cancelled request once before retirement" {
    const rr = @import("reqresp/root.zig");
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const core = &setup.client;
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    defer core.shutdown(setup.pair.now);
    const request = try core.sendReqRespRequest(&setup.server.peerId(), .blocks_by_root_v2, &([_]u8{0} ** 32), sink, .{}, setup.pair.now);
    core.shutdown(setup.pair.now);
    try setup.pair.pump();
    _ = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{} }, .{}, .{});
    _ = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{} }, .{}, .{});
    try std.testing.expect(!core.isClosed());
    const blocked = core.waitPlan(setup.pair.now, .{}, .{});
    try std.testing.expect(blocked.timeout.deadline.compare(.gt, blocked.now.monotonic));
    var output: [1]rr.ReqResp.Event = undefined;
    try std.testing.expect(core.waitPlan(setup.pair.now, .{ .application = &output }, .{}).timeout.deadline.compare(.eq, setup.pair.now.monotonic));
    const delivered = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{} }, .{ .application = &output }, .{});
    try std.testing.expectEqual(@as(usize, 1), delivered.counts.application);
    try std.testing.expectEqual(request, output[0].failed.request);
    try std.testing.expectEqual(.cancelled, output[0].failed.reason);
    try std.testing.expect(!core.isClosed());
    const retired = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{} }, .{ .application = &output }, .{});
    try std.testing.expectEqual(@as(usize, 0), retired.counts.application);
    try std.testing.expect(core.isClosed());
}

test "core shutdown waits for retained host serving work after stream retirement" {
    const rr = @import("reqresp/root.zig");
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    defer setup.client.shutdown(setup.pair.now);
    _ = try setup.client.sendReqRespRequest(&setup.server.peerId(), .blocks_by_root_v2, &([_]u8{0} ** 32), sink, .{}, setup.pair.now);
    const core = &setup.server;
    var output: [1]rr.ReqResp.Event = undefined;
    var retained: ?rr.ReqResp.RequestHandle = null;
    var serving: ?rr.ReqResp.ServingHandle = null;
    for (0..50) |_| {
        try setup.pair.pump();
        _ = try setup.turn(&setup.client, .{});
        const result = try setup.turn(core, .{ .application = &output });
        if (result.counts.application == 1 and output[0] == .request) {
            retained = output[0].request.request;
            serving = core.retainServing(retained.?) orelse return error.TestUnexpectedResult;
            break;
        }
    }
    try std.testing.expect(retained != null);
    const host_socket = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer host_socket.close(std.testing.io);
    try core.setHostWake(host_socket.handle);
    defer core.setHostWake(null) catch unreachable;
    core.shutdown(setup.pair.now);
    try std.testing.expectError(error.ProtocolDisabled, core.protocols.request(&core.transport.engine, .{ .index = 0, .generation = 1 }, .ping_v1, &.{}, &.{}, .{}, setup.pair.now));
    var terminal_count: usize = 0;
    for (0..5) |_| {
        try setup.pair.pump();
        const result = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = .{} }, .{ .application = &output }, .{});
        if (result.counts.application == 1 and output[0] == .failed) {
            try std.testing.expectEqual(retained.?, output[0].failed.request);
            terminal_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), terminal_count);
    try std.testing.expectEqual(@as(u16, 0), core.transport.engine.resourceSnapshot().active);
    try std.testing.expect(!core.isClosed());
    try std.testing.expect(core.waitPlan(setup.pair.now, .{ .application = &output }, .{}).timeout.deadline.compare(.gt, setup.pair.now.monotonic));
    const Completion = struct {
        socket: std.Io.net.Socket,
        serving: rr.ReqResp.ServingHandle,
        released: bool = false,

        fn apply(context: *anyopaque, owner: *NetworkCore, _: types.Now) NetworkCore.HostProgress {
            const self: *@This() = @ptrCast(@alignCast(context));
            var byte: [1]u8 = undefined;
            const packet = self.socket.receiveTimeout(std.testing.io, &byte, .{ .duration = .{ .clock = .awake, .raw = .zero } }) catch return .{};
            if (std.mem.eql(u8, packet.data, "c")) self.released = owner.releaseServing(self.serving);
            return .{};
        }
    };
    var completion: Completion = .{ .socket = host_socket, .serving = serving.? };
    try host_socket.send(std.testing.io, &host_socket.address, "c");
    const ready = wait.poll(std.testing.io, core.waitPlan(setup.pair.now, .{}, .{}).sources, .{ .duration = .{ .clock = .awake, .raw = .zero } });
    try std.testing.expect(ready.host);
    const result = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .readiness = ready }, .{}, .{ .handler = .{ .context = &completion, .apply = Completion.apply } });
    try std.testing.expect(result.failure == null);
    try std.testing.expect(completion.released);
    try std.testing.expect(core.isClosed());
}

test "core clock failure preserves dial intent without starting a connection" {
    const setup = try std.testing.allocator.create(Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const core = &setup.client;
    try core.connectUntil(&setup.server.peerId(), &.{setup.server.transport.localAddress()}, setup.pair.now, time.milliseconds(setup.pair.now.millis() + 10_000));
    const pending = core.waitPlan(setup.pair.now, .{}, .{});
    const dirty = core.peer_manager.catalog.dial.dirty_count;
    const visits = core.peer_manager.dialing.visits;
    try std.testing.expectEqualDeep(pending, core.waitPlan(setup.pair.now, .{}, .{}));
    try std.testing.expectEqual(dirty, core.peer_manager.catalog.dial.dirty_count);
    try std.testing.expectEqual(visits, core.peer_manager.dialing.visits);
    const failed = core.advance(setup.pair.io(), .{ .now = setup.pair.now, .clock_failure = error.ClockOutOfRange }, .{}, .{});
    try std.testing.expectEqual(error.ClockOutOfRange, failed.failure.?);
    try std.testing.expectEqual(@as(u8, 0), failed.dial_started);
    try std.testing.expectEqual(@as(u8, 0), failed.dial_failed);
    const resumed = core.advance(setup.pair.io(), .{ .now = setup.pair.now }, .{}, .{});
    try std.testing.expect(resumed.failure == null);
    try std.testing.expectEqual(@as(u8, 1), resumed.dial_started);
}

test "core lifecycle only advances and closed owners reject new connections" {
    for ([_]bool{ false, true }) |graceful| {
        const setup = try std.testing.allocator.create(Setup);
        defer std.testing.allocator.destroy(setup);
        setup.* = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        const core = &setup.server;
        try std.testing.expectEqual(.running, core.phase());
        if (graceful) {
            core.beginGracefulClose(setup.pair.now);
            core.beginGracefulClose(setup.pair.now);
            try std.testing.expectEqual(.quiescing, core.phase());
            try std.testing.expectError(error.Stopped, core.connectUntil(&setup.client.peerId(), &.{}, setup.pair.now, time.milliseconds(setup.pair.now.millis() + 1)));
            try std.testing.expectError(error.Stopped, core.addDirectPeer(&setup.client.peerId(), &.{}, setup.pair.now));
        } else core.shutdown(setup.pair.now);
        _ = try setup.pair.dial();
        try setup.pair.pump();
        try std.testing.expectEqual(@as(u16, 0), core.transport.engine.resourceSnapshot().active);
        core.shutdown(setup.pair.now);
        core.shutdown(setup.pair.now);
        core.beginGracefulClose(setup.pair.now);
        try std.testing.expectEqual(.stopping, core.phase());
        for (0..3) |_| _ = core.advance(setup.pair.io(), .{ .now = setup.pair.now }, .{}, .{});
        try std.testing.expect(core.isClosed());
        try std.testing.expectError(error.Stopped, core.transport.engine.dial(&test_support.client_address, setup.client.peerId(), setup.pair.now));
        try setup.pair.pump();
        _ = core.advance(setup.pair.io(), .{ .now = setup.pair.now }, .{}, .{});
        try std.testing.expect(core.isClosed());
    }
}

test "core cancellation preserves prior failure and events while stopping further I/O" {
    const Core = @import("network_core.zig").NetworkCore;
    const Host = struct {
        calls: usize = 0,
        fn apply(context: *anyopaque, _: *Core, _: types.Now) Core.HostProgress {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return .{};
        }
    };
    for ([_]bool{ false, true }) |already_cancelled| {
        const setup = try std.testing.allocator.create(Setup);
        defer std.testing.allocator.destroy(setup);
        setup.* = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        const core = &setup.client;
        const failed = try setup.pair.dial();
        try std.testing.expect(core.transport.engine.failSend(failed));
        try core.connectUntil(&setup.server.peerId(), &.{test_support.server_address}, setup.pair.now, time.milliseconds(setup.pair.now.millis() + 1000));
        var host: Host = .{};
        var faults: fault_io = .{ .base = setup.pair.io(), .receive = .{} };
        const result = core.advance(faults.io(), .{
            .now = setup.pair.now,
            .readiness = .{ .cancelled = already_cancelled, .failure = error.WaitFailed, .host = true },
        }, .{}, .{ .handler = .{ .context = &host, .apply = Host.apply } });
        try std.testing.expect(result.cancelled);
        try std.testing.expectEqual(error.WaitFailed, result.failure.?);
        try std.testing.expectEqual(@as(usize, if (already_cancelled) 0 else 1), faults.receive_calls);
        try std.testing.expectEqual(@as(usize, 0), faults.send_calls);
        try std.testing.expectEqual(@as(usize, 0), host.calls);
        try std.testing.expectEqual(@as(u8, 0), result.dial_started);
        try std.testing.expectEqual(@as(usize, 1), result.transport_events.len);
        try std.testing.expectEqual(failed, result.transport_events[0].closed.conn);
    }
}
