const std = @import("std");
const rr = @import("reqresp.zig");
const Protocol = @import("protocol.zig").Protocol;
const Plan = @import("receive_plan.zig").Plan;
const harness = @import("test_pair.zig");
const support = @import("../test_support.zig");
const policy = @import("policy_fixture.zig").config;

fn application(setup: *harness.Pair, which: Protocol, bytes: []const u8, sink: []u8) !rr.RequestHandle {
    return setup.shared.client.reqresp.request(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.handles.client, which, bytes, sink, .{}, setup.shared.pair.now);
}

fn receive(setup: *harness.Pair) !@FieldType(rr.Event, "request") {
    for (0..100) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) return event.request;
            if (event == .failed) return error.UnexpectedFailure;
        }
    }
    return error.RequestNotDelivered;
}

test "reqresp admission lifecycle incomplete requests cannot consume another connection's receive reservation" {
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{ .inbound_max = 2, .inbound_control_reserved = 1 });
    defer setup.deinit();
    for (0..2) |_| {
        const stream = try setup.openRaw(.blocks_by_root_v2);
        try setup.awaitRawSelection(stream, .blocks_by_root_v2);
    }
    try std.testing.expectEqual(@as(u16, 2), setup.shared.server.reqresp.active().inbound);
    try std.testing.expectEqual(@as(usize, 0), setup.shared.server.reqresp.resourceSnapshot().serving_occupied);
    // Let gossip on the first connection settle so the dial reports only the new connection.
    for (0..8) |_| try setup.pumpOnce();
    const second = try support.connectPair(&setup.shared.pair);
    setup.shared.handles = .{ .client = second.client, .server = second.server };
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try application(&setup, .blocks_by_root_v2, &.{}, sink);
    const incoming = try receive(&setup);
    try std.testing.expectEqual(second.server, incoming.peer);
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.reqresp.resourceSnapshot().serving_occupied);
    try std.testing.expectEqual(@as(usize, 2), setup.shared.server.reqresp.resourceSnapshot().inbound_phases[@intFromEnum(rr.metrics.InboundPhase.receiving_request)]);
}

test "reqresp admission lifecycle cancellation retains execution until host retirement" {
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{ .inbound_max = 2, .inbound_control_reserved = 1, .serving_per_peer_max = 1 });
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    const first = try application(&setup, .blocks_by_root_v2, &.{}, sink);
    const incoming = try receive(&setup);
    const owner = &setup.shared.server.reqresp;
    try std.testing.expect(owner.retainServing(incoming.request));
    try std.testing.expect(!owner.retainServing(incoming.request));
    const extra = try std.testing.allocator.alloc(u8, Protocol.blob_sidecars_by_root_v1.info().response_max);
    defer std.testing.allocator.free(extra);
    _ = try application(&setup, .blob_sidecars_by_root_v1, &.{}, extra);
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| try std.testing.expect(event != .request);
    }
    try std.testing.expectEqual(@as(usize, 1), owner.resourceSnapshot().inbound_phases[@intFromEnum(rr.metrics.InboundPhase.ready)]);
    try std.testing.expect(setup.shared.client.reqresp.cancel(first));
    var terminal = false;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            try std.testing.expect(event != .request);
            if (event == .failed and std.meta.eql(event.failed.request, incoming.request)) terminal = true;
        }
    }
    try std.testing.expect(terminal);
    try std.testing.expectEqual(@as(usize, 1), owner.resourceSnapshot().retiring);
    try std.testing.expectEqual(@as(usize, 1), owner.resourceSnapshot().serving_occupied);
    try std.testing.expect(owner.releaseServing(incoming.request));
    try std.testing.expect(!owner.releaseServing(incoming.request));
    const resumed = try receive(&setup);
    try std.testing.expectEqual(Protocol.blob_sidecars_by_root_v1, resumed.protocol);
    try std.testing.expectEqual(@as(usize, 0), owner.resourceSnapshot().retiring);
}

test "reqresp admission lifecycle response permission waits without retaining a generated payload" {
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    var sink: [8]u8 = undefined;
    const bytes = [_]u8{1} ** 8;
    _ = try application(&setup, .ping_v1, &bytes, &sink);
    const incoming = try receive(&setup);
    const owner = &setup.shared.server.reqresp;
    const method = @intFromEnum(Protocol.ping_v1);
    owner.limiter.global[method] = .{ .tokens = 0, .refilled_ms = setup.shared.pair.now.mono_ms };
    try std.testing.expect(!owner.reserveResponse(incoming.request, setup.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 0), owner.inbound[incoming.request.index].request.io.payload.len);
    try std.testing.expectEqual(.waiting_capacity, owner.inbound[incoming.request.index].state);
    const due = owner.nextWakeup(setup.shared.pair.now, .{ .control = 1 }).?;
    try std.testing.expect(due > setup.shared.pair.now.mono_ms);
    setup.shared.pair.advance(due - setup.shared.pair.now.mono_ms);
    try std.testing.expect(owner.reserveResponse(incoming.request, setup.shared.pair.now));
    try owner.respond(incoming.request, &bytes, null, setup.shared.pair.now);
    try std.testing.expectEqual(.writing_chunk, owner.inbound[incoming.request.index].state);
    try std.testing.expect(!owner.inbound[incoming.request.index].response_reserved);
}

test "reqresp admission lifecycle fair dispatch advances to the next peer before another request from a busy peer" {
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{ .inbound_max = 2 });
    defer setup.deinit();
    const owner = &setup.shared.server.reqresp;
    for ([_]u16{ 0, 0, 1, 2 }, 0..) |peer, ordinal| {
        const index = Plan.first(peer, .blocks_by_root_v2) + @intFromBool(ordinal == 1);
        const slot = &owner.inbound[index];
        slot.identity = .{ .bytes = @splat(@as(u8, @intCast(peer + 1))) };
        slot.state = .ready;
        slot.progress_ms = setup.shared.pair.now.mono_ms;
        slot.request = .{
            .direction = .inbound,
            .generation = 1,
            .completion = .active,
            .protocol = .blocks_by_root_v2,
            .conn = .{ .index = peer, .generation = std.math.maxInt(u32) },
            .stream = .{ .conn = .{ .index = peer, .generation = std.math.maxInt(u32) }, .slot = 0, .id = ordinal * 4 },
        };
    }
    var events: [4]rr.Event = undefined;
    const first = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &events });
    try std.testing.expectEqual(@as(usize, 2), first.application);
    try std.testing.expectEqual(@as(u16, 0), events[0].request.peer.index);
    try std.testing.expectEqual(@as(u16, 1), events[1].request.peer.index);
    try std.testing.expect(owner.cancel(events[0].request.request));
    _ = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &events });
    const next = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &events });
    try std.testing.expectEqual(@as(usize, 1), next.application);
    try std.testing.expectEqual(@as(u16, 2), events[0].request.peer.index);
}

fn allocation(allocator: std.mem.Allocator) !void {
    var owner = try rr.ReqResp.init(allocator, .{
        .peers = 2,
        .forks = &.{},
        .admission = try rr.AdmissionOptions.defaults(&policy(), 2, 1, 1),
        .outbound_max = 2,
        .inbound_max = 2,
        .inbound_control_reserved = 1,
    });
    defer owner.deinit();
    for (0..2) |peer| for (std.enums.values(Protocol)) |which| {
        const first = Plan.first(@intCast(peer), which);
        const bounds = owner.policy.requestMaxFor(which);
        try std.testing.expectEqual(bounds, owner.inboundSink(@intCast(first)).len);
        try std.testing.expectEqual(bounds, owner.inboundSink(@intCast(first + 1)).len);
    };
}

test "reqresp admission lifecycle control traffic preserves application quota fairness" {
    const quotas = @import("admission_fixture.zig").quotas(4, 1000);
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{
        .inbound_max = 3,
        .inbound_control_reserved = 1,
        .admission = .{ .policy = policy(), .limits = .{ .identities = 3, .peer = quotas, .global = quotas } },
    });
    defer setup.deinit();
    const owner = &setup.shared.server.reqresp;
    for ([_]Protocol{ .blocks_by_root_v2, .blocks_by_root_v2, .ping_v1 }, 0..) |which, peer| {
        const slot = &owner.inbound[Plan.first(@intCast(peer), which)];
        slot.identity = .{ .bytes = @splat(@as(u8, @intCast(peer + 1))) };
        slot.state = .ready;
        slot.charged_cost = if (peer == 0) 4 else 1;
        slot.progress_ms = setup.shared.pair.now.mono_ms;
        const conn: @import("../types.zig").Handle = .{ .index = @intCast(peer), .generation = std.math.maxInt(u32) };
        slot.request = .{
            .direction = .inbound,
            .generation = 1,
            .completion = .active,
            .protocol = which,
            .conn = conn,
            .stream = .{ .conn = conn, .slot = 0, .id = 0 },
        };
    }
    const heavy = &owner.inbound[Plan.first(0, .blocks_by_root_v2)];
    try std.testing.expectEqual(.allowed, owner.admission.limiter.take(&heavy.identity, .blocks_by_root_v2, 4, .fulu, setup.shared.pair.now.mono_ms));
    var application_events: [4]rr.Event = undefined;
    var control_events: [4]rr.Event = undefined;
    setup.shared.pair.advance(250);
    const first = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &application_events, .control = &control_events });
    try std.testing.expectEqual(@as(usize, 0), first.application);
    try std.testing.expectEqual(@as(usize, 1), first.control);
    try std.testing.expectEqual(@as(u128, 1), heavy.admission_paid);
    setup.shared.pair.advance(250);
    const second = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &application_events, .control = &control_events });
    try std.testing.expectEqual(@as(usize, 1), second.application);
    try std.testing.expectEqual(@as(u16, 1), application_events[0].request.peer.index);
    try std.testing.expectEqual(@as(u128, 1), heavy.admission_paid);
}

test "reqresp admission lifecycle protocol buffers and all startup allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocation, .{});
}

test "reqresp admission lifecycle a fresh burst starts full requests before splitting residual quota" {
    var setup: harness.Pair = .{};
    try setup.init(.{}, .{
        .inbound_max = 3,
        .inbound_control_reserved = 1,
        .admission = .{ .policy = policy(), .limits = .{
            .identities = 4,
            .peer = @import("admission_fixture.zig").quotas(4, 1000),
            .global = @import("admission_fixture.zig").quotas(8, 1000),
        } },
    });
    defer setup.deinit();
    const owner = &setup.shared.server.reqresp;
    for (0..4) |peer| {
        const slot = &owner.inbound[Plan.first(@intCast(peer), .blocks_by_root_v2)];
        slot.identity = .{ .bytes = @splat(@as(u8, @intCast(peer + 1))) };
        slot.state = .ready;
        slot.charged_cost = 4;
        slot.progress_ms = setup.shared.pair.now.mono_ms;
        const conn: @import("../types.zig").Handle = .{ .index = @intCast(peer), .generation = std.math.maxInt(u32) };
        slot.request = .{
            .direction = .inbound,
            .generation = 1,
            .completion = .active,
            .protocol = .blocks_by_root_v2,
            .conn = conn,
            .stream = .{ .conn = conn, .slot = 0, .id = 0 },
        };
    }
    var events: [4]rr.Event = undefined;
    const result = owner.pump(&setup.shared.pair.server, &setup.shared.server.router, setup.shared.pair.now, .{ .application = &events });
    try std.testing.expectEqual(@as(usize, 2), result.application);
    try std.testing.expectEqual(@as(u16, 0), events[0].request.peer.index);
    try std.testing.expectEqual(@as(u16, 1), events[1].request.peer.index);
    try std.testing.expectEqual(@as(u128, 8), owner.counters.charged_work);
}

test "reqresp admission lifecycle a blocked control writer cannot take another peer's execution reserve" {
    var pool = try @import("serving_pool.zig").Pool.init(std.testing.allocator, 6, 2, 4);
    defer pool.deinit(std.testing.allocator);
    const PeerId = @import("../wire/peer_id.zig").PeerId;
    const first: PeerId = .{ .bytes = @splat(1) };
    const second: PeerId = .{ .bytes = @splat(2) };
    const index = pool.available(&first, true).?;
    _ = pool.acquire(index, .{ .direction = .inbound, .index = 0, .generation = 1 }, &first, true);
    try std.testing.expectEqual(@as(?u16, null), pool.available(&first, true));
    try std.testing.expect(pool.available(&second, true) != null);
    try std.testing.expect(pool.available(&first, false) != null);
    pool.retire(index);
    try std.testing.expect(pool.available(&first, true) != null);
}
