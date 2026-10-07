const std = @import("std");
const Now = @import("../types.zig").Now;
const RequestIO = @import("RequestIO.zig");
const rr = @import("ReqResp.zig");
const Protocol = @import("protocol.zig").Protocol;
const ReceiveLayout = @import("ReceiveLayout.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const types = @import("../types.zig");
const support = @import("../quic/test_support.zig");
const Router = @import("../router.zig").Router;
const quotas = @import("admission_fixture.zig").quotas;
const policy_fixture = @import("policy_fixture.zig");
const Engine = @import("../quic/Engine.zig");
const constants = @import("constants.zig");

fn options(connections: u16) rr.Options {
    return .{
        .connections = connections,
        .outbound_max = 1,
        .serving_max = 4,
        .inbound_per_connection_max = 8,
        .forks = &.{},
        .admission = .{ .policy = policy_fixture.config(), .limits = .{
            .identities = 4,
            .peer = quotas(4, 1000),
            .global = quotas(4, 1000),
            .starts = .{ .tokens = 2, .period_ms = 1000 },
        } },
    };
}

fn inboundStream(pair: *support.Pair, conn: types.Handle) !types.StreamHandle {
    const stream = try pair.client.openStream(conn);
    try std.testing.expectEqual(1, try pair.client.write(stream, &.{0}, false));
    try pair.pump();
    var events: [16]Engine.Event = undefined;
    for (pair.events(&pair.server, &events)) |event| {
        if (event == .stream_opened) return event.stream_opened;
    }
    return error.TestUnexpectedResult;
}

test "inbound admission receive exhaustion and selected handoff checks precede the start debit" {
    for ([_]bool{ false, true }) |handoff| {
        var pair: support.Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        const handles = try support.connectPair(&pair);
        var owner = try rr.init(std.testing.allocator, options(128));
        defer owner.deinit();
        var router = try Router.init(std.testing.allocator, .{});
        defer router.deinit();
        defer owner.cancelAll(&pair.server, &router, pair.now);
        const identity = pair.server.peerId(handles.server).?;
        _ = try owner.accept(&pair.server, try inboundStream(&pair, handles.client), .{
            .protocol = .{ .reqresp = .ping_v1 },
            .leftover = &.{},
            .fin = false,
        }, pair.now);
        const first = ReceiveLayout.first(handles.server.index, .metadata_v1);
        owner.inbound[first].request.generation = std.math.maxInt(u32);
        if (!handoff) owner.inbound[first + 1].request.generation = std.math.maxInt(u32);
        var bytes: [RequestIO.read_buffer_length]u8 = @splat(0);
        const leftover: []const u8 = if (handoff) bytes[0 .. owner.inbound[first + 1].receive.read.len + 1] else &.{};
        const refused = try inboundStream(&pair, handles.client);
        defer pair.server.closeStream(refused, 0);
        try std.testing.expectError(if (handoff) error.InvalidHandoff else error.SlotsExhausted, owner.accept(&pair.server, refused, .{
            .protocol = .{ .reqresp = .metadata_v1 },
            .leftover = leftover,
            .fin = false,
        }, pair.now));
        try std.testing.expectEqual(pair.now.millis(), owner.admission.limiter.startAt(&identity, true, pair.now.millis()));
        const third = try owner.accept(&pair.server, try inboundStream(&pair, handles.client), .{
            .protocol = .{ .reqresp = .metadata_v2 },
            .leftover = &.{},
            .fin = false,
        }, pair.now);
        try std.testing.expect(!owner.inbound[third.index].admission.start_pending);
        try std.testing.expectEqual(pair.now.millis() + 500, owner.admission.limiter.startAt(&identity, true, pair.now.millis()));
    }
}

fn readySlot(owner: *rr, peer: u16, which: Protocol, ordinal: u16, identity: PeerId, accepted_ms: u64) u16 {
    std.debug.assert(peer < owner.options.connections);
    std.debug.assert(ordinal < constants.MAX_CONCURRENT_REQUESTS);
    const index: u16 = @intCast(ReceiveLayout.first(peer, which) + ordinal);
    const slot = &owner.inbound[index];
    std.debug.assert(slot.request.available());
    const conn: types.Handle = .{ .index = peer, .generation = 1 };
    slot.identity = identity;
    slot.state = .ready;
    slot.progress_ms = accepted_ms;
    slot.request = .{
        .direction = .inbound,
        .completion = .running,
        .generation = 1,
        .conn = conn,
        .stream = .{ .conn = conn, .id = ordinal * 4, .slot = @intCast(ordinal) },
        .protocol = which,
        .started_ms = accepted_ms,
    };
    return index;
}

fn deferStart(owner: *rr, index: u16, now_ms: u64) void {
    const slot = &owner.inbound[index];
    slot.admission.start_pending = true;
    slot.admission.eligible_ms = owner.admission.limiter.startAt(&slot.identity, slot.request.protocol.isControl(), now_ms);
    slot.admission.wait = if (slot.admission.eligible_ms > now_ms) .start else .none;
    owner.settleSlot(.inbound, index);
}

test "inbound admission delayed decode and equal timestamps retain acceptance then slot ordering" {
    var owner = try rr.init(std.testing.allocator, options(1));
    defer owner.deinit();
    const identity: PeerId = .{ .bytes = @splat(1) };
    const late = readySlot(&owner, 0, .blocks_by_root_v2, 0, identity, 10);
    const early = readySlot(&owner, 0, .blob_sidecars_by_root_v1, 0, identity, 9);
    try std.testing.expect(late < early);
    // The older request decodes after the newer one has joined admission.
    deferStart(&owner, late, 10);
    deferStart(&owner, early, 10);
    owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 10, .unix_s = 0 }));
    try std.testing.expect(owner.inbound[early].request.pendingEvent() != null);
    try std.testing.expect(owner.inbound[late].admission.start_pending);
    owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 10, .unix_s = 0 }));
    try std.testing.expect(owner.inbound[late].request.pendingEvent() != null);

    var ties = try rr.init(std.testing.allocator, options(1));
    defer ties.deinit();
    const low = readySlot(&ties, 0, .blocks_by_root_v2, 0, identity, 20);
    const high = readySlot(&ties, 0, .blob_sidecars_by_root_v1, 0, identity, 20);
    // Reverse readiness order and start the round-robin scan at the higher slot.
    deferStart(&ties, high, 20);
    deferStart(&ties, low, 20);
    ties.admission.connection_cursors[0].admission[0] = @intCast(high);
    ties.admission.promoteReady(&ties, Now.fromMilliseconds(.{ .mono_ms = 20, .unix_s = 0 }));
    try std.testing.expect(ties.inbound[low].request.pendingEvent() != null);
    try std.testing.expect(ties.inbound[high].admission.start_pending);
}

test "inbound admission keeps an incomplete older request out of the ready start order" {
    var owner = try rr.init(std.testing.allocator, options(1));
    defer owner.deinit();
    const identity: PeerId = .{ .bytes = @splat(2) };
    const early = readySlot(&owner, 0, .blocks_by_root_v2, 0, identity, 1);
    owner.inbound[early].state = .receiving_request;
    deferStart(&owner, early, 2);
    const complete = readySlot(&owner, 0, .blob_sidecars_by_root_v1, 0, identity, 2);
    deferStart(&owner, complete, 2);
    owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 2, .unix_s = 0 }));
    try std.testing.expect(owner.inbound[complete].request.pendingEvent() != null);
    try std.testing.expect(owner.inbound[early].admission.start_pending);
}

test "inbound admission wide costs keep incremental credit and share identity quota across connections" {
    var owner = try rr.init(std.testing.allocator, options(2));
    defer owner.deinit();
    const identity: PeerId = .{ .bytes = @splat(3) };
    const large = readySlot(&owner, 0, .blocks_by_root_v2, 0, identity, 0);
    const small = readySlot(&owner, 1, .blocks_by_root_v2, 0, identity, 0);
    owner.inbound[large].admission.decoded(@as(u128, std.math.maxInt(u64)) * 2, 0);
    try std.testing.expectEqual(.allowed, owner.admission.limiter.take(&identity, .blocks_by_root_v2, 4, .phase0, 0));
    owner.settleSlot(.inbound, large);
    owner.settleSlot(.inbound, small);
    owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 0, .unix_s = 0 }));
    for (1..5) |installment| {
        const now: types.Now = Now.fromMilliseconds(.{ .mono_ms = installment * 250, .unix_s = 0 });
        owner.admission.waitEnded(&owner.inbound[large]);
        if (owner.inbound[small].state == .ready) owner.admission.waitEnded(&owner.inbound[small]);
        owner.admission.promoteReady(&owner, now);
        // The rotation lets the small request take the second refill; the large one keeps its credit.
        const expected: u128 = if (installment == 1) 1 else installment - 1;
        try std.testing.expectEqual(expected, owner.inbound[large].admission.paid);
        if (installment == 2) try std.testing.expect(owner.inbound[small].request.pendingEvent() != null);
        if (installment < 2) try std.testing.expect(owner.inbound[small].request.pendingEvent() == null);
    }
    try std.testing.expectEqual(@as(u128, std.math.maxInt(u64)) * 2, owner.inbound[large].admission.cost);
    owner.admission.waitEnded(&owner.inbound[large]);
    owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 1250, .unix_s = 0 }));
    try std.testing.expectEqual(@as(u128, 4), owner.inbound[large].admission.paid);
    try std.testing.expect(owner.inbound[large].request.pendingEvent() != null);
}

test "inbound admission cancellation removes each wait without refunding or spinning" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var router = try Router.init(std.testing.allocator, .{});
    defer router.deinit();
    const Wait = enum { start, tokens, serving };
    for ([_]Wait{ .start, .tokens, .serving }) |wait| {
        var owner = try rr.init(std.testing.allocator, options(1));
        defer owner.deinit();
        const identity: PeerId = .{ .bytes = @splat(4) };
        const index = readySlot(&owner, 0, .blocks_by_root_v2, 0, identity, 0);
        const slot = &owner.inbound[index];
        var serving: ?rr.ServingHandle = null;
        const holder: rr.RequestHandle = .{ .direction = .inbound, .index = index + 1, .generation = 1 };
        switch (wait) {
            .start => {
                for (0..2) |_| try std.testing.expectEqual(.allowed, owner.admission.limiter.start(&identity, false, 0));
                deferStart(&owner, index, 0);
            },
            .tokens => {
                slot.admission.decoded(4, 0);
                try std.testing.expectEqual(.allowed, owner.admission.limiter.take(&identity, .blocks_by_root_v2, 3, .phase0, 0));
            },
            .serving => {
                owner.serving.per_peer_max = 1;
                const execution = owner.serving.available(&identity, false).?;
                _ = owner.serving.acquire(execution, holder, &identity, false);
                serving = owner.retainServing(holder) orelse return error.TestUnexpectedResult;
                owner.serving.retire(execution);
            },
        }
        owner.settleSlot(.inbound, index);
        owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 0, .unix_s = 0 }));
        try std.testing.expectEqualStrings(@tagName(wait), @tagName(slot.admission.wait));
        if (wait == .tokens) try std.testing.expectEqual(@as(u128, 1), slot.admission.paid);
        const start_due = owner.admission.limiter.startAt(&identity, false, 0);
        const tokens_due = owner.admission.limiter.eligibleAt(&identity, .blocks_by_root_v2, 1, .phase0, 0);
        try std.testing.expect(owner.cancel(&pair.server, &router, slot.request.handle(index), Now.fromMilliseconds(.{ .mono_ms = 0, .unix_s = 0 })));
        if (wait == .serving) try std.testing.expect(owner.releaseServing(serving.?));
        try std.testing.expectEqual(start_due, owner.admission.limiter.startAt(&identity, false, 0));
        try std.testing.expectEqual(tokens_due, owner.admission.limiter.eligibleAt(&identity, .blocks_by_root_v2, 1, .phase0, 0));
        try std.testing.expect(!owner.admission.due());
        const visits = owner.visits;
        for (0..32) |_| owner.admission.promoteReady(&owner, Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 }));
        try std.testing.expectEqual(visits, owner.visits);
        try std.testing.expectEqual(@as(usize, 0), owner.resourceSnapshot().serving_occupied);
        try std.testing.expectEqual(@as(u32, 0), owner.admission.ready[0].len);
        owner.admission.checkSlot(slot, index);
    }
}

test "inbound admission fair dispatch advances to the next peer before another request from a busy peer" {
    var opts = options(3);
    opts.work_per_pump_max = 1;
    var owner = try rr.init(std.testing.allocator, opts);
    defer owner.deinit();
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    var indexes: [4]u16 = undefined;
    for ([_]u16{ 0, 0, 1, 2 }, 0..) |peer, ordinal| {
        indexes[ordinal] = readySlot(&owner, peer, .blocks_by_root_v2, @intFromBool(ordinal == 1), .{ .bytes = @splat(@as(u8, @intCast(peer + 1))) }, now.millis());
        owner.settleSlot(.inbound, indexes[ordinal]);
        owner.admission.checkSlot(&owner.inbound[indexes[ordinal]], indexes[ordinal]);
    }
    var admitted: [4]bool = @splat(false);
    for ([_]usize{ 0, 2, 3, 1 }) |expected| {
        owner.admission.promoteReady(&owner, now);
        admitted[expected] = true;
        for (indexes, admitted) |index, ready| {
            const event = owner.inbound[index].request.pendingEvent();
            try std.testing.expectEqual(ready, event != null);
            if (event) |value| {
                try std.testing.expect(value == .request);
                try std.testing.expectEqual(index, value.request.request.index);
            }
            owner.admission.checkSlot(&owner.inbound[index], index);
        }
    }
    try std.testing.expect(!owner.admission.due());
}
