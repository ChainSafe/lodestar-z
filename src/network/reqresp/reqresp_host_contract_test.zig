const std = @import("std");
const rr = @import("reqresp.zig");
const Pair = @import("test_pair.zig").Pair;

fn request(pair: *Pair, bytes: []const u8, sink: []u8) !rr.RequestHandle {
    _ = try pair.shared.client.reqresp.request(&pair.shared.pair.client, &pair.shared.client.router, pair.shared.handles.client, .ping_v1, bytes, sink, .{}, pair.shared.pair.now);
    pair.server_event_capacity = 0;
    for (0..32) |_| {
        try pair.pumpOnce();
        for (pair.shared.server.reqresp.inbound, 0..) |*slot, index| {
            if (slot.request.pendingEvent()) |event| if (event == .request) return slot.request.handle(@intCast(index));
        }
    }
    return error.RequestNotReceived;
}

fn drain(pair: *Pair, output: []rr.Event) usize {
    return pair.shared.server.reqresp.pump(&pair.shared.pair.server, &pair.shared.server.router, pair.shared.pair.now, .{ .control = output }).control;
}

test "reqresp host readiness distinguishes notification pressure terminal race and stale handles" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const bytes = [_]u8{9} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try request(&pair, &bytes, &sink);
    const owner = &pair.shared.server.reqresp;
    try std.testing.expectEqual(.backpressured, owner.responseReadiness(handle));
    try std.testing.expectError(error.Busy, owner.respond(handle, &bytes, null, pair.shared.pair.now));
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try std.testing.expect(events[0] == .request);
    const borrowed = events[0].request.bytes;
    try std.testing.expectEqual(.ready, owner.responseReadiness(handle));
    const before = owner.resourceSnapshot();
    try std.testing.expectEqual(.ready, owner.responseReadiness(handle));
    try std.testing.expectEqualDeep(before, owner.resourceSnapshot());
    try std.testing.expect(owner.retainServing(handle));
    try std.testing.expect(owner.cancel(handle));
    try std.testing.expect(!owner.cancel(handle));
    try std.testing.expectEqual(@as(u32, 1), owner.closing.len);
    try std.testing.expectEqual(.terminal, owner.responseReadiness(handle));
    try std.testing.expectError(error.Terminal, owner.respond(handle, &bytes, null, pair.shared.pair.now));
    try std.testing.expectError(error.Terminal, owner.respondError(handle, 2, "closed", pair.shared.pair.now));
    try std.testing.expect(!owner.finish(handle, pair.shared.pair.now));
    var stale = handle;
    stale.generation += 1;
    try std.testing.expectEqual(.stale, owner.responseReadiness(stale));
    try std.testing.expectError(error.StaleHandle, owner.respond(stale, &bytes, null, pair.shared.pair.now));
    stale = handle;
    stale.direction = .outbound;
    try std.testing.expectEqual(.stale, owner.responseReadiness(stale));
    owner.cleanupPending(&pair.shared.pair.server, &pair.shared.server.router);
    const closed = owner.resourceSnapshot();
    owner.cleanupPending(&pair.shared.pair.server, &pair.shared.server.router);
    try std.testing.expectEqualDeep(closed, owner.resourceSnapshot());
    try std.testing.expectEqual(@as(u32, 0), owner.closing.len);
    try std.testing.expectEqual(.closed, owner.inbound[handle.index].request.stream_owner);
    try std.testing.expectEqualSlices(u8, &bytes, borrowed);
    try std.testing.expectEqual(@as(usize, 0), drain(&pair, &.{}));
    try std.testing.expectEqual(.terminal, owner.responseReadiness(handle));
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try std.testing.expectEqual(rr.Failure.cancelled, events[0].failed.reason);
    try std.testing.expectEqual(.stale, owner.responseReadiness(handle));
    try std.testing.expectError(error.StaleHandle, owner.respond(handle, &bytes, null, pair.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 0), drain(&pair, &events));
    try std.testing.expect(!owner.inbound[handle.index].request.occupied());
    try std.testing.expectEqual(@as(usize, 1), owner.resourceSnapshot().serving_occupied);
    try std.testing.expect(owner.releaseServing(handle));
    try std.testing.expectEqual(@as(usize, 0), owner.resourceSnapshot().serving_occupied);
}

test "reqresp queued chunk acknowledgement precedes cancellation terminal after cleanup" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const bytes = [_]u8{7} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try request(&pair, &bytes, &sink);
    const owner = &pair.shared.server.reqresp;
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try owner.respond(handle, &bytes, null, pair.shared.pair.now);
    try std.testing.expectEqual(.backpressured, owner.responseReadiness(handle));
    for (0..8) |_| {
        _ = drain(&pair, &.{});
        if (owner.inbound[handle.index].request.pendingEvent() != null) break;
    }
    try std.testing.expectEqual(.chunk_sent, std.meta.activeTag(owner.inbound[handle.index].request.pendingEvent().?));
    try std.testing.expectEqual(.backpressured, owner.responseReadiness(handle));
    try std.testing.expect(owner.cancel(handle));
    owner.cleanupPending(&pair.shared.pair.server, &pair.shared.server.router);
    try std.testing.expectEqual(.terminal, owner.responseReadiness(handle));
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try std.testing.expectEqual(@as(u32, 1), events[0].chunk_sent.chunks);
    try std.testing.expectEqual(.terminal, owner.responseReadiness(handle));
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try std.testing.expectEqual(rr.Failure.cancelled, events[0].failed.reason);
    try std.testing.expectEqual(@as(usize, 0), drain(&pair, &events));
}

test "reqresp finish while writing retains its independent host operation contract" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const bytes = [_]u8{4} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try request(&pair, &bytes, &sink);
    const owner = &pair.shared.server.reqresp;
    var events: [1]rr.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try owner.respond(handle, &bytes, null, pair.shared.pair.now);
    try std.testing.expectEqual(.backpressured, owner.responseReadiness(handle));
    try std.testing.expect(owner.finish(handle, pair.shared.pair.now));
    try std.testing.expect(!owner.finish(handle, pair.shared.pair.now));
    for (0..8) |_| {
        _ = drain(&pair, &.{});
        if (owner.responseReadiness(handle) == .terminal) break;
    }
    try std.testing.expectEqual(.terminal, owner.responseReadiness(handle));
    try std.testing.expectEqual(@as(usize, 1), drain(&pair, &events));
    try std.testing.expectEqual(@as(u32, 1), events[0].served.chunks);
    try std.testing.expectEqual(@as(usize, 0), drain(&pair, &events));
}
