const std = @import("std");
const PeerManager = @import("peer_manager.zig").PeerManager;
const t = @import("peers/types.zig");
const wire = @import("control_wire.zig");
const rr = @import("reqresp/root.zig");
const Now = @import("types.zig").Now;
const remembered = @import("peers/remembered.zig");
const history = @import("peers/dial_history.zig");

const identity: t.PeerId = .{ .bytes = @splat(1) };
const endpoint: t.Address = .{ .ip4 = .{ .octets = .{ 203, 0, 113, 1 }, .port = 9000 } };
const conn: t.Handle = .{ .index = 0, .generation = 1 };

fn init() !PeerManager {
    return PeerManager.init(std.testing.allocator, &.{ .bytes = @splat(0) }, &.{}, .{
        .peers = .{ .capacity = 4, .outbound_reserve = 0, .target_peers = 3, .max_peers = 4, .min_outbound = 0 },
        .dial = .{ .capacity = 4, .concurrent_max = 2, .seed = 1 },
    }, .initEmpty(), 4);
}
fn at(ms: u64) Now {
    return .{ .mono_ms = ms, .unix_s = @intCast(1_000 + ms / 1_000) };
}
fn admit(manager: *PeerManager, connection: t.Handle, direction: t.Direction, now: Now) !t.PeerRef {
    const admitted = manager.admit(&.{ .conn = connection, .peer_id = identity, .direction = direction }, endpoint, now) orelse return error.AdmissionRefused;
    return admitted.peer;
}
fn outbound(manager: *PeerManager, now: Now) !t.PeerRef {
    try manager.connect(&identity, &.{endpoint}, now);
    // Select the operator's already-admitted dial without running gossip or transport. The owner
    // still receives the real started/admitted transitions and records the original dial endpoint.
    var intents: [1]@import("peers/dialing.zig").DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), manager.dialing.poll(&manager.catalog, now.mono_ms, &intents));
    try std.testing.expect(manager.dialStarted(intents[0].token, conn));
    return admit(manager, conn, .outbound, now);
}
fn startProbe(manager: *PeerManager, generation: u32, now: Now) !wire.ControlReply {
    var pass = manager.beginControl(now);
    const due = manager.nextControl(&pass, now) orelse return error.NoProbe;
    const probe = due.request orelse return error.NoProbe;
    try std.testing.expect(due.close == null);
    const request: rr.RequestHandle = .{ .index = 0, .generation = generation, .direction = .outbound };
    manager.controlStarted(&due, true, request, now);
    try std.testing.expect(manager.nextControl(&pass, now) == null);
    return .{ .peer = due.peer, .conn = due.conn, .request = request, .protocol = probe.protocol, .after_ready = probe.after_ready };
}
fn reply(manager: *PeerManager, observation: wire.ControlReply, bytes: []const u8, now: Now) void {
    var result = observation;
    manager.controlReplied(&result, .{ .chunk = .{ .request = result.request.?, .bytes = bytes, .fork = null } }, now, 0);
    result.received = true;
    manager.controlReplied(&result, .{ .done = .{ .request = result.request.?, .chunks = 1 } }, now, 0);
}
fn qualify(manager: *PeerManager, now: Now) !void {
    var bytes: [wire.status_size_max]u8 = undefined;
    const status = try startProbe(manager, 1, now);
    try std.testing.expectEqual(rr.Protocol.status_v1, status.protocol);
    reply(manager, status, bytes[0..try wire.encodeStatus(.status_v1, &manager.local.status, &bytes)], now);
    const metadata = try startProbe(manager, 2, now);
    try std.testing.expectEqual(rr.Protocol.metadata_v1, metadata.protocol);
    reply(manager, metadata, bytes[0..try wire.encodeMetadata(.metadata_v1, &manager.local.metadata, manager.local.fork, &bytes)], now);
}

test "peer owner replacement waits for cancelled request settlement without inheriting its evidence" {
    var manager = try init();
    defer manager.deinit();
    const peer = try admit(&manager, conn, .inbound, at(10));
    var old = try startProbe(&manager, 1, at(20_000));
    const replacement: t.Handle = .{ .index = 1, .generation = 2 };
    try std.testing.expectEqualDeep(peer, try admit(&manager, replacement, .outbound, at(20_001)));
    try std.testing.expect(manager.retireConnection(peer, conn, .health_error, at(20_001)) == null);
    try std.testing.expect(manager.controlWakeup(at(20_001)) == null);
    try std.testing.expect(manager.catalog.get(peer).?.status == null);

    old.cancelled = true;
    manager.controlReplied(&old, .{ .failed = .{ .request = old.request.?, .reason = .cancelled } }, at(20_002), 0);
    try std.testing.expectEqual(at(20_002).mono_ms, manager.controlWakeup(at(20_002)).?);
    const current = try startProbe(&manager, 2, at(20_002));
    try std.testing.expectEqualDeep(replacement, current.conn);
    // A repeated terminal result for the old generation cannot free the new request reservation.
    manager.controlReplied(&old, .{ .failed = .{ .request = old.request.?, .reason = .cancelled } }, at(20_003), 0);
    try std.testing.expect(manager.controlWakeup(at(20_003)) == null);
    try std.testing.expectEqual(@as(u64, 0), manager.control.counters.closed[@intFromEnum(t.DisconnectReason.health_error)]);
    try std.testing.expectEqual(@as(u8, 0), manager.catalog.rowFor(peer).?.intent.failures);
}

test "peer owner qualification clears dial evidence before later proven health" {
    var manager = try init();
    defer manager.deinit();
    const key = manager.catalog.history.endpointKey(&identity, endpoint);
    manager.catalog.history.recordEndpoint(key, .unanswered, 1, 1);
    manager.catalog.history.recordEndpoint(key, .health, 1, 1);
    _ = try outbound(&manager, at(10));
    try std.testing.expectEqual(@as(u8, 2), manager.catalog.history.strikesFor(key, 1, 10));
    try qualify(&manager, at(10));
    try std.testing.expectEqual(@as(u8, 1), manager.catalog.history.strikesFor(key, 1, 10));
    const ping = try startProbe(&manager, 3, at(20_010));
    try std.testing.expectEqual(rr.Protocol.ping_v1, ping.protocol);
    try std.testing.expect(ping.after_ready);
    reply(&manager, ping, &@as([8]u8, @splat(0)), at(20_010));
    try std.testing.expectEqual(@as(u8, 0), manager.catalog.history.strikesFor(key, 1, 20_010));
}

test "peer owner retirement preserves remembered and rejection lifetimes and settles once" {
    for ([_]u64{ remembered.qualify_ms - 1, remembered.qualify_ms, history.kept_connection_ms }) |lifetime| {
        var manager = try init();
        defer manager.deinit();
        const key = manager.catalog.history.identityKey(&identity);
        _ = manager.catalog.history.reject(key, .too_many_peers, 1);
        const peer = try outbound(&manager, at(10));
        try qualify(&manager, at(10));
        const now = at(10 + lifetime);
        try std.testing.expect(manager.retireConnection(peer, conn, .host, now) != null);
        const failures = manager.catalog.rowFor(peer).?.intent.failures;
        const deadline = manager.catalog.rowFor(peer).?.intent.eligible_at_ms;
        try std.testing.expect(manager.retireConnection(peer, conn, .host, now) == null);
        try std.testing.expect(manager.transportClosed(&.{ .conn = conn, .peer_id = identity, .direction = .outbound, .reason = .{ .peer_closed = .{ .app = true, .code = 0 } } }, 129, now) == null);
        try std.testing.expectEqual(failures, manager.catalog.rowFor(peer).?.intent.failures);
        try std.testing.expectEqual(deadline, manager.catalog.rowFor(peer).?.intent.eligible_at_ms);
        try std.testing.expectEqual(@as(u64, 1), manager.control.counters.closed[@intFromEnum(t.DisconnectReason.host)]);
        var records: [remembered.capacity]remembered.Record = undefined;
        try std.testing.expectEqual(@as(usize, @intFromBool(lifetime >= remembered.qualify_ms)), manager.rememberedPeers(now, &records));
        const block = manager.catalog.history.reject(key, .too_many_peers, now.mono_ms);
        try std.testing.expectEqual(@as(u64, if (lifetime >= history.kept_connection_ms) 5 * 60_000 else 15 * 60_000), block);
    }
}

test "peer owner local probe refusal defers without peer evidence" {
    var manager = try init();
    defer manager.deinit();
    const peer = try admit(&manager, conn, .outbound, at(10));
    var pass = manager.beginControl(at(10));
    const due = manager.nextControl(&pass, at(10)).?;
    manager.controlStarted(&due, false, null, at(10));
    try std.testing.expect(manager.nextControl(&pass, at(10)) == null);
    try std.testing.expectEqual(@as(u64, 1_010), manager.controlWakeup(at(10)).?);
    try std.testing.expectEqual(@as(u64, 1), manager.control.counters.deferred);
    try std.testing.expectEqual(@as(u8, 0), manager.catalog.rowFor(peer).?.intent.failures);
    try std.testing.expectEqual(@as(f64, 0), manager.catalog.get(peer).?.score);
    try std.testing.expectEqual(@as(u64, 0), manager.catalog.history.rejectedUntil(manager.catalog.history.identityKey(&identity), 10));
}
