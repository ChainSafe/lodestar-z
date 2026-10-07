const std = @import("std");
const schedule_test_support = @import("schedule_test_support.zig");
const ct = @import("consensus_types");
const protocol = @import("reqresp/protocol.zig");
const reqresp = @import("reqresp/ReqResp.zig");
const Engine = @import("quic/Engine.zig");
const harness = @import("protocols_reqresp_test_support.zig");
const policy_fixture = @import("reqresp/policy_fixture.zig");
const admission_fixture = @import("reqresp/admission_fixture.zig");
const protocols_test_support = @import("protocols_test_support.zig");

const support = @import("quic/test_support.zig");
const reservedOptions = @import("reqresp/control_fixture.zig").reservedOptions;

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const statusBytes = harness.statusBytes;

const Pair = harness.Pair;

fn roundTrip(setup: *Pair, seed: u8) !void {
    const request_ssz = statusBytes(seed);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try setup.shared.client.request(
        &setup.shared.pair.client,
        setup.shared.handles.client,
        .status_v1,
        &request_ssz,
        &sink,
        .{},
        setup.shared.pair.now,
    );
    const reply = statusBytes(seed +% 1);
    var done = false;
    var rounds: usize = 0;
    while (rounds < 40 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.status_v1, incoming.protocol);
                try setup.shared.server.reqresp.respond(incoming.request, &reply, null, setup.shared.pair.now);
            },
            .chunk_sent => |sent| try std.testing.expect(setup.shared.server.reqresp.finish(sent.request, setup.shared.pair.now)),
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &reply, chunk.bytes);
                try std.testing.expect(setup.shared.client.reqresp.consume(chunk.request, setup.shared.pair.now));
            },
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
}

test "protocol stack round trips a status request through the collapsed host loop" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .serving_max = 4 }, .{ .outbound_max = 4, .serving_max = 4 });
    defer setup.deinit();

    try roundTrip(&setup, 5);
    try std.testing.expectEqual(@as(u16, 0), setup.shared.client.reqresp.pendingCounts().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.pendingCounts().inbound);
}

test "protocol stack reclaims inbound sinks across more requests than it has slots" {
    const admission: reqresp.Options.Admission = .{ .policy = policy_fixture.config(), .limits = .{
        .identities = 2,
        .peer = admission_fixture.quotas(1_000, 1_000),
        .global = admission_fixture.quotas(1_000, 1_000),
    } };
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .serving_max = 4 }, .{ .outbound_max = 4, .serving_max = 4, .admission = admission });
    defer setup.deinit();

    var seed: u8 = 0;
    while (seed < 12) : (seed += 1) try roundTrip(&setup, seed);
    try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.pendingCounts().inbound);
}

test "protocol stack fails in-flight requests when the connection closes" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .serving_max = 4 }, .{ .outbound_max = 4, .serving_max = 4 });
    defer setup.deinit();

    const request_ssz = statusBytes(1);
    var sink: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = try setup.shared.client.request(
        &setup.shared.pair.client,
        setup.shared.handles.client,
        .status_v1,
        &request_ssz,
        &sink,
        .{},
        setup.shared.pair.now,
    );
    var seen = false;
    var rounds: usize = 0;
    while (rounds < 12 and !seen) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) seen = true;
        }
    }
    try std.testing.expect(seen);

    try std.testing.expect(setup.shared.pair.client.close(setup.shared.handles.client, 0));
    var client_failed = false;
    var server_failed = false;
    rounds = 0;
    while (rounds < 20 and !(client_failed and server_failed)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) client_failed = true;
        }
        for (setup.serverEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) server_failed = true;
        }
    }
    try std.testing.expect(client_failed);
    try std.testing.expect(server_failed);
    try std.testing.expectEqual(@as(u16, 0), setup.shared.server.reqresp.pendingCounts().inbound);
}

test "protocol stack control wakeup includes negotiation after application quiescence" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .serving_max = 4 }, .{ .outbound_max = 4, .serving_max = 4 });
    defer setup.deinit();
    setup.shared.client.closeApplications(&setup.shared.pair.client, setup.shared.pair.now);
    const bytes = [_]u8{0} ** 8;
    var sink: [8]u8 = undefined;
    const handle = try setup.shared.client.request(&setup.shared.pair.client, setup.shared.handles.client, .ping_v1, &bytes, &sink, .{ .timeouts = .{ .response = .fromMilliseconds(60_000) } }, setup.shared.pair.now);
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{ .control = &.{} }).control;
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.millis() + 5_000), schedule_test_support.wakeupMilliseconds(setup.shared.client.schedule(.{ .control = 0 }), setup.shared.pair.now.millis()));
    try std.testing.expect(setup.shared.client.reqresp.cancel(handle, setup.shared.pair.now));
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{ .control = &.{} }).control;
    try std.testing.expectEqual(@as(?u64, null), schedule_test_support.wakeupMilliseconds(setup.shared.client.schedule(.{ .control = 0 }), setup.shared.pair.now.millis()));
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{ .control = &events }).control);
    try std.testing.expect(events[0].failed.reason == .cancelled);
}

test "protocol stack preserves drained native stream events across a partial request sweep" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 4, .serving_max = 4 }, .{ .outbound_max = 4, .serving_max = 4 });
    defer setup.deinit();
    const bytes = [_]u8{9} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.shared.client.request(&setup.shared.pair.client, setup.shared.handles.client, .ping_v1, &bytes, &sink, .{}, setup.shared.pair.now);
    var incoming: ?reqresp.RequestHandle = null;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .request) {
            incoming = event.request.request;
        };
        if (incoming != null) break;
    }
    try std.testing.expect(incoming != null);
    const stream = setup.shared.server.reqresp.inbound[incoming.?.index].request.stream;
    setup.shared.client.reqresp.options.work_per_pump_max = 1;
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{ .control = &.{} }).control;
    const codec = @import("reqresp/codec.zig");
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, null, &bytes, &wire);
    try std.testing.expectEqual(encoded.len, try setup.shared.pair.server.write(stream, encoded, false));
    try setup.shared.pair.pump();
    var events: [1]Event = undefined;
    var transport: [16]Engine.Event = undefined;
    const polled = setup.shared.pair.events(&setup.shared.pair.client, &transport);
    try std.testing.expect(polled.len > 0);
    const first_count = setup.shared.client.process(&setup.shared.pair.client, polled, setup.shared.pair.now, .{ .control = &events }).control;
    var received = first_count == 1;
    for (0..10) |_| {
        if (received) break;
        try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.millis()), schedule_test_support.wakeupMilliseconds(setup.shared.client.schedule(.{ .control = 1 }), setup.shared.pair.now.millis()));
        const count = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{ .control = &events }).control;
        if (count == 1) {
            try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
}

test "protocol stack request work remains bounded and rotates between live streams" {
    var setup: Pair = .{};
    try setup.init(.{ .outbound_max = 64, .serving_max = 64 }, .{});
    defer setup.deinit();
    const bytes = [_]u8{9} ** 8;
    var sinks: [2][8]u8 = undefined;
    var handles: [2]reqresp.RequestHandle = undefined;
    for (&sinks, &handles) |*sink, *handle| {
        handle.* = try setup.shared.client.request(&setup.shared.pair.client, setup.shared.handles.client, .ping_v1, &bytes, sink, .{}, setup.shared.pair.now);
    }
    var incoming: [2]reqresp.RequestHandle = undefined;
    var received: usize = 0;
    for (0..30) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .request) {
            try std.testing.expect(received < incoming.len);
            incoming[received] = event.request.request;
            received += 1;
        };
        if (received == incoming.len) break;
    }
    try std.testing.expectEqual(incoming.len, received);
    const codec = @import("reqresp/codec.zig");
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeChunk(0, null, &bytes, &wire);
    for (incoming) |handle| {
        const stream = setup.shared.server.reqresp.inbound[handle.index].request.stream;
        try std.testing.expectEqual(encoded.len, try setup.shared.pair.server.write(stream, encoded, false));
    }
    try setup.shared.pair.pump();
    protocols_test_support.forward(&setup.shared.pair, &setup.shared.pair.client, .{ .reqresp = &setup.shared.client.reqresp });
    setup.shared.client.reqresp.options.work_per_pump_max = 1;
    var events: [2]Event = undefined;
    var delivered: [2]reqresp.RequestHandle = undefined;
    for (&delivered) |*handle| {
        const count = setup.shared.client.reqresp.pump(&setup.shared.pair.client, &setup.shared.client.router, setup.shared.pair.now, .{ .control = &events }).control;
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expectEqualSlices(u8, &bytes, events[0].chunk.bytes);
        handle.* = events[0].chunk.request;
    }
    try std.testing.expect(!std.meta.eql(delivered[0], delivered[1]));
    for (handles) |handle| try std.testing.expect(setup.shared.client.reqresp.consume(handle, setup.shared.pair.now));
}

test "protocol stack reqresp slot is serviced only after a stream event or its deadline" {
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 1_000 });
    defer setup.deinit();
    const server = &setup.shared.server.reqresp;
    const codec = @import("reqresp/codec.zig");
    // Two accepted ping streams whose request bytes have not arrived.
    const fed = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(fed, .ping_v1);
    const starved = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(starved, .ping_v1);
    try std.testing.expectEqual(@as(u8, 2), server.inboundProtocolRunningCount(setup.shared.handles.server, .ping_v1));
    for (0..2) |_| try setup.pumpOnce();
    const idle = server.visits;
    for (0..8) |_| {
        try setup.pumpOnce();
        try std.testing.expectEqual(idle, server.visits);
        try std.testing.expect(schedule_test_support.wakeupMilliseconds(server.schedule(.{ .control = 1 }), setup.shared.pair.now.millis()).? > setup.shared.pair.now.millis());
    }

    const ping = [_]u8{3} ** 8;
    var wire: [codec.frame_scratch_max]u8 = undefined;
    const encoded = try codec.encodeRequest(&ping, &wire);
    try std.testing.expectEqual(encoded.len, try setup.shared.pair.client.write(fed, encoded, true));
    var request: ?reqresp.RequestHandle = null;
    for (0..8) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .request) {
            try std.testing.expectEqualSlices(u8, &ping, event.request.bytes);
            request = event.request.request;
        };
        if (request != null) break;
    }
    try std.testing.expect(request != null);
    try std.testing.expect(server.visits > idle);

    // The starved slot is next visited when its progress deadline passes.
    const waiting = server.visits;
    for (0..4) |_| {
        try setup.pumpOnce();
        try std.testing.expectEqual(waiting, server.visits);
    }
    setup.shared.pair.advance(1_000);
    var timed_out = false;
    for (0..4) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .failed) {
            try std.testing.expect(!std.meta.eql(request.?, event.failed.request));
            try std.testing.expectEqual(reqresp.Failure.timeout, event.failed.reason);
            timed_out = true;
        };
        if (timed_out) break;
    }
    try std.testing.expect(timed_out);
    try std.testing.expect(server.visits > waiting);
}

test "protocol stack reqresp deadline fires on time while more slots than the pump budget stay ready" {
    // One client identity opens every stream, so its request starts need a larger burst.
    var admission = try reqresp.Options.Admission.defaults(&policy_fixture.config(), 128, 128, 8);
    admission.limits.starts.tokens = 64;
    var setup: Pair = .{};
    try setup.init(.{}, .{ .progress_timeout_ms = 1_000, .admission = admission });
    defer setup.deinit();
    const server = &setup.shared.server.reqresp;
    // An accepted ping stream whose request never arrives.
    const stream = try setup.openRaw(.ping_v1);
    try setup.awaitRawSelection(stream, .ping_v1);
    var waiting: ?u16 = null;
    for (server.inbound, 0..) |*slot, index| if (slot.request.running()) {
        try std.testing.expect(waiting == null);
        waiting = @intCast(index);
    };
    const deadline = server.inbound[waiting.?].request.started_ms + 1_000;

    // Busy slots on other connections, accepted later so their deadlines fall after it.
    setup.shared.pair.advance(500);
    var connections: [9]Engine.Handle = undefined;
    var dialed: usize = 0;
    // The server admits a bounded number of handshakes per source address.
    while (dialed < connections.len) {
        const batch = @min(4, connections.len - dialed);
        for (connections[dialed..][0..batch]) |*conn| conn.* = try setup.shared.pair.dial();
        dialed += batch;
        for (0..2) |_| try setup.pumpOnce();
    }
    for (connections) |conn| for ([_]Protocol{ .ping_v1, .ping_v1, .status_v1, .status_v1 }) |which| {
        const opened = try setup.openRawOn(conn, which);
        try setup.awaitRawSelection(opened, which);
    };
    var busy: [4 * connections.len]u16 = undefined;
    var count: usize = 0;
    for (server.inbound, 0..) |*slot, index| if (slot.request.running() and index != waiting.?) {
        busy[count] = @intCast(index);
        count += 1;
    };
    try std.testing.expectEqual(busy.len, count);

    setup.shared.pair.advance(500);
    try std.testing.expectEqual(deadline, setup.shared.pair.now.millis());
    for (busy) |index| server.markReady(.inbound, index);
    try std.testing.expect(server.ready.len > server.options.work_per_pump_max);
    try setup.pumpOnce();
    var timed_out = false;
    for (setup.serverEvents()) |event| if (event == .failed) {
        try std.testing.expectEqual(waiting.?, event.failed.request.index);
        try std.testing.expectEqual(reqresp.Failure.timeout, event.failed.reason);
        timed_out = true;
    };
    try std.testing.expect(timed_out);
}

test "protocol stack reqresp slots stay indexed by connection across a reconnect at the same index" {
    var setup: Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const server = &setup.shared.server.reqresp;
    const client = &setup.shared.client.reqresp;
    const old = setup.shared.handles;
    const bytes = [_]u8{4} ** 8;
    var sinks: [2][8]u8 = undefined;
    _ = try setup.shared.client.request(&setup.shared.pair.client, old.client, .ping_v1, &bytes, &sinks[0], .{}, setup.shared.pair.now);
    const stale = try awaitRequest(&setup);
    const slots_per_connection = @import("reqresp/ReceiveLayout.zig").slots_per_connection;
    try std.testing.expectEqual(@as(usize, old.server.index), stale.index / slots_per_connection);

    // The server holds its host events while the connection closes and a new one takes its index.
    setup.server_event_capacity = 0;
    try std.testing.expect(setup.shared.pair.client.close(old.client, 0));
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), setup.shared.pair.server.registry.active_len);
    const fresh_client = try setup.shared.pair.dial();
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 1), setup.shared.pair.server.registry.active_len);
    const fresh_server = setup.shared.pair.server.sendOwner(setup.shared.pair.server.registry.activeIndices()[0]).?;
    try std.testing.expectEqual(old.server.index, fresh_server.index);
    try std.testing.expect(old.server.generation != fresh_server.generation);

    _ = try setup.shared.client.request(&setup.shared.pair.client, fresh_client, .ping_v1, &bytes, &sinks[1], .{}, setup.shared.pair.now);
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(u8, 1), server.inboundProtocolRunningCount(fresh_server, .ping_v1));
    try std.testing.expectEqual(@as(u8, 1), server.inboundPendingCount(old.server));
    try std.testing.expectEqual(@as(u8, 1), client.outboundProtocolPendingCount(fresh_client, .ping_v1));
    try std.testing.expectEqual(@as(u8, 0), client.outboundProtocolPendingCount(old.client, .ping_v1));
    // A repeated close of the old connection leaves the new one's slot running.
    server.connectionClosed(old.server, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u8, 1), server.inboundProtocolRunningCount(fresh_server, .ping_v1));

    setup.server_event_capacity = 16;
    var fresh: ?reqresp.RequestHandle = null;
    var stale_failed = false;
    for (0..8) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(fresh_server, incoming.conn);
                try std.testing.expectEqual(stale.index / slots_per_connection, incoming.request.index / slots_per_connection);
                try std.testing.expect(incoming.request.index != stale.index);
                fresh = incoming.request;
            },
            .failed => |failed| {
                try std.testing.expectEqual(stale, failed.request);
                try std.testing.expectEqual(reqresp.Failure.connection_closed, failed.reason);
                stale_failed = true;
            },
            else => {},
        };
        if (fresh != null and stale_failed) break;
    }
    try std.testing.expect(fresh != null and stale_failed);
    try std.testing.expectError(error.StaleHandle, server.respond(stale, &bytes, null, setup.shared.pair.now));
    try server.respond(fresh.?, &bytes, null, setup.shared.pair.now);
    var done = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .chunk_sent) {
            try std.testing.expect(server.finish(event.chunk_sent.request, setup.shared.pair.now));
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(client.consume(chunk.request, setup.shared.pair.now)),
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
}

fn awaitRequest(setup: *Pair) !reqresp.RequestHandle {
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .request) return event.request.request;
    }
    return error.TestUnexpectedResult;
}

test "protocol stack reqresp request on one connection among 64 visits only its own slots" {
    var setup: Pair = .{};
    try setup.init(.{}, .{});
    defer setup.deinit();
    const server = &setup.shared.server.reqresp;
    const client = &setup.shared.client.reqresp;
    var connections: [64]Engine.Handle = undefined;
    connections[0] = setup.shared.handles.client;
    var dialed: usize = 1;
    // The server admits a bounded number of handshakes per source address.
    while (dialed < connections.len) {
        const batch = @min(4, connections.len - dialed);
        for (connections[dialed..][0..batch]) |*conn| conn.* = try setup.shared.pair.dial();
        dialed += batch;
        for (0..2) |_| try setup.pumpOnce();
    }
    try std.testing.expectEqual(@as(usize, connections.len), setup.shared.pair.server.registry.active_len);
    for (0..2) |_| try setup.pumpOnce();
    const idle = .{ client.visits, server.visits };
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expectEqual(idle[0], client.visits);
    try std.testing.expectEqual(idle[1], server.visits);

    const bytes = [_]u8{6} ** 8;
    var sink: [8]u8 = undefined;
    _ = try setup.shared.client.request(&setup.shared.pair.client, connections[41], .ping_v1, &bytes, &sink, .{}, setup.shared.pair.now);
    const incoming = try awaitRequest(&setup);
    try server.respond(incoming, &bytes, null, setup.shared.pair.now);
    var done = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .chunk_sent) {
            try std.testing.expect(server.finish(event.chunk_sent.request, setup.shared.pair.now));
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| try std.testing.expect(client.consume(chunk.request, setup.shared.pair.now)),
            .done => done = true,
            else => {},
        };
        if (done) break;
    }
    try std.testing.expect(done);
    for (0..2) |_| try setup.pumpOnce();
    // One slot per side, each taken from a list a handful of times over its lifetime; a scan
    // would visit every slot of every connection.
    try std.testing.expect(client.visits - idle[0] <= 16);
    try std.testing.expect(server.visits - idle[1] <= 16);
    try std.testing.expectEqual(@as(?u64, null), schedule_test_support.wakeupMilliseconds(server.schedule(.{ .control = 1 }), setup.shared.pair.now.millis()));
    try std.testing.expectEqual(@as(?u64, null), schedule_test_support.wakeupMilliseconds(client.schedule(.{ .control = 1 }), setup.shared.pair.now.millis()));
}

test "protocol stack reqresp retains request and chunk bytes through control progress" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var options = try reservedOptions();
    options.forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .deneb }};
    var client = try protocols_test_support.initProtocols(std.testing.allocator, .{ .reqresp = options, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } }, &pair.client);
    defer client.deinit();
    var server = try protocols_test_support.initProtocols(std.testing.allocator, .{ .reqresp = options, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1 } }, &pair.server);
    defer server.deinit();
    defer server.reqresp.cancelAll(&pair.server, &server.router, pair.now);
    const sink = try std.testing.allocator.alloc(
        u8,
        protocol.Protocol.blocks_by_root_v2.info().response_max,
    );
    defer {
        client.reqresp.cancelAll(&pair.client, &client.router, pair.now);
        std.testing.allocator.free(sink);
    }
    const root = [_]u8{0xa5} ** 32;
    const app = try client.request(
        &pair.client,
        handles.client,
        .blocks_by_root_v2,
        &root,
        sink,
        .{ .expected_chunks = 1 },
        pair.now,
    );
    const ping_bytes = [_]u8{42} ++ [_]u8{0} ** 7;
    var pong: [8]u8 = undefined;
    _ = try client.request(
        &pair.client,
        handles.client,
        .ping_v1,
        &ping_bytes,
        &pong,
        .{},
        pair.now,
    );
    var got_pong = false;
    var transport: [16]Engine.Event = undefined;
    var output: [1]reqresp.Event = undefined;
    for (0..24) |_| {
        try pair.pump();
        const received = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..received.control]) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &ping_bytes, chunk.bytes);
                try std.testing.expect(client.reqresp.consume(chunk.request, pair.now));
                got_pong = true;
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        const incoming = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .application = &.{}, .control = &output });
        for (output[0..incoming.control]) |event| switch (event) {
            .request => |request| {
                try std.testing.expectEqual(protocol.Protocol.ping_v1, request.protocol);
                try server.reqresp.respond(request.request, &ping_bytes, null, pair.now);
            },
            .chunk_sent => |sent| _ = server.reqresp.finish(sent.request, pair.now),
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(got_pong);
    try std.testing.expectEqual(
        1,
        server.reqresp.pump(&pair.server, &server.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    const request = output[0].request;
    try std.testing.expectEqualSlices(u8, &root, request.bytes);
    const block = [_]u8{0x5a} ** ct.deneb.SignedBeaconBlock.min_size;
    try server.reqresp.respond(request.request, &block, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .deneb }, pair.now);
    for (0..16) |_| {
        try pair.pump();
        _ = client.process(&pair.client, pair.events(&pair.client, &transport), pair.now, .{ .application = &.{}, .control = &output });
        const count = server.process(&pair.server, pair.events(&pair.server, &transport), pair.now, .{ .control = &output }).control;
        for (output[0..count]) |event| {
            if (event == .chunk_sent) _ = server.reqresp.finish(event.chunk_sent.request, pair.now);
        }
    }
    try std.testing.expect(client.reqresp.outbound[app.index].request.pendingEvent() != null);
    try std.testing.expectEqualSlices(u8, &block, sink[0..block.len]);
    try std.testing.expectEqual(
        pair.now.millis() + 10_000,
        schedule_test_support.wakeupMilliseconds(client.reqresp.schedule(.{ .application = 0, .control = 1 }), pair.now.millis()),
    );
    try std.testing.expectEqual(
        pair.now.millis(),
        schedule_test_support.wakeupMilliseconds(client.reqresp.schedule(.{ .application = 1, .control = 0 }), pair.now.millis()),
    );
    try std.testing.expect(client.reqresp.cancel(app, pair.now));
    _ = client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &.{}, .control = &.{} });
    try std.testing.expectEqual(
        1,
        client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    try std.testing.expectEqualSlices(u8, &block, output[0].chunk.bytes);
    try std.testing.expectEqual(app, output[0].chunk.request);
    try std.testing.expectEqual(
        1,
        client.reqresp.pump(&pair.client, &client.router, pair.now, .{ .application = &output, .control = &.{} }).application,
    );
    try std.testing.expectEqual(app, output[0].failed.request);
}
