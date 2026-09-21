const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const support = @import("test_support.zig");
const managed = @import("managed.zig");
const t = @import("peers/types.zig");
const Engine = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");

const options = @import("managed_test_support.zig").options;
const localState = @import("managed_test_support.zig").localState;
const Setup = @import("managed_test_support.zig").Setup;

fn subscribeServer(setup: *Setup, name: []const u8) !void {
    setup.client_service.gossipsub.options.observe_subscriptions = false;
    setup.server_service.gossipsub.options.observe_subscriptions = false;
    const g = setup.client_service.gossipsub;
    g.peers.scores.applyValidatedTopic(gossip_test.intern(g, name).?, .{ .weight = 0 });
    try gossip_test.subscribe(setup.server_service.gossipsub, name);
}

test "managed native two owners establish relevance and fetch initial metadata without public output" {
    for ([_]@import("config").ForkSeq{ .phase0, .altair, .fulu }) |fork| {
        const local: t.LocalState = .{
            .fork = .{ .fork = fork },
            .status = .{ .earliest_available_slot = if (fork.gte(.fulu)) 0 else null },
            .metadata = .{
                .seq_number = 3,
                .attnets = @splat(7),
                .custody_group_count = if (fork.gte(.fulu)) 1 else null,
            },
        };
        var setup: Setup = .{};
        try setup.init(&local);
        defer setup.deinit();
        for (0..60) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
        try std.testing.expectEqual(@as(u16, 1), setup.server.peerCounts().relevant);
        try std.testing.expectEqualSlices(u64, &.{ 0, 1 }, &setup.client.control.counters.events.connected);
        try std.testing.expectEqualSlices(u64, &.{ 1, 0 }, &setup.server.control.counters.events.connected);
        try std.testing.expect(setup.client.control.counters.events.relevance[0] > 0);
        var snapshots: [4]t.Snapshot = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
        try std.testing.expectEqual(t.Direction.outbound, snapshots[0].direction);
        _ = setup.server.snapshots(&snapshots);
        try std.testing.expectEqual(t.Direction.inbound, snapshots[0].direction);
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
    }
}

test "managed publishes the authenticated endpoint after QUIC rebinding" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.snapshots(&snapshots));
    const before = snapshots[0];
    try std.testing.expect(before.relevant);
    const rebound: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4003 } };
    setup.pair.client_source = rebound;
    setup.client.reStatusPeers(setup.pair.now);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u64, 1), setup.pair.server.counters.path_changes);
    try std.testing.expectEqual(rebound, setup.pair.server.peerAddress(before.connection.?).?);
    const after = setup.server.catalog.get(before.peer).?;
    try std.testing.expectEqual(before.connection, after.connection);
    try std.testing.expectEqual(rebound, after.endpoint);
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.catalog.pollEvents(&event));
    try std.testing.expectEqual(before.peer, event[0].updated.peer);
    try std.testing.expectEqual(rebound, event[0].updated.endpoint);
}

test "managed native ping coalesces metadata and confirms unchanged freshness then periodic Status" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const before = snapshots[0].metadata_at_ms;
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(1);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].metadata_at_ms > before);
    const changed: t.Metadata = .{ .seq_number = 10, .attnets = @splat(9) };
    try @import("managed_test_support.zig").updateLocal(&setup.server, &setup.server_service, &metadataUpdate(&setup.server, &localState(.{ .metadata = changed }).metadata), setup.pair.now);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(changed, snapshots[0].metadata.?);
    const status: t.Status = .{ .head_slot = 80 };
    try setup.server.updateStatus(&setup.server_service, &localState(.{ .status = status }).status);
    setup.pair.advance(300_000);
    for (0..50) |_| try setup.step(1);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(status, snapshots[0].status.?);
}

test "managed native immutable metadata response survives local update during pending writer" {
    var setup: Setup = .{};
    const old: t.LocalState = .{ .metadata = .{ .seq_number = 4, .attnets = @splat(8) } };
    try setup.init(&old);
    defer setup.deinit();
    var pending = false;
    for (0..40) |_| {
        try setup.step(0);
        for (setup.server.control.responses) |response| if (response.request) |request| {
            const slot = setup.server_service.reqresp.inboundSlot(request).?;
            if (slot.request.protocol != .metadata_v1) continue;
            try std.testing.expect(slot.request.io.writing);
            const changed: t.Metadata = .{ .seq_number = 5, .attnets = @splat(9) };
            try @import("managed_test_support.zig").updateLocal(&setup.server, &setup.server_service, &metadataUpdate(&setup.server, &localState(.{ .metadata = changed }).metadata), setup.pair.now);
            pending = true;
            break;
        };
        if (pending) break;
    }
    try std.testing.expect(pending);
    for (0..40) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(old.metadata, snapshots[0].metadata.?);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 5), snapshots[0].metadata.?.seq_number);
}

test "managed native wrong fork Goodbye hard closes with zero output and shutdown repeats" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try @import("managed_test_support.zig").updateLocal(&setup.server, &setup.server_service, &localState(.{ .fork = .{ .digest = @splat(1) }, .status = .{ .fork_digest = @splat(1) } }), setup.pair.now);
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().relevant);
    setup.pair.advance(2_001);
    for (0..5) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.catalog.connectedCount());
    try std.testing.expectEqual(@as(u16, 0), setup.server.catalog.connectedCount());
    var events: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&events));
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, events[0].closed.reason);
    managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
    managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
}

test "managed native control timeout releases owners independent of public output" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    setup.client.reStatusPeers(setup.pair.now);
    try setup.step(0);
    setup.pair.drop_to_server = true;
    setup.pair.advance(10_001);
    for (0..4) |_| try setup.step(0);
    setup.pair.advance(2_001);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.catalog.connectedCount());
    var events: [1]t.Event = undefined;
    _ = setup.client.catalog.pollEvents(&events);
    try std.testing.expectEqual(t.DisconnectReason.health_timeout, events[0].closed.reason);
}

test "managed native control distinguishes RPC errors timeouts and local retries" {
    const Case = struct { failure: rr.Failure, reason: ?t.DisconnectReason };
    for ([_]Case{
        .{ .failure = .stream_closed, .reason = .health_error },
        .{ .failure = .{ .invalid_response = error.Truncated }, .reason = .health_error },
        .{ .failure = .{ .negotiation_failed = .timeout }, .reason = .health_timeout },
        .{ .failure = .host_timeout, .reason = null },
        .{ .failure = .quota_timeout, .reason = null },
        .{ .failure = .cancelled, .reason = null },
    }) |case| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
        setup.client.reStatusPeers(setup.pair.now);
        try setup.step(0);
        var injected = false;
        for (setup.client.control.operations) |operation| if (operation.request) |request| {
            if (operation.protocol != .status_v1) continue;
            const service = &setup.client_service.reqresp;
            const slot = service.outboundSlot(request).?;
            slot.fail(service, request.index, case.failure, &setup.pair.client);
            injected = true;
            break;
        };
        try std.testing.expect(injected);
        for (0..4) |_| try setup.step(0);
        setup.pair.advance(2_001);
        for (0..12) |_| try setup.step(0);
        if (case.reason) |reason| {
            try std.testing.expectEqual(@as(u16, 0), setup.client.catalog.connectedCount());
            var events: [1]t.Event = undefined;
            try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&events));
            try std.testing.expectEqual(reason, events[0].closed.reason);
        } else {
            try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
        }
    }
}

fn allocationCheck(a: std.mem.Allocator) !void {
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    var service = try @import("service.zig").Service.init(a, managed.serviceOptions(options(), &.{}));
    defer service.deinit();
    var core = try managed.PeerManager.init(a, &identity, &localState(.{}), managed.peerOptions(options()), &service);
    defer core.deinit();
    try std.testing.expect(core.memoryPlan().allocated_bytes > core.memoryPlan().control_bytes);
}

test "managed startup allocation failure cleans every prefix and memory accounts exact reservations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    var service = try @import("service.zig").Service.init(failing.allocator(), managed.serviceOptions(options(), &.{}));
    defer service.deinit();
    var core = try managed.PeerManager.init(failing.allocator(), &identity, &localState(.{}), managed.peerOptions(options()), &service);
    const expected = core.memoryPlan().allocated_bytes + service.allocatedBytes();
    std.debug.print("sampling core allocation={d} prefixes={d} inline={d}\n", .{ expected, failing.alloc_index, @sizeOf(managed.PeerManager) });
    try std.testing.expectEqual(expected, failing.allocated_bytes);
    const core_bytes = core.memoryPlan().allocated_bytes;
    core.deinit();
    try std.testing.expectEqual(core_bytes, failing.freed_bytes);
}

test "managed native deterministic replacement cancels old control and ignores stale physical close" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    try setup.initDirection(&local, true);
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const old = snapshots[0];
    try std.testing.expect(old.relevant);
    try std.testing.expectEqual(@as(usize, 4), old.custody_groups.?.count());
    try std.testing.expectEqual(@as(usize, 8), old.sampling_groups.?.count());
    setup.client.reStatusPeers(setup.pair.now);
    try setup.step(1);
    var old_request: ?rr.RequestHandle = null;
    for (setup.client.control.operations) |op| if (op.request != null) {
        old_request = op.request;
        break;
    };
    try std.testing.expect(old_request != null);
    _ = try setup.pair.dial();
    for (0..60) |_| try setup.step(1);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(old.peer, snapshots[0].peer);
    try std.testing.expect(!std.meta.eql(old.connection, snapshots[0].connection));
    try std.testing.expect(snapshots[0].relevant);
    const selected = snapshots[0];
    try std.testing.expectEqual(old.custody_groups, selected.custody_groups);
    try std.testing.expectEqual(old.sampling_groups, selected.sampling_groups);
    try std.testing.expect(setup.pair.client.registry.slots[old.connection.?.index].conn == null);
    try std.testing.expectEqual(@as(u16, 1), setup.pair.client.registry.active_len);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(old.connection.?));
    _ = managed.process(
        &setup.client,
        &setup.client_service,
        &setup.pair.client,
        &.{.{ .closed = .{
            .conn = old.connection.?,
            .peer_id = old.identity,
            .direction = old.direction,
            .reason = .host,
        } }},
        &.{},
        setup.pair.now,
        100,
        &.{},
        &.{},
        &.{},
    );
    setup.client.control.events(
        &setup.client_service,
        &setup.client.catalog,
        &setup.pair.client,
        &setup.client.local,
        setup.pair.now,
        100,
        &.{.{ .failed = .{ .request = old_request.?, .reason = .timeout } }},
    );
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(selected, snapshots[0]);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
}

test "managed native saturated app requests retain partitioned borrows while controls progress" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    const bytes = [_]u8{0} ** 8 ++ [_]u8{1} ++ [_]u8{0} ** 15;
    const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, sink_size * 8);
    defer std.testing.allocator.free(sinks);
    defer managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
    const protocols = [_]rr.Protocol{
        .blocks_by_range_v2,
        .blocks_by_root_v2,
        .blob_sidecars_by_range_v1,
        .blob_sidecars_by_root_v1,
    };
    for (0..8) |index| {
        const protocol = protocols[index / 2];
        _ = try managed.sendReqRespRequest(
            &setup.client,
            &setup.client_service,
            &setup.pair.client,
            conn,
            protocol,
            bytes[0..protocol.info().request_min],
            sinks[index * sink_size ..][0..sink_size],
            .{},
            setup.pair.now,
        );
    }
    try std.testing.expectError(
        error.TooManyRequests,
        managed.sendReqRespRequest(
            &setup.client,
            &setup.client_service,
            &setup.pair.client,
            conn,
            .blocks_by_range_v2,
            &bytes,
            sinks[0..sink_size],
            .{},
            setup.pair.now,
        ),
    );
    try std.testing.expectError(
        error.ControlProtocol,
        managed.sendReqRespRequest(
            &setup.client,
            &setup.client_service,
            &setup.pair.client,
            conn,
            .ping_v1,
            &([_]u8{0} ** 8),
            sinks[0..sink_size],
            .{},
            setup.pair.now,
        ),
    );
    setup.client.reStatusPeers(setup.pair.now);
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
    var applications: [1]rr.Event = undefined;
    var delivered: usize = 0;
    for (0..16) |_| {
        const counts = managed.process(
            &setup.server,
            &setup.server_service,
            &setup.pair.server,
            &.{},
            &.{},
            setup.pair.now,
            100,
            &.{},
            &applications,
            &.{},
        );
        if (counts.application == 0) continue;
        if (applications[0] != .request) continue;
        const request = applications[0].request;
        try std.testing.expect(!request.protocol.isControl());
        try std.testing.expectEqualSlices(
            u8,
            bytes[0..request.protocol.info().request_min],
            request.bytes,
        );
        delivered += 1;
        _ = setup.server_service.reqresp.cancel(request.request);
    }
    try std.testing.expectEqual(@as(usize, 8), delivered);
}

test "managed native local control capacity defers with future wakeup and no peer penalty" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    var streams: usize = 0;
    for (0..64) |_| {
        _ = setup.pair.client.openStream(conn) catch break;
        streams += 1;
    }
    try std.testing.expect(streams > 0);
    setup.client.reStatusPeers(setup.pair.now);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(f64, 0), snapshots[0].score);
    try std.testing.expect(snapshots[0].relevant);
    const control_due = setup.client.control.nextWakeup(&setup.client.catalog, setup.pair.now).?;
    try std.testing.expect(control_due > setup.pair.now.mono_ms);
    managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
}

test "managed retains explicit direct connections without periodically resurrecting gossip" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const selected = snapshots[0];
    const conn = selected.connection.?;
    try std.testing.expect(setup.client.catalog.setDirect(selected.peer, true));
    var remote: [4]t.Snapshot = undefined;
    _ = setup.server.snapshots(&remote);
    try std.testing.expect(setup.server.catalog.setDirect(remote[0].peer, true));
    const driver = setup.client_service.gossipsub;
    @import("gossipsub/session_io.zig").retirePeer(driver, &setup.client_service.router, &setup.pair.client, driver.sessions.findPeer(conn).?);
    const started = driver.counters.negotiation_started;
    for (0..4) |_| {
        setup.pair.advance(1_000);
        setup.client.reStatusPeers(setup.pair.now);
        for (0..16) |_| try setup.step(0);
        try std.testing.expect(!driver.admitted(conn));
        const snapshot = setup.client.catalog.get(selected.peer).?;
        try std.testing.expect(snapshot.relevant);
        try std.testing.expect(snapshot.disconnect_reason == null);
        try std.testing.expectEqual(@as(f64, 0), snapshot.score);
    }
    try std.testing.expectEqual(started, driver.counters.negotiation_started);
    try std.testing.expectEqual(@as(u16, 1), setup.client.selection.deficits.outbound);
}

test "managed direct removal clears both pins and gossip score reads have no feedback" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const identity = setup.pair.server_ctx.local_peer_id;
    try setup.client.addDirectPeer(&setup.client_service, &identity, &.{support.server_address}, setup.pair.now);
    setup.pair.advance(1_000);
    for (0..3) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].direct);
    const conn = snapshots[0].connection.?;
    @import("gossipsub/test_support.zig").penalize(setup.client_service.gossipsub, conn, 7);
    const before = setup.client.gossipScore(&setup.client_service, snapshots[0].peer, setup.pair.now).?;
    try std.testing.expect(std.math.isFinite(before));
    _ = setup.client.reportPeer(snapshots[0].peer, .high_tolerance, setup.pair.now);
    try std.testing.expectEqual(
        before,
        setup.client.gossipScore(&setup.client_service, snapshots[0].peer, setup.pair.now).?,
    );
    _ = setup.client.removeDirectPeer(&setup.client_service, &identity);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(!snapshots[0].direct);
    const logical = setup.client_service.gossipsub.peers.find(&identity).?;
    try std.testing.expect(!setup.client_service.gossipsub.peers.rows[logical.index].direct);
    var intents: [2]@import("peers/dial_queue.zig").DialIntent = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents),
    );
}

test "managed native preserves gossip events under one output and caller validation wrappers" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    try gossip_test.subscribe(setup.client_service.gossipsub, topic);
    try gossip_test.subscribe(setup.server_service.gossipsub, topic);
    for (0..50) |_| try setup.step(0);
    setup.pair.advance(1_001);
    for (0..30) |_| try setup.step(0);
    for (0..30) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var output: [1]gossip.Event = undefined;
        _ = managed.process(&setup.server, &setup.server_service, &setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &output);
        _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &output);
    }
    setup.pair.advance(1_001);
    for (0..10) |_| try setup.step(0);
    const payload = "bounded managed gossip payload";
    _ = try managed.publishGossipWithOptions(&setup.client, &setup.client_service, topic, payload, .{ .allow_zero_peers = false }, setup.pair.now);
    try std.testing.expectError(error.Duplicate, managed.publishGossipWithOptions(&setup.client, &setup.client_service, topic, payload, .{}, setup.pair.now));
    try std.testing.expect((try managed.publishGossipWithOptions(&setup.client, &setup.client_service, topic, payload, .{ .ignore_duplicate = true }, setup.pair.now)).duplicate);
    var received: usize = 0;
    for (0..50) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var activity: [4]Engine.Handle = undefined;
        var messages: [1]gossip.Event = undefined;
        const active = setup.pair.server.takeActivity(&activity);
        const counts = managed.process(&setup.server, &setup.server_service, &setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), activity[0..active], setup.pair.now, 100, &.{}, &.{}, &messages);
        if (counts.gossipsub == 1 and messages[0] == .message) {
            const message = messages[0].message;
            try std.testing.expectEqualStrings(payload, message.bytes);
            try std.testing.expectEqual(
                gossip.ReportOutcome{ .applied = .accept },
                setup.server_service.gossipsub.report(message.handle, .accept, setup.pair.now),
            );
            try std.testing.expectEqualStrings(payload, message.bytes);
            received += 1;
        }
        _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try gossip_test.unsubscribe(setup.client_service.gossipsub, topic);
}

test "raw Service defaults stay unreserved" {
    const raw: @import("service.zig").Options = .{ .reqresp = .{ .forks = &.{} } };
    try std.testing.expectEqual(@as(u16, 0), raw.reqresp.outbound_control_reserved);
    try std.testing.expectEqual(@as(u8, 8), raw.reqresp.inbound_per_peer_max);
    try std.testing.expectEqual(@as(u8, 0), raw.reqresp.inbound_application_per_peer_max);
    try std.testing.expect(raw.automatic_gossip_admission);
}

test "managed native continuous reStatus cannot starve due metadata sequence confirmation" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    try @import("managed_test_support.zig").updateLocal(&setup.server, &setup.server_service, &metadataUpdate(&setup.server, &localState(.{ .metadata = .{ .seq_number = 12 } }).metadata), setup.pair.now);
    setup.pair.advance(21_000);
    for (0..60) |_| {
        setup.client.reStatusPeers(setup.pair.now);
        try setup.step(0);
    }
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 12), snapshots[0].metadata.?.seq_number);
}

test "managed native Goodbye immediately removes relevance and delayed Status cannot revive it" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    setup.client.reStatusPeers(setup.pair.now);
    try setup.step(0);
    try std.testing.expectEqual(
        t.ReputationDecision.none,
        setup.client.reportPeer(peer, .low_tolerance, setup.pair.now).?,
    );
    try std.testing.expectEqual(
        t.ReputationDecision.disconnect,
        setup.client.reportPeer(peer, .low_tolerance, setup.pair.now).?,
    );
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().connected);
    for (0..20) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().relevant);
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&event));
    try std.testing.expect(!event[0].updated.relevant);
    setup.pair.advance(2_000);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().connected);
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&event));
    try std.testing.expectEqual(t.DisconnectReason.reputation, event[0].closed.reason);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1 }, &setup.client.control.counters.events.disconnected);
    const fault = @intFromEnum(@import("peers/goodbye.zig").Reason.bad_score);
    try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.events.sent_goodbyes[fault]);
    try std.testing.expectEqual(@as(u64, 1), setup.server.control.counters.events.goodbyes[fault]);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1 }, &setup.client.control.counters.events.disconnected);
}

test "managed native hard close retires QUIC routes streams and registry with zero public output" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    try std.testing.expect(setup.client.disconnect(snapshots[0].peer, .host, setup.pair.now));
    setup.pair.advance(2_000);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
    try std.testing.expectEqual(@as(usize, 0), setup.pair.client.registry.routes.count);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(conn));
}

test "managed native leased dial retires uncompleted handshake and rejects late acknowledgements" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var identity = setup.pair.server_ctx.local_peer_id;
    var address = support.server_address;
    try setup.client.connect(&identity, &.{address}, setup.pair.now);
    identity.bytes[0] ^= 1;
    address = .unspecified;
    var output: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &output),
    );
    const intent = output[0];
    try std.testing.expect(intent.peer.eql(&setup.pair.server_ctx.local_peer_id));
    try std.testing.expect(intent.address.eql(support.server_address));
    const conn = try setup.pair.client.dial(
        &intent.address,
        intent.peer,
        setup.pair.now,
    );
    try std.testing.expect(setup.client.dialStarted(intent.token, conn));
    setup.pair.advance(10_000);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 0, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.dialing);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expect(!setup.client.dialStarted(intent.token, conn));
    try std.testing.expect(!setup.client.dialFailed(intent.token, setup.pair.now));
    try std.testing.expect(setup.client.dial_queue.nextWakeup(setup.pair.now.mono_ms, 1).? >
        setup.pair.now.mono_ms);
}

test "managed native dial expiry closes authenticated attempt before connected event delivery" {
    for ([_]bool{ false, true }) |shutdown| {
        var setup: Setup = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        try setup.client.connect(
            &setup.pair.server_ctx.local_peer_id,
            &.{support.server_address},
            setup.pair.now,
        );
        var output: [1]managed.DialIntent = undefined;
        _ = setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &output);
        const intent = output[0];
        const conn = try setup.pair.client.dial(
            &intent.address,
            intent.peer,
            setup.pair.now,
        );
        try std.testing.expect(setup.client.dialStarted(intent.token, conn));
        try setup.pair.pump();
        try std.testing.expect(setup.pair.client.peerId(conn) != null);
        if (shutdown) managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now) else {
            setup.pair.advance(10_000);
            _ = setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &output);
        }
        for (0..8) |_| {
            try setup.pair.pump();
            var events: [32]Engine.Event = undefined;
            _ = setup.pair.events(&setup.pair.client, &events);
            _ = setup.pair.events(&setup.pair.server, &events);
        }
        try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
        try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
        try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    }
}

test "managed competing one-shot attempt expires during selected peer ban cooldown" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    try setup.client.connect(&setup.pair.server_ctx.local_peer_id, &.{support.server_address}, setup.pair.now);
    var intents: [1]managed.DialIntent = undefined;
    _ = setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents);
    const token = intents[0].token;
    const attempt = try setup.pair.dial();
    try std.testing.expect(setup.client.dialStarted(token, attempt));
    _ = try setup.pair.server.dial(&support.client_address, setup.pair.client_ctx.local_peer_id, setup.pair.now);
    try setup.pair.pump();
    try std.testing.expect(setup.pair.client.peerId(attempt) != null);
    var transport: [32]Engine.Event = undefined;
    const events = setup.pair.events(&setup.pair.client, &transport);
    var selected: ?Engine.Event = null;
    for (events) |event| if (event == .connected and event.connected.direction == .inbound) {
        selected = event;
    };
    try std.testing.expect(selected != null);
    // Deliver the inbound authentication first, retaining the competing connected event at the host.
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{selected.?}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(!std.meta.eql(attempt, snapshots[0].connection.?));
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.reportPeer(snapshots[0].peer, .fatal, setup.pair.now).?);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    setup.pair.advance(10_000);
    _ = setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[attempt.index].conn == null);
    try std.testing.expect(!setup.client.dialStarted(token, attempt));
    try std.testing.expect(!setup.client.dialFailed(token, setup.pair.now));
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
    try std.testing.expectEqual(@as(?u64, null), setup.client.dial_queue.nextWakeup(setup.pair.now.mono_ms, 1));
    try std.testing.expectEqual(@as(usize, 0), setup.client.dial_queue.resourceSnapshot().occupied);
}

test "managed review early native close preserves selected reason and counts it once" {
    for ([_]?t.DisconnectReason{ .host, .reputation, .banned, .incompatible_fork, null }) |reason| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(1);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.server.snapshots(&snapshots);
        const remote_conn = snapshots[0].connection.?;
        _ = setup.client.snapshots(&snapshots);
        if (reason) |typed| {
            try std.testing.expect(setup.client.disconnect(snapshots[0].peer, typed, setup.pair.now));
            for (0..8) |_| try setup.step(0);
        }
        try std.testing.expect(setup.pair.server.close(remote_conn, 0));
        for (0..8) |_| try setup.step(0);
        var output: [1]t.Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&output));
        const expected = reason orelse .transport_closed;
        try std.testing.expectEqual(expected, output[0].closed.reason);
        try std.testing.expectEqual(@as(u64, 1), setup.client.control.counters.closed[@intFromEnum(expected)]);
        setup.pair.advance(2_000);
        for (0..8) |_| try setup.step(0);
        var total: u64 = 0;
        for (setup.client.control.counters.closed) |count| total += count;
        try std.testing.expectEqual(@as(u64, 1), total);
    }
}

test "managed coverage demand copies persists across slots and keeps general discovery independent" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var demand: t.Demand = .{ .syncnets = 1 };
    try setup.client.setDemand(&demand);
    demand.syncnets = 2;
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.discoveryNeed().general);
    setup.pair.advance(60_000);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.discoveryNeed().syncnets);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 10_000, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.discoveryNeed().syncnets);
    try setup.client.setDemand(&.{});
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 10_000, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.discoveryNeed().general);
    const due = managed.nextWakeup(&setup.client, &setup.client_service, setup.pair.now, 0, 0, 0, 0);
    try std.testing.expect(due == null or due.? > setup.pair.now.mono_ms);
}

test "managed coverage authenticated custody differs from gossip delivery and invalidates fork groups" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .syncnets = 1, .custody_group_count = 128 } };
    try setup.init(&local);
    defer setup.deinit();
    try subscribeServer(&setup, "/eth2/00000000/sync_committee_0/ssz_snappy");
    try subscribeServer(&setup, "/eth2/00000000/data_column_sidecar_0/ssz_snappy");
    var demand: t.Demand = .{ .syncnets = 1 };
    demand.group_targets[0] = 1;
    try setup.client.setDemand(&demand);
    for (0..60) |_| try setup.step(0);
    setup.pair.advance(1_000);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(setup.client.catalog.setDirect(snapshots[0].peer, true));
    const connection = snapshots[0].connection.?;
    const index = setup.client_service.gossipsub.sessions.findPeer(connection).?;
    @import("gossipsub/session_io.zig").resetOutbound(setup.client_service.gossipsub, &setup.pair.client, index);
    try std.testing.expect(!setup.client_service.gossipsub.deliveryAvailable(connection));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try @import("managed_test_support.zig").updateLocal(&setup.client, &setup.client_service, &local, setup.pair.now);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].custody_groups == null);
}

test "managed coverage physical closing capacity blocks new leased intents" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(setup.client.disconnect(snapshots[0].peer, .host, setup.pair.now));
    for (0..2) |_| _ = try setup.pair.client.dial(&support.server_address, setup.pair.server_ctx.local_peer_id, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 3), setup.pair.client.registry.active_len);
    var secret: [32]u8 = @splat(0);
    secret[31] = 17;
    const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    try setup.client.connect(&peer, &.{support.server_address}, setup.pair.now);
    var out: [2]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.dial_queue.attempts().total);
}

test "managed coverage direct candidate dials at soft target and respects physical hard capacity" {
    var setup: Setup = .{};
    var opts = options();
    opts.peers.target_peers = 1;
    opts.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    var secret: [32]u8 = @splat(0);
    secret[31] = 17;
    const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    try setup.client.addDirectPeer(&setup.client_service, &peer, &.{support.server_address}, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&peer));
}

fn candidateFor(peer: *const t.PeerId, count: ?u64) !@import("peers/enr.zig").Candidate {
    return .{ .peer = peer.*, .node_id = try @import("peers/custody.zig").nodeId(peer), .sequence = 1, .record_hash = @splat(0), .addresses = .{ support.server_address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = null, .custody_group_count = count };
}

test "managed coverage automatic retention renews only at authenticated Status success" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    const horizon = setup.client.dial_queue.rows[0].history_until_ms;
    setup.pair.advance(1000);
    for (0..10) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.dial_queue.rows[0].history_until_ms);
    candidate.sequence = 2;
    try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.dial_queue.rows[0].history_until_ms);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..50) |_| try setup.step(0);
    try std.testing.expect(setup.client.dial_queue.rows[0].history_until_ms > horizon);
}

test "managed coverage bounded custody work resumes without output and stale metadata cannot satisfy demand" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 127, .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    var demand: t.Demand = .{ .syncnets = 1 };
    demand.group_targets[0] = 1;
    try setup.client.setDemand(&demand);
    for (0..50) |_| try setup.step(0);
    var initial: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&initial);
    try std.testing.expect(setup.client.catalog.updateMetadata(initial[0].peer, initial[0].connection.?, &.{ .seq_number = 10, .custody_group_count = 1 }, setup.pair.now.mono_ms));
    try std.testing.expect(setup.client.catalog.updateMetadata(initial[0].peer, initial[0].connection.?, &.{ .seq_number = 11, .custody_group_count = 127, .syncnets = 1 }, setup.pair.now.mono_ms));
    for (0..4) |i| {
        var secret: [32]u8 = @splat(0);
        secret[31] = @intCast(i + 20);
        const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
        const peer = t.PeerId.fromPublicKey(&key);
        const candidate = try candidateFor(&peer, 127);
        try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    }
    var saw_pending = false;
    for (0..80) |_| {
        const before = setup.client.counters.custody_hashes;
        try setup.step(0);
        try std.testing.expect(setup.client.counters.custody_hashes - before <= 256);
        if (setup.client.custody_pending) {
            saw_pending = true;
            try std.testing.expect(managed.nextWakeup(&setup.client, &setup.client_service, setup.pair.now, 0, 0, 0, 0).? <= setup.pair.now.mono_ms +| 1);
        }
    }
    try std.testing.expect(saw_pending);
    try std.testing.expect(!setup.client.custody_pending);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(usize, 127), snapshots[0].custody_groups.?.count());
    setup.pair.advance(60_000);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
}

test "managed coverage outbound deficit uses hard room or retires inbound before replacement" {
    for ([_]u16{ 1, 2 }) |maximum| {
        var setup: Setup = .{};
        var opts = options();
        opts.peers.max_peers = maximum;
        opts.peers.target_peers = 1;
        opts.peers.min_outbound = 1;
        try setup.initOwnersWithOptions(&.{}, opts);
        defer setup.deinit();
        _ = try setup.pair.dial();
        for (0..60) |_| try setup.step(0);
        if (maximum == 1) {
            setup.pair.advance(setup.server.control.options.inbound_status_grace_ms);
            setup.server.reconcile(&setup.server_service, setup.pair.now);
            try std.testing.expect(setup.server.counters.policy_disconnects > 0);
            setup.pair.advance(2000);
            for (0..8) |_| try setup.step(0);
            try std.testing.expectEqual(@as(u16, 0), setup.pair.server.registry.active_len);
        } else try std.testing.expectEqual(@as(u16, 1), setup.server.peerCounts().relevant);
        var secret: [32]u8 = @splat(0);
        secret[31] = 17;
        const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
        const peer = t.PeerId.fromPublicKey(&key);
        const candidate = try candidateFor(&peer, null);
        try std.testing.expectEqual(@as(u16, 1), setup.server.discoveredBatch(&setup.server_service, &.{candidate}, setup.pair.now).accepted);
        var out: [1]managed.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.dialIntents(&setup.server_service, &setup.pair.server, setup.pair.now, &out));
        try std.testing.expect(out[0].peer.eql(&peer));
    }
}

test "managed coverage review same-digest group update disables cached automatic candidate" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 128 } };
    try setup.initOwners(&local);
    defer setup.deinit();
    var candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, 128);
    candidate.syncnets = 1;
    try setup.client.setDemand(&.{ .syncnets = 1 });
    try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try @import("managed_test_support.zig").updateLocal(&setup.client, &setup.client_service, &local, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.dial_queue.rows[0].priority);
    try std.testing.expectEqual(@as(u64, 1), setup.client.dial_queue.rows[0].hints.?.sequence);
    candidate.sequence = 2;
    candidate.custody_group_count = 64;
    try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "managed reconciliation idle and candidate batch work" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    for (0..8) |_| {
        try setup.step(0);
        _ = setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &.{});
    }
    const c = setup.client.counters;
    const requested = setup.client.requested_connect;
    const candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    for (0..4) |_| try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    const after = setup.client.counters;
    try std.testing.expectEqual(@as(u64, 1), c.selections);
    try std.testing.expectEqual(@as(u64, 1), c.candidate_syncs);
    try std.testing.expectEqual(@as(u64, 0), after.selections - c.selections);
    try std.testing.expectEqual(requested, setup.client.requested_connect);
    try std.testing.expectEqual(c.selections, setup.client.selection_duration.count);
    try std.testing.expect(after.candidate_syncs - c.candidate_syncs <= 1);
}

test "managed reconciliation scans retained deadlines once and accounts for candidate lookups" {
    var opts = options();
    opts.peers.capacity = 32;
    opts.dial.capacity = 16;
    var setup: Setup = .{};
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    const core = &setup.client;
    const now = setup.pair.now;
    const candidates = opts.dial.capacity / 2;
    for (0..opts.peers.capacity) |i| {
        const identity: t.PeerId = .{ .bytes = @splat(@intCast(i + 1)) };
        const conn: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        const peer = core.catalog.admit(&identity, &core.local_identity, conn, &.{ .direction = .outbound, .endpoint = support.server_address, .now_ms = now.mono_ms }).admitted.peer;
        try std.testing.expectEqual(.ban, core.catalog.report(peer, .fatal, now.mono_ms).?);
        try std.testing.expect(core.catalog.disconnect(peer, conn, .banned, now.mono_ms));
        if (i < candidates) try core.dial_queue.enqueue(&identity, &.{support.server_address}, true, now.mono_ms);
    }
    const lookup_rows: u64 = @as(u64, candidates) * (candidates + 1) / 2 +
        @as(u64, opts.peers.capacity - candidates) * opts.dial.capacity;
    core.reconcile(&setup.client_service, now);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.catalog_deadline_rows);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.candidate_rows);
    try std.testing.expectEqual(lookup_rows, core.dial_queue.counters.sync_lookup_rows);
    const due = now.mono_ms + @import("peers/reputation.zig").ban_cooldown_ms;
    for (core.dial_queue.rows[0..candidates]) |row| try std.testing.expectEqual(due, row.eligible_at_ms);
    const before = core.counters;
    const dial_before = core.dial_queue.counters;
    core.reconcile(&setup.client_service, now);
    try std.testing.expectEqualDeep(before, core.counters);
    try std.testing.expectEqualDeep(dial_before, core.dial_queue.counters);

    const retained = core.catalog.get(.{ .index = 0, .generation = 1 }).?;
    try std.testing.expectEqual(.ban, core.catalog.report(retained.peer, .fatal, now.mono_ms).?);
    core.reconcile(&setup.client_service, now);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.catalog_deadline_rows - before.catalog_deadline_rows);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.candidate_rows - before.candidate_rows);
    try std.testing.expectEqual(lookup_rows, core.dial_queue.counters.sync_lookup_rows - dial_before.sync_lookup_rows);

    const offline = core.catalog.get(.{ .index = opts.peers.capacity - 1, .generation = 1 }).?;
    const sync_before = core.counters;
    const lookup_before = core.dial_queue.counters.sync_lookup_rows;
    try core.connect(&offline.identity, &.{support.server_address}, now);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.candidate_lookup_rows - sync_before.candidate_lookup_rows);
    try std.testing.expectEqual(@as(u64, opts.peers.capacity), core.counters.catalog_deadline_rows - sync_before.catalog_deadline_rows);
    try std.testing.expectEqual(@as(u64, candidates + 1), core.dial_queue.counters.sync_lookup_rows - lookup_before);
    try std.testing.expectEqual(due, core.dial_queue.rows[candidates].eligible_at_ms);
}

test "managed reconciliation reads preserve completed demand and catalog evaluation" {
    var setup: Setup = .{};
    var opts = options();
    opts.peers.target_peers = 1;
    opts.peers.min_outbound = 0;
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 1 } };
    try setup.initOwnersWithOptions(&local, opts);
    defer setup.deinit();
    const view: *const managed.PeerManager = &setup.client;
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(managed.DiscoveryNeed{}, view.discoveryNeed());
    var demand: t.Demand = .{ .attnets = 0x81, .syncnets = 1 };
    demand.group_targets[0] = 1;
    try setup.client.setDemand(&demand);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    const deficits = view.coverageDeficits();
    const need = view.discoveryNeed();
    try std.testing.expectEqual(@as(u16, 2), deficits.attestation);
    try std.testing.expectEqual(@as(u16, 1), deficits.sync);
    try std.testing.expectEqual(@as(u16, 1), deficits.groups);
    try std.testing.expect(need.general and need.custody);
    try std.testing.expectEqual(@as(u8, 0x81), need.attnets[0]);
    try std.testing.expectEqual(@as(u8, 1), need.syncnets);

    try setup.client.setDemand(&.{});
    try std.testing.expectEqual(setup.pair.now.mono_ms, managed.nextWakeup(&setup.client, &setup.client_service, setup.pair.now, 0, 0, 0, 0).?);
    const dirty = view.diagnostics(&setup.client_service);
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.diagnostics(&setup.client_service));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(managed.DiscoveryNeed{ .general = true }, view.discoveryNeed());

    const identity = setup.pair.server_ctx.local_peer_id;
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = setup.client.catalog.admit(&identity, &view.local_identity, conn, &.{ .direction = .outbound, .endpoint = support.server_address, .now_ms = setup.pair.now.mono_ms }).admitted.peer;
    try std.testing.expect(setup.client.catalog.updateStatus(peer, conn, &local.status, setup.pair.now.mono_ms));
    try std.testing.expect(setup.client.catalog.setDirect(peer, true));
    try std.testing.expectEqual(setup.pair.now.mono_ms, managed.nextWakeup(&setup.client, &setup.client_service, setup.pair.now, 0, 0, 0, 0).?);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(managed.DiscoveryNeed{ .general = true }, view.discoveryNeed());
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(managed.DiscoveryNeed{}, view.discoveryNeed());
}

test "managed reconciliation reads do not decay reputation or schedule peer removal" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
    const snapshot = snapshots[0];
    const view: *const managed.PeerManager = &setup.client;
    const deficits = view.coverageDeficits();
    const need = view.discoveryNeed();
    try std.testing.expectEqual(.none, setup.client.reportPeer(snapshot.peer, .high_tolerance, setup.pair.now).?);
    setup.pair.advance(100);
    try setup.client.addDirectPeer(&setup.client_service, &snapshot.identity, &.{support.server_address}, setup.pair.now);
    const incompatible: t.Status = .{ .fork_digest = @splat(1) };
    try std.testing.expect(setup.client.catalog.updateStatus(snapshot.peer, snapshot.connection.?, &incompatible, setup.pair.now.mono_ms));
    var events: [4]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&events));
    const dirty = view.catalog.get(snapshot.peer).?;
    const diagnostics = view.diagnostics(&setup.client_service);
    const dial_counters = view.dial_queue.counters;
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.catalog.get(snapshot.peer).?);
    try std.testing.expectEqualDeep(diagnostics, view.diagnostics(&setup.client_service));
    try std.testing.expectEqualDeep(dial_counters, view.dial_queue.counters);
    try std.testing.expect(!view.catalog.eventsPending());
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    const evaluated = view.catalog.get(snapshot.peer).?;
    try std.testing.expect(evaluated.score > dirty.score);
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, evaluated.disconnect_reason.?);
    try std.testing.expectEqual(@as(u16, 1), view.coverageDeficits().outbound);
    try std.testing.expect(view.discoveryNeed().general);
    try std.testing.expect(view.catalog.eventsPending());
}

test "managed reconciliation clears policy observations at quiescence and shutdown" {
    for ([_]bool{ false, true }) |graceful| {
        var setup: Setup = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        try setup.client.setDemand(&.{ .syncnets = 1 });
        _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
        try std.testing.expect(setup.client.discoveryNeed().general);
        if (graceful) {
            managed.beginGracefulClose(&setup.client, &setup.client_service, setup.pair.now);
        } else managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
        const view: *const managed.PeerManager = &setup.client;
        const diagnostics = view.diagnostics(&setup.client_service);
        setup.pair.advance(60_000);
        setup.client.reconcile(&setup.client_service, setup.pair.now);
        try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
        try std.testing.expectEqualDeep(managed.DiscoveryNeed{}, view.discoveryNeed());
        try std.testing.expectEqualDeep(diagnostics, view.diagnostics(&setup.client_service));
        _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 200, &.{}, &.{}, &.{});
        try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
        try std.testing.expectEqualDeep(managed.DiscoveryNeed{}, view.discoveryNeed());
    }
}

test "managed reconciliation raw mutators and deadlines invalidate once" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .altair }, .metadata = .{ .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    try subscribeServer(&setup, "/eth2/00000000/sync_committee_0/ssz_snappy");
    const demand: t.Demand = .{ .syncnets = 1 };
    try setup.client.setDemand(&demand);
    for (0..60) |_| try setup.step(0);
    setup.pair.advance(setup.client.control.options.inbound_status_grace_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    const before = setup.client.counters.selections;
    for (0..8) |_| {
        setup.pair.advance(1);
        setup.client.reconcile(&setup.client_service, setup.pair.now);
        _ = setup.client.coverageDeficits();
    }
    try std.testing.expectEqual(before, setup.client.counters.selections);
    try std.testing.expect(setup.client.catalog.updateMetadata(peer, conn, &.{ .seq_number = 10, .syncnets = 0 }, setup.pair.now.mono_ms));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(before + 1, setup.client.counters.selections);
    try std.testing.expectEqual(@as(u4, 0), setup.client.policy_scratch[0].stable.syncnets);
    try std.testing.expect(setup.client.catalog.updateMetadata(peer, conn, &.{ .seq_number = 11, .syncnets = 1 }, setup.pair.now.mono_ms));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    const deadline = setup.client.selection_deadline.?;
    var clock = setup.pair.now;
    clock.mono_ms = deadline - 1;
    setup.client.reconcile(&setup.client_service, clock);
    const fresh = setup.client.counters.selections;
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.discoveryNeed().syncnets);
    try std.testing.expectEqual(deadline, setup.client.reconciliation_deadline.?);
    clock.mono_ms = deadline;
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(@as(u4, 0), setup.client.policy_scratch[0].stable.syncnets);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.discoveryNeed().syncnets);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);
    clock.mono_ms += 1;
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);

    @import("gossipsub/test_support.zig").penalize(setup.client_service.gossipsub, conn, 7);
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);
    _ = setup.client_service.gossipsub.scoreSnapshot(conn, clock);
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);
    _ = setup.client.reportPeer(peer, .high_tolerance, clock);
    setup.client.reconcile(&setup.client_service, clock);
    const penalized = setup.client.counters.selections;
    const health = setup.client.catalog.get(peer).?.score;
    clock.mono_ms += 100;
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expect(setup.client.catalog.get(peer).?.score > health);
    try std.testing.expectEqual(penalized, setup.client.counters.selections);

    try setup.client.addDirectPeer(&setup.client_service, &snapshots[0].identity, &.{support.server_address}, clock);
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(penalized + 1, setup.client.counters.selections);
    _ = setup.client.removeDirectPeer(&setup.client_service, &snapshots[0].identity);
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(penalized + 2, setup.client.counters.selections);
    try setup.client.setDemand(&.{});
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(penalized + 3, setup.client.counters.selections);
    try setup.client.setDemand(&.{});
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(penalized + 3, setup.client.counters.selections);
    try std.testing.expect(setup.client.disconnect(peer, .host, clock));
    setup.client.reconcile(&setup.client_service, clock);
    try std.testing.expectEqual(@as(u16, 0), setup.client.selection.retained_count);
}

test "managed reconciliation batch counts refusal and fresh native room independently" {
    var setup: Setup = .{};
    var opts = options();
    opts.peers.max_peers = 1;
    opts.peers.target_peers = 1;
    opts.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    const baseline = setup.client.counters;
    const candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    const self_candidate = try candidateFor(&setup.pair.client_ctx.local_peer_id, null);
    var invalid = candidate;
    invalid.address_count = 0;
    const result = setup.client.discoveredBatch(&setup.client_service, &.{ candidate, self_candidate, invalid, candidate }, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 2), result.accepted);
    try std.testing.expectEqual(@as(u16, 2), result.refused);
    const conn = try setup.pair.dial();
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(setup.pair.client.abandon(conn));
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(baseline.selections, setup.client.counters.selections);
    try std.testing.expectEqual(baseline.candidate_selections + 1, setup.client.counters.candidate_selections);
    try std.testing.expectEqual(baseline.candidate_syncs, setup.client.counters.candidate_syncs);
}

test "managed reconciliation exhausted revisions stay invalidated" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    setup.client.catalog.revision = std.math.maxInt(u64);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    const before = setup.client.counters.selections;
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(before + 1, setup.client.counters.selections);
}

test "managed reconciliation ban expiry still defers until strict score recovery" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.reportPeer(peer, .fatal, setup.pair.now).?);
    setup.client.control.close(&setup.client_service, &setup.client.catalog, &setup.pair.client, peer, conn, .banned, setup.pair.now);
    const candidate = try candidateFor(&snapshots[0].identity, null);
    try std.testing.expectEqual(@as(u16, 1), setup.client.discoveredBatch(&setup.client_service, &.{candidate}, setup.pair.now).accepted);
    var out: [1]managed.DialIntent = undefined;
    const ban = setup.client.catalog.get(peer).?.ban_until_ms;
    var clock = setup.pair.now;
    clock.mono_ms = ban - 1;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, clock, &out));
    clock.mono_ms = ban;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, clock, &out));
    const recovery = setup.client.reconciliation_deadline.?;
    try std.testing.expect(recovery > ban);
    clock.mono_ms = recovery - 1;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.client_service, &setup.pair.client, clock, &out));
    clock.mono_ms = recovery;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, clock, &out));
    try std.testing.expect(setup.client.catalog.get(peer).?.score > -50);
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "managed native immediate close preserves direct membership and rejects stale generations" {
    for ([_]usize{ 0, 1 }) |capacity| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..60) |_| try setup.step(1);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.client.snapshots(&snapshots);
        const captured = snapshots[0];
        try setup.client.addDirectPeer(&setup.client_service, &captured.identity, &.{support.server_address}, setup.pair.now);
        var identities: [4]t.PeerId = undefined;
        try std.testing.expectEqual(@as(usize, 1), try setup.client.directPeers(&identities));
        var stale_peer = captured.peer;
        stale_peer.generation += 1;
        var stale_conn = captured.connection.?;
        stale_conn.generation += 1;
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, stale_peer, captured.connection.?, setup.pair.now));
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, captured.peer, stale_conn, setup.pair.now));
        try std.testing.expect(setup.client.closePeer(&setup.client_service, &setup.pair.client, captured.peer, captured.connection.?, setup.pair.now));
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, captured.peer, captured.connection.?, setup.pair.now));
        try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().connected);
        try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().relevant);
        try std.testing.expect(setup.client.catalog.get(captured.peer).?.connection == null);
        try std.testing.expect(!setup.client.dial_queue.rows[0].connected);
        try std.testing.expect(setup.client.selection_revision == null);
        try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(captured.connection.?));
        const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
        defer std.testing.allocator.free(sink);
        try std.testing.expectError(error.StaleHandle, managed.sendReqRespRequest(
            &setup.client,
            &setup.client_service,
            &setup.pair.client,
            captured.connection.?,
            .blocks_by_root_v2,
            &.{},
            sink,
            .{},
            setup.pair.now,
        ));
        var closed: [4]t.Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&closed));
        try std.testing.expectEqualDeep(captured.connection.?, closed[0].closed.connection);
        try std.testing.expectEqual(t.DisconnectReason.host, closed[0].closed.reason);
        for (0..60) |_| try setup.step(capacity);
        try std.testing.expectEqual(@as(usize, 0), setup.client.catalog.pollEvents(&closed));
        try std.testing.expectEqual(@as(u16, 0), setup.server.peerCounts().connected);
        try std.testing.expectEqual(@as(u64, 0), setup.server.control.counters.closed[@intFromEnum(t.DisconnectReason.remote_goodbye)]);
        try std.testing.expectEqual(@as(usize, 1), try setup.client.directPeers(&identities));
        _ = setup.server.catalog.pollEvents(&closed);
        setup.pair.advance(60_000);
        var intents: [1]@import("peers/dial_queue.zig").DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents));
        const replacement = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
        try std.testing.expect(setup.client.dialStarted(intents[0].token, replacement));
        for (0..60) |_| try setup.step(1);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().relevant);
        const current = setup.client.catalog.get(captured.peer).?;
        try std.testing.expect(!std.meta.eql(captured.connection, current.connection));
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, captured.peer, captured.connection.?, setup.pair.now));
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, stale_peer, current.connection.?, setup.pair.now));
        _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{.{ .closed = .{
            .conn = captured.connection.?,
            .peer_id = captured.identity,
            .direction = captured.direction,
            .reason = .host,
        } }}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
        try std.testing.expectEqualDeep(current, setup.client.catalog.get(captured.peer).?);
        managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
        try std.testing.expect(!setup.client.closePeer(&setup.client_service, &setup.pair.client, current.peer, current.connection.?, setup.pair.now));
    }
}

test "managed native peer counts distinguish open relevant invalidated and closed without scratch mutation" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try setup.step(0);
    const owner: *const managed.PeerManager = &setup.client;
    try std.testing.expectEqual(@as(u16, 1), owner.peerCounts().connected);
    try std.testing.expectEqual(@as(u16, 0), owner.peerCounts().relevant);
    for (0..60) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const captured = snapshots[0];
    var sentinel = captured;
    sentinel.peer.generation += 1;
    @memset(setup.client.snapshot_scratch, sentinel);
    const before = setup.client.snapshot_scratch[0..4].*;
    try std.testing.expectEqualDeep(managed.PeerManager.PeerCounts{ .connected = 1, .relevant = 1, .outbound_relevant = 1 }, owner.peerCounts());
    try std.testing.expectEqualDeep(before, setup.client.snapshot_scratch[0..4].*);
    try std.testing.expect(setup.client.catalog.invalidateStatus(captured.peer, captured.connection.?));
    try std.testing.expectEqualDeep(managed.PeerManager.PeerCounts{ .connected = 1, .relevant = 0, .outbound_relevant = 0 }, owner.peerCounts());
    try std.testing.expect(setup.client.closePeer(&setup.client_service, &setup.pair.client, captured.peer, captured.connection.?, setup.pair.now));
    try std.testing.expectEqualDeep(managed.PeerManager.PeerCounts{ .connected = 0, .relevant = 0, .outbound_relevant = 0 }, owner.peerCounts());
    const offline: t.PeerId = .{ .bytes = @splat(9) };
    try setup.client.addDirectPeer(&setup.client_service, &offline, &.{support.server_address}, setup.pair.now);
    try std.testing.expect(setup.client.catalog.find(&offline) == null);
    var direct: [1]t.PeerId = undefined;
    try std.testing.expectEqual(@as(usize, 1), try owner.directPeers(&direct));
    try std.testing.expect(direct[0].eql(&offline));
    try std.testing.expect(setup.client.removeDirectPeer(&setup.client_service, &offline));
    try std.testing.expect(!setup.client.removeDirectPeer(&setup.client_service, &offline));
}

test "managed native public close cancels overlapping attempts and preserves bounded direct retry" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    try setup.client.addDirectPeer(&setup.client_service, &setup.pair.server_ctx.local_peer_id, &.{support.server_address}, setup.pair.now);
    var intents: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents));
    const token = intents[0].token;
    const attempt = try setup.pair.dial();
    try std.testing.expect(setup.client.dialStarted(token, attempt));
    _ = try setup.pair.server.dial(&support.client_address, setup.pair.client_ctx.local_peer_id, setup.pair.now);
    try setup.pair.pump();
    try std.testing.expect(setup.pair.client.peerId(attempt) != null);
    var transport: [32]Engine.Event = undefined;
    var selected: ?Engine.Event = null;
    for (setup.pair.events(&setup.pair.client, &transport)) |event| {
        if (event == .connected and event.connected.direction == .inbound) selected = event;
    }
    try std.testing.expect(selected != null);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{selected.?}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
    const accepted = snapshots[0];
    try std.testing.expect(!std.meta.eql(attempt, accepted.connection.?));
    const row = &setup.client.dial_queue.rows[token.index];
    try std.testing.expect(row.connected and row.attempt);
    try std.testing.expect(setup.client.closePeer(&setup.client_service, &setup.pair.client, accepted.peer, accepted.connection.?, setup.pair.now));
    try std.testing.expect(!row.connected and !row.attempt);
    try std.testing.expect(row.conn == null);
    try std.testing.expect(row.direct);
    try std.testing.expectEqual(token.generation, row.generation);
    try std.testing.expect(setup.pair.client.registry.slots[attempt.index].close_reason != null);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(!row.connected and !row.attempt);
    try std.testing.expect(!setup.client.dial_queue.dialClosed(attempt, setup.pair.now.mono_ms));
    const due = setup.client.dial_queue.nextWakeup(setup.pair.now.mono_ms, 1) orelse return error.MissingRetryDeadline;
    try std.testing.expect(due >= setup.pair.now.mono_ms + 60_000);
    setup.pair.advance(due - setup.pair.now.mono_ms);
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.client_service, &setup.pair.client, setup.pair.now, &intents));
    try std.testing.expectEqualDeep(accepted.identity, intents[0].peer);
    try std.testing.expectEqual(token.generation + 1, intents[0].token.generation);
}

fn waitSampling(setup: *Setup) !t.Snapshot {
    var snapshots: [4]t.Snapshot = undefined;
    for (0..200) |_| {
        try setup.step(0);
        if (setup.client.snapshots(&snapshots) == 1) {
            const snapshot = snapshots[0];
            if (snapshot.sampling_groups != null and snapshot.relevant and
                setup.client_service.gossipsub.deliveryAvailable(snapshot.connection.?)) return snapshot;
        }
        setup.pair.advance(25);
    }
    return error.SamplingReadinessTimeout;
}

test "managed sampling delivery follows real outbound stream retirement replacement and stale events" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    var opts = options();
    opts.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(@splat(0))};
    opts.service.gossipsub.observe_subscriptions = false;
    try setup.initOwnersWithOptions(&local, opts);
    defer setup.deinit();
    _ = try setup.pair.dial();
    const snapshot = try waitSampling(&setup);
    try std.testing.expectEqual(@as(usize, 4), snapshot.custody_groups.?.count());
    try std.testing.expectEqual(@as(usize, 8), snapshot.sampling_groups.?.count());
    var demand: t.Demand = .{};
    for (0..128) |i| if (snapshot.sampling_groups.?.isSet(i)) {
        demand.group_targets[i] = 1;
    };
    for (0..@import("preset").NUMBER_OF_COLUMNS) |column| {
        if (!snapshot.sampling_groups.?.isSet(column % local.fork.custody_groups)) continue;
        var buffer: [80]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "/eth2/00000000/data_column_sidecar_{d}/ssz_snappy", .{column});
        try subscribeServer(&setup, name);
    }
    for (0..40) |_| {
        try setup.step(0);
        setup.pair.advance(25);
    }
    try setup.client.setDemand(&demand);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().groups);
    const handler = setup.client_service.gossipsub;
    const index = handler.sessions.findPeer(snapshot.connection.?).?;
    const old_stream = handler.sessions.rows[index].outbound.live.stream;
    setup.pair.client.closeStream(old_stream, 0);
    handler.transportEvents(&setup.client_service.router, &setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.pair.now);
    try std.testing.expect(!handler.deliveryAvailable(snapshot.connection.?));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 8), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(snapshot.custody_groups, setup.client.catalog.get(snapshot.peer).?.custody_groups);
    handler.negotiationResult(&setup.pair.client, .{ .stream = old_stream, .direction = .outbound, .owner = .meshsub, .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_2 }, .leftover = &.{}, .fin = false } } }, setup.pair.now);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 8), setup.client.coverageDeficits().groups);
    for (0..16) |_| try setup.step(1);
    setup.pair.advance(60_000);
    for (0..16) |_| try setup.step(1);
    _ = try setup.pair.dial();
    const replacement = try waitSampling(&setup);
    for (0..80) |_| {
        try setup.step(0);
        setup.pair.advance(25);
    }
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expect(!std.meta.eql(snapshot.connection, replacement.connection));
    const replacement_index = handler.sessions.findPeer(replacement.connection.?).?;
    const replacement_stream = handler.sessions.rows[replacement_index].outbound.live.stream;
    try std.testing.expect(!std.meta.eql(old_stream, replacement_stream));
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().groups);
    handler.transportEvents(&setup.client_service.router, &setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.pair.now);
    try std.testing.expect(handler.deliveryAvailable(replacement.connection.?));
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(snapshot.custody_groups, setup.client.catalog.get(snapshot.peer).?.custody_groups);
    managed.shutdown(&setup.client, &setup.client_service, &setup.pair.client, setup.pair.now);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{.{ .stream_closed = .{ .stream = replacement_stream, .reset_code = 0 } }}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().connected);
    try std.testing.expect(!handler.deliveryAvailable(snapshot.connection.?));
}

test "managed sampling demand rejects atomically trims fork bound and persists until replacement" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    try setup.initOwners(&local);
    defer setup.deinit();
    var demand: t.Demand = .{};
    demand.group_targets[0] = 1;
    demand.custody_group_targets[0] = 1;
    demand.group_targets[127] = setup.client.catalog.options.max_peers;
    try setup.client.setDemand(&demand);
    const before = setup.client.demand;
    demand.group_targets[1] = setup.client.catalog.options.max_peers + 1;
    try std.testing.expectError(error.InvalidDemand, setup.client.setDemand(&demand));
    try std.testing.expectEqualDeep(before, setup.client.demand);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 4), setup.client.coverageDeficits().groups);
    local.fork.custody_groups = 64;
    try @import("managed_test_support.zig").updateLocal(&setup.client, &setup.client_service, &local, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.demand.group_targets[127]);
    try std.testing.expectEqual(@as(u16, 4), setup.client.coverageDeficits().groups);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 10_000, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().custody_groups);
    try std.testing.expect(setup.client.discoveryNeed().custody);
    try setup.client.setDemand(&.{});
    _ = managed.process(&setup.client, &setup.client_service, &setup.pair.client, &.{}, &.{}, setup.pair.now, 10_000, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().custody_groups);
    try std.testing.expect(!setup.client.discoveryNeed().custody);
    try std.testing.expectEqualDeep(t.Demand{}, setup.client.demand);
}

test "managed replaces failed gossip below target without a reputation penalty or admission timer" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const snapshot = snapshots[0];
    const conn = snapshot.connection.?;
    const driver = setup.client_service.gossipsub;
    const index = driver.sessions.findPeer(conn).?;
    const started = driver.counters.negotiation_started;
    try std.testing.expect(driver.deliveryAvailable(conn));
    try std.testing.expectEqual(@as(u16, 1), setup.client.selection.retained_count);
    @import("gossipsub/session_io.zig").resetOutbound(driver, &setup.pair.client, index);
    try std.testing.expectEqual(setup.pair.now.mono_ms, managed.nextWakeup(&setup.client, &setup.client_service, setup.pair.now, 0, 0, 0, 0).?);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.selection.retained_count);
    try std.testing.expectEqual(@as(u16, 1), setup.client.selection.deficits.outbound);
    const after = setup.client.catalog.get(snapshot.peer).?;
    try std.testing.expectEqual(t.DisconnectReason.gossip_unavailable, after.disconnect_reason.?);
    try std.testing.expectEqual(snapshot.score, after.score);
    try std.testing.expectEqual(@as(u64, 0), after.ban_until_ms);
    setup.client.control.maintain(&setup.client_service, &setup.client.catalog, &setup.pair.client, &setup.client.local, setup.pair.now);
    try std.testing.expectEqual(started, driver.counters.negotiation_started);
}

fn metadataUpdate(manager: *const managed.PeerManager, metadata: *const t.Metadata) t.LocalState {
    var local = manager.local;
    local.metadata = metadata.*;
    return local;
}
