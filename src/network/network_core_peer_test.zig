const schedule_test_support = @import("schedule_test_support.zig");
const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const PeerManager = @import("peer_manager.zig").PeerManager;
const DialIntent = @import("peers/dialing.zig").Dialing.DialIntent;
const DiscoveryNeed = @import("peer_manager.zig").DiscoveryNeed;
const support = @import("quic/test_support.zig");
const t = @import("peers/types.zig");
const Engine = @import("quic/Engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");

const options = @import("network_core_test_support.zig").options;
const localState = @import("network_core_test_support.zig").localState;
const Setup = @import("network_core_test_support.zig").Setup;
const updateDemand = @import("network_core_test_support.zig").updateDemand;

fn clientWakeup(setup: *Setup) ?u64 {
    return schedule_test_support.wakeupMilliseconds(setup.client.wakeups(setup.pair.now, .{}).schedule(), setup.pair.now.millis());
}

fn subscribeServer(setup: *Setup, name: []const u8) !void {
    const g = setup.client.service.gossipsub;
    g.peers.scores.applyValidatedTopic(gossip_test.intern(g, name).?, .{ .weight = 0 });
    try gossip_test.subscribe(setup.server.service.gossipsub, name);
}

test "core native two owners establish relevance and fetch initial metadata without public output" {
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
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        try std.testing.expectEqual(@as(u16, 1), setup.server.peer_manager.peerCounts().relevant);
        try std.testing.expectEqualSlices(u64, &.{ 0, 1 }, &setup.client.peer_manager.control.counters.events.connected);
        try std.testing.expectEqualSlices(u64, &.{ 1, 0 }, &setup.server.peer_manager.control.counters.events.connected);
        var snapshots: [4]t.Snapshot = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.snapshots(&snapshots));
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
        try std.testing.expectEqual(t.Direction.outbound, snapshots[0].direction);
        _ = setup.server.peer_manager.snapshots(&snapshots);
        try std.testing.expectEqual(t.Direction.inbound, snapshots[0].direction);
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
    }
}

test "core publishes the authenticated endpoint after QUIC rebinding" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.peer_manager.snapshots(&snapshots));
    const before = snapshots[0];
    try std.testing.expect(before.relevant);
    const rebound: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4003 } };
    setup.pair.client_source = rebound;
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(rebound, setup.pair.server.peerAddress(before.connection.?).?);
    const after = setup.server.peer_manager.catalog.get(before.peer).?;
    try std.testing.expectEqual(before.connection, after.connection);
    try std.testing.expectEqual(rebound, after.endpoint);
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.server.peer_manager.catalog.pollEvents(&event));
    try std.testing.expectEqual(before.peer, event[0].updated.peer);
    try std.testing.expectEqual(rebound, event[0].updated.endpoint);
}

test "core native ping coalesces metadata and confirms unchanged freshness then periodic Status" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const before = snapshots[0].metadata_at_ms;
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(1);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].metadata_at_ms > before);
    try @import("network_core_test_support.zig").updateLocal(&setup.server, &metadataUpdate(&setup.server, &localState(.{ .metadata = .{ .attnets = @splat(9) } }).metadata), setup.pair.now);
    var changed = setup.server.localState().metadata;
    try std.testing.expectEqual(@as(u64, 1), changed.seq_number);
    // Phase0 Metadata carries no custody count.
    changed.custody_group_count = null;
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqualDeep(changed, snapshots[0].metadata.?);
    const status: t.Status = .{ .head_slot = 80 };
    try setup.server.updateStatus(&localState(.{ .status = status }).status);
    setup.pair.advance(300_000);
    for (0..50) |_| try setup.step(1);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqualDeep(status, snapshots[0].status.?);
}

test "core native immutable metadata response survives local update during pending writer" {
    var setup: Setup = .{};
    const old: t.LocalState = .{ .metadata = .{ .seq_number = 4, .attnets = @splat(8) } };
    try setup.init(&old);
    defer setup.deinit();
    var pending = false;
    for (0..40) |_| {
        try setup.step(0);
        for (setup.server.control_protocol.responses) |response| if (response.request) |request| {
            const slot = &setup.server.service.reqresp.inbound[request.index];
            if (slot.request.protocol != .metadata_v1) continue;
            try std.testing.expect(slot.request.io.writing);
            const changed: t.Metadata = .{ .seq_number = 5, .attnets = @splat(9) };
            try @import("network_core_test_support.zig").updateLocal(&setup.server, &metadataUpdate(&setup.server, &localState(.{ .metadata = changed }).metadata), setup.pair.now);
            pending = true;
            break;
        };
        if (pending) break;
    }
    try std.testing.expect(pending);
    for (0..40) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqualDeep(old.metadata, snapshots[0].metadata.?);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 5), snapshots[0].metadata.?.seq_number);
}

test "core native wrong fork Goodbye hard closes with zero output and shutdown repeats" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try @import("network_core_test_support.zig").updateLocal(&setup.server, &localState(.{ .fork = .{ .digest = @splat(3) }, .status = .{ .fork_digest = @splat(3) } }), setup.pair.now);
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().relevant);
    setup.pair.advance(2_001);
    for (0..5) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
    try std.testing.expectEqual(@as(u16, 0), setup.server.peer_manager.catalog.connectedCount());
    var events: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&events));
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, events[0].closed.reason);
    setup.client.shutdown(setup.pair.now);
    setup.client.shutdown(setup.pair.now);
}

test "core native control timeout releases owners independent of public output" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    setup.client.peer_manager.control.options.health_failures_max = 1;
    for (0..50) |_| try setup.step(0);
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    try setup.step(0);
    setup.pair.drop_to_server = true;
    setup.pair.advance(10_001);
    for (0..4) |_| try setup.step(0);
    setup.pair.advance(2_001);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
    var events: [1]t.Event = undefined;
    _ = setup.client.peer_manager.catalog.pollEvents(&events);
    try std.testing.expectEqual(t.DisconnectReason.health_timeout, events[0].closed.reason);
}

fn failStatus(setup: *Setup, failure: rr.ReqResp.Failure) !void {
    for (setup.client.control_protocol.operations) |operation| if (operation.request) |request| {
        if (operation.protocol != .status_v1) continue;
        const service = &setup.client.service.reqresp;
        const slot = &service.outbound[request.index];
        slot.fail(service, request.index, failure, setup.pair.now);
        service.cleanupPending(setup.pair.client, &setup.client.service.router);
        return;
    };
    return error.TestUnexpectedResult;
}

fn failStatusRound(setup: *Setup, failure: rr.ReqResp.Failure) !void {
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    try setup.step(0);
    try failStatus(setup, failure);
    for (0..4) |_| try setup.step(0);
}

test "core native control disconnects only after consecutive health failures" {
    const status = @intFromEnum(@import("peers/control.zig").Control.HealthProbe.status);
    const Case = struct { failure: rr.ReqResp.Failure, reason: ?t.DisconnectReason };
    for ([_]Case{
        .{ .failure = .stream_closed, .reason = .health_error },
        .{ .failure = .{ .invalid_response = error.Truncated }, .reason = .health_error },
        .{ .failure = .empty_response, .reason = .health_error },
        .{ .failure = .{ .negotiation_failed = .timeout }, .reason = .health_timeout },
        .{ .failure = .timeout, .reason = .health_timeout },
        .{ .failure = .host_timeout, .reason = null },
        .{ .failure = .quota_timeout, .reason = null },
        .{ .failure = .cancelled, .reason = null },
    }) |case| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        const limit = setup.client.peer_manager.control.options.health_failures_max;
        for (0..limit) |round| {
            try failStatusRound(&setup, case.failure);
            if (case.reason != null and round + 1 == limit) break;
            try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
            try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.catalog.connectedCount());
            setup.pair.advance(setup.client.peer_manager.control.options.failure_retry_ms);
        }
        if (case.reason) |reason| {
            try std.testing.expectEqual(@as(u64, limit), setup.client.peer_manager.control.counters.health_failures[status]);
            setup.pair.advance(2_001);
            for (0..12) |_| try setup.step(0);
            try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
            var events: [1]t.Event = undefined;
            try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&events));
            try std.testing.expectEqual(reason, events[0].closed.reason);
        } else {
            try std.testing.expectEqual(@as(u64, 0), setup.client.peer_manager.control.counters.health_failures[status]);
            try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        }
    }
}

test "core native control retries a failed probe on the turn its retry deadline passes" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const peer = setup.client.peer_manager.catalog.find(&setup.server.peerId()).?;
    const row = &setup.client.peer_manager.control.schedules[peer.index];
    const status = @intFromEnum(@import("peers/control.zig").Control.HealthProbe.status);
    try failStatusRound(&setup, .timeout);
    try std.testing.expectEqual(@as(u8, 1), row.health_failures[status]);
    const retry = row.retry_ms;
    try std.testing.expectEqual(setup.pair.now.millis() + setup.client.peer_manager.control.options.failure_retry_ms, retry);
    try std.testing.expectEqual(retry, schedule_test_support.wakeupMilliseconds(setup.client.peer_manager.control.schedule(&setup.client.peer_manager.catalog, setup.pair.now), setup.pair.now.millis()).?);
    const counter = &setup.client.service.reqresp.protocol_counters[@intFromEnum(rr.Protocol.status_v1)].outgoing;
    const started = counter.*;
    const visits = setup.client.peer_manager.control.visits;
    setup.pair.now.monotonic = @import("time.zig").milliseconds(retry - 1);
    try setup.step(0);
    try std.testing.expectEqual(started, counter.*);
    try std.testing.expectEqual(visits, setup.client.peer_manager.control.visits);
    setup.pair.now.monotonic = @import("time.zig").milliseconds(retry);
    try setup.step(0);
    try std.testing.expectEqual(started + 1, counter.*);
    try std.testing.expectEqual(visits + 1, setup.client.peer_manager.control.visits);
    try std.testing.expectEqual(@as(u8, 1), row.health_failures[status]);
}

test "core native control success clears a health failure streak" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const peer = setup.client.peer_manager.catalog.find(&setup.server.peerId()).?;
    const status = @intFromEnum(@import("peers/control.zig").Control.HealthProbe.status);
    const limit = setup.client.peer_manager.control.options.health_failures_max;
    for (0..2) |_| {
        for (0..limit - 1) |_| {
            try failStatusRound(&setup, .timeout);
            setup.pair.advance(setup.client.peer_manager.control.options.failure_retry_ms);
        }
        try std.testing.expectEqual(limit - 1, setup.client.peer_manager.control.schedules[peer.index].health_failures[status]);
        setup.client.peer_manager.reStatusPeers(setup.pair.now);
        for (0..20) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u8, 0), setup.client.peer_manager.control.schedules[peer.index].health_failures[status]);
    }
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
}

/// Dials the discovered server, so the client's connection has a dialed endpoint.
fn dialServer(setup: *Setup) !void {
    var intents: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    const handle = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.dialStarted(intents[0].token, handle));
}

fn serverStrikes(setup: *Setup, server: *const @import("peers/enr.zig").Candidate) u8 {
    const history = &setup.client.peer_manager.catalog.history;
    return history.strikesFor(history.endpointKey(&server.peer, support.server_address), server.sequence, setup.pair.now.millis());
}

fn discoverServer(setup: *Setup) !@import("peers/enr.zig").Candidate {
    const server = try discoveredAt(2, support.server_address);
    try std.testing.expect(server.peer.eql(&setup.server.peerId()));
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{server}, setup.pair.now).accepted);
    return server;
}

test "core Status and Metadata clear dial failures that QUIC admission keeps" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const server = try discoverServer(&setup);
    const history = &setup.client.peer_manager.catalog.history;
    history.recordEndpoint(history.endpointKey(&server.peer, support.server_address), .unanswered, server.sequence, setup.pair.now.millis());
    try dialServer(&setup);
    for (0..20) |_| {
        try setup.step(1);
        if (setup.client.peer_manager.catalog.connectedCount() == 1) break;
    }
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.catalog.connectedCount());
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().relevant);
    try std.testing.expectEqual(@as(u8, 1), serverStrikes(&setup, &server));
    for (0..50) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    try std.testing.expectEqual(@as(u8, 0), serverStrikes(&setup, &server));
    const peer = setup.client.peer_manager.catalog.find(&server.peer).?;
    try std.testing.expect(setup.client.peer_manager.control.schedules[peer.index].evidence == .ready);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(1);
    try std.testing.expect(setup.client.peer_manager.control.schedules[peer.index].evidence == .proven);
    try std.testing.expectEqual(@as(u8, 0), serverStrikes(&setup, &server));
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
}

test "core health strikes survive an answered reconnect until a later probe succeeds" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const server = try discoverServer(&setup);
    try dialServer(&setup);
    for (0..50) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    const limit = setup.client.peer_manager.control.options.health_failures_max;
    for (0..limit) |round| {
        try failStatusRound(&setup, .timeout);
        if (round + 1 < limit) setup.pair.advance(setup.client.peer_manager.control.options.failure_retry_ms);
    }
    setup.pair.advance(2_001);
    for (0..12) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
    try std.testing.expectEqual(@as(u8, 1), serverStrikes(&setup, &server));
    // Both sides hold a Goodbye cooldown after the health close.
    setup.pair.advance(60_000);
    try dialServer(&setup);
    for (0..50) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    try std.testing.expectEqual(@as(u64, 1), setup.client.peer_manager.dialing.retries[@intFromEnum(t.DialFailure.health)]);
    try std.testing.expectEqual(@as(u8, 1), serverStrikes(&setup, &server));
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u8, 0), serverStrikes(&setup, &server));
}

test "core local probe stalls add no health strike" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const server = try discoverServer(&setup);
    try dialServer(&setup);
    for (0..50) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    for (0..setup.client.peer_manager.control.options.health_failures_max + 1) |_| {
        try failStatusRound(&setup, .host_timeout);
        setup.pair.advance(setup.client.peer_manager.control.options.local_retry_ms);
    }
    setup.pair.advance(2_001);
    for (0..12) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.catalog.connectedCount());
    try std.testing.expectEqual(@as(u8, 0), serverStrikes(&setup, &server));
}

fn allocationCheck(a: std.mem.Allocator) !void {
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    const opts = options().core;
    const receive = @import("router.zig").Router.initialCapabilities(opts.service.router).receive;
    var core = try PeerManager.init(a, &identity, &localState(.{}), opts.peerManager(), receive, 4);
    defer core.deinit();
}

test "core startup allocation failure cleans every prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
}

test "core native deterministic replacement cancels old control and ignores stale physical close" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    try setup.initDirection(&local, true);
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const old = snapshots[0];
    try std.testing.expect(old.relevant);
    try std.testing.expectEqual(@as(usize, 4), old.custody_groups.?.count());
    try std.testing.expectEqual(@as(usize, 8), old.sampling_groups.?.count());
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    try setup.step(1);
    var old_request: ?rr.ReqResp.RequestHandle = null;
    for (setup.client.control_protocol.operations) |op| if (op.request != null) {
        old_request = op.request;
        break;
    };
    try std.testing.expect(old_request != null);
    _ = try setup.pair.dial();
    for (0..60) |_| try setup.step(1);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqualDeep(old.peer, snapshots[0].peer);
    try std.testing.expect(!std.meta.eql(old.connection, snapshots[0].connection));
    try std.testing.expect(snapshots[0].relevant);
    const selected = snapshots[0];
    try std.testing.expectEqual(old.custody_groups, selected.custody_groups);
    try std.testing.expectEqual(old.sampling_groups, selected.sampling_groups);
    try std.testing.expect(setup.pair.client.registry.slots[old.connection.?.index].conn == null);
    try std.testing.expectEqual(@as(u16, 1), setup.pair.client.registry.active_len);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(old.connection.?));
    // The old connection's close and its cancelled Status have reached the owner by now.
    for (setup.client.control_protocol.operations) |op| try std.testing.expect(!std.meta.eql(old_request, op.request));
    for (0..8) |_| try setup.step(1);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqualDeep(selected, snapshots[0]);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
}

test "core native saturated app requests retain partitioned borrows while controls progress" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const server_id = setup.server.peerId();
    const bytes = [_]u8{0} ** 8 ++ [_]u8{1} ++ [_]u8{0} ** 15;
    const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, sink_size * 8);
    defer std.testing.allocator.free(sinks);
    defer setup.client.shutdown(setup.pair.now);
    const protocols = [_]rr.Protocol{
        .blocks_by_range_v2,
        .blocks_by_root_v2,
        .blob_sidecars_by_range_v1,
        .blob_sidecars_by_root_v1,
    };
    for (0..8) |index| {
        const protocol = protocols[index / 2];
        _ = try setup.client.sendReqRespRequest(
            &server_id,
            protocol,
            bytes[0..protocol.info().request_min],
            sinks[index * sink_size ..][0..sink_size],
            .{},
            setup.pair.now,
        );
    }
    try std.testing.expectError(
        error.TooManyRequests,
        setup.client.sendReqRespRequest(
            &server_id,
            .blocks_by_range_v2,
            &bytes,
            sinks[0..sink_size],
            .{},
            setup.pair.now,
        ),
    );
    try std.testing.expectError(
        error.ControlProtocol,
        setup.client.sendReqRespRequest(
            &server_id,
            .ping_v1,
            &([_]u8{0} ** 8),
            sinks[0..sink_size],
            .{},
            setup.pair.now,
        ),
    );
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    var applications: [1]rr.ReqResp.Event = undefined;
    var delivered: usize = 0;
    for (0..16) |_| {
        const counts = (try setup.turn(&setup.server, .{ .application = &applications })).counts;
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
        _ = setup.server.service.reqresp.cancel(request.request, setup.pair.now);
    }
    try std.testing.expectEqual(@as(usize, 8), delivered);
}

test "core native local control capacity defers with future wakeup and no peer penalty" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    var streams: usize = 0;
    for (0..64) |_| {
        _ = setup.pair.client.openStream(conn) catch break;
        streams += 1;
    }
    try std.testing.expect(streams > 0);
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqual(@as(f64, 0), snapshots[0].score);
    try std.testing.expect(snapshots[0].relevant);
    const control_due = schedule_test_support.wakeupMilliseconds(setup.client.peer_manager.control.schedule(&setup.client.peer_manager.catalog, setup.pair.now), setup.pair.now.millis()).?;
    try std.testing.expect(control_due > setup.pair.now.millis());
    setup.client.shutdown(setup.pair.now);
}

test "core retains explicit direct connections without periodically resurrecting gossip" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const selected = snapshots[0];
    const conn = selected.connection.?;
    try std.testing.expect(setup.client.peer_manager.catalog.setDirect(selected.peer, true));
    var remote: [4]t.Snapshot = undefined;
    _ = setup.server.peer_manager.snapshots(&remote);
    try std.testing.expect(setup.server.peer_manager.catalog.setDirect(remote[0].peer, true));
    const driver = setup.client.service.gossipsub;
    @import("gossipsub/session_io.zig").retirePeer(driver, &setup.client.service.router, setup.pair.client, driver.sessions.find(conn).?);
    const started = driver.counters.negotiation_started;
    for (0..4) |_| {
        setup.pair.advance(1_000);
        setup.client.peer_manager.reStatusPeers(setup.pair.now);
        for (0..16) |_| try setup.step(0);
        try std.testing.expect(!driver.admitted(conn));
        const snapshot = setup.client.peer_manager.catalog.get(selected.peer).?;
        try std.testing.expect(snapshot.relevant);
        try std.testing.expect(snapshot.disconnect_reason == null);
        try std.testing.expectEqual(@as(f64, 0), snapshot.score);
    }
    try std.testing.expectEqual(started, driver.counters.negotiation_started);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.selection.deficits.outbound);
}

test "core direct removal clears both pins and gossip score reads have no feedback" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const identity = setup.server.peerId();
    try setup.client.addDirectPeer(&identity, &.{support.server_address}, setup.pair.now);
    setup.pair.advance(1_000);
    for (0..3) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].direct);
    const conn = snapshots[0].connection.?;
    @import("gossipsub/test_support.zig").penalize(setup.client.service.gossipsub, conn, 7);
    const before = setup.client.peer_manager.gossipScore(setup.client.service.gossipsub, snapshots[0].peer, setup.pair.now).?;
    try std.testing.expect(std.math.isFinite(before));
    _ = setup.client.peer_manager.reportPeer(snapshots[0].peer, .high_tolerance, setup.pair.now);
    try std.testing.expectEqual(
        before,
        setup.client.peer_manager.gossipScore(setup.client.service.gossipsub, snapshots[0].peer, setup.pair.now).?,
    );
    _ = setup.client.removeDirectPeer(&identity);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(!snapshots[0].direct);
    const logical = setup.client.service.gossipsub.peers.find(&identity).?;
    try std.testing.expect(!setup.client.service.gossipsub.peers.rows[logical.index].direct);
    var intents: [2]@import("peers/dialing.zig").Dialing.DialIntent = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents),
    );
}

test "core native preserves gossip events under one output and caller validation wrappers" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    try gossip_test.subscribe(setup.client.service.gossipsub, topic);
    try gossip_test.subscribe(setup.server.service.gossipsub, topic);
    for (0..50) |_| try setup.step(0);
    setup.pair.advance(1_001);
    for (0..30) |_| try setup.step(0);
    for (0..30) |_| {
        try setup.pair.pump();
        _ = try setup.turn(&setup.server, .{});
        _ = try setup.turn(&setup.client, .{});
    }
    setup.pair.advance(1_001);
    for (0..10) |_| try setup.step(0);
    const payload = "bounded core gossip payload";
    _ = try setup.client.publishGossipWithOptions(topic, payload, .{ .allow_zero_peers = false }, setup.pair.now);
    try std.testing.expectError(error.Duplicate, setup.client.publishGossipWithOptions(topic, payload, .{}, setup.pair.now));
    try std.testing.expect((try setup.client.publishGossipWithOptions(topic, payload, .{ .ignore_duplicate = true }, setup.pair.now)).duplicate);
    var received: usize = 0;
    for (0..50) |_| {
        try setup.pair.pump();
        _ = try setup.turn(&setup.server, .{});
        for (setup.server_inbox.messages()) |message| {
            try std.testing.expectEqualStrings(payload, message.bytes);
            try std.testing.expectEqual(
                gossip.Gossipsub.ReportOutcome{ .applied = .accept },
                setup.server.service.gossipsub.report(message.handle, .accept, setup.pair.now),
            );
            try std.testing.expectEqualStrings(payload, message.bytes);
            received += 1;
        }
        setup.server_inbox.clear();
        _ = try setup.turn(&setup.client, .{});
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try gossip_test.unsubscribe(setup.client.service.gossipsub, topic);
}

test "core native continuous reStatus cannot starve due metadata sequence confirmation" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    try @import("network_core_test_support.zig").updateLocal(&setup.server, &metadataUpdate(&setup.server, &localState(.{ .metadata = .{ .attnets = @splat(12) } }).metadata), setup.pair.now);
    const sequence = setup.server.localState().metadata.seq_number;
    try std.testing.expect(sequence > 0);
    setup.pair.advance(21_000);
    for (0..60) |_| {
        setup.client.peer_manager.reStatusPeers(setup.pair.now);
        try setup.step(0);
    }
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqual(sequence, snapshots[0].metadata.?.seq_number);
}

test "core native Goodbye immediately removes relevance and delayed Status cannot revive it" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    try setup.step(0);
    try std.testing.expectEqual(
        t.ReputationDecision.none,
        setup.client.peer_manager.reportPeer(peer, .low_tolerance, setup.pair.now).?,
    );
    try std.testing.expectEqual(
        t.ReputationDecision.disconnect,
        setup.client.peer_manager.reportPeer(peer, .low_tolerance, setup.pair.now).?,
    );
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().connected);
    for (0..20) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().relevant);
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&event));
    try std.testing.expect(!event[0].updated.relevant);
    setup.pair.advance(2_000);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().connected);
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&event));
    try std.testing.expectEqual(t.DisconnectReason.reputation, event[0].closed.reason);
    const fault = @intFromEnum(@import("peers/goodbye.zig").Reason.bad_score);
    try std.testing.expectEqual(@as(u64, 1), setup.server.peer_manager.control.counters.events.goodbyes[fault]);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().connected);
}

test "core native hard close retires QUIC routes streams and registry with zero public output" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    try std.testing.expect(setup.client.peer_manager.disconnect(snapshots[0].peer, .host, setup.pair.now));
    setup.pair.advance(2_000);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
    try std.testing.expectEqual(@as(usize, 0), setup.pair.client.registry.routes.count);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(conn));
}

test "core native leased dial retires uncompleted handshake and rejects late acknowledgements" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var identity = setup.server.peerId();
    var address = support.server_address;
    try setup.client.peer_manager.connect(&identity, &.{address}, setup.pair.now);
    identity.bytes[0] ^= 1;
    address = .unspecified;
    var output: [1]DialIntent = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &output),
    );
    const intent = output[0];
    try std.testing.expect(intent.peer.eql(&setup.server.peerId()));
    try std.testing.expect(intent.address.eql(support.server_address));
    const conn = try setup.pair.client.dial(
        &intent.address,
        intent.peer,
        setup.pair.now,
    );
    try std.testing.expect(setup.client.peer_manager.dialStarted(intent.token, conn));
    setup.pair.advance(10_000);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.dialing);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expect(!setup.client.peer_manager.dialStarted(intent.token, conn));
    try std.testing.expect(!setup.client.peer_manager.dialFailed(intent.token, setup.pair.now));
    try std.testing.expect(schedule_test_support.wakeupMilliseconds(setup.client.peer_manager.dialing.schedule(&setup.client.peer_manager.catalog, 1), setup.pair.now.millis()).? >
        setup.pair.now.millis());
}

test "core native dial expiry closes authenticated attempt before connected event delivery" {
    for ([_]bool{ false, true }) |shutdown| {
        var setup: Setup = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        try setup.client.peer_manager.connect(
            &setup.server.peerId(),
            &.{support.server_address},
            setup.pair.now,
        );
        var output: [1]DialIntent = undefined;
        _ = setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &output);
        const intent = output[0];
        const conn = try setup.pair.client.dial(
            &intent.address,
            intent.peer,
            setup.pair.now,
        );
        try std.testing.expect(setup.client.peer_manager.dialStarted(intent.token, conn));
        try setup.pair.pump();
        try std.testing.expect(setup.pair.client.peerId(conn) != null);
        if (shutdown) setup.client.shutdown(setup.pair.now) else {
            setup.pair.advance(10_000);
            setup.client.peer_manager.expireDials(setup.pair.client, setup.pair.now);
            _ = setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &output);
        }
        for (0..8) |_| {
            try setup.pair.pump();
            var events: [32]Engine.Event = undefined;
            _ = setup.pair.events(setup.pair.client, &events);
            _ = setup.pair.events(setup.pair.server, &events);
        }
        try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
        try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
        try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    }
}

test "core simultaneous selected dials consume one commitment and preserve duplicate tie breaking" {
    var setup: Setup = .{};
    var opts = options();
    opts.core.peers.target_peers = 1;
    opts.core.peers.max_peers = 2;
    opts.core.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    const nodes = [_]*@import("network_core.zig").NetworkCore{ &setup.client, &setup.server };
    const identities = [_]t.PeerId{ setup.server.peerId(), setup.client.peerId() };
    const addresses = [_]t.Address{ support.server_address, support.client_address };
    const blocker: t.PeerId = .{ .bytes = @splat(99) };
    for (nodes, &identities, addresses) |node, *identity, address| {
        const owner = &node.peer_manager;
        try std.testing.expect(owner.catalog.admit(&blocker, &owner.local_identity, .{ .index = 3, .generation = 1 }, &.{
            .direction = .inbound,
            .endpoint = .unspecified,
            .now_ms = setup.pair.now.millis(),
            .outbound_reserved = 1,
        }) == .admitted);
        try owner.connect(identity, &.{address}, setup.pair.now);
        var intents: [1]DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), owner.dialIntents(node.service.gossipsub, &node.transport.engine, setup.pair.now, &intents));
        const conn = try node.transport.engine.dial(&intents[0].address, intents[0].peer, setup.pair.now);
        try std.testing.expect(owner.dialStarted(intents[0].token, conn));
    }
    try setup.pair.pump();
    for (nodes, &identities) |node, *identity| {
        const owner = &node.peer_manager;
        _ = try setup.turn(node, .{});
        try std.testing.expectEqual(@as(u16, 2), owner.catalog.connectedCount());
        try std.testing.expectEqual(@as(u16, 0), owner.dialing.pendingPeers(&owner.catalog, null));
        const row = owner.catalog.rowFor(owner.catalog.find(identity).?).?;
        const expected: t.Direction = if (std.mem.order(u8, &owner.local_identity.bytes, &identity.bytes) == .lt) .outbound else .inbound;
        try std.testing.expectEqual(expected, row.direction);
        try std.testing.expectEqual(@as(u16, 0), owner.dialing.attempts().total);
        try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
    }
    for (0..8) |_| {
        try setup.step(0);
        for (nodes) |node| try std.testing.expectEqual(@as(u16, 2), node.peer_manager.catalog.connectedCount());
    }
}

test "core competing one-shot attempt expires during selected peer ban cooldown" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    // The attempt's datagrams never arrive, so the server's own dial authenticates first.
    const unanswered: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_009 } };
    setup.pair.drop_to_address = unanswered;
    try setup.client.peer_manager.connect(&setup.server.peerId(), &.{unanswered}, setup.pair.now);
    var intents: [1]DialIntent = undefined;
    _ = setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents);
    const token = intents[0].token;
    const attempt = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.dialStarted(token, attempt));
    _ = try setup.pair.server.dial(&support.client_address, setup.client.peerId(), setup.pair.now);
    try setup.pair.pump();
    _ = try setup.turn(&setup.client, .{});
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(!std.meta.eql(attempt, snapshots[0].connection.?));
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.peer_manager.reportPeer(snapshots[0].peer, .fatal, setup.pair.now).?);
    _ = try setup.turn(&setup.client, .{});
    setup.pair.advance(10_000);
    _ = setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[attempt.index].conn == null);
    try std.testing.expect(!setup.client.peer_manager.dialStarted(token, attempt));
    try std.testing.expect(!setup.client.peer_manager.dialFailed(token, setup.pair.now));
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
    try std.testing.expectEqual(@as(?u64, null), schedule_test_support.wakeupMilliseconds(setup.client.peer_manager.dialing.schedule(&setup.client.peer_manager.catalog, 1), setup.pair.now.millis()));
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.catalog.intent_count);
}

test "core review early native close preserves selected reason and counts it once" {
    for ([_]?t.DisconnectReason{ .host, .reputation, .banned, .incompatible_fork, null }) |reason| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..50) |_| try setup.step(1);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.server.peer_manager.snapshots(&snapshots);
        const remote_conn = snapshots[0].connection.?;
        _ = setup.client.peer_manager.snapshots(&snapshots);
        if (reason) |typed| {
            try std.testing.expect(setup.client.peer_manager.disconnect(snapshots[0].peer, typed, setup.pair.now));
            for (0..8) |_| try setup.step(0);
        }
        try std.testing.expect(setup.pair.server.close(remote_conn, 0));
        for (0..8) |_| try setup.step(0);
        var output: [1]t.Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&output));
        const expected = reason orelse .transport_closed;
        try std.testing.expectEqual(expected, output[0].closed.reason);
        try std.testing.expectEqual(@as(u64, 1), setup.client.peer_manager.control.counters.closed[@intFromEnum(expected)]);
        setup.pair.advance(2_000);
        for (0..8) |_| try setup.step(0);
        var total: u64 = 0;
        for (setup.client.peer_manager.control.counters.closed) |count| total += count;
        try std.testing.expectEqual(@as(u64, 1), total);
    }
}

test "core records a remote close of its dial before Status as an early close and none once ready" {
    for ([_]bool{ false, true }) |ready| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..if (ready) 50 else 1) |_| try setup.step(0);
        var snapshots: [4]t.Snapshot = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.peer_manager.snapshots(&snapshots));
        const remote_conn = snapshots[0].connection.?;
        const server_view = setup.server.peer_manager.catalog.history.identityKey(&snapshots[0].identity);
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.snapshots(&snapshots));
        try std.testing.expectEqual(ready, snapshots[0].relevant);
        const client_view = setup.client.peer_manager.catalog.history.identityKey(&snapshots[0].identity);
        const gate: u64 = 0x47415445;
        try std.testing.expect(setup.pair.server.close(remote_conn, gate));
        for (0..8) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
        const expected: ?t.Rejection = if (ready) null else .early_close;
        try std.testing.expectEqual(expected, setup.client.peer_manager.catalog.history.rejection(client_view, setup.pair.now.millis()));
        try std.testing.expectEqual(@as(u64, @intFromBool(!ready)), setup.client.peer_manager.catalog.rejections[@intFromEnum(t.Rejection.early_close)]);
        try std.testing.expectEqual(@as(?t.Rejection, null), setup.server.peer_manager.catalog.history.rejection(server_view, setup.pair.now.millis()));
    }
}

/// Refuses the client's Status in flight at negotiation, then runs the close it starts.
fn refuseStatus(setup: *Setup) !void {
    try failStatus(setup, .negotiation_rejected);
    for (0..4) |_| try setup.step(1);
    setup.pair.advance(2_001);
    for (0..8) |_| try setup.step(1);
}

/// Checks that the client counted and closed `count` refused Status probes and recorded `rejections` early closes.
fn expectRefusals(setup: *Setup, count: u64, rejections: u64) !void {
    const manager = &setup.client.peer_manager;
    try std.testing.expectEqual(@as(u16, 0), manager.catalog.connectedCount());
    try std.testing.expectEqual(count, manager.control.counters.health_failures[@intFromEnum(@import("peers/control.zig").Control.HealthProbe.status)]);
    try std.testing.expectEqual(count, manager.control.counters.closed[@intFromEnum(t.DisconnectReason.health_error)]);
    try std.testing.expectEqual(rejections, manager.catalog.rejections[@intFromEnum(t.Rejection.early_close)]);
}

test "core records a refused Status on its dial before readiness as an early close that escalates across endpoints" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const manager = &setup.client.peer_manager;
    const history = &manager.catalog.history;
    const second: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_003 } };
    var server = try discoveredAt(2, support.server_address);
    server.addresses[1] = second;
    server.address_count = 2;
    const identity = history.identityKey(&server.peer);
    // Two health strikes block the first endpoint for 30 minutes, so the third dial takes the second.
    for ([_]struct { t.Address, u64 }{
        .{ support.server_address, 60_000 },
        .{ support.server_address, 15 * 60_000 },
        .{ second, 60 * 60_000 },
    }, 1..) |round, count| {
        try std.testing.expectEqual(@as(u16, 1), manager.discoveredBatch(setup.client.service.gossipsub, &.{server}, setup.pair.now).accepted);
        var intents: [1]DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
        try std.testing.expect(intents[0].address.eql(round[0]));
        const handle = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
        try std.testing.expect(manager.dialStarted(intents[0].token, handle));
        setup.pair.server_source = round[0];
        for (0..20) |_| {
            try setup.step(1);
            if (manager.catalog.connectedCount() == 1) break;
        }
        try std.testing.expectEqual(@as(u16, 1), manager.catalog.connectedCount());
        const peer = manager.catalog.find(&server.peer).?;
        try std.testing.expect(manager.control.schedules[peer.index].evidence == .pending);
        try refuseStatus(&setup);
        try expectRefusals(&setup, count, count);
        try std.testing.expectEqual(@as(?t.Rejection, .early_close), history.rejection(identity, setup.pair.now.millis()));
        try std.testing.expectEqual(setup.pair.now.millis() + round[1], history.rejectedUntil(identity, setup.pair.now.millis()));
        try std.testing.expectEqual(@as(u16, 1), manager.discoveredBatch(setup.client.service.gossipsub, &.{server}, setup.pair.now).refused);
        try std.testing.expectEqual(@as(u64, count), manager.dialing.refused.identity[@intFromEnum(t.Rejection.early_close)]);
        setup.pair.advance(round[1]);
    }
}

test "core refused Status records no rejection once ready or on an inbound connection" {
    for ([_]bool{ false, true }) |inbound| {
        var setup: Setup = .{};
        try setup.initDirection(&.{}, inbound);
        defer setup.deinit();
        const manager = &setup.client.peer_manager;
        // A dialer that starts no Status of its own leaves the connection short of readiness.
        if (inbound) setup.server.peer_manager.control.options.starts_per_turn_max = 0;
        for (0..50) |_| try setup.step(1);
        manager.reStatusPeers(setup.pair.now);
        try setup.step(1);
        const peer = manager.catalog.find(&setup.server.peerId()).?;
        try std.testing.expectEqual(!inbound, manager.control.schedules[peer.index].evidence != .pending);
        try refuseStatus(&setup);
        try expectRefusals(&setup, 1, 0);
        try std.testing.expectEqual(@as(?t.Rejection, null), manager.catalog.history.rejection(manager.catalog.history.identityKey(&setup.server.peerId()), setup.pair.now.millis()));
    }
}

test "core refused Status inside the fork transition grace neither closes nor records" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    const manager = &setup.client.peer_manager;
    for (0..20) |_| {
        try setup.step(1);
        if (manager.peerCounts().relevant == 1) break;
    }
    const peer = manager.catalog.find(&setup.server.peerId()).?;
    const row = &manager.control.schedules[peer.index];
    try std.testing.expect(row.evidence == .pending);
    var next = manager.local;
    next.fork.digest = @splat(3);
    next.status.fork_digest = next.fork.digest;
    try @import("network_core_test_support.zig").updateLocal(&setup.client, &next, setup.pair.now);
    try setup.step(1);
    try failStatus(&setup, .negotiation_rejected);
    for (0..4) |_| try setup.step(1);
    try std.testing.expect(setup.pair.now.millis() < row.transition_until_ms);
    try std.testing.expect(manager.catalog.get(peer).?.disconnect_reason == null);
    try std.testing.expectEqual(@as(?t.Rejection, null), row.rejection);
    try std.testing.expectEqual(@as(u64, 0), manager.control.counters.health_failures[@intFromEnum(@import("peers/control.zig").Control.HealthProbe.status)]);
    // Past the grace, the same refusal closes and records.
    setup.pair.advance(row.transition_until_ms - setup.pair.now.millis());
    try setup.step(1);
    try refuseStatus(&setup);
    try expectRefusals(&setup, 1, 1);
}

test "core coverage demand copies persists across slots and keeps general discovery independent" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var demand: t.Demand = .{ .syncnets = 1 };
    try updateDemand(&setup.client, &demand, setup.pair.now);
    demand.syncnets = 2;
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.peer_manager.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.peer_manager.discoveryNeed().general);
    setup.pair.advance(60_000);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.peer_manager.discoveryNeed().syncnets);
    try @import("network_core_test_support.zig").advanceSlot(&setup.client, 10_000, setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.peer_manager.discoveryNeed().syncnets);
    try updateDemand(&setup.client, &.{}, setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.peer_manager.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.peer_manager.discoveryNeed().general);
    const due = clientWakeup(&setup);
    try std.testing.expect(due == null or due.? > setup.pair.now.millis());
}

test "core coverage authenticated custody differs from gossip delivery and invalidates fork groups" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .syncnets = 1, .custody_group_count = 128 } };
    try setup.init(&local);
    defer setup.deinit();
    try subscribeServer(&setup, "/eth2/00000000/sync_committee_0/ssz_snappy");
    try subscribeServer(&setup, "/eth2/00000000/data_column_sidecar_0/ssz_snappy");
    var demand: t.Demand = .{ .syncnets = 1 };
    demand.group_targets[0] = 1;
    try updateDemand(&setup.client, &demand, setup.pair.now);
    for (0..60) |_| try setup.step(0);
    setup.pair.advance(1_000);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(setup.client.peer_manager.catalog.setDirect(snapshots[0].peer, true));
    const connection = snapshots[0].connection.?;
    const index = setup.client.service.gossipsub.sessions.find(connection).?;
    @import("gossipsub/session_io.zig").resetOutbound(setup.client.service.gossipsub, setup.pair.client, index);
    try std.testing.expect(!setup.client.service.gossipsub.deliveryAvailable(connection));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().groups);
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try @import("network_core_test_support.zig").updateLocal(&setup.client, &local, setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().groups);
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].custody_groups == null);
}

test "core coverage physical closing capacity blocks new leased intents" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expect(setup.client.peer_manager.disconnect(snapshots[0].peer, .host, setup.pair.now));
    setup.pair.client.limits.dialing_max = 3;
    setup.pair.client.outbound_max = 4;
    for (0..3) |_| _ = try setup.pair.client.dial(&support.server_address, setup.server.peerId(), setup.pair.now);
    try std.testing.expectEqual(@as(u16, 4), setup.pair.client.registry.active_len);
    var secret: [32]u8 = @splat(0);
    secret[31] = 17;
    const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    try setup.client.peer_manager.connect(&peer, &.{support.server_address}, setup.pair.now);
    var out: [2]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.dialing.attempts().total);
}

test "core coverage direct candidate dials at soft target and respects physical hard capacity" {
    var setup: Setup = .{};
    var opts = options();
    opts.core.peers.target_peers = 1;
    opts.core.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    var secret: [32]u8 = @splat(0);
    secret[31] = 17;
    const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    try setup.client.addDirectPeer(&peer, &.{support.server_address}, setup.pair.now);
    var out: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&peer));
    try setup.client.addDirectPeer(&peer, &.{support.server_address}, setup.pair.now);
    try std.testing.expectError(error.DirectPeerCapacity, setup.client.addDirectPeer(&setup.server.peerId(), &.{support.server_address}, setup.pair.now));
}

fn candidateFor(peer: *const t.PeerId, count: ?u64) !@import("peers/enr.zig").Candidate {
    return .{ .peer = peer.*, .node_id = try @import("peers/custody.zig").nodeId(peer), .sequence = 1, .record_hash = @splat(0), .addresses = .{ support.server_address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = null, .custody_group_count = count };
}

test "core coverage automatic retention renews only at authenticated Status success" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var candidate = try candidateFor(&setup.server.peerId(), null);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    const horizon = setup.client.peer_manager.catalog.rows[0].intent.history_until_ms;
    setup.pair.advance(1000);
    for (0..10) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.peer_manager.catalog.rows[0].intent.history_until_ms);
    candidate.sequence = 2;
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.peer_manager.catalog.rows[0].intent.history_until_ms);
    setup.client.peer_manager.reStatusPeers(setup.pair.now);
    for (0..50) |_| try setup.step(0);
    try std.testing.expect(setup.client.peer_manager.catalog.rows[0].intent.history_until_ms > horizon);
}

test "core coverage bounded custody work resumes without output and stale metadata cannot satisfy demand" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 127, .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    var demand: t.Demand = .{ .syncnets = 1 };
    demand.group_targets[0] = 1;
    try updateDemand(&setup.client, &demand, setup.pair.now);
    for (0..50) |_| try setup.step(0);
    var initial: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&initial);
    try std.testing.expect(setup.client.peer_manager.catalog.updateMetadata(initial[0].peer, initial[0].connection.?, &.{ .seq_number = 10, .custody_group_count = 1 }, setup.pair.now.millis()));
    try std.testing.expect(setup.client.peer_manager.catalog.updateMetadata(initial[0].peer, initial[0].connection.?, &.{ .seq_number = 11, .custody_group_count = 127, .syncnets = 1 }, setup.pair.now.millis()));
    for (0..4) |i| {
        var secret: [32]u8 = @splat(0);
        secret[31] = @intCast(i + 20);
        const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
        const peer = t.PeerId.fromPublicKey(&key);
        const candidate = try candidateFor(&peer, 127);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    }
    var saw_pending = false;
    for (0..80) |_| {
        const before = setup.client.peer_manager.counters.custody_hashes;
        try setup.step(0);
        try std.testing.expect(setup.client.peer_manager.counters.custody_hashes - before <= 256);
        if (setup.client.peer_manager.custody_pending) {
            saw_pending = true;
            try std.testing.expect(clientWakeup(&setup).? <= setup.pair.now.millis() +| 1);
        }
    }
    try std.testing.expect(saw_pending);
    try std.testing.expect(!setup.client.peer_manager.custody_pending);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    try std.testing.expectEqual(@as(usize, 127), snapshots[0].custody_groups.?.count());
    setup.pair.advance(60_000);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
}

test "core coverage outbound deficit uses admission headroom while retaining existing inbound" {
    for ([_]u16{ 2, 3 }) |maximum| {
        var setup: Setup = .{};
        var opts = options();
        opts.core.peers.max_peers = maximum;
        opts.core.peers.target_peers = 1;
        opts.core.peers.min_outbound = 1;
        try setup.initOwnersWithOptions(&.{}, opts);
        defer setup.deinit();
        _ = try setup.pair.dial();
        for (0..60) |_| try setup.step(0);
        try std.testing.expectEqual(@as(u16, 1), setup.server.peer_manager.peerCounts().relevant);
        var secret: [32]u8 = @splat(0);
        secret[31] = 17;
        const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
        const peer = t.PeerId.fromPublicKey(&key);
        const candidate = try candidateFor(&peer, null);
        try std.testing.expectEqual(@as(u16, 1), setup.server.peer_manager.discoveredBatch(setup.server.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
        var out: [1]DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.peer_manager.dialIntents(setup.server.service.gossipsub, setup.pair.server, setup.pair.now, &out));
        try std.testing.expect(out[0].peer.eql(&peer));
    }
}

test "core coverage review same-digest group update disables cached automatic candidate" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 128 } };
    try setup.initOwners(&local);
    defer setup.deinit();
    var candidate = try candidateFor(&setup.server.peerId(), 128);
    candidate.syncnets = 1;
    try updateDemand(&setup.client, &.{ .syncnets = 1 }, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try @import("network_core_test_support.zig").updateLocal(&setup.client, &local, setup.pair.now);
    var out: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.rows[0].intent.priority);
    try std.testing.expectEqual(@as(u64, 1), setup.client.peer_manager.catalog.rows[0].intent.hints.?.sequence);
    candidate.sequence = 2;
    candidate.custody_group_count = 64;
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "core reconciliation idle and candidate batch work" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    for (0..8) |_| {
        try setup.step(0);
        _ = setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &.{});
    }
    const c = setup.client.peer_manager.counters;
    const candidate = try candidateFor(&setup.server.peerId(), null);
    for (0..4) |_| try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    var out: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    const after = setup.client.peer_manager.counters;
    try std.testing.expectEqual(@as(u64, 1), c.selections);
    try std.testing.expectEqual(@as(u64, 0), after.selections - c.selections);
}

test "core reconciliation reads preserve completed demand and catalog evaluation" {
    var setup: Setup = .{};
    var opts = options();
    opts.core.peers.target_peers = 1;
    opts.core.peers.min_outbound = 0;
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 1 } };
    try setup.initOwnersWithOptions(&local, opts);
    defer setup.deinit();
    const view: *const PeerManager = &setup.client.peer_manager;
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
    var demand: t.Demand = .{ .attnets = 0x81, .syncnets = 1 };
    demand.group_targets[0] = 1;
    try updateDemand(&setup.client, &demand, setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    const deficits = view.coverageDeficits();
    const need = view.discoveryNeed();
    try std.testing.expectEqual(@as(u16, 2), deficits.attestation);
    try std.testing.expectEqual(@as(u16, 1), deficits.sync);
    try std.testing.expectEqual(@as(u16, 1), deficits.groups);
    try std.testing.expect(need.general and need.custody);
    try std.testing.expectEqual(@as(u8, 0x81), need.attnets[0]);
    try std.testing.expectEqual(@as(u8, 1), need.syncnets);

    try updateDemand(&setup.client, &.{}, setup.pair.now);
    try std.testing.expectEqual(setup.pair.now.millis(), clientWakeup(&setup).?);
    const dirty = view.counters;
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.counters);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());

    const identity = setup.server.peerId();
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = setup.client.peer_manager.catalog.admit(&identity, &view.local_identity, conn, &.{ .direction = .outbound, .endpoint = support.server_address, .now_ms = setup.pair.now.millis() }).admitted.peer;
    try std.testing.expect(setup.client.peer_manager.catalog.updateStatus(peer, conn, &local.status, setup.pair.now.millis()));
    try std.testing.expect(setup.client.peer_manager.catalog.setDirect(peer, true));
    try std.testing.expectEqual(setup.pair.now.millis(), clientWakeup(&setup).?);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
}

test "core reconciliation reads do not decay reputation or schedule peer removal" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.snapshots(&snapshots));
    const snapshot = snapshots[0];
    const view: *const PeerManager = &setup.client.peer_manager;
    const deficits = view.coverageDeficits();
    const need = view.discoveryNeed();
    try std.testing.expectEqual(.none, setup.client.peer_manager.reportPeer(snapshot.peer, .high_tolerance, setup.pair.now).?);
    setup.pair.advance(100);
    try setup.client.addDirectPeer(&snapshot.identity, &.{support.server_address}, setup.pair.now);
    const incompatible: t.Status = .{ .fork_digest = @splat(1) };
    try std.testing.expect(setup.client.peer_manager.catalog.updateStatus(snapshot.peer, snapshot.connection.?, &incompatible, setup.pair.now.millis()));
    var events: [4]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&events));
    const dirty = view.catalog.get(snapshot.peer).?;
    const counters = view.counters;
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.catalog.get(snapshot.peer).?);
    try std.testing.expectEqualDeep(counters, view.counters);
    try std.testing.expect(!view.catalog.eventsPending());
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    const evaluated = view.catalog.get(snapshot.peer).?;
    try std.testing.expect(evaluated.score > dirty.score);
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, evaluated.disconnect_reason.?);
    try std.testing.expectEqual(@as(u16, 1), view.coverageDeficits().outbound);
    try std.testing.expect(view.discoveryNeed().general);
    try std.testing.expect(view.catalog.eventsPending());
}

test "core reconciliation clears policy observations at quiescence and shutdown" {
    for ([_]bool{ false, true }) |graceful| {
        var setup: Setup = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        try updateDemand(&setup.client, &.{ .syncnets = 1 }, setup.pair.now);
        _ = try setup.turn(&setup.client, .{});
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.coverageDeficits().sync);
        try std.testing.expect(setup.client.peer_manager.discoveryNeed().general);
        if (graceful) {
            setup.client.beginGracefulClose(setup.pair.now);
        } else setup.client.shutdown(setup.pair.now);
        const view: *const PeerManager = &setup.client.peer_manager;
        const counters = view.counters;
        setup.pair.advance(60_000);
        setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
        try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
        try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
        try std.testing.expectEqualDeep(counters, view.counters);
        _ = try setup.turn(&setup.client, .{});
        try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
        try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
    }
}

test "core reconciliation raw mutators and deadlines invalidate once" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .altair }, .metadata = .{ .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    try subscribeServer(&setup, "/eth2/00000000/sync_committee_0/ssz_snappy");
    const demand: t.Demand = .{ .syncnets = 1 };
    try updateDemand(&setup.client, &demand, setup.pair.now);
    for (0..60) |_| try setup.step(0);
    setup.pair.advance(setup.client.peer_manager.control.options.inbound_status_grace_ms);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    const before = setup.client.peer_manager.counters.selections;
    for (0..8) |_| {
        setup.pair.advance(1);
        setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
        _ = setup.client.peer_manager.coverageDeficits();
    }
    try std.testing.expectEqual(before, setup.client.peer_manager.counters.selections);
    try std.testing.expect(setup.client.peer_manager.catalog.updateMetadata(peer, conn, &.{ .seq_number = 10, .syncnets = 0 }, setup.pair.now.millis()));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(before + 1, setup.client.peer_manager.counters.selections);
    try std.testing.expectEqual(@as(u4, 0), setup.client.peer_manager.policy_scratch[0].stable.syncnets);
    try std.testing.expect(setup.client.peer_manager.catalog.updateMetadata(peer, conn, &.{ .seq_number = 11, .syncnets = 1 }, setup.pair.now.millis()));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    const deadline = setup.client.peer_manager.selection_deadline.?;
    var clock = setup.pair.now;
    clock.monotonic = @import("time.zig").milliseconds(deadline - 1);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    const fresh = setup.client.peer_manager.counters.selections;
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.peer_manager.discoveryNeed().syncnets);
    try std.testing.expectEqual(deadline, setup.client.peer_manager.reconciliation_deadline.?);
    clock.monotonic = @import("time.zig").milliseconds(deadline);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(@as(u4, 0), setup.client.peer_manager.policy_scratch[0].stable.syncnets);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.peer_manager.discoveryNeed().syncnets);
    try std.testing.expectEqual(fresh + 1, setup.client.peer_manager.counters.selections);
    clock.monotonic = @import("time.zig").milliseconds(clock.millis() + 1);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.peer_manager.counters.selections);

    @import("gossipsub/test_support.zig").penalize(setup.client.service.gossipsub, conn, 7);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.peer_manager.counters.selections);
    _ = setup.client.service.gossipsub.scoreSnapshot(conn, clock);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(fresh + 1, setup.client.peer_manager.counters.selections);
    _ = setup.client.peer_manager.reportPeer(peer, .high_tolerance, clock);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    const penalized = setup.client.peer_manager.counters.selections;
    const health = setup.client.peer_manager.catalog.get(peer).?.score;
    clock.monotonic = @import("time.zig").milliseconds(clock.millis() + 100);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expect(setup.client.peer_manager.catalog.get(peer).?.score > health);
    try std.testing.expectEqual(penalized, setup.client.peer_manager.counters.selections);

    try setup.client.addDirectPeer(&snapshots[0].identity, &.{support.server_address}, clock);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(penalized + 1, setup.client.peer_manager.counters.selections);
    _ = setup.client.removeDirectPeer(&snapshots[0].identity);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(penalized + 2, setup.client.peer_manager.counters.selections);
    try updateDemand(&setup.client, &.{}, clock);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().sync);
    try std.testing.expectEqual(penalized + 3, setup.client.peer_manager.counters.selections);
    try updateDemand(&setup.client, &.{}, clock);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(penalized + 3, setup.client.peer_manager.counters.selections);
    try std.testing.expect(setup.client.peer_manager.disconnect(peer, .host, clock));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, clock);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.selection.retained_count);
}

test "core reconciliation batch counts refusal and fresh native room independently" {
    var setup: Setup = .{};
    var opts = options();
    opts.core.peers.max_peers = 2;
    opts.core.peers.target_peers = 1;
    opts.core.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    const baseline = setup.client.peer_manager.counters;
    const candidate = try candidateFor(&setup.server.peerId(), null);
    const self_candidate = try candidateFor(&setup.client.peerId(), null);
    var invalid = candidate;
    invalid.address_count = 0;
    const result = setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{ candidate, self_candidate, invalid, candidate }, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 2), result.accepted);
    try std.testing.expectEqual(@as(u16, 2), result.refused);
    setup.pair.client.limits.dialing_max = 2;
    const conn = try setup.pair.dial();
    _ = try setup.pair.dial();
    setup.pair.client.limits.dialing_max = 4;
    setup.pair.client.outbound_max = 4;
    _ = try setup.pair.dial();
    _ = try setup.pair.dial();
    var out: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(setup.pair.client.abandon(conn));
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(baseline.selections, setup.client.peer_manager.counters.selections);
    try std.testing.expectEqual(baseline.candidate_selections + 1, setup.client.peer_manager.counters.candidate_selections);
}

test "core reconciliation exhausted revisions stay invalidated" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    setup.client.peer_manager.catalog.revision = std.math.maxInt(u64);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    const before = setup.client.peer_manager.counters.selections;
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(before + 1, setup.client.peer_manager.counters.selections);
}

test "core reconciliation ban expiry still defers until strict score recovery" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.peer_manager.reportPeer(peer, .fatal, setup.pair.now).?);
    setup.pair.advance(2_001);
    for (0..4) |_| try setup.step(0);
    try std.testing.expect(setup.client.peer_manager.catalog.get(peer).?.connection == null);
    const candidate = try candidateFor(&snapshots[0].identity, null);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{candidate}, setup.pair.now).accepted);
    var out: [1]DialIntent = undefined;
    const ban = setup.client.peer_manager.catalog.get(peer).?.ban_until_ms;
    var clock = setup.pair.now;
    clock.monotonic = @import("time.zig").milliseconds(ban - 1);
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, clock, &out));
    clock.monotonic = @import("time.zig").milliseconds(ban);
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, clock, &out));
    const recovery = setup.client.peer_manager.reconciliation_deadline.?;
    try std.testing.expect(recovery > ban);
    clock.monotonic = @import("time.zig").milliseconds(recovery - 1);
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, clock, &out));
    clock.monotonic = @import("time.zig").milliseconds(recovery);
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, clock, &out));
    try std.testing.expect(setup.client.peer_manager.catalog.get(peer).?.score > -50);
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "core native immediate close preserves direct membership and rejects stale generations" {
    for ([_]usize{ 0, 1 }) |capacity| {
        var setup: Setup = .{};
        try setup.init(&.{});
        defer setup.deinit();
        for (0..60) |_| try setup.step(1);
        var snapshots: [4]t.Snapshot = undefined;
        _ = setup.client.peer_manager.snapshots(&snapshots);
        const captured = snapshots[0];
        try setup.client.addDirectPeer(&captured.identity, &.{support.server_address}, setup.pair.now);
        var identities: [4]t.PeerId = undefined;
        try std.testing.expectEqual(@as(usize, 1), try setup.client.peer_manager.directPeers(&identities));
        try std.testing.expect(setup.client.closePeer(&captured.identity, setup.pair.now));
        try std.testing.expect(!setup.client.closePeer(&captured.identity, setup.pair.now));
        try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().connected);
        try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().relevant);
        try std.testing.expect(setup.client.peer_manager.catalog.get(captured.peer).?.connection == null);
        try std.testing.expect(setup.client.peer_manager.catalog.rows[0].connection == null);
        try std.testing.expect(setup.client.peer_manager.selection_revision == null);
        try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(captured.connection.?));
        const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
        defer std.testing.allocator.free(sink);
        try std.testing.expectError(error.Disconnected, setup.client.sendReqRespRequest(
            &captured.identity,
            .blocks_by_root_v2,
            &.{},
            sink,
            .{},
            setup.pair.now,
        ));
        var closed: [4]t.Event = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.catalog.pollEvents(&closed));
        try std.testing.expectEqualDeep(captured.connection.?, closed[0].closed.connection);
        try std.testing.expectEqual(t.DisconnectReason.host, closed[0].closed.reason);
        for (0..60) |_| try setup.step(capacity);
        try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.catalog.pollEvents(&closed));
        try std.testing.expectEqual(@as(u16, 0), setup.server.peer_manager.peerCounts().connected);
        try std.testing.expectEqual(@as(u64, 0), setup.server.peer_manager.control.counters.closed[@intFromEnum(t.DisconnectReason.remote_goodbye)]);
        try std.testing.expectEqual(@as(usize, 1), try setup.client.peer_manager.directPeers(&identities));
        _ = setup.server.peer_manager.catalog.pollEvents(&closed);
        setup.pair.advance(60_000);
        var intents: [1]@import("peers/dialing.zig").Dialing.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
        const replacement = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
        try std.testing.expect(setup.client.peer_manager.dialStarted(intents[0].token, replacement));
        for (0..60) |_| try setup.step(1);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        const current = setup.client.peer_manager.catalog.get(captured.peer).?;
        try std.testing.expect(!std.meta.eql(captured.connection, current.connection));
        // The first connection's physical close reached the owner during these turns.
        for (0..4) |_| try setup.step(1);
        try std.testing.expectEqualDeep(current, setup.client.peer_manager.catalog.get(captured.peer).?);
        setup.client.shutdown(setup.pair.now);
        try std.testing.expect(!setup.client.closePeer(&current.identity, setup.pair.now));
    }
}

test "core native peer counts distinguish open relevant invalidated and closed without scratch mutation" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try setup.step(0);
    const owner: *const PeerManager = &setup.client.peer_manager;
    try std.testing.expectEqual(@as(u16, 1), owner.peerCounts().connected);
    try std.testing.expectEqual(@as(u16, 0), owner.peerCounts().relevant);
    for (0..60) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const captured = snapshots[0];
    var sentinel = captured;
    sentinel.peer.generation += 1;
    @memset(setup.client.peer_manager.snapshot_scratch, sentinel);
    const before = setup.client.peer_manager.snapshot_scratch[0..4].*;
    try std.testing.expectEqualDeep(PeerManager.PeerCounts{ .connected = 1, .relevant = 1, .outbound_relevant = 1 }, owner.peerCounts());
    try std.testing.expectEqualDeep(before, setup.client.peer_manager.snapshot_scratch[0..4].*);
    try std.testing.expect(setup.client.peer_manager.catalog.invalidateStatus(captured.peer, captured.connection.?));
    try std.testing.expectEqualDeep(PeerManager.PeerCounts{ .connected = 1, .relevant = 0, .outbound_relevant = 0 }, owner.peerCounts());
    try std.testing.expect(setup.client.closePeer(&captured.identity, setup.pair.now));
    try std.testing.expectEqualDeep(PeerManager.PeerCounts{ .connected = 0, .relevant = 0, .outbound_relevant = 0 }, owner.peerCounts());
    const offline: t.PeerId = .{ .bytes = @splat(9) };
    try setup.client.addDirectPeer(&offline, &.{support.server_address}, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.catalog.get(setup.client.peer_manager.catalog.find(&offline).?) == null);
    var direct: [1]t.PeerId = undefined;
    try std.testing.expectEqual(@as(usize, 1), try owner.directPeers(&direct));
    try std.testing.expect(direct[0].eql(&offline));
    try std.testing.expect(setup.client.removeDirectPeer(&offline));
    try std.testing.expect(!setup.client.removeDirectPeer(&offline));
}

test "core native public close cancels overlapping attempts and preserves bounded direct retry" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    // The attempt's datagrams never arrive, so the server's own dial authenticates first.
    const unanswered: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_009 } };
    setup.pair.drop_to_address = unanswered;
    try setup.client.addDirectPeer(&setup.server.peerId(), &.{unanswered}, setup.pair.now);
    var intents: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    const token = intents[0].token;
    const attempt = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.dialStarted(token, attempt));
    _ = try setup.pair.server.dial(&support.client_address, setup.client.peerId(), setup.pair.now);
    try setup.pair.pump();
    _ = try setup.turn(&setup.client, .{});
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.snapshots(&snapshots));
    const accepted = snapshots[0];
    try std.testing.expect(!std.meta.eql(attempt, accepted.connection.?));
    const row = setup.client.peer_manager.catalog.rowFor(accepted.peer).?;
    try std.testing.expect(row.connection != null and row.attempt != null);
    try std.testing.expect(setup.client.closePeer(&accepted.identity, setup.pair.now));
    try std.testing.expect(row.connection == null and row.attempt == null);
    try std.testing.expect(setup.client.peer_manager.dialing.active[token.index].connection == null);
    try std.testing.expect(row.direct);
    try std.testing.expectEqual(token.generation, row.generation);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(attempt));
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(row.connection == null and row.attempt == null);
    try std.testing.expect(!setup.client.peer_manager.dialing.dialClosed(&setup.client.peer_manager.catalog, attempt, .handshake_timeout, setup.pair.now.millis()));
    const due = schedule_test_support.wakeupMilliseconds(setup.client.peer_manager.dialing.schedule(&setup.client.peer_manager.catalog, 1), setup.pair.now.millis()) orelse return error.MissingRetryDeadline;
    try std.testing.expect(due >= setup.pair.now.millis() + 60_000);
    setup.pair.advance(due - setup.pair.now.millis());
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    try std.testing.expectEqualDeep(accepted.identity, intents[0].peer);
    try std.testing.expectEqual(token.generation + 1, intents[0].token.generation);
}

fn waitSampling(setup: *Setup) !t.Snapshot {
    var snapshots: [4]t.Snapshot = undefined;
    for (0..200) |_| {
        try setup.step(0);
        if (setup.client.peer_manager.snapshots(&snapshots) == 1) {
            const snapshot = snapshots[0];
            if (snapshot.sampling_groups != null and snapshot.relevant and
                setup.client.service.gossipsub.deliveryAvailable(snapshot.connection.?)) return snapshot;
        }
        setup.pair.advance(25);
    }
    return error.SamplingReadinessTimeout;
}

test "core sampling delivery follows real outbound stream retirement replacement and stale events" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    var opts = options();
    opts.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(@splat(0))};
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
    try updateDemand(&setup.client, &demand, setup.pair.now);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().groups);
    const handler = setup.client.service.gossipsub;
    const index = handler.sessions.find(snapshot.connection.?).?;
    const old_stream = handler.sessions.rows[index].outbound.live.stream;
    setup.pair.client.closeStream(old_stream, 0);
    handler.transportEvents(&setup.client.service.router, setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.pair.now);
    try std.testing.expect(!handler.deliveryAvailable(snapshot.connection.?));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 8), setup.client.peer_manager.coverageDeficits().groups);
    try std.testing.expectEqual(snapshot.custody_groups, setup.client.peer_manager.catalog.get(snapshot.peer).?.custody_groups);
    handler.negotiationResult(setup.pair.client, .{ .stream = old_stream, .direction = .outbound, .owner = .meshsub, .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_2 }, .leftover = &.{}, .fin = false } } }, setup.pair.now);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 8), setup.client.peer_manager.coverageDeficits().groups);
    for (0..16) |_| try setup.step(1);
    setup.pair.advance(60_000);
    for (0..16) |_| try setup.step(1);
    _ = try setup.pair.dial();
    const replacement = try waitSampling(&setup);
    for (0..80) |_| {
        try setup.step(0);
        setup.pair.advance(25);
    }
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expect(!std.meta.eql(snapshot.connection, replacement.connection));
    const replacement_index = handler.sessions.find(replacement.connection.?).?;
    const replacement_stream = handler.sessions.rows[replacement_index].outbound.live.stream;
    try std.testing.expect(!std.meta.eql(old_stream, replacement_stream));
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().groups);
    handler.transportEvents(&setup.client.service.router, setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.pair.now);
    try std.testing.expect(handler.deliveryAvailable(replacement.connection.?));
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.coverageDeficits().groups);
    try std.testing.expectEqual(snapshot.custody_groups, setup.client.peer_manager.catalog.get(snapshot.peer).?.custody_groups);
    setup.client.shutdown(setup.pair.now);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.peerCounts().connected);
    try std.testing.expect(!handler.deliveryAvailable(snapshot.connection.?));
}

test "local intent refuses sampling demand beyond its fork atomically and a valid replacement persists" {
    var setup: Setup = .{};
    try setup.initOwners(&.{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } });
    defer setup.deinit();
    const node = &setup.client;
    const manager = &node.peer_manager;
    const owner = @import("network_core_test_support.zig");
    const local = node.localState();
    var demand: t.Demand = .{};
    demand.group_targets[0] = 1;
    demand.custody_group_targets[0] = 1;
    demand.group_targets[127] = manager.catalog.options.max_peers;
    try owner.updateLocalDemand(node, &local, &demand, setup.pair.now);
    try std.testing.expectEqualDeep(demand, manager.demand);
    // A demand change past the peer ceiling and a fork too narrow for the committed demand are
    // both refused before any owner commits.
    var excessive = demand;
    excessive.group_targets[1] = manager.catalog.options.max_peers + 1;
    try std.testing.expectError(error.InvalidDemand, owner.updateLocalDemand(node, &local, &excessive, setup.pair.now));
    var narrower = local;
    narrower.fork.custody_groups = 64;
    const request_fork = node.service.reqresp.request_fork;
    try std.testing.expectError(error.InvalidDemand, owner.updateLocal(node, &narrower, setup.pair.now));
    try std.testing.expectEqualDeep(demand, manager.demand);
    try std.testing.expectEqualDeep(local, node.localState());
    try std.testing.expectEqual(request_fork, node.service.reqresp.request_fork);
    manager.reconcile(node.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 4), manager.coverageDeficits().groups);
    // The narrower fork commits with a demand inside it; selection keeps its last result until
    // the next evaluation.
    var within = demand;
    within.group_targets[127] = 0;
    try owner.updateLocalDemand(node, &narrower, &within, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 64), node.localState().fork.custody_groups);
    try std.testing.expectEqualDeep(within, manager.demand);
    try std.testing.expectEqual(@as(u16, 4), manager.coverageDeficits().groups);
    manager.reconcile(node.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), manager.coverageDeficits().groups);
    _ = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u16, 1), manager.coverageDeficits().groups);
    try owner.advanceSlot(node, 10_000, setup.pair.now);
    _ = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u16, 1), manager.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 1), manager.coverageDeficits().custody_groups);
    try std.testing.expect(manager.discoveryNeed().custody);
    try owner.updateLocalDemand(node, &node.localState(), &.{}, setup.pair.now);
    _ = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u16, 0), manager.coverageDeficits().groups);
    try std.testing.expectEqual(@as(u16, 0), manager.coverageDeficits().custody_groups);
    try std.testing.expect(!manager.discoveryNeed().custody);
    try std.testing.expectEqualDeep(t.Demand{}, manager.demand);
}

test "core replaces failed gossip below target without a reputation penalty or admission timer" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..80) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.peer_manager.snapshots(&snapshots);
    const snapshot = snapshots[0];
    const conn = snapshot.connection.?;
    const driver = setup.client.service.gossipsub;
    const index = driver.sessions.find(conn).?;
    const started = driver.counters.negotiation_started;
    try std.testing.expect(driver.deliveryAvailable(conn));
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.selection.retained_count);
    @import("gossipsub/session_io.zig").resetOutbound(driver, setup.pair.client, index);
    try std.testing.expectEqual(setup.pair.now.millis(), clientWakeup(&setup).?);
    setup.client.peer_manager.reconcile(setup.client.service.gossipsub, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.selection.retained_count);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.selection.deficits.outbound);
    const after = setup.client.peer_manager.catalog.get(snapshot.peer).?;
    try std.testing.expectEqual(t.DisconnectReason.gossip_unavailable, after.disconnect_reason.?);
    try std.testing.expectEqual(snapshot.score, after.score);
    try std.testing.expectEqual(@as(u64, 0), after.ban_until_ms);
    _ = try setup.turn(&setup.client, .{});
    try std.testing.expectEqual(started, driver.counters.negotiation_started);
}

fn metadataUpdate(node: *const @import("network_core.zig").NetworkCore, metadata: *const t.Metadata) t.LocalState {
    var local = node.localState();
    local.metadata = metadata.*;
    return local;
}

fn discoveredAt(tag: u8, endpoint: t.Address) !@import("peers/enr.zig").Candidate {
    var secret: [32]u8 = @splat(0);
    secret[31] = tag;
    const key = try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret);
    const peer = t.PeerId.fromPublicKey(&key.publicKey());
    return .{ .peer = peer, .node_id = try @import("peers/custody.zig").nodeId(&peer), .sequence = 1, .record_hash = @splat(0), .addresses = .{ endpoint, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = 0, .custody_group_count = null };
}

test "core dial admission reserve counts only answered dials" {
    var setup: Setup = .{};
    var opts = @import("network_core_test_support.zig").options();
    opts.core.dial.concurrent_max = 2;
    opts.limits.dialing_max = 2;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    const dead: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_999 } };
    setup.pair.drop_to_address = dead;
    const answering = try discoveredAt(9, support.server_address);
    const silent = try discoveredAt(10, dead);
    try std.testing.expectEqual(@as(u16, 2), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{ answering, silent }, setup.pair.now).accepted);
    var intents: [2]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 2), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    for (intents) |intent| {
        const handle = try setup.pair.client.dial(&intent.address, intent.peer, setup.pair.now);
        try std.testing.expect(setup.client.peer_manager.dialStarted(intent.token, handle));
    }
    _ = setup.pair.transfer(setup.pair.client, setup.pair.server, support.client_address, false);
    setup.client.peer_manager.dialing.syncAnswered(setup.pair.client);
    try std.testing.expectEqual(@as(u16, 2), setup.client.peer_manager.dialing.pendingPeers(&setup.client.peer_manager.catalog, null));
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.dialing.answeredPeers(&setup.client.peer_manager.catalog, null));
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.dialing.answeredPeers(&setup.client.peer_manager.catalog, &answering.peer));
}

test "core inbound admission is not blocked by unanswered dials in flight" {
    var setup: Setup = .{};
    var opts = @import("network_core_test_support.zig").options();
    opts.core.dial.concurrent_max = 3;
    opts.limits.dialing_max = 3;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    setup.pair.client.limits.dialing_max = 3;
    const dead: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_999 } };
    setup.pair.drop_to_address = dead;
    for (0..3) |index| {
        const silent = try discoveredAt(@intCast(20 + index), dead);
        try setup.client.peer_manager.connect(&silent.peer, &.{dead}, setup.pair.now);
    }
    var intents: [3]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 3), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    for (intents) |intent| {
        const handle = try setup.pair.client.dial(&intent.address, intent.peer, setup.pair.now);
        try std.testing.expect(setup.client.peer_manager.dialStarted(intent.token, handle));
    }
    _ = try setup.pair.server.dial(&support.client_address, setup.client.peerId(), setup.pair.now);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 3), setup.client.peer_manager.dialing.pendingPeers(&setup.client.peer_manager.catalog, null));
    try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.dialing.answeredPeers(&setup.client.peer_manager.catalog, null));
    const inbound = setup.client.peer_manager.catalog.find(&setup.server.peerId()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(setup.client.peer_manager.catalog.rowFor(inbound).?.connection != null);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().connected);
}

test "core peer id mismatch releases the discovered endpoint and refuses its rediscovery" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const stranger = try discoveredAt(9, support.server_address);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{stranger}, setup.pair.now).accepted);
    var intents: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    const handle = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.dialStarted(intents[0].token, handle));
    for (0..20) |_| try setup.step(0);
    try std.testing.expect(setup.client.peer_manager.catalog.find(&stranger.peer) == null);
    try std.testing.expectEqual(@as(u64, 1), setup.client.peer_manager.dialing.outcomes[@intFromEnum(t.DialOutcome.peer_id_mismatch)]);
    var newer = stranger;
    newer.sequence = 2;
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.discoveredBatch(setup.client.service.gossipsub, &.{newer}, setup.pair.now).refused);
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    try std.testing.expectEqual(@as(u64, 0), setup.client.peer_manager.dialing.retries[@intFromEnum(t.DialFailure.peer_id_mismatch)]);
}

test "core remembers a served dial, keeps it through close, and replays it after a restart" {
    const remembered = @import("peers/remembered.zig");
    var records: [remembered.capacity]remembered.Record = undefined;
    var count: usize = 0;
    {
        var setup: Setup = .{};
        try setup.initOwners(&.{});
        defer setup.deinit();
        const server = try discoverServer(&setup);
        try dialServer(&setup);
        for (0..60) |_| try setup.step(1);
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        // Pings keep the connection serving while five minutes pass.
        for (0..20) |_| {
            setup.pair.advance(15_000);
            for (0..10) |_| try setup.step(1);
        }
        try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
        count = setup.client.peer_manager.rememberedPeers(setup.pair.now, &records);
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expect(records[0].peer.eql(&server.peer));
        try std.testing.expect(records[0].address.eql(support.server_address));
        try std.testing.expectEqual(@as(u64, support.now_unix), records[0].qualified_at_s);
        var inbound: [remembered.capacity]remembered.Record = undefined;
        try std.testing.expectEqual(@as(usize, 0), setup.server.peer_manager.rememberedPeers(setup.pair.now, &inbound));
        // Close clears the peer state but keeps the records a final snapshot reads.
        setup.client.shutdown(setup.pair.now);
        try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.connectedCount());
        try std.testing.expectEqual(@as(u16, 0), setup.client.peer_manager.catalog.intent_count);
        try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.rememberedPeers(setup.pair.now, &inbound));
        try std.testing.expectEqualDeep(records[0], inbound[0]);
    }
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    setup.client.peer_manager.loadRemembered(records[0..count], setup.pair.now);
    // The first turn queues the remembered candidate, and its due first attempt wakes the next.
    var intents: [1]DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    try std.testing.expectEqual(setup.pair.now.millis(), clientWakeup(&setup).?);
    try std.testing.expectEqual(@as(usize, 1), setup.client.peer_manager.dialIntents(setup.client.service.gossipsub, setup.pair.client, setup.pair.now, &intents));
    try std.testing.expect(intents[0].peer.eql(&records[0].peer));
    try std.testing.expect(intents[0].address.eql(support.server_address));
    const handle = try setup.pair.client.dial(&intents[0].address, intents[0].peer, setup.pair.now);
    try std.testing.expect(setup.client.peer_manager.dialStarted(intents[0].token, handle));
    for (0..60) |_| try setup.step(1);
    try std.testing.expectEqual(@as(u16, 1), setup.client.peer_manager.peerCounts().relevant);
    const funnel = setup.client.peer_manager.catalog.remembered.counters.funnel;
    try std.testing.expectEqual([3]u64{ 1, 1, 0 }, funnel[@intFromEnum(remembered.Origin.remembered)]);
    try std.testing.expectEqual([3]u64{ 0, 0, 0 }, funnel[@intFromEnum(remembered.Origin.fresh)]);
    try std.testing.expect(setup.client.peer_manager.catalog.remembered.nextReplay(support.now_unix) == null);
}
