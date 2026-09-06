const std = @import("std");
const support = @import("test_support.zig");
const managed = @import("core.zig");
const t = @import("peers/types.zig");
const Engine = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");

pub fn options() managed.Options {
    const gc = @import("gossipsub/constants.zig");
    return .{
        .peers = .{
            .capacity = 4,
            .outbound_reserve = 1,
            .max_peers = 3,
            .target_peers = 2,
            .min_outbound = 1,
            .engine_capacity = 4,
        },
        .service = .{
            .router = .{ .negotiations_max = 24, .outbound_control_reserved = 8 },
            .reqresp = .{
                .peers = 4,
                .outbound_max = 16,
                .inbound_max = 16,
                .outbound_control_reserved = 8,
                .inbound_control_reserved = 8,
                .outbound_per_peer_max = 8,
                .inbound_per_peer_max = 16,
                .inbound_application_per_peer_max = 8,
                .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }},
            },
            .gossipsub = .{
                .random_seed = 1,
                .seen_capacity = 16,
                .mcache_capacity = 8,
                .validation_capacity = 2,
                .mcache_arena_bytes = gc.maxCompressedLen(gc.MAX_PAYLOAD_SIZE) + 4096,
                .decompressed_arena_bytes = gc.MAX_PAYLOAD_SIZE + 256,
                .large_pool_count = 1,
                .body_buffer_bytes = 256,
                .control_bytes = 512,
                .critical_bytes = 512,
            },
        },
        .dial = .{ .capacity = 4, .concurrent_max = 2, .engine_dialing_max = 2, .seed = 7 },
        .control = .{ .operations_max = 2 },
    };
}

pub const Setup = struct {
    pair: support.Pair = .{},
    client: managed.Core = undefined,
    server: managed.Core = undefined,
    client_events: [1]t.Event = undefined,
    server_events: [1]t.Event = undefined,
    pub fn init(self: *Setup, local: *const t.LocalState) !void {
        try self.initDirection(local, false);
    }
    pub fn initDirection(self: *Setup, local: *const t.LocalState, reverse: bool) !void {
        try self.initOwners(local);
        errdefer self.deinit();
        if (reverse) {
            _ = try self.pair.server.dial(
                &support.client_address,
                self.pair.client_ctx.local_peer_id,
                self.pair.now,
                self.pair.nextEntropy(),
            );
        } else _ = try self.pair.dial();
    }
    pub fn initOwners(self: *Setup, local: *const t.LocalState) !void {
        try self.initOwnersWithOptions(local, options());
    }
    pub fn initOwnersWithOptions(
        self: *Setup,
        local: *const t.LocalState,
        opts: managed.Options,
    ) !void {
        const limits: Engine.Limits = .{
            .connections_max = 4,
            .handshaking_max = 4,
            .handshaking_per_source_max = 4,
            .dialing_max = 2,
        };
        try self.pair.init(limits, limits);
        errdefer self.pair.deinit();
        self.client = try managed.Core.init(
            std.testing.allocator,
            &self.pair.client_ctx.local_peer_id,
            local,
            opts,
        );
        errdefer self.client.deinit();
        self.server = try managed.Core.init(
            std.testing.allocator,
            &self.pair.server_ctx.local_peer_id,
            local,
            opts,
        );
    }
    pub fn deinit(self: *Setup) void {
        self.client.shutdown(&self.pair.client, self.pair.now);
        self.server.shutdown(&self.pair.server, self.pair.now);
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }
    pub fn step(self: *Setup, capacity: usize) !void {
        try self.pair.pump();
        var events: [32]Engine.Event = undefined;
        var activity: [4]Engine.Handle = undefined;
        var count = self.pair.server.driverView().takeActivity(&activity);
        _ = self.server.process(
            &self.pair.server,
            self.pair.events(&self.pair.server, &events),
            activity[0..count],
            self.pair.now,
            100,
            self.server_events[0..capacity],
            &.{},
            &.{},
        );
        count = self.pair.client.driverView().takeActivity(&activity);
        _ = self.client.process(
            &self.pair.client,
            self.pair.events(&self.pair.client, &events),
            activity[0..count],
            self.pair.now,
            100,
            self.client_events[0..capacity],
            &.{},
            &.{},
        );
    }
};

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
        try std.testing.expectEqual(@as(u16, 1), setup.client.connectedPeerCount());
        try std.testing.expectEqual(@as(u16, 1), setup.server.connectedPeerCount());
        var snapshots: [4]t.Snapshot = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.client.snapshots(&snapshots));
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
        try std.testing.expectEqual(t.Direction.outbound, snapshots[0].direction);
        _ = setup.server.snapshots(&snapshots);
        try std.testing.expectEqual(t.Direction.inbound, snapshots[0].direction);
        try std.testing.expectEqualDeep(local.metadata, snapshots[0].metadata.?);
    }
}

test "core native ping coalesces metadata and confirms unchanged freshness then periodic Status" {
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
    try setup.server.updateMetadata(&changed);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(changed, snapshots[0].metadata.?);
    const status: t.Status = .{ .head_slot = 80 };
    try setup.server.updateStatus(&status);
    setup.pair.advance(300_000);
    for (0..50) |_| try setup.step(1);
    _ = setup.client.snapshots(&snapshots);
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
        for (setup.server.control.responses) |response| if (response.request) |request| {
            const slot = setup.server.service.reqresp.inner.inboundSlot(request).?;
            if (slot.protocol != .metadata_v1) continue;
            try std.testing.expect(slot.io.writing);
            const changed: t.Metadata = .{ .seq_number = 5, .attnets = @splat(9) };
            try setup.server.updateMetadata(&changed);
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

test "core native wrong fork Goodbye hard closes with zero output and shutdown repeats" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    try setup.server.updateFork(
        &.{ .fork = .{ .digest = @splat(1) }, .status = .{ .fork_digest = @splat(1) } },
        setup.pair.now,
    );
    for (0..40) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.connectedPeerCount());
    setup.pair.advance(2_001);
    for (0..5) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.catalog.connectedCount());
    try std.testing.expectEqual(@as(u16, 0), setup.server.catalog.connectedCount());
    var events: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&events));
    try std.testing.expectEqual(t.DisconnectReason.incompatible_fork, events[0].closed.reason);
    setup.client.shutdown(&setup.pair.client, setup.pair.now);
    setup.client.shutdown(&setup.pair.client, setup.pair.now);
}

test "core native control timeout releases owners independent of public output" {
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

fn allocationCheck(a: std.mem.Allocator) !void {
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    var core = try managed.Core.init(a, &identity, &.{}, options());
    defer core.deinit();
    try std.testing.expect(core.memoryPlan().allocated_bytes > core.memoryPlan().control_bytes);
}

test "core startup allocation failure cleans every prefix and memory accounts exact reservations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    var core = try managed.Core.init(failing.allocator(), &identity, &.{}, options());
    const expected = core.memoryPlan().allocated_bytes;
    try std.testing.expectEqual(expected, failing.allocated_bytes);
    core.deinit();
    try std.testing.expectEqual(expected, failing.freed_bytes);
}

test "core native deterministic replacement cancels old control and ignores stale physical close" {
    var setup: Setup = .{};
    try setup.initDirection(&.{}, true);
    defer setup.deinit();
    for (0..60) |_| try setup.step(1);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const old = snapshots[0];
    try std.testing.expect(old.relevant);
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
    try std.testing.expect(setup.pair.client.registry.slots[old.connection.?.index].conn == null);
    try std.testing.expectEqual(@as(u16, 1), setup.pair.client.registry.active_len);
    try std.testing.expectError(error.StaleHandle, setup.pair.client.openStream(old.connection.?));
    _ = setup.client.process(
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
        &setup.client.service,
        &setup.client.catalog,
        &setup.pair.client,
        &setup.client.local,
        setup.pair.now,
        100,
        &.{.{ .failed = .{ .request = old_request.?, .reason = .timeout } }},
    );
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqualDeep(selected, snapshots[0]);
    try std.testing.expectEqual(@as(u16, 1), setup.client.connectedPeerCount());
}

test "core native saturated app requests retain partitioned borrows while controls progress" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    const bytes = [_]u8{0} ** 24;
    const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, sink_size * 8);
    defer std.testing.allocator.free(sinks);
    defer setup.client.shutdown(&setup.pair.client, setup.pair.now);
    const protocols = [_]rr.Protocol{
        .blocks_by_range_v2,
        .blocks_by_root_v2,
        .blob_sidecars_by_range_v1,
        .blob_sidecars_by_root_v1,
    };
    for (0..8) |index| {
        const protocol = protocols[index / 2];
        _ = try setup.client.sendReqRespRequest(
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
        setup.client.sendReqRespRequest(
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
        setup.client.sendReqRespRequest(
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
    try std.testing.expectEqual(@as(u16, 1), setup.client.connectedPeerCount());
    var applications: [1]rr.Event = undefined;
    var delivered: usize = 0;
    for (0..16) |_| {
        const counts = setup.server.process(
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
        _ = setup.server.cancel(request.request);
    }
    try std.testing.expectEqual(@as(usize, 8), delivered);
}

test "core native local control capacity defers with future wakeup and no peer penalty" {
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
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(f64, 0), snapshots[0].score);
    try std.testing.expect(snapshots[0].relevant);
    const control_due = setup.client.control.nextWakeup(setup.pair.now).?;
    try std.testing.expect(control_due > setup.pair.now.mono_ms);
    setup.client.shutdown(&setup.pair.client, setup.pair.now);
}

test "core native gossip refusal retries selected connection once a second without score feedback" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const selected = snapshots[0];
    const other = try setup.pair.dial();
    try setup.pair.pump();
    var transport: [32]Engine.Event = undefined;
    _ = setup.pair.events(&setup.pair.client, &transport);
    _ = setup.pair.events(&setup.pair.server, &transport);
    setup.client.service.gossipsub.inner.connectionClosed(selected.connection.?);
    try std.testing.expectEqual(
        gossip.Handler.Admission.admitted,
        setup.client.service.gossipsub.peerConnected(&setup.pair.client, other, setup.pair.now),
    );
    setup.pair.advance(1_000);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(!setup.client.service.gossipsub.admitted(selected.connection.?));
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].relevant);
    try std.testing.expectEqual(@as(f64, 0), snapshots[0].score);
    setup.client.service.gossipsub.inner.connectionClosed(other);
    setup.pair.advance(999);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(!setup.client.service.gossipsub.admitted(selected.connection.?));
    setup.pair.advance(1);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expect(setup.client.service.gossipsub.admitted(selected.connection.?));
}

test "core direct removal clears both pins and gossip score reads have no feedback" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    const identity = setup.pair.server_ctx.local_peer_id;
    try setup.client.addDirectPeer(&identity, &.{support.server_address}, setup.pair.now);
    setup.pair.advance(1_000);
    for (0..3) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].direct);
    const conn = snapshots[0].connection.?;
    try std.testing.expect(setup.client.service.gossipsub.setPeerScore(conn, -3));
    const before = setup.client.gossipScore(snapshots[0].peer, setup.pair.now).?;
    try std.testing.expect(std.math.isFinite(before));
    _ = setup.client.reportPeer(snapshots[0].peer, .high_tolerance, setup.pair.now);
    try std.testing.expectEqual(
        before,
        setup.client.gossipScore(snapshots[0].peer, setup.pair.now).?,
    );
    setup.client.removeDirectPeer(&identity);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(!snapshots[0].direct);
    const logical = setup.client.service.gossipsub.inner.peers.find(&identity).?;
    try std.testing.expect(!setup.client.service.gossipsub.inner.peers.rows[logical.index].direct);
    var intents: [2]@import("peers/dial_queue.zig").DialIntent = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        setup.client.dialIntents(&setup.pair.client, setup.pair.now, &intents),
    );
}

test "core native preserves gossip events under one output and caller validation wrappers" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.subscribe(topic));
    try std.testing.expect(setup.server.subscribe(topic));
    for (0..50) |_| try setup.step(0);
    setup.pair.advance(1_001);
    for (0..30) |_| try setup.step(0);
    for (0..30) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var output: [1]gossip.Event = undefined;
        _ = setup.server.process(&setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &output);
        _ = setup.client.process(&setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &output);
    }
    setup.pair.advance(1_001);
    for (0..10) |_| try setup.step(0);
    const payload = "bounded Core gossip payload";
    _ = try setup.client.publishGossip(topic, payload, setup.pair.now);
    var received: usize = 0;
    for (0..50) |_| {
        try setup.pair.pump();
        var transport: [32]Engine.Event = undefined;
        var activity: [4]Engine.Handle = undefined;
        var messages: [1]gossip.Event = undefined;
        const active = setup.pair.server.driverView().takeActivity(&activity);
        const counts = setup.server.process(&setup.pair.server, setup.pair.events(
            &setup.pair.server,
            &transport,
        ), activity[0..active], setup.pair.now, 100, &.{}, &.{}, &messages);
        if (counts.gossipsub == 1 and messages[0] == .message) {
            const message = messages[0].message;
            try std.testing.expectEqualStrings(payload, message.bytes);
            try std.testing.expectEqual(
                gossip.ReportOutcome{ .applied = .accept },
                setup.server.reportValidation(message.handle, .accept, setup.pair.now),
            );
            try std.testing.expectEqualStrings(payload, message.bytes);
            received += 1;
        }
        _ = setup.client.process(&setup.pair.client, setup.pair.events(
            &setup.pair.client,
            &transport,
        ), &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try std.testing.expect(setup.client.unsubscribe(topic));
}

test "core managed defaults reserve maintenance while raw Service defaults stay unreserved" {
    const defaults: managed.Options = .{ .dial = .{ .seed = 1 } };
    try std.testing.expectEqual(@as(u16, 8), defaults.service.reqresp.outbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 8), defaults.service.reqresp.inbound_control_reserved);
    try std.testing.expectEqual(@as(u16, 8), defaults.service.router.outbound_control_reserved);
    try std.testing.expectEqual(@as(u8, 8), defaults.service.reqresp.outbound_per_peer_max);
    try std.testing.expectEqual(@as(u8, 16), defaults.service.reqresp.inbound_per_peer_max);
    try std.testing.expectEqual(
        @as(u8, 8),
        defaults.service.reqresp.inbound_application_per_peer_max,
    );
    const raw: @import("service.zig").Options = .{ .reqresp = .{ .forks = &.{} } };
    try std.testing.expectEqual(@as(u16, 0), raw.reqresp.outbound_control_reserved);
    try std.testing.expectEqual(@as(u8, 8), raw.reqresp.inbound_per_peer_max);
    try std.testing.expectEqual(@as(u8, 0), raw.reqresp.inbound_application_per_peer_max);
    try std.testing.expect(raw.automatic_gossip_admission);
}

test "core native continuous reStatus cannot starve due metadata sequence confirmation" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    try setup.server.updateMetadata(&.{ .seq_number = 12 });
    setup.pair.advance(21_000);
    for (0..60) |_| {
        setup.client.reStatusPeers(setup.pair.now);
        try setup.step(0);
    }
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(u64, 12), snapshots[0].metadata.?.seq_number);
}

test "core native Goodbye immediately removes relevance and delayed Status cannot revive it" {
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
    try std.testing.expectEqual(@as(u16, 0), setup.client.connectedPeerCount());
    try std.testing.expectEqual(@as(u16, 1), setup.client.peerCounts().connected);
    for (0..20) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.connectedPeerCount());
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&event));
    try std.testing.expect(!event[0].updated.relevant);
    setup.pair.advance(2_000);
    for (0..4) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.peerCounts().connected);
    try std.testing.expectEqual(@as(usize, 1), setup.client.catalog.pollEvents(&event));
    try std.testing.expectEqual(t.DisconnectReason.reputation, event[0].closed.reason);
}

test "core native hard close retires QUIC routes streams and registry with zero public output" {
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

test "core native leased dial retires uncompleted handshake and rejects late acknowledgements" {
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
        setup.client.dialIntents(&setup.pair.client, setup.pair.now, &output),
    );
    const intent = output[0];
    try std.testing.expect(intent.peer.eql(&setup.pair.server_ctx.local_peer_id));
    try std.testing.expect(intent.address.eql(support.server_address));
    const conn = try setup.pair.client.dial(
        &intent.address,
        intent.peer,
        setup.pair.now,
        setup.pair.nextEntropy(),
    );
    try std.testing.expect(setup.client.dialStarted(intent.token, conn));
    setup.pair.advance(10_000);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 0, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.dialing);
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.active_len);
    try std.testing.expect(setup.pair.client.registry.slots[conn.index].conn == null);
    try std.testing.expect(!setup.client.dialStarted(intent.token, conn));
    try std.testing.expect(!setup.client.dialFailed(intent.token, setup.pair.now));
    try std.testing.expect(setup.client.dial_queue.nextWakeup(setup.pair.now.mono_ms, 1).? >
        setup.pair.now.mono_ms);
}

test "core native dial expiry closes authenticated attempt before connected event delivery" {
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
        _ = setup.client.dialIntents(&setup.pair.client, setup.pair.now, &output);
        const intent = output[0];
        const conn = try setup.pair.client.dial(
            &intent.address,
            intent.peer,
            setup.pair.now,
            setup.pair.nextEntropy(),
        );
        try std.testing.expect(setup.client.dialStarted(intent.token, conn));
        try setup.pair.pump();
        try std.testing.expect(setup.pair.client.peerId(conn) != null);
        if (shutdown) setup.client.shutdown(&setup.pair.client, setup.pair.now) else {
            setup.pair.advance(10_000);
            _ = setup.client.dialIntents(&setup.pair.client, setup.pair.now, &output);
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

test "core review native competing attempt expires during selected peer ban cooldown" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    try setup.client.connect(&setup.pair.server_ctx.local_peer_id, &.{support.server_address}, setup.pair.now);
    var intents: [1]managed.DialIntent = undefined;
    _ = setup.client.dialIntents(&setup.pair.client, setup.pair.now, &intents);
    const token = intents[0].token;
    const attempt = try setup.pair.dial();
    try std.testing.expect(setup.client.dialStarted(token, attempt));
    _ = try setup.pair.server.dial(&support.client_address, setup.pair.client_ctx.local_peer_id, setup.pair.now, setup.pair.nextEntropy());
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
    _ = setup.client.process(&setup.pair.client, &.{selected.?}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(!std.meta.eql(attempt, snapshots[0].connection.?));
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.reportPeer(snapshots[0].peer, .fatal, setup.pair.now).?);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    setup.pair.advance(10_000);
    _ = setup.client.dialIntents(&setup.pair.client, setup.pair.now, &intents);
    for (0..8) |_| try setup.step(0);
    try std.testing.expect(setup.pair.client.registry.slots[attempt.index].conn == null);
    try std.testing.expect(!setup.client.dialStarted(token, attempt));
    try std.testing.expect(!setup.client.dialFailed(token, setup.pair.now));
    try std.testing.expectEqual(@as(u16, 0), setup.pair.client.registry.outbound);
    try std.testing.expect(setup.client.dial_queue.nextWakeup(setup.pair.now.mono_ms, 1).? >
        setup.pair.now.mono_ms);
}

test "core review early native close preserves selected reason and counts it once" {
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

test "core coverage demand copies expires at host slot and keeps general discovery independent" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var demand: t.Demand = .{ .coverage = .{ .syncnets = 1 }, .expires_at_slot = 101 };
    try setup.client.setDemand(&demand);
    demand.coverage.syncnets = 2;
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 1), setup.client.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.discoveryNeed().general);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 101, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u8, 0), setup.client.discoveryNeed().syncnets);
    try std.testing.expect(setup.client.discoveryNeed().general);
    const due = setup.client.nextWakeup(setup.pair.now, 0, 0, 0, 0);
    try std.testing.expect(due == null or due.? > setup.pair.now.mono_ms);
}

test "core coverage authenticated custody differs from gossip delivery and invalidates fork groups" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .syncnets = 1, .custody_group_count = 128 } };
    try setup.init(&local);
    defer setup.deinit();
    var demand: t.Demand = .{ .coverage = .{ .syncnets = 1 }, .expires_at_slot = 200 };
    demand.coverage.custody.set(0);
    try setup.client.setDemand(&demand);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().custody);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const connection = snapshots[0].connection.?;
    const index = setup.client.service.gossipsub.inner.state.findPeer(connection).?;
    setup.client.service.gossipsub.inner.resetOutbound(&setup.pair.client, index);
    try std.testing.expect(!setup.client.service.gossipsub.deliveryAvailable(connection));
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    setup.client.service.gossipsub.streams[index].outbound = .{ .waiting = setup.pair.now.mono_ms +| 30_000 };
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().custody);
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try setup.client.updateFork(&local, setup.pair.now);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().custody);
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(snapshots[0].custody_groups == null);
}

test "core coverage physical closing capacity blocks new leased intents" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expect(setup.client.disconnect(snapshots[0].peer, .host, setup.pair.now));
    for (0..2) |_| _ = try setup.pair.client.dial(&support.server_address, setup.pair.server_ctx.local_peer_id, setup.pair.now, setup.pair.nextEntropy());
    try std.testing.expectEqual(@as(u16, 3), setup.pair.client.registry.active_len);
    var secret: [32]u8 = @splat(0);
    secret[31] = 17;
    const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
    const peer = t.PeerId.fromPublicKey(&key);
    try setup.client.connect(&peer, &.{support.server_address}, setup.pair.now);
    var out: [2]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.dial_queue.attempts().total);
}

test "core coverage direct candidate dials at soft target and respects physical hard capacity" {
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
    try setup.client.addDirectPeer(&peer, &.{support.server_address}, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&peer));
}

fn candidateFor(peer: *const t.PeerId, count: ?u64) !@import("peers/enr.zig").Candidate {
    return .{ .peer = peer.*, .node_id = try @import("peers/custody.zig").nodeId(peer), .sequence = 1, .addresses = .{ support.server_address, .unspecified }, .address_count = 1, .fork = .{ .digest = @splat(0), .next_version = @splat(0), .next_epoch = 0 }, .next_fork_digest = null, .attnets = null, .syncnets = null, .custody_group_count = count };
}

test "core coverage automatic retention renews only at authenticated Status success" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    var candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    try setup.client.discovered(&candidate, setup.pair.now);
    _ = try setup.pair.dial();
    for (0..50) |_| try setup.step(0);
    const horizon = setup.client.dial_queue.rows[0].history_until_ms;
    setup.pair.advance(1000);
    for (0..10) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.dial_queue.rows[0].history_until_ms);
    candidate.sequence = 2;
    try setup.client.discovered(&candidate, setup.pair.now);
    setup.pair.advance(21_000);
    for (0..50) |_| try setup.step(0);
    try std.testing.expectEqual(horizon, setup.client.dial_queue.rows[0].history_until_ms);
    setup.client.reStatusPeers(setup.pair.now);
    for (0..50) |_| try setup.step(0);
    try std.testing.expect(setup.client.dial_queue.rows[0].history_until_ms > horizon);
}

test "core coverage bounded custody work resumes without output and stale metadata cannot satisfy demand" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 127, .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    var demand: t.Demand = .{ .coverage = .{ .syncnets = 1 }, .expires_at_slot = 200 };
    demand.coverage.custody.set(0);
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
        try setup.client.discovered(&candidate, setup.pair.now);
    }
    var saw_pending = false;
    for (0..80) |_| {
        const before = setup.client.counters.custody_hashes;
        try setup.step(0);
        try std.testing.expect(setup.client.counters.custody_hashes - before <= 256);
        if (setup.client.custody_pending) {
            saw_pending = true;
            try std.testing.expect(setup.client.nextWakeup(setup.pair.now, 0, 0, 0, 0).? <= setup.pair.now.mono_ms +| 1);
        }
    }
    try std.testing.expect(saw_pending);
    try std.testing.expect(!setup.client.custody_pending);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    try std.testing.expectEqual(@as(usize, 127), snapshots[0].custody_groups.?.count());
    setup.pair.advance(60_000);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().custody);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
}

test "core coverage outbound deficit uses hard room or retires inbound before replacement" {
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
            try std.testing.expect(setup.server.counters.policy_disconnects > 0);
            setup.pair.advance(2000);
            for (0..8) |_| try setup.step(0);
            try std.testing.expectEqual(@as(u16, 0), setup.pair.server.registry.active_len);
        } else try std.testing.expectEqual(@as(u16, 1), setup.server.connectedPeerCount());
        var secret: [32]u8 = @splat(0);
        secret[31] = 17;
        const key = (try @import("wire/keys.zig").KeyPair.fromSecretKey(&secret)).publicKey();
        const peer = t.PeerId.fromPublicKey(&key);
        const candidate = try candidateFor(&peer, null);
        try setup.server.discovered(&candidate, setup.pair.now);
        var out: [1]managed.DialIntent = undefined;
        try std.testing.expectEqual(@as(usize, 1), setup.server.dialIntents(&setup.pair.server, setup.pair.now, &out));
        try std.testing.expect(out[0].peer.eql(&peer));
    }
}

test "core coverage review same-digest group update disables cached automatic candidate" {
    var setup: Setup = .{};
    var local: t.LocalState = .{ .fork = .{ .fork = .fulu }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 128 } };
    try setup.initOwners(&local);
    defer setup.deinit();
    var candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, 128);
    candidate.syncnets = 1;
    try setup.client.setDemand(&.{ .coverage = .{ .syncnets = 1 }, .expires_at_slot = 200 });
    try setup.client.discovered(&candidate, setup.pair.now);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, 100, &.{}, &.{}, &.{});
    local.fork.custody_groups = 64;
    local.metadata.custody_group_count = 64;
    try setup.client.updateFork(&local, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(@as(u16, 0), setup.client.dial_queue.rows[0].priority);
    try std.testing.expectEqual(@as(u64, 1), setup.client.dial_queue.rows[0].hints.?.sequence);
    candidate.sequence = 2;
    candidate.custody_group_count = 64;
    try setup.client.discovered(&candidate, setup.pair.now);
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "core reconciliation idle and candidate batch work" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    for (0..8) |_| {
        try setup.step(0);
        _ = setup.client.dialIntents(&setup.pair.client, setup.pair.now, &.{});
    }
    const c = setup.client.counters;
    const candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    for (0..4) |_| try setup.client.discovered(&candidate, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    const after = setup.client.counters;
    try std.testing.expectEqual(@as(u64, 1), c.selections);
    try std.testing.expectEqual(@as(u64, 1), c.candidate_syncs);
    try std.testing.expectEqual(@as(u64, 0), after.selections - c.selections);
    try std.testing.expect(after.candidate_syncs - c.candidate_syncs <= 1);
}

test "core reconciliation raw mutators deadlines and read getters invalidate once" {
    var setup: Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .altair }, .metadata = .{ .syncnets = 1 } };
    try setup.init(&local);
    defer setup.deinit();
    const demand: t.Demand = .{ .coverage = .{ .syncnets = 1 }, .expires_at_slot = 200 };
    try setup.client.setDemand(&demand);
    for (0..60) |_| try setup.step(0);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    const before = setup.client.counters.selections;
    for (0..8) |_| {
        setup.pair.advance(1);
        setup.client.reconcile(setup.pair.now);
        _ = setup.client.coverageDeficits();
    }
    try std.testing.expectEqual(before, setup.client.counters.selections);
    try std.testing.expect(setup.client.catalog.updateMetadata(peer, conn, &.{ .seq_number = 10, .syncnets = 0 }, setup.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(before + 1, setup.client.counters.selections);
    try std.testing.expect(setup.client.catalog.updateMetadata(peer, conn, &.{ .seq_number = 11, .syncnets = 1 }, setup.pair.now.mono_ms));
    setup.client.reconcile(setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    const deadline = setup.client.metadata_deadline.?;
    var clock = setup.pair.now;
    clock.mono_ms = deadline - 1;
    setup.client.reconcile(clock);
    const fresh = setup.client.counters.selections;
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    clock.mono_ms = deadline;
    setup.client.reconcile(clock);
    try std.testing.expectEqual(@as(u16, 1), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);
    clock.mono_ms += 1;
    setup.client.reconcile(clock);
    try std.testing.expectEqual(fresh + 1, setup.client.counters.selections);

    try std.testing.expect(setup.client.service.gossipsub.inner.setPeerScore(conn, -10));
    setup.client.reconcile(clock);
    try std.testing.expectEqual(fresh + 2, setup.client.counters.selections);
    try std.testing.expect(setup.client.service.gossipsub.inner.setPeerScore(conn, -10));
    setup.client.reconcile(clock);
    try std.testing.expectEqual(fresh + 2, setup.client.counters.selections);
    _ = setup.client.reportPeer(peer, .high_tolerance, clock);
    setup.client.reconcile(clock);
    const penalized = setup.client.counters.selections;
    const health = setup.client.catalog.get(peer).?.score;
    clock.mono_ms += 100;
    setup.client.reconcile(clock);
    try std.testing.expect(setup.client.catalog.get(peer).?.score > health);
    try std.testing.expectEqual(penalized, setup.client.counters.selections);

    try setup.client.addDirectPeer(&snapshots[0].identity, &.{support.server_address}, clock);
    _ = setup.client.coverageDeficits();
    try std.testing.expectEqual(penalized + 1, setup.client.counters.selections);
    setup.client.removeDirectPeer(&snapshots[0].identity);
    _ = setup.client.coverageDeficits();
    try std.testing.expectEqual(penalized + 2, setup.client.counters.selections);
    try setup.client.setDemand(&.{});
    try std.testing.expectEqual(@as(u16, 0), setup.client.coverageDeficits().sync);
    try std.testing.expectEqual(penalized + 3, setup.client.counters.selections);
    try setup.client.setDemand(&.{});
    _ = setup.client.coverageDeficits();
    try std.testing.expectEqual(penalized + 3, setup.client.counters.selections);
    try std.testing.expect(setup.client.disconnect(peer, .host, clock));
    setup.client.reconcile(clock);
    try std.testing.expectEqual(@as(u16, 0), setup.client.selection.retained_count);
}

test "core reconciliation batch counts refusal and fresh native room independently" {
    var setup: Setup = .{};
    var opts = options();
    opts.peers.max_peers = 1;
    opts.peers.target_peers = 1;
    opts.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    setup.client.reconcile(setup.pair.now);
    const baseline = setup.client.counters;
    const candidate = try candidateFor(&setup.pair.server_ctx.local_peer_id, null);
    const self_candidate = try candidateFor(&setup.pair.client_ctx.local_peer_id, null);
    var invalid = candidate;
    invalid.address_count = 0;
    const result = setup.client.discoveredBatch(&.{ candidate, self_candidate, invalid, candidate }, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 2), result.accepted);
    try std.testing.expectEqual(@as(u16, 2), result.refused);
    const conn = try setup.pair.dial();
    var out: [1]managed.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expect(setup.pair.client.abandon(conn));
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.pair.client, setup.pair.now, &out));
    try std.testing.expectEqual(baseline.selections, setup.client.counters.selections);
    try std.testing.expectEqual(baseline.candidate_selections + 1, setup.client.counters.candidate_selections);
    try std.testing.expectEqual(baseline.candidate_syncs, setup.client.counters.candidate_syncs);
}

test "core reconciliation exhausted revisions stay invalidated" {
    var setup: Setup = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    setup.client.catalog.revision = std.math.maxInt(u64);
    setup.client.reconcile(setup.pair.now);
    const before = setup.client.counters.selections;
    setup.client.reconcile(setup.pair.now);
    try std.testing.expectEqual(before + 1, setup.client.counters.selections);
}

test "core reconciliation ban expiry still defers until strict score recovery" {
    var setup: Setup = .{};
    try setup.init(&.{});
    defer setup.deinit();
    for (0..50) |_| try setup.step(0);
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const peer = snapshots[0].peer;
    const conn = snapshots[0].connection.?;
    try std.testing.expectEqual(t.ReputationDecision.ban, setup.client.reportPeer(peer, .fatal, setup.pair.now).?);
    setup.client.control.close(&setup.client.service, &setup.client.catalog, &setup.pair.client, peer, conn, .banned, setup.pair.now);
    const candidate = try candidateFor(&snapshots[0].identity, null);
    try setup.client.discovered(&candidate, setup.pair.now);
    var out: [1]managed.DialIntent = undefined;
    const ban = setup.client.catalog.get(peer).?.ban_until_ms;
    var clock = setup.pair.now;
    clock.mono_ms = ban - 1;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, clock, &out));
    clock.mono_ms = ban;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, clock, &out));
    const recovery = setup.client.reconciliation_deadline.?;
    try std.testing.expect(recovery > ban);
    clock.mono_ms = recovery - 1;
    try std.testing.expectEqual(@as(usize, 0), setup.client.dialIntents(&setup.pair.client, clock, &out));
    clock.mono_ms = recovery;
    try std.testing.expectEqual(@as(usize, 1), setup.client.dialIntents(&setup.pair.client, clock, &out));
    try std.testing.expect(setup.client.catalog.get(peer).?.score > -50);
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}
