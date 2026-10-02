const transport_test = @import("transport_test_support.zig");
const core_test = @import("network_core_test_support.zig");
const FaultIo = @import("fault_io");
const std = @import("std");
const NetworkCore = @import("network_core.zig").NetworkCore;
const t = @import("peers/types.zig");
const keys = @import("wire/keys.zig");
const d = @import("discv5");

const options = @import("network_core_test_support.zig").networkOptions;
const Inbox = @import("gossipsub/test_support.zig").Inbox;
const Now = @import("types.zig").Now;

/// Applies a local update through the host intent path with the current subscriptions and demand.
fn applyLocal(node: *NetworkCore, update: *const NetworkCore.LocalUpdate, now: Now) !bool {
    var boundaries: [@import("gossipsub/topic_policy.zig").boundary_max]@import("gossipsub/local_intent.zig").Boundary = undefined;
    var desired = core_test.intent(node, try @import("gossipsub/test_support.zig").subscriptionUpdate(node.service.gossipsub, null, false, &boundaries));
    desired.update = update.*;
    return node.applyIntent(&desired, now);
}

fn updateLocalWithEndpoints(node: *NetworkCore, local: *const t.LocalState, schedule: NetworkCore.ForkSchedule, endpoints: ?NetworkCore.AdvertisementEndpoints, now: Now) !bool {
    return applyLocal(node, &.{ .local = local.*, .schedule = schedule, .endpoints = endpoints, .capabilities = node.service.router.capabilities() }, now);
}

fn updateLocal(node: *NetworkCore, local: *const t.LocalState, schedule: NetworkCore.ForkSchedule, now: Now) !bool {
    return updateLocalWithEndpoints(node, local, schedule, node.advertisementEndpoints(), now);
}

/// Steps at the current time with a host that only bounds the wait at `wait_ms`.
fn stepAfter(node: *NetworkCore, wait_ms: u32) !NetworkCore.Result {
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    return node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| wait_ms));
}

const MaintenancePeers = struct {
    nodes: []NetworkCore,

    fn init(hub_allocator: std.mem.Allocator) !MaintenancePeers {
        const nodes = try std.testing.allocator.alloc(NetworkCore, 4);
        errdefer std.testing.allocator.free(nodes);
        var initialized: usize = 0;
        errdefer for (nodes[0..initialized]) |*node| node.deinit(std.testing.io);
        for (nodes, 0..) |*node, index| {
            const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{@as(u8, @intCast(80 + index))}));
            var opts = options(&key);
            opts.resolved.core.peers.target_peers = 3;
            opts.resolved.core.peers.max_peers = 4;
            opts.resolved.core.control.starts_per_turn_max = 1;
            opts.resolved.core.service.reqresp.outbound_max = 6;
            opts.resolved.core.service.reqresp.outbound_control_reserved = 4;
            opts.resolved.core.service.reqresp.inbound_control_reserved = 4;
            opts.resolved.core.service.reqresp.outbound_per_peer_max = 2;
            opts.resolved.core.service.router = .{ .negotiations_max = 16, .outbound_control_reserved = 4, .outbound_reserved = 8 };
            try node.init(if (index == 0) hub_allocator else std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
            initialized += 1;
        }
        const hub = &nodes[0];
        errdefer |err| std.debug.print("maintenance bootstrap failed: {t}, peers={any}, operations={any}, requests={any}\n", .{ err, hub.peerCounts(), core_test.controlOperations(hub), hub.service.reqresp.pendingCounts() });
        for (nodes[1..]) |*remote| try hub.connectUntil(&remote.peerId(), &.{remote.transport.localAddress()}, hub.last_now, hub.last_now.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
        for (0..3000) |_| {
            try step(&.{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] });
            if (hub.peerCounts().relevant != 3 or core_test.controlOperations(hub) != 0) continue;
            var snapshots: [4]t.Snapshot = undefined;
            const count = hub.peer_manager.snapshots(&snapshots);
            var metadata = true;
            for (snapshots[0..count]) |snapshot| metadata = metadata and snapshot.metadata != null;
            var retired = true;
            for (hub.service.reqresp.outbound) |slot| retired = retired and !slot.request.occupied();
            for (hub.service.router.negotiator.entries) |entry| retired = retired and entry.state == .free;
            if (metadata and retired) return .{ .nodes = nodes };
        }
        return error.TestUnexpectedResult;
    }

    fn deinit(self: *MaintenancePeers) void {
        for (self.nodes) |*node| node.deinit(std.testing.io);
        std.testing.allocator.free(self.nodes);
    }

    fn step(nodes: []const *NetworkCore) !void {
        for (nodes) |node| {
            const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
            const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
            if (result.failure) |err| return err;
        }
    }
};

test "core rejects incomplete serving state before startup allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var node: NetworkCore = undefined;
    opts.startup.local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.local.status.earliest_available_slot = null;
    try std.testing.expectError(error.MissingAvailability, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

test "core maintenance isolates slow peers and full application capacity" {
    const rr = @import("reqresp/root.zig");
    var backing_hub = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var fixture = try MaintenancePeers.init(backing_hub.allocator());
    defer fixture.deinit();
    const hub = &fixture.nodes[0];
    errdefer |err| std.debug.print("maintenance isolation failed: {t}, peers={any}, operations={any}, requests={any}\n", .{ err, hub.peerCounts(), core_test.controlOperations(hub), hub.service.reqresp.pendingCounts() });
    const healthy = &fixture.nodes[3];
    const slow = hub.peer_manager.catalog.find(&fixture.nodes[1].peerId()).?;
    const healthy_peer = hub.peer_manager.catalog.find(&healthy.peerId()).?;
    const conn = hub.peer_manager.catalog.get(slow).?.connection.?;
    const size = rr.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 2 * size);
    defer {
        hub.service.reqresp.shutdown(&hub.transport.engine, &hub.service.router, hub.last_now);
        std.testing.allocator.free(sinks);
    }
    const calls = backing_hub.allocations;
    for (0..2) |index| _ = try hub.sendReqRespRequest(&fixture.nodes[1].peerId(), .blocks_by_root_v2, &([_]u8{1} ** 32), sinks[index * size ..][0..size], .{}, hub.last_now);
    for (0..10) |_| _ = try hub.service.router.beginMeshsub(&hub.transport.engine, conn, hub.last_now);
    try std.testing.expectError(error.NegotiationTableFull, hub.service.router.beginMeshsub(&hub.transport.engine, conn, hub.last_now));
    var status = healthy.localState().status;
    status.head_slot = 42;
    try healthy.updateStatus(&status);
    hub.peer_manager.reStatusPeers(hub.last_now);
    const control = &hub.peer_manager.control;
    const started = control.counters.started;
    for (0..3) |turn| {
        const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
        _ = hub.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
        try std.testing.expectEqual(started + turn + 1, control.counters.started);
    }
    try std.testing.expectEqual(@as(usize, 3), core_test.controlOperations(hub));
    for (0..1000) |_| {
        try MaintenancePeers.step(&.{ hub, healthy });
        const snapshot = hub.peer_manager.catalog.get(healthy_peer).?;
        if (snapshot.status.?.head_slot == 42 and core_test.controlOperations(hub) == 2) break;
    }
    try std.testing.expectEqual(@as(u64, 42), hub.peer_manager.catalog.get(healthy_peer).?.status.?.head_slot);
    try std.testing.expectEqual(@as(usize, 2), core_test.controlOperations(hub));
    try std.testing.expectEqual(@as(u16, 2), hub.service.reqresp.outboundApplicationOccupiedCount(conn));
    try std.testing.expectEqual(calls, backing_hub.allocations);
}

test "core validates capacities and current application fork before allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: NetworkCore = undefined;
    var opts = options(&key);
    opts.resolved.core.peers.capacity = 5;
    opts.resolved.core.peers.max_peers = 5;
    opts.resolved.core.service.reqresp.peers = 5;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidOptions, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
    opts = options(&key);
    opts.resolved.core.service.reqresp.forks = &.{};
    try std.testing.expectError(error.UnknownFork, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
}

test "core loads at most 256 remembered peers and snapshots them" {
    const remembered = @import("peers/remembered.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: NetworkCore = undefined;
    var opts = options(&key);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    var records: [remembered.capacity + 1]remembered.Record = undefined;
    for (&records, 0..) |*record, i| record.* = .{
        .peer = .{ .bytes = @splat(@truncate(i + 2)) },
        .address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = @intCast(9 + i) } },
        .qualified_at_s = remembered.seconds(now) - 60,
    };
    opts.startup.remembered = &records;
    try std.testing.expectError(error.InvalidOptions, node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup));
    opts.startup.remembered = records[0..2];
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var out: [remembered.capacity]remembered.Record = undefined;
    try std.testing.expectError(error.OutputTooSmall, node.rememberedPeers(node.last_now, out[0 .. remembered.capacity - 1]));
    try std.testing.expectEqual(@as(usize, 2), try node.rememberedPeers(node.last_now, &out));
    try std.testing.expectEqual(@as(u64, 2), node.peer_manager.catalog.remembered.counters.seeds[@intFromEnum(remembered.Seed.loaded)]);
}

test "core metrics copy peer processing work without advancing it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: NetworkCore = undefined;
    const opts = options(&key);
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    node.peer_manager.reconcile(node.service.gossipsub, node.last_now);
    const peer_work = node.peer_manager.counters;
    try std.testing.expect(peer_work.catalog_deadline_rows > 0);
    const metrics = @import("metrics/export.zig");
    const context = metrics.Context.init(&node, node.last_now, true);
    const bytes = try std.testing.allocator.alloc(u8, metrics.fixed_text_capacity);
    defer std.testing.allocator.free(bytes);
    var writer = std.Io.Writer.fixed(bytes);
    try metrics.write(&context, &writer);
    try std.testing.expectEqualDeep(peer_work, node.peer_manager.counters);
}

test "core signed bootstrap reaches relevant peer with zero and one outputs" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{12}));
    var opts_b = options(&key_b);
    opts_b.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var b: NetworkCore = undefined;
    var backing_b = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try b.init(backing_b.allocator(), std.testing.io, &opts_b.resolved, opts_b.startup);
    defer b.deinit(std.testing.io);
    var opts_a = options(&key_a);
    opts_a.startup.discovery = opts_b.startup.discovery;
    opts_a.startup.discovery.?.bootstrap = &.{b.localRecord().?.*};
    var a: NetworkCore = undefined;
    var backing_a = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try a.init(backing_a.allocator(), std.testing.io, &opts_a.resolved, opts_a.startup);
    defer a.deinit(std.testing.io);
    var a_inbox: Inbox = .{};
    defer a_inbox.deinit();
    a_inbox.attach(a.service.gossipsub);
    var b_inbox: Inbox = .{};
    defer b_inbox.deinit();
    b_inbox.attach(b.service.gossipsub);
    const calls_a = backing_a.allocations;
    const calls_b = backing_b.allocations;
    var events: [1]t.Event = undefined;
    var ready = false;
    const start = try @import("transport.zig").Transport.currentTime(std.testing.io);
    errdefer std.debug.print("core scenario elapsed={}ms a={any} b={any}\n", .{ a.last_now.mono_ms -| start.mono_ms, a.peerCounts(), b.peerCounts() });
    for (0..3000) |turn| {
        const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        const result_a = a.step(std.testing.io, now, .{ .peers = events[0..@intFromBool(turn > 10)] }, .deadlineOnly(now.mono_ms +| 1));
        if (result_a.failure) |err| return err;
        if (result_a.counts.peers > 0 and events[0] == .ready) ready = true;
        const result_b = b.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
        if (result_b.failure) |err| return err;
        if (ready and a.peerCounts().relevant == 1 and b.peerCounts().relevant == 1) break;
    }
    try std.testing.expect(ready);
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), b.peerCounts().relevant);
    const hint_now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    const accepted = a.peer_manager.catalog.rowFor(a.peer_manager.catalog.find(&b.peerId()).?).?;
    try std.testing.expect(hint_now.mono_ms < accepted.intent.hints_at_ms +| @import("peers/catalog.zig").Catalog.hint_freshness_ms);
    const hints = accepted.intent.hints.?;
    const candidate = try @import("peers/enr.zig").decode(b.localRecord().?, &a.localState().fork);
    try std.testing.expectEqualDeep(candidate.fork, hints.fork);
    try std.testing.expectEqualDeep(candidate.next_fork_digest, hints.next_fork_digest);
    const local = a.localState();
    _ = try updateLocal(&a, &local, .{ .next_version = .{ 1, 1, 1, 1 }, .next_epoch = 123, .next_digest = .{ 1, 2, 3, 4 } }, hint_now);
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    _ = try updateLocal(&a, &local, .{}, hint_now);
    try applicationAndFork(&a, &b, &b_inbox);
    try failureAndReplacement(&a, &b);
    try std.testing.expectEqual(calls_a, backing_a.allocations);
    try std.testing.expectEqual(calls_b, backing_b.allocations);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    a.shutdown(a.last_now);
    a.shutdown(a.last_now);
    b.shutdown(b.last_now);
    // Closing needs only a datagram exchange, so the bound stays far below the QUIC timers (the
    // 5 s handshake limit, the 10 s idle timeout) that would retire a connection whose close was lost.
    var tick = now;
    for (0..100_000) |_| {
        if (a.isClosed() and b.isClosed()) break;
        if (tick.mono_ms -| now.mono_ms >= 1_000) break;
        _ = a.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        _ = b.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
    }
    try std.testing.expect(a.isClosed());
    try std.testing.expect(b.isClosed());
    _ = d;
}

fn applicationAndFork(a: *NetworkCore, b: *NetworkCore, b_inbox: *Inbox) !void {
    var stage: enum { transition, application, gossip } = .transition;
    const begun = try @import("transport.zig").Transport.currentTime(std.testing.io);
    errdefer std.debug.print("core stage={s} elapsed={}ms a={any} b={any}\n", .{ @tagName(stage), a.last_now.mono_ms -| begun.mono_ms, a.peerCounts(), b.peerCounts() });
    const rr = @import("reqresp/root.zig");
    var rows: [4]t.Snapshot = undefined;
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    for ([_]*NetworkCore{ a, b }) |node| {
        var local = node.localState();
        local.fork.fork = .fulu;
        local.fork.digest = .{ 1, 2, 3, 4 };
        local.status.fork_digest = local.fork.digest;
        local.status.earliest_available_slot = 0;
        local.metadata.custody_group_count = local.fork.custody_groups;
        local.metadata.attnets[0] = 0x81;
        _ = try updateLocal(node, &local, .{ .fulu_scheduled = true }, now);
        node.peer_manager.reStatusPeers(now);
    }
    var peer_a: ?t.PeerRef = null;
    var peer_b: ?t.PeerRef = null;
    for (0..2000) |_| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        _ = b.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        for (rows[0..a.peer_manager.snapshots(&rows)]) |row| {
            if (row.relevant and row.status != null and row.status.?.earliest_available_slot != null and row.custody_groups != null) peer_a = row.peer;
        }
        for (rows[0..b.peer_manager.snapshots(&rows)]) |row| {
            if (row.relevant and row.status != null and row.status.?.earliest_available_slot != null and row.custody_groups != null) peer_b = row.peer;
        }
        if (peer_a != null and peer_b != null) break;
    }
    try std.testing.expect(peer_a != null and peer_b != null);
    stage = .application;
    var request: [24]u8 = @splat(0);
    request[8] = 1;
    request[16] = 1;
    const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 4 * sink_size);
    defer std.testing.allocator.free(sinks);
    var handles: [4]rr.ReqResp.RequestHandle = undefined;
    for (&handles, 0..) |*handle, i| {
        const protocol: rr.Protocol = if (i < 2) .blocks_by_range_v2 else .blocks_by_root_v2;
        handle.* = try a.sendReqRespRequest(&b.peerId(), protocol, if (i < 2) &request else &([_]u8{0} ** 32), sinks[i * sink_size ..][0..sink_size], .{ .expected_chunks = 1 }, now);
    }
    try std.testing.expectError(error.TooManyRequests, a.sendReqRespRequest(&b.peerId(), .blocks_by_range_v2, &request, sinks[0..sink_size], .{}, now));
    a.peer_manager.reStatusPeers(now);
    b.peer_manager.reStatusPeers(now);
    for (0..20) |_| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        _ = b.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
    }
    const response = [_]u8{9} ** @import("consensus_types").fulu.SignedBeaconBlock.min_size;
    var app: [1]rr.ReqResp.Event = undefined;
    var peer_events: [1]t.Event = undefined;
    var done: usize = 0;
    var chunks: usize = 0;
    for (0..3000) |_| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        const received = b.step(std.testing.io, tick, .{ .application = &app }, .deadlineOnly(tick.mono_ms +| 1));
        if (received.failure) |err| return err;
        for (app[0..received.counts.application]) |event| switch (event) {
            .request => |value| try b.respond(value.request, &response, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }, tick),
            .chunk_sent => |value| try std.testing.expect(b.finish(value.request, tick)),
            .failed => return error.ApplicationFailed,
            else => {},
        };
        const sent = a.step(std.testing.io, tick, .{ .application = &app, .peers = &peer_events }, .deadlineOnly(tick.mono_ms +| 1));
        if (sent.failure) |err| return err;
        for (app[0..sent.counts.application]) |event| switch (event) {
            .chunk => |value| {
                try std.testing.expectEqual(t.ForkSeq.fulu, value.fork.?);
                try std.testing.expectEqualSlices(u8, &response, value.bytes);
                try std.testing.expect(a.consume(value.request, try @import("transport.zig").Transport.currentTime(std.testing.io)));
                chunks += 1;
            },
            .done => done += 1,
            .failed => return error.ApplicationFailed,
            else => {},
        };
        if (done == 4) break;
    }
    try std.testing.expectEqual(@as(usize, 4), done);
    try std.testing.expectEqual(@as(usize, 4), chunks);
    stage = .gossip;
    try a.addDirectPeer(&b.peerId(), &.{b.transport.localAddress()}, now);
    try b.addDirectPeer(&a.peerId(), &.{a.transport.localAddress()}, now);
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try core_test.subscribe(a, topic);
    try core_test.subscribe(b, topic);
    var got = false;
    var published = false;
    for (0..3000) |turn| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        if (!published and turn > 20 and a.service.gossipsub.resourceSnapshot().remote_subscriptions > 0 and
            a.service.gossipsub.peers.rows[0].direct)
        {
            const sent = try a.publishGossipWithOptions(topic, &response, .{ .allow_zero_peers = false }, tick);
            try std.testing.expectError(error.Duplicate, a.publishGossipWithOptions(topic, &response, .{}, tick));
            try std.testing.expect((try a.publishGossipWithOptions(topic, &response, .{ .ignore_duplicate = true }, tick)).duplicate);
            published = sent.queued > 0;
        }
        b_inbox.clear();
        _ = b.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        for (b_inbox.messages()) |message| {
            try std.testing.expectEqualSlices(u8, &response, message.bytes);
            try std.testing.expect(b.reportValidation(message.handle, .accept, tick) == .applied);
            got = true;
        }
        if (got) break;
        // QUIC retransmission requires elapsed time.
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    if (!published or !got) std.debug.print("gossip published={} received={} subscriptions={} direct={}\n", .{ published, got, a.service.gossipsub.resourceSnapshot().remote_subscriptions, a.service.gossipsub.peers.rows[0].direct });
    try std.testing.expect(published);
    try std.testing.expect(got);
    try core_test.unsubscribe(a, topic);
    try core_test.unsubscribe(b, topic);
    _ = a.removeDirectPeer(&b.peerId());
    _ = b.removeDirectPeer(&a.peerId());
}

test "core every allocation prefix cleans up and reservations count owned storage" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };

    opts.resolved.core.service.reqresp.admission = .{ .policy = @import("reqresp/policy_fixture.zig").config(), .limits = .{
        .identities = opts.resolved.core.peers.capacity,
        .peer = @import("reqresp/admission_fixture.zig").quotas(100, 1000),
        .global = @import("reqresp/admission_fixture.zig").quotas(1000, 1000),
    } };
    var allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var node: NetworkCore = undefined;
    try node.init(allocation.allocator(), std.testing.io, &opts.resolved, opts.startup);
    const allocated = node.reservations.bytes;
    std.debug.print("local intent memory: allocated={} inline={} workspace={} prefixes={}\n", .{ allocated, @sizeOf(NetworkCore), @sizeOf(@import("gossipsub/local_intent.zig").Workspace), allocation.alloc_index });
    try std.testing.expectEqual(allocation.allocated_bytes, allocated);
    const allocations = allocation.alloc_index;
    const runtime_calls = allocation.allocations;
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    for (0..4) |_| _ = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expectEqual(allocation.allocated_bytes, allocated);
    try std.testing.expectEqual(runtime_calls, allocation.allocations);
    node.deinit(std.testing.io);
    node.deinit(std.testing.io);
    try std.testing.expectEqual(allocation.allocated_bytes, allocation.freed_bytes);
    try std.testing.expect(allocations < 128);
    for (0..allocations) |index| {
        var failed = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, node.init(failed.allocator(), std.testing.io, &opts.resolved, opts.startup));
        try std.testing.expectEqual(failed.allocated_bytes, failed.freed_bytes);
    }
}

test "core demand persists until replacement and reaches discovery after selection" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.resolved.core.peers.target_peers = 0;
    opts.resolved.core.peers.min_outbound = 0;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var desired = core_test.intent(&node, &.{});
    desired.demand = .{ .attnets = 1 };
    _ = try node.applyIntent(&desired, node.last_now);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    _ = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expectEqual(@as(u8, 1), node.discovery.?.demand.attnets[0]);
    const view: *const NetworkCore = &node;
    const evaluated = view.peer_manager.coverageDeficits();
    desired.demand = .{ .attnets = 2 };
    _ = try node.applyIntent(&desired, node.last_now);
    try std.testing.expectEqual(node.last_now.mono_ms, node.nextWakeup(node.last_now, .{}).?);
    try std.testing.expectEqualDeep(evaluated, view.peer_manager.coverageDeficits());
    try std.testing.expectEqual(@as(u8, 1), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 1), node.discovery.?.demand.attnets[0]);
    _ = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.demand.attnets[0]);
    _ = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expectEqual(@as(u16, 1), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.demand.attnets[0]);
    desired.demand = .{ .attnets = 4, .attestation_target = 0 };
    try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
    _ = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expectEqual(@as(u16, 1), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.demand.attnets[0]);
    desired.demand = .{};
    _ = try node.applyIntent(&desired, node.last_now);
    _ = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expectEqual(@as(u16, 0), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 0), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 0), node.discovery.?.demand.attnets[0]);
}

test "core fails a dial the host refuses without failing the turn or penalizing the peer" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{25}));
    var node: NetworkCore = undefined;
    const opts = options(&key);
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    const peer = t.PeerId.fromPublicKey(&remote.publicKey());
    try node.connectUntil(&peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } }}, now, now.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
    var faults: FaultIo = .{
        .send = .{ .socket = node.transport.sockets.primary().handle },
        .send_failure = error.AccessDenied,
    };
    const refused = node.step(faults.io(), now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expect(refused.failure == null);
    try std.testing.expectEqual(@as(u8, 1), refused.dial_failed);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_deferred);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_started);
    const row = &node.peer_manager.catalog.rows[0];
    try std.testing.expectEqual(@as(u8, 1), row.intent.failures);
    try std.testing.expect(row.attempt == null);
    try std.testing.expectEqual(@as(f64, 0), row.reputation.score);
    try std.testing.expect(!row.reputation.banned(now.mono_ms));
    const history = &node.peer_manager.catalog.history;
    try std.testing.expect(history.rejection(history.identityKey(&peer), now.mono_ms) == null);
}

test "core socket faults preserve the other owner and local dial refusal is deferred" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const remote_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .coordinator = .{ .query_interval_ms = 100 } };
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    var faults: FaultIo = .{};
    const io = faults.io();
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    for ([_]std.Io.net.Socket{ node.transport.sockets.primary(), node.discovery.?.transport.sockets.primary() }) |socket| {
        // The owner receives only from a socket its poll reported readable.
        try sender.send(std.testing.io, &socket.address, "invalid");
        faults.receive = .{ .socket = socket.handle };
        faults.receive_calls = 0;
        const result = node.step(io, now, .{}, .deadlineOnly(now.mono_ms +| 1000));
        try std.testing.expectEqual(error.Canceled, result.failure.?);
        try std.testing.expect(faults.receive_calls >= 1);
        try std.testing.expect(node.last_now.mono_ms >= now.mono_ms);
        faults.receive = null;
        _ = node.step(io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    }
    faults.receive = null;
    const idle = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expect(idle.failure == null);
    const settled = node.last_now;
    const discovery_due = node.discovery.?.nextWakeup(settled.mono_ms).?;
    try std.testing.expect(discovery_due > settled.mono_ms);
    try std.testing.expectEqual(discovery_due, node.nextWakeup(settled, .{}).?);
    const peer = t.PeerId.fromPublicKey(&remote_key.publicKey());
    try node.connectUntil(&peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } }}, settled, settled.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
    try std.testing.expectEqual(settled.mono_ms, node.nextWakeup(settled, .{}).?);
    faults.clock = .{};
    const refused = node.step(io, settled, .{}, .deadlineOnly(settled.mono_ms));
    try std.testing.expectEqual(@as(u8, 1), refused.dial_deferred);
    try std.testing.expectEqual(error.ClockOutOfRange, refused.failure.?);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_started);
    for (node.peer_manager.catalog.rows) |row| if (row.occupied) {
        try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
        try std.testing.expect(row.attempt == null);
    };
    const calls = backing_node.allocations;
    const clean = node.step(std.testing.io, settled, .{}, .deadlineOnly(settled.mono_ms));
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(calls, backing_node.allocations);
}

test "core discovery drain is nonblocking under the standalone default interval" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{26}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const standalone: d.Transport.Options = .{};
    try std.testing.expectEqual(standalone.poll_interval_ms, node.discovery.?.transport.poll_interval_ms);
    var faults: FaultIo = .{};
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    try sender.send(std.testing.io, &node.discovery.?.transport.sockets.primary().address, "invalid");
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    // The readable datagram keeps the drain going until a receive finds the socket empty.
    const drained = node.step(faults.io(), now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expect(drained.failure == null);
    const rejected = &node.discovery.?.datagram_rejections[@intFromEnum(d.types.RejectReason.malformed_packet)];
    try std.testing.expectEqual(@as(u64, 1), rejected.*);
    const after_datagram = faults.receive_calls;
    try std.testing.expect(after_datagram >= 2);
    const idle = node.step(faults.io(), node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expect(idle.failure == null);
    try std.testing.expectEqual(@as(u64, 1), rejected.*);
    try std.testing.expectEqual(after_datagram, faults.receive_calls);
    try std.testing.expectEqual(@as(i64, 0), faults.longest_wait_ms);
}

fn failureAndReplacement(a: *NetworkCore, b: *NetworkCore) !void {
    var snapshots: [4]t.Snapshot = undefined;
    const count = a.peer_manager.snapshots(&snapshots);
    var target: ?t.PeerRef = null;
    for (snapshots[0..count]) |snapshot| if (snapshot.connection != null) {
        target = snapshot.peer;
    };
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    try std.testing.expectEqual(t.ReputationDecision.ban, a.reportPeer(&a.peer_manager.catalog.get(target.?).?.identity, .fatal, now).?);
    var faults: FaultIo = .{ .receive = .{ .socket = a.transport.sockets.primary().handle } };
    const faulty_io = faults.io();
    const deadline = a.peer_manager.control.schedules[target.?.index].closing.?.deadline_ms;
    var after_deadline = now;
    after_deadline.mono_ms = deadline;
    const result = a.step(faulty_io, after_deadline, .{}, .deadlineOnly(after_deadline.mono_ms));
    try std.testing.expectEqual(error.Canceled, result.failure.?);
    try std.testing.expectEqual(@as(u16, 0), a.peerCounts().relevant);
    try std.testing.expect(a.peer_manager.catalog.get(target.?).?.connection == null);
    for (0..100) |_| {
        _ = a.step(std.testing.io, a.last_now, .{}, .deadlineOnly(a.last_now.mono_ms));
        _ = b.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
        if (a.peerCounts().connected == 0) break;
    }
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.startup.local = a.localState();
    opts.startup.schedule = a.schedule;
    var replacement: NetworkCore = undefined;
    try replacement.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer replacement.deinit(std.testing.io);
    try replacement.connectUntil(&a.peerId(), &.{a.transport.localAddress()}, now, now.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
    for (0..2000) |_| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        const added = replacement.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        if (added.failure) |err| return err;
        var host_tick = tick;
        host_tick.mono_ms = @max(host_tick.mono_ms, a.last_now.mono_ms);
        const accepted = a.step(std.testing.io, host_tick, .{}, .deadlineOnly(host_tick.mono_ms +| 1));
        if (accepted.failure) |err| return err;
        if (a.peerCounts().relevant == 1 and replacement.peerCounts().relevant == 1) break;
    }
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), replacement.peerCounts().relevant);
    try std.testing.expect(replacement.counters.dial_started > 0);
    replacement.shutdown(try @import("transport.zig").Transport.currentTime(std.testing.io));
}

test "core profiles measure reservations and unwind byte exhaustion" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    inline for (.{ @import("configuration.zig").Profile.small, .beacon_node }) |profile| {
        var ledger: @import("reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var request: @import("configuration.zig").Request = .{ .profile = profile, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() };
        const startup: NetworkCore.Startup = .{ .host = &key, .bind = .{ .ip4 = .loopback(0) }, .local = @import("network_core_test_support.zig").localState(.{}) };
        var resolved = try @import("configuration.zig").resolve(request);
        var node: NetworkCore = undefined;
        try node.init(ledger.allocator(), std.testing.io, &resolved, startup);
        var initialized = true;
        defer if (initialized) node.deinit(std.testing.io);
        const measured = ledger.bytes;
        const mib = 1024 * 1024;
        const total: usize = if (profile == .small) 96 * mib else 384 * mib;
        std.debug.print("core memory {s}: total={d} reqresp={d} negotiations={d}\n", .{ @tagName(profile), measured, node.service.reqresp.memoryPlan().total_bytes, node.service.router.negotiator.entries.len });
        try std.testing.expect(measured <= total);
        try std.testing.expectEqual(@as(u64, if (profile == .small) 64 * mib else 512 * mib), node.transport.engine.memoryPlan().receive_window_bytes);
        try std.testing.expect(measured <= node.reservations.byte_limit.?);
        node.deinit(std.testing.io);
        initialized = false;
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
        request.byte_limit = measured - 1;
        resolved = try @import("configuration.zig").resolve(request);
        try std.testing.expectError(error.OutOfMemory, node.init(ledger.allocator(), std.testing.io, &resolved, startup));
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
        request.byte_limit = measured;
        resolved = try @import("configuration.zig").resolve(request);
        try node.init(ledger.allocator(), std.testing.io, &resolved, startup);
        initialized = true;
        node.deinit(std.testing.io);
        initialized = false;
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
    }
}

test "core small profile cleans every failed allocation prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, profileAllocationFailures, .{});
}

fn profileAllocationFailures(a: std.mem.Allocator) !void {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .socket_buffers = @import("network_core_test_support.zig").socket_buffers, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: NetworkCore = undefined;
    try node.init(a, std.testing.io, &resolved, .{ .host = &key, .bind = .{ .ip4 = .loopback(0) }, .local = @import("network_core_test_support.zig").localState(.{}) });
    node.deinit(std.testing.io);
}

test "core native readiness wakes for either delayed protocol socket" {
    if (!NetworkCore.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    for (0..2) |source| {
        for (0..2) |_| {
            const settled = try stepAfter(&node, 0);
            try std.testing.expect(settled.failure == null);
        }
        const target = if (source == 0) node.transport.sockets.primary() else node.discovery.?.transport.sockets.primary();
        const task = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ sender, target.address });
        defer task.join();
        const result = try stepAfter(&node, 100);
        try std.testing.expect(result.failure == null);
        if (source == 0) {
            try std.testing.expectEqual([2]bool{ true, false }, result.readiness.quic);
            try std.testing.expectEqual(@as(u32, 1), result.transport.datagrams_received);
        } else {
            try std.testing.expect(result.readiness.discoveryReady());
            try std.testing.expectEqualSlices(u8, "invalid", node.discovery.?.transport.receive_buffer[0..7]);
        }
    }
}

fn delayedRuntimeDatagram(sender: std.Io.net.Socket, address: std.Io.net.IpAddress) void {
    std.testing.io.sleep(.fromMilliseconds(10), .awake) catch unreachable;
    sender.send(std.testing.io, &address, "invalid") catch unreachable;
}

test "core native host wake validates rollback detaches and preserves bytes" {
    if (!NetworkCore.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const host = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer host.close(std.testing.io);
    try node.setHostWake(host.handle);
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(-1));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.transport.sockets.primary().handle));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.discovery.?.transport.sockets.primary().handle));
    _ = try stepAfter(&node, 0);
    const sender = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ host, host.address });
    defer sender.join();
    const result = try stepAfter(&node, 100);
    try std.testing.expect(result.failure == null and result.readiness.host);
    const repeated = try stepAfter(&node, 0);
    try std.testing.expect(repeated.readiness.host);
    try node.setHostWake(null);
    const detached = try stepAfter(&node, 0);
    try std.testing.expect(!detached.readiness.host);
    try node.setHostWake(host.handle);
    node.shutdown(node.last_now);
    const stopped = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms +| 100));
    try std.testing.expect(!stopped.readiness.host);
    try std.testing.expectError(error.Stopped, node.setHostWake(host.handle));
    var buffer: [8]u8 = undefined;
    const message = try host.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
    try std.testing.expectEqualStrings("invalid", message.data);
}

test "core native wait source failure retains completed protocol progress" {
    const runner = @import("root");
    if (!NetworkCore.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{34}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var pipe: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.pipe(&pipe));
    defer _ = std.c.close(pipe[0]);
    try node.setHostWake(pipe[0]);
    try std.testing.expectEqual(@as(c_int, 0), std.c.close(pipe[1]));
    try node.transport.sockets.primary().send(std.testing.io, &node.transport.sockets.primary().address, "invalid");
    try node.transport.sockets.primary().send(std.testing.io, &node.discovery.?.transport.sockets.primary().address, "invalid");
    const allocations = backing_node.allocations;
    var buffer: [128]u8 = undefined;
    var expected: runner.LogExpectation = .{ .level = .err, .scope = "network_runtime", .message = try std.fmt.bufPrint(&buffer, "owner_poll_source_failed role=host family=none descriptor={d} revents={x}", .{ pipe[0], @as(c_short, std.c.POLL.HUP) }) };
    const previous = runner.expected_log;
    defer runner.expected_log = previous;
    runner.expected_log = &expected;
    const result = try stepAfter(&node, 100);
    try std.testing.expectEqual(error.WaitSourceClosed, result.failure.?);
    try std.testing.expect(expected.matched);
    try std.testing.expect(result.readiness.quicReady() and result.readiness.discoveryReady());
    try std.testing.expectEqual(@as(u32, 1), result.transport.datagrams_received);
    try std.testing.expectEqualSlices(u8, "invalid", node.discovery.?.transport.receive_buffer[0..7]);
    try std.testing.expectEqual(allocations, backing_node.allocations);
    try node.setHostWake(null);
    const clean = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(@as(u64, 1), node.counters.readiness_failures);
}

test "core native wait honors engine timers and pending lifecycle work" {
    if (!NetworkCore.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{35}));
    var opts = options(&key);
    opts.resolved.limits.handshake_timeout_ms = 80;
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const remote = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer remote.close(std.testing.io);
    const destination = @import("udp").Address.fromNetwork(remote.address);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    _ = try node.transport.engine.dial(&destination, node.peerId(), now);
    try std.testing.expect(node.transport.engine.backlog());
    const first = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 100));
    try std.testing.expect(first.failure == null);
    try std.testing.expect(first.transport.datagrams_sent > 0);
    try std.testing.expect(!first.transport.backlog);
    const current = node.last_now;
    const deadline = node.transport.nextDeadlineNs().?;
    const deadline_ms = deadline / std.time.ns_per_ms + @intFromBool(deadline % std.time.ns_per_ms != 0);
    try std.testing.expect(deadline_ms <= now.mono_ms + 80);
    try std.testing.expect(node.nextWakeup(current, .{}).? <= deadline_ms);
    const timer = node.step(std.testing.io, current, .{}, .deadlineOnly(current.mono_ms +| 100));
    try std.testing.expect(timer.failure == null);
    const failed = try node.transport.engine.dial(&destination, node.peerId(), node.last_now);
    try std.testing.expect(node.transport.engine.failSend(failed));
    try std.testing.expect(node.transport.engine.eventsPending());
    const lifecycle = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms +| 100));
    try std.testing.expect(lifecycle.failure == null);
    try std.testing.expect(lifecycle.transport.events > 0);
    const repeated = node.step(std.testing.io, node.last_now, .{}, .deadlineOnly(node.last_now.mono_ms));
    try std.testing.expectEqual(@as(usize, 0), repeated.transport.events);
}

test "core flushes a protocol reply in the turn that wrote it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{36}));
    const spoke_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{37}));
    var opts = options(&key);
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    // A bare QUIC peer: it speaks multistream by hand and runs no protocol of its own.
    var spoke: @import("transport.zig").Transport = .{};
    try spoke.init(std.testing.allocator, std.testing.io, .{ .host = &spoke_key, .bind = .{ .ip4 = .loopback(0) } });
    defer spoke.deinit(std.testing.io);
    const conn = try spoke.dialPeer(std.testing.io, node.transport.localAddress(), node.peerId());
    var events: [32]@import("quic/Engine.zig").Event = undefined;
    var connected = false;
    for (0..400) |_| {
        const stepped = try transport_test.step(&spoke, std.testing.io, &events, .{ .wait_max_ms = 1 });
        for (events[0..stepped.events]) |event| connected = connected or event == .connected;
        _ = try stepAfter(&node, 1);
        if (connected) break;
    }
    try std.testing.expect(connected);
    for (0..20) |_| {
        _ = try transport_test.step(&spoke, std.testing.io, &events, .{ .wait_max_ms = 1 });
        _ = try stepAfter(&node, 1);
    }

    const stream = try spoke.engine.openStream(conn);
    const dialer = try @import("wire/multistream.zig").Dialer.init(@import("reqresp/root.zig").Protocol.ping_v1.id());
    var proposal: [256]u8 = undefined;
    const hello = try dialer.initialWrite(&proposal);
    try std.testing.expectEqual(hello.len, try spoke.engine.write(stream, hello, false));
    const flushed = try transport_test.step(&spoke, std.testing.io, &events, .{ .wait_max_ms = 0 });
    try std.testing.expect(flushed.datagrams_sent > 0);

    const turn = try stepAfter(&node, 100);
    try std.testing.expect(turn.failure == null);
    try std.testing.expect(turn.transport.datagrams_received > 0);
    try std.testing.expect(turn.transport.datagrams_sent > 0);
    try std.testing.expect(!turn.transport.backlog);
    try std.testing.expect(!turn.transport.events_pending);
    try std.testing.expect(node.transport.nextDeadlineNs().? > node.last_now.nanos());

    // The spoke reads the reply without the node taking another turn.
    var reply: [256]u8 = undefined;
    var received: usize = 0;
    for (0..20) |_| {
        _ = try transport_test.step(&spoke, std.testing.io, &events, .{ .wait_max_ms = 10 });
        received += (try spoke.engine.read(stream, reply[received..])).len;
        if (received >= hello.len) break;
    }
    try std.testing.expectEqualSlices(u8, hello, reply[0..hello.len]);
}

test "core beacon idle scans do not manufacture immediate deadlines" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .beacon_node, .seed = 7, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = @import("network_core_test_support.zig").localState(.{}),
        .slot = 100,
    });
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    const calls = backing_node.allocations;
    for (0..8) |_| {
        const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
        try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(@as(?u64, null), node.service.reqresp.nextWakeup(now, .{}));
        try std.testing.expect(node.nextWakeup(now, .{}).? > now.mono_ms);
    }
    try std.testing.expectEqual(calls, backing_node.allocations);
}

test "core idle turns with pending negotiations are never due for reqresp or negotiation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{38}));
    const spoke_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{39}));
    var opts = options(&key);
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    // A bare QUIC peer never answers the node's identify, meshsub and status proposals, so
    // their negotiations stay pending on future deadlines.
    var spoke: @import("transport.zig").Transport = .{};
    try spoke.init(std.testing.allocator, std.testing.io, .{ .host = &spoke_key, .bind = .{ .ip4 = .loopback(0) } });
    defer spoke.deinit(std.testing.io);
    _ = try spoke.dialPeer(std.testing.io, node.transport.localAddress(), node.peerId());
    var events: [32]@import("quic/Engine.zig").Event = undefined;
    for (0..40) |_| {
        _ = try transport_test.step(&spoke, std.testing.io, &events, .{ .wait_max_ms = 1 });
        _ = try stepAfter(&node, 1);
    }
    try std.testing.expect(node.service.router.negotiator.active() > 0);
    const Source = @import("wake_sources.zig").Source;
    const due = node.due_now_turns;
    const visits = .{ node.service.reqresp.visits, node.service.router.negotiator.visits };
    for (0..64) |_| {
        const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
        if (node.service.reqresp.nextWakeup(now, .{ .application = 1, .control = 1 })) |wakeup| try std.testing.expect(wakeup > now.mono_ms);
        try std.testing.expect(node.service.router.nextWakeup(now, 1).? > now.mono_ms);
        try std.testing.expect(node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms)).failure == null);
    }
    try std.testing.expectEqual(due[@intFromEnum(Source.reqresp)], node.due_now_turns[@intFromEnum(Source.reqresp)]);
    try std.testing.expectEqual(due[@intFromEnum(Source.negotiation)], node.due_now_turns[@intFromEnum(Source.negotiation)]);
    try std.testing.expectEqual(visits[0], node.service.reqresp.visits);
    try std.testing.expectEqual(visits[1], node.service.router.negotiator.visits);
    try std.testing.expect(node.service.router.negotiator.active() > 0);
}

test "core BPO duplicate digest validation precedes allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: NetworkCore = undefined;
    var opts = options(&key);
    opts.resolved.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = @splat(0), .fork = .fulu },
    };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidOptions, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
}

test "core targeted Status serves two current schedules and immediate close is local" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    const key_c = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{33}));
    var a: NetworkCore = undefined;
    var b: NetworkCore = undefined;
    var c: NetworkCore = undefined;
    var opts = options(&key_a);
    opts.resolved.core.peers.capacity = 3;
    opts.resolved.core.peers.min_outbound = 0;
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    var backing_a = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try a.init(backing_a.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer a.deinit(std.testing.io);
    opts = options(&key_b);
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    try b.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer b.deinit(std.testing.io);
    opts = options(&key_c);
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    try c.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer c.deinit(std.testing.io);
    const start = try @import("transport.zig").Transport.currentTime(std.testing.io);
    try a.addDirectPeer(&b.peerId(), &.{b.transport.localAddress()}, start);
    try a.addDirectPeer(&c.peerId(), &.{c.transport.localAddress()}, start);
    var rows: [4]t.Snapshot = undefined;
    var ready = false;
    for (0..3000) |_| {
        const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        for ([_]*NetworkCore{ &a, &b, &c }) |node| {
            const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
            if (result.failure) |err| return err;
        }
        const count = a.peer_manager.snapshots(&rows);
        if (count == 2 and a.peerCounts().relevant == 2 and rows[0].identify != null and rows[1].identify != null and
            core_test.controlOperations(&a) == 0)
        {
            ready = true;
            break;
        }
    }
    try std.testing.expect(ready);
    const calls = backing_a.allocations;
    const selected = rows[0];
    const other = rows[1];
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    try std.testing.expect(a.reStatusPeer(&other.identity, now));
    const unselected = a.peer_manager.control.schedules[other.peer.index];
    const before = a.peer_manager.control.schedules[selected.peer.index];
    try std.testing.expect(a.reStatusPeer(&selected.identity, now));
    var expected = before;
    expected.status_due_ms = now.mono_ms;
    try std.testing.expectEqualDeep(expected, a.peer_manager.control.schedules[selected.peer.index]);
    try std.testing.expectEqualDeep(unselected, a.peer_manager.control.schedules[other.peer.index]);
    const result = a.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    if (result.failure) |err| return err;
    var status_started: usize = 0;
    for (a.control_protocol.operations) |op| if (op.request != null and op.protocol == .status_v1) {
        status_started += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), status_started);
    try std.testing.expectEqual(before.identify_state, a.peer_manager.control.schedules[selected.peer.index].identify_state);
    try std.testing.expect(a.closePeer(&selected.identity, now));
    try std.testing.expect(!a.reStatusPeer(&selected.identity, now));
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().connected);
    var direct: [2]t.PeerId = undefined;
    const owner: *const NetworkCore = &a;
    try std.testing.expectEqual(@as(usize, 2), try owner.directPeers(&direct));
    try std.testing.expect(a.removeDirectPeer(&selected.identity));
    try std.testing.expect(!a.removeDirectPeer(&selected.identity));
    try std.testing.expectEqual(@as(usize, 1), try owner.directPeers(&direct));
    try std.testing.expectEqual(calls, backing_a.allocations);
    try recycledPeerOperations(&a, &b, &c, &selected);
}

fn recycledPeerOperations(a: *NetworkCore, b: *NetworkCore, c: *NetworkCore, previous: *const t.Snapshot) !void {
    // Fill the spare established slot before requiring the disconnected generation to be reclaimed.
    for (0..2) |attempt| {
        const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{@as(u8, @intCast(34 + attempt))}));
        var replacement: NetworkCore = undefined;
        const opts = options(&key);
        try replacement.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
        defer replacement.deinit(std.testing.io);
        var events: [4]t.Event = undefined;
        _ = a.peer_manager.catalog.pollEvents(&events);
        const start = try @import("transport.zig").Transport.currentTime(std.testing.io);
        try a.addDirectPeer(&replacement.peerId(), &.{replacement.transport.localAddress()}, start);
        var current: ?t.Snapshot = null;
        for (0..3000) |_| {
            const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
            if (now.mono_ms - start.mono_ms > 10_000) break;
            for ([_]*NetworkCore{ a, b, c, &replacement }) |node| {
                const result = node.step(std.testing.io, now, .{ .peers = &events }, .deadlineOnly(now.mono_ms +| 1));
                if (result.failure) |err| return err;
            }
            const ref = a.peer_manager.catalog.find(&replacement.peerId()) orelse continue;
            const row = a.peer_manager.catalog.get(ref) orelse continue;
            if (!row.relevant) continue;
            current = row;
            break;
        }
        const selected = current orelse return error.ReplacementNotReady;
        try std.testing.expect(!std.meta.eql(previous.peer, selected.peer));
        if (attempt == 0) {
            try std.testing.expect(a.peer_manager.catalog.get(previous.peer).?.connection == null);
        } else {
            try std.testing.expect(a.peer_manager.catalog.get(previous.peer) == null);
        }
        try std.testing.expect(!a.closePeer(&previous.identity, a.last_now));
        try std.testing.expect(!a.reStatusPeer(&previous.identity, a.last_now));
        try std.testing.expectEqualDeep(selected, a.peer_manager.catalog.get(selected.peer).?);
        try std.testing.expect(a.closePeer(&selected.identity, a.last_now));
        try std.testing.expect(a.removeDirectPeer(&selected.identity));
    }
}

test "application transport borrow authenticates while remote Status remains unavailable" {
    const capability = @import("capabilities.zig");
    const rr = @import("reqresp/root.zig");
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{51}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{52}));
    var opts_b = options(&key_b);
    var active: capability.Set = .initEmpty();
    for (0..rr.Protocol.count) |i| {
        const protocol: rr.Protocol = @enumFromInt(i);
        if (protocol == .status_v1 or protocol == .status_v2) continue;
        active.insert(.{ .reqresp = protocol });
    }
    opts_b.resolved.core.service.router.capabilities = .{ .receive = active, .request = active };
    var a: NetworkCore = undefined;
    const opts_a = options(&key_a);
    try a.init(std.testing.allocator, std.testing.io, &opts_a.resolved, opts_a.startup);
    defer a.deinit(std.testing.io);
    var b: NetworkCore = undefined;
    try b.init(std.testing.allocator, std.testing.io, &opts_b.resolved, opts_b.startup);
    defer b.deinit(std.testing.io);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    try a.connectUntil(&b.peerId(), &.{b.transport.localAddress()}, now, now.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
    var authenticated = false;
    for (0..300) |_| {
        const tick = try @import("transport.zig").Transport.currentTime(std.testing.io);
        const result = a.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
        if (result.failure) |err| return err;
        for (a.transportEvents()) |event| if (event == .connected) {
            try std.testing.expect(event.connected.peer_id.eql(&b.peerId()));
            authenticated = true;
        };
        _ = b.step(std.testing.io, tick, .{}, .deadlineOnly(tick.mono_ms +| 1));
    }
    try std.testing.expect(authenticated);
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().connected);
    try std.testing.expectEqual(@as(u16, 0), a.peerCounts().relevant);
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), try a.completeSnapshots(&snapshots));
    try std.testing.expect(snapshots[0].connection != null);
    try std.testing.expect(snapshots[0].status == null);
    try std.testing.expectError(error.OutputTooSmall, a.completeSnapshots(snapshots[0..1]));
}

test "application complete snapshot includes all 512 occupied disconnected rows" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.resolved.core.peers.capacity = 512;
    opts.resolved.core.service.gossipsub.retained_capacity = 512;
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const local = node.peerId();
    var events: [2]t.Event = undefined;
    for (0..512) |i| {
        var secret: [32]u8 = @splat(0);
        std.mem.writeInt(u32, secret[28..32], @intCast(i + 2), .big);
        const remote_key = try keys.KeyPair.fromSecretKey(&secret);
        const remote = @import("wire/peer_id.zig").PeerId.fromPublicKey(&remote_key.publicKey());
        const handle: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        const peer = node.peer_manager.catalog.admit(&remote, &local, handle, &.{ .direction = .outbound, .endpoint = .unspecified, .now_ms = 0 }).admitted.peer;
        try std.testing.expectEqual(@as(u16, @intCast(i)), peer.index);
        _ = node.peer_manager.catalog.report(peer, .fatal, 0);
        try std.testing.expect(node.peer_manager.catalog.disconnect(peer, handle, .host, 0));
        _ = node.peer_manager.catalog.pollEvents(&events);
    }
    const snapshots = try std.testing.allocator.alloc(t.Snapshot, 512);
    defer std.testing.allocator.free(snapshots);
    try std.testing.expectEqual(@as(usize, 512), try node.completeSnapshots(snapshots));
    try std.testing.expectEqual(@as(u16, 0), node.peerCounts().connected);
    for (snapshots, 0..) |row, i| {
        try std.testing.expectEqual(@as(u16, @intCast(i)), row.peer.index);
        try std.testing.expect(row.connection == null and row.ban_until_ms > 0);
    }
    try std.testing.expectError(error.OutputTooSmall, node.completeSnapshots(snapshots[0..511]));
}

test "dual-stack runtime signs both bound discovery and QUIC endpoints" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{25}));
    var opts = options(&key);
    opts.startup.bind = .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } };
    opts.startup.discovery = .{ .bind = opts.startup.bind };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const record = node.localRecord().?;
    const quic = node.transport.sockets.localAddresses();
    const decoded = try @import("peers/enr.zig").decode(record, &opts.startup.local.fork);
    try std.testing.expectEqual(@as(u8, 2), decoded.address_count);
    try std.testing.expectEqualDeep(quic[0].?, decoded.addresses[0]);
    try std.testing.expectEqualDeep(quic[1].?, decoded.addresses[1]);
    try std.testing.expectEqual(node.discovery.?.transport.sockets.values[0].?.address.getPort(), record.udp.?);
    try std.testing.expectEqual(node.discovery.?.transport.sockets.values[1].?.address.getPort(), record.udp6.?);
    try std.testing.expectEqualSlices(u8, &quic[0].?.ip4.octets, &record.ip4.?);
    try std.testing.expectEqualSlices(u8, &quic[1].?.ip6.octets, &record.ip6.?);
}

test "core candidate identities do not expose admitted APIs or enlarge snapshot capacity" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    var node: NetworkCore = undefined;
    const opts = options(&key);
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const peer = t.PeerId.fromPublicKey(&remote.publicKey());
    const now = node.last_now;
    try node.addDirectPeer(&peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9001 } }}, now);
    try std.testing.expect(node.peer_manager.catalog.find(&peer) != null);
    try std.testing.expect(!node.isConnected(&peer));
    try std.testing.expect(!node.closePeer(&peer, now));
    try std.testing.expect(!node.reStatusPeer(&peer, now));
    try std.testing.expect(node.reportPeer(&peer, .fatal, now) == null);
    try std.testing.expectError(error.StalePeer, node.sendReqRespRequest(&peer, .ping_v1, &.{}, &.{}, .{}, now));
    var snapshots: [4]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 0), try node.completeSnapshots(&snapshots));
}

test "core discovery config bounds session capacity and idle lifetime" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{41}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const config = node.discovery.?.transport.engine.config;
    try std.testing.expectEqual(@import("peers/discovery.zig").Discovery.discovery_session_capacity, config.session_capacity);
    try std.testing.expectEqual(@import("peers/discovery.zig").Discovery.discovery_session_idle_timeout_ms, config.session_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 2_048), config.session_capacity);
    try std.testing.expectEqual(@as(u64, 600_000), config.session_idle_timeout_ms);
}

test "core cancellation releases every selected dial without blaming unstarted peers" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{121}));
    var node: NetworkCore = undefined;
    var opts = options(&key);
    opts.resolved.core.dial.concurrent_max = 3;
    opts.resolved.limits.dialing_max = 3;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").Transport.currentTime(std.testing.io);
    var peers: [3]t.PeerId = undefined;
    for (&peers, 122..) |*peer, seed| {
        const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{@as(u8, @intCast(seed))}));
        peer.* = t.PeerId.fromPublicKey(&remote.publicKey());
        try node.connectUntil(peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } }}, now, now.mono_ms + 30_000);
    }
    var faults: FaultIo = .{ .send = .{}, .send_failure = error.Canceled };
    const stopped = node.step(faults.io(), now, .{}, .deadlineOnly(now.mono_ms));
    try std.testing.expectEqual(error.Canceled, stopped.failure.?);
    try std.testing.expectEqual(@as(u8, 3), stopped.dial_deferred);
    try std.testing.expectEqual(@as(u8, 0), stopped.dial_started);
    try std.testing.expectEqual(@as(u8, 0), stopped.dial_failed);
    try std.testing.expectEqual(@as(usize, 1), faults.send_calls);
    try std.testing.expectEqual(@as(u16, 0), node.peer_manager.dialing.held.total);
    try std.testing.expectEqual(@as(u16, 0), node.peer_manager.dialing.held.unstarted);
    try std.testing.expectEqual(@as(u16, 0), node.transport.engine.registry.active_len);
    node.peer_manager.expireDials(&node.transport.engine, .{ .mono_ms = now.mono_ms + 10_001, .unix_s = now.unix_s });
    for (peers) |peer| {
        const row = node.peer_manager.catalog.rowFor(node.peer_manager.catalog.find(&peer).?).?;
        try std.testing.expect(row.attempt == null);
        try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
        try std.testing.expectEqual(@as(u8, 0), row.intent.address_index);
        try std.testing.expectEqual(@as(f64, 0), row.reputation.score);
    }
    try std.testing.expectEqual(@as(u64, 0), node.peer_manager.dialing.outcomes[@intFromEnum(t.DialOutcome.expired)]);
}

test "core unreachable destination backs off and rotates to its alternate address" {
    const setup = try std.testing.allocator.create(core_test.Setup);
    defer std.testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.initOwners(&.{});
    defer setup.deinit();
    const node = &setup.client;
    const now = setup.pair.now;
    const peer = setup.server.peerId();
    try node.connectUntil(&peer, &.{
        .{ .ip6 = .{ .octets = .{0} ** 15 ++ .{1}, .port = 19003 } },
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } },
    }, now, now.mono_ms +| @import("peers/dialing.zig").Dialing.connect_timeout_ms);
    const refused = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u8, 1), refused.dial_failed);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_deferred);
    const row = &node.peer_manager.catalog.rows[0];
    try std.testing.expectEqual(@as(u8, 1), row.intent.failures);
    try std.testing.expectEqual(@as(u8, 1), row.intent.address_index);
    try std.testing.expect(row.attempt == null);
    try std.testing.expect(row.intent.eligible_at_ms >= now.mono_ms + 1000);
    setup.pair.advance(row.intent.eligible_at_ms - now.mono_ms - 1);
    const early = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u8, 0), early.dial_started);
    try std.testing.expect(row.attempt == null);
    setup.pair.advance(1);
    const result = try setup.turn(node, .{});
    try std.testing.expectEqual(@as(u8, 1), result.dial_started);
    try std.testing.expect(node.peer_manager.dialing.active[row.attempt.?].connection != null);
}
