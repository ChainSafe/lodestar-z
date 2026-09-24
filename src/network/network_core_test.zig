const core_test = @import("test_support.zig");
const FaultIo = @import("udp").testing.FaultIo;
const std = @import("std");
const runtime = @import("network_core.zig");
const t = @import("peers/types.zig");
const keys = @import("wire/keys.zig");
const d = @import("discv5");

const options = @import("test_support.zig").networkOptions;
const Inbox = @import("gossipsub/test_support.zig").Inbox;
const Now = @import("types.zig").Now;

/// Applies a local update through the host intent path with the current subscriptions and demand.
fn applyLocal(node: *runtime.NetworkCore, update: *const runtime.LocalUpdate, now: Now) !bool {
    var boundaries: [@import("gossipsub/topic_policy.zig").boundary_max]@import("gossipsub/local_intent.zig").Boundary = undefined;
    var desired = core_test.intent(node, try @import("gossipsub/test_support.zig").subscriptionUpdate(node.service.gossipsub, null, false, &boundaries));
    desired.update = update.*;
    return node.applyIntent(&desired, now);
}

fn updateLocalWithEndpoints(node: *runtime.NetworkCore, local: *const t.LocalState, schedule: runtime.ForkSchedule, endpoints: ?runtime.AdvertisementEndpoints, now: Now) !bool {
    return applyLocal(node, &.{ .local = local.*, .schedule = schedule, .endpoints = endpoints, .capabilities = node.service.router.capabilities() }, now);
}

fn updateLocal(node: *runtime.NetworkCore, local: *const t.LocalState, schedule: runtime.ForkSchedule, now: Now) !bool {
    return updateLocalWithEndpoints(node, local, schedule, node.advertisementEndpoints(), now);
}

const MaintenancePeers = struct {
    nodes: []runtime.NetworkCore,

    fn init() !MaintenancePeers {
        const nodes = try std.testing.allocator.alloc(runtime.NetworkCore, 4);
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
            try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
            initialized += 1;
        }
        const hub = &nodes[0];
        errdefer |err| std.debug.print("maintenance bootstrap failed: {t}, peers={any}, operations={any}, requests={any}\n", .{ err, hub.peerCounts(), hub.peer_manager.control.resourceSnapshot(), hub.service.reqresp.active() });
        for (nodes[1..]) |*remote| try hub.connectUntil(&remote.peerId(), &.{remote.transport.localAddress()}, hub.last_now, hub.last_now.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
        for (0..3000) |_| {
            try step(&.{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] });
            if (hub.peerCounts().relevant != 3 or hub.peer_manager.control.resourceSnapshot().operations != 0) continue;
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

    fn step(nodes: []const *runtime.NetworkCore) !void {
        for (nodes) |node| {
            const now = try @import("transport.zig").currentTime(std.testing.io);
            const result = node.step(std.testing.io, now, 100, .{}, 1);
            if (result.failure) |err| return err;
        }
    }
};

test "managed runtime rejects incomplete serving state before startup allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var node: runtime.NetworkCore = undefined;
    opts.startup.local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.local.status.earliest_available_slot = null;
    try std.testing.expectError(error.MissingAvailability, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

test "managed maintenance isolates slow peers and full application capacity" {
    const rr = @import("reqresp/root.zig");
    var fixture = try MaintenancePeers.init();
    defer fixture.deinit();
    const hub = &fixture.nodes[0];
    errdefer |err| std.debug.print("maintenance isolation failed: {t}, peers={any}, operations={any}, requests={any}\n", .{ err, hub.peerCounts(), hub.peer_manager.control.resourceSnapshot(), hub.service.reqresp.active() });
    const healthy = &fixture.nodes[3];
    const slow = hub.peer_manager.catalog.find(&fixture.nodes[1].peerId()).?;
    const healthy_peer = hub.peer_manager.catalog.find(&healthy.peerId()).?;
    const conn = hub.peer_manager.catalog.get(slow).?.connection.?;
    const size = rr.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 2 * size);
    defer {
        hub.service.reqresp.shutdown(&hub.transport.engine, &hub.service.router);
        std.testing.allocator.free(sinks);
    }
    const calls = hub.reservations.allocation_calls;
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
        control.maintain(&hub.service, &hub.peer_manager.catalog, &hub.transport.engine, &hub.peer_manager.local, hub.last_now);
        try std.testing.expectEqual(started + turn + 1, control.counters.started);
    }
    try std.testing.expectEqual(@as(usize, 3), control.resourceSnapshot().operations);
    for (0..1000) |_| {
        try MaintenancePeers.step(&.{ hub, healthy });
        const snapshot = hub.peer_manager.catalog.get(healthy_peer).?;
        if (snapshot.status.?.head_slot == 42 and control.resourceSnapshot().operations == 2) break;
    }
    try std.testing.expectEqual(@as(u64, 42), hub.peer_manager.catalog.get(healthy_peer).?.status.?.head_slot);
    try std.testing.expectEqual(@as(usize, 2), control.resourceSnapshot().operations);
    try std.testing.expectEqual(@as(u16, 2), hub.service.reqresp.outboundApplicationCount(conn));
    try std.testing.expectEqual(calls, hub.reservations.allocation_calls);
}

test "managed runtime validates capacities and current application fork before allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
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

test "managed runtime metrics copy peer processing work without advancing it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    const opts = options(&key);
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    node.peer_manager.reconcile(&node.service, node.last_now);
    const peer_work = node.peer_manager.counters;
    const dial_work = node.peer_manager.dialing.counters;
    try std.testing.expect(peer_work.catalog_deadline_rows > 0);
    const metrics = @import("metrics/export.zig");
    const context = metrics.Context.init(&node, node.last_now, true);
    const bytes = try std.testing.allocator.alloc(u8, metrics.fixed_text_capacity);
    defer std.testing.allocator.free(bytes);
    var writer = std.Io.Writer.fixed(bytes);
    try metrics.write(&context, &writer);
    try std.testing.expectEqualDeep(peer_work, node.peer_manager.counters);
    try std.testing.expectEqualDeep(dial_work, node.peer_manager.dialing.counters);
}

test "managed runtime local transaction sequences no-op schedule and rollback" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const initial = node.localRecord().?.*;
    try @import("peers/enr.zig").requireIdentity(&initial, &node.peerId());
    var local = node.localState();
    try std.testing.expect(!try updateLocal(&node, &local, .{}, now));
    try std.testing.expectEqual(initial.sequence, node.localRecord().?.sequence);
    local.metadata.attnets[0] = 0x81;
    try std.testing.expect(try updateLocal(&node, &local, .{}, now));
    try std.testing.expectEqual(@as(u64, 1), node.localState().metadata.seq_number);
    try std.testing.expectEqual(initial.sequence + 1, node.localRecord().?.sequence);
    local = node.localState();
    local.status.head_slot = 42;
    try std.testing.expect(try updateLocal(&node, &local, .{}, now));
    try std.testing.expectEqual(@as(u64, 1), node.localState().metadata.seq_number);
    try std.testing.expectEqual(initial.sequence + 1, node.localRecord().?.sequence);
    const before = node.localRecord().?.*;
    const scheduled: runtime.ForkSchedule = .{ .fulu_scheduled = true };
    local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, updateLocal(&node, &local, scheduled, now));
    try std.testing.expectEqualSlices(u8, before.slice(), node.localRecord().?.slice());
    local.metadata.custody_group_count = 1;
    try std.testing.expect(try updateLocal(&node, &local, scheduled, now));
    const candidate = try @import("peers/enr.zig").decode(node.localRecord().?, &local.fork);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, candidate.next_fork_digest.?);
    try std.testing.expectEqual(@as(u64, 1), candidate.custody_group_count.?);
    const invalid: runtime.ForkSchedule = .{ .fulu_scheduled = true, .next_digest = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.InvalidSchedule, updateLocal(&node, &local, invalid, now));
}

test "managed runtime signed bootstrap reaches relevant peer with zero and one outputs" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{12}));
    var opts_b = options(&key_b);
    opts_b.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var b: runtime.NetworkCore = undefined;
    try b.init(std.testing.allocator, std.testing.io, &opts_b.resolved, opts_b.startup);
    defer b.deinit(std.testing.io);
    var opts_a = options(&key_a);
    opts_a.startup.discovery = opts_b.startup.discovery;
    opts_a.startup.discovery.?.bootstrap = &.{b.localRecord().?.*};
    var a: runtime.NetworkCore = undefined;
    try a.init(std.testing.allocator, std.testing.io, &opts_a.resolved, opts_a.startup);
    defer a.deinit(std.testing.io);
    var a_inbox: Inbox = .{};
    defer a_inbox.deinit();
    a_inbox.attach(a.service.gossipsub);
    var b_inbox: Inbox = .{};
    defer b_inbox.deinit();
    b_inbox.attach(b.service.gossipsub);
    const calls_a = a.reservations.allocation_calls;
    const calls_b = b.reservations.allocation_calls;
    var events: [1]t.Event = undefined;
    var ready = false;
    const start = try @import("transport.zig").currentTime(std.testing.io);
    errdefer std.debug.print("managed scenario elapsed={}ms a={any} b={any}\n", .{ a.last_now.mono_ms -| start.mono_ms, a.peerCounts(), b.peerCounts() });
    for (0..3000) |turn| {
        const now = try @import("transport.zig").currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        const result_a = a.step(std.testing.io, now, 100, .{ .peers = events[0..@intFromBool(turn > 10)] }, 1);
        if (result_a.failure) |err| return err;
        if (result_a.counts.peers > 0 and events[0] == .ready) ready = true;
        const result_b = b.step(std.testing.io, now, 100, .{}, 1);
        if (result_b.failure) |err| return err;
        if (ready and a.peerCounts().relevant == 1 and b.peerCounts().relevant == 1) break;
    }
    try std.testing.expect(ready);
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), b.peerCounts().relevant);
    try std.testing.expect(a.counters.discovered > 0);
    try std.testing.expect(a.counters.future_fork_unknown > 0);
    try std.testing.expectEqual(@as(u64, 0), a.counters.future_fork_mismatches);
    const hint_now = try @import("transport.zig").currentTime(std.testing.io);
    const hints = a.peer_manager.candidateHints(&b.peerId(), hint_now).?;
    const candidate = try @import("peers/enr.zig").decode(b.localRecord().?, &a.localState().fork);
    try std.testing.expectEqualDeep(candidate.fork, hints.fork);
    try std.testing.expectEqualDeep(candidate.next_fork_digest, hints.next_fork_digest);
    try std.testing.expectEqual(@as(?bool, null), runtime.futureCompatible(&candidate, a.schedule));
    const local = a.localState();
    _ = try updateLocal(&a, &local, .{ .next_version = .{ 1, 1, 1, 1 }, .next_epoch = 123, .next_digest = .{ 1, 2, 3, 4 } }, hint_now);
    try std.testing.expectEqual(@as(?bool, false), runtime.futureCompatible(&candidate, a.schedule));
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    _ = try updateLocal(&a, &local, .{}, hint_now);
    try applicationAndFork(&a, &b, &b_inbox);
    try failureAndReplacement(&a, &b);
    try std.testing.expectEqual(calls_a, a.reservations.allocation_calls);
    try std.testing.expectEqual(calls_b, b.reservations.allocation_calls);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    a.shutdown(now);
    a.shutdown(now);
    b.shutdown(now);
    for (0..100) |_| {
        _ = a.step(std.testing.io, a.last_now, 100, .{}, 0);
        _ = b.step(std.testing.io, now, 100, .{}, 0);
        if (a.isClosed() and b.isClosed()) break;
    }
    try std.testing.expect(a.isClosed());
    try std.testing.expect(b.isClosed());
    _ = d;
}

fn applicationAndFork(a: *runtime.NetworkCore, b: *runtime.NetworkCore, b_inbox: *Inbox) !void {
    var stage: enum { transition, application, gossip } = .transition;
    const begun = try @import("transport.zig").currentTime(std.testing.io);
    errdefer std.debug.print("managed stage={s} elapsed={}ms a={any} b={any}\n", .{ @tagName(stage), a.last_now.mono_ms -| begun.mono_ms, a.peerCounts(), b.peerCounts() });
    const rr = @import("reqresp/root.zig");
    var rows: [4]t.Snapshot = undefined;
    const now = try @import("transport.zig").currentTime(std.testing.io);
    for ([_]*runtime.NetworkCore{ a, b }) |node| {
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
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{}, 1);
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
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
    var handles: [4]rr.RequestHandle = undefined;
    for (&handles, 0..) |*handle, i| {
        const protocol: rr.Protocol = if (i < 2) .blocks_by_range_v2 else .blocks_by_root_v2;
        handle.* = try a.sendReqRespRequest(&b.peerId(), protocol, if (i < 2) &request else &([_]u8{0} ** 32), sinks[i * sink_size ..][0..sink_size], .{ .expected_chunks = 1 }, now);
    }
    try std.testing.expectError(error.TooManyRequests, a.sendReqRespRequest(&b.peerId(), .blocks_by_range_v2, &request, sinks[0..sink_size], .{}, now));
    a.peer_manager.reStatusPeers(now);
    b.peer_manager.reStatusPeers(now);
    for (0..20) |_| {
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{}, 1);
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
    }
    const response = [_]u8{9} ** @import("consensus_types").fulu.SignedBeaconBlock.min_size;
    var app: [1]rr.Event = undefined;
    var peer_events: [1]t.Event = undefined;
    var done: usize = 0;
    var chunks: usize = 0;
    for (0..3000) |_| {
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        const received = b.step(std.testing.io, tick, 100, .{ .application = &app }, 1);
        if (received.failure) |err| return err;
        for (app[0..received.counts.application]) |event| switch (event) {
            .request => |value| try b.respond(value.request, &response, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }, tick),
            .chunk_sent => |value| try std.testing.expect(b.finish(value.request, tick)),
            .failed => return error.ApplicationFailed,
            else => {},
        };
        const sent = a.step(std.testing.io, tick, 100, .{ .application = &app, .peers = &peer_events }, 1);
        if (sent.failure) |err| return err;
        for (app[0..sent.counts.application]) |event| switch (event) {
            .chunk => |value| {
                try std.testing.expectEqual(t.ForkSeq.fulu, value.fork.?);
                try std.testing.expectEqualSlices(u8, &response, value.bytes);
                try std.testing.expect(a.consume(value.request, try @import("transport.zig").currentTime(std.testing.io)));
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
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{}, 1);
        if (!published and turn > 20 and a.service.gossipsub.resourceSnapshot().remote_subscriptions > 0 and
            a.service.gossipsub.peers.rows[0].direct)
        {
            const sent = try a.publishGossipWithOptions(topic, &response, .{ .allow_zero_peers = false }, tick);
            try std.testing.expectError(error.Duplicate, a.publishGossipWithOptions(topic, &response, .{}, tick));
            try std.testing.expect((try a.publishGossipWithOptions(topic, &response, .{ .ignore_duplicate = true }, tick)).duplicate);
            published = sent.queued > 0;
        }
        b_inbox.clear();
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
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

test "managed runtime every allocation prefix cleans up and reservations count owned storage" {
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
    var node: runtime.NetworkCore = undefined;
    try node.init(allocation.allocator(), std.testing.io, &opts.resolved, opts.startup);
    const allocated = node.reservations.bytes;
    std.debug.print("local intent memory: allocated={} inline={} workspace={} prefixes={}\n", .{ allocated, @sizeOf(runtime.NetworkCore), @sizeOf(@import("gossipsub/local_intent.zig").Workspace), allocation.alloc_index });
    try std.testing.expectEqual(allocation.allocated_bytes, allocated);
    const allocations = allocation.alloc_index;
    const runtime_calls = node.reservations.allocation_calls;
    const now = try @import("transport.zig").currentTime(std.testing.io);
    for (0..4) |_| _ = node.step(std.testing.io, now, 0, .{}, 0);
    try std.testing.expectEqual(allocation.allocated_bytes, allocated);
    try std.testing.expectEqual(runtime_calls, node.reservations.allocation_calls);
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

test "managed runtime reservation forwarding tracks resize remap and failure without ownership" {
    const Reservations = @import("reservations.zig").Reservations;
    var buffer: [4096]u8 = undefined;
    var backing = std.heap.FixedBufferAllocator.init(&buffer);
    var reservation: Reservations = .{ .backing = backing.allocator() };
    const allocator = reservation.allocator();
    var bytes = try allocator.alignedAlloc(u8, .@"16", 32);
    try std.testing.expectEqual(@as(usize, 32), reservation.bytes);
    try std.testing.expect(allocator.resize(bytes, 64));
    bytes = bytes.ptr[0..64];
    try std.testing.expectEqual(@as(usize, 64), reservation.bytes);
    bytes = allocator.remap(bytes, 128).?;
    try std.testing.expectEqual(@as(usize, 128), reservation.bytes);
    try std.testing.expect(!allocator.resize(bytes, 8192));
    try std.testing.expect(allocator.remap(bytes, 8192) == null);
    try std.testing.expectEqual(@as(usize, 128), reservation.bytes);
    allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), reservation.bytes);
}

test "managed runtime sequence exhaustion rolls back and future fork hints stay advisory" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    var opts = options(&key);
    opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const before = node.localState();
    const record = node.localRecord().?.*;
    var desired = before;
    desired.metadata.attnets[0] = 1;
    try std.testing.expectError(error.SequenceExhausted, updateLocal(&node, &desired, .{}, now));
    try std.testing.expectEqualDeep(before, node.localState());
    try std.testing.expectEqual(before.fork.fork, node.service.reqresp.request_fork);
    var schedule: runtime.ForkSchedule = .{ .next_epoch = 100, .next_version = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.SequenceExhausted, updateLocal(&node, &before, schedule, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
    var candidate = try @import("peers/enr.zig").decode(&record, &before.fork);
    try std.testing.expectEqual(@as(?bool, false), runtime.futureCompatible(&candidate, schedule));
    candidate.fork.next_epoch = schedule.next_epoch;
    candidate.fork.next_version = schedule.next_version;
    try std.testing.expectEqual(@as(?bool, null), runtime.futureCompatible(&candidate, schedule));
    candidate.next_fork_digest = schedule.next_digest;
    try std.testing.expectEqual(@as(?bool, true), runtime.futureCompatible(&candidate, schedule));
    schedule.next_digest = .{ 4, 3, 2, 1 };
    candidate.next_fork_digest = .{ 1, 2, 3, 4 };
    try std.testing.expectEqual(@as(?bool, false), runtime.futureCompatible(&candidate, schedule));
    desired = before;
    desired.status.head_slot = 2;
    try std.testing.expect(try updateLocal(&node, &desired, .{}, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
}

test "managed runtime demand persists until replacement and reaches discovery after selection" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.resolved.core.peers.target_peers = 0;
    opts.resolved.core.peers.min_outbound = 0;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var desired = core_test.intent(&node, &.{});
    desired.demand = .{ .attnets = 1 };
    _ = try node.applyIntent(&desired, node.last_now);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    _ = node.step(std.testing.io, now, 4, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), node.discovery.?.coordinator.demand.attnets[0]);
    const view: *const runtime.NetworkCore = &node;
    const evaluated = view.peer_manager.coverageDeficits();
    desired.demand = .{ .attnets = 2 };
    _ = try node.applyIntent(&desired, node.last_now);
    try std.testing.expectEqual(node.last_now.mono_ms, node.nextWakeup(node.last_now, .{}).?);
    try std.testing.expectEqualDeep(evaluated, view.peer_manager.coverageDeficits());
    try std.testing.expectEqual(@as(u8, 1), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 1), node.discovery.?.coordinator.demand.attnets[0]);
    _ = node.step(std.testing.io, node.last_now, 4, .{}, 0);
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.coordinator.demand.attnets[0]);
    _ = node.step(std.testing.io, node.last_now, 10_000, .{}, 0);
    try std.testing.expectEqual(@as(u16, 1), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.coordinator.demand.attnets[0]);
    desired.demand = .{ .attnets = 4, .attestation_target = 0 };
    try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
    _ = node.step(std.testing.io, node.last_now, 10_001, .{}, 0);
    try std.testing.expectEqual(@as(u16, 1), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 2), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 2), node.discovery.?.coordinator.demand.attnets[0]);
    desired.demand = .{};
    _ = try node.applyIntent(&desired, node.last_now);
    _ = node.step(std.testing.io, node.last_now, 10_001, .{}, 0);
    try std.testing.expectEqual(@as(u16, 0), view.peer_manager.coverageDeficits().attestation);
    try std.testing.expectEqual(@as(u8, 0), view.peer_manager.discoveryNeed().attnets[0]);
    try std.testing.expectEqual(@as(u8, 0), node.discovery.?.coordinator.demand.attnets[0]);
}

test "managed runtime explicit advertisement is independent and atomic" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.startup.bind = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } };
    opts.startup.discovery = .{ .bind = opts.startup.bind };
    var node: runtime.NetworkCore = undefined;
    opts.startup.discovery.?.fixed = .{ .ip4 = .{ 127, 0, 0, 1 }, .udp = 19000, .quic = 19001 };
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const before = node.localRecord().?.*;
    var local = node.localState();
    var endpoints = node.advertisementEndpoints().?;
    endpoints.quic = 19002;
    try std.testing.expect(try updateLocalWithEndpoints(&node, &local, .{}, endpoints, now));
    try std.testing.expectEqual(before.sequence + 1, node.localRecord().?.sequence);
    try std.testing.expectEqual(@as(u64, 0), node.localState().metadata.seq_number);
    try std.testing.expectEqual(@as(u16, 19002), node.advertisementEndpoints().?.quic.?);
    try std.testing.expect(!try updateLocalWithEndpoints(&node, &local, .{}, endpoints, now));
    const committed = node.localRecord().?.*;
    local.metadata.attnets[0] = 1;
    endpoints.ip4 = @splat(0);
    try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &local, .{}, endpoints, now));
    try std.testing.expectEqualSlices(u8, committed.slice(), node.localRecord().?.slice());
    try std.testing.expectEqual(@as(u64, 0), node.localState().metadata.seq_number);
    for ([_]runtime.AdvertisementEndpoints{
        .{ .ip4 = .{ 0, 1, 2, 3 }, .udp = 19000, .quic = 19001 },
        .{ .ip6 = .{ 0xfe, 0x80 } ++ .{0} ** 13 ++ .{1}, .udp6 = 19000, .quic6 = 19001 },
    }) |invalid| try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &local, .{}, invalid, now));
    const privileged: runtime.AdvertisementEndpoints = .{ .ip4 = .{ 127, 0, 0, 1 }, .udp = 443, .quic = 443 };
    try std.testing.expect(try updateLocalWithEndpoints(&node, &local, .{}, privileged, now));
    try std.testing.expectEqual(@as(u16, 443), node.advertisementEndpoints().?.quic.?);
    const ipv6: runtime.AdvertisementEndpoints = .{ .ip6 = .{0} ** 15 ++ .{1}, .udp6 = 19000, .quic6 = 19001 };
    const previous = node.localRecord().?.*;
    try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &local, .{}, ipv6, now));
    try std.testing.expectEqualSlices(u8, previous.slice(), node.localRecord().?.slice());
}

test "managed runtime unreachable destination backs off and rotates to its alternate address" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var node: runtime.NetworkCore = undefined;
    const opts = options(&key);
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const peer = t.PeerId.fromPublicKey(&remote.publicKey());
    try node.connectUntil(&peer, &.{
        .{ .ip6 = .{ .octets = .{0} ** 15 ++ .{1}, .port = 19003 } },
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } },
    }, now, now.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
    var faults: FaultIo = .{ .send = .{} };
    faults.init(std.testing.io);
    defer faults.deinit();
    const io = faults.io();
    const refused = node.step(io, now, 0, .{}, 0);
    try std.testing.expect(refused.failure == null);
    try std.testing.expectEqual(@as(u8, 1), refused.dial_failed);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_deferred);
    const row = &node.peer_manager.catalog.rows[0];
    try std.testing.expectEqual(@as(u8, 1), row.intent.failures);
    try std.testing.expectEqual(@as(u8, 1), row.intent.address_index);
    try std.testing.expect(row.attempt == null);
    try std.testing.expect(row.intent.eligible_at_ms >= now.mono_ms + 1000);
    const retry: @import("types.zig").Now = .{ .mono_ms = row.intent.eligible_at_ms, .unix_s = now.unix_s };
    const result = node.step(std.testing.io, retry, 0, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), result.dial_started);
    try std.testing.expect(node.peer_manager.dialing.active[row.attempt.?].connection != null);
}

test "managed runtime socket faults preserve the other owner and local dial refusal is deferred" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const remote_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .coordinator = .{ .query_interval_ms = 100 } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    var faults: FaultIo = .{};
    faults.init(std.testing.io);
    defer faults.deinit();
    const io = faults.io();
    for ([_]std.Io.net.Socket.Handle{ node.transport.udp.sockets.primary().handle, node.discovery.?.transport.sockets.primary().handle }) |socket| {
        faults.receive = .{ .socket = socket };
        faults.receive_calls = 0;
        faults.longest_wait_ms = 0;
        const result = node.step(io, now, 0, .{}, 1000);
        try std.testing.expectEqual(error.Canceled, result.failure.?);
        if (socket == node.discovery.?.transport.sockets.primary().handle) {
            try std.testing.expectEqual(@import("discv5").Transport.FailureStage.receive, result.discovery.failure_stage);
            try std.testing.expectEqual(@as(u64, 1), node.discovery.?.coordinator.counters.receive_failures);
        }
        try std.testing.expect(faults.receive_calls >= 2);
        try std.testing.expect(faults.longest_wait_ms <= runtime.poll_wait_max_ms);
        try std.testing.expect(node.last_now.mono_ms >= now.mono_ms);
    }
    faults.receive = null;
    const idle = node.step(std.testing.io, now, 0, .{}, 0);
    try std.testing.expect(idle.failure == null);
    const settled = node.last_now;
    const discovery_due = node.discovery.?.coordinator.nextWakeup(settled.mono_ms).?;
    try std.testing.expect(discovery_due > settled.mono_ms);
    try std.testing.expectEqual(discovery_due, node.nextWakeup(settled, .{}).?);
    var protocol_wakeups: @import("wake_sources.zig").Wakeups = .{};
    @import("managed.zig").collectWakeups(&node.peer_manager, &node.service, settled, 0, 0, 4, &protocol_wakeups);
    const protocol_due = protocol_wakeups.earliest();
    try std.testing.expect(protocol_due == null or protocol_due.? > discovery_due);
    const peer = t.PeerId.fromPublicKey(&remote_key.publicKey());
    try node.connectUntil(&peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } }}, settled, settled.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
    try std.testing.expectEqual(settled.mono_ms, node.nextWakeup(settled, .{}).?);
    faults.clock = .{};
    const refused = node.step(io, settled, 0, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), refused.dial_deferred);
    try std.testing.expectEqual(error.ClockOutOfRange, refused.failure.?);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_started);
    for (node.peer_manager.catalog.rows) |row| if (row.occupied) {
        try std.testing.expectEqual(@as(u8, 0), row.intent.failures);
        try std.testing.expect(row.attempt == null);
    };
    const calls = node.reservations.allocation_calls;
    const clean = node.step(std.testing.io, settled, 0, .{}, 0);
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

fn failureAndReplacement(a: *runtime.NetworkCore, b: *runtime.NetworkCore) !void {
    var snapshots: [4]t.Snapshot = undefined;
    const count = a.peer_manager.snapshots(&snapshots);
    var target: ?t.PeerRef = null;
    for (snapshots[0..count]) |snapshot| if (snapshot.connection != null) {
        target = snapshot.peer;
    };
    const now = try @import("transport.zig").currentTime(std.testing.io);
    try std.testing.expectEqual(t.ReputationDecision.ban, a.reportPeer(&a.peer_manager.catalog.get(target.?).?.identity, .fatal, now).?);
    var faults: FaultIo = .{ .receive = .{ .socket = a.transport.udp.sockets.primary().handle } };
    faults.init(std.testing.io);
    defer faults.deinit();
    const faulty_io = faults.io();
    const deadline = a.peer_manager.control.schedules[target.?.index].closing.?.deadline_ms;
    var after_deadline = now;
    after_deadline.mono_ms = deadline;
    const result = a.step(faulty_io, after_deadline, 100, .{}, 0);
    try std.testing.expectEqual(error.Canceled, result.failure.?);
    try std.testing.expectEqual(@as(u16, 0), a.peerCounts().relevant);
    try std.testing.expect(a.peer_manager.catalog.get(target.?).?.connection == null);
    for (0..100) |_| {
        _ = a.step(std.testing.io, a.last_now, 100, .{}, 0);
        _ = b.step(std.testing.io, now, 100, .{}, 0);
        if (a.peerCounts().connected == 0) break;
    }
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.startup.local = a.localState();
    opts.startup.schedule = a.schedule;
    var replacement: runtime.NetworkCore = undefined;
    try replacement.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer replacement.deinit(std.testing.io);
    try replacement.connectUntil(&a.peerId(), &.{a.transport.localAddress()}, now, now.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
    for (0..2000) |_| {
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        const added = replacement.step(std.testing.io, tick, 100, .{}, 1);
        if (added.failure) |err| return err;
        var host_tick = tick;
        host_tick.mono_ms = @max(host_tick.mono_ms, a.last_now.mono_ms);
        const accepted = a.step(std.testing.io, host_tick, 100, .{}, 1);
        if (accepted.failure) |err| return err;
        if (a.peerCounts().relevant == 1 and replacement.peerCounts().relevant == 1) break;
    }
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    try std.testing.expectEqual(@as(u16, 1), replacement.peerCounts().relevant);
    try std.testing.expect(replacement.counters.dial_started > 0);
    replacement.shutdown(now);
}

test "managed profiles measure reservations and unwind byte exhaustion" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    inline for (.{ @import("configuration.zig").Profile.small, .beacon_node }) |profile| {
        var ledger: @import("reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var request: @import("configuration.zig").Request = .{ .profile = profile, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() };
        const startup: runtime.Startup = .{ .host = &key, .bind = .{ .ip4 = .loopback(0) }, .local = @import("managed_test_support.zig").localState(.{}) };
        var resolved = try @import("configuration.zig").resolve(request);
        var node: runtime.NetworkCore = undefined;
        try node.init(ledger.allocator(), std.testing.io, &resolved, startup);
        var initialized = true;
        defer if (initialized) node.deinit(std.testing.io);
        const measured = ledger.bytes;
        const mib = 1024 * 1024;
        const total: usize = if (profile == .small) 96 * mib else 384 * mib;
        std.debug.print("managed memory {s}: total={d} reqresp={d} negotiations={d}\n", .{ @tagName(profile), measured, node.service.reqresp.memoryPlan().total_bytes, node.service.router.negotiator.entries.len });
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

test "managed small profile cleans every failed allocation prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, profileAllocationFailures, .{});
}

fn profileAllocationFailures(a: std.mem.Allocator) !void {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: runtime.NetworkCore = undefined;
    try node.init(a, std.testing.io, &resolved, .{ .host = &key, .bind = .{ .ip4 = .loopback(0) }, .local = @import("managed_test_support.zig").localState(.{}) });
    node.deinit(std.testing.io);
}

test "managed invalid complete sections reject before allocation" {
    const forks: []const @import("reqresp/reqresp.zig").ForkEntry = &.{.{ .digest = @splat(0), .fork = .phase0 }};
    inline for (.{ error.InvalidOptions, error.InvalidOptions, error.InvalidOptions, error.InvalidLimits, error.InvalidLimits, error.InvalidOptions }, 0..) |expected, section| {
        var request: @import("configuration.zig").Request = .{ .profile = .small, .seed = 1, .forks = forks, .admission_policy = @import("reqresp/policy_fixture.zig").config() };
        switch (section) {
            0 => request.reqresp.work_per_pump_max = 0,
            1 => request.control = .{ .ping_inbound_ms = 0 },
            2 => request.dial = .{ .seed = 1, .concurrent_max = 0 },
            3 => request.gossip.score_params = .{ .decay_interval_ms = 0 },
            4 => request.limits = .{ .handshaking_max = 0 },
            5 => request.peers = .{ .capacity = 0 },
            else => unreachable,
        }
        try std.testing.expectError(expected, @import("configuration.zig").resolve(request));
    }
}

test "managed runtime native readiness wakes for either delayed protocol socket" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    var opts = options(&key);
    opts.startup.wait_mode = .native_poll;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    for (0..2) |source| {
        for (0..2) |_| {
            const settled = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 0);
            try std.testing.expect(settled.failure == null);
        }
        const target = if (source == 0) node.transport.udp.sockets.primary() else node.discovery.?.transport.sockets.primary();
        const task = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ sender, target.address });
        defer task.join();
        const result = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 100);
        try std.testing.expect(result.failure == null);
        if (source == 0) {
            try std.testing.expect(result.readiness.quic);
            try std.testing.expectEqual(@as(u32, 1), result.transport.datagrams_received);
        } else {
            try std.testing.expect(result.readiness.discovery);
            try std.testing.expectEqualSlices(u8, "invalid", node.discovery.?.transport.receive_buffer[0..7]);
        }
    }
}

fn delayedRuntimeDatagram(sender: std.Io.net.Socket, address: std.Io.net.IpAddress) void {
    std.testing.io.sleep(.fromMilliseconds(10), .awake) catch unreachable;
    sender.send(std.testing.io, &address, "invalid") catch unreachable;
}

test "managed runtime native host wake validates rollback detaches and preserves bytes" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    var opts = options(&key);
    opts.startup.wait_mode = .native_poll;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const host = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer host.close(std.testing.io);
    try node.setHostWake(host.handle);
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(-1));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.transport.udp.sockets.primary().handle));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.discovery.?.transport.sockets.primary().handle));
    _ = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 0);
    const sender = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ host, host.address });
    defer sender.join();
    const result = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 100);
    try std.testing.expect(result.failure == null and result.readiness.host);
    const repeated = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 0);
    try std.testing.expect(repeated.readiness.host);
    try std.testing.expectEqual(@as(u32, 0), repeated.readiness.timeout_ms);
    try node.setHostWake(null);
    const detached = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 0);
    try std.testing.expect(!detached.readiness.host);
    try node.setHostWake(host.handle);
    node.shutdown(node.last_now);
    const stopped = node.step(std.testing.io, node.last_now, 0, .{}, 100);
    try std.testing.expect(!stopped.readiness.host);
    try std.testing.expectEqual(@as(u32, 0), stopped.readiness.timeout_ms);
    try std.testing.expectError(error.Stopped, node.setHostWake(host.handle));
    var buffer: [8]u8 = undefined;
    const message = try host.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
    try std.testing.expectEqualStrings("invalid", message.data);
}

test "managed runtime portable fallback rejects enabled host source" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{33}));
    var node: runtime.NetworkCore = undefined;
    var opts = options(&key);
    opts.startup.wait_mode = .portable;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    try std.testing.expectError(error.UnsupportedWait, node.setHostWake(1));
    try node.setHostWake(null);
    const result = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 0);
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(@as(u64, 0), node.counters.readiness_calls);
}

test "managed runtime native wait source failure retains completed protocol progress" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{34}));
    var opts = options(&key);
    opts.startup.wait_mode = .native_poll;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var pipe: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.pipe(&pipe));
    defer _ = std.c.close(pipe[0]);
    try node.setHostWake(pipe[0]);
    try std.testing.expectEqual(@as(c_int, 0), std.c.close(pipe[1]));
    try node.transport.udp.sockets.primary().send(std.testing.io, &node.transport.udp.sockets.primary().address, "invalid");
    try node.transport.udp.sockets.primary().send(std.testing.io, &node.discovery.?.transport.sockets.primary().address, "invalid");
    const allocations = node.reservations.allocation_calls;
    const result = node.step(std.testing.io, try @import("transport.zig").currentTime(std.testing.io), 0, .{}, 100);
    try std.testing.expectEqual(error.WaitSourceClosed, result.failure.?);
    try std.testing.expect(result.readiness.quic and result.readiness.discovery);
    try std.testing.expectEqual(@as(u32, 1), result.transport.datagrams_received);
    try std.testing.expectEqualSlices(u8, "invalid", node.discovery.?.transport.receive_buffer[0..7]);
    try std.testing.expectEqual(allocations, node.reservations.allocation_calls);
    try node.setHostWake(null);
    const clean = node.step(std.testing.io, node.last_now, 0, .{}, 0);
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(@as(u64, 1), node.counters.readiness_failures);
}

test "managed runtime native wait honors pacing native timers and pending lifecycle work" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{35}));
    var opts = options(&key);
    opts.startup.wait_mode = .native_poll;
    opts.resolved.limits.handshake_timeout_ms = 80;
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const remote = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer remote.close(std.testing.io);
    const destination = @import("udp.zig").fromNetwork(remote.address);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const handle = try node.transport.engine.dial(&destination, node.peerId(), now);
    const first = node.step(std.testing.io, now, 0, .{}, 100);
    try std.testing.expect(first.failure == null);
    try std.testing.expectEqual(@as(u32, 0), first.readiness.timeout_ms);
    try std.testing.expect(first.transport.datagrams_sent > 0);
    const current = node.last_now;
    var paced_bytes = "paced".*;
    try node.transport.pending.put(handle, .{
        .bytes = &paced_bytes,
        .to = destination,
        .transmit_at_ns = current.nanos() + 10 * std.time.ns_per_ms,
    });
    try std.testing.expectEqual(current.mono_ms + 10, node.nextWakeup(current, .{}).?);
    const paced = node.step(std.testing.io, current, 0, .{}, 100);
    try std.testing.expect(paced.failure == null);
    try std.testing.expectEqual(@as(u32, 10), paced.readiness.timeout_ms);
    const remaining = (now.mono_ms + 80) -| node.last_now.mono_ms;
    try std.testing.expect(node.nextWakeup(node.last_now, .{}).? <= node.last_now.mono_ms + remaining);
    const timer = node.step(std.testing.io, node.last_now, 0, .{}, 100);
    try std.testing.expect(timer.failure == null);
    try std.testing.expect(timer.readiness.timeout_ms <= remaining);
    const failed = try node.transport.engine.dial(&destination, node.peerId(), node.last_now);
    node.transport.engine.failSend(failed.index);
    _ = node.transport.engine.takeHostWork();
    try std.testing.expect(node.transport.engine.eventsPending());
    const lifecycle = node.step(std.testing.io, node.last_now, 0, .{}, 100);
    try std.testing.expect(lifecycle.failure == null);
    try std.testing.expectEqual(@as(u32, 0), lifecycle.readiness.timeout_ms);
    try std.testing.expect(lifecycle.transport.events > 0);
    const repeated = node.step(std.testing.io, node.last_now, 0, .{}, 0);
    try std.testing.expectEqual(@as(usize, 0), repeated.transport.events);
}

test "managed runtime subscriptions use copied startup policy and reject atomically" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.resolved.core.service.gossipsub.topic_policy = &@import("gossipsub/topic_fixture.zig").churn;
    opts.resolved.core.service.gossipsub.topic_params = @splat(.{ .params = .{ .weight = 2 } });
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const calls = node.reservations.allocation_calls;
    const initial = node.transport.engine.resourceSnapshot();
    try std.testing.expectEqual(@as(usize, 4), initial.capacity);
    try std.testing.expectEqual(@as(usize, 0), initial.active);
    try std.testing.expectEqual(@as(usize, 0), node.peer_manager.dialing.resourceSnapshot(&node.peer_manager.catalog).custody_incomplete);
    const owner = node.service.gossipsub;
    opts.resolved.core.service.gossipsub.topic_params.?[0].params.weight = 3;
    var text = "/eth2/01020304/beacon_block/ssz_snappy".*;
    try core_test.subscribe(&node, &text);
    text[6] = 'f';
    try std.testing.expectEqual(@as(f64, 2), owner.peers.scores.topic_params[0].weight);
    try std.testing.expectEqualStrings("/eth2/01020304/beacon_block/ssz_snappy", owner.overlay.topicString(0));
    const revision = owner.peers.scores.revision;
    try std.testing.expectError(error.InvalidTopic, core_test.subscribe(&node, "bad"));
    try std.testing.expectEqual(revision, owner.peers.scores.revision);
    try std.testing.expectEqual(@as(u64, 1), owner.overlay.rows[0].generation);
    var name: [@import("gossipsub/topic.zig").topic_max_len]u8 = undefined;
    for (0..@import("gossipsub/constants.zig").topics_cap - 1) |index| {
        const topic = try @import("gossipsub/topic_fixture.zig").churnTopic(index, &name);
        try core_test.subscribe(&node, topic);
    }
    const full_revision = owner.peers.scores.revision;
    const excess = try @import("gossipsub/topic_fixture.zig").churnTopic(511, &name);
    try std.testing.expectError(error.TopicCapacity, core_test.subscribe(&node, excess));
    try std.testing.expectEqual(full_revision, owner.peers.scores.revision);
    node.shutdown(node.last_now);
    try std.testing.expectError(error.Stopped, core_test.subscribe(&node, owner.overlay.topicString(0)));
    try std.testing.expectEqual(full_revision, owner.peers.scores.revision);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

test "managed beacon idle scans do not manufacture immediate deadlines" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .beacon_node, .seed = 7, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }}, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = @import("managed_test_support.zig").localState(.{}),
    });
    defer node.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    const calls = node.reservations.allocation_calls;
    for (0..8) |_| {
        const result = node.step(std.testing.io, now, 100, .{}, 0);
        try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(@as(?u64, null), node.service.reqresp.nextWakeup(now, .{}));
        try std.testing.expect(node.nextWakeup(now, .{}).? > now.mono_ms);
    }
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

test "managed runtime BPO same-fork digest transition updates status and advertisement" {
    const rr = @import("reqresp/reqresp.zig");
    const first: rr.ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
    const second: rr.ForkEntry = .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu };
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{ first, second }, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &resolved, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{
            .fork = .{ .digest = first.digest, .fork = first.fork },
            .status = .{ .fork_digest = first.digest, .earliest_available_slot = 0 },
            .metadata = .{ .custody_group_count = 1 },
        },
        .discovery = .{ .bind = .{ .ip4 = .loopback(0) } },
    });
    defer node.deinit(std.testing.io);
    const initial = node.localRecord().?.sequence;
    var local = node.localState();
    try std.testing.expectEqual(first.digest, local.status.fork_digest);
    try std.testing.expectEqual(first.fork, node.service.reqresp.request_fork);
    local.fork.digest = second.digest;
    local.status.fork_digest = second.digest;
    try std.testing.expect(try updateLocal(&node, &local, .{}, try @import("transport.zig").currentTime(std.testing.io)));
    try std.testing.expectEqual(second.digest, node.localState().status.fork_digest);
    try std.testing.expectEqual(second.digest, node.localState().fork.digest);
    try std.testing.expectEqual(second.fork, node.localState().fork.fork);
    try std.testing.expectEqual(second.fork, node.service.reqresp.request_fork);
    try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    const candidate = try @import("peers/enr.zig").decode(node.localRecord().?, &local.fork);
    try std.testing.expectEqual(second.digest, candidate.fork.digest);
    for ([_]rr.ForkEntry{
        .{ .digest = .{ 9, 9, 9, 9 }, .fork = .fulu },
        .{ .digest = second.digest, .fork = .gloas },
    }) |invalid| {
        local.fork = .{ .digest = invalid.digest, .fork = invalid.fork };
        local.status.fork_digest = invalid.digest;
        try std.testing.expectError(error.UnknownFork, updateLocal(&node, &local, .{}, node.last_now));
        try std.testing.expectEqual(second.digest, node.localState().status.fork_digest);
        try std.testing.expectEqual(second.fork, node.localState().fork.fork);
        try std.testing.expectEqual(second.fork, node.service.reqresp.request_fork);
        try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    }
}

test "managed runtime BPO duplicate digest validation precedes allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    var opts = options(&key);
    opts.resolved.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = @splat(0), .fork = .fulu },
    };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidOptions, node.init(failing.allocator(), std.testing.io, &opts.resolved, opts.startup));
}

test "managed runtime request admission selector commits with validated local fork" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.resolved.core.service.reqresp.request_fork = .gloas;
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    try std.testing.expectEqual(t.ForkSeq.phase0, node.service.reqresp.request_fork);
    var local = node.localState();
    local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    local.status.fork_digest = local.fork.digest;
    local.status.earliest_available_slot = 0;
    local.metadata.custody_group_count = 1;
    const now = try @import("transport.zig").currentTime(std.testing.io);
    try std.testing.expect(try updateLocal(&node, &local, .{}, now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.service.reqresp.request_fork);
    local.fork.fork = .gloas;
    try std.testing.expectError(error.UnknownFork, updateLocal(&node, &local, .{}, now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.service.reqresp.request_fork);
}

const ActivationSnapshot = struct {
    local: t.LocalState,
    schedule: runtime.ForkSchedule,
    endpoints: ?runtime.AdvertisementEndpoints,
    capabilities: @import("capabilities.zig").Directional,
    request_fork: t.ForkSeq,
    record: d.identity.enr.Record,

    fn capture(node: *const runtime.NetworkCore) ActivationSnapshot {
        return .{
            .local = node.localState(),
            .schedule = node.schedule,
            .endpoints = node.advertisementEndpoints(),
            .capabilities = node.service.router.capabilities(),
            .request_fork = node.service.reqresp.request_fork,
            .record = node.localRecord().?.*,
        };
    }

    fn expectUnchanged(self: *const ActivationSnapshot, node: *const runtime.NetworkCore) !void {
        try std.testing.expectEqualDeep(self.local, node.localState());
        try std.testing.expectEqualDeep(self.schedule, node.schedule);
        try std.testing.expectEqualDeep(self.endpoints, node.advertisementEndpoints());
        try std.testing.expectEqualDeep(self.capabilities, node.service.router.capabilities());
        try std.testing.expectEqual(self.request_fork, node.service.reqresp.request_fork);
        try std.testing.expectEqual(self.record.sequence, node.localRecord().?.sequence);
        try std.testing.expectEqualSlices(u8, self.record.slice(), node.localRecord().?.slice());
    }
};

test "managed runtime capabilities activation rolls back all owners on rejected candidates" {
    const caps = @import("capabilities.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.resolved.core.service.router.meshsub_versions = &.{.v1_2};
    opts.resolved.core.service.identify = .{ .agent = "capability-rollback" };
    opts.resolved.core.service.router.capabilities = caps.withIdentify(try caps.forFork(.phase0, false, &.{.v1_2}));
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const before = ActivationSnapshot.capture(&node);
    const identify = node.service.identify.local;
    const now = node.last_now;
    var update: runtime.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
    update.local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(identify, node.service.identify.local);
    update.local = before.local;
    update.local.status.earliest_available_slot = null;
    update.capabilities.receive.insert(.{ .reqresp = .status_v2 });
    try std.testing.expectError(error.MissingAvailability, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(identify, node.service.identify.local);
    update.local = before.local;
    update.capabilities = before.capabilities;
    update.local.status.head_slot = 10;
    update.endpoints.?.quic = 443;
    update.capabilities.request.insert(.{ .meshsub = .v1_0 });
    try std.testing.expectError(error.InvalidCapabilities, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    update.capabilities = try caps.forFork(.fulu, false, &.{.v1_2});
    update.local.fork.fork = .fulu;
    update.local.status.earliest_available_slot = 0;
    try std.testing.expectError(error.UnknownFork, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    update.local.fork.digest = .{ 1, 2, 3, 4 };
    update.local.status.fork_digest = update.local.fork.digest;
    try std.testing.expectError(error.SequenceExhausted, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
}

test "managed runtime capabilities activation commits fork BPO and copied directional values" {
    const caps = @import("capabilities.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{25}));
    var opts = options(&key);
    opts.startup.local.metadata.custody_group_count = 1;
    const quotas = @import("reqresp/admission_fixture.zig").quotas(2048, 1000);

    opts.resolved.core.service.reqresp.admission = .{ .policy = @import("reqresp/policy_fixture.zig").config(), .limits = .{ .identities = 2, .peer = quotas, .global = quotas } };
    opts.resolved.core.service.router.capabilities = try caps.forFork(.phase0, true, &.{ .v1_2, .v1_1 });
    opts.resolved.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu },
        .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu },
    };
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const admission = &node.service.reqresp.admission.limiter;
    const identity = node.peerId();
    try std.testing.expectEqual(.allowed, admission.take(&identity, .blocks_by_root_v2, 1, .phase0, node.last_now.mono_ms));
    const admitted_debt = admission.global;
    const admitted_row = admission.rows[0];
    const allocations = node.reservations.allocation_calls;
    const before = ActivationSnapshot.capture(&node);
    var update: runtime.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
    update.capabilities.request = .initEmpty();
    try std.testing.expect(try applyLocal(&node, &update, node.last_now));
    try std.testing.expectEqualDeep(before.local, node.localState());
    try std.testing.expectEqual(before.record.sequence, node.localRecord().?.sequence);
    try std.testing.expect(!try applyLocal(&node, &update, node.last_now));
    update.local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    update.local.status.fork_digest = update.local.fork.digest;
    update.local.status.earliest_available_slot = 0;
    update.capabilities = try caps.forFork(.fulu, false, &.{ .v1_2, .v1_1 });
    try std.testing.expect(try applyLocal(&node, &update, node.last_now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.service.reqresp.request_fork);
    const active = node.service.router.capabilities();
    try std.testing.expect(active.receive.contains(.{ .reqresp = .status_v2 }));
    try std.testing.expect(active.receive.contains(.{ .reqresp = .status_v1 }));
    try std.testing.expect(!active.request.contains(.{ .reqresp = .status_v1 }));
    try std.testing.expect(!active.receive.contains(.{ .reqresp = .metadata_v2 }));
    try std.testing.expect(active.receive.contains(.{ .reqresp = .metadata_v3 }));
    try std.testing.expect(!active.receive.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    try std.testing.expect(active.request.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    update.local.fork.digest = .{ 5, 6, 7, 8 };
    update.local.status.fork_digest = update.local.fork.digest;
    try std.testing.expect(try applyLocal(&node, &update, node.last_now));
    try std.testing.expectEqualDeep(active, node.service.router.capabilities());
    try std.testing.expectEqual(before.record.sequence + 2, node.localRecord().?.sequence);
    try std.testing.expectEqual(before.local.metadata.seq_number, node.localState().metadata.seq_number);
    try std.testing.expectEqualDeep(admitted_debt, admission.global);
    try std.testing.expectEqualDeep(admitted_row, admission.rows[0]);
    try std.testing.expectEqual(allocations, node.reservations.allocation_calls);
    const committed = ActivationSnapshot.capture(&node);
    try std.testing.expect(!try applyLocal(&node, &update, node.last_now));
    update.local.metadata.attnets[0] = 1;
    update.capabilities.receive = .initEmpty();
    update.endpoints.?.quic = 443;
    update.schedule.next_epoch = 5;
    try committed.expectUnchanged(&node);
    try std.testing.expect(try updateLocal(&node, &update.local, .{}, node.last_now));
    try std.testing.expectEqualDeep(active, node.service.router.capabilities());
    try std.testing.expectEqual(before.local.metadata.seq_number + 1, node.localState().metadata.seq_number);
}

test "identify managed advertisement follows committed endpoints and rejected updates preserve it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.resolved.core.service.identify = .{ .agent = "managed", .addresses = &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19009 } }} };
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{ .session_capacity = 8, .challenge_capacity = 8, .call_capacity = 8 } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const initial = node.service.identify.local.?;
    const address = try @import("wire/multiaddr.zig").Multiaddr.decode(initial.addresses[0].bytes[0..initial.addresses[0].len]);
    try std.testing.expectEqual(node.transport.localAddress(), address.address);
    var endpoints = node.advertisementEndpoints().?;
    endpoints.quic = 443;
    const now = node.last_now;
    try std.testing.expect(try updateLocalWithEndpoints(&node, &node.peer_manager.local, node.schedule, endpoints, now));
    const updated = node.service.identify.local.?;
    const next = try @import("wire/multiaddr.zig").Multiaddr.decode(updated.addresses[0].bytes[0..updated.addresses[0].len]);
    try std.testing.expectEqual(@as(u16, 443), next.address.port());
    endpoints.quic = 0;
    try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &node.peer_manager.local, node.schedule, endpoints, now));
    try std.testing.expectEqualDeep(updated, node.service.identify.local.?);
}

test "managed runtime targeted Status serves two current schedules and immediate close is local" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    const key_c = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{33}));
    var a: runtime.NetworkCore = undefined;
    var b: runtime.NetworkCore = undefined;
    var c: runtime.NetworkCore = undefined;
    var opts = options(&key_a);
    opts.resolved.core.peers.min_outbound = 0;
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    try a.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer a.deinit(std.testing.io);
    opts = options(&key_b);
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    try b.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer b.deinit(std.testing.io);
    opts = options(&key_c);
    opts.resolved.core.service.identify = .{ .agent = "peer-operations" };
    try c.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer c.deinit(std.testing.io);
    const start = try @import("transport.zig").currentTime(std.testing.io);
    try a.addDirectPeer(&b.peerId(), &.{b.transport.localAddress()}, start);
    try a.addDirectPeer(&c.peerId(), &.{c.transport.localAddress()}, start);
    var rows: [4]t.Snapshot = undefined;
    var ready = false;
    for (0..3000) |_| {
        const now = try @import("transport.zig").currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        for ([_]*runtime.NetworkCore{ &a, &b, &c }) |node| {
            const result = node.step(std.testing.io, now, 100, .{}, 1);
            if (result.failure) |err| return err;
        }
        const count = a.peer_manager.snapshots(&rows);
        if (count == 2 and a.peerCounts().relevant == 2 and rows[0].identify != null and rows[1].identify != null and
            a.peer_manager.control.resourceSnapshot().operations == 0)
        {
            ready = true;
            break;
        }
    }
    try std.testing.expect(ready);
    const calls = a.reservations.allocation_calls;
    const selected = rows[0];
    const other = rows[1];
    const now = try @import("transport.zig").currentTime(std.testing.io);
    a.peer_manager.control.schedules[other.peer.index].status_due_ms = now.mono_ms;
    const unselected = a.peer_manager.control.schedules[other.peer.index];
    const before = a.peer_manager.control.schedules[selected.peer.index];
    try std.testing.expect(a.reStatusPeer(&selected.identity, now));
    var expected = before;
    expected.status_due_ms = now.mono_ms;
    try std.testing.expectEqualDeep(expected, a.peer_manager.control.schedules[selected.peer.index]);
    try std.testing.expectEqualDeep(unselected, a.peer_manager.control.schedules[other.peer.index]);
    const result = a.step(std.testing.io, now, 100, .{}, 0);
    if (result.failure) |err| return err;
    var status_started: usize = 0;
    for (a.peer_manager.control.operations) |op| if (op.request != null and op.protocol == .status_v1) {
        status_started += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), status_started);
    try std.testing.expectEqual(before.identify_state, a.peer_manager.control.schedules[selected.peer.index].identify_state);
    try std.testing.expect(a.closePeer(&selected.identity, now));
    try std.testing.expect(!a.reStatusPeer(&selected.identity, now));
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().connected);
    var direct: [2]t.PeerId = undefined;
    const owner: *const runtime.NetworkCore = &a;
    try std.testing.expectEqual(@as(usize, 2), try owner.directPeers(&direct));
    try std.testing.expect(a.removeDirectPeer(&selected.identity));
    try std.testing.expect(!a.removeDirectPeer(&selected.identity));
    try std.testing.expectEqual(@as(usize, 1), try owner.directPeers(&direct));
    try std.testing.expectEqual(calls, a.reservations.allocation_calls);
    try recycledPeerOperations(&a, &b, &c, &selected);
}

fn recycledPeerOperations(a: *runtime.NetworkCore, b: *runtime.NetworkCore, c: *runtime.NetworkCore, previous: *const t.Snapshot) !void {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{34}));
    var replacement: runtime.NetworkCore = undefined;
    const opts = options(&key);
    try replacement.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer replacement.deinit(std.testing.io);
    var events: [4]t.Event = undefined;
    _ = a.peer_manager.catalog.pollEvents(&events);
    const start = try @import("transport.zig").currentTime(std.testing.io);
    try a.addDirectPeer(&replacement.peerId(), &.{replacement.transport.localAddress()}, start);
    var current: ?t.Snapshot = null;
    for (0..3000) |_| {
        const now = try @import("transport.zig").currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        for ([_]*runtime.NetworkCore{ a, b, c, &replacement }) |node| {
            const result = node.step(std.testing.io, now, 100, .{ .peers = &events }, 1);
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
    try std.testing.expect(a.peer_manager.catalog.get(previous.peer) == null);
    try std.testing.expect(!a.closePeer(&previous.identity, a.last_now));
    try std.testing.expect(!a.reStatusPeer(&previous.identity, a.last_now));
    try std.testing.expectEqualDeep(selected, a.peer_manager.catalog.get(selected.peer).?);
    try std.testing.expect(a.closePeer(&selected.identity, a.last_now));
}

test "managed runtime complete local intent rejects invalid last topic atomically" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{41}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.identify = .{ .agent = "local-intent" };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const block_topic = "/eth2/01020304/beacon_block/ssz_snappy";
    const update: runtime.LocalUpdate = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() };
    var desired: runtime.LocalIntent = .{ .update = update, .demand = .{}, .subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{block_topic}) };
    const now = node.last_now;
    try std.testing.expect(try node.applyIntent(&desired, now));
    try std.testing.expect(!(try node.applyIntent(&desired, now)));
    const before = ActivationSnapshot.capture(&node);
    const identify = node.service.identify.local;
    const demand = node.peer_manager.demand;
    const g = node.service.gossipsub;
    const topic = g.overlay.findTopic(block_topic).?;
    const params = g.peers.scores.topic_params[topic];
    desired.update.local.metadata.attnets[0] = 1;
    desired.subscriptions = &.{ desired.subscriptions[0], .{ .digest = @splat(255) } };
    try std.testing.expectError(error.InvalidTopic, node.applyIntent(&desired, now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(identify, node.service.identify.local);
    try std.testing.expectEqualDeep(demand, node.peer_manager.demand);
    try std.testing.expectEqualDeep(params, g.peers.scores.topic_params[topic]);
    try std.testing.expect(g.overlay.subscribed(topic));
    try std.testing.expectEqual(@as(?u16, topic), g.overlay.findTopic(block_topic));
}

fn intentFor(node: *const runtime.NetworkCore) runtime.LocalIntent {
    return .{
        .update = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() },
        .demand = node.peer_manager.demand,
        .subscriptions = &.{},
    };
}

test "managed runtime Status-only update preserves local owners and permits a regressing head" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{44}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
    opts.resolved.core.service.identify = .{ .agent = "status-only" };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var desired = intentFor(&node);
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    desired.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{name});
    desired.demand = .{ .attnets = 7, .syncnets = 3 };
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    var expected = ActivationSnapshot.capture(&node);
    const identify = node.service.identify.local;
    const now = node.last_now;
    const allocations = node.reservations.allocation_calls;
    const gossip = node.service.gossipsub;
    const topic = gossip.overlay.findTopic(name).?;
    const revision = gossip.peers.scores.revision;
    const params = gossip.peers.scores.topic_params[topic];
    var status = node.localState().status;
    for ([_]u64{ 100, 80 }) |head_slot| {
        status.head_slot = head_slot;
        status.head_root = @splat(@intCast(head_slot));
        expected.local.status = status;
        try node.updateStatus(&status);
        status.head_root[0] = 0;
        try expected.expectUnchanged(&node);
        try std.testing.expectEqualDeep(desired.demand, node.peer_manager.demand);
        try std.testing.expectEqualDeep(identify, node.service.identify.local);
        try std.testing.expectEqualDeep(now, node.last_now);
        try std.testing.expectEqualDeep(params, gossip.peers.scores.topic_params[topic]);
        try std.testing.expectEqual(revision, gossip.peers.scores.revision);
        try std.testing.expect(gossip.overlay.subscribed(topic));
        try std.testing.expectEqual(@as(?u16, topic), gossip.overlay.findTopic(name));
        try std.testing.expectEqual(allocations, node.reservations.allocation_calls);
        try std.testing.expect(node.peer_manager.selection_revision == null);
    }
}

test "managed runtime Status-only validation preserves accepted local state" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{45}));
    var opts = options(&key);
    opts.startup.local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    opts.startup.local.status.fork_digest = opts.startup.local.fork.digest;
    opts.startup.local.status.earliest_available_slot = 0;
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const before = ActivationSnapshot.capture(&node);
    var status = before.local.status;
    status.fork_digest[0] = 9;
    try std.testing.expectError(error.InvalidForkDigest, node.updateStatus(&status));
    try before.expectUnchanged(&node);
    status = before.local.status;
    status.earliest_available_slot = null;
    try std.testing.expectError(error.MissingAvailability, node.updateStatus(&status));
    try before.expectUnchanged(&node);
    node.shutdown(node.last_now);
    try std.testing.expectError(error.Stopped, node.updateStatus(&before.local.status));
    try before.expectUnchanged(&node);
}

test "managed runtime local intent demand candidate sequence and stopped refusals" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{42}));
    for (0..2) |exhausted| {
        var opts = options(&key);
        opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = if (exhausted == 0) std.math.maxInt(u64) else 1 };
        if (exhausted == 1) opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
        opts.resolved.core.service.identify = .{ .agent = "local-intent" };
        opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
        var node: runtime.NetworkCore = undefined;
        try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
        defer node.deinit(std.testing.io);
        const before = ActivationSnapshot.capture(&node);
        const identify = node.service.identify.local;
        const g = node.service.gossipsub;
        const revision = g.peers.scores.revision;
        var desired = intentFor(&node);
        desired.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{"/eth2/01020304/beacon_block/ssz_snappy"});
        desired.update.local.fork.custody_groups = 1;
        desired.demand.group_targets[1] = 1;
        try desired.demand.validate(&node.peer_manager.local.fork, node.peer_manager.catalog.options.max_peers);
        try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
        desired.update.local.fork = node.peer_manager.local.fork;
        desired.demand.group_targets[1] = node.peer_manager.catalog.options.max_peers + 1;
        try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
        desired.demand = .{ .attnets = 1 };
        desired.update.local.metadata.attnets[0] = 1;
        try std.testing.expectError(error.SequenceExhausted, node.applyIntent(&desired, node.last_now));
        try before.expectUnchanged(&node);
        try std.testing.expectEqualDeep(identify, node.service.identify.local);
        try std.testing.expectEqualDeep(t.Demand{}, node.peer_manager.demand);
        try std.testing.expectEqual(revision, g.peers.scores.revision);
        try std.testing.expect(g.overlay.findTopic("/eth2/01020304/beacon_block/ssz_snappy") == null);
        node.shutdown(node.last_now);
        try std.testing.expectError(error.Stopped, node.applyIntent(&desired, node.last_now));
        try before.expectUnchanged(&node);
    }
}

test "managed runtime local intent topic demand no-op preserves Status scheduling and counters" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{43}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const g = node.service.gossipsub;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const before = ActivationSnapshot.capture(&node);
    const calls = node.reservations.allocation_calls;
    node.peer_manager.control.schedules[0].peer = .{ .index = 0, .generation = 1 };
    node.peer_manager.control.schedules[0].status_due_ms = node.last_now.mono_ms + 500;
    const schedule = node.peer_manager.control.schedules[0];
    defer node.peer_manager.control.schedules[0].peer = null;
    var desired = intentFor(&node);
    desired.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{name});
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    const row = g.overlay.findTopic(name).?;
    g.peers.scores.invalid(0, row);
    const counters = g.peers.scores.topics[row];
    const revision = g.peers.scores.revision;
    const retained = g.overlay.rows[row].retire_after_ms;
    try std.testing.expect(!try node.applyIntent(&desired, node.last_now));
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    desired.demand = .{ .attnets = 1 };
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    try std.testing.expect(!try node.applyIntent(&desired, node.last_now));
    try std.testing.expectEqualDeep(desired.demand, node.peer_manager.demand);
    try std.testing.expectEqualDeep(counters, g.peers.scores.topics[row]);
    try std.testing.expectEqual(retained, g.overlay.rows[row].retire_after_ms);
    try std.testing.expectEqualDeep(schedule, node.peer_manager.control.schedules[0]);
    try before.expectUnchanged(&node);
    desired.subscriptions = &.{};
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    try std.testing.expect(!g.overlay.subscribed(row));
    const deadline = g.overlay.rows[row].retire_after_ms;
    try std.testing.expect(!try node.applyIntent(&desired, .{ .mono_ms = node.last_now.mono_ms + 1, .unix_s = node.last_now.unix_s }));
    try std.testing.expectEqual(deadline, g.overlay.rows[row].retire_after_ms);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

const IntentPair = struct {
    a: runtime.NetworkCore = undefined,
    b: runtime.NetworkCore = undefined,
    a_inbox: Inbox = .{},
    b_inbox: Inbox = .{},
    b_app: [4]@import("reqresp/root.zig").Event = undefined,

    fn attachInboxes(self: *IntentPair) void {
        self.a_inbox.attach(self.a.service.gossipsub);
        self.b_inbox.attach(self.b.service.gossipsub);
    }

    fn deinitInboxes(self: *IntentPair) void {
        self.b_inbox.deinit();
        self.a_inbox.deinit();
    }

    /// Gossip delivered in earlier steps is cleared first.
    fn pump(self: *IntentPair) !struct { a: runtime.Result, b: runtime.Result } {
        self.a_inbox.clear();
        self.b_inbox.clear();
        const now = try @import("transport.zig").currentTime(std.testing.io);
        const a = self.a.step(std.testing.io, now, 100, .{}, 1);
        if (a.failure) |err| return err;
        const b = self.b.step(std.testing.io, now, 100, .{ .application = &self.b_app }, 1);
        if (b.failure) |err| return err;
        return .{ .a = a, .b = b };
    }
};

test "managed runtime metrics aggregate subnets and count distinct mesh peers" {
    const full = @import("gossipsub/topic_fixture.zig").full;
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{51}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{52}));
    const pair = try std.testing.allocator.create(IntentPair);
    defer std.testing.allocator.destroy(pair);
    pair.* = .{};
    defer pair.deinitInboxes();
    var opts = options(&key_a);
    opts.resolved.core.service.gossipsub.topic_policy = &.{full(@splat(0))};
    try pair.a.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.a.deinit(std.testing.io);
    opts.startup.host = &key_b;
    try pair.b.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.b.deinit(std.testing.io);
    pair.attachInboxes();
    var a_intent = intentFor(&pair.a);
    a_intent.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{ "/eth2/00000000/beacon_block/ssz_snappy", "/eth2/00000000/blob_sidecar_0/ssz_snappy", "/eth2/00000000/blob_sidecar_1/ssz_snappy" });
    var b_intent = intentFor(&pair.b);
    b_intent.subscriptions = a_intent.subscriptions;
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    const metrics = @import("metrics/export.zig");
    try pair.a.connectUntil(&pair.b.peerId(), &.{pair.b.transport.localAddress()}, pair.a.last_now, pair.a.last_now.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
    const start = pair.a.last_now.mono_ms;
    var mesh_count: usize = 0;
    for (0..3000) |_| {
        _ = try pair.pump();
        if (pair.a.last_now.mono_ms - start > 10_000) break;
        mesh_count = pair.a.service.gossipsub.resourceSnapshot().mesh_members;
        if (mesh_count == 3) break;
    }
    const context = metrics.Context.init(&pair.a, pair.a.last_now, true);
    try std.testing.expectEqual(@as(usize, 3), mesh_count);
    try std.testing.expectEqual(@as(usize, 1), context.peer_count);
    try std.testing.expectEqual(@as(u16, 1), context.scores.values.count);
    var clients: usize = 0;
    for (context.mesh_clients) |count| clients += count;
    try std.testing.expectEqual(@as(usize, 1), clients);
}

test "managed runtime local intent fork BPO announcements remembered peer and event borrows" {
    const full = @import("gossipsub/topic_fixture.zig").full;
    const old = "/eth2/00000000/beacon_block/ssz_snappy";
    const active = "/eth2/01020304/beacon_block/ssz_snappy";
    const bpo = "/eth2/05060708/beacon_block/ssz_snappy";
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{44}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{45}));
    const pair = try std.testing.allocator.create(IntentPair);
    defer std.testing.allocator.destroy(pair);
    pair.* = .{};
    defer pair.deinitInboxes();
    var opts = options(&key_a);
    opts.resolved.core.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }) };
    opts.resolved.core.service.gossipsub.topic_params = @splat(.{ .params = .{ .weight = 7 } });
    opts.resolved.core.service.reqresp.forks = &.{ .{ .digest = @splat(0), .fork = .phase0 }, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }, .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu } };
    opts.startup.local.metadata.custody_group_count = 4;
    opts.startup.local.fork.minimum_sampling_groups = @min(8, opts.startup.local.fork.custody_groups);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    try pair.a.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.a.deinit(std.testing.io);
    opts.startup.host = &key_b;
    try pair.b.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.b.deinit(std.testing.io);
    pair.attachInboxes();
    var a_intent = intentFor(&pair.a);
    a_intent.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{ old, active, bpo });
    var b_intent = intentFor(&pair.b);
    b_intent.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{old});
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    try pair.a.addDirectPeer(&pair.b.peerId(), &.{pair.b.transport.localAddress()}, pair.a.last_now);
    const start = pair.a.last_now.mono_ms;
    const gb = pair.b.service.gossipsub;
    var connected = false;
    for (0..3000) |_| {
        _ = try pair.pump();
        if (pair.a.last_now.mono_ms - start > 10_000) break;
        const ns = &gb.overlay.namespace.?;
        if (pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1 and ns.subscribed(0, ns.lookup(active).?.ordinal) and ns.subscribed(0, ns.lookup(bpo).?.ordinal) and gb.sessions.rows[0].outStream() != null and pair.a.service.gossipsub.sessions.rows[0].outStream() != null) {
            connected = true;
            break;
        }
    }
    try std.testing.expect(connected);
    try std.testing.expect(gb.overlay.findTopic(active) == null);
    const calls = pair.b.reservations.allocation_calls;
    for ([_]*runtime.LocalIntent{ &a_intent, &b_intent }) |intent| {
        intent.update.local.fork.fork = .fulu;
        intent.update.local.fork.digest = .{ 1, 2, 3, 4 };
        intent.update.local.status.fork_digest = intent.update.local.fork.digest;
        intent.update.local.status.earliest_available_slot = 0;
        intent.update.capabilities = try @import("capabilities.zig").forFork(.fulu, false, &.{ .v1_2, .v1_1 });
    }
    b_intent.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{active});
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    const activated = gb.overlay.findTopic(active).?;
    try std.testing.expectEqual(@as(f64, 7), gb.peers.scores.topic_params[activated].weight);
    try std.testing.expectEqual(@as(usize, 1), gb.overlay.subscribers(activated).count());
    const publication = try pair.b.publishGossipWithOptions(active, "0123456789", .{ .allow_zero_peers = false }, pair.b.last_now);
    try std.testing.expectEqual(@as(usize, 1), publication.queued);
    var delivered = false;
    for (0..3000) |_| {
        _ = try pair.pump();
        for (pair.a_inbox.messages()) |value| {
            try std.testing.expectEqualStrings(active, value.topic);
            try std.testing.expectEqualStrings("0123456789", value.bytes);
            delivered = true;
            _ = pair.a.reportValidation(value.handle, .accept, pair.a.last_now);
        }
        if (delivered and pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1) break;
    }
    try std.testing.expect(delivered);
    for ([_]*runtime.LocalIntent{ &a_intent, &b_intent }) |intent| {
        intent.update.local.fork.digest = .{ 5, 6, 7, 8 };
        intent.update.local.status.fork_digest = intent.update.local.fork.digest;
    }
    b_intent.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{bpo});
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    for (0..3000) |_| {
        _ = try pair.pump();
        if (pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1) break;
    }
    const borrowed_topic = gb.overlay.findTopic(bpo).?;
    try std.testing.expectEqual(@as(f64, 7), gb.peers.scores.topic_params[borrowed_topic].weight);
    var request: [24]u8 = @splat(0);
    request[8] = 1;
    request[16] = 1;
    const sink = try std.testing.allocator.alloc(u8, @import("reqresp/root.zig").Protocol.blocks_by_range_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try pair.a.sendReqRespRequest(&pair.b.peerId(), .blocks_by_range_v2, &request, sink, .{}, pair.a.last_now);
    _ = try pair.a.publishGossipWithOptions(bpo, "borrowed gossip", .{}, pair.a.last_now);
    var got_request = false;
    var got_message = false;
    for (0..3000) |_| {
        const result = try pair.pump();
        for (pair.b_app[0..result.b.counts.application]) |event| if (event == .request) {
            const bytes = event.request.bytes;
            try std.testing.expectEqualSlices(u8, &request, bytes);
            try intentBorrowUpdate(&pair.b, &b_intent);
            try std.testing.expectEqualSlices(u8, &request, bytes);
            try std.testing.expect(pair.b.finish(event.request.request, pair.b.last_now));
            got_request = true;
        };
        for (pair.b_inbox.messages()) |message| {
            try std.testing.expectEqual(@as(f64, 7), gb.peers.scores.topic_params[borrowed_topic].weight);
            try intentBorrowUpdate(&pair.b, &b_intent);
            try std.testing.expectEqualStrings(bpo, message.topic);
            try std.testing.expectEqualStrings("borrowed gossip", message.bytes);
            _ = pair.b.reportValidation(message.handle, .reject, pair.b.last_now);
            try std.testing.expect(gb.peers.scores.retainsTopic(borrowed_topic));
            got_message = true;
        }
        if (got_request and got_message) break;
    }
    try std.testing.expect(got_request and got_message);
    try std.testing.expectEqual(calls, pair.b.reservations.allocation_calls);
}

fn intentBorrowUpdate(node: *runtime.NetworkCore, desired: *runtime.LocalIntent) !void {
    desired.demand.attnets ^= 1;
    desired.subscriptions = if (desired.demand.attnets == 1) @import("gossipsub/topic_fixture.zig").subscriptions(&.{ "/eth2/05060708/beacon_block/ssz_snappy", "/eth2/05060708/voluntary_exit/ssz_snappy" }) else @import("gossipsub/topic_fixture.zig").subscriptions(&.{ "/eth2/05060708/beacon_block/ssz_snappy", "/eth2/05060708/proposer_slashing/ssz_snappy" });
    try std.testing.expect(try node.applyIntent(desired, node.last_now));
    var invalid = desired.*;
    invalid.update.local.metadata.attnets[0] ^= 1;
    invalid.subscriptions = &.{ desired.subscriptions[0], .{ .digest = @splat(255) } };
    const before = ActivationSnapshot.capture(node);
    try std.testing.expectError(error.InvalidTopic, node.applyIntent(&invalid, node.last_now));
    try before.expectUnchanged(node);
}

const BoundaryUnion = struct {
    entries: [3]@import("gossipsub/local_intent.zig").Boundary = undefined,
    len: usize = 0,

    fn fill(self: *BoundaryUnion, columns: u16) !void {
        std.debug.assert(columns <= 128);
        self.len = 0;
        for (&self.entries, [_][4]u8{ @splat(0), .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 } }) |*entry, digest| {
            entry.* = .{ .digest = digest };
            for (0..@import("gossipsub/topic_policy.zig").kind_count) |k| {
                const kind: @import("gossipsub/topic.zig").Kind = @enumFromInt(k);
                const count: u16 = switch (kind) {
                    .blob_sidecar => 0,
                    .data_column_sidecar => columns,
                    else => kind.countMax(),
                };
                entry.lengths[k] = @intCast((count + 7) / 8);
                for (0..count) |subnet| entry.mask(kind)[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
                self.len += count;
            }
        }
    }
};

test "managed runtime local intent three boundaries fit and all-column overlap refuses atomically" {
    const full = @import("gossipsub/topic_fixture.zig").full;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{46}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const union_topics = try std.testing.allocator.create(BoundaryUnion);
    defer std.testing.allocator.destroy(union_topics);
    try union_topics.fill(64);
    try std.testing.expectEqual(@as(usize, 423), union_topics.len);
    var desired = intentFor(&node);
    desired.subscriptions = &union_topics.entries;
    desired.update.local.metadata.attnets[0] = 1;
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    const before = ActivationSnapshot.capture(&node);
    const g = node.service.gossipsub;
    const revision = g.peers.scores.revision;
    const old_demand = node.peer_manager.demand;
    try union_topics.fill(128);
    try std.testing.expectEqual(@as(usize, 615), union_topics.len);
    desired.subscriptions = &union_topics.entries;
    desired.update.local.metadata.attnets[0] = 2;
    desired.demand = .{ .attnets = 3 };
    try std.testing.expectError(error.TopicCapacity, node.applyIntent(&desired, node.last_now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(old_demand, node.peer_manager.demand);
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    var count: usize = 0;
    for (g.overlay.rows) |row| if (row.subscribed) {
        count += 1;
    };
    try std.testing.expectEqual(@as(usize, 423), count);
    try std.testing.expect(g.overlay.findTopic("/eth2/05060708/data_column_sidecar_127/ssz_snappy") == null);
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
    var a: runtime.NetworkCore = undefined;
    const opts_a = options(&key_a);
    try a.init(std.testing.allocator, std.testing.io, &opts_a.resolved, opts_a.startup);
    defer a.deinit(std.testing.io);
    var b: runtime.NetworkCore = undefined;
    try b.init(std.testing.allocator, std.testing.io, &opts_b.resolved, opts_b.startup);
    defer b.deinit(std.testing.io);
    const now = try @import("transport.zig").currentTime(std.testing.io);
    try a.connectUntil(&b.peerId(), &.{b.transport.localAddress()}, now, now.mono_ms +| @import("peers/dialing.zig").connect_timeout_ms);
    var authenticated = false;
    for (0..300) |_| {
        const tick = try @import("transport.zig").currentTime(std.testing.io);
        const result = a.step(std.testing.io, tick, 100, .{}, 1);
        if (result.failure) |err| return err;
        for (a.transportEvents()) |event| if (event == .connected) {
            try std.testing.expect(event.connected.peer_id.eql(&b.peerId()));
            authenticated = true;
        };
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
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
    var node: runtime.NetworkCore = undefined;
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
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const record = node.localRecord().?;
    const quic = node.transport.udp.localAddresses();
    const decoded = try @import("peers/enr.zig").decode(record, &opts.startup.local.fork);
    try std.testing.expectEqual(@as(u8, 2), decoded.address_count);
    try std.testing.expectEqualDeep(quic[0].?, decoded.addresses[0]);
    try std.testing.expectEqualDeep(quic[1].?, decoded.addresses[1]);
    try std.testing.expectEqual(node.discovery.?.transport.sockets.values[0].?.address.getPort(), record.udp.?);
    try std.testing.expectEqual(node.discovery.?.transport.sockets.values[1].?.address.getPort(), record.udp6.?);
    try std.testing.expectEqualSlices(u8, &quic[0].?.ip4.octets, &record.ip4.?);
    try std.testing.expectEqualSlices(u8, &quic[1].?.ip6.octets, &record.ip6.?);
}

test "managed runtime candidate identities do not expose admitted APIs or enlarge snapshot capacity" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    var node: runtime.NetworkCore = undefined;
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

test "managed runtime discovery sessions expire idle lookup contacts" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{41}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const config = node.discovery.?.transport.engine.config;
    try std.testing.expectEqual(runtime.discovery_session_capacity, config.session_capacity);
    try std.testing.expectEqual(runtime.discovery_session_idle_timeout_ms, config.session_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 2_048), config.session_capacity);
    try std.testing.expectEqual(@as(u64, 600_000), config.session_idle_timeout_ms);
}
