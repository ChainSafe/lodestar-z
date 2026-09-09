const std = @import("std");
const runtime = @import("network_core.zig");
const t = @import("peers/types.zig");
const keys = @import("wire/keys.zig");
const d = @import("discv5");

fn options(key: *const keys.KeyPair) runtime.Options {
    var result: runtime.Options = .{
        .wait_mode = if (runtime.wait.supported) .native_poll else .portable,
        .transport = .{ .host = key, .bind = .{ .ip4 = .loopback(0) }, .limits = .{
            .connections_max = 4,
            .handshaking_max = 4,
            .handshaking_per_source_max = 4,
            .dialing_max = 2,
        } },
        .core = @import("core_test.zig").options(),
        .local = .{},
        .schedule = .{},
    };
    result.core.service.reqresp.outbound_per_peer_max = 4;
    result.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu },
    };
    return result;
}

test "managed runtime validates capacities and current application fork before allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    var opts = options(&key);
    opts.core.peers.engine_capacity = 5;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidOptions, node.init(failing.allocator(), std.testing.io, opts));
    opts = options(&key);
    opts.core.service.reqresp.forks = &.{};
    try std.testing.expectError(error.UnknownFork, node.init(failing.allocator(), std.testing.io, opts));
}

test "managed runtime local transaction sequences no-op schedule and rollback" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const initial = node.localRecord().?.*;
    try @import("peers/enr.zig").requireIdentity(&initial, &node.peerId());
    var local = node.localState();
    try std.testing.expect(!try node.updateLocal(&local, .{}, now));
    try std.testing.expectEqual(initial.sequence, node.localRecord().?.sequence);
    local.metadata.attnets[0] = 0x81;
    try std.testing.expect(try node.updateLocal(&local, .{}, now));
    try std.testing.expectEqual(@as(u64, 1), node.localState().metadata.seq_number);
    try std.testing.expectEqual(initial.sequence + 1, node.localRecord().?.sequence);
    local = node.localState();
    local.status.head_slot = 42;
    try std.testing.expect(try node.updateLocal(&local, .{}, now));
    try std.testing.expectEqual(@as(u64, 1), node.localState().metadata.seq_number);
    try std.testing.expectEqual(initial.sequence + 1, node.localRecord().?.sequence);
    const before = node.localRecord().?.*;
    const scheduled: runtime.ForkSchedule = .{ .fulu_scheduled = true };
    try std.testing.expectError(error.MissingCustodyAdvertisement, node.updateLocal(&local, scheduled, now));
    try std.testing.expectEqualSlices(u8, before.slice(), node.localRecord().?.slice());
    local.metadata.custody_group_count = 1;
    try std.testing.expect(try node.updateLocal(&local, scheduled, now));
    const candidate = try @import("peers/enr.zig").decode(node.localRecord().?, &local.fork);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, candidate.next_fork_digest.?);
    try std.testing.expectEqual(@as(u64, 1), candidate.custody_group_count.?);
    const invalid: runtime.ForkSchedule = .{ .fulu_scheduled = true, .next_digest = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.InvalidSchedule, node.updateLocal(&local, invalid, now));
}

test "managed runtime signed bootstrap reaches relevant peer with zero and one outputs" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{12}));
    var opts_b = options(&key_b);
    opts_b.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var b: runtime.NetworkCore = undefined;
    try b.init(std.testing.allocator, std.testing.io, opts_b);
    defer b.deinit(std.testing.io);
    var opts_a = options(&key_a);
    opts_a.discovery = opts_b.discovery;
    opts_a.discovery.?.bootstrap = &.{b.localRecord().?.*};
    var a: runtime.NetworkCore = undefined;
    try a.init(std.testing.allocator, std.testing.io, opts_a);
    defer a.deinit(std.testing.io);
    const calls_a = a.reservations.allocation_calls;
    const calls_b = b.reservations.allocation_calls;
    var events: [1]t.Event = undefined;
    var ready = false;
    const start = try @import("driver.zig").currentTime(std.testing.io);
    errdefer std.debug.print("managed scenario elapsed={}ms a={any} b={any}\n", .{ a.last_now.mono_ms -| start.mono_ms, a.peerCounts(), b.peerCounts() });
    for (0..3000) |turn| {
        const now = try @import("driver.zig").currentTime(std.testing.io);
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
    try std.testing.expect(a.diagnostics().runtime.discovered > 0);
    const hint_now = try @import("driver.zig").currentTime(std.testing.io);
    try std.testing.expect(a.futureForkHint(&b.peerId(), hint_now).?.compatible);
    const local = a.localState();
    _ = try a.updateLocal(&local, .{ .next_version = .{ 1, 1, 1, 1 }, .next_epoch = 123, .next_digest = .{ 1, 2, 3, 4 } }, hint_now);
    try std.testing.expect(!a.futureForkHint(&b.peerId(), hint_now).?.compatible);
    try std.testing.expectEqual(@as(u16, 1), a.peerCounts().relevant);
    _ = try a.updateLocal(&local, .{}, hint_now);
    try applicationAndFork(&a, &b);
    try failureAndReplacement(&a, &b);
    try std.testing.expectEqual(calls_a, a.reservations.allocation_calls);
    try std.testing.expectEqual(calls_b, b.reservations.allocation_calls);
    const now = try @import("driver.zig").currentTime(std.testing.io);
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

fn applicationAndFork(a: *runtime.NetworkCore, b: *runtime.NetworkCore) !void {
    var stage: enum { transition, application, gossip } = .transition;
    const begun = try @import("driver.zig").currentTime(std.testing.io);
    errdefer std.debug.print("managed stage={s} elapsed={}ms a={any} b={any}\n", .{ @tagName(stage), a.last_now.mono_ms -| begun.mono_ms, a.peerCounts(), b.peerCounts() });
    const rr = @import("reqresp/root.zig");
    const gossip = @import("gossipsub/root.zig");
    var rows: [4]t.Snapshot = undefined;
    const now = try @import("driver.zig").currentTime(std.testing.io);
    for ([_]*runtime.NetworkCore{ a, b }) |node| {
        var local = node.localState();
        local.fork.fork = .fulu;
        local.fork.digest = .{ 1, 2, 3, 4 };
        local.status.fork_digest = local.fork.digest;
        local.status.earliest_available_slot = 0;
        local.metadata.custody_group_count = local.fork.custody_groups;
        local.metadata.attnets[0] = 0x81;
        _ = try node.updateLocal(&local, .{ .fulu_scheduled = true }, now);
        node.reStatusPeers(now);
    }
    var peer_a: ?t.PeerRef = null;
    var peer_b: ?t.PeerRef = null;
    for (0..2000) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{}, 1);
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
        for (rows[0..a.snapshots(&rows)]) |row| {
            if (row.relevant and row.status != null and row.status.?.earliest_available_slot != null and row.custody_groups != null) peer_a = row.peer;
        }
        for (rows[0..b.snapshots(&rows)]) |row| {
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
        handle.* = try a.sendReqRespRequest(peer_a.?, protocol, request[0..protocol.info().request_min], sinks[i * sink_size ..][0..sink_size], .{ .expected_chunks = 1 }, now);
    }
    try std.testing.expectError(error.TooManyRequests, a.sendReqRespRequest(peer_a.?, .blocks_by_range_v2, &request, sinks[0..sink_size], .{}, now));
    a.reStatusPeers(now);
    b.reStatusPeers(now);
    for (0..20) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{}, 1);
        _ = b.step(std.testing.io, tick, 100, .{}, 1);
    }
    const response = [_]u8{9} ** @import("consensus_types").fulu.SignedBeaconBlock.min_size;
    var app: [1]rr.Event = undefined;
    var peer_events: [1]t.Event = undefined;
    var done: usize = 0;
    var chunks: usize = 0;
    for (0..3000) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
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
                try std.testing.expect(a.consume(value.request, tick));
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
    try a.addDirectPeer(&b.peerId(), &.{b.localAddress()}, now);
    try b.addDirectPeer(&a.peerId(), &.{a.localAddress()}, now);
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(a.subscribe(topic));
    try std.testing.expect(b.subscribe(topic));
    var messages: [1]gossip.Event = undefined;
    var got = false;
    var published = false;
    for (0..3000) |turn| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
        _ = a.step(std.testing.io, tick, 100, .{ .gossipsub = &messages }, 1);
        if (!published and turn > 20 and a.core.service.gossipsub.inner.resourceSnapshot().remote_subscriptions > 0 and
            a.core.service.gossipsub.inner.peers.rows[0].direct)
        {
            const sent = try a.publishGossipWithOptions(topic, &response, .{ .allow_zero_peers = false }, tick);
            try std.testing.expectError(error.Duplicate, a.publishGossip(topic, &response, tick));
            try std.testing.expect((try a.publishGossipWithOptions(topic, &response, .{ .ignore_duplicate = true }, tick)).duplicate);
            published = sent.queued > 0;
        }
        const received = b.step(std.testing.io, tick, 100, .{ .gossipsub = if (turn > 30) &messages else &.{} }, 1);
        for (messages[0..received.counts.gossipsub]) |event| if (event == .message) {
            try std.testing.expectEqualSlices(u8, &response, event.message.bytes);
            try std.testing.expect(b.reportValidation(event.message.handle, .accept, tick) == .applied);
            got = true;
        };
        if (got) break;
        // Native QUIC and the one-second direct-admission retry use elapsed time.
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    if (!published or !got) std.debug.print("gossip published={} received={} subscriptions={} direct={}\n", .{ published, got, a.core.service.gossipsub.inner.resourceSnapshot().remote_subscriptions, a.core.service.gossipsub.inner.peers.rows[0].direct });
    try std.testing.expect(published);
    try std.testing.expect(got);
    try std.testing.expect(a.unsubscribe(topic));
    try std.testing.expect(b.unsubscribe(topic));
    _ = a.removeDirectPeer(&b.peerId());
    _ = b.removeDirectPeer(&a.peerId());
}

test "managed runtime every allocation prefix cleans up and memory plan counts owned storage" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    opts.core.service.reqresp.request_policy = @import("reqresp/request_policy_test.zig").fixture();
    opts.core.service.reqresp.admission = .{
        .identities = opts.core.peers.capacity,
        .peer = @import("reqresp/admission_test.zig").quotas(100, 1000),
        .global = @import("reqresp/admission_test.zig").quotas(1000, 1000),
    };
    var allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var node: runtime.NetworkCore = undefined;
    try node.init(allocation.allocator(), std.testing.io, opts);
    const plan = node.memoryPlan();
    try std.testing.expectEqual(@sizeOf(@import("gossipsub/local_intent.zig").Workspace), plan.local_intent_bytes);
    try std.testing.expectEqual(@sizeOf(runtime.NetworkCore), plan.inline_bytes);
    try std.testing.expectEqual(plan.allocated_bytes, plan.transport_bytes + plan.core_bytes + plan.scratch_bytes + plan.local_intent_bytes + plan.discovery_bytes);
    std.debug.print("local intent memory: allocated={} inline={} workspace={} prefixes={} core={} transport={} scratch={} discovery={}\n", .{ plan.allocated_bytes, plan.inline_bytes, plan.local_intent_bytes, allocation.alloc_index, plan.core_bytes, plan.transport_bytes, plan.scratch_bytes, plan.discovery_bytes });
    try std.testing.expectEqual(allocation.allocated_bytes, plan.allocated_bytes);
    const allocations = allocation.alloc_index;
    const runtime_calls = node.reservations.allocation_calls;
    const now = try @import("driver.zig").currentTime(std.testing.io);
    for (0..4) |_| _ = node.step(std.testing.io, now, 0, .{}, 0);
    try std.testing.expectEqual(allocation.allocated_bytes, plan.allocated_bytes);
    try std.testing.expectEqual(runtime_calls, node.reservations.allocation_calls);
    node.deinit(std.testing.io);
    node.deinit(std.testing.io);
    try std.testing.expectEqual(allocation.allocated_bytes, allocation.freed_bytes);
    try std.testing.expect(allocations < 128);
    for (0..allocations) |index| {
        var failed = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, node.init(failed.allocator(), std.testing.io, opts));
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
    opts.local.metadata.seq_number = std.math.maxInt(u64);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const before = node.localState();
    const record = node.localRecord().?.*;
    var desired = before;
    desired.metadata.attnets[0] = 1;
    try std.testing.expectError(error.SequenceExhausted, node.updateLocal(&desired, .{}, now));
    try std.testing.expectEqualDeep(before, node.localState());
    try std.testing.expectEqual(before.fork.fork, node.core.service.reqresp.inner.request_fork);
    var schedule: runtime.ForkSchedule = .{ .next_epoch = 100, .next_version = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.SequenceExhausted, node.updateLocal(&before, schedule, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
    var candidate = try @import("peers/enr.zig").decode(&record, &before.fork);
    try std.testing.expect(!runtime.futureCompatible(&candidate, schedule));
    candidate.fork.next_epoch = schedule.next_epoch;
    candidate.fork.next_version = schedule.next_version;
    try std.testing.expect(runtime.futureCompatible(&candidate, schedule));
    schedule.next_digest = .{ 4, 3, 2, 1 };
    candidate.next_fork_digest = .{ 1, 2, 3, 4 };
    try std.testing.expect(!runtime.futureCompatible(&candidate, schedule));
    desired = before;
    desired.status.head_slot = 2;
    try std.testing.expect(try node.updateLocal(&desired, .{}, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
}

test "managed runtime demand expires before discovery submission without another borrow window" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.core.peers.target_peers = 0;
    opts.core.peers.min_outbound = 0;
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    try node.setDemand(&.{ .attnets = 1, .expires_at_slot = 5 });
    const now = try @import("driver.zig").currentTime(std.testing.io);
    _ = node.step(std.testing.io, now, 4, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), node.discovery.?.coordinator.demand.attnets[0]);
    _ = node.step(std.testing.io, now, 5, .{}, 0);
    try std.testing.expectEqual(@as(u8, 0), node.discovery.?.coordinator.demand.attnets[0]);
    _ = node.step(std.testing.io, now, 4, .{}, 0);
    try std.testing.expectEqual(@as(u8, 0), node.discovery.?.coordinator.demand.attnets[0]);
}

test "managed runtime explicit advertisement is independent atomic and required for wildcard" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.transport.bind = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } };
    opts.discovery = .{ .bind = opts.transport.bind };
    var node: runtime.NetworkCore = undefined;
    try std.testing.expectError(error.InvalidAdvertisement, node.init(std.testing.allocator, std.testing.io, opts));
    opts.discovery.?.advertisement = .{ .ip4 = .{ 127, 0, 0, 1 }, .udp = 19000, .quic = 19001 };
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const before = node.localRecord().?.*;
    var local = node.localState();
    var endpoints = node.advertisementEndpoints().?;
    endpoints.quic = 19002;
    try std.testing.expect(try node.updateLocalWithEndpoints(&local, .{}, endpoints, now));
    try std.testing.expectEqual(before.sequence + 1, node.localRecord().?.sequence);
    try std.testing.expectEqual(@as(u64, 0), node.localState().metadata.seq_number);
    try std.testing.expectEqual(@as(u16, 19002), node.advertisementEndpoints().?.quic.?);
    try std.testing.expect(!try node.updateLocalWithEndpoints(&local, .{}, endpoints, now));
    const committed = node.localRecord().?.*;
    local.metadata.attnets[0] = 1;
    endpoints.ip4 = @splat(0);
    try std.testing.expectError(error.InvalidAdvertisement, node.updateLocalWithEndpoints(&local, .{}, endpoints, now));
    try std.testing.expectEqualSlices(u8, committed.slice(), node.localRecord().?.slice());
    try std.testing.expectEqual(@as(u64, 0), node.localState().metadata.seq_number);
    for ([_]runtime.AdvertisementEndpoints{
        .{ .ip4 = .{ 0, 1, 2, 3 }, .udp = 19000, .quic = 19001 },
        .{ .ip6 = .{ 0xfe, 0x80 } ++ .{0} ** 13 ++ .{1}, .udp6 = 19000, .quic6 = 19001 },
    }) |invalid| try std.testing.expectError(error.InvalidAdvertisement, node.updateLocalWithEndpoints(&local, .{}, invalid, now));
    const privileged: runtime.AdvertisementEndpoints = .{ .ip4 = .{ 127, 0, 0, 1 }, .udp = 443, .quic = 443 };
    try std.testing.expect(try node.updateLocalWithEndpoints(&local, .{}, privileged, now));
    try std.testing.expectEqual(@as(u16, 443), node.advertisementEndpoints().?.quic.?);
    const ipv6: runtime.AdvertisementEndpoints = .{ .ip6 = .{0} ** 15 ++ .{1}, .udp6 = 19000, .quic6 = 19001 };
    try std.testing.expect(try node.updateLocalWithEndpoints(&local, .{}, ipv6, now));
    try std.testing.expect(node.localRecord().?.ip4 == null);
    try std.testing.expectEqual(ipv6.ip6, node.localRecord().?.ip6);
}

const ReceiveFault = struct {
    socket: ?std.Io.net.Socket.Handle = null,
    calls: usize = 0,
    longest_wait_ms: i64 = 0,

    threadlocal var active: ReceiveFault = .{};

    fn receive(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        if (batch.submitted.head != .none) {
            const operation = batch.storage[batch.submitted.head.toIndex()].submission.operation;
            if (operation == .net_receive) {
                active.calls += 1;
                if (timeout == .duration) active.longest_wait_ms = @max(active.longest_wait_ms, timeout.duration.raw.toMilliseconds());
                if (active.socket == operation.net_receive.socket_handle) return error.Canceled;
            }
        }
        return std.testing.io.vtable.batchAwaitConcurrent(userdata, batch, timeout);
    }
};

fn noEntropy(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
    return error.EntropyUnavailable;
}

fn unreachableSend(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
    return .{ error.AddressFamilyUnsupported, 0 };
}

test "managed runtime unreachable destination backs off and rotates to its alternate address" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const remote = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, options(&key));
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const peer = t.PeerId.fromPublicKey(&remote.publicKey());
    try node.connect(&peer, &.{
        .{ .ip6 = .{ .octets = .{0} ** 15 ++ .{1}, .port = 19003 } },
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } },
    }, now);
    var vtable = std.testing.io.vtable.*;
    vtable.netSend = unreachableSend;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    const refused = node.step(io, now, 0, .{}, 0);
    try std.testing.expectEqual(error.DestinationUnreachable, refused.failure.?);
    try std.testing.expectEqual(@as(u8, 1), refused.dial_failed);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_deferred);
    const row = &node.core.dial_queue.rows[0];
    try std.testing.expectEqual(@as(u8, 1), row.failures);
    try std.testing.expectEqual(@as(u8, 1), row.address_index);
    try std.testing.expect(!row.attempt);
    try std.testing.expect(row.eligible_at_ms >= now.mono_ms + 1000);
    const retry: @import("types.zig").Now = .{ .mono_ms = row.eligible_at_ms, .unix_s = now.unix_s };
    const result = node.step(std.testing.io, retry, 0, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), result.dial_started);
    try std.testing.expect(row.conn != null);
}

test "managed runtime socket faults preserve the other owner and local dial refusal is deferred" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    const remote_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .coordinator = .{ .query_interval_ms = 100 } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    var vtable = std.testing.io.vtable.*;
    vtable.batchAwaitConcurrent = ReceiveFault.receive;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    for ([_]std.Io.net.Socket.Handle{ node.transport.udp.socket.handle, node.discovery.?.udp.socket.handle }) |socket| {
        ReceiveFault.active = .{ .socket = socket };
        const result = node.step(io, now, 0, .{}, 1000);
        try std.testing.expectEqual(error.Canceled, result.failure.?);
        try std.testing.expect(ReceiveFault.active.calls >= 2);
        try std.testing.expect(ReceiveFault.active.longest_wait_ms <= runtime.poll_wait_max_ms);
        try std.testing.expect(node.last_now.mono_ms >= now.mono_ms);
        try std.testing.expect(node.transport.udp.admitted == null);
        try std.testing.expect(node.discovery.?.udp.admitted == null);
    }
    ReceiveFault.active = .{};
    const idle = node.step(std.testing.io, now, 0, .{}, 0);
    try std.testing.expect(idle.failure == null);
    const settled = node.last_now;
    const discovery_due = node.discovery.?.coordinator.nextWakeup(settled.mono_ms).?;
    try std.testing.expect(discovery_due > settled.mono_ms);
    try std.testing.expectEqual(discovery_due, node.nextWakeup(settled, .{}).?);
    const protocol_due = node.core.nextWakeup(settled, 0, 0, 0, 4);
    try std.testing.expect(protocol_due == null or protocol_due.? > discovery_due);
    const peer = t.PeerId.fromPublicKey(&remote_key.publicKey());
    try node.connect(&peer, &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19003 } }}, now);
    try std.testing.expectEqual(now.mono_ms, node.nextWakeup(now, .{}).?);
    vtable.randomSecure = noEntropy;
    const refused = node.step(io, now, 0, .{}, 0);
    try std.testing.expectEqual(@as(u8, 1), refused.dial_deferred);
    try std.testing.expectEqual(error.EntropyUnavailable, refused.failure.?);
    try std.testing.expectEqual(@as(u8, 0), refused.dial_started);
    for (node.core.dial_queue.rows) |row| if (row.occupied) {
        try std.testing.expectEqual(@as(u8, 0), row.failures);
        try std.testing.expect(!row.attempt);
    };
    const calls = node.reservations.allocation_calls;
    const clean = node.step(std.testing.io, now, 0, .{}, 0);
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

fn failureAndReplacement(a: *runtime.NetworkCore, b: *runtime.NetworkCore) !void {
    var snapshots: [4]t.Snapshot = undefined;
    const count = a.snapshots(&snapshots);
    var target: ?t.PeerRef = null;
    for (snapshots[0..count]) |snapshot| if (snapshot.connection != null) {
        target = snapshot.peer;
    };
    const now = try @import("driver.zig").currentTime(std.testing.io);
    try std.testing.expectEqual(t.ReputationDecision.ban, a.reportPeer(target.?, .fatal, now).?);
    var vtable = std.testing.io.vtable.*;
    vtable.batchAwaitConcurrent = ReceiveFault.receive;
    const faulty_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    ReceiveFault.active = .{ .socket = a.transport.udp.socket.handle };
    const deadline = a.core.control.schedules[target.?.index].closing.?.deadline_ms;
    var after_deadline = now;
    after_deadline.mono_ms = deadline;
    const result = a.step(faulty_io, after_deadline, 100, .{}, 0);
    try std.testing.expectEqual(error.Canceled, result.failure.?);
    try std.testing.expectEqual(@as(u16, 0), a.peerCounts().relevant);
    try std.testing.expect(a.core.catalog.get(target.?).?.connection == null);
    for (0..100) |_| {
        _ = a.step(std.testing.io, a.last_now, 100, .{}, 0);
        _ = b.step(std.testing.io, now, 100, .{}, 0);
        if (a.peerCounts().connected == 0) break;
    }
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.local = a.localState();
    opts.schedule = a.schedule;
    var replacement: runtime.NetworkCore = undefined;
    try replacement.init(std.testing.allocator, std.testing.io, opts);
    defer replacement.deinit(std.testing.io);
    try replacement.connect(&a.peerId(), &.{a.localAddress()}, now);
    for (0..2000) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
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
    try std.testing.expect(replacement.diagnostics().runtime.dial_started > 0);
    replacement.shutdown(now);
}

test "managed profiles measure reservations and unwind byte exhaustion" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    inline for (.{ @import("configuration.zig").Profile.small, .beacon_node }) |profile| {
        var ledger: @import("reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var opts: runtime.ManagedOptions = .{
            .host = &key,
            .bind = .{ .ip4 = .loopback(0) },
            .local = .{},
            .configuration = .{ .profile = profile, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }} },
        };
        var node: runtime.NetworkCore = undefined;
        try node.initManaged(ledger.allocator(), std.testing.io, opts);
        const measured = ledger.bytes;
        try std.testing.expectEqual(measured, node.memoryPlan().allocated_bytes);
        try std.testing.expect(measured <= node.reservations.byte_limit.?);
        node.deinit(std.testing.io);
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
        opts.configuration.byte_limit = measured - 1;
        try std.testing.expectError(error.OutOfMemory, node.initManaged(ledger.allocator(), std.testing.io, opts));
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
        opts.configuration.byte_limit = measured;
        try node.initManaged(ledger.allocator(), std.testing.io, opts);
        node.deinit(std.testing.io);
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
    }
}

test "managed small profile cleans every failed allocation prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, profileAllocationFailures, .{});
}

fn profileAllocationFailures(a: std.mem.Allocator) !void {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    var node: runtime.NetworkCore = undefined;
    try node.initManaged(a, std.testing.io, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{},
        .configuration = .{ .profile = .small, .seed = 1, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }} },
    });
    node.deinit(std.testing.io);
}

test "managed invalid complete sections reject before allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    const forks: []const @import("reqresp/reqresp.zig").ForkEntry = &.{.{ .digest = @splat(0), .fork = .phase0 }};
    const base = try @import("configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = forks });
    inline for (.{ error.InvalidOptions, error.InvalidOptions, error.InvalidQuota, error.InvalidOptions, error.InvalidLimits, error.InvalidLimits, error.InvalidLimits, error.InvalidOptions }, 0..) |expected, section| {
        var request: @import("configuration.zig").Request = .{ .profile = .small, .seed = 1, .forks = forks };
        switch (section) {
            0 => {
                var requests = base.core.service.reqresp;
                requests.work_per_pump_max = 0;
                request.reqresp = requests;
            },
            1 => request.control = .{ .ping_inbound_ms = 0 },
            2 => {
                var requests = base.core.service.reqresp;
                var quotas = @import("reqresp/limiter.zig").defaultQuotas();
                quotas[0].period_ms = 0;
                requests.global_quotas = quotas;
                request.reqresp = requests;
            },
            3 => request.dial = .{ .seed = 1, .concurrent_max = 0 },
            4 => request.router = .{ .meshsub = false },
            5 => {
                var gossip_options = base.core.service.gossipsub;
                gossip_options.score_params.decay_interval_ms = 0;
                request.gossip = gossip_options;
            },
            6 => request.limits = .{ .handshaking_max = 0 },
            7 => request.peers = .{ .capacity = 0 },
            else => unreachable,
        }
        var ledger: @import("reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var node: runtime.NetworkCore = undefined;
        try std.testing.expectError(expected, node.initManaged(ledger.allocator(), std.testing.io, .{ .host = &key, .bind = .{ .ip4 = .loopback(0) }, .local = .{}, .configuration = request }));
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
        try std.testing.expectEqual(@as(usize, 0), ledger.allocation_calls);
    }
}

test "managed runtime native readiness wakes for either delayed protocol socket" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    var opts = options(&key);
    opts.wait_mode = .native_poll;
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    for (0..2) |source| {
        for (0..2) |_| {
            const settled = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 0);
            try std.testing.expect(settled.failure == null);
        }
        const target = if (source == 0) node.transport.udp.socket else node.discovery.?.udp.socket;
        const generation = if (source == 0) node.transport.udp.next_generation else node.discovery.?.udp.next_generation;
        const task = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ sender, target.address });
        defer task.join();
        const result = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 100);
        try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(generation + 1, if (source == 0) node.transport.udp.next_generation else node.discovery.?.udp.next_generation);
        try std.testing.expect(node.transport.udp.admitted == null and node.discovery.?.udp.admitted == null);
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
    opts.wait_mode = .native_poll;
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const host = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer host.close(std.testing.io);
    try node.setHostWake(host.handle);
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(-1));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.transport.udp.socket.handle));
    try std.testing.expectError(error.InvalidWakeSource, node.setHostWake(node.discovery.?.udp.socket.handle));
    _ = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 0);
    const sender = try std.Thread.spawn(.{}, delayedRuntimeDatagram, .{ host, host.address });
    defer sender.join();
    const result = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 100);
    try std.testing.expect(result.failure == null and result.readiness.host);
    const repeated = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 0);
    try std.testing.expect(repeated.readiness.host);
    try std.testing.expectEqual(@as(u32, 0), repeated.readiness.timeout_ms);
    try node.setHostWake(null);
    const detached = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 0);
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
    opts.wait_mode = .portable;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    try std.testing.expectError(error.UnsupportedWait, node.setHostWake(1));
    try node.setHostWake(null);
    const result = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 0);
    try std.testing.expect(result.failure == null);
    try std.testing.expectEqual(@as(u64, 0), node.diagnostics().runtime.readiness_calls);
}

test "managed runtime native wait source failure retains completed protocol progress" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{34}));
    var opts = options(&key);
    opts.wait_mode = .native_poll;
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    var pipe: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.pipe(&pipe));
    defer _ = std.c.close(pipe[0]);
    try node.setHostWake(pipe[0]);
    try std.testing.expectEqual(@as(c_int, 0), std.c.close(pipe[1]));
    try node.transport.udp.socket.send(std.testing.io, &node.transport.udp.socket.address, "invalid");
    try node.transport.udp.socket.send(std.testing.io, &node.discovery.?.udp.socket.address, "invalid");
    const allocations = node.reservations.allocation_calls;
    const result = node.step(std.testing.io, try @import("driver.zig").currentTime(std.testing.io), 0, .{}, 100);
    try std.testing.expectEqual(error.WaitSourceClosed, result.failure.?);
    try std.testing.expect(result.readiness.quic and result.readiness.discovery);
    try std.testing.expectEqual(@as(u32, 1), result.transport.datagrams_received);
    try std.testing.expectEqual(@as(u64, 2), node.discovery.?.udp.next_generation);
    try std.testing.expect(node.transport.udp.admitted == null and node.discovery.?.udp.admitted == null);
    try std.testing.expectEqual(allocations, node.reservations.allocation_calls);
    try node.setHostWake(null);
    const clean = node.step(std.testing.io, node.last_now, 0, .{}, 0);
    try std.testing.expect(clean.failure == null);
    try std.testing.expectEqual(@as(u64, 1), node.diagnostics().runtime.readiness_failures);
}

test "managed runtime native wait honors pacing native timers and pending lifecycle work" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{35}));
    var opts = options(&key);
    opts.wait_mode = .native_poll;
    opts.transport.limits.handshake_timeout_ms = 80;
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const remote = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer remote.close(std.testing.io);
    const destination = @import("udp.zig").fromNetwork(remote.address);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const handle = try node.transport.engine.dial(&destination, node.peerId(), now, @splat(17));
    const first = node.step(std.testing.io, now, 0, .{}, 100);
    try std.testing.expect(first.failure == null);
    try std.testing.expectEqual(@as(u32, 0), first.readiness.timeout_ms);
    try std.testing.expect(first.transport.datagrams_sent > 0);
    const current = node.last_now;
    var paced_bytes = "paced".*;
    try node.transport.driver.pending.put(handle, .{
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
    const failed = try node.transport.engine.dial(&destination, node.peerId(), node.last_now, @splat(18));
    node.transport.engine.driverView().failSend(failed.index);
    _ = node.transport.engine.driverView().takeHostWork();
    try std.testing.expect(node.transport.engine.eventsPending());
    const lifecycle = node.step(std.testing.io, node.last_now, 0, .{}, 100);
    try std.testing.expect(lifecycle.failure == null);
    try std.testing.expectEqual(@as(u32, 0), lifecycle.readiness.timeout_ms);
    try std.testing.expect(lifecycle.transport.events > 0);
    const repeated = node.step(std.testing.io, node.last_now, 0, .{}, 0);
    try std.testing.expectEqual(@as(usize, 0), repeated.transport.events);
}

test "managed runtime topic policy copies values and rejects atomically" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, options(&key));
    defer node.deinit(std.testing.io);
    const calls = node.reservations.allocation_calls;
    const initial = node.diagnostics();
    try std.testing.expectEqual(@as(usize, 4), initial.transport_resources.capacity);
    try std.testing.expectEqual(@as(usize, 0), initial.transport_resources.active);
    try std.testing.expectEqual(@as(usize, 0), initial.core.dialing.custody_incomplete);
    const revision_before_read = node.core.service.gossipsub.inner.scores.revision;
    try std.testing.expectEqualDeep(initial, node.diagnostics());
    try std.testing.expectEqual(revision_before_read, node.core.service.gossipsub.inner.scores.revision);
    var params: @import("gossipsub/score.zig").TopicParams = .{ .weight = 2 };
    var text = "/eth2/ABCDEF00/custom/name/ssz_snappy".*;
    try node.configureTopic(&text, &params);
    params.weight = 3;
    text[6] = '0';
    const owner = &node.core.service.gossipsub.inner;
    try std.testing.expectEqual(@as(f64, 2), owner.scores.topic_params[0].weight);
    try std.testing.expectEqualStrings("/eth2/ABCDEF00/custom/name/ssz_snappy", owner.state.topicString(0));
    const revision = owner.scores.revision;
    try std.testing.expectError(error.InvalidLimits, node.configureTopic(&text, &.{ .weight = std.math.nan(f64) }));
    try std.testing.expectError(error.InvalidTopic, node.configureTopic("bad", &.{}));
    try std.testing.expectEqual(revision, owner.scores.revision);
    try std.testing.expectEqual(@as(u64, 1), owner.state.topics[0].generation);
    for (0..@import("gossipsub/constants.zig").topics_cap) |index| {
        var name: [@import("gossipsub/topic.zig").topic_max_len]u8 = undefined;
        const topic = try std.fmt.bufPrint(&name, "/eth2/{x:0>8}/custom/ssz_snappy", .{index});
        try std.testing.expect(node.subscribe(topic));
    }
    const full_revision = owner.scores.revision;
    try std.testing.expectError(error.TopicCapacity, node.configureTopic("/eth2/ffffffff/custom/ssz_snappy", &.{}));
    try std.testing.expectEqual(full_revision, owner.scores.revision);
    node.shutdown(node.last_now);
    try std.testing.expectError(error.Stopped, node.configureTopic("bad", &.{}));
    try std.testing.expectEqual(full_revision, owner.scores.revision);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

test "managed beacon idle scans do not manufacture immediate deadlines" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    var node: runtime.NetworkCore = undefined;
    try node.initManaged(std.testing.allocator, std.testing.io, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = .{},
        .configuration = .{ .profile = .beacon_node, .seed = 7, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }} },
    });
    defer node.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    const calls = node.reservations.allocation_calls;
    for (0..8) |_| {
        const result = node.step(std.testing.io, now, 100, .{}, 0);
        try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(@as(?u64, null), node.core.service.reqresp.inner.nextWakeup(now, 0));
        try std.testing.expect(node.nextWakeup(now, .{}).? > now.mono_ms);
    }
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

test "managed runtime BPO same-fork digest transition updates status and advertisement" {
    const rr = @import("reqresp/reqresp.zig");
    const first: rr.ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
    const second: rr.ForkEntry = .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu };
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    try node.initManaged(std.testing.allocator, std.testing.io, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .configuration = .{ .profile = .small, .seed = 1, .forks = &.{ first, second } },
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
    try std.testing.expectEqual(first.fork, node.core.service.reqresp.inner.request_fork);
    local.fork.digest = second.digest;
    local.status.fork_digest = second.digest;
    try std.testing.expect(try node.updateLocal(&local, .{}, try @import("driver.zig").currentTime(std.testing.io)));
    try std.testing.expectEqual(second.digest, node.localState().status.fork_digest);
    try std.testing.expectEqual(second.digest, node.localState().fork.digest);
    try std.testing.expectEqual(second.fork, node.localState().fork.fork);
    try std.testing.expectEqual(second.fork, node.core.service.reqresp.inner.request_fork);
    try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    const candidate = try @import("peers/enr.zig").decode(node.localRecord().?, &local.fork);
    try std.testing.expectEqual(second.digest, candidate.fork.digest);
    for ([_]rr.ForkEntry{
        .{ .digest = .{ 9, 9, 9, 9 }, .fork = .fulu },
        .{ .digest = second.digest, .fork = .gloas },
    }) |invalid| {
        local.fork = .{ .digest = invalid.digest, .fork = invalid.fork };
        local.status.fork_digest = invalid.digest;
        try std.testing.expectError(error.UnknownFork, node.updateLocal(&local, .{}, node.last_now));
        try std.testing.expectEqual(second.digest, node.localState().status.fork_digest);
        try std.testing.expectEqual(second.fork, node.localState().fork.fork);
        try std.testing.expectEqual(second.fork, node.core.service.reqresp.inner.request_fork);
        try std.testing.expectEqual(initial + 1, node.localRecord().?.sequence);
    }
}

test "managed runtime BPO duplicate digest validation precedes allocation" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var node: runtime.NetworkCore = undefined;
    var opts = options(&key);
    opts.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = @splat(0), .fork = .fulu },
    };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidOptions, node.init(failing.allocator(), std.testing.io, opts));
}

test "managed runtime request admission selector commits with validated local fork" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.core.service.reqresp.request_fork = .gloas;
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    try std.testing.expectEqual(t.ForkSeq.phase0, node.core.service.reqresp.inner.request_fork);
    var local = node.localState();
    local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    local.status.fork_digest = local.fork.digest;
    local.status.earliest_available_slot = 0;
    local.metadata.custody_group_count = 1;
    const now = try @import("driver.zig").currentTime(std.testing.io);
    try std.testing.expect(try node.updateLocal(&local, .{}, now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.core.service.reqresp.inner.request_fork);
    local.fork.fork = .gloas;
    try std.testing.expectError(error.UnknownFork, node.updateLocal(&local, .{}, now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.core.service.reqresp.inner.request_fork);
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
            .capabilities = node.core.service.router.capabilities(),
            .request_fork = node.core.service.reqresp.inner.request_fork,
            .record = node.localRecord().?.*,
        };
    }

    fn expectUnchanged(self: *const ActivationSnapshot, node: *const runtime.NetworkCore) !void {
        try std.testing.expectEqualDeep(self.local, node.localState());
        try std.testing.expectEqualDeep(self.schedule, node.schedule);
        try std.testing.expectEqualDeep(self.endpoints, node.advertisementEndpoints());
        try std.testing.expectEqualDeep(self.capabilities, node.core.service.router.capabilities());
        try std.testing.expectEqual(self.request_fork, node.core.service.reqresp.inner.request_fork);
        try std.testing.expectEqual(self.record.sequence, node.localRecord().?.sequence);
        try std.testing.expectEqualSlices(u8, self.record.slice(), node.localRecord().?.slice());
    }
};

test "managed runtime capabilities activation rolls back all owners on rejected candidates" {
    const caps = @import("capabilities.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.core.service.router.meshsub_versions = &.{.v1_2};
    opts.core.service.router.capabilities = try caps.forFork(.phase0, false, &.{.v1_2});
    opts.local.metadata.custody_group_count = 1;
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const before = ActivationSnapshot.capture(&node);
    const now = node.last_now;
    var update: runtime.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
    update.local.status.head_slot = 10;
    update.endpoints.?.quic = 443;
    update.capabilities.request.insert(.{ .meshsub = .v1_0 });
    try std.testing.expectError(error.InvalidCapabilities, node.applyLocal(&update, now));
    try before.expectUnchanged(&node);
    update.capabilities = try caps.forFork(.fulu, false, &.{.v1_2});
    update.local.fork.fork = .fulu;
    update.local.status.earliest_available_slot = 0;
    try std.testing.expectError(error.UnknownFork, node.applyLocal(&update, now));
    try before.expectUnchanged(&node);
    update.local.fork.digest = .{ 1, 2, 3, 4 };
    update.local.status.fork_digest = update.local.fork.digest;
    try std.testing.expectError(error.SequenceExhausted, node.applyLocal(&update, now));
    try before.expectUnchanged(&node);
}

test "managed runtime capabilities activation commits fork BPO and copied directional values" {
    const caps = @import("capabilities.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{25}));
    var opts = options(&key);
    opts.local.metadata.custody_group_count = 1;
    const quotas = @import("reqresp/admission_test.zig").quotas(2048, 1000);
    opts.core.service.reqresp.request_policy = @import("reqresp/request_policy_test.zig").fixture();
    opts.core.service.reqresp.admission = .{ .identities = 2, .peer = quotas, .global = quotas };
    opts.core.service.router.capabilities = try caps.forFork(.phase0, true, &.{ .v1_2, .v1_1 });
    opts.core.service.reqresp.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu },
        .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu },
    };
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const limiter = &node.core.service.reqresp.inner.limiter;
    const peer: t.Handle = .{ .index = 0, .generation = 1 };
    limiter.bind(peer, node.last_now.mono_ms);
    try std.testing.expect(limiter.take(peer, .blocks_by_root_v2, 1, node.last_now.mono_ms));
    const debt = limiter.global;
    const admission = &node.core.service.reqresp.inner.admission.?;
    const identity = node.peerId();
    try std.testing.expectEqual(.allowed, admission.take(&identity, .blocks_by_root_v2, 1, .phase0, node.last_now.mono_ms));
    const admitted_debt = admission.global;
    const admitted_row = admission.rows[0];
    const allocations = node.reservations.allocation_calls;
    const before = ActivationSnapshot.capture(&node);
    var update: runtime.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
    update.capabilities.request = .initEmpty();
    try std.testing.expect(try node.applyLocal(&update, node.last_now));
    try std.testing.expectEqualDeep(before.local, node.localState());
    try std.testing.expectEqual(before.record.sequence, node.localRecord().?.sequence);
    try std.testing.expect(!try node.applyLocal(&update, node.last_now));
    update.local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    update.local.status.fork_digest = update.local.fork.digest;
    update.local.status.earliest_available_slot = 0;
    update.capabilities = try caps.forFork(.fulu, false, &.{ .v1_2, .v1_1 });
    try std.testing.expect(try node.applyLocal(&update, node.last_now));
    try std.testing.expectEqual(t.ForkSeq.fulu, node.core.service.reqresp.inner.request_fork);
    const active = node.core.service.router.capabilities();
    try std.testing.expect(active.receive.contains(.{ .reqresp = .status_v2 }));
    try std.testing.expect(!active.receive.contains(.{ .reqresp = .status_v1 }));
    try std.testing.expect(!active.receive.contains(.{ .reqresp = .metadata_v2 }));
    try std.testing.expect(active.receive.contains(.{ .reqresp = .metadata_v3 }));
    try std.testing.expect(!active.receive.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    try std.testing.expect(active.request.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    update.local.fork.digest = .{ 5, 6, 7, 8 };
    update.local.status.fork_digest = update.local.fork.digest;
    try std.testing.expect(try node.applyLocal(&update, node.last_now));
    try std.testing.expectEqualDeep(active, node.core.service.router.capabilities());
    try std.testing.expectEqual(before.record.sequence + 2, node.localRecord().?.sequence);
    try std.testing.expectEqual(before.local.metadata.seq_number, node.localState().metadata.seq_number);
    try std.testing.expectEqualDeep(debt, limiter.global);
    try std.testing.expectEqualDeep(admitted_debt, admission.global);
    try std.testing.expectEqualDeep(admitted_row, admission.rows[0]);
    try std.testing.expectEqual(allocations, node.reservations.allocation_calls);
    const committed = ActivationSnapshot.capture(&node);
    try std.testing.expect(!try node.applyLocal(&update, node.last_now));
    update.local.metadata.attnets[0] = 1;
    update.capabilities.receive = .initEmpty();
    update.endpoints.?.quic = 443;
    update.schedule.next_epoch = 5;
    try committed.expectUnchanged(&node);
    try std.testing.expect(try node.updateLocal(&update.local, .{}, node.last_now));
    try std.testing.expectEqualDeep(active, node.core.service.router.capabilities());
    try std.testing.expectEqual(before.local.metadata.seq_number + 1, node.localState().metadata.seq_number);
}

test "identify managed advertisement follows committed endpoints and rejected updates preserve it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.core.service.identify = .{ .agent = "managed", .addresses = &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19009 } }} };
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{ .session_capacity = 8, .challenge_capacity = 8, .call_capacity = 8 } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const initial = node.core.service.identify.?.local.?;
    const address = try @import("wire/multiaddr.zig").Multiaddr.decode(initial.addresses[0].bytes[0..initial.addresses[0].len]);
    try std.testing.expectEqual(node.transport.localAddress(), address.address);
    var endpoints = node.advertisementEndpoints().?;
    endpoints.quic = 443;
    const now = node.last_now;
    try std.testing.expect(try node.updateLocalWithEndpoints(&node.core.local, node.schedule, endpoints, now));
    const updated = node.core.service.identify.?.local.?;
    const next = try @import("wire/multiaddr.zig").Multiaddr.decode(updated.addresses[0].bytes[0..updated.addresses[0].len]);
    try std.testing.expectEqual(@as(u16, 443), next.address.port());
    endpoints.quic = 0;
    try std.testing.expectError(error.InvalidAdvertisement, node.updateLocalWithEndpoints(&node.core.local, node.schedule, endpoints, now));
    try std.testing.expectEqualDeep(updated, node.core.service.identify.?.local.?);
}

test "managed runtime targeted Status serves two current schedules and immediate close is local" {
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{31}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{32}));
    const key_c = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{33}));
    var a: runtime.NetworkCore = undefined;
    var b: runtime.NetworkCore = undefined;
    var c: runtime.NetworkCore = undefined;
    var opts = options(&key_a);
    opts.core.service.identify = .{ .agent = "peer-operations" };
    try a.init(std.testing.allocator, std.testing.io, opts);
    defer a.deinit(std.testing.io);
    opts = options(&key_b);
    opts.core.service.identify = .{ .agent = "peer-operations" };
    try b.init(std.testing.allocator, std.testing.io, opts);
    defer b.deinit(std.testing.io);
    opts = options(&key_c);
    opts.core.service.identify = .{ .agent = "peer-operations" };
    try c.init(std.testing.allocator, std.testing.io, opts);
    defer c.deinit(std.testing.io);
    const start = try @import("driver.zig").currentTime(std.testing.io);
    try a.addDirectPeer(&b.peerId(), &.{b.transport.localAddress()}, start);
    try a.addDirectPeer(&c.peerId(), &.{c.transport.localAddress()}, start);
    var rows: [4]t.Snapshot = undefined;
    var ready = false;
    for (0..3000) |_| {
        const now = try @import("driver.zig").currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        for ([_]*runtime.NetworkCore{ &a, &b, &c }) |node| {
            const result = node.step(std.testing.io, now, 100, .{}, 1);
            if (result.failure) |err| return err;
        }
        const count = a.snapshots(&rows);
        if (count == 2 and a.peerCounts().relevant == 2 and rows[0].identify != null and rows[1].identify != null and
            a.core.control.resourceSnapshot().operations == 0)
        {
            ready = true;
            break;
        }
    }
    try std.testing.expect(ready);
    const calls = a.reservations.allocation_calls;
    const selected = rows[0];
    const other = rows[1];
    const now = try @import("driver.zig").currentTime(std.testing.io);
    a.core.control.schedules[other.peer.index].status_due_ms = now.mono_ms;
    const unselected = a.core.control.schedules[other.peer.index];
    const before = a.core.control.schedules[selected.peer.index];
    try std.testing.expect(a.reStatusPeer(selected.peer, selected.connection.?, now));
    var expected = before;
    expected.status_due_ms = now.mono_ms;
    try std.testing.expectEqualDeep(expected, a.core.control.schedules[selected.peer.index]);
    try std.testing.expectEqualDeep(unselected, a.core.control.schedules[other.peer.index]);
    const result = a.step(std.testing.io, now, 100, .{}, 0);
    if (result.failure) |err| return err;
    var status_started: usize = 0;
    for (a.core.control.operations) |op| if (op.request != null and op.protocol == .status_v1) {
        status_started += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), status_started);
    try std.testing.expectEqual(before.identify_state, a.core.control.schedules[selected.peer.index].identify_state);
    try std.testing.expect(a.closePeer(selected.peer, selected.connection.?, now));
    try std.testing.expect(!a.reStatusPeer(selected.peer, selected.connection.?, now));
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
    try replacement.init(std.testing.allocator, std.testing.io, options(&key));
    defer replacement.deinit(std.testing.io);
    var events: [4]t.Event = undefined;
    _ = a.core.catalog.pollEvents(&events);
    const start = try @import("driver.zig").currentTime(std.testing.io);
    try a.addDirectPeer(&replacement.peerId(), &.{replacement.transport.localAddress()}, start);
    var current: ?t.Snapshot = null;
    for (0..3000) |_| {
        const now = try @import("driver.zig").currentTime(std.testing.io);
        if (now.mono_ms - start.mono_ms > 10_000) break;
        for ([_]*runtime.NetworkCore{ a, b, c, &replacement }) |node| {
            const result = node.step(std.testing.io, now, 100, .{ .peers = &events }, 1);
            if (result.failure) |err| return err;
        }
        const ref = a.core.catalog.find(&replacement.peerId()) orelse continue;
        const row = a.core.catalog.get(ref).?;
        if (!row.relevant) continue;
        current = row;
        break;
    }
    const selected = current orelse return error.ReplacementNotReady;
    try std.testing.expectEqual(previous.peer.index, selected.peer.index);
    try std.testing.expect(previous.peer.generation != selected.peer.generation);
    try std.testing.expect(!a.closePeer(previous.peer, selected.connection.?, a.last_now));
    try std.testing.expect(!a.reStatusPeer(previous.peer, selected.connection.?, a.last_now));
    try std.testing.expect(!a.closePeer(selected.peer, previous.connection.?, a.last_now));
    try std.testing.expect(!a.reStatusPeer(selected.peer, previous.connection.?, a.last_now));
    try std.testing.expectEqualDeep(selected, a.core.catalog.get(selected.peer).?);
    try std.testing.expect(a.closePeer(selected.peer, selected.connection.?, a.last_now));
}

test "managed runtime complete local intent rejects invalid last topic atomically" {
    const gossip = @import("gossipsub/root.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{41}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.core.service.identify = .{ .agent = "local-intent" };
    opts.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_policy_test.zig").full(.{ 1, 2, 3, 4 })};
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const block_topic = "/eth2/01020304/beacon_block/ssz_snappy";
    const update: runtime.LocalUpdate = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.core.service.router.capabilities() };
    var desired: runtime.LocalIntent = .{ .update = update, .demand = .{}, .subscriptions = &.{.{ .name = block_topic, .params = .{} }} };
    const now = node.last_now;
    try std.testing.expect(try node.applyIntent(&desired, now));
    try std.testing.expect(!(try node.applyIntent(&desired, now)));
    const before = ActivationSnapshot.capture(&node);
    const identify = node.core.service.identify.?.local;
    const demand = node.core.demand;
    const g = &node.core.service.gossipsub.inner;
    const topic = g.state.findTopic(block_topic).?;
    const params = g.scores.topic_params[topic];
    desired.update.local.metadata.attnets[0] = 1;
    desired.subscriptions = &[_]gossip.local_intent.Subscription{
        .{ .name = block_topic, .params = .{ .weight = 2 } },
        .{ .name = "invalid", .params = .{} },
    };
    try std.testing.expectError(error.InvalidTopic, node.applyIntent(&desired, now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(identify, node.core.service.identify.?.local);
    try std.testing.expectEqualDeep(demand, node.core.demand);
    try std.testing.expectEqualDeep(params, g.scores.topic_params[topic]);
    try std.testing.expect(g.state.subscribed(topic));
    try std.testing.expectEqual(@as(?u16, topic), g.state.findTopic(block_topic));
}

fn intentFor(node: *const runtime.NetworkCore) runtime.LocalIntent {
    return .{
        .update = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.core.service.router.capabilities() },
        .demand = node.core.demand,
        .subscriptions = &.{},
    };
}

test "managed runtime local intent demand candidate sequence and stopped refusals" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{42}));
    for (0..2) |exhausted| {
        var opts = options(&key);
        opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = if (exhausted == 0) std.math.maxInt(u64) else 1 };
        if (exhausted == 1) opts.local.metadata.seq_number = std.math.maxInt(u64);
        opts.core.service.identify = .{ .agent = "local-intent" };
        opts.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_policy_test.zig").full(.{ 1, 2, 3, 4 })};
        var node: runtime.NetworkCore = undefined;
        try node.init(std.testing.allocator, std.testing.io, opts);
        defer node.deinit(std.testing.io);
        const before = ActivationSnapshot.capture(&node);
        const identify = node.core.service.identify.?.local;
        const g = &node.core.service.gossipsub.inner;
        const revision = g.scores.revision;
        var desired = intentFor(&node);
        desired.subscriptions = &.{.{ .name = "/eth2/01020304/beacon_block/ssz_snappy", .params = .{ .weight = 2 } }};
        desired.update.local.fork.custody_groups = 1;
        desired.demand.group_targets[1] = 1;
        try desired.demand.validate(&node.core.local.fork, node.core.catalog.options.max_peers);
        try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
        desired.update.local.fork = node.core.local.fork;
        desired.demand.group_targets[1] = node.core.catalog.options.max_peers + 1;
        try std.testing.expectError(error.InvalidDemand, node.applyIntent(&desired, node.last_now));
        desired.demand = .{ .attnets = 1, .expires_at_slot = 100 };
        desired.update.local.metadata.attnets[0] = 1;
        try std.testing.expectError(error.SequenceExhausted, node.applyIntent(&desired, node.last_now));
        try before.expectUnchanged(&node);
        try std.testing.expectEqualDeep(identify, node.core.service.identify.?.local);
        try std.testing.expectEqualDeep(t.Demand{}, node.core.demand);
        try std.testing.expectEqual(revision, g.scores.revision);
        try std.testing.expect(g.state.findTopic(desired.subscriptions[0].name) == null);
        node.shutdown(node.last_now);
        try std.testing.expectError(error.Stopped, node.applyIntent(&desired, node.last_now));
        try before.expectUnchanged(&node);
    }
}

test "managed runtime local intent topic demand no-op preserves Status scheduling and counters" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{43}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_policy_test.zig").full(.{ 1, 2, 3, 4 })};
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const g = &node.core.service.gossipsub.inner;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const before = ActivationSnapshot.capture(&node);
    const calls = node.reservations.allocation_calls;
    node.core.control.schedules[0].peer = .{ .index = 0, .generation = 1 };
    node.core.control.schedules[0].status_due_ms = node.last_now.mono_ms + 500;
    const schedule = node.core.control.schedules[0];
    defer node.core.control.schedules[0].peer = null;
    var desired = intentFor(&node);
    desired.subscriptions = &.{.{ .name = name, .params = .{ .weight = 2 } }};
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    const row = g.state.findTopic(name).?;
    g.scores.invalid(0, row);
    const counters = g.scores.topics[row];
    const revision = g.scores.revision;
    const retained = g.state.topics[row].retire_after_ms;
    try std.testing.expect(!try node.applyIntent(&desired, node.last_now));
    try std.testing.expectEqual(revision, g.scores.revision);
    desired.demand = .{ .attnets = 1, .expires_at_slot = 100 };
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    try std.testing.expect(!try node.applyIntent(&desired, node.last_now));
    try std.testing.expectEqualDeep(desired.demand, node.core.demand);
    try std.testing.expectEqualDeep(counters, g.scores.topics[row]);
    try std.testing.expectEqual(retained, g.state.topics[row].retire_after_ms);
    try std.testing.expectEqualDeep(schedule, node.core.control.schedules[0]);
    try before.expectUnchanged(&node);
    desired.subscriptions = &.{};
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    try std.testing.expect(!g.state.subscribed(row));
    const deadline = g.state.topics[row].retire_after_ms;
    try std.testing.expect(!try node.applyIntent(&desired, .{ .mono_ms = node.last_now.mono_ms + 1, .unix_s = node.last_now.unix_s }));
    try std.testing.expectEqual(deadline, g.state.topics[row].retire_after_ms);
    try std.testing.expectEqual(calls, node.reservations.allocation_calls);
}

const IntentPair = struct {
    a: runtime.NetworkCore = undefined,
    b: runtime.NetworkCore = undefined,
    a_gossip: [16]@import("gossipsub/root.zig").Event = undefined,
    b_gossip: [16]@import("gossipsub/root.zig").Event = undefined,
    b_app: [4]@import("reqresp/root.zig").Event = undefined,

    fn pump(self: *IntentPair) !struct { a: runtime.Result, b: runtime.Result } {
        const now = try @import("driver.zig").currentTime(std.testing.io);
        const a = self.a.step(std.testing.io, now, 100, .{ .gossipsub = &self.a_gossip }, 1);
        if (a.failure) |err| return err;
        const b = self.b.step(std.testing.io, now, 100, .{ .gossipsub = &self.b_gossip, .application = &self.b_app }, 1);
        if (b.failure) |err| return err;
        return .{ .a = a, .b = b };
    }
};

test "managed runtime local intent fork BPO announcements remembered peer and event borrows" {
    const full = @import("gossipsub/topic_policy_test.zig").full;
    const old = "/eth2/00000000/beacon_block/ssz_snappy";
    const active = "/eth2/01020304/beacon_block/ssz_snappy";
    const bpo = "/eth2/05060708/beacon_block/ssz_snappy";
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{44}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{45}));
    const pair = try std.testing.allocator.create(IntentPair);
    defer std.testing.allocator.destroy(pair);
    var opts = options(&key_a);
    opts.core.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }) };
    opts.core.service.reqresp.forks = &.{ .{ .digest = @splat(0), .fork = .phase0 }, .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }, .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu } };
    opts.local.metadata.custody_group_count = 4;
    opts.local.fork.minimum_sampling_groups = @min(8, opts.local.fork.custody_groups);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    try pair.a.init(std.testing.allocator, std.testing.io, opts);
    defer pair.a.deinit(std.testing.io);
    opts.transport.host = &key_b;
    try pair.b.init(std.testing.allocator, std.testing.io, opts);
    defer pair.b.deinit(std.testing.io);
    var a_intent = intentFor(&pair.a);
    a_intent.subscriptions = &.{ .{ .name = old, .params = .{} }, .{ .name = active, .params = .{} }, .{ .name = bpo, .params = .{} } };
    var b_intent = intentFor(&pair.b);
    b_intent.subscriptions = &.{.{ .name = old, .params = .{} }};
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    try pair.a.addDirectPeer(&pair.b.peerId(), &.{pair.b.localAddress()}, pair.a.last_now);
    const start = pair.a.last_now.mono_ms;
    const gb = &pair.b.core.service.gossipsub.inner;
    var connected = false;
    for (0..3000) |_| {
        _ = try pair.pump();
        if (pair.a.last_now.mono_ms - start > 10_000) break;
        const ns = &gb.namespace.?;
        if (pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1 and ns.subscribed(0, ns.lookup(active).?.ordinal) and ns.subscribed(0, ns.lookup(bpo).?.ordinal) and gb.state.peers[0].out_stream != null and pair.a.core.service.gossipsub.inner.state.peers[0].out_stream != null) {
            connected = true;
            break;
        }
    }
    try std.testing.expect(connected);
    try std.testing.expect(gb.state.findTopic(active) == null);
    const calls = pair.b.reservations.allocation_calls;
    for ([_]*runtime.LocalIntent{ &a_intent, &b_intent }) |intent| {
        intent.update.local.fork.fork = .fulu;
        intent.update.local.fork.digest = .{ 1, 2, 3, 4 };
        intent.update.local.status.fork_digest = intent.update.local.fork.digest;
        intent.update.local.status.earliest_available_slot = 0;
        intent.update.capabilities = try @import("capabilities.zig").forFork(.fulu, false, &.{ .v1_2, .v1_1 });
    }
    b_intent.subscriptions = &.{.{ .name = active, .params = .{ .weight = 7 } }};
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    const activated = gb.state.findTopic(active).?;
    try std.testing.expectEqual(@as(f64, 7), gb.scores.topic_params[activated].weight);
    try std.testing.expectEqual(@as(usize, 1), gb.state.subscribers(activated).count());
    const publication = try pair.b.publishGossipWithOptions(active, "0123456789", .{ .allow_zero_peers = false }, pair.b.last_now);
    try std.testing.expectEqual(@as(usize, 1), publication.queued);
    var announced = false;
    var withdrawn = false;
    var delivered = false;
    for (0..3000) |_| {
        const result = try pair.pump();
        for (pair.a_gossip[0..result.a.counts.gossipsub]) |event| switch (event) {
            .subscription_change => |value| {
                if (std.mem.eql(u8, value.topic, active) and value.subscribed) announced = true;
                if (std.mem.eql(u8, value.topic, old) and !value.subscribed) withdrawn = true;
            },
            .message => |value| {
                try std.testing.expectEqualStrings(active, value.topic);
                try std.testing.expectEqualStrings("0123456789", value.bytes);
                delivered = true;
                _ = pair.a.reportValidation(value.handle, .accept, pair.a.last_now);
            },
        };
        if (announced and withdrawn and delivered and pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1) break;
    }
    try std.testing.expect(announced and withdrawn and delivered);
    for ([_]*runtime.LocalIntent{ &a_intent, &b_intent }) |intent| {
        intent.update.local.fork.digest = .{ 5, 6, 7, 8 };
        intent.update.local.status.fork_digest = intent.update.local.fork.digest;
    }
    b_intent.subscriptions = &.{.{ .name = bpo, .params = .{ .weight = 9 } }};
    try std.testing.expect(try pair.a.applyIntent(&a_intent, pair.a.last_now));
    try std.testing.expect(try pair.b.applyIntent(&b_intent, pair.b.last_now));
    announced = false;
    withdrawn = false;
    for (0..3000) |_| {
        const result = try pair.pump();
        for (pair.a_gossip[0..result.a.counts.gossipsub]) |event| if (event == .subscription_change) {
            const value = event.subscription_change;
            if (std.mem.eql(u8, value.topic, bpo) and value.subscribed) announced = true;
            if (std.mem.eql(u8, value.topic, active) and !value.subscribed) withdrawn = true;
        };
        if (announced and withdrawn and pair.a.peerCounts().relevant == 1 and pair.b.peerCounts().relevant == 1) break;
    }
    try std.testing.expect(announced and withdrawn);
    const borrowed_topic = gb.state.findTopic(bpo).?;
    try std.testing.expectEqual(@as(f64, 9), gb.scores.topic_params[borrowed_topic].weight);
    const peer = pair.a.core.catalog.find(&pair.b.peerId()).?;
    var request: [24]u8 = @splat(0);
    request[8] = 1;
    request[16] = 1;
    const sink = try std.testing.allocator.alloc(u8, @import("reqresp/root.zig").Protocol.blocks_by_range_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try pair.a.sendReqRespRequest(peer, .blocks_by_range_v2, &request, sink, .{}, pair.a.last_now);
    _ = try pair.a.publishGossip(bpo, "borrowed gossip", pair.a.last_now);
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
        for (pair.b_gossip[0..result.b.counts.gossipsub]) |event| if (event == .message) {
            try std.testing.expectEqual(@as(f64, 9), gb.scores.topic_params[borrowed_topic].weight);
            try intentBorrowUpdate(&pair.b, &b_intent);
            try std.testing.expectEqualStrings(bpo, event.message.topic);
            try std.testing.expectEqualStrings("borrowed gossip", event.message.bytes);
            _ = pair.b.reportValidation(event.message.handle, .reject, pair.b.last_now);
            try std.testing.expect(gb.scores.retainsTopic(borrowed_topic));
            got_message = true;
        };
        if (got_request and got_message) break;
    }
    try std.testing.expect(got_request and got_message);
    try std.testing.expectEqual(calls, pair.b.reservations.allocation_calls);
}

fn intentBorrowUpdate(node: *runtime.NetworkCore, desired: *runtime.LocalIntent) !void {
    desired.demand.attnets ^= 1;
    desired.demand.expires_at_slot = 1000;
    desired.subscriptions = if (desired.demand.attnets == 1) &.{
        .{ .name = "/eth2/05060708/beacon_block/ssz_snappy", .params = .{ .weight = 9 } },
        .{ .name = "/eth2/05060708/voluntary_exit/ssz_snappy", .params = .{ .weight = 0 } },
    } else &.{
        .{ .name = "/eth2/05060708/beacon_block/ssz_snappy", .params = .{ .weight = 9 } },
        .{ .name = "/eth2/05060708/proposer_slashing/ssz_snappy", .params = .{ .weight = 0 } },
    };
    try std.testing.expect(try node.applyIntent(desired, node.last_now));
    var invalid = desired.*;
    invalid.update.local.metadata.attnets[0] ^= 1;
    invalid.subscriptions = &.{ desired.subscriptions[0], .{ .name = "invalid", .params = .{} } };
    const before = ActivationSnapshot.capture(node);
    try std.testing.expectError(error.InvalidTopic, node.applyIntent(&invalid, node.last_now));
    try before.expectUnchanged(node);
}

const BoundaryUnion = struct {
    names: [615][@import("gossipsub/topic.zig").topic_max_len]u8 = undefined,
    entries: [615]@import("gossipsub/local_intent.zig").Subscription = undefined,
    len: usize = 0,

    fn fill(self: *BoundaryUnion, columns: u16) !void {
        std.debug.assert(columns <= 128);
        self.len = 0;
        for ([_]u32{ 0, 0x01020304, 0x05060708 }) |digest| {
            for ([_][]const u8{ "beacon_block", "beacon_aggregate_and_proof", "proposer_slashing", "attester_slashing", "voluntary_exit", "sync_committee_contribution_and_proof", "light_client_finality_update", "light_client_optimistic_update", "bls_to_execution_change" }) |kind| {
                try self.append(digest, kind, null);
            }
            for (0..64) |index| try self.append(digest, "beacon_attestation", @intCast(index));
            for (0..4) |index| try self.append(digest, "sync_committee", @intCast(index));
            for (0..columns) |index| try self.append(digest, "data_column_sidecar", @intCast(index));
        }
    }

    fn append(self: *BoundaryUnion, digest: u32, kind: []const u8, index: ?u16) !void {
        std.debug.assert(self.len < self.entries.len);
        const name = if (index) |value|
            try std.fmt.bufPrint(&self.names[self.len], "/eth2/{x:0>8}/{s}_{d}/ssz_snappy", .{ digest, kind, value })
        else
            try std.fmt.bufPrint(&self.names[self.len], "/eth2/{x:0>8}/{s}/ssz_snappy", .{ digest, kind });
        self.entries[self.len] = .{ .name = name, .params = .{ .weight = 2 } };
        self.len += 1;
    }
};

test "managed runtime local intent three boundaries fit and all-column overlap refuses atomically" {
    const full = @import("gossipsub/topic_policy_test.zig").full;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{46}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.core.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }) };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const union_topics = try std.testing.allocator.create(BoundaryUnion);
    defer std.testing.allocator.destroy(union_topics);
    try union_topics.fill(64);
    try std.testing.expectEqual(@as(usize, 423), union_topics.len);
    var desired = intentFor(&node);
    desired.subscriptions = union_topics.entries[0..union_topics.len];
    desired.update.local.metadata.attnets[0] = 1;
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    const before = ActivationSnapshot.capture(&node);
    const g = &node.core.service.gossipsub.inner;
    const revision = g.scores.revision;
    const old_demand = node.core.demand;
    try union_topics.fill(128);
    try std.testing.expectEqual(@as(usize, 615), union_topics.len);
    desired.subscriptions = union_topics.entries[0..union_topics.len];
    desired.update.local.metadata.attnets[0] = 2;
    desired.demand = .{ .attnets = 3, .expires_at_slot = 100 };
    try std.testing.expectError(error.TopicCapacity, node.applyIntent(&desired, node.last_now));
    try before.expectUnchanged(&node);
    try std.testing.expectEqualDeep(old_demand, node.core.demand);
    try std.testing.expectEqual(revision, g.scores.revision);
    var count: usize = 0;
    for (g.state.topics) |row| if (row.subscribed) {
        count += 1;
    };
    try std.testing.expectEqual(@as(usize, 423), count);
    try std.testing.expect(g.state.findTopic("/eth2/05060708/data_column_sidecar_127/ssz_snappy") == null);
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
    opts_b.core.service.router.capabilities = .{ .receive = active, .request = active };
    var a: runtime.NetworkCore = undefined;
    try a.init(std.testing.allocator, std.testing.io, options(&key_a));
    defer a.deinit(std.testing.io);
    var b: runtime.NetworkCore = undefined;
    try b.init(std.testing.allocator, std.testing.io, opts_b);
    defer b.deinit(std.testing.io);
    const now = try @import("driver.zig").currentTime(std.testing.io);
    try a.connect(&b.peerId(), &.{b.localAddress()}, now);
    var authenticated = false;
    for (0..300) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
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
    opts.core.peers.capacity = 512;
    opts.core.service.gossipsub.retained_capacity = 512;
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, opts);
    defer node.deinit(std.testing.io);
    const local = node.peerId();
    var events: [2]t.Event = undefined;
    for (0..512) |i| {
        var secret: [32]u8 = @splat(0);
        std.mem.writeInt(u32, secret[28..32], @intCast(i + 2), .big);
        const remote_key = try keys.KeyPair.fromSecretKey(&secret);
        const remote = @import("wire/peer_id.zig").PeerId.fromPublicKey(&remote_key.publicKey());
        const handle: t.Handle = .{ .index = 0, .generation = @intCast(i + 1) };
        const peer = node.core.catalog.admit(&remote, &local, handle, &.{ .direction = .outbound, .endpoint = .unspecified, .now_ms = 0 }).admitted.peer;
        try std.testing.expectEqual(@as(u16, @intCast(i)), peer.index);
        _ = node.core.catalog.report(peer, .fatal, 0);
        try std.testing.expect(node.core.catalog.disconnect(peer, handle, .host, 0));
        _ = node.core.catalog.pollEvents(&events);
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
