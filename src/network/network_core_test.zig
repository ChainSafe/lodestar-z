const std = @import("std");
const runtime = @import("network_core.zig");
const t = @import("peers/types.zig");
const keys = @import("wire/keys.zig");
const d = @import("discv5");

fn options(key: *const keys.KeyPair) runtime.Options {
    var result: runtime.Options = .{
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
        if (ready and a.connectedPeerCount() == 1 and b.connectedPeerCount() == 1) break;
    }
    try std.testing.expect(ready);
    try std.testing.expectEqual(@as(u16, 1), a.connectedPeerCount());
    try std.testing.expectEqual(@as(u16, 1), b.connectedPeerCount());
    try std.testing.expect(a.diagnostics().discovered > 0);
    const hint_now = try @import("driver.zig").currentTime(std.testing.io);
    try std.testing.expect(a.futureForkHint(&b.peerId(), hint_now).?.compatible);
    const local = a.localState();
    _ = try a.updateLocal(&local, .{ .next_version = .{ 1, 1, 1, 1 }, .next_epoch = 123, .next_digest = .{ 1, 2, 3, 4 } }, hint_now);
    try std.testing.expect(!a.futureForkHint(&b.peerId(), hint_now).?.compatible);
    try std.testing.expectEqual(@as(u16, 1), a.connectedPeerCount());
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
    const response = [_]u8{9} ** rr.Protocol.blocks_by_range_v2.info().response_min;
    var app: [1]rr.Event = undefined;
    var peer_events: [1]t.Event = undefined;
    var done: usize = 0;
    var chunks: usize = 0;
    for (0..3000) |_| {
        const tick = try @import("driver.zig").currentTime(std.testing.io);
        const received = b.step(std.testing.io, tick, 100, .{ .application = &app }, 1);
        if (received.failure) |err| return err;
        for (app[0..received.counts.application]) |event| switch (event) {
            .request => |value| try b.respond(value.request, &response, .fulu, tick),
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
            const sent = try a.publishGossip(topic, &response, tick);
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
    a.removeDirectPeer(&b.peerId());
    b.removeDirectPeer(&a.peerId());
}

test "managed runtime every allocation prefix cleans up and memory plan counts owned storage" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var node: runtime.NetworkCore = undefined;
    try node.init(allocation.allocator(), std.testing.io, opts);
    const plan = node.memoryPlan();
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
    try node.setDemand(&.{ .coverage = .{ .attnets = 1 }, .expires_at_slot = 5 });
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
    try std.testing.expectEqual(@as(u16, 0), a.connectedPeerCount());
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
        if (a.connectedPeerCount() == 1 and replacement.connectedPeerCount() == 1) break;
    }
    try std.testing.expectEqual(@as(u16, 1), a.connectedPeerCount());
    try std.testing.expectEqual(@as(u16, 1), replacement.connectedPeerCount());
    try std.testing.expect(replacement.diagnostics().dial_started > 0);
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
