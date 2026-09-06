const std = @import("std");
const network = @import("network");
const rr = network.reqresp;
const t = network.peers.types;
const turns = 512;
const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
const topic = "/eth2/00000000/beacon_block/ssz_snappy";

const Samples = struct {
    ns: [turns]u64 = undefined,
    received: u64 = 0,
    sent: u64 = 0,
    work: u64 = 0,
    immediate: usize = 0,

    fn record(self: *Samples, index: usize, elapsed: u64, result: network.network_core.Result, immediate: bool) !void {
        if (result.failure) |err| return err;
        self.ns[index] = elapsed;
        self.received += result.transport.datagrams_received;
        self.sent += result.transport.datagrams_sent;
        self.work += result.transport.work_processed;
        self.immediate += @intFromBool(immediate);
    }
    fn print(self: *Samples, name: []const u8) void {
        std.mem.sort(u64, &self.ns, {}, std.sort.asc(u64));
        std.debug.print("case={s} turns={} wait_max_ms=0 p50_ns={} p95_ns={} p99_ns={} max_ns={} rx={} tx={} native_work={} immediate_deadlines={}\n", .{ name, turns, self.ns[turns / 2], self.ns[turns * 95 / 100], self.ns[turns * 99 / 100], self.ns[turns - 1], self.received, self.sent, self.work, self.immediate });
    }
};

fn options(key: *const network.KeyPair) network.network_core.Options {
    return .{
        .wait_mode = .native_poll,
        .transport = .{ .host = key, .bind = .{ .ip4 = .loopback(0) }, .limits = .{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 } },
        .core = .{
            .peers = .{ .capacity = 4, .outbound_reserve = 1, .max_peers = 3, .target_peers = 2, .min_outbound = 1, .engine_capacity = 4 },
            .dial = .{ .capacity = 4, .concurrent_max = 2, .engine_dialing_max = 2, .seed = 7 },
            .control = .{ .operations_max = 2 },
            .service = .{
                .router = .{ .negotiations_max = 24, .outbound_control_reserved = 8 },
                .reqresp = .{ .peers = 4, .outbound_max = 16, .inbound_max = 16, .outbound_control_reserved = 8, .inbound_control_reserved = 8, .outbound_per_peer_max = 4, .inbound_per_peer_max = 16, .inbound_application_per_peer_max = 8, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }} },
                .gossipsub = .{ .random_seed = 1 },
            },
        },
        .local = .{},
        .schedule = .{},
    };
}

fn timestamp(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn turn(node: *network.NetworkCore, io: std.Io, outputs: network.network_core.Outputs) !network.network_core.Result {
    const result = node.step(io, try network.driver.currentTime(io), 100, outputs, 0);
    if (result.failure) |err| return err;
    return result;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len > 2) return error.InvalidProfile;
    const selected = if (args.len == 2) args[1] else "baseline";
    if (std.mem.eql(u8, selected, "idle_wait")) return idleWait(init);
    const profile: ?network.configuration.Profile = if (std.mem.eql(u8, selected, "baseline")) null else if (std.mem.eql(u8, selected, "small")) .small else if (std.mem.eql(u8, selected, "beacon_node")) .beacon_node else return error.InvalidProfile;
    std.debug.print("profile={s} baseline=task1_raw_configuration\n", .{selected});
    const io = init.io;
    const allocator = init.gpa;
    const sinks = try allocator.alloc(u8, 4 * sink_size);
    defer allocator.free(sinks);
    const key_a = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const key_b = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{12}));
    const a = try allocator.create(network.NetworkCore);
    defer allocator.destroy(a);
    try initialize(a, allocator, io, &key_a, profile);
    defer a.deinit(io);
    std.debug.print("history_entry_bytes={} history_owner_bytes={} startup_requested_zig_bytes={} inline_bytes={} gossip_bytes={} allocation_calls={} native_allocator_os_excluded=true\n", .{ @sizeOf(network.gossipsub.mcache.HistoryEntry), @sizeOf(network.gossipsub.mcache.History), a.memoryPlan().allocated_bytes, a.memoryPlan().inline_bytes, a.core.service.gossipsub.inner.memoryPlan().total_bytes, a.reservations.allocation_calls });
    const allocations_a = a.reservations.allocation_calls;
    var samples: Samples = .{};
    for (0..turns) |i| {
        const now = try network.driver.currentTime(io);
        const immediate = if (a.nextWakeup(now, .{})) |deadline| deadline <= now.mono_ms else false;
        const start = timestamp(io);
        const result = try turn(a, io, .{});
        try samples.record(i, timestamp(io) - start, result, immediate);
    }
    samples.print("idle");
    printReconciliation(a, "idle");
    const b = try allocator.create(network.NetworkCore);
    defer allocator.destroy(b);
    try initialize(b, allocator, io, &key_b, profile);
    defer b.deinit(io);
    const allocations_b = b.reservations.allocation_calls;
    const peer = try connectPair(a, b, io);
    try pressure(a, b, sinks, io, peer);
    printReconciliation(a, "connected_cumulative");
    std.debug.print("turn_allocation_calls_a={} turn_allocation_calls_b={} process_rss=external_time_maximum_resident_set_kbytes\n", .{ a.reservations.allocation_calls - allocations_a, b.reservations.allocation_calls - allocations_b });
}

fn initialize(node: *network.NetworkCore, a: std.mem.Allocator, io: std.Io, key: *const network.KeyPair, profile: ?network.configuration.Profile) !void {
    if (profile) |selected| {
        try node.initManaged(a, io, .{ .wait_mode = .native_poll, .host = key, .bind = .{ .ip4 = .loopback(0) }, .local = .{}, .configuration = .{ .profile = selected, .seed = 7, .forks = &.{.{ .digest = @splat(0), .fork = .phase0 }} } });
    } else try node.init(a, io, options(key));
}

fn connectPair(a: *network.NetworkCore, b: *network.NetworkCore, io: std.Io) !t.PeerRef {
    try a.addDirectPeer(&b.peerId(), &.{b.localAddress()}, try network.driver.currentTime(io));
    var rows: [4]t.Snapshot = undefined;
    var peer: ?t.PeerRef = null;
    for (0..10000) |_| {
        _ = try turn(a, io, .{});
        _ = try turn(b, io, .{});
        for (rows[0..a.snapshots(&rows)]) |row| {
            if (row.relevant) peer = row.peer;
        }
        if (peer != null and b.connectedPeerCount() == 1) break;
    }
    if (peer == null) return error.ConnectionDeadline;
    try b.addDirectPeer(&a.peerId(), &.{a.localAddress()}, try network.driver.currentTime(io));
    var peer_events: [4]t.Event = undefined;
    var gossip_events: [1]network.gossipsub.Event = undefined;
    if (!a.subscribe(topic) or !b.subscribe(topic)) return error.SubscriptionRefused;
    for (0..4000) |_| {
        const result_a = a.step(io, try network.driver.currentTime(io), 100, .{ .peers = &peer_events, .gossipsub = &gossip_events }, 1);
        if (result_a.failure) |err| return err;
        const result_b = b.step(io, try network.driver.currentTime(io), 100, .{ .peers = &peer_events, .gossipsub = &gossip_events }, 1);
        if (result_b.failure) |err| return err;
        if (a.core.service.gossipsub.inner.resourceSnapshot().remote_subscriptions > 0 and a.core.service.gossipsub.inner.peers.rows[0].direct) break;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    if (a.core.service.gossipsub.inner.resourceSnapshot().remote_subscriptions == 0) {
        std.debug.print("setup a={any} b={any} gossip_a={any} gossip_b={any}\n", .{ a.peerCounts(), b.peerCounts(), a.core.service.gossipsub.inner.resourceSnapshot(), b.core.service.gossipsub.inner.resourceSnapshot() });
        return error.SubscriptionDeadline;
    }
    return peer.?;
}

fn pressure(a: *network.NetworkCore, b: *network.NetworkCore, sinks: []u8, io: std.Io, peer: t.PeerRef) !void {
    var payload: [64 * 1024]u8 = undefined;
    var random = std.Random.DefaultPrng.init(123);
    random.random().bytes(&payload);
    var gossip_queued: usize = 0;
    var gossip_pressured: usize = 0;
    var peak_descriptors: usize = 0;
    var peak_validations: usize = 0;
    var request: [24]u8 = @splat(0);
    request[8] = 1;
    request[16] = 1;
    var requests: [4]rr.RequestHandle = undefined;
    for (&requests, 0..) |*handle, i| {
        const protocol: rr.Protocol = if (i < 2) .blocks_by_range_v2 else .blocks_by_root_v2;
        handle.* = try a.sendReqRespRequest(peer, protocol, request[0..protocol.info().request_min], sinks[i * sink_size ..][0..sink_size], .{ .expected_chunks = 1 }, try network.driver.currentTime(io));
    }
    var status = b.localState().status;
    status.head_slot = 42;
    try b.updateStatus(&status, try network.driver.currentTime(io));
    a.reStatusPeers(try network.driver.currentTime(io));
    var samples: Samples = .{};
    for (0..turns) |i| {
        if (i < 256) {
            std.mem.writeInt(u64, payload[0..8], i, .little);
            const published = try a.publishGossip(topic, &payload, try network.driver.currentTime(io));
            gossip_queued += published.queued;
            gossip_pressured += published.pressured;
        }
        _ = try turn(b, io, .{});
        const sender = a.core.service.gossipsub.inner.resourceSnapshot();
        const receiver = b.core.service.gossipsub.inner.resourceSnapshot();
        peak_descriptors = @max(peak_descriptors, sender.queued_descriptors);
        peak_validations = @max(peak_validations, receiver.pending_validations);
        const now = try network.driver.currentTime(io);
        const immediate = if (a.nextWakeup(now, .{})) |deadline| deadline <= now.mono_ms else false;
        const start = timestamp(io);
        const result = try turn(a, io, .{});
        try samples.record(i, timestamp(io) - start, result, immediate);
    }
    samples.print("connected_slow_application_control");
    std.debug.print("gossip_attempted_bytes={} queued={} pressured={} peak_descriptors={} peak_pending_validations={}\n", .{ 256 * payload.len, gossip_queued, gossip_pressured, peak_descriptors, peak_validations });
    if (gossip_queued == 0) return error.GossipDidNotQueue;
    var rows: [4]t.Snapshot = undefined;
    var control_progress = false;
    for (rows[0..a.snapshots(&rows)]) |row| {
        if (row.status) |remote| if (remote.head_slot == 42) {
            control_progress = true;
        };
    }
    if (!control_progress) return error.ControlDidNotProgress;
    std.debug.print("control_status_head_slot=42 progress=true request_count=4 caller_sink_bytes={} gossip_resources={any}\n", .{ sinks.len, b.core.service.gossipsub.inner.resourceSnapshot() });
    try drain(a, b, io, requests.len);
}

fn drain(a: *network.NetworkCore, b: *network.NetworkCore, io: std.Io, expected: usize) !void {
    var events: [4]rr.Event = undefined;
    var received: usize = 0;
    var terminals: usize = 0;
    for (0..turns) |_| {
        const result = try turn(b, io, .{ .application = &events });
        for (events[0..result.counts.application]) |event| switch (event) {
            .request => |value| {
                received += 1;
                try b.respondError(value.request, 3, "benchmark", try network.driver.currentTime(io));
            },
            else => {},
        };
        const sent = try turn(a, io, .{ .application = &events });
        for (events[0..sent.counts.application]) |event| switch (event) {
            .failed => |failure| {
                if (failure.reason != .peer_error or failure.reason.peer_error.code != 3) return error.UnexpectedRequestFailure;
                terminals += 1;
            },
            else => return error.UnexpectedApplicationEvent,
        };
        if (received == expected and terminals == expected) break;
    }
    if (received != expected or terminals != expected) return error.RequestsDidNotDrain;
    std.debug.print("drained_application_requests={} terminal_results={}\n", .{ received, terminals });
}

fn printReconciliation(node: *network.NetworkCore, name: []const u8) void {
    const c = node.core.counters;
    const score = &node.core.service.gossipsub.inner.scores;
    std.debug.print("case={s} selections={} selection_rows={} candidate_syncs={} candidate_rows={} candidate_lookup_rows={} availability_rows={} candidate_selections={} score_calculations={} score_topic_visits={}\n", .{ name, c.selections, c.selection_rows, c.candidate_syncs, c.candidate_rows, c.candidate_lookup_rows, c.availability_rows, c.candidate_selections, score.calculations, score.topic_visits });
}

fn idleWait(init: std.process.Init) !void {
    const io = init.io;
    const key = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const node = try init.gpa.create(network.NetworkCore);
    defer init.gpa.destroy(node);
    try initialize(node, init.gpa, io, &key, .small);
    defer node.deinit(io);
    const calls = node.reservations.allocation_calls;
    const start = timestamp(io);
    var count: u32 = 0;
    var positive_waits: u32 = 0;
    var immediate: u32 = 0;
    var work: u64 = 0;
    var elapsed_turns: u64 = 0;
    for (0..10000) |_| {
        const before = timestamp(io);
        if (before - start >= 1_000_000_000) break;
        const now = try network.driver.currentTime(io);
        const due = node.nextWakeup(now, .{});
        const ready = if (due) |value| value <= now.mono_ms else false;
        immediate += @intFromBool(ready);
        positive_waits += @intFromBool(!ready);
        const remaining_ms: u32 = @intCast((1_000_000_000 - (before - start) + 999_999) / 1_000_000);
        const result = node.step(io, now, 0, .{}, @min(100, remaining_ms));
        if (result.failure) |err| return err;
        elapsed_turns += timestamp(io) - before;
        count += 1;
        work += result.transport.work_processed;
    }
    const elapsed = timestamp(io) - start;
    const readiness = node.diagnostics();
    std.debug.print("readiness_calls={} nonzero_readiness_waits={} readiness_failures={}\n", .{ readiness.readiness_calls, readiness.readiness_nonzero_waits, readiness.readiness_failures });
    if (elapsed < 1_000_000_000) return error.TurnLimit;
    std.debug.print("case=idle_wait profile=small requested_duration_ms=1000 host_wait_ms=100 elapsed_ns={} turns={} positive_wait_turns={} immediate_deadlines={} turn_elapsed_ns={} native_work={} turn_allocation_calls={}\n", .{ elapsed, count, positive_waits, immediate, elapsed_turns, work, node.reservations.allocation_calls - calls });
}
