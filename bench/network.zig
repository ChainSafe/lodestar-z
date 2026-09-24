const std = @import("std");
const network = @import("network");
const config = @import("config");
const preset = @import("preset");
const rr = network.reqresp;
const t = network.peers.types;
const turns = 512;
const sink_size = rr.Protocol.blocks_by_range_v2.info().response_max;
const chain_config = if (preset.active_preset == .minimal) &config.minimal.config else &config.mainnet.config;
const warmup_turns = 64;

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

/// Admits gossip as the gossip processor does and keeps each validation handle.
const GossipSink = struct {
    handles: [256]network.gossipsub.ValidationHandle = undefined,
    count: usize = 0,
    excess: bool = false,
    sink: network.gossipsub.MessageSink = undefined,

    /// The sink must not move while the node holds it.
    fn attach(self: *GossipSink, node: *network.NetworkCore) void {
        self.sink = .{ .context = self, .has_capacity = hasCapacity, .admit = admit };
        node.service.gossipsub.message_sink = &self.sink;
    }

    fn hasCapacity(context: *anyopaque, _: network.gossipsub.topic.Kind, _: usize) bool {
        const self: *GossipSink = @ptrCast(@alignCast(context));
        if (self.count < self.handles.len) return true;
        self.excess = true;
        return false;
    }

    fn admit(context: *anyopaque, candidate: *network.gossipsub.Admission) bool {
        const self: *GossipSink = @ptrCast(@alignCast(context));
        if (self.count == self.handles.len or !candidate.feasible(&.{})) return false;
        candidate.commit();
        self.handles[self.count] = candidate.event.handle;
        self.count += 1;
        return true;
    }
};

fn timestamp(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn turn(node: *network.NetworkCore, io: std.Io, outputs: network.network_core.Outputs) !network.network_core.Result {
    const result = node.step(io, try network.transport.currentTime(io), 100, outputs, 0);
    if (result.failure) |err| return err;
    return result;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len > 2) return error.InvalidProfile;
    const selected = if (args.len == 2) args[1] else return error.InvalidProfile;
    if (std.mem.eql(u8, selected, "idle_wait")) return idleWait(init);
    const profile: network.configuration.Profile = if (std.mem.eql(u8, selected, "small")) .small else if (std.mem.eql(u8, selected, "beacon_node")) .beacon_node else return error.InvalidProfile;
    std.debug.print("profile={s} preset={s} optimize={s} warmup_turns={} measured_turns={} payload=synthetic_transport_bytes host_consensus_validation=false\n", .{ selected, @tagName(preset.active_preset), @tagName(@import("builtin").mode), warmup_turns, turns });
    const plan = try network.chain.Plan.init(chain_config, false);
    const io = init.io;
    const allocator = init.gpa;
    const sinks = try allocator.alloc(u8, 4 * sink_size);
    defer allocator.free(sinks);
    const key_a = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const key_b = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{12}));
    const a = try allocator.create(network.NetworkCore);
    defer allocator.destroy(a);
    try initialize(a, allocator, io, &key_a, profile, &plan);
    defer a.deinit(io);
    std.debug.print("history_entry_bytes={} history_owner_bytes={} startup_requested_zig_bytes={} inline_bytes={} gossip_bytes={} allocation_calls={} native_allocator_os_excluded=true\n", .{ @sizeOf(network.gossipsub.mcache.HistoryEntry), @sizeOf(network.gossipsub.mcache.History), a.memoryPlan().allocated_bytes, a.memoryPlan().inline_bytes, a.service.gossipsub.memoryPlan().total_bytes, a.reservations.allocation_calls });
    std.debug.print("gossip_metadata_bytes={}\n", .{a.service.gossipsub.memoryPlan().metadata_bytes});
    for (0..warmup_turns) |_| _ = try turn(a, io, .{});
    const idle_allocations = a.reservations.allocation_calls;
    var samples: Samples = .{};
    for (0..turns) |i| {
        const now = try network.transport.currentTime(io);
        const immediate = if (a.nextWakeup(now, .{})) |deadline| deadline <= now.mono_ms else false;
        const start = timestamp(io);
        const result = try turn(a, io, .{});
        try samples.record(i, timestamp(io) - start, result, immediate);
    }
    samples.print("idle");
    std.debug.print("case=idle turn_allocation_calls={}\n", .{a.reservations.allocation_calls - idle_allocations});
    printReconciliation(a, "idle");
    const b = try allocator.create(network.NetworkCore);
    defer allocator.destroy(b);
    try initialize(b, allocator, io, &key_b, profile, &plan);
    defer b.deinit(io);
    var topic_buffer: [network.gossipsub.topic.topic_max_len]u8 = undefined;
    const topic = network.gossipsub.topic.build(plan.forks[0].digest, "beacon_block", &topic_buffer);
    try connectPair(a, b, io, topic);
    for (0..warmup_turns) |_| {
        _ = try turn(a, io, .{});
        _ = try turn(b, io, .{});
    }
    const allocations_a = a.reservations.allocation_calls;
    const allocations_b = b.reservations.allocation_calls;
    try pressure(a, b, sinks, io, topic, plan.forks[0]);
    printReconciliation(a, "connected_cumulative");
    std.debug.print("turn_allocation_calls_a={} turn_allocation_calls_b={} process_rss=external_time_maximum_resident_set_kbytes\n", .{ a.reservations.allocation_calls - allocations_a, b.reservations.allocation_calls - allocations_b });
}

fn initialize(node: *network.NetworkCore, a: std.mem.Allocator, io: std.Io, key: *const network.KeyPair, profile: network.configuration.Profile, plan: *const network.chain.Plan) !void {
    const update = try plan.update(.{ .metadata = .{ .custody_group_count = chain_config.chain.CUSTODY_REQUIREMENT } }, null, 0);
    try node.initManaged(a, io, .{
        .wait_mode = .native_poll,
        .host = key,
        .bind = .{ .ip4 = .loopback(0) },
        .local = update.local,
        .schedule = update.schedule,
        .configuration = .{
            .profile = profile,
            .seed = 7,
            .forks = plan.forks[0..plan.boundary_count],
            .admission_policy = plan.requestPolicy(),
            .router = .{ .capabilities = update.capabilities },
            .gossip = .{ .topic_policy = plan.topics[0..plan.boundary_count], .message_id_policy = .{ .phase0_digest = plan.phase0_digest } },
        },
    });
}

fn connectPair(a: *network.NetworkCore, b: *network.NetworkCore, io: std.Io, topic: []const u8) !void {
    try a.addDirectPeer(&b.peerId(), &.{b.transport.localAddress()}, try network.transport.currentTime(io));
    var rows: [4]t.Snapshot = undefined;
    var peer: ?t.PeerRef = null;
    for (0..10000) |_| {
        _ = try turn(a, io, .{});
        _ = try turn(b, io, .{});
        for (rows[0..a.peer_manager.snapshots(&rows)]) |row| {
            if (row.relevant) peer = row.peer;
        }
        if (peer != null and b.peerCounts().relevant == 1) break;
    }
    if (peer == null) return error.ConnectionDeadline;
    try b.addDirectPeer(&a.peerId(), &.{a.transport.localAddress()}, try network.transport.currentTime(io));
    var peer_events: [4]t.Event = undefined;
    var subscription: network.gossipsub.local_intent.Boundary = .{ .digest = network.gossipsub.topic.parseCanonical(topic).?.digest };
    subscription.mask(.beacon_block)[0] = 1;
    subscription.lengths[@intFromEnum(network.gossipsub.topic.Kind.beacon_block)] = 1;
    for ([_]*network.NetworkCore{ a, b }) |node| {
        const intent: network.network_core.LocalIntent = .{
            .update = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() },
            .demand = node.peer_manager.demand,
            .subscriptions = &.{subscription},
            .slot = 100,
        };
        _ = try node.applyIntent(&intent, try network.transport.currentTime(io));
    }
    for (0..4000) |_| {
        const result_a = a.step(io, try network.transport.currentTime(io), 100, .{ .peers = &peer_events }, 1);
        if (result_a.failure) |err| return err;
        const result_b = b.step(io, try network.transport.currentTime(io), 100, .{ .peers = &peer_events }, 1);
        if (result_b.failure) |err| return err;
        if (a.service.gossipsub.resourceSnapshot().remote_subscriptions > 0 and a.service.gossipsub.peers.rows[0].direct) break;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    if (a.service.gossipsub.resourceSnapshot().remote_subscriptions == 0) {
        std.debug.print("setup a={any} b={any} gossip_a={any} gossip_b={any}\n", .{ a.peerCounts(), b.peerCounts(), a.service.gossipsub.resourceSnapshot(), b.service.gossipsub.resourceSnapshot() });
        return error.SubscriptionDeadline;
    }
}

fn pressure(a: *network.NetworkCore, b: *network.NetworkCore, sinks: []u8, io: std.Io, topic: []const u8, context: rr.ForkEntry) !void {
    var payload: [64 * 1024]u8 = undefined;
    var random = std.Random.DefaultPrng.init(123);
    random.random().bytes(&payload);
    var gossip_queued: usize = 0;
    var gossip_pressured: usize = 0;
    var peak_descriptors: usize = 0;
    var peak_validations: usize = 0;
    var gossip: GossipSink = .{};
    gossip.attach(b);
    defer b.service.gossipsub.message_sink = null;
    var request: [32]u8 = @splat(0);
    request[8] = 1;
    request[16] = 1;
    var requests: [4]rr.RequestHandle = undefined;
    for (&requests, 0..) |*handle, i| {
        const protocol: rr.Protocol = if (i < 2) .blocks_by_range_v2 else .blocks_by_root_v2;
        handle.* = try a.sendReqRespRequest(&b.peerId(), protocol, request[0..if (i < 2) 24 else 32], sinks[i * sink_size ..][0..sink_size], .{ .expected_chunks = 1 }, try network.transport.currentTime(io));
    }
    var status = b.localState().status;
    status.head_slot = 42;
    try b.updateStatus(&status);
    _ = a.reStatusPeer(&b.peerId(), try network.transport.currentTime(io));
    var samples: Samples = .{};
    for (0..turns) |i| {
        if (i < 256) {
            std.mem.writeInt(u64, payload[0..8], i, .little);
            const published = try a.publishGossipWithOptions(topic, &payload, .{}, try network.transport.currentTime(io));
            gossip_queued += published.queued;
            gossip_pressured += published.pressured;
        }
        _ = try turn(b, io, .{});
        if (gossip.excess) return error.ExcessGossip;
        const sender = a.service.gossipsub.resourceSnapshot();
        const receiver = b.service.gossipsub.resourceSnapshot();
        peak_descriptors = @max(peak_descriptors, sender.queued_descriptors);
        peak_validations = @max(peak_validations, receiver.pending_validations);
        const now = try network.transport.currentTime(io);
        const immediate = if (a.nextWakeup(now, .{})) |deadline| deadline <= now.mono_ms else false;
        const start = timestamp(io);
        const result = try turn(a, io, .{});
        try samples.record(i, timestamp(io) - start, result, immediate);
    }
    samples.print("connected_slow_application_control");
    std.debug.print("gossip_attempted_bytes={} queued={} pressured={} peak_descriptors={} peak_pending_validations={}\n", .{ 256 * payload.len, gossip_queued, gossip_pressured, peak_descriptors, peak_validations });
    if (gossip_queued == 0 or gossip.count == 0 or peak_validations == 0) return error.GossipDidNotDeliver;
    var rows: [4]t.Snapshot = undefined;
    var control_progress = false;
    for (rows[0..a.peer_manager.snapshots(&rows)]) |row| {
        if (row.status) |remote| if (remote.head_slot == 42) {
            control_progress = true;
        };
    }
    if (!control_progress) return error.ControlDidNotProgress;
    std.debug.print("control_status_head_slot=42 progress=true request_count=4 caller_sink_bytes={} gossip_resources={any}\n", .{ sinks.len, b.service.gossipsub.resourceSnapshot() });
    for (gossip.handles[0..gossip.count]) |handle| {
        const verdict = b.reportValidation(handle, .ignore, try network.transport.currentTime(io));
        if (verdict != .applied) return error.GossipVerdictFailed;
    }
    const delivered_gossip = gossip.count;
    gossip.count = 0;
    try drain(a, b, io, requests.len, &payload, context, &gossip, delivered_gossip);
}

fn drain(a: *network.NetworkCore, b: *network.NetworkCore, io: std.Io, expected: usize, payload: []const u8, context: rr.ForkEntry, gossip: *GossipSink, delivered_gossip: usize) !void {
    var events: [8]rr.Event = undefined;
    var received: usize = 0;
    var chunks: usize = 0;
    var terminals: usize = 0;
    var served: usize = 0;
    var messages = delivered_gossip;
    for (0..turns) |_| {
        const result = try turn(b, io, .{ .application = &events });
        for (gossip.handles[0..gossip.count]) |handle| {
            messages += 1;
            _ = b.reportValidation(handle, .ignore, try network.transport.currentTime(io));
        }
        gossip.count = 0;
        for (events[0..result.counts.application]) |event| switch (event) {
            .request => |value| {
                received += 1;
                try b.respond(value.request, payload, context, try network.transport.currentTime(io));
            },
            .chunk_sent => |value| if (!b.finish(value.request, try network.transport.currentTime(io))) {
                return error.FinishFailed;
            },
            .served => served += 1,
            else => return error.UnexpectedServerEvent,
        };
        const sent = try turn(a, io, .{ .application = &events });
        for (events[0..sent.counts.application]) |event| switch (event) {
            .chunk => |value| {
                if (value.fork != context.fork or !std.mem.eql(u8, value.bytes, payload)) return error.InvalidResponse;
                if (!a.consume(value.request, try network.transport.currentTime(io))) return error.ConsumeFailed;
                chunks += 1;
            },
            .done => |value| {
                if (value.chunks != 1) return error.InvalidChunkCount;
                terminals += 1;
            },
            else => return error.UnexpectedApplicationEvent,
        };
        if (received == expected and terminals == expected and served == expected) break;
    }
    if (received != expected or chunks != expected or terminals != expected or served != expected) return error.RequestsDidNotDrain;
    std.debug.print("successful_requests={} response_chunks={} response_bytes={} gossip_delivered={} gossip_verdict=ignore\n", .{ terminals, chunks, chunks * payload.len, messages });
}

fn printReconciliation(node: *network.NetworkCore, name: []const u8) void {
    const c = node.peer_manager.counters;
    const score = &node.service.gossipsub.peers.scores;
    std.debug.print("case={s} selections={} selection_rows={} candidate_selections={} score_calculations={} score_topic_visits={}\n", .{ name, c.selections, c.selection_rows, c.candidate_selections, score.calculations, score.topic_visits });
}

fn idleWait(init: std.process.Init) !void {
    const io = init.io;
    const key = try network.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{11}));
    const node = try init.gpa.create(network.NetworkCore);
    defer init.gpa.destroy(node);
    const plan = try network.chain.Plan.init(chain_config, false);
    try initialize(node, init.gpa, io, &key, .small, &plan);
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
        const now = try network.transport.currentTime(io);
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
    const readiness = node.diagnostics().runtime;
    std.debug.print("readiness_calls={} nonzero_readiness_waits={} readiness_failures={}\n", .{ readiness.readiness_calls, readiness.readiness_nonzero_waits, readiness.readiness_failures });
    if (elapsed < 1_000_000_000) return error.TurnLimit;
    std.debug.print("case=idle_wait profile=small requested_duration_ms=1000 host_wait_ms=100 elapsed_ns={} turns={} positive_wait_turns={} immediate_deadlines={} turn_elapsed_ns={} native_work={} turn_allocation_calls={}\n", .{ elapsed, count, positive_waits, immediate, elapsed_turns, work, node.reservations.allocation_calls - calls });
}
