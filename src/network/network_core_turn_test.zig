const std = @import("std");
const runtime = @import("network_core.zig");
const keys = @import("wire/keys.zig");
const options = @import("test_support.zig").networkOptions;
const Now = @import("types.zig").Now;
const Source = @import("wake_sources.zig").Source;
const Inbox = @import("gossipsub/test_support.zig").Inbox;

fn currentTime() !Now {
    return @import("transport.zig").currentTime(std.testing.io);
}

fn monotonicNs() u64 {
    return @intCast(std.Io.Clock.awake.now(std.testing.io).nanoseconds);
}

/// A scripted host: a nonblocking wake pipe, and an apply that drains it and then runs the
/// test's host work.
const TestHost = struct {
    pipe: [2]std.c.fd_t = .{ -1, -1 },
    applies: u32 = 0,
    /// The next applies that report a per-turn cap.
    more: u32 = 0,
    /// The next apply writes its own wake after draining, as a concurrent submission would.
    resubmit: bool = false,
    publication: ?[]const u8 = null,
    published: usize = 0,
    failure: ?anyerror = null,

    fn init(self: *TestHost) !void {
        if (std.c.pipe(&self.pipe) != 0) return error.PipeFailed;
        const flags = std.c.fcntl(self.pipe[0], std.c.F.GETFL);
        const nonblock: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
        if (flags < 0 or std.c.fcntl(self.pipe[0], std.c.F.SETFL, flags | nonblock) < 0) return error.PipeFailed;
    }

    fn deinit(self: *TestHost) void {
        for (self.pipe) |fd| _ = std.c.close(fd);
    }

    fn signal(self: *const TestHost) void {
        std.debug.assert(std.c.write(self.pipe[1], "w", 1) == 1);
    }

    fn seam(self: *TestHost, deadline_ms: ?u64) runtime.Host {
        return .{ .context = self, .apply = apply, .deadline_ms = deadline_ms };
    }

    fn apply(context: *anyopaque, core: *runtime.NetworkCore, now: Now) runtime.HostProgress {
        const self: *TestHost = @ptrCast(@alignCast(context));
        self.applies += 1;
        var buffer: [64]u8 = undefined;
        _ = std.c.read(self.pipe[0], &buffer, buffer.len);
        if (self.resubmit) {
            self.resubmit = false;
            self.signal();
        }
        if (self.publication) |topic| {
            self.publication = null;
            const outcome = core.publishGossipWithOptions(topic, "host publication", .{}, now) catch |err| {
                self.failure = err;
                return .{};
            };
            self.published = outcome.queued;
        }
        const more = self.more > 0;
        self.more -|= 1;
        return .{ .more = more };
    }
};

fn delayedSignal(host: *const TestHost, delay_ms: i64, written_ns: *std.atomic.Value(u64)) void {
    std.testing.io.sleep(.fromMilliseconds(delay_ms), .awake) catch unreachable;
    written_ns.store(monotonicNs(), .release);
    host.signal();
}

const Pair = struct {
    a: runtime.NetworkCore = undefined,
    b: runtime.NetworkCore = undefined,
    a_inbox: Inbox = .{},
    b_inbox: Inbox = .{},

    fn pump(self: *Pair) !void {
        self.a_inbox.clear();
        self.b_inbox.clear();
        for ([_]*runtime.NetworkCore{ &self.a, &self.b }) |node| {
            const now = try currentTime();
            const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
            if (result.failure) |err| return err;
        }
    }
};

fn intent(node: *const runtime.NetworkCore, subscriptions: []const @import("gossipsub/local_intent.zig").Boundary) runtime.LocalIntent {
    return .{
        .update = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() },
        .demand = node.peer_manager.demand,
        .subscriptions = subscriptions,
    };
}

test "a host publication submitted while the owner waits leaves in the flush of the turn that saw the wake" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    const key_a = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{61}));
    const key_b = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{62}));
    const pair = try std.testing.allocator.create(Pair);
    defer std.testing.allocator.destroy(pair);
    pair.* = .{};
    var opts = options(&key_a);
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(@splat(0))};
    try pair.a.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.a.deinit(std.testing.io);
    opts.startup.host = &key_b;
    try pair.b.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer pair.b.deinit(std.testing.io);
    pair.a_inbox.attach(pair.a.service.gossipsub);
    pair.b_inbox.attach(pair.b.service.gossipsub);
    defer {
        pair.b_inbox.deinit();
        pair.a_inbox.deinit();
    }
    const subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{topic});
    _ = try pair.a.applyIntent(&intent(&pair.a, subscriptions), pair.a.last_now);
    _ = try pair.b.applyIntent(&intent(&pair.b, subscriptions), pair.b.last_now);
    try pair.a.addDirectPeer(&pair.b.peerId(), &.{pair.b.transport.localAddress()}, pair.a.last_now);
    const ga = pair.a.service.gossipsub;
    const gb = pair.b.service.gossipsub;
    var ready = false;
    for (0..3000) |_| {
        try pair.pump();
        const subscribed = ga.resourceSnapshot().remote_subscriptions > 0 and gb.resourceSnapshot().remote_subscriptions > 0;
        if (subscribed and ga.sessions.rows[0].outStream() != null and gb.sessions.rows[0].outStream() != null) {
            ready = true;
            break;
        }
    }
    try std.testing.expect(ready);
    for (0..20) |_| try pair.pump();

    var host: TestHost = .{};
    try host.init();
    defer host.deinit();
    try pair.b.setHostWake(host.pipe[0]);
    host.publication = topic;
    var written_ns = std.atomic.Value(u64).init(0);
    const writer = try std.Thread.spawn(.{}, delayedSignal, .{ &host, 30, &written_ns });
    var woke: ?runtime.Result = null;
    var returned_ns: u64 = 0;
    var turns: usize = 0;
    // Each turn waits for its earliest deadline or the wake; the host deadline lies beyond both.
    for (0..64) |_| {
        const now = try currentTime();
        const result = pair.b.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
        returned_ns = monotonicNs();
        turns += 1;
        if (result.failure) |err| return err;
        if (result.readiness.host) {
            woke = result;
            break;
        }
        try std.testing.expectEqual(@as(u32, 0), host.applies);
    }
    writer.join();
    const turn = woke orelse return error.TestUnexpectedResult;
    try std.testing.expect(host.failure == null);
    try std.testing.expectEqual(@as(u32, 1), host.applies);
    try std.testing.expectEqual(@as(usize, 1), host.published);
    try std.testing.expect(turn.transport.datagrams_sent > 0);
    try std.testing.expect(!turn.transport.backlog);
    const latency_ns = returned_ns - written_ns.load(.acquire);
    std.debug.print("host publication wake_to_flush_us={d} turns={d}\n", .{ latency_ns / std.time.ns_per_us, turns });
    try std.testing.expect(latency_ns < 100 * std.time.ns_per_ms);

    var delivered = false;
    for (0..3000) |_| {
        const now = try currentTime();
        _ = pair.a.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
        for (pair.a_inbox.messages()) |message| {
            try std.testing.expectEqualStrings("host publication", message.bytes);
            _ = pair.a.reportValidation(message.handle, .accept, pair.a.last_now);
            delivered = true;
        }
        pair.a_inbox.clear();
        if (delivered) break;
    }
    try std.testing.expect(delivered);
}

test "a host applies only on its wake, a carried-over cap or its deadline" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{63}));
    const opts = options(&key);
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var host: TestHost = .{};
    try host.init();
    defer host.deinit();
    try node.setHostWake(host.pipe[0]);
    for (0..4) |_| {
        const now = try currentTime();
        _ = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    }
    const host_source = @intFromEnum(Source.host);

    // A turn woken by a QUIC datagram, with the host deadline in the future, leaves the host alone.
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    try sender.send(std.testing.io, &node.transport.udp.sockets.primary().address, "junk");
    var now = try currentTime();
    const quic = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
    try std.testing.expect(quic.failure == null and quic.readiness.quic and !quic.readiness.host);
    try std.testing.expectEqual(@as(u32, 0), host.applies);

    // The host deadline bounds the wait and is applied when it passes.
    now = try currentTime();
    const expected: u32 = @intCast(@min(150, (node.nextWakeup(now, .{}) orelse now.mono_ms + 150) -| now.mono_ms));
    const timed = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms + 150));
    try std.testing.expect(timed.failure == null and !timed.readiness.host);
    try std.testing.expectEqual(expected, timed.readiness.timeout_ms);
    if (expected == 150) {
        try std.testing.expect(timed.transport.now.mono_ms >= now.mono_ms + 150);
        try std.testing.expectEqual(@as(u32, 1), host.applies);
    }
    const applied = host.applies;

    // A cap carried over makes the next turn due now under host, without a wake.
    host.more = 1;
    host.signal();
    now = try currentTime();
    const capped = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
    try std.testing.expect(capped.readiness.host);
    try std.testing.expectEqual(applied + 1, host.applies);
    const due = node.due_now_turns[host_source];
    now = try currentTime();
    const carried = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
    try std.testing.expect(!carried.readiness.host);
    try std.testing.expectEqual(@as(u32, 0), carried.readiness.timeout_ms);
    try std.testing.expectEqual(due + 1, node.due_now_turns[host_source]);
    try std.testing.expectEqual(applied + 2, host.applies);

    // A submission that lands after the drain wakes the next poll.
    host.resubmit = true;
    host.signal();
    now = try currentTime();
    const drained = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
    try std.testing.expect(drained.readiness.host);
    now = try currentTime();
    const rewoken = node.step(std.testing.io, now, .{}, host.seam(now.mono_ms +| 5_000));
    try std.testing.expect(rewoken.readiness.host);
    try std.testing.expectEqual(applied + 4, host.applies);
}

const Visits = struct {
    timer: u64,
    collect: u64,
    flush: u64,
    reqresp: u64,
    negotiation: u64,
    gossip: u64,
    control: u64,
    dial: u64,

    fn capture(node: *const runtime.NetworkCore) Visits {
        const engine = node.transport.engine.visits;
        return .{
            .timer = engine.timer,
            .collect = engine.collect,
            .flush = engine.flush,
            .reqresp = node.service.reqresp.visits,
            .negotiation = node.service.router.negotiator.visits,
            .gossip = node.service.gossipsub.sessions.visits,
            .control = node.peer_manager.control.visits,
            .dial = node.peer_manager.dialing.visits,
        };
    }
};

fn datagramsCounted(node: *const runtime.NetworkCore) u64 {
    const coordinator = &node.discovery.?.coordinator;
    var total = coordinator.counters.datagrams_accepted;
    for (coordinator.datagram_rejections) |count| total += count;
    return total;
}

test "a junk flood on the discovery socket costs discovery-only turns in batches" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{64}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    for (0..4) |_| {
        const now = try currentTime();
        _ = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    }
    const settled = try currentTime();
    try std.testing.expect(node.nextWakeup(settled, .{}).? > settled.mono_ms);
    const sender = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);
    const target = node.discovery.?.transport.sockets.primary().address;
    for (0..40) |_| try sender.send(std.testing.io, &target, "junk datagram");
    const visits = Visits.capture(&node);
    const counted = datagramsCounted(&node);
    const readiness = node.counters.readiness_calls;
    for ([_]u16{ runtime.discovery_batch_max, 40 - runtime.discovery_batch_max }) |expected| {
        const now = try currentTime();
        const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 5_000));
        try std.testing.expect(result.failure == null);
        try std.testing.expect(result.readiness.discovery and result.discovery_only);
        try std.testing.expectEqual(expected, result.discovery.datagrams);
        try std.testing.expectEqual(@as(u32, 0), result.transport.datagrams_sent);
    }
    try std.testing.expectEqual(counted + 40, datagramsCounted(&node));
    try std.testing.expectEqual(@as(u64, 2), node.counters.discovery_only_turns);
    try std.testing.expectEqual(readiness + 2, node.counters.readiness_calls);
    try std.testing.expectEqualDeep(visits, Visits.capture(&node));
}

test "discovery readiness with other work due runs a full turn" {
    if (!runtime.wait.supported) return error.SkipZigTest;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{65}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: runtime.NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    for (0..4) |_| {
        const now = try currentTime();
        _ = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms));
    }
    const remote = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer remote.close(std.testing.io);
    const destination = @import("udp.zig").fromNetwork(remote.address);
    _ = try node.transport.engine.dial(&destination, node.peerId(), node.last_now);
    try std.testing.expect(node.transport.engine.backlog());
    try remote.send(std.testing.io, &node.discovery.?.transport.sockets.primary().address, "junk datagram");
    const now = try currentTime();
    const result = node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 5_000));
    try std.testing.expect(result.failure == null and result.readiness.discovery);
    try std.testing.expect(!result.discovery_only);
    try std.testing.expectEqual(@as(u16, 1), result.discovery.datagrams);
    try std.testing.expect(result.transport.datagrams_sent > 0);
    try std.testing.expectEqual(@as(u64, 0), node.counters.discovery_only_turns);
}
