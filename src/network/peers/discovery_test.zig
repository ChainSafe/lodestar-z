const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");
const discovery = @import("discovery.zig");
const types = @import("types.zig");
const context = types.ForkContext{ .digest = .{ 1, 2, 3, 4 } };

test "peer discovery answers unknown TALK protocols without demand or candidate output" {
    var requester: Node = undefined;
    try requester.init(31, 9031);
    defer requester.deinit();
    var responder: Node = undefined;
    try responder.init(32, 9032);
    defer responder.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &responder.driver, &context, &.{}, now, .{});
    defer controller.deinit();
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for ([_][]const u8{ "portal/test", "" }, 0..) |protocol, index| {
        const request_id = try d.wire.message.RequestId.init(&.{@intCast(index + 1)});
        const request: d.wire.message.Message = .{ .talk_request = .{
            .request_id = request_id,
            .protocol = protocol,
            .request = "unsupported application data",
        } };
        const handle = try requester.driver.startCall(std.testing.io, .{
            .node_id = responder.engine.localRecord().node_id,
            .address = responder.udp.localAddress(),
        }, responder.engine.localRecord(), &request);
        var completed = false;
        for (0..100) |_| {
            const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
            const result = try controller.step(std.testing.io, tick, tick, &.{});
            if (result.failure) |err| return err;
            try std.testing.expectEqual(@as(usize, 0), result.candidates);
            const received = try requester.driver.stepUntil(std.testing.io, &expiries, tick);
            if (received.failure) |err| return err;
            if (received.event == .response) {
                const response = received.event.response.matched;
                try std.testing.expectEqual(handle, response.handle);
                try std.testing.expect(response.terminal);
                try std.testing.expectEqualDeep(request_id, response.response.talk_response.request_id);
                try std.testing.expectEqual(@as(usize, 0), response.response.talk_response.response.len);
                completed = true;
                break;
            }
        }
        try std.testing.expect(completed);
        try std.testing.expectEqual(@as(usize, 0), requester.engine.calls.count());
    }
}

test "peer discovery TALK send failure preserves call expiry progress" {
    var requester: Node = undefined;
    try requester.init(33, 9033);
    defer requester.deinit();
    var responder: Node = undefined;
    try responder.init(34, 9034);
    defer responder.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    const from: d.types.Endpoint = .{ .node_id = requester.engine.localRecord().node_id, .address = requester.udp.localAddress() };
    const to: d.types.Endpoint = .{ .node_id = responder.engine.localRecord().node_id, .address = responder.udp.localAddress() };
    const session: d.SessionStore.Session = .{ .read_key = @splat(7), .write_key = @splat(7) };
    requester.engine.channel.sessions.install(to, &session, now);
    responder.engine.channel.sessions.install(from, &session, now);
    var controller = try discovery.Discovery.init(std.testing.allocator, &responder.driver, &context, &.{}, now, .{});
    defer controller.deinit();
    const request: d.wire.message.Message = .{ .talk_request = .{
        .request_id = try d.wire.message.RequestId.init(&.{1}),
        .protocol = "unknown",
        .request = &.{},
    } };
    _ = try requester.driver.startCall(std.testing.io, to, responder.engine.localRecord(), &request);
    const expired = try responder.engine.calls.begin(from, &requester.engine.localRecord().public_key, &request, now, d.wire.constants.ordinary_plaintext_size_max);
    var host: SendFailure = .{ .now_ms = now, .receive_real = true };
    const result = try controller.step(host.io(), now, now, &.{});
    try std.testing.expectEqual(error.DestinationUnreachable, result.failure.?);
    try std.testing.expectEqual(d.Driver.FailureStage.process, result.failure_stage);
    try std.testing.expectEqual(@as(usize, 1), host.sends);
    try std.testing.expectEqual(@as(u16, 1), result.unowned);
    try std.testing.expect(responder.engine.calls.endpoint(expired) == null);
    try std.testing.expectEqual(@as(u64, 1), controller.counters.processing_failures);
    try std.testing.expectEqual(@as(u64, 1), controller.counters.query_timeouts);
}

test "peer discovery publishes signed referrals before their discovery endpoint responds" {
    try referralCase(null);
}

test "peer discovery referrals retain fork demand endpoint and output bounds" {
    for ([_]discovery.Rejection{ .incompatible_fork, .demand, .endpoint_scope, .no_quic, .output_capacity }) |reason| {
        try referralCase(reason);
    }
}

fn referralCase(rejection: ?discovery.Rejection) !void {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(2, 9002);
    defer b.deinit();
    var c: Node = undefined;
    try c.init(7, if (rejection == .no_quic) null else if (rejection == .endpoint_scope) 1024 else 9003);
    defer c.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    const b_peer: d.types.Endpoint = .{ .node_id = b.engine.localRecord().node_id, .address = b.udp.localAddress() };
    const c_peer: d.types.Endpoint = .{ .node_id = c.engine.localRecord().node_id, .address = c.udp.localAddress() };
    _ = try a.engine.confirmPeer(&b_peer, b.engine.localRecord(), now);
    _ = try b.engine.confirmPeer(&c_peer, c.engine.localRecord(), now);
    var fork = context;
    if (rejection == .incompatible_fork) fork.digest[0] = 9;
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &fork, &.{}, now, .{});
    defer controller.deinit();
    try controller.request(if (rejection == .demand) .{ .syncnets = 1 } else .{ .general = true }, now);
    const seed = a.engine.peerRecord(&b_peer.node_id).?;
    var lookup: d.Lookup = undefined;
    try lookup.init(&controller.storage.foreground, a.engine.localRecord().node_id, c_peer.node_id, &.{seed}, .dual);
    controller.lookup = lookup;
    var output: [16]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var found: ?adapter.Candidate = null;
    for (0..100) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, output[0..if (rejection == .output_capacity) @as(usize, 0) else output.len]);
        if (result.failure) |err| return err;
        const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (remote.failure) |err| return err;
        for (output[0..result.candidates]) |candidate| {
            if (std.mem.eql(u8, &candidate.node_id, &c_peer.node_id)) found = candidate;
        }
        if (controller.counters.referrals_received > 0) break;
    }
    try std.testing.expectEqual(@as(u64, 1), controller.counters.referrals_received);
    try std.testing.expect(a.engine.peerRecord(&c_peer.node_id) == null);
    if (rejection) |reason| {
        try std.testing.expect(found == null);
        try std.testing.expectEqual(@as(u64, 0), controller.counters.referrals_published);
        try std.testing.expect(controller.rejections[@intFromEnum(reason)] > 0);
        return;
    }
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u64, 1), controller.counters.referrals_published);
    _ = try a.driver.stepUntil(std.testing.io, &expiries, now);
    try adapter.requireIdentity(c.engine.localRecord(), &found.?.peer);
    try std.testing.expectEqual(@as(u16, 9003), found.?.addresses[0].port());
    try handoff(&found.?);
}

test "peer discovery publishes authenticated foreground and bootstrap responders outside a full routing bucket" {
    for ([_]bool{ false, true }) |foreground| {
        var a: Node = undefined;
        try a.init(1, 9001);
        defer a.deinit();
        var b: Node = undefined;
        try b.init(2, 9002);
        defer b.deinit();
        const now = try d.Driver.monotonicMilliseconds(std.testing.io);
        var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{ .query_interval_ms = 1, .local_retry_ms = 1 });
        defer controller.deinit();
        try controller.request(.{ .general = true }, now);
        var output: [1]adapter.Candidate = undefined;
        var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
        var checked = false;
        for (0..300) |_| {
            const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
            if (foreground and controller.lookup == null) controller.query_due_ms = tick;
            const result = try controller.step(std.testing.io, tick, tick, &output);
            if (result.failure) |err| return err;
            const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
            if (remote.failure) |err| return err;
            const progress = try a.driver.stepUntil(std.testing.io, &expiries, tick);
            if (progress.failure) |err| return err;
            const selected = progress.event == .response and progress.event.response.matched.terminal and
                (controller.lookup != null and controller.lookup.?.ownsCall(progress.event.response.matched.handle)) == foreground;
            if (selected) try fillResponderBucket(&a.engine, b.engine.localRecord(), progress.now_ms);
            const consumed = controller.consume(&progress, expiries[0..progress.calls_expired], &output);
            if (consumed.failure) |err| return err;
            if (selected) {
                try std.testing.expect(a.engine.peerRecord(&b.engine.localRecord().node_id) == null);
                try std.testing.expectEqual(@as(usize, 1), consumed.candidates);
                try adapter.requireIdentity(b.engine.localRecord(), &output[0].peer);
                try std.testing.expectEqual(@as(u16, 9002), output[0].addresses[0].port());
                try std.testing.expectEqual(@as(u64, 1), controller.counters.authenticated_not_retained);
                checked = true;
                break;
            }
        }
        try std.testing.expect(checked);
    }
}

fn fillResponderBucket(engine: *d.Engine, responder: *const d.identity.enr.Record, now_ms: u64) !void {
    if (engine.peerRecord(&responder.node_id)) |entry| try std.testing.expect(engine.forgetPeerIfStale(&responder.node_id, entry.last_verified_ms));
    try std.testing.expect(d.types.logDistance(&engine.localRecord().node_id, &responder.node_id) > 8);
    for (1..d.RoutingTable.bucket_size + 1) |index| {
        var record = std.mem.zeroes(d.identity.enr.Record);
        record.node_id = responder.node_id;
        record.node_id[31] ^= @intCast(index);
        record.ip4 = .{ 10, @intCast(index), 0, 1 };
        record.udp = 19_000;
        const peer: d.types.Endpoint = .{ .node_id = record.node_id, .address = record.endpoint().? };
        try std.testing.expectEqual(d.RoutingTable.PutResult.inserted, try engine.confirmPeer(&peer, &record, now_ms));
    }
}

test "peer discovery clears an active foreground walk at demand expiry and can restart" {
    var a: Node = undefined;
    try a.init(61, 9061);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(62, 9062);
    defer b.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    try controller.request(.{ .general = true }, now);
    var candidates: [16]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for (0..100) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &candidates);
        _ = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (result.candidates > 0) break;
    }
    try std.testing.expect(a.engine.peerCount() > 0);
    controller.deinit();
    controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{}, now, .{});
    for ([_]bool{ false, true }) |replace_demand| {
        const tick = now + if (replace_demand) @as(u64, 4000) else @as(u64, 2000);
        try controller.request(.{ .attnets = .{1} ++ .{0} ** 7, .expires_ms = tick + 1 }, tick);
        _ = try controller.step(std.testing.io, tick, now, &candidates);
        try std.testing.expect(controller.lookup != null and controller.lookup.?.waitingCount() > 0);
        const waiting = controller.lookup.?.waitingCount();
        const count = a.engine.calls.count();
        const background = controller.maintenance.pending;
        if (replace_demand) try controller.request(.{}, tick + 1) else _ = try controller.step(std.testing.io, tick + 1, now, &candidates);
        try std.testing.expect(controller.lookup == null);
        try std.testing.expect(a.engine.calls.count() <= count - waiting);
        try std.testing.expectEqualDeep(background, controller.maintenance.pending);
        try std.testing.expect(!controller.stopped);
    }
}

const Node = struct {
    udp: d.Udp,
    engine: d.Engine,
    driver: d.Driver,

    fn init(self: *Node, scalar: u8, quic: ?u16) !void {
        return self.initAddress(scalar, quic, .{ .ip4 = .loopback(0) }, null);
    }
    fn initAddress(self: *Node, scalar: u8, quic: ?u16, bind_address: std.Io.net.IpAddress, alternate_ip4: ?[4]u8) !void {
        return self.initBindings(scalar, quic, .single(bind_address), alternate_ip4);
    }
    fn initBindings(self: *Node, scalar: u8, quic: ?u16, bindings: d.Udp.Bindings, alternate_ip4: ?[4]u8) !void {
        self.udp = try d.Udp.bind(std.testing.io, bindings);
        errdefer self.udp.close(std.testing.io);
        const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{scalar}));
        const local = adapter.LocalAdvertisement{
            .fork = .{ .digest = context.digest, .next_version = @splat(0), .next_epoch = std.math.maxInt(u64) },
            .ip4 = switch (self.udp.localAddress()) {
                .ip4 => |value| value.octets,
                .ip6 => alternate_ip4,
            },
            .ip6 = if (self.udp.sockets.values[1]) |socket| socket.address.ip6.bytes else null,
            .udp = if (self.udp.localAddress() == .ip4) self.udp.localAddress().port() else if (alternate_ip4 != null) @as(u16, 9000) else null,
            .udp6 = if (self.udp.sockets.values[1]) |socket| socket.address.getPort() else null,
            .quic = quic,
        };
        const record = try adapter.build(&key, 1, &local, &context);
        try self.engine.initWithConfig(std.testing.allocator, key, record, .{
            .session_capacity = 8,
            .challenge_capacity = 8,
            .call_capacity = 8,
        });
        self.driver = try d.Driver.initWithConfig(&self.engine, &self.udp, .{ .poll_interval_ms = 1 });
    }
    fn deinit(self: *Node) void {
        self.engine.deinit(std.testing.allocator);
        self.udp.close(std.testing.io);
    }
};

test "peer discovery independent local nodes confirm signed candidates and cancel all owned work" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(2, 9002);
    defer b.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    try controller.request(.{ .general = true }, now);
    var output: [16]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var found = false;
    for (0..100) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &output);
        if (result.failure) |err| return err;
        const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (remote.failure) |err| return err;
        for (output[0..result.candidates]) |candidate| {
            try adapter.requireIdentity(b.engine.localRecord(), &candidate.peer);
            try std.testing.expectEqual(@as(u16, 9002), candidate.addresses[0].port());
            found = true;
        }
        if (found) break;
    }
    try std.testing.expect(found);
    try handoff(&output[0]);
    controller.cancel();
    controller.cancel();
    try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
    try std.testing.expect(controller.nextWakeup(now) == null);
    try std.testing.expectError(error.Stopped, controller.request(.{ .general = true }, now));
    try foregroundQuery(&a, &b);
}

test "peer discovery empty lookup backs off and startup allocations balance" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var controller = try discovery.Discovery.init(allocation.allocator(), &a.driver, &context, &.{}, 10, .{});
    const plan = controller.memoryPlan();
    try std.testing.expectEqual(allocation.allocated_bytes, plan.allocated_bytes);
    try controller.request(.{ .general = true }, 10);
    var out: [1]adapter.Candidate = undefined;
    const result = try controller.step(std.testing.io, 10, 10, &out);
    try std.testing.expectEqual(@as(usize, 0), result.candidates);
    try std.testing.expect(controller.nextWakeup(10).? > 10);
    try std.testing.expectEqual(@as(u64, 1), controller.lookup_time.count);
    try std.testing.expectEqual(@as(u64, 1), controller.lookup_finishes[@intFromEnum(d.Lookup.FinishReason.exhausted)]);
    const completed = controller.lookup_time;
    const progress: d.Driver.StepResult = .{ .now_ms = 11 };
    _ = controller.consume(&progress, &.{}, &out);
    try std.testing.expectEqualDeep(completed, controller.lookup_time);
    try std.testing.expect(controller.last_candidate_ms == null);
    try std.testing.expectEqual(allocation.allocated_bytes, plan.allocated_bytes);
    controller.deinit();
    try std.testing.expectEqual(allocation.allocated_bytes, allocation.freed_bytes);
    var failed = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, discovery.Discovery.init(failed.allocator(), &a.driver, &context, &.{}, 10, .{}));
}

test "peer discovery QUIC relay checks reject public to private and unscoped IPv6" {
    const public: d.types.Address = .{ .ip4 = .{ .octets = .{ 8, 8, 8, 8 }, .port = 9000 } };
    const local: d.types.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9000 } };
    for ([_][4]u8{ .{ 127, 0, 0, 1 }, .{ 10, 0, 0, 1 }, .{ 100, 64, 0, 1 }, .{ 169, 254, 0, 1 }, .{ 0, 0, 0, 0 }, .{ 224, 0, 0, 1 } }) |ip| {
        try std.testing.expect(!discovery.relayAllowed(public, .{ .ip4 = .{ .octets = ip, .port = 9001 } }));
    }
    try std.testing.expect(discovery.relayAllowed(local, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9001 } }));
    try std.testing.expect(!discovery.relayAllowed(public, .{ .ip4 = .{ .octets = .{ 8, 8, 4, 4 }, .port = 1024 } }));
    const link: [16]u8 = .{ 0xfe, 0x80 } ++ .{0} ** 13 ++ .{1};
    try std.testing.expect(!discovery.relayAllowed(.{ .ip6 = .{ .octets = link, .port = 9000 } }, .{ .ip6 = .{ .octets = link, .port = 9001 } }));
    const mapped: [16]u8 = .{0} ** 10 ++ .{ 0xff, 0xff, 127, 0, 0, 1 };
    try std.testing.expect(!discovery.relayAllowed(public, .{ .ip6 = .{ .octets = mapped, .port = 9001 } }));
}

test "peer discovery consumes actual response and expiry alongside failure before borrowed scratch reuse" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(2, 9002);
    defer b.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    try controller.request(.{ .general = true }, now);
    var output: [1]adapter.Candidate = undefined;
    _ = try controller.step(std.testing.io, now, now, &output);
    const active = a.engine.calls.count();
    var stale = controller.maintenance.pending.?.handle.?;
    stale.generation += 1;
    const stale_result = controller.consume(&.{ .now_ms = now, .event = .{ .failed = .{ .handle = stale, .peer = .{ .node_id = b.engine.localRecord().node_id, .address = b.udp.localAddress() }, .reason = error.InvalidRecord } } }, &.{}, &output);
    try std.testing.expectEqual(@as(u16, 1), stale_result.unowned);
    try std.testing.expectEqual(active, a.engine.calls.count());
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var candidate: ?adapter.Candidate = null;
    for (0..30) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (remote.failure) |err| return err;
        var progress = try a.driver.stepUntil(std.testing.io, &expiries, tick);
        const response = progress.event == .response;
        if (response) {
            progress.failure = error.DestinationUnreachable;
            progress.failure_stage = .process;
        }
        const consumed = controller.consume(&progress, expiries[0..progress.calls_expired], &output);
        if (response) {
            try std.testing.expectEqual(error.DestinationUnreachable, consumed.failure.?);
            try std.testing.expectEqual(d.Driver.FailureStage.process, consumed.failure_stage);
            try std.testing.expectEqual(@as(u64, 1), controller.counters.processing_failures);
            try std.testing.expectEqual(@as(usize, 1), consumed.candidates);
            candidate = output[0];
            break;
        }
    }
    try std.testing.expect(candidate != null);
    _ = try a.driver.stepUntil(std.testing.io, &expiries, now);
    try adapter.requireIdentity(b.engine.localRecord(), &candidate.?.peer);
    try std.testing.expectEqual(@as(u16, 9002), candidate.?.addresses[0].port());
    const future = now + 60_000;
    _ = try controller.step(std.testing.io, future, now, &.{});
    try std.testing.expect(a.engine.calls.count() > 0);
    const expired = a.engine.tick(future + 1_000, &expiries);
    try std.testing.expect(expired.calls > 0);
    const consumed = controller.consume(&.{ .now_ms = future + 1_000, .calls_expired = expired.calls, .failure = error.DestinationUnreachable }, expiries[0..expired.calls], &.{});
    try std.testing.expectEqual(expired.calls, consumed.expired);
    try std.testing.expectEqual(error.DestinationUnreachable, consumed.failure.?);
    controller.cancel();
    try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
}

test "peer discovery no QUIC nodes remain confirmed but produce no dial candidates" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(2, null);
    defer b.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    try controller.request(.{ .general = true }, now);
    var output: [1]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var rejected: usize = 0;
    for (0..30) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &output);
        if (result.failure) |err| return err;
        rejected += result.rejected;
        try std.testing.expectEqual(@as(usize, 0), result.candidates);
        const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (remote.failure) |err| return err;
        if (rejected > 0) break;
    }
    try std.testing.expect(rejected > 0);
    try std.testing.expectEqual(@as(usize, 1), a.engine.peerCount());
    controller.cancel();
    try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
}

const SendFailure = struct {
    now_ms: u64,
    sends: usize = 0,
    receive_real: bool = false,
    fn io(self: *SendFailure) std.Io {
        const vtable = comptime blk: {
            var value = std.Io.failing.vtable.*;
            value.randomSecure = random;
            value.batchAwaitConcurrent = receive;
            value.now = currentTime;
            value.netSend = send;
            break :blk value;
        };
        return .{ .userdata = self, .vtable = &vtable };
    }
    fn random(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        return std.Io.randomSecure(std.testing.io, buffer);
    }
    fn receive(context_ptr: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self: *SendFailure = @ptrCast(@alignCast(context_ptr.?));
        if (self.receive_real) return std.testing.io.vtable.batchAwaitConcurrent(std.testing.io.userdata, batch, timeout);
        return error.ConcurrencyUnavailable;
    }
    fn currentTime(context_ptr: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *SendFailure = @ptrCast(@alignCast(context_ptr.?));
        return .{ .nanoseconds = @as(i96, @intCast(self.now_ms)) * std.time.ns_per_ms };
    }
    fn send(context_ptr: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *SendFailure = @ptrCast(@alignCast(context_ptr.?));
        self.sends += 1;
        return .{ error.NetworkUnreachable, 0 };
    }
};

test "peer discovery failed initial send cancels call and defers maintenance retry" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var b: Node = undefined;
    try b.init(2, 9002);
    defer b.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{b.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    var host = SendFailure{ .now_ms = now };
    const result = try controller.step(host.io(), now, now, &.{});
    try std.testing.expectEqual(error.DestinationUnreachable, result.failure.?);
    try std.testing.expectEqual(@as(usize, 1), host.sends);
    try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
    try std.testing.expect(controller.nextWakeup(now).? >= now + 1_000);
}

fn handoff(candidate: *const adapter.Candidate) !void {
    const support = @import("../test_support.zig");
    const core_mod = @import("../core.zig");
    const dial = @import("dial_queue.zig");
    var pair = support.Pair{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 }, .{ .connections_max = 4, .handshaking_max = 4, .handshaking_per_source_max = 4, .dialing_max = 2 });
    defer pair.deinit();
    var core = try core_mod.Core.init(std.testing.allocator, &pair.client_ctx.local_peer_id, &.{ .fork = context, .status = .{ .fork_digest = context.digest } }, @import("../core_test.zig").options());
    defer core.deinit();
    defer core.shutdown(&pair.client, pair.now);
    try core.discovered(candidate, pair.now);
    try std.testing.expectEqual(candidate.sequence, core.dial_queue.rows[0].hints.?.sequence);
    var intents: [2]dial.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), core.dialIntents(&pair.client, pair.now, &intents));
    try std.testing.expect(intents[0].peer.eql(&candidate.peer));
    try std.testing.expectEqual(candidate.addresses[0], intents[0].address);
    try std.testing.expect(core.dialFailed(intents[0].token, pair.now));
    try core.discovered(candidate, pair.now);
    try std.testing.expectEqual(@as(usize, 0), core.dialIntents(&pair.client, pair.now, &intents));
    for (3..6) |scalar| {
        const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{@as(u8, @intCast(scalar))}));
        const identity = types.PeerId.fromPublicKey(&key.publicKey());
        try core.connect(&identity, candidate.addresses[0..candidate.address_count], pair.now);
    }
    const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{6}));
    try std.testing.expectError(error.Capacity, core.connect(&types.PeerId.fromPublicKey(&key.publicKey()), candidate.addresses[0..candidate.address_count], pair.now));
    try core.discovered(candidate, pair.now);
    const count = core.dialIntents(&pair.client, pair.now, &intents);
    try std.testing.expectEqual(@as(usize, 2), count);
    for (intents[0..count]) |intent| try std.testing.expect(!intent.peer.eql(&candidate.peer));
}

test "peer discovery fork and subnet filtering plus output pressure preserve confirmed routing" {
    for (0..5) |mode| {
        var a: Node = undefined;
        try a.init(1, 9001);
        defer a.deinit();
        var b: Node = undefined;
        try b.init(2, 9002);
        defer b.deinit();
        if (mode >= 3) {
            const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{2}));
            const dual = try adapter.build(&key, 2, &.{
                .fork = .{ .digest = context.digest, .next_version = @splat(0), .next_epoch = 0 },
                .ip4 = .{ 127, 0, 0, 1 },
                .udp = b.udp.localAddress().port(),
                .ip6 = .{0} ** 15 ++ .{1},
                .quic6 = 9003,
            }, &context);
            try b.engine.updateLocalRecord(&dual);
        }
        const now = try d.Driver.monotonicMilliseconds(std.testing.io);
        var fork = context;
        if (mode == 0) fork.digest[0] = 9;
        var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &fork, &.{b.engine.localRecord().*}, now, .{ .quic_mode = if (mode == 4) .ip4 else .dual });
        defer controller.deinit();
        try controller.request(if (mode == 1) .{ .syncnets = 1 } else .{ .general = true }, now);
        var output: [1]adapter.Candidate = undefined;
        var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
        var filtered: usize = 0;
        for (0..30) |_| {
            const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
            const result = try controller.step(std.testing.io, tick, tick, output[0..if (mode == 2) @as(usize, 0) else 1]);
            if (result.failure) |err| return err;
            filtered += if (mode == 2) result.dropped else result.rejected;
            try std.testing.expectEqual(@as(usize, 0), result.candidates);
            const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
            if (remote.failure) |err| return err;
            if (filtered > 0) break;
        }
        try std.testing.expect(filtered > 0);
        const reason: discovery.Rejection = switch (mode) {
            0 => .incompatible_fork,
            1 => .demand,
            2 => .output_capacity,
            3 => .endpoint_scope,
            4 => .endpoint_family,
            else => unreachable,
        };
        try std.testing.expect(controller.rejections[@intFromEnum(reason)] > 0);
        try std.testing.expectEqual(@as(usize, 1), a.engine.peerCount());
        controller.cancel();
        try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
    }
}

fn foregroundQuery(a: *Node, b: *Node) !void {
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{}, now, .{});
    defer controller.deinit();
    try controller.request(.{ .general = true }, now);
    var output: [1]adapter.Candidate = undefined;
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    var found = false;
    var started: usize = 0;
    for (0..30) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &output);
        if (result.failure) |err| return err;
        started += result.started;
        const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
        if (remote.failure) |err| return err;
        if (result.candidates != 0) {
            try adapter.requireIdentity(b.engine.localRecord(), &output[0].peer);
            try std.testing.expect(controller.lookup != null);
            try std.testing.expectEqual(@as(u64, 0), controller.counters.lookups_completed);
            try std.testing.expectEqual(@as(u64, 1), controller.counters.candidates_published);
            try std.testing.expect(controller.last_candidate_ms != null);
            found = true;
            break;
        }
    }
    try std.testing.expect(found and started != 0);
    try std.testing.expect(controller.nextWakeup(now).? >= now);
    controller.cancel();
    try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
}

test "peer discovery initialization rollback and coalesced demand retain query deadline" {
    var a: Node = undefined;
    try a.init(1, 9001);
    defer a.deinit();
    var allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = allocation.allocator();
    try std.testing.expectError(error.InvalidConfig, discovery.Discovery.init(allocator, &a.driver, &context, &.{}, 0, .{ .maintenance = .{ .retry_interval_ms = 0 } }));
    try std.testing.expectEqual(allocation.allocated_bytes, allocation.freed_bytes);
    const key = try d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{2}));
    const no_endpoint = try adapter.build(&key, 1, &.{ .fork = .{ .digest = context.digest, .next_version = @splat(0), .next_epoch = 0 } }, &context);
    try std.testing.expectError(error.InvalidBootstrap, discovery.Discovery.init(allocator, &a.driver, &context, &.{no_endpoint}, 0, .{}));
    try std.testing.expectEqual(allocation.allocated_bytes, allocation.freed_bytes);
    var controller = try discovery.Discovery.init(allocator, &a.driver, &context, &.{}, 0, .{});
    defer controller.deinit();
    try std.testing.expectError(error.InvalidDemand, controller.request(.{ .syncnets = 0x10 }, 0));
    try controller.request(.{ .general = true }, 0);
    const result = try controller.step(std.testing.io, 0, 0, &.{});
    try std.testing.expectEqual(@as(usize, 0), result.candidates);
    const next = controller.nextWakeup(0);
    for (0..100) |_| try controller.request(.{ .general = true }, 0);
    try std.testing.expectEqual(next, controller.nextWakeup(0));
    var invalid = context;
    invalid.custody_groups = 0;
    try std.testing.expectError(error.InvalidForkContext, controller.updateFork(&invalid));
    try controller.updateFork(&context);
}

test "peer discovery foreground retains authenticated IPv6 source over alternate signed IPv4" {
    for ([_][4]u8{ .{ 10, 0, 0, 1 }, .{ 127, 0, 0, 1 } }) |alternate| {
        var a: Node = undefined;
        try a.initAddress(1, null, .{ .ip6 = .loopback(0) }, null);
        defer a.deinit();
        var b: Node = undefined;
        try b.initAddress(2, 9001, .{ .ip6 = .loopback(0) }, alternate);
        defer b.deinit();
        _ = try b.driver.startCall(std.testing.io, .{ .node_id = a.engine.localRecord().node_id, .address = a.udp.localAddress() }, a.engine.localRecord(), &.{ .ping = .{ .request_id = try d.wire.message.RequestId.init(&.{1}), .enr_sequence = 1 } });
        var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
        var authenticated = false;
        for (0..30) |_| {
            const now = try d.Driver.monotonicMilliseconds(std.testing.io);
            const incoming = try a.driver.stepUntil(std.testing.io, &expiries, now);
            if (incoming.failure) |err| return err;
            const response = try b.driver.stepUntil(std.testing.io, &expiries, now);
            if (response.failure) |err| return err;
            if (response.event == .response) {
                authenticated = true;
                break;
            }
        }
        try std.testing.expect(authenticated);
        const entry = a.engine.peerRecord(&b.engine.localRecord().node_id).?;
        try std.testing.expectEqualDeep(b.udp.localAddress(), entry.peer.address);
        try std.testing.expect(entry.record.endpoint().? == .ip4);
        const now = try d.Driver.monotonicMilliseconds(std.testing.io);
        var controller = try discovery.Discovery.init(std.testing.allocator, &a.driver, &context, &.{}, now, .{});
        defer controller.deinit();
        try controller.request(.{ .general = true }, now);
        var output: [1]adapter.Candidate = undefined;
        var completed = false;
        for (0..30) |_| {
            const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
            const result = try controller.step(std.testing.io, tick, tick, &output);
            if (result.failure) |err| return err;
            try std.testing.expectEqual(@as(usize, 0), result.candidates);
            if (result.rejected > 0) {
                completed = true;
                break;
            }
            const remote = try b.driver.stepUntil(std.testing.io, &expiries, tick);
            if (remote.failure) |err| return err;
        }
        try std.testing.expect(completed);
        try std.testing.expect(controller.lookup != null);
        controller.cancel();
        try std.testing.expectEqual(@as(usize, 0), a.engine.calls.count());
    }
}

test "dual-stack discovery confirms both families in one routing table" {
    var hub: Node = undefined;
    try hub.initBindings(91, null, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } }, null);
    defer hub.deinit();
    var ipv4: Node = undefined;
    try ipv4.init(92, null);
    defer ipv4.deinit();
    var ipv6: Node = undefined;
    try ipv6.initAddress(93, null, .{ .ip6 = .loopback(0) }, null);
    defer ipv6.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &hub.driver, &context, &.{ ipv4.engine.localRecord().*, ipv6.engine.localRecord().* }, now, .{ .maintenance = .{ .bootstrap_interval_ms = 1, .discovery_stall_ms = 1, .retry_interval_ms = 1 } });
    defer controller.deinit();
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for (0..400) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &.{});
        if (result.failure) |err| return err;
        for ([_]*Node{ &ipv4, &ipv6 }) |node| {
            const remote = try node.driver.stepUntil(std.testing.io, &expiries, tick);
            if (remote.failure) |err| return err;
        }
        if (hub.engine.peerCount() == 2) break;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(usize, 2), hub.engine.peerCount());
    try std.testing.expect(hub.engine.peerRecord(&ipv4.engine.localRecord().node_id).?.peer.address == .ip4);
    try std.testing.expect(hub.engine.peerRecord(&ipv6.engine.localRecord().node_id).?.peer.address == .ip6);
}

test "IPv6-only discovery bootstraps a dual-stack record over IPv6" {
    var node: Node = undefined;
    try node.initAddress(94, null, .{ .ip6 = .loopback(0) }, null);
    defer node.deinit();
    var seed: Node = undefined;
    try seed.initAddress(95, null, .{ .ip6 = .loopback(0) }, .{ 127, 0, 0, 1 });
    defer seed.deinit();
    const now = try d.Driver.monotonicMilliseconds(std.testing.io);
    var controller = try discovery.Discovery.init(std.testing.allocator, &node.driver, &context, &.{seed.engine.localRecord().*}, now, .{});
    defer controller.deinit();
    var expiries: [d.CallTable.capacity_max]d.CallTable.Expired = undefined;
    for (0..100) |_| {
        const tick = try d.Driver.monotonicMilliseconds(std.testing.io);
        const result = try controller.step(std.testing.io, tick, tick, &.{});
        if (result.failure) |err| return err;
        const response = try seed.driver.stepUntil(std.testing.io, &expiries, tick);
        if (response.failure) |err| return err;
        if (node.engine.peerCount() == 1) break;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(node.engine.peerRecord(&seed.engine.localRecord().node_id).?.peer.address == .ip6);
}
