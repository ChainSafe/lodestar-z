const core_test = @import("network_core_test_support.zig");
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
    const now = try @import("transport.zig").currentTime(std.testing.io);
    return node.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| wait_ms));
}

fn intentFor(node: *const NetworkCore) NetworkCore.LocalIntent {
    return .{
        .update = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() },
        .demand = node.peer_manager.demand,
        .subscriptions = &.{},
    };
}

const IntentPair = struct {
    a: NetworkCore = undefined,
    b: NetworkCore = undefined,
    a_inbox: Inbox = .{},
    b_inbox: Inbox = .{},
    b_app: [4]@import("reqresp/root.zig").ReqResp.Event = undefined,

    fn attachInboxes(self: *IntentPair) void {
        self.a_inbox.attach(self.a.service.gossipsub);
        self.b_inbox.attach(self.b.service.gossipsub);
    }

    fn deinitInboxes(self: *IntentPair) void {
        self.b_inbox.deinit();
        self.a_inbox.deinit();
    }

    /// Gossip delivered in earlier steps is cleared first.
    fn pump(self: *IntentPair) !struct { a: NetworkCore.Result, b: NetworkCore.Result } {
        self.a_inbox.clear();
        self.b_inbox.clear();
        const now = try @import("transport.zig").currentTime(std.testing.io);
        const a = self.a.step(std.testing.io, now, .{}, .deadlineOnly(now.mono_ms +| 1));
        if (a.failure) |err| return err;
        const b = self.b.step(std.testing.io, now, .{ .application = &self.b_app }, .deadlineOnly(now.mono_ms +| 1));
        if (b.failure) |err| return err;
        return .{ .a = a, .b = b };
    }
};

const ActivationSnapshot = struct {
    local: t.LocalState,
    schedule: NetworkCore.ForkSchedule,
    endpoints: ?NetworkCore.AdvertisementEndpoints,
    capabilities: @import("capabilities.zig").Directional,
    request_fork: t.ForkSeq,
    record: d.identity.enr.Record,
    identify: @import("identify/root.zig").Local,

    fn capture(node: *const NetworkCore) ActivationSnapshot {
        return .{
            .local = node.localState(),
            .schedule = node.schedule,
            .endpoints = node.advertisementEndpoints(),
            .capabilities = node.service.router.capabilities(),
            .request_fork = node.service.reqresp.request_fork,
            .record = node.localRecord().?.*,
            .identify = node.service.identify.local,
        };
    }

    fn expectUnchanged(self: *const ActivationSnapshot, node: *const NetworkCore) !void {
        try std.testing.expectEqualDeep(self.local, node.localState());
        try std.testing.expectEqualDeep(self.identify, node.service.identify.local);
        try std.testing.expectEqualDeep(self.schedule, node.schedule);
        try std.testing.expectEqualDeep(self.endpoints, node.advertisementEndpoints());
        try std.testing.expectEqualDeep(self.capabilities, node.service.router.capabilities());
        try std.testing.expectEqual(self.request_fork, node.service.reqresp.request_fork);
        try std.testing.expectEqual(self.record.sequence, node.localRecord().?.sequence);
        try std.testing.expectEqualSlices(u8, self.record.slice(), node.localRecord().?.slice());
    }
};

fn intentBorrowUpdate(node: *NetworkCore, desired: *NetworkCore.LocalIntent) !void {
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

test "core local transaction sequences no-op schedule and rollback" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{
        .session_capacity = 8,
        .challenge_capacity = 8,
        .call_capacity = 8,
    } };
    var node: NetworkCore = undefined;
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
    const scheduled: NetworkCore.ForkSchedule = .{ .fulu_scheduled = true };
    local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, updateLocal(&node, &local, scheduled, now));
    try std.testing.expectEqualSlices(u8, before.slice(), node.localRecord().?.slice());
    local.metadata.custody_group_count = 1;
    try std.testing.expect(try updateLocal(&node, &local, scheduled, now));
    const candidate = try @import("peers/enr.zig").decode(node.localRecord().?, &local.fork);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, candidate.next_fork_digest.?);
    try std.testing.expectEqual(@as(u64, 1), candidate.custody_group_count.?);
    const invalid: NetworkCore.ForkSchedule = .{ .fulu_scheduled = true, .next_digest = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.InvalidSchedule, updateLocal(&node, &local, invalid, now));
}

test "core sequence exhaustion rolls back and future fork hints stay advisory" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{22}));
    var opts = options(&key);
    opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: NetworkCore = undefined;
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
    const schedule: NetworkCore.ForkSchedule = .{ .next_epoch = 100, .next_version = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.SequenceExhausted, updateLocal(&node, &before, schedule, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
    desired = before;
    desired.status.head_slot = 2;
    try std.testing.expect(try updateLocal(&node, &desired, .{}, now));
    try std.testing.expectEqualSlices(u8, record.slice(), node.localRecord().?.slice());
}

test "core explicit advertisement is independent and atomic" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{21}));
    var opts = options(&key);
    opts.startup.bind = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } };
    opts.startup.discovery = .{ .bind = opts.startup.bind };
    var node: NetworkCore = undefined;
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
    for ([_]NetworkCore.AdvertisementEndpoints{
        .{ .ip4 = .{ 0, 1, 2, 3 }, .udp = 19000, .quic = 19001 },
        .{ .ip6 = .{ 0xfe, 0x80 } ++ .{0} ** 13 ++ .{1}, .udp6 = 19000, .quic6 = 19001 },
    }) |invalid| try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &local, .{}, invalid, now));
    const privileged: NetworkCore.AdvertisementEndpoints = .{ .ip4 = .{ 127, 0, 0, 1 }, .udp = 443, .quic = 443 };
    try std.testing.expect(try updateLocalWithEndpoints(&node, &local, .{}, privileged, now));
    try std.testing.expectEqual(@as(u16, 443), node.advertisementEndpoints().?.quic.?);
    const ipv6: NetworkCore.AdvertisementEndpoints = .{ .ip6 = .{0} ** 15 ++ .{1}, .udp6 = 19000, .quic6 = 19001 };
    const previous = node.localRecord().?.*;
    try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &local, .{}, ipv6, now));
    try std.testing.expectEqualSlices(u8, previous.slice(), node.localRecord().?.slice());
}

test "core subscriptions use copied startup policy and reject atomically" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    var opts = options(&key);
    opts.resolved.core.service.gossipsub.topic_policy = &@import("gossipsub/topic_fixture.zig").churn;
    opts.resolved.core.service.gossipsub.topic_params = @splat(.{ .params = .{ .weight = 2 } });
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const calls = backing_node.allocations;
    try std.testing.expectEqual(@as(usize, 4), node.transport.engine.registry.slots.len);
    try std.testing.expectEqual(@as(usize, 0), node.transport.engine.resourceSnapshot().active);
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
    try std.testing.expectEqual(calls, backing_node.allocations);
}

test "core BPO same-fork digest transition updates status and advertisement" {
    const first: @import("types.zig").ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
    const second: @import("types.zig").ForkEntry = .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu };
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    const resolved = try @import("configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{ first, second }, .admission_policy = @import("reqresp/policy_fixture.zig").config() });
    var node: NetworkCore = undefined;
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
    for ([_]@import("types.zig").ForkEntry{
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

test "core request admission selector commits with validated local fork" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{23}));
    var opts = options(&key);
    opts.resolved.core.service.reqresp.request_fork = .gloas;
    var node: NetworkCore = undefined;
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

test "core capabilities activation rolls back all owners on rejected candidates" {
    const caps = @import("capabilities.zig");
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.resolved.core.service.router.meshsub_versions = &.{.v1_2};
    opts.resolved.core.service.identify = .{ .agent = "capability-rollback" };
    opts.resolved.core.service.router.capabilities = caps.withIdentify(try caps.forFork(.phase0, false, &.{.v1_2}));
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const before = ActivationSnapshot.capture(&node);
    const now = node.last_now;
    var update: NetworkCore.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
    update.local.metadata.custody_group_count = 0;
    try std.testing.expectError(error.InvalidCustodyCount, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    update.local.metadata.custody_group_count = null;
    try std.testing.expectError(error.MissingCustodyAdvertisement, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
    update.local = before.local;
    update.local.status.earliest_available_slot = null;
    update.capabilities.receive.insert(.{ .reqresp = .status_v2 });
    try std.testing.expectError(error.MissingAvailability, applyLocal(&node, &update, now));
    try before.expectUnchanged(&node);
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

test "core capabilities activation commits fork BPO and copied directional values" {
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
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const admission = &node.service.reqresp.admission.limiter;
    const identity = node.peerId();
    try std.testing.expectEqual(.allowed, admission.take(&identity, .blocks_by_root_v2, 1, .phase0, node.last_now.mono_ms));
    const admitted_debt = admission.global;
    const admitted_row = admission.rows[0];
    const allocations = backing_node.allocations;
    const before = ActivationSnapshot.capture(&node);
    var update: NetworkCore.LocalUpdate = .{ .local = before.local, .schedule = before.schedule, .endpoints = before.endpoints, .capabilities = before.capabilities };
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
    try std.testing.expectEqual(allocations, backing_node.allocations);
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

test "identify advertisement follows committed endpoints and rejected updates preserve it" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{24}));
    var opts = options(&key);
    opts.resolved.core.service.identify = .{ .agent = "core", .addresses = &.{.{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 19009 } }} };
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .engine = .{ .session_capacity = 8, .challenge_capacity = 8, .call_capacity = 8 } };
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const initial = node.service.identify.local;
    const address = try @import("wire/multiaddr.zig").Multiaddr.decode(initial.addresses[0].bytes[0..initial.addresses[0].len]);
    try std.testing.expectEqual(node.transport.localAddress(), address.address);
    var endpoints = node.advertisementEndpoints().?;
    endpoints.quic = 443;
    const now = node.last_now;
    try std.testing.expect(try updateLocalWithEndpoints(&node, &node.peer_manager.local, node.schedule, endpoints, now));
    const updated = node.service.identify.local;
    const next = try @import("wire/multiaddr.zig").Multiaddr.decode(updated.addresses[0].bytes[0..updated.addresses[0].len]);
    try std.testing.expectEqual(@as(u16, 443), next.address.port());
    endpoints.quic = 0;
    try std.testing.expectError(error.InvalidAdvertisement, updateLocalWithEndpoints(&node, &node.peer_manager.local, node.schedule, endpoints, now));
    try std.testing.expectEqualDeep(updated, node.service.identify.local);
}

test "core complete local intent rejects invalid last topic atomically" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{41}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.identify = .{ .agent = "local-intent" };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: NetworkCore = undefined;
    try node.init(std.testing.allocator, std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const block_topic = "/eth2/01020304/beacon_block/ssz_snappy";
    const update: NetworkCore.LocalUpdate = .{ .local = node.localState(), .schedule = node.schedule, .endpoints = node.advertisementEndpoints(), .capabilities = node.service.router.capabilities() };
    var desired: NetworkCore.LocalIntent = .{ .update = update, .demand = .{}, .subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{block_topic}) };
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

test "core Status-only update preserves local owners and permits a regressing head" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{44}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = std.math.maxInt(u64) };
    opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
    opts.resolved.core.service.identify = .{ .agent = "status-only" };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    var desired = intentFor(&node);
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    desired.subscriptions = @import("gossipsub/topic_fixture.zig").subscriptions(&.{name});
    desired.demand = .{ .attnets = 7, .syncnets = 3 };
    try std.testing.expect(try node.applyIntent(&desired, node.last_now));
    var expected = ActivationSnapshot.capture(&node);
    const identify = node.service.identify.local;
    const now = node.last_now;
    const allocations = backing_node.allocations;
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
        try std.testing.expectEqual(allocations, backing_node.allocations);
        try std.testing.expect(node.peer_manager.selection_revision == null);
    }
}

test "core Status-only validation preserves accepted local state" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{45}));
    var opts = options(&key);
    opts.startup.local.fork = .{ .fork = .fulu, .digest = .{ 1, 2, 3, 4 } };
    opts.startup.local.status.fork_digest = opts.startup.local.fork.digest;
    opts.startup.local.status.earliest_available_slot = 0;
    opts.startup.local.metadata.custody_group_count = 1;
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    var node: NetworkCore = undefined;
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

test "core local intent demand candidate sequence and stopped refusals" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{42}));
    for (0..2) |exhausted| {
        var opts = options(&key);
        opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) }, .sequence = if (exhausted == 0) std.math.maxInt(u64) else 1 };
        if (exhausted == 1) opts.startup.local.metadata.seq_number = std.math.maxInt(u64);
        opts.resolved.core.service.identify = .{ .agent = "local-intent" };
        opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
        var node: NetworkCore = undefined;
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

test "core local intent topic demand no-op preserves Status scheduling and counters" {
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{43}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.gossipsub.topic_policy = &.{@import("gossipsub/topic_fixture.zig").full(.{ 1, 2, 3, 4 })};
    var node: NetworkCore = undefined;
    var backing_node = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try node.init(backing_node.allocator(), std.testing.io, &opts.resolved, opts.startup);
    defer node.deinit(std.testing.io);
    const g = node.service.gossipsub;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const before = ActivationSnapshot.capture(&node);
    const calls = backing_node.allocations;
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
    try std.testing.expectEqual(calls, backing_node.allocations);
}

test "core local intent fork BPO announcements remembered peer and event borrows" {
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
    var backing_pair_b = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try pair.b.init(backing_pair_b.allocator(), std.testing.io, &opts.resolved, opts.startup);
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
    const calls = backing_pair_b.allocations;
    for ([_]*NetworkCore.LocalIntent{ &a_intent, &b_intent }) |intent| {
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
    for ([_]*NetworkCore.LocalIntent{ &a_intent, &b_intent }) |intent| {
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
    try std.testing.expectEqual(calls, backing_pair_b.allocations);
}

test "core local intent three boundaries fit and all-column overlap refuses atomically" {
    const full = @import("gossipsub/topic_fixture.zig").full;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{46}));
    var opts = options(&key);
    opts.startup.discovery = .{ .bind = .{ .ip4 = .loopback(0) } };
    opts.resolved.core.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(.{ 1, 2, 3, 4 }), full(.{ 5, 6, 7, 8 }) };
    var node: NetworkCore = undefined;
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
