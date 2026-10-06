const std = @import("std");
const PeerManager = @import("peer_manager.zig").PeerManager;
const DiscoveryNeed = @import("peer_manager.zig").DiscoveryNeed;
const t = @import("peers/types.zig");
const Now = @import("types.zig").Now;
const Gossipsub = @import("gossipsub/Gossipsub.zig");
const test_support = @import("gossipsub/test_support.zig");
const policy = @import("peers/policy.zig");
const quic_test_support = @import("quic/test_support.zig");
const wake_sources = @import("wake_sources.zig");
const Source = wake_sources.Source;
const time = @import("time.zig");
const Schedule = @import("schedule.zig").Schedule;
const Dialing = @import("peers/dialing.zig").Dialing;

const Fixture = struct {
    manager: PeerManager,
    gossip: Gossipsub,

    fn init() !Fixture {
        var manager = try PeerManager.init(std.testing.allocator, &.{ .bytes = @splat(0) }, &.{
            .fork = .{ .fork = .fulu },
            .status = .{ .earliest_available_slot = 0 },
            .metadata = .{ .custody_group_count = 1 },
        }, .{
            .peers = .{ .capacity = 4, .outbound_reserve = 0, .target_peers = 1, .max_peers = 4, .min_outbound = 0 },
            .dial = .{ .capacity = 4, .concurrent_max = 2, .seed = 1 },
        }, .initEmpty(), 4);
        errdefer manager.deinit();
        const gossip = try test_support.init(std.testing.allocator, .{
            .random_seed = 1,
            .connected_capacity = 4,
            .retained_capacity = 8,
            .retained_outbound_reserve = 1,
            .seen_capacity = 16,
            .mcache_capacity = 8,
            .validation_capacity = 2,
        });
        return .{ .manager = manager, .gossip = gossip };
    }

    fn deinit(self: *Fixture) void {
        self.gossip.deinit();
        self.manager.deinit();
    }

    fn wakeups(self: *const Fixture, now: Now, capacities: PeerManager.Capacities) wake_sources.Wakeups {
        var result: wake_sources.Wakeups = .{};
        self.manager.collectWakeups(&self.gossip, now, capacities, &result);
        return result;
    }
};

test "peer manager reconciliation reads preserve completed demand and catalog evaluation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const owner = &fixture.manager;
    const g = &fixture.gossip;
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    const view: *const PeerManager = owner;
    try std.testing.expectEqualDeep(policy.Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
    var demand: t.Demand = .{ .attnets = 0x81, .syncnets = 1 };
    demand.group_targets[0] = 1;
    owner.commitDemand(&demand);
    owner.reconcile(g, now);
    const deficits = view.coverageDeficits();
    const need = view.discoveryNeed();
    try std.testing.expectEqual(@as(u16, 2), deficits.attestation);
    try std.testing.expectEqual(@as(u16, 1), deficits.sync);
    try std.testing.expectEqual(@as(u16, 1), deficits.groups);
    try std.testing.expect(need.general and need.custody);
    try std.testing.expectEqual(@as(u8, 0x81), need.attnets[0]);
    try std.testing.expectEqual(@as(u8, 1), need.syncnets);

    owner.commitDemand(&.{});
    try std.testing.expect(fixture.wakeups(now, .{ .peers = 0, .dials = 0 }).sources[@intFromEnum(Source.peer_policy)].runnable);
    const dirty = view.counters;
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.counters);
    owner.reconcile(g, now);
    try std.testing.expectEqualDeep(policy.Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());

    const identity: t.PeerId = .{ .bytes = @splat(1) };
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = owner.catalog.admit(&identity, &view.local_identity, conn, &.{ .direction = .outbound, .endpoint = quic_test_support.server_address, .now_ms = now.millis() }).admitted.peer;
    try std.testing.expect(owner.catalog.updateStatus(peer, conn, &owner.local.status, now.millis()));
    try std.testing.expect(owner.catalog.setDirect(peer, true));
    try std.testing.expect(fixture.wakeups(now, .{ .peers = 0, .dials = 0 }).sources[@intFromEnum(Source.peer_policy)].runnable);
    try std.testing.expectEqualDeep(policy.Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());
    owner.reconcile(g, now);
    try std.testing.expectEqualDeep(policy.Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{}, view.discoveryNeed());
}

test "peer manager reconciliation exhausted revisions stay invalidated" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const owner = &fixture.manager;
    const g = &fixture.gossip;
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    owner.catalog.revision = std.math.maxInt(u64);
    owner.reconcile(g, now);
    const before = owner.counters.selections;
    owner.reconcile(g, now);
    try std.testing.expectEqual(before + 1, owner.counters.selections);
}

test "peer manager wakeups preserve dial bookkeeping and expiry without output capacity" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const owner = &fixture.manager;
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    try owner.connectUntil(&identity, &.{quic_test_support.server_address}, now, 4000);
    owner.native_dial_room = 4;
    const blocked: PeerManager.Capacities = .{ .peers = 0, .dials = 0 };
    const first = fixture.wakeups(now, blocked);
    try std.testing.expect(first.sources[@intFromEnum(Source.dial)].runnable);
    const dirty = owner.catalog.dial.dirty_count;
    const visits = owner.dialing.visits;
    const counters = owner.counters;
    for (0..3) |_| try std.testing.expectEqualDeep(first, fixture.wakeups(now, blocked));
    try std.testing.expectEqual(dirty, owner.catalog.dial.dirty_count);
    try std.testing.expectEqual(visits, owner.dialing.visits);
    try std.testing.expectEqualDeep(counters, owner.counters);

    owner.reconcile(&fixture.gossip, now);
    owner.finishDialBatch(now);
    const deferred = fixture.wakeups(now, blocked).sources[@intFromEnum(Source.dial)];
    try std.testing.expectEqualDeep(Schedule{ .deadline = time.milliseconds(4000) }, deferred);
    try std.testing.expect(fixture.wakeups(now, .{ .peers = 0, .dials = 1 }).sources[@intFromEnum(Source.dial)].due(now.monotonic));

    const expired = Now.fromMilliseconds(.{ .mono_ms = 4000, .unix_s = 3 });
    var close: [Dialing.attempts_max]t.Handle = undefined;
    try std.testing.expectEqual(@as(usize, 0), owner.expireDials(expired, &close).len);
    owner.reconcile(&fixture.gossip, expired);
    try std.testing.expect(owner.catalog.find(&identity) == null);
    try std.testing.expectEqualDeep(Schedule{}, fixture.wakeups(expired, blocked).sources[@intFromEnum(Source.dial)]);
}

test "peer manager quiescence preserves control and peer delivery wakeups" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const owner = &fixture.manager;
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    const identity: t.PeerId = .{ .bytes = @splat(1) };
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const admission = owner.admit(&.{ .peer_id = identity, .conn = conn, .direction = .outbound }, quic_test_support.server_address, now) orelse return error.AdmissionRefused;
    try std.testing.expect(owner.catalog.updateStatus(admission.peer, conn, &owner.local.status, now.millis()));
    var event: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), owner.pollEvents(&event));
    try std.testing.expect(event[0] == .ready);
    try owner.connectUntil(&.{ .bytes = @splat(2) }, &.{quic_test_support.client_address}, now, 4000);
    try std.testing.expect(owner.quiesce(now));

    const blocked = fixture.wakeups(now, .{ .peers = 0, .dials = 1 });
    try std.testing.expect(blocked.sources[@intFromEnum(Source.control)].due(now.monotonic));
    try std.testing.expectEqualDeep(Schedule{}, blocked.sources[@intFromEnum(Source.dial)]);
    try std.testing.expectEqualDeep(Schedule{}, blocked.sources[@intFromEnum(Source.peer_policy)]);
    try std.testing.expectEqualDeep(Schedule{}, blocked.sources[@intFromEnum(Source.peer_events)]);
    try std.testing.expect(fixture.wakeups(now, .{ .peers = 1, .dials = 1 }).sources[@intFromEnum(Source.peer_events)].runnable);
    try std.testing.expectEqual(@as(usize, 1), owner.pollEvents(&event));
    try std.testing.expect(event[0] == .updated);
    try std.testing.expect(!event[0].updated.relevant);
    try std.testing.expectEqualDeep(Schedule{}, fixture.wakeups(now, .{ .peers = 1, .dials = 1 }).sources[@intFromEnum(Source.peer_events)]);
}
