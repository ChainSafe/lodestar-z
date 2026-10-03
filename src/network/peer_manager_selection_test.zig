const std = @import("std");
const PeerManager = @import("peer_manager.zig").PeerManager;
const DiscoveryNeed = @import("peer_manager.zig").DiscoveryNeed;
const t = @import("peers/types.zig");
const Now = @import("types.zig").Now;
const Gossipsub = @import("gossipsub/Gossipsub.zig");

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
        const gossip = try @import("gossipsub/test_support.zig").init(std.testing.allocator, .{
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
};

test "peer manager reconciliation reads preserve completed demand and catalog evaluation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const owner = &fixture.manager;
    const g = &fixture.gossip;
    const now = Now.fromMilliseconds(.{ .mono_ms = 1000, .unix_s = 0 });
    const view: *const PeerManager = owner;
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
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
    try std.testing.expect(owner.policySchedule(g).runnable);
    const dirty = view.counters;
    for (0..8) |_| {
        try std.testing.expectEqualDeep(deficits, view.coverageDeficits());
        try std.testing.expectEqualDeep(need, view.discoveryNeed());
    }
    try std.testing.expectEqualDeep(dirty, view.counters);
    owner.reconcile(g, now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());

    const identity: t.PeerId = .{ .bytes = @splat(1) };
    const conn: t.Handle = .{ .index = 0, .generation = 1 };
    const peer = owner.catalog.admit(&identity, &view.local_identity, conn, &.{ .direction = .outbound, .endpoint = @import("quic/test_support.zig").server_address, .now_ms = now.millis() }).admitted.peer;
    try std.testing.expect(owner.catalog.updateStatus(peer, conn, &owner.local.status, now.millis()));
    try std.testing.expect(owner.catalog.setDirect(peer, true));
    try std.testing.expect(owner.policySchedule(g).runnable);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
    try std.testing.expectEqualDeep(DiscoveryNeed{ .general = true }, view.discoveryNeed());
    owner.reconcile(g, now);
    try std.testing.expectEqualDeep(@import("peers/policy.zig").Deficits{}, view.coverageDeficits());
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
