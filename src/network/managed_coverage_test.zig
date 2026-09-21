const gossip_test = @import("gossipsub/test_support.zig");
const std = @import("std");
const managed = @import("managed.zig");
const manager = @import("peer_manager.zig");
const support = @import("managed_test_support.zig");
const t = @import("peers/types.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const attestation = "/eth2/00000000/beacon_attestation_7/ssz_snappy";

fn init(setup: *support.Setup, local: *const t.LocalState) !void {
    var opts = support.options();
    const full = @import("gossipsub/topic_fixture.zig").full;
    opts.service.gossipsub.topic_policy = &.{ full(@splat(0)), full(@splat(1)) };
    opts.service.gossipsub.score_params.topic.weight = 0;
    opts.service.gossipsub.observe_subscriptions = false;
    try setup.initOwnersWithOptions(local, opts);
    errdefer setup.deinit();
    _ = try setup.pair.dial();
}

fn settle(setup: *support.Setup) !void {
    for (0..80) |_| {
        try setup.step(0);
        setup.pair.advance(25);
    }
    setup.client.reconcile(&setup.client_service, setup.pair.now);
}

test "managed coverage counts real duty subscriptions separately from custodians" {
    var setup: support.Setup = .{};
    const local: t.LocalState = .{ .fork = .{ .fork = .fulu, .minimum_sampling_groups = 8 }, .status = .{ .earliest_available_slot = 0 }, .metadata = .{ .custody_group_count = 4 } };
    try init(&setup, &local);
    defer setup.deinit();
    try settle(&setup);
    var snapshots: [4]t.Snapshot = undefined;
    try equal(@as(usize, 1), setup.client.snapshots(&snapshots));
    const peer = snapshots[0];
    try equal(@as(usize, 8), peer.sampling_groups.?.count());
    var demand: t.Demand = .{ .attnets = 1 << 7 };
    for (0..128) |group| if (peer.sampling_groups.?.isSet(group)) {
        demand.group_targets[group] = 1;
        demand.custody_group_targets[group] = 1;
    };
    try setup.client.setDemand(&demand);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 8), setup.client.coverageDeficits().groups);
    try equal(@as(u16, 4), setup.client.coverageDeficits().custody_groups);
    try equal(@as(u16, 1), setup.client.coverageDeficits().attestation);
    try gossip_test.subscribe(setup.server_service.gossipsub, attestation);
    try gossip_test.subscribe(setup.server_service.gossipsub, "/eth2/01010101/beacon_attestation_8/ssz_snappy");
    for (0..@import("preset").NUMBER_OF_COLUMNS) |column| {
        if (!peer.sampling_groups.?.isSet(column % local.fork.custody_groups)) continue;
        var buffer: [80]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "/eth2/00000000/data_column_sidecar_{d}/ssz_snappy", .{column});
        try gossip_test.subscribe(setup.server_service.gossipsub, name);
    }
    try settle(&setup);
    try equal(@as(u16, 0), setup.client.coverageDeficits().groups);
    try equal(@as(u16, 4), setup.client.coverageDeficits().custody_groups);
    try equal(@as(u16, 0), setup.client.coverageDeficits().attestation);
    try expect(setup.client.discoveryNeed().custody);
    try equal(@as(u16, 0), setup.client.selection.coverage.attestation[8]);
    try expect(setup.client_service.gossipsub.overlay.findTopic(attestation) == null);
    try equal(@as(u64, 0), setup.client.policy_scratch[0].stable.attnets);
    setup.pair.advance(setup.client.metadata_freshness_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 8), setup.client.coverageDeficits().custody_groups);
    try equal(@as(u16, 0), setup.client.coverageDeficits().groups);
    try equal(@as(f64, 0), setup.client.catalog.get(peer.peer).?.score);
}

test "managed coverage coalesces subscription and score changes with operation eligibility" {
    var setup: support.Setup = .{};
    try init(&setup, &.{ .fork = .{ .fork = .altair } });
    defer setup.deinit();
    try settle(&setup);
    try setup.client.setDemand(&.{ .attnets = 1 << 7 });
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    const g = setup.client_service.gossipsub;
    var snapshots: [4]t.Snapshot = undefined;
    _ = setup.client.snapshots(&snapshots);
    const conn = snapshots[0].connection.?;
    const index = g.sessions.findPeer(conn).?;
    const baseline = setup.client.counters.selections;
    gossip_test.control(g, index, .{ .subscription = .{ .topic = attestation, .subscribe = true } }, setup.pair.now);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(baseline, setup.client.counters.selections);
    const due = setup.client.policyWakeup(&setup.client_service, setup.pair.now).?;
    try equal(setup.pair.now.mono_ms + manager.coverage_reconcile_interval_ms, due);
    const revision = g.coverageRevision();
    for (0..100) |_| gossip_test.control(g, index, .{ .subscription = .{ .topic = attestation, .subscribe = true } }, setup.pair.now);
    try equal(revision, g.coverageRevision());
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(baseline + 1, setup.client.counters.selections);
    try equal(@as(u16, 0), setup.client.coverageDeficits().attestation);
    gossip_test.penalize(g, conn, 7);
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 0), setup.client.coverageDeficits().attestation);
    try gossip_test.subscribe(g, attestation);
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 1), setup.client.coverageDeficits().attestation);
    try gossip_test.unsubscribe(g, attestation);
    gossip_test.penalize(g, conn, 40);
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 1), setup.client.coverageDeficits().attestation);
    g.peers.scores.rows[g.sessions.rows[index].logical.index].behaviour = 0;
    gossip_test.penalize(g, conn, 0);
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 0), setup.client.coverageDeficits().attestation);
    gossip_test.control(g, index, .{ .subscription = .{ .topic = attestation, .subscribe = false } }, setup.pair.now);
    setup.pair.advance(manager.coverage_reconcile_interval_ms);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 1), setup.client.coverageDeficits().attestation);
    try equal(@as(f64, 0), setup.client.catalog.get(snapshots[0].peer).?.score);
}

test "managed coverage gives initial subscriptions finite grace even after metadata arrives" {
    var setup: support.Setup = .{};
    var opts = support.options();
    opts.peers.target_peers = 1;
    opts.peers.max_peers = 1;
    opts.peers.min_outbound = 0;
    try setup.initOwnersWithOptions(&.{}, opts);
    defer setup.deinit();
    try setup.client.setDemand(&.{ .attnets = 1 });
    _ = try setup.pair.dial();
    try settle(&setup);
    var snapshots: [4]t.Snapshot = undefined;
    try equal(@as(usize, 1), setup.client.snapshots(&snapshots));
    try expect(snapshots[0].metadata != null);
    try equal(@as(u16, 1), setup.client.selection.retained_count);
    const grace = snapshots[0].connected_at_ms + setup.client.control.options.inbound_status_grace_ms;
    setup.pair.advance(grace - setup.pair.now.mono_ms - 1);
    try setup.client.setDemand(&.{ .attnets = 3 });
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 1), setup.client.selection.retained_count);
    setup.pair.advance(1);
    setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u16, 0), setup.client.selection.retained_count);
    try equal(@as(u64, 1), setup.client.counters.policy_disconnects);
    try equal(setup.pair.now.mono_ms + manager.replacement_interval_ms, setup.client.replacement_after_ms);
    try equal(@as(u16, 1), setup.client.selection.dial_budget);
    try equal(@as(u16, 2), setup.client.coverageDeficits().attestation);
    for (0..10) |_| setup.client.reconcile(&setup.client_service, setup.pair.now);
    try equal(@as(u64, 1), setup.client.counters.policy_disconnects);
}
