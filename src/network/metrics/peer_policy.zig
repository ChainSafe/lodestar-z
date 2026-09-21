const std = @import("std");
const policy = @import("../peers/policy.zig");
const t = @import("../peers/types.zig");
const prom = @import("registry.zig");
const Distribution = @import("histogram.zig").Distribution;
const SubnetPeers = Distribution(&.{ 0, 2, 4, 6, 8, 12 });

pub fn write(manager: *const @import("../peer_manager.zig").PeerManager, running: bool, w: *prom.Encoder) prom.Error!void {
    const empty: policy.Result = .{};
    const selection = if (running) &manager.selection else &empty;
    const wanted: t.Coverage = if (running) manager.demand.wanted() else .{};
    const group_count = manager.local.fork.custody_groups;
    var catalog_entries: usize = 0;
    var managed_connections: usize = 0;
    var disconnects: [std.meta.fields(t.DisconnectReason).len]u16 = @splat(0);
    if (running) {
        for (manager.catalog.rows) |*row| catalog_entries += @intFromBool(row.occupied);
        for (manager.control.schedules) |*schedule| managed_connections += @intFromBool(schedule.peer != null);
        for (selection.reasons) |reason| if (reason) |value| {
            disconnects[@intFromEnum(value)] += 1;
        };
    }
    try w.scalar(.{ .name = "lodestar_peers_requested_total_to_connect", .kind = .counter, .help = "Cumulative additional peer dials requested by uncached peer selections" }, manager.requested_connect);
    try w.enums(.{ .name = "lodestar_peers_requested_total_to_disconnect", .kind = .counter, .help = "Cumulative disconnect decisions from uncached peer selections", .labels = &.{"reason"} }, t.DisconnectReason, &manager.requested_disconnect);
    try w.scalar(.{
        .name = "lodestar_peer_manager_score_map_size",
        .kind = .gauge,
        .help = "Occupied native peer catalog entries, including retained disconnected identities",
    }, catalog_entries);
    try w.scalar(.{
        .name = "lodestar_peer_manager_connected_peers_map_size",
        .kind = .gauge,
        .help = "Connections tracked by native peer control schedules",
    }, managed_connections);
    try w.scalar(.{
        .name = "lodestar_native_peer_dials_requested",
        .kind = .gauge,
        .help = "Additional dials permitted by the latest peer selection",
    }, selection.dial_budget);
    try w.enums(.{
        .name = "lodestar_native_peer_disconnects_requested",
        .kind = .gauge,
        .help = "Disconnect decisions in the latest native peer selection",
        .labels = &.{"reason"},
    }, t.DisconnectReason, &disconnects);
    const memberships = try w.family(.{
        .name = "lodestar_discovery_subnet_peers_to_connect",
        .kind = .gauge,
        .help = "Missing peer memberships across requested subnets after selection",
        .labels = &.{"type"},
    });
    try memberships.sample(.{"attnets"}, selection.deficits.attestation);
    try memberships.sample(.{"syncnets"}, selection.deficits.sync);
    const subnets = try w.family(.{
        .name = "lodestar_discovery_subnets_to_connect",
        .kind = .gauge,
        .help = "Requested subnets with insufficient usable peers",
        .labels = &.{"type"},
    });
    try subnets.sample(.{"attnets"}, @popCount(selection.deficits.missing.attnets));
    try subnets.sample(.{"syncnets"}, @popCount(selection.deficits.missing.syncnets));
    try w.scalar(.{
        .name = "lodestar_discovery_custody_group_peers_to_connect",
        .kind = .gauge,
        .help = "Missing peer memberships across requested sampling groups",
    }, selection.deficits.groups);
    try w.scalar(.{
        .name = "lodestar_discovery_custody_groups_to_connect",
        .kind = .gauge,
        .help = "Requested sampling groups with insufficient usable peers",
    }, selection.deficits.missing.groups.count());
    try w.scalar(.{
        .name = "lodestar_native_custody_peers_missing",
        .kind = .gauge,
        .help = "Missing custody service memberships across requested groups",
    }, selection.deficits.custody_groups);
    try w.scalar(.{
        .name = "lodestar_native_custody_groups_missing",
        .kind = .gauge,
        .help = "Requested groups with insufficient custodians",
    }, selection.deficits.missing.custody_groups.count());
    try w.scalar(.{
        .name = "lodestar_native_peer_outbound_deficit",
        .kind = .gauge,
        .help = "Missing relevant outbound peers after selection",
    }, selection.deficits.outbound);
    const sampling_groups = try w.family(.{
        .name = "lodestar_peer_count_per_sampling_group",
        .kind = .gauge,
        .help = "Retained eligible subscribers to every current fork column subnet in each group",
        .labels = &.{"groupIndex"},
    });
    for (selection.coverage.groups[0..group_count], 0..) |count, index| {
        var buffer: [5]u8 = undefined;
        const label = std.fmt.bufPrint(&buffer, "{d}", .{index}) catch unreachable;
        try sampling_groups.sample(.{label}, count);
    }
    const custodians = try w.family(.{
        .name = "lodestar_native_custody_peers",
        .kind = .gauge,
        .help = "Retained healthy custodians with fresh compatible metadata per group",
        .labels = &.{"groupIndex"},
    });
    for (selection.coverage.custody_groups[0..group_count], 0..) |count, index| {
        var buffer: [5]u8 = undefined;
        const label = std.fmt.bufPrint(&buffer, "{d}", .{index}) catch unreachable;
        try custodians.sample(.{label}, count);
    }
    const subnet_peers = try w.histograms(.{
        .name = "lodestar_native_peers_per_active_subnet",
        .kind = .histogram,
        .help = "Current usable peer memberships in demanded subnets; collected from current peer selection",
        .labels = &.{"type"},
        .unit = .scalar,
    }, SubnetPeers);
    var attnets: SubnetPeers = .{};
    var syncnets: SubnetPeers = .{};
    for (selection.coverage.attestation, 0..) |count, index| {
        if (wanted.attnets & (@as(u64, 1) << @intCast(index)) != 0) attnets.observe(@floatFromInt(count));
    }
    for (selection.coverage.sync, 0..) |count, index| {
        if (wanted.syncnets & (@as(u4, 1) << @intCast(index)) != 0) syncnets.observe(@floatFromInt(count));
    }
    try subnet_peers.histogram(.{"attnets"}, &attnets);
    try subnet_peers.histogram(.{"syncnets"}, &syncnets);
}
