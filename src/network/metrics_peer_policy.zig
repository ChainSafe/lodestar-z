const std = @import("std");
const policy = @import("peers/policy.zig");
const t = @import("peers/types.zig");
const prom = @import("metrics_prometheus.zig");
const Distribution = @import("metrics_distribution.zig").Distribution;
const SubnetPeers = Distribution(&.{ 0, 2, 4, 6, 8, 12 });

pub const Snapshot = struct {
    coverage: policy.Counts = .{},
    deficits: policy.Deficits = .{},
    wanted: t.Coverage = .{},
    group_count: u16 = 0,
    dial_budget: u16 = 0,
    disconnects: [@typeInfo(t.DisconnectReason).@"enum".fields.len]u16 = @splat(0),
    catalog_entries: u16 = 0,
    managed_connections: u16 = 0,

    pub fn collect(self: *Snapshot, selection: *const policy.Result, demand: *const t.Demand, slot: u64, group_count: u16) void {
        std.debug.assert(group_count <= self.coverage.groups.len);
        self.* = .{
            .coverage = selection.coverage,
            .deficits = selection.deficits,
            .wanted = if (slot < demand.expires_at_slot) demand.wanted() else .{},
            .group_count = group_count,
            .dial_budget = selection.dial_budget,
        };
        for (selection.reasons) |reason| if (reason) |value| {
            self.disconnects[@intFromEnum(value)] += 1;
        };
    }

    pub fn write(self: *const Snapshot, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try prom.scalar(w, "lodestar_peer_manager_score_map_size", .gauge, "Occupied native peer catalog entries, including retained disconnected identities", self.catalog_entries);
        try prom.scalar(w, "lodestar_peer_manager_connected_peers_map_size", .gauge, "Connections tracked by native peer control schedules", self.managed_connections);
        try prom.scalar(w, "lodestar_peers_requested_total_to_connect", .gauge, "Additional dials permitted by the latest peer selection", self.dial_budget);
        try prom.family(w, "lodestar_peers_requested_total_to_disconnect", .gauge, "Disconnect decisions in the latest native peer selection");
        inline for (@typeInfo(t.DisconnectReason).@"enum".fields) |field|
            try prom.sample(w, "lodestar_peers_requested_total_to_disconnect", "reason", field.name, self.disconnects[field.value]);
        try prom.family(w, "lodestar_discovery_subnet_peers_to_connect", .gauge, "Missing peer memberships across requested subnets after selection");
        try prom.sample(w, "lodestar_discovery_subnet_peers_to_connect", "type", "attnets", self.deficits.attestation);
        try prom.sample(w, "lodestar_discovery_subnet_peers_to_connect", "type", "syncnets", self.deficits.sync);
        try prom.family(w, "lodestar_discovery_subnets_to_connect", .gauge, "Requested subnets with insufficient usable peers");
        try prom.sample(w, "lodestar_discovery_subnets_to_connect", "type", "attnets", @popCount(self.deficits.missing.attnets));
        try prom.sample(w, "lodestar_discovery_subnets_to_connect", "type", "syncnets", @popCount(self.deficits.missing.syncnets));
        try prom.scalar(w, "lodestar_discovery_custody_group_peers_to_connect", .gauge, "Missing peer memberships across requested sampling groups", self.deficits.groups);
        try prom.scalar(w, "lodestar_discovery_custody_groups_to_connect", .gauge, "Requested sampling groups with insufficient usable peers", self.deficits.missing.groups.count());
        try prom.scalar(w, "lodestar_native_peer_outbound_deficit", .gauge, "Missing relevant outbound peers after selection", self.deficits.outbound);
        try prom.family(w, "lodestar_peer_count_per_sampling_group", .gauge, "Retained peers with fresh compatible metadata and available gossip delivery per sampling group");
        for (self.coverage.groups[0..self.group_count], 0..) |count, index|
            try w.print("lodestar_peer_count_per_sampling_group{{groupIndex=\"{d}\"}} {d}\n", .{ index, count });
        try prom.family(w, "lodestar_peer_manager_peers_per_active_subnet", .histogram, "Current usable peer memberships in demanded subnets; rebuilt each snapshot");
        var attnets: SubnetPeers = .{};
        var syncnets: SubnetPeers = .{};
        for (self.coverage.attestation, 0..) |count, index| {
            if (self.wanted.attnets & (@as(u64, 1) << @intCast(index)) != 0) attnets.observe(@floatFromInt(count));
        }
        for (self.coverage.sync, 0..) |count, index| {
            if (self.wanted.syncnets & (@as(u4, 1) << @intCast(index)) != 0) syncnets.observe(@floatFromInt(count));
        }
        try prom.histogram(w, "lodestar_peer_manager_peers_per_active_subnet", "type", "attnets", &attnets);
        try prom.histogram(w, "lodestar_peer_manager_peers_per_active_subnet", "type", "syncnets", &syncnets);
    }
};

test "peer policy metrics use retained coverage, preserve missing memberships and expire demand" {
    var demand: t.Demand = .{ .attnets = 3, .syncnets = 1, .attestation_target = 2, .sync_target = 1, .expires_at_slot = 10 };
    demand.group_targets[0] = 2;
    var inputs = [_]policy.Input{ .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true }, .{ .coverage = .{ .attnets = 3 }, .reject = .banned } };
    inputs[0].coverage.groups.set(0);
    const selected = policy.select(&inputs, &demand, .{ .target_peers = 8, .max_peers = 12 }, 0);
    var snapshot: Snapshot = .{};
    snapshot.collect(&selected, &demand, 9, 128);
    try std.testing.expectEqual(@as(u16, 3), snapshot.deficits.attestation);
    try std.testing.expectEqual(@as(u16, 1), snapshot.coverage.groups[0]);
    try std.testing.expectEqual(@as(u16, 1), snapshot.disconnects[@intFromEnum(t.DisconnectReason.banned)]);
    var buffer: [24 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try snapshot.write(&writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_count_per_sampling_group{groupIndex=\"127\"} 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_manager_peers_per_active_subnet_count{type=\"attnets\"} 2\n") != null);
    snapshot.collect(&.{}, &demand, 10, 64);
    try std.testing.expectEqual(@as(u64, 0), snapshot.wanted.attnets);
    snapshot = .{};
    writer.end = 0;
    try snapshot.write(&writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "groupIndex=") == null);
}
