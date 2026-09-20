const std = @import("std");
const policy = @import("../peers/policy.zig");
const t = @import("../peers/types.zig");
const prom = @import("registry.zig");
const Distribution = @import("histogram.zig").Distribution;
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

    pub fn write(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
        try w.scalar(.{
            .name = "lodestar_peer_manager_score_map_size",
            .kind = .gauge,
            .help = "Occupied native peer catalog entries, including retained disconnected identities",
        }, self.catalog_entries);
        try w.scalar(.{
            .name = "lodestar_peer_manager_connected_peers_map_size",
            .kind = .gauge,
            .help = "Connections tracked by native peer control schedules",
        }, self.managed_connections);
        try w.scalar(.{
            .name = "lodestar_peers_requested_total_to_connect",
            .kind = .gauge,
            .help = "Additional dials permitted by the latest peer selection",
        }, self.dial_budget);
        try w.enums(.{
            .name = "lodestar_peers_requested_total_to_disconnect",
            .kind = .gauge,
            .help = "Disconnect decisions in the latest native peer selection",
            .labels = &.{"reason"},
        }, t.DisconnectReason, &self.disconnects);
        const memberships = try w.family(.{
            .name = "lodestar_discovery_subnet_peers_to_connect",
            .kind = .gauge,
            .help = "Missing peer memberships across requested subnets after selection",
            .labels = &.{"type"},
        });
        try memberships.sample(.{"attnets"}, self.deficits.attestation);
        try memberships.sample(.{"syncnets"}, self.deficits.sync);
        const subnets = try w.family(.{
            .name = "lodestar_discovery_subnets_to_connect",
            .kind = .gauge,
            .help = "Requested subnets with insufficient usable peers",
            .labels = &.{"type"},
        });
        try subnets.sample(.{"attnets"}, @popCount(self.deficits.missing.attnets));
        try subnets.sample(.{"syncnets"}, @popCount(self.deficits.missing.syncnets));
        try w.scalar(.{
            .name = "lodestar_discovery_custody_group_peers_to_connect",
            .kind = .gauge,
            .help = "Missing peer memberships across requested sampling groups",
        }, self.deficits.groups);
        try w.scalar(.{
            .name = "lodestar_discovery_custody_groups_to_connect",
            .kind = .gauge,
            .help = "Requested sampling groups with insufficient usable peers",
        }, self.deficits.missing.groups.count());
        try w.scalar(.{
            .name = "lodestar_native_custody_peers_missing",
            .kind = .gauge,
            .help = "Missing custody service memberships across requested groups",
        }, self.deficits.custody_groups);
        try w.scalar(.{
            .name = "lodestar_native_custody_groups_missing",
            .kind = .gauge,
            .help = "Requested groups with insufficient custodians",
        }, self.deficits.missing.custody_groups.count());
        try w.scalar(.{
            .name = "lodestar_native_peer_outbound_deficit",
            .kind = .gauge,
            .help = "Missing relevant outbound peers after selection",
        }, self.deficits.outbound);
        const sampling_groups = try w.family(.{
            .name = "lodestar_peer_count_per_sampling_group",
            .kind = .gauge,
            .help = "Retained eligible subscribers to every current fork column subnet in each group",
            .labels = &.{"groupIndex"},
        });
        for (self.coverage.groups[0..self.group_count], 0..) |count, index| {
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
        for (self.coverage.custody_groups[0..self.group_count], 0..) |count, index| {
            var buffer: [5]u8 = undefined;
            const label = std.fmt.bufPrint(&buffer, "{d}", .{index}) catch unreachable;
            try custodians.sample(.{label}, count);
        }
        const subnet_peers = try w.histograms(.{
            .name = "lodestar_peer_manager_peers_per_active_subnet",
            .kind = .histogram,
            .help = "Current usable peer memberships in demanded subnets; rebuilt each snapshot",
            .labels = &.{"type"},
            .unit = .scalar,
        }, SubnetPeers);
        var attnets: SubnetPeers = .{};
        var syncnets: SubnetPeers = .{};
        for (self.coverage.attestation, 0..) |count, index| {
            if (self.wanted.attnets & (@as(u64, 1) << @intCast(index)) != 0) attnets.observe(@floatFromInt(count));
        }
        for (self.coverage.sync, 0..) |count, index| {
            if (self.wanted.syncnets & (@as(u4, 1) << @intCast(index)) != 0) syncnets.observe(@floatFromInt(count));
        }
        try subnet_peers.histogram(.{"attnets"}, &attnets);
        try subnet_peers.histogram(.{"syncnets"}, &syncnets);
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
    var encoder: prom.Encoder = .{ .writer = &writer };
    try snapshot.write(&encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_count_per_sampling_group{groupIndex=\"127\"} 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_discovery_subnet_peers_to_connect{type=\"attnets\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_manager_peers_per_active_subnet_count{type=\"attnets\"} 2\n") != null);
    snapshot.collect(&.{}, &demand, 10, 64);
    try std.testing.expectEqual(@as(u64, 0), snapshot.wanted.attnets);
    snapshot = .{};
    writer.end = 0;
    encoder = .{ .writer = &writer };
    try snapshot.write(&encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "groupIndex=") == null);
}
