const std = @import("std");
const prom = @import("registry.zig");

/// The latest peer selection's deficits and sampling-group coverage. Gauges read zero once the
/// owner stops.
pub fn write(manager: *const @import("../peer_manager.zig").PeerManager, running: bool, w: *prom.Encoder) prom.Error!void {
    const empty: @import("../peers/policy.zig").Result = .{};
    const selection = if (running) &manager.selection else &empty;
    const memberships = try w.family(.{
        .name = "lodestar_discovery_subnet_peers_to_connect",
        .kind = .gauge,
        .help = "Missing peer memberships across requested subnets after selection",
        .labels = &.{"type"},
    });
    try memberships.sample(.{"attnets"}, selection.deficits.attestation);
    try memberships.sample(.{"syncnets"}, selection.deficits.sync);
    try w.scalar(.{
        .name = "lodestar_discovery_custody_group_peers_to_connect",
        .kind = .gauge,
        .help = "Missing peer memberships across requested sampling groups",
    }, selection.deficits.groups);
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
    for (selection.coverage.groups[0..manager.local.fork.custody_groups], 0..) |count, index| {
        var buffer: [5]u8 = undefined;
        const label = std.fmt.bufPrint(&buffer, "{d}", .{index}) catch unreachable;
        try sampling_groups.sample(.{label}, count);
    }
}
