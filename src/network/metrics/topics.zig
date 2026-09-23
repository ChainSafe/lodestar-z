const std = @import("std");
const gossip = @import("../gossipsub/root.zig");
const policy = gossip.topic_policy;
const prom = @import("registry.zig");
const Context = @import("context.zig").Context;

pub fn write(context: *const Context, w: *prom.Encoder) prom.Error!void {
    const overlay = context.owner.service.gossipsub.overlay;
    const ns = if (overlay.namespace) |*value| value else return;
    var mesh: [policy.topic_max]u16 = @splat(0);
    var subscribed = std.StaticBitSet(policy.topic_max).initEmpty();
    var visible = std.StaticBitSet(policy.boundary_max).initEmpty();
    if (context.running) {
        for (ns.boundaries, 0..) |*boundary, index| {
            if (std.mem.eql(u8, &boundary.digest, &context.owner.peer_manager.local.fork.digest)) visible.set(index);
        }
        for (&overlay.rows) |*row| {
            if (!row.active) continue;
            const match = ns.lookup(row.string[0..row.string_len]) orelse continue;
            mesh[match.ordinal] = @intCast(row.mesh.count());
            if (!row.subscribed) continue;
            subscribed.set(match.ordinal);
            for (ns.offsets, ns.boundaries, 0..) |starts, boundary, index| {
                const last = starts[policy.kind_count - 1] + boundary.rules[policy.kind_count - 1].count;
                if (match.ordinal >= starts[0] and match.ordinal < last) visible.set(index);
            }
        }
    }
    inline for (.{ "mesh", "topic", "subscriptions" }) |group| {
        inline for (.{ "type", "beacon_attestation_subnet", "sync_committee_subnet", "data_column_subnet" }) |suffix| {
            const metric = try w.family(.{
                .name = (if (std.mem.eql(u8, group, "subscriptions")) "lodestar_native_gossip_subscriptions_by_" else "lodestar_gossip_" ++ group ++ "_peers_by_") ++ suffix ++ "_count",
                .kind = .gauge,
                .help = if (std.mem.eql(u8, group, "subscriptions")) "Local subscriptions in the current and locally subscribed fork boundaries" else if (std.mem.eql(u8, group, "mesh")) "Peer/topic mesh memberships in the current and locally subscribed fork boundaries" else "Accepted remote subscription memberships, including topics without local overlay rows, in the current and locally subscribed fork boundaries",
                .labels = &.{ if (std.mem.eql(u8, suffix, "type")) "type" else "subnet", "boundary" },
            });
            for (ns.boundaries, ns.offsets, 0..) |*boundary, starts, index| {
                if (!visible.isSet(index)) continue;
                const fork = boundary.fork orelse continue;
                var label_buffer: [48]u8 = undefined;
                const boundary_label = std.fmt.bufPrint(&label_buffer, "{s}_{d}", .{ @tagName(fork), boundary.epoch }) catch unreachable;
                inline for (std.meta.fields(policy.Kind)) |kind| {
                    const selected_suffix = comptime switch (@as(policy.Kind, @enumFromInt(kind.value))) {
                        .beacon_attestation => "beacon_attestation_subnet",
                        .sync_committee => "sync_committee_subnet",
                        .data_column_sidecar => "data_column_subnet",
                        else => "type",
                    };
                    if (comptime !std.mem.eql(u8, suffix, selected_suffix)) continue;
                    const count = boundary.rules[kind.value].count;
                    var total: usize = 0;
                    for (0..count) |subnet| {
                        const ordinal = starts[kind.value] + subnet;
                        const value: usize = if (comptime std.mem.eql(u8, group, "mesh")) mesh[ordinal] else if (comptime std.mem.eql(u8, group, "topic")) ns.subscriber_counts[ordinal] else @intFromBool(subscribed.isSet(ordinal));
                        if (comptime std.mem.eql(u8, suffix, "type")) {
                            total += value;
                        } else {
                            var subnet_buffer: [5]u8 = undefined;
                            const label = std.fmt.bufPrint(&subnet_buffer, if (kind.value == @intFromEnum(policy.Kind.beacon_attestation)) "{d:0>2}" else "{d}", .{subnet}) catch unreachable;
                            try metric.sample(.{ label, boundary_label }, value);
                        }
                    }
                    if (comptime std.mem.eql(u8, suffix, "type")) {
                        if (count > 0) try metric.sample(.{ kind.name, boundary_label }, total);
                    }
                }
            }
        }
    }
    inline for (.{ "mesh", "topic" }) |group| {
        const metric = try w.family(.{
            .name = "gossipsub_" ++ group ++ "_peer_count",
            .kind = .gauge,
            .help = if (comptime std.mem.eql(u8, group, "mesh")) "Mesh peers per topic in the current and locally subscribed fork boundaries" else "Subscribed peers per topic in the current and locally subscribed fork boundaries",
            .labels = &.{"topicStr"},
        });
        for (ns.boundaries, ns.offsets, 0..) |*boundary, starts, index| {
            if (!visible.isSet(index)) continue;
            inline for (std.meta.fields(policy.Kind)) |kind| {
                for (0..boundary.rules[kind.value].count) |subnet| {
                    const ordinal = starts[kind.value] + subnet;
                    var name: [gossip.topic.topic_max_len]u8 = undefined;
                    const topic = gossip.topic.buildCanonical(.{ .digest = boundary.digest, .name = .{ .kind = @enumFromInt(kind.value), .subnet = @intCast(subnet) } }, &name);
                    try metric.sample(.{topic}, if (comptime std.mem.eql(u8, group, "mesh")) mesh[ordinal] else ns.subscriber_counts[ordinal]);
                }
            }
        }
    }
}
