const std = @import("std");
const t = @import("types.zig");
const w = @import("../control_wire.zig");
const Catalog = @import("catalog.zig").Catalog;
const Control = @import("control.zig").Control;
const ControlProtocol = @import("../control_protocol.zig").ControlProtocol;
const relevance = @import("control.zig").relevance;

test "control repeated Status intent preserves the first due time" {
    var control = try Control.init(std.testing.allocator, .{}, 2);
    defer control.deinit(std.testing.allocator);
    var requests = try ControlProtocol.init(std.testing.allocator, 2, 2, 1);
    defer requests.deinit(std.testing.allocator);
    var catalog = try Catalog.init(std.testing.allocator, .{ .capacity = 2, .outbound_reserve = 0, .target_peers = 2, .max_peers = 2, .min_outbound = 0 }, 2, 0);
    defer catalog.deinit(std.testing.allocator);
    const first: t.PeerRef = .{ .index = 0, .generation = 1 };
    const second: t.PeerRef = .{ .index = 1, .generation = 1 };
    const first_conn: t.Handle = .{ .index = 0, .generation = 1 };
    const second_conn: t.Handle = .{ .index = 1, .generation = 1 };
    control.connected(&catalog, &requests, first, first_conn, .outbound, .{ .mono_ms = 10, .unix_s = 0 });
    control.connected(&catalog, &requests, second, second_conn, .inbound, .{ .mono_ms = 10, .unix_s = 0 });
    for ([_]u64{ 20, 30, 40 }) |now| {
        control.reStatusPeers(&catalog, &requests, .{ .mono_ms = now, .unix_s = 0 });
        try std.testing.expect(control.reStatusPeer(&catalog, &requests, second, second_conn, .{ .mono_ms = now, .unix_s = 0 }));
        try std.testing.expectEqual(@as(u64, 10), control.schedules[0].status_due_ms);
        try std.testing.expectEqual(@as(u64, 20), control.schedules[1].status_due_ms);
    }
}

test "peer control relevance boundary roots forks and availability" {
    var local: t.LocalState = .{};
    local.status.finalized_epoch = 4;
    local.status.finalized_root = @splat(1);
    var remote = local.status;
    remote.head_slot = 11;
    try std.testing.expectEqual(@as(?t.DisconnectReason, null), relevance(&local, &remote, 10));
    remote.head_slot = 12;
    try std.testing.expectEqual(t.DisconnectReason.future_head, relevance(&local, &remote, 10).?);
    remote.head_slot = 10;
    remote.fork_digest[0] = 1;
    try std.testing.expectEqual(
        t.DisconnectReason.incompatible_fork,
        relevance(&local, &remote, 10).?,
    );
    remote.fork_digest[0] = 0;
    remote.finalized_root = @splat(2);
    try std.testing.expectEqual(
        t.DisconnectReason.finalized_mismatch,
        relevance(&local, &remote, 10).?,
    );
    remote.finalized_epoch = 3;
    try std.testing.expect(relevance(&local, &remote, 10) == null);
    remote.finalized_epoch = 4;
    remote.finalized_root = @splat(0);
    try std.testing.expect(relevance(&local, &remote, 10) == null);
    local.fork.fork = .fulu;
    try std.testing.expectEqual(
        t.DisconnectReason.missing_availability,
        relevance(&local, &remote, 10).?,
    );
    remote.earliest_available_slot = 0;
    try std.testing.expect(relevance(&local, &remote, 10) == null);
    try std.testing.expectEqual(w.Protocol.status_v2, w.statusProtocol(local.fork));
    try std.testing.expectEqual(w.Protocol.metadata_v3, w.metadataProtocol(local.fork));
    local.fork.fork = .altair;
    try std.testing.expectEqual(w.Protocol.metadata_v2, w.metadataProtocol(local.fork));
    local.fork.fork = .phase0;
    try std.testing.expectEqual(w.Protocol.metadata_v1, w.metadataProtocol(local.fork));
}
