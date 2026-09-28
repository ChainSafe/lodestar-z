const std = @import("std");
const t = @import("types.zig");
const w = @import("../control_wire.zig");
const Catalog = @import("catalog.zig").Catalog;
const Control = @import("control.zig").Control;
const ControlProtocol = @import("../control_protocol.zig").ControlProtocol;
const relevance = @import("control.zig").relevance;
const rr = @import("../reqresp/root.zig");
const Now = @import("../types.zig").Now;

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

test "control start quota and cursor preserve order across Identify and RPC starts" {
    const a = std.testing.allocator;
    var catalog = try Catalog.init(a, .{ .capacity = 4, .outbound_reserve = 0, .target_peers = 4, .max_peers = 4, .min_outbound = 0 }, 4, 0);
    defer catalog.deinit(a);
    var control = try Control.init(a, .{ .starts_per_turn_max = 3 }, 4);
    defer control.deinit(a);
    var requests = try ControlProtocol.init(a, 4, 4, 1);
    defer requests.deinit(a);
    const now: Now = .{ .mono_ms = 10, .unix_s = 0 };
    const local: t.LocalState = .{};
    const local_identity: t.PeerId = .{ .bytes = @splat(0) };
    for (0..4) |index| {
        const identity: t.PeerId = .{ .bytes = @splat(@intCast(index + 1)) };
        const conn: t.Handle = .{ .index = @intCast(index), .generation = 1 };
        const peer = catalog.admit(&identity, &local_identity, conn, &.{ .direction = .outbound, .endpoint = .unspecified, .now_ms = now.mono_ms }).admitted.peer;
        try std.testing.expect(catalog.updateStatus(peer, conn, &local.status, now.mono_ms));
        control.connected(&catalog, &requests, peer, conn, .outbound, now);
    }
    // Every row is due for an Identify and a Status start. Nothing holds an operation here, so a
    // started Status stays due; the passes check which work each row gets and in what order.
    const Work = struct { index: u32, request: ?rr.Protocol };
    const passes = [_]struct { work: [2]Work, cursor: usize }{
        .{ .work = .{ .{ .index = 0, .request = .status_v1 }, .{ .index = 1, .request = null } }, .cursor = 2 },
        .{ .work = .{ .{ .index = 2, .request = .status_v1 }, .{ .index = 3, .request = null } }, .cursor = 0 },
    };
    for (passes) |expected| {
        var pass = control.beginMaintenance(now);
        var seen: usize = 0;
        while (control.nextDue(&pass, &catalog, &requests, &local, now)) |*due| : (seen += 1) {
            try std.testing.expect(seen < expected.work.len);
            try std.testing.expectEqual(expected.work[seen].index, due.index);
            try std.testing.expect(due.close == null and due.identify);
            try std.testing.expectEqual(expected.work[seen].request, if (due.request) |probe| probe.protocol else null);
            control.identifyStarted(due, true, now);
            if (due.request != null) control.requestStarted(due, .started, now);
            control.rekey(&catalog, &requests, due.index);
        }
        try std.testing.expectEqual(expected.work.len, seen);
        try std.testing.expectEqual(expected.cursor, control.cursor);
    }
    try std.testing.expectEqual(@as(u64, 2), control.counters.started);
    try std.testing.expectEqual(@as(u64, 8), control.visits);
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
