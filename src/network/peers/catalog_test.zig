const std = @import("std");
const t = @import("types.zig");
const Catalog = @import("catalog.zig").Catalog;
const Handle = t.Handle;
const opts: t.Options = .{
    .capacity = 2,
    .outbound_reserve = 0,
    .target_peers = 2,
    .max_peers = 2,
    .min_outbound = 0,
    .engine_capacity = 2,
};
const local = identity(
    "0025080212210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
const remote = identity(
    "0025080212210379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
const third = identity(
    "00250802122102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
);
fn identity(comptime hex: []const u8) t.PeerId {
    var value: t.PeerId = undefined;
    _ = std.fmt.hexToBytes(&value.bytes, hex) catch unreachable;
    return value;
}
const first = Handle{ .index = 1, .generation = 1 };
const replacement = Handle{ .index = 1, .generation = 2 };
fn admit(
    c: *Catalog,
    id: *const t.PeerId,
    conn: Handle,
    direction: t.Direction,
    now: u64,
) t.Admission {
    return c.admit(id, &local, conn, &.{
        .direction = direction,
        .endpoint = .unspecified,
        .now_ms = now,
    });
}
test "peer catalog identity duplicates and obsolete close preserve replacement" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .inbound, 0).admitted.peer;
    try std.testing.expectEqual(
        t.Admission.duplicate,
        admit(&c, &remote, replacement, .inbound, 0),
    );
    const result = admit(&c, &remote, replacement, .outbound, 0).admitted;
    try std.testing.expectEqual(first, result.displaced.?);
    try std.testing.expectEqual(ref, result.peer);
    try std.testing.expect(!c.disconnect(ref, first, .transport_closed, 1));
    try std.testing.expectEqual(replacement, c.get(ref).?.connection.?);
    const distinct = third;
    const other = admit(&c, &distinct, .{ .index = 0, .generation = 1 }, .inbound, 1).admitted.peer;
    try std.testing.expect(!std.meta.eql(ref, other));
}
test "peer catalog zero output closes native ownership and pins terminal until one output" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .outbound, 0).admitted.peer;
    try std.testing.expect(c.updateStatus(ref, first, &.{}, 0));
    var out: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&out));
    try std.testing.expectEqual(.ready, std.meta.activeTag(out[0]));
    try std.testing.expect(c.disconnect(ref, first, .host, 1));
    try std.testing.expectEqual(@as(usize, 0), c.pollEvents(&.{}));
    try std.testing.expect(c.get(ref).?.connection == null);
    try std.testing.expectEqual(
        t.Admission.capacity,
        admit(&c, &remote, replacement, .outbound, 2),
    );
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&out));
    try std.testing.expectEqual(.closed, std.meta.activeTag(out[0]));
    try std.testing.expectEqual(ref, admit(&c, &remote, replacement, .outbound, 2).admitted.peer);
}
test "peer catalog banned retention and outbound reserve reject pressure" {
    var options = opts;
    options.outbound_reserve = 1;
    var c = try Catalog.init(std.testing.allocator, options);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .inbound, 0).admitted.peer;
    try std.testing.expectEqual(t.ReputationDecision.ban, c.report(ref, .fatal, 0).?);
    try std.testing.expect(c.disconnect(ref, first, .banned, 0));
    var out: [1]t.Event = undefined;
    _ = c.pollEvents(&out);
    try std.testing.expectEqual(t.Admission.banned, admit(&c, &remote, replacement, .inbound, 1));
    const distinct = third;
    try std.testing.expectEqual(
        t.Admission.capacity,
        admit(&c, &distinct, replacement, .inbound, 1),
    );
    _ = admit(&c, &distinct, replacement, .outbound, 1).admitted;
    try std.testing.expectEqual(@as(f64, -100), c.get(ref).?.score);
}
test "peer catalog exhausted generations never wrap and allocator cleanup" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    c.rows[0].generation = std.math.maxInt(u64);
    const ref = admit(&c, &remote, first, .outbound, 0).admitted.peer;
    try std.testing.expectEqual(@as(u16, 1), ref.index);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
}
fn allocationCheck(a: std.mem.Allocator) !void {
    var c = try Catalog.init(a, opts);
    defer c.deinit(a);
    try std.testing.expectEqual(
        opts.capacity * @sizeOf(@import("catalog.zig").Row),
        c.memoryPlan().allocated_bytes,
    );
}
test "peer catalog published replacement updates availability and rejects stale completions" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .inbound, 0).admitted.peer;
    try std.testing.expect(c.updateStatus(ref, first, &.{}, 0));
    var out: [1]t.Event = undefined;
    _ = c.pollEvents(&out);
    _ = admit(&c, &remote, replacement, .outbound, 1).admitted;
    try std.testing.expect(!c.updateStatus(ref, first, &.{}, 2));
    try std.testing.expect(!c.updateMetadata(ref, first, &.{}, 2));
    try std.testing.expect(!c.remoteGoodbye(ref, first, 2, 100));
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&out));
    try std.testing.expect(!out[0].updated.relevant);
    try std.testing.expectEqual(replacement, out[0].updated.connection.?);
    try std.testing.expect(c.updateStatus(ref, replacement, &.{}, 3));
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&out));
    try std.testing.expect(out[0].updated.relevant);
    try std.testing.expectEqual(@as(usize, 0), c.pollEvents(&out));
}
test "peer catalog larger local identity prefers inbound and unchanged direction keeps owner" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = c.admit(&local, &remote, first, &.{
        .direction = .outbound,
        .endpoint = .unspecified,
        .now_ms = 0,
    }).admitted.peer;
    try std.testing.expectEqual(first, c.admit(&local, &remote, replacement, &.{
        .direction = .inbound,
        .endpoint = .unspecified,
        .now_ms = 0,
    }).admitted.displaced.?);
    try std.testing.expectEqual(t.Admission.duplicate, c.admit(&local, &remote, first, &.{
        .direction = .outbound,
        .endpoint = .unspecified,
        .now_ms = 0,
    }));
    try std.testing.expectEqual(replacement, c.get(ref).?.connection.?);
}
test "peer catalog unpublished closure coalesces updates without artificial ready" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .outbound, 0).admitted.peer;
    try std.testing.expect(c.updateStatus(ref, first, &.{}, 1));
    try std.testing.expect(c.updateStatus(ref, first, &.{ .head_slot = 2 }, 2));
    try std.testing.expect(c.updateMetadata(ref, first, &.{ .seq_number = 2 }, 2));
    try std.testing.expect(!c.updateMetadata(ref, first, &.{ .seq_number = 1 }, 3));
    try std.testing.expect(c.disconnect(ref, first, .host, 3));
    var out: [1]t.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), c.pollEvents(&out));
    try std.testing.expectEqual(.closed, std.meta.activeTag(out[0]));
    try std.testing.expectEqual(@as(usize, 0), c.pollEvents(&out));
}
test "peer catalog negative reconnect survives while direct and pending slots resist reuse" {
    var options = opts;
    options.capacity = 1;
    options.max_peers = 1;
    options.target_peers = 1;
    var c = try Catalog.init(std.testing.allocator, options);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .outbound, 0).admitted.peer;
    _ = c.report(ref, .mid_tolerance, 0);
    try std.testing.expect(c.disconnect(ref, first, .host, 0));
    const other = third;
    try std.testing.expectEqual(t.Admission.capacity, admit(&c, &other, replacement, .outbound, 0));
    var out: [1]t.Event = undefined;
    _ = c.pollEvents(&out);
    try std.testing.expectEqual(t.Admission.capacity, admit(&c, &other, replacement, .outbound, 0));
    try std.testing.expectEqual(ref, admit(&c, &remote, replacement, .outbound, 0).admitted.peer);
    try std.testing.expectEqual(@as(f64, -5), c.get(ref).?.score);
    try std.testing.expect(c.setDirect(ref, true));
    try std.testing.expect(c.disconnect(ref, replacement, .host, 0));
    _ = c.pollEvents(&out);
    try std.testing.expectEqual(
        t.Admission.capacity,
        admit(&c, &other, replacement, .outbound, 40_000_000),
    );
    try std.testing.expect(c.setDirect(ref, false));
    const next = admit(&c, &other, replacement, .outbound, 40_000_000).admitted.peer;
    try std.testing.expectEqual(ref.generation + 1, next.generation);
    try std.testing.expect(c.get(ref) == null);
    var snapshots: [1]t.Snapshot = undefined;
    try std.testing.expectEqual(@as(usize, 1), c.snapshots(&snapshots));
    try std.testing.expectEqual(next, snapshots[0].peer);
}
test "peer catalog rejected banned reconnect does not mutate retained reputation" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const ref = admit(&c, &remote, first, .outbound, 0).admitted.peer;
    _ = c.report(ref, .fatal, 0);
    try std.testing.expect(c.disconnect(ref, first, .banned, 0));
    var out: [1]t.Event = undefined;
    _ = c.pollEvents(&out);
    const before = c.rows[ref.index].reputation;
    try std.testing.expectEqual(
        t.Admission.banned,
        admit(&c, &remote, replacement, .outbound, 1_800_000),
    );
    try std.testing.expectEqual(
        t.Admission.banned,
        admit(&c, &remote, replacement, .outbound, 2_400_000),
    );
    try std.testing.expectEqual(before, c.rows[ref.index].reputation);
    try std.testing.expectEqual(@as(u64, 2_400_001), c.nextDeadline(2_400_000).?);
    c.refresh(2_400_001);
    try std.testing.expectEqual(
        ref,
        admit(&c, &remote, replacement, .outbound, 2_400_001).admitted.peer,
    );
    try std.testing.expect(c.get(ref).?.score > -50);
}
test "peer catalog memory plan equals actual allocation reservation" {
    var a = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var c = try Catalog.init(a.allocator(), .{});
    const plan = c.memoryPlan();
    try std.testing.expectEqual(a.allocated_bytes, plan.allocated_bytes);
    c.deinit(a.allocator());
    try std.testing.expectEqual(a.allocated_bytes, a.freed_bytes);
}

test "peer catalog accepts native generation zero and still rejects another full handle" {
    var c = try Catalog.init(std.testing.allocator, opts);
    defer c.deinit(std.testing.allocator);
    const zero: Handle = .{ .index = 0, .generation = 0 };
    const ref = admit(&c, &remote, zero, .outbound, 0).admitted.peer;
    try std.testing.expect(ref.generation != 0);
    try std.testing.expect(c.updateStatus(ref, zero, &.{}, 0));
    try std.testing.expect(!c.disconnect(ref, .{ .index = 0, .generation = 1 }, .host, 0));
    try std.testing.expect(c.disconnect(ref, zero, .host, 0));
}
