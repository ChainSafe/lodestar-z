const std = @import("std");
const readiness = @import("network_readiness.zig");
const Readiness = readiness.Readiness;
const Row = readiness.Row;

fn order(ready: *const Readiness) [readiness.row_count]?Row {
    var result: [readiness.row_count]?Row = @splat(null);
    var index = ready.payload.head;
    for (&result) |*slot| {
        if (index == @import("network").index_list.none) break;
        slot.* = @enumFromInt(index);
        index = ready.rows[index].link.next;
    }
    return result;
}

test "only the first move into a list, or from none to parked, disarms" {
    var ready: Readiness = .{};
    try std.testing.expect(ready.recompute(.peers, .payload));
    try std.testing.expect(!ready.armed);
    try std.testing.expect(!ready.recompute(.gossip, .payload));
    try std.testing.expect(!ready.arm());
    _ = ready.recompute(.peers, .none);
    _ = ready.recompute(.gossip, .none);
    try std.testing.expect(ready.arm());
    try std.testing.expect(ready.recompute(.serving, .parked));
    try std.testing.expect(ready.arm());
    // A parked row that becomes queued disarms again; queued to parked does not.
    try std.testing.expect(ready.recompute(.serving, .payload));
    _ = ready.recompute(.serving, .parked);
    try std.testing.expect(ready.arm());
    try std.testing.expect(!ready.recompute(.serving, .parked));
    try std.testing.expect(ready.recompute(.legacy, .control));
}

test "recomputing a queued row keeps its position" {
    var ready: Readiness = .{ .armed = false };
    for ([_]Row{ .peers, .checks, .gossip }) |row| _ = ready.recompute(row, .payload);
    _ = ready.recompute(.checks, .payload);
    try std.testing.expectEqual([_]?Row{ .peers, .checks, .gossip, null, null }, order(&ready));
}

test "a pinned row ignores publications until its unpin, which rolls back to the head or moves it" {
    var ready: Readiness = .{ .armed = false };
    for ([_]Row{ .peers, .checks, .gossip }) |row| _ = ready.recompute(row, .payload);
    // Rows pinned in list order and unpinned in reverse keep their order on a rollback.
    const first = ready.pin(.peers);
    const second = ready.pin(.checks);
    try std.testing.expect(!ready.recompute(.checks, .none));
    try std.testing.expectEqual(readiness.Place.none, ready.place(.checks));
    ready.unpin(.checks, second, .payload, true);
    ready.unpin(.peers, first, .payload, true);
    try std.testing.expectEqual([_]?Row{ .peers, .checks, .gossip, null, null }, order(&ready));
    // A commit, or a rollback whose row wants another place, moves the row as a recompute does.
    const committed = ready.pin(.peers);
    ready.unpin(.peers, committed, .payload, false);
    try std.testing.expectEqual([_]?Row{ .checks, .gossip, .peers, null, null }, order(&ready));
    const rolled = ready.pin(.checks);
    ready.unpin(.checks, rolled, .none, true);
    const changed = ready.pin(.gossip);
    ready.unpin(.gossip, changed, .parked, true);
    try std.testing.expectEqual([_]?Row{ .peers, null, null, null, null }, order(&ready));
    try std.testing.expectEqual(readiness.Place.parked, ready.place(.gossip));
    try std.testing.expect(!ready.arm());
}
