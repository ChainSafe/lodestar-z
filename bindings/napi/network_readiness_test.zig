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

test "a pinned row ignores publications until its unpin moves it where it belongs, and forget re-arms" {
    var ready: Readiness = .{ .armed = false };
    for ([_]Row{ .peers, .checks, .gossip }) |row| _ = ready.recompute(row, .payload);
    ready.pin(.peers);
    ready.pin(.checks);
    try std.testing.expect(!ready.recompute(.checks, .none));
    try std.testing.expectEqual(readiness.Place.none, ready.place(.checks));
    try std.testing.expectEqual([_]?Row{ .gossip, null, null, null, null }, order(&ready));
    ready.unpin(.checks, .none);
    ready.unpin(.peers, .payload);
    try std.testing.expectEqual([_]?Row{ .gossip, .peers, null, null, null }, order(&ready));
    ready.pin(.gossip);
    ready.unpin(.gossip, .parked);
    try std.testing.expectEqual(readiness.Place.parked, ready.place(.gossip));
    try std.testing.expect(!ready.arm());
    // A declined notification forgets every row, so recomputing any of them with work notifies again.
    ready.forget();
    try std.testing.expect(ready.armed and ready.payload.len == 0);
    try std.testing.expect(ready.recompute(.peers, .payload));
}
