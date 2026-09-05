const std = @import("std");
const mod = @import("dial_queue.zig");
const t = @import("types.zig");
const a = std.testing.allocator;
const address: t.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 1234 } };
test "peer dial queue copies candidates rotates addresses and ignores stale leased tokens" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 2, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 4 },
    );
    defer q.deinit(a);
    var peer: t.PeerId = .{ .bytes = @splat(1) };
    var addresses = [_]t.Address{
        address,
        .{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4321 } },
    };
    try q.enqueue(&peer, &addresses, false, 0);
    try q.enqueue(&peer, &addresses, false, 0);
    peer.bytes[0] = 9;
    addresses[0] = .unspecified;
    var out: [1]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    const first = out[0];
    try std.testing.expectEqual(@as(u8, 1), first.peer.bytes[0]);
    try std.testing.expectEqualDeep(address, first.address);
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 1));
    try std.testing.expectEqual(@as(usize, 0), q.poll(10_000, &out));
    try std.testing.expect(!q.dialStarted(first.token, .{ .index = 0, .generation = 1 }));
    const due = q.nextWakeup(10_000, 1).?;
    try std.testing.expect(due >= 11_000 and due <= 12_000);
    try std.testing.expectEqual(@as(usize, 1), q.poll(due, &out));
    try std.testing.expectEqual(@as(u16, 4321), out[0].address.port());
    try std.testing.expect(!q.dialFailed(first.token, due));
    try std.testing.expect(q.dialStarted(out[0].token, .{ .index = 2, .generation = 7 }));
    try std.testing.expect(q.dialFailed(out[0].token, due));
}

test "peer dial queue bounded pressure generation exhaustion and zero output do not spin" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 2, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 9 },
    );
    defer q.deinit(a);
    const first: t.PeerId = .{ .bytes = @splat(1) };
    const second: t.PeerId = .{ .bytes = @splat(2) };
    const third: t.PeerId = .{ .bytes = @splat(3) };
    try q.enqueue(&first, &.{address}, true, 0);
    try q.enqueue(&second, &.{address}, false, 0);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
    try std.testing.expectEqual(@as(?u64, null), q.nextWakeup(0, 0));
    var out: [2]mod.DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expectEqual(@as(?u64, 10_000), q.nextWakeup(0, 2));
    const token = out[0].token;
    try std.testing.expect(q.dialFailed(token, 0));
    try std.testing.expectEqual(@as(usize, 1), q.poll(0, &out));
    try std.testing.expect(out[0].peer.eql(&second));
    try std.testing.expect(q.isDirect(&first));
    q.removeDirect(&first);
    try std.testing.expect(!q.isDirect(&first));
    q.remove(&first);
    q.rows[token.index].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.Capacity, q.enqueue(&third, &.{address}, false, 0));
}

test "peer dial queue exponential retry remains bounded through repeated failure" {
    var q = try mod.DialQueue.init(
        a,
        .{ .capacity = 1, .concurrent_max = 1, .engine_dialing_max = 1, .seed = 10 },
    );
    defer q.deinit(a);
    const peer: t.PeerId = .{ .bytes = @splat(1) };
    try q.enqueue(&peer, &.{address}, false, 0);
    var now: u64 = 0;
    var out: [1]mod.DialIntent = undefined;
    for (0..20) |_| {
        try std.testing.expectEqual(@as(usize, 1), q.poll(now, &out));
        try std.testing.expect(q.dialFailed(out[0].token, now));
        const due = q.nextWakeup(now, 1).?;
        try std.testing.expect(due - now >= 1_000 and due - now <= 60_000);
        now = due;
    }
}
