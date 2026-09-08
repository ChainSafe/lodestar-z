const std = @import("std");
const g = @import("network_gossip.zig");
const Budget = @import("network_incoming.zig").Budget;

test "gossip exact shared 2Q admission and generation exhaustion" {
    var budget: Budget = .{ .limit = 19 };
    var table = try g.Table.init(std.testing.allocator, 64, &budget);
    defer table.deinit();
    try std.testing.expectError(error.NetworkBridgeFull, table.reserve(10));
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    budget.limit = 20;
    const token = try table.reserve(10);
    try std.testing.expectEqual(@as(usize, 20), budget.used);
    table.retire(token);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    table.cells[0].generation = std.math.maxInt(u64);
    const next = try table.reserve(10);
    try std.testing.expectEqual(@as(u16, 1), next.index);
    try std.testing.expect(table.get(token) == null);
    table.retire(next);
}

test "gossip table and payload allocation prefixes unwind shared reservation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationPrefix, .{});
}
fn allocationPrefix(allocator: std.mem.Allocator) !void {
    var budget: Budget = .{ .limit = 20 };
    var table = try g.Table.init(allocator, 1024, &budget);
    defer table.deinit();
    const token = try table.reserve(10);
    defer table.retire(token);
    try table.allocate(token, "0123456789");
}

test "gossip batch bounds, rollback and expiry keep pins until full completion" {
    var budget: Budget = .{ .limit = 64 * 1024 * 1024 };
    var table = try g.Table.init(std.testing.allocator, 1024, &budget);
    defer table.deinit();
    const data = try std.testing.allocator.alloc(u8, 10 * 1024 * 1024);
    defer std.testing.allocator.free(data);
    @memset(data, 7);
    const first = try table.reserve(data.len);
    try table.allocate(first, data);
    table.get(first).?.deadline = 100;
    const second = try table.reserve(7 * 1024 * 1024);
    try table.allocate(second, data[0 .. 7 * 1024 * 1024]);
    table.get(second).?.deadline = 100;
    var batch = table.claim(99);
    try std.testing.expectEqual(@as(usize, 1), batch.len);
    try std.testing.expectEqual(first, batch.tokens[0]);
    table.expire(100);
    try std.testing.expectEqual(@as(usize, 1), table.diag.occupied);
    try std.testing.expectEqual(@as(usize, 20 * 1024 * 1024), budget.used);
    table.finish(&batch, true);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    try std.testing.expectEqual(@as(u64, 2), table.diag.queuedExpired);
    for (0..65) |_| {
        const token = try table.reserve(1);
        try table.allocate(token, "x");
        table.get(token).?.deadline = 200;
    }
    batch = table.claim(101);
    try std.testing.expectEqual(@as(usize, 64), batch.len);
    table.finish(&batch, false);
    try std.testing.expectEqual(@as(usize, 65), table.snapshot().queued);
    batch = table.claim(102);
    table.finish(&batch, true);
    try std.testing.expect(table.oldest() != null);
    try std.testing.expectEqual(@as(usize, 1), table.snapshot().queued);
    table.close();
    try std.testing.expectEqual(@as(usize, 0), budget.used);
}

test "gossip original admission wall projection is precise and independent of drain" {
    try std.testing.expectEqual(@as(u64, 1700000000123), try g.projectWall(100, .{ .mono_ms = 150, .unix_ms = 1700000000173 }));
    try std.testing.expectEqual(@as(u64, 1700000000623), try g.projectWall(100, .{ .mono_ms = 150, .unix_ms = 1700000000673 }));
    try std.testing.expectError(error.InvalidNetworkClock, g.projectWall(151, .{ .mono_ms = 150, .unix_ms = 1700000000173 }));
}

test "gossip flags remain independent of full command capacity and reject stale generations" {
    var commands: @import("network_commands.zig").Table = .{};
    for (0..32) |_| _ = try commands.reserve(.small);
    var budget: Budget = .{ .limit = 128 };
    var table = try g.Table.init(std.testing.allocator, 64, &budget);
    defer table.deinit();
    var handles: [64]g.Token = undefined;
    for (&handles) |*token| {
        token.* = try table.reserve(1);
        try table.allocate(token.*, "x");
        table.get(token.*).?.deadline = 100;
    }
    try std.testing.expectError(error.NetworkGossipFull, table.reserve(1));
    const batch = table.claim(1);
    table.finish(&batch, true);
    for (handles) |token| {
        try std.testing.expect(table.report(token, .accept, 2));
        try std.testing.expect(!table.report(token, .reject, 2));
    }
    try std.testing.expectEqual(@as(usize, 64), table.snapshot().pendingVerdicts);
    try std.testing.expectEqual(@as(u64, 0), table.waitLimit(2, 100));
    table.expire(100);
    try std.testing.expectEqual(@as(u64, 100), table.waitLimit(100, 100));
    const replacement = try table.reserve(1);
    try table.allocate(replacement, "y");
    table.get(replacement).?.deadline = 200;
    try std.testing.expect(!table.report(handles[0], .accept, 101));
    table.close();
    try std.testing.expectEqual(@as(usize, 0), budget.used);
}
