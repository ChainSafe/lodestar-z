const std = @import("std");
const g = @import("network_gossip.zig");
const limits_mod = @import("network").gossip_processor.limits_mod;

fn plan(block: limits_mod.Limit) @import("network").gossip_processor.Plan {
    var limits: limits_mod.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    limits[@intFromEnum(limits_mod.Kind.beacon_block)] = block;
    return .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits, .execution = limits };
}

test "gossip exact shared 2Q admission and generation exhaustion" {
    var table = try g.Table.init(std.testing.allocator, plan(.{ .items = 64, .bytes = 64 * 4096 }));
    defer table.deinit();
    const token = try table.reserve(10);
    table.retire(token);
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
    var table = try g.Table.init(allocator, plan(.{ .items = 1024, .bytes = 64 * 1024 * 1024 }));
    defer table.deinit();
    const token = try table.reserve(10);
    defer table.retire(token);
    table.install(token, "0123456789");
}

test "gossip batch bounds, rollback and expiry keep pins until full completion" {
    var table = try g.Table.init(std.testing.allocator, plan(.{ .items = 1024, .bytes = 64 * 1024 * 1024 }));
    defer table.deinit();
    const data = try std.testing.allocator.alloc(u8, 10 * 1024 * 1024);
    defer std.testing.allocator.free(data);
    @memset(data, 7);
    const first = try table.reserve(data.len);
    table.get(first).?.deadline = 100;
    table.install(first, data);
    const second = try table.reserve(7 * 1024 * 1024);
    table.get(second).?.deadline = 100;
    table.install(second, data[0 .. 7 * 1024 * 1024]);
    var batch = table.claim(99);
    try std.testing.expectEqual(@as(usize, 1), batch.len);
    try std.testing.expectEqual(first, batch.tokens[0]);
    table.expire(100);
    try std.testing.expectEqual(@as(usize, 1), table.diag.occupied);
    table.finish(&batch, true);
    try std.testing.expect(!table.report(first, .accept, 100));
    try std.testing.expectEqual(@as(u64, 2), table.diag.queuedExpired);
    for (0..65) |_| {
        const token = try table.reserve(1);
        table.get(token).?.deadline = 200;
        table.install(token, "x");
    }
    batch = table.claim(101);
    try std.testing.expectEqual(@as(usize, 64), batch.len);
    table.finish(&batch, false);
    try std.testing.expectEqual(@as(usize, 65), table.snapshot(1).queued);
    batch = table.claim(102);
    table.finish(&batch, true);
    try std.testing.expect(table.oldest() != null);
    try std.testing.expectEqual(@as(usize, 1), table.snapshot(1).queued);
    table.close();
}

test "gossip original admission wall projection is precise and independent of drain" {
    try std.testing.expectEqual(@as(u64, 1700000000123), try g.projectWall(100, .{ .mono_ms = 150, .unix_ms = 1700000000173 }));
    try std.testing.expectEqual(@as(u64, 1700000000623), try g.projectWall(100, .{ .mono_ms = 150, .unix_ms = 1700000000673 }));
    try std.testing.expectError(error.InvalidNetworkClock, g.projectWall(151, .{ .mono_ms = 150, .unix_ms = 1700000000173 }));
}

test "gossip flags remain independent of full command capacity and reject stale generations" {
    var commands: @import("network_commands.zig").Table = .{};
    for (0..32) |_| _ = try commands.reserve(.getIdentity);
    var table = try g.Table.init(std.testing.allocator, plan(.{ .items = 64, .bytes = 64 * 4096 }));
    defer table.deinit();
    var handles: [64]g.Token = undefined;
    for (&handles) |*token| {
        token.* = try table.reserve(1);
        table.get(token.*).?.deadline = 100;
        table.install(token.*, "x");
    }
    try std.testing.expectError(error.NetworkGossipFull, table.reserve(1));
    const batch = table.claim(1);
    table.finish(&batch, true);
    for (handles) |token| {
        try std.testing.expect(table.report(token, .accept, 2));
        try std.testing.expect(!table.report(token, .reject, 2));
    }
    try std.testing.expectEqual(@as(usize, 64), table.snapshot(1).pendingVerdicts);
    try std.testing.expectEqual(@as(u64, 0), table.waitLimit(2, 100));
    table.expire(100);
    try std.testing.expectEqual(@as(u64, 100), table.waitLimit(100, 100));
    const replacement = try table.reserve(1);
    table.get(replacement).?.deadline = 200;
    table.install(replacement, "y");
    try std.testing.expect(!table.report(handles[0], .accept, 101));
    table.close();
}
