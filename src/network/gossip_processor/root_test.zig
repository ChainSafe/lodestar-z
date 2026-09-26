const std = @import("std");
const p = @import("root.zig");
const t = std.testing;

test "gossip processor backing bytes match allocations at page boundaries" {
    const page = @import("../gossipsub/message_store.zig").page_bytes;
    for ([_]u32{ 2, 64 }) |items| {
        for ([_]u32{ page, 2 * page }) |kind_bytes| {
            const limits: p.limits_mod.Limits = @splat(.{ .items = items, .bytes = kind_bytes });
            const capacity = p.limits_mod.items(&limits);
            const bytes = p.limits_mod.bytes(&limits);
            var measured = t.FailingAllocator.init(t.allocator, .{});
            {
                var table = try p.GossipProcessor.init(measured.allocator(), .{ .capacity = capacity, .bytes = bytes, .limits = limits });
                defer table.deinit();
                try t.expectEqual(measured.allocated_bytes, p.GossipProcessor.backingBytes(capacity, bytes));
            }
            try t.expectEqual(measured.allocated_bytes, measured.freed_bytes);
            for (0..measured.alloc_index) |prefix| {
                var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = prefix });
                try t.expectError(error.OutOfMemory, p.GossipProcessor.init(failing.allocator(), .{ .capacity = capacity, .bytes = bytes, .limits = limits }));
                try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            }
        }
    }
}

fn add(table: *p.GossipProcessor, kind: p.limits_mod.Kind, root: ?[32]u8) !p.Token {
    const token = try table.reserveKind(kind, 1);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = if (table.expiry.tail == @import("../index_list.zig").none) 100 else @max(100, table.cells[table.expiry.tail].deadline);
    cell.metadata = .{ .root = root, .slot = 1 };
    table.install(token, "x");
    return token;
}

test "gossip processor isolates kinds and bounds dependency waiting" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(7);
    for (0..4) |_| _ = try add(&table, .beacon_attestation, root);
    try t.expectError(error.NetworkGossipFull, add(&table, .beacon_attestation, root));
    const checks = table.claimChecks(1, p.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 2), table.snapshot(1).waiting);
    try t.expectEqual(@as(u64, 2), table.refusals[@intFromEnum(p.limits_mod.Kind.beacon_attestation)][@intFromEnum(p.Refusal.dependency_full)]);
    try t.expectEqual([_]u64{ 0, 2, 0, 0 }, table.occupancy(.beacon_attestation));
    const block = try add(&table, .beacon_block, null);
    const batch = table.claimDemand(1, .{ .ordinary = false });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(block, batch.tokens[0]);
    table.finish(&batch, true);
    try t.expectEqual([_]u64{ 0, 0, 0, 1 }, table.occupancy(.beacon_block));
    table.notifyBlock(root);
    table.maintain(2, 0);
    const retry = table.claimChecks(2, p.batch_max);
    try t.expectEqual(@as(usize, 2), retry.len);
}

test "gossip processor dependency notification cannot race a negative check" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(2);
    const token = try add(&table, .beacon_attestation, root);
    _ = table.claimChecks(1, p.batch_max);
    table.notifyBlock(root);
    try t.expect(table.classify(token, false));
    try t.expectEqual(p.State.needs_check, table.get(token).?.state);
    _ = table.claimChecks(2, p.batch_max);
    try t.expect(table.classify(token, true));
    const batch = table.claim(2);
    table.finish(&batch, true);
    table.expire(100);
    try t.expectEqual(@as(usize, 1), table.snapshot(1).executing);
    try t.expect(!table.report(token, .accept, 101));
    try t.expectEqual(@as(usize, 0), table.snapshot(1).executing);
    try t.expectEqual(@as(usize, 0), table.diag.occupied);
}

test "gossip processor copy rollback preserves paged bytes" {
    const payload: [4097]u8 = @splat(9);
    const limits: p.limits_mod.Limits = @splat(.{ .items = 2, .bytes = 8192 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const token = try table.reserve(payload.len);
    table.get(token).?.deadline = 100;
    table.get(token).?.id = @splat(1);
    table.install(token, &payload);
    const batch = table.claim(1);
    var bytes: [payload.len]u8 = undefined;
    table.copyPayload(table.get(token).?, &bytes);
    try t.expectEqualSlices(u8, &payload, &bytes);
    table.finish(&batch, false);
    try t.expectEqual(@as(usize, 0), table.snapshot(1).executing);
    try t.expectEqual(p.State.queued, table.get(token).?.state);
    try t.expectEqual(p.limits_mod.bytes(&limits) / 4096 - 2, table.store.free_pages);
}

test "gossip processor claims an item larger than the demand bytes alone" {
    const payload: [4097]u8 = @splat(9);
    const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    var blocks: [2]p.Token = undefined;
    for (&blocks) |*block| {
        block.* = try table.reserve(payload.len);
        table.get(block.*).?.deadline = 100;
        table.get(block.*).?.id = @splat(1);
        table.install(block.*, &payload);
    }
    const attestation = try add(&table, .beacon_attestation, null);
    for (blocks) |block| {
        const batch = table.claimDemand(1, .{ .bytes = 4096 });
        try t.expectEqual(@as(usize, 1), batch.len);
        try t.expectEqual(block, batch.tokens[0]);
        table.finish(&batch, true);
    }
    const batch = table.claimDemand(1, .{ .bytes = 4096 });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(attestation, batch.tokens[0]);
    table.finish(&batch, true);
}

test "gossip processor batches identical attestation data with a bounded wait" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 64, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const first = try table.reserveKind(.beacon_attestation, 1);
    const second = try table.reserveKind(.beacon_attestation, 1);
    for ([_]p.Token{ first, second }) |token| {
        const cell = table.get(token).?;
        cell.metadata.group = @splat(3);
        @memset(&cell.topic, 0);
        cell.admitted_ms = 1;
        cell.deadline = 100;
        table.install(token, "x");
    }
    try t.expectEqual(@as(usize, 0), table.claim(49).len);
    try t.expectEqual(@as(?u64, 51), table.deadline());
    table.maintain(51, 0);
    const batch = table.claim(51);
    try t.expectEqual(@as(usize, 2), batch.len);
    try t.expectEqual(@as(usize, 1), batch.job_count);
    try t.expect(batch.jobs[0].grouped);
    table.finish(&batch, false);
    try t.expectEqual(@as(usize, 2), table.snapshot(1).queued);
}

test "gossip processor deferral leaves per-source capacity" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(2);
    for (0..3) |_| {
        const token = try add(&table, .beacon_attestation, root);
        table.get(token).?.source = .{ .index = 0, .generation = 1 };
    }
    const checks = table.claimChecks(1, p.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 2), table.snapshot(1).waiting);
    table.notifyBlock(root);
    table.maintain(1, 0);
    try t.expectEqual(@as(u16, 0), table.waiting_per_peer[0][@intFromEnum(p.limits_mod.Kind.beacon_attestation)]);
}

test "gossip processor new attestation groups cannot postpone a mature group" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 64, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const older = try table.reserveKind(.beacon_attestation, 1);
    const newer = try table.reserveKind(.beacon_attestation, 1);
    for ([_]p.Token{ older, newer }, 0..) |token, i| {
        const cell = table.get(token).?;
        cell.metadata.group = @splat(@intCast(i));
        @memset(&cell.topic, 0);
        cell.admitted_ms = if (i == 0) 1 else 50;
        cell.deadline = 100 + cell.admitted_ms;
        table.install(token, "x");
    }
    try t.expectEqual(@as(usize, 0), table.claim(50).len);
    try t.expectEqual(@as(?u64, 51), table.deadline());
    table.maintain(51, 0);
    const batch = table.claim(51);
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(older, batch.tokens[0]);
    table.finish(&batch, true);
}

test "gossip processor copied host work survives native expiry but close releases native ownership" {
    for ([_]bool{ false, true }) |close| {
        const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
        var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
        defer table.deinit();
        defer table.close();
        const token = try add(&table, .beacon_block, null);
        const batch = table.claim(1);
        if (close) table.close() else table.expire(100);
        try t.expectEqual(@as(usize, 1), table.diag.occupied);
        table.finish(&batch, true);
        try t.expectEqual(@as(usize, if (close) 0 else 1), table.snapshot(101).executing);
        try t.expectEqual(@as(usize, if (close) 0 else 1), table.snapshot(101).expiredExecuting);
        try t.expectEqual(@as(u64, if (close) 0 else 1), table.snapshot(101).oldestExpiredExecutionAgeMs);
        try t.expect(!table.report(token, .accept, 101));
        try t.expectEqual(@as(usize, 0), table.diag.occupied);
    }
}

test "gossip processor expired execution diagnostics track delivered work until actual completion" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 8, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const first = try add(&table, .beacon_block, null);
    table.finish(&table.claim(10), true);
    const second = try add(&table, .beacon_block, null);
    table.get(second).?.deadline = 125;
    table.finish(&table.claim(20), true);
    const reported = try add(&table, .beacon_block, null);
    table.finish(&table.claim(21), true);
    try t.expect(table.report(reported, .accept, 22));
    _ = try add(&table, .beacon_block, null);
    const copying = table.claim(23);
    try t.expectEqual(@as(usize, 1), copying.len);
    _ = try add(&table, .beacon_block, null);

    try t.expectEqual(@as(usize, 0), table.snapshot(99).expiredExecuting);
    try t.expectEqual(@as(usize, 1), table.snapshot(100).expiredExecuting);
    try t.expectEqual(@as(u64, 0), table.snapshot(100).oldestExpiredExecutionAgeMs);
    table.expire(125);
    try t.expectEqual(@as(usize, 2), table.snapshot(125).expiredExecuting);
    try t.expectEqual(@as(u64, 25), table.snapshot(125).oldestExpiredExecutionAgeMs);
    try t.expectEqual(@as(usize, 2), table.snapshot(140).expiredExecuting);
    try t.expectEqual(@as(u64, 40), table.snapshot(140).oldestExpiredExecutionAgeMs);

    try t.expect(!table.report(first, .accept, 140));
    try t.expectEqual(@as(usize, 1), table.snapshot(140).expiredExecuting);
    try t.expectEqual(@as(u64, 15), table.snapshot(140).oldestExpiredExecutionAgeMs);
    try t.expect(!table.report(first, .reject, 141));
    try t.expectEqual(@as(usize, 1), table.snapshot(141).expiredExecuting);
    table.finish(&copying, false);
    try t.expect(!table.report(second, .reject, 150));
    try t.expectEqual(@as(usize, 0), table.snapshot(150).expiredExecuting);
    try t.expectEqual(@as(u64, 0), table.snapshot(150).oldestExpiredExecutionAgeMs);
    try t.expectEqual(@as(usize, 0), table.snapshot(150).occupied);
}

test "gossip processor rechecks every waiting root in bounded passes and runs one more after an overlap" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 128, .bytes = 1 << 20 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const rows = table.dependencies.rows.len;
    for (0..40) |i| _ = try add(&table, .beacon_attestation, @splat(@intCast(i)));
    const checks = table.claimChecks(1, p.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 40), table.snapshot(1).waiting);
    // A negative check in flight when the recheck lands retries instead of waiting.
    const late = try add(&table, .beacon_attestation, @splat(99));
    _ = table.claimChecks(1, p.batch_max);
    table.recheck();
    try t.expect(table.classify(late, false));
    try t.expectEqual(p.State.needs_check, table.get(late).?.state);
    // A second recheck during the pass lets it finish, then walks every row once more.
    table.recheck();
    var turns: usize = 0;
    for (0..2 * rows) |_| {
        if (!table.dependencies.rechecking()) break;
        table.maintain(1, 0);
        turns += 1;
    }
    try t.expect(!table.pending());
    try t.expectEqual(@as(usize, 0), table.snapshot(1).waiting);
    // Each pass walks every row and spends one step ending.
    try t.expectEqual((2 * (rows + 1) + p.batch_max - 1) / p.batch_max, turns);
}
