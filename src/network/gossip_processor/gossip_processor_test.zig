const std = @import("std");
const topic_mod = @import("../gossipsub/topic.zig");
const p = @import("root.zig");
const t = std.testing;
const index_list = @import("../index_list.zig");

test "gossip processor validates explicit execution overrides before allocating" {
    const limits: p.limits.Limits = @splat(.{ .items = 4096, .bytes = 4096 });
    const cases = [_]p.limits.Limit{
        .{ .items = 0, .bytes = 4096 },
        .{ .items = 4097, .bytes = 4096 },
        .{ .items = 1, .bytes = 0 },
        .{ .items = 1261, .bytes = 4096 },
        .{ .items = 1, .bytes = 128 * 1024 * 1024 },
    };
    for (cases) |limit| {
        const execution: p.limits.Limits = @splat(limit);
        var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
        try t.expectError(error.InvalidGossipProcessorLimits, p.GossipProcessor.init(failing.allocator(), .{ .limits = limits, .execution = execution }));
        try t.expectError(error.InvalidGossipProcessorLimits, p.GossipProcessor.Options.resolve(limits, execution, &.{}, &.{}, 1));
    }
}

test "gossip processor preserves derived defaults above explicit execution ceilings" {
    const limits: p.limits.Limits = @splat(.{ .items = 4096, .bytes = 4096 });
    const resolved = try p.GossipProcessor.Options.resolve(limits, null, &.{}, &.{}, 1);
    try t.expectEqual(@as(?p.limits.Limits, null), resolved.execution);
    try t.expectEqual(@as(u32, 2048), resolved.executionLimits()[0].items);
    for ([_]p.GossipProcessor.Options{ .{ .limits = limits }, resolved }) |options| {
        var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
        try t.expectError(error.OutOfMemory, p.GossipProcessor.init(failing.allocator(), options));
    }
    const explicit: p.limits.Limits = @splat(.{ .items = 1, .bytes = 4096 });
    const valid = try p.GossipProcessor.Options.resolve(limits, explicit, &.{}, &.{}, 1);
    try t.expectEqualDeep(explicit, valid.executionLimits());
}

test "gossip processor backing bytes match allocations at page boundaries" {
    const page = @import("../gossipsub/message_store.zig").page_bytes;
    const capacities = [_]struct { items: u32, attestations: u32 }{
        .{ .items = 2, .attestations = 2 },
        .{ .items = 64, .attestations = 64 },
        .{ .items = 64, .attestations = 2 },
    };
    for (capacities) |capacity| {
        for ([_]u32{ page, 2 * page }) |kind_bytes| {
            var limits: p.limits.Limits = @splat(.{ .items = capacity.items, .bytes = kind_bytes });
            limits[@intFromEnum(p.limits.Kind.beacon_attestation)].items = capacity.attestations;
            var measured = t.FailingAllocator.init(t.allocator, .{});
            {
                var table = try p.GossipProcessor.init(measured.allocator(), .{ .limits = limits });
                defer table.deinit();
                try t.expectEqual(@as(usize, capacity.attestations), table.groups.rows.len);
                try t.expectEqual(measured.allocated_bytes, p.GossipProcessor.backingBytes(&.{ .limits = limits }));
            }
            try t.expectEqual(measured.allocated_bytes, measured.freed_bytes);
            for (0..measured.alloc_index) |prefix| {
                var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = prefix });
                try t.expectError(error.OutOfMemory, p.GossipProcessor.init(failing.allocator(), .{ .limits = limits }));
                try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            }
        }
    }
}

fn add(table: *p.GossipProcessor, kind: p.limits.Kind, root: ?[32]u8) !p.GossipProcessor.Token {
    const token = try table.reserve(kind, 1);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = if (table.expiry.tail == index_list.none) 100 else @max(100, table.cells[table.expiry.tail].deadline);
    cell.metadata = .{ .root = root, .slot = 1 };
    table.install(token, "x");
    return token;
}

test "gossip processor isolates kinds and bounds dependency waiting" {
    const limits: p.limits.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(7);
    for (0..4) |_| _ = try add(&table, .beacon_attestation, root);
    try t.expectError(error.NetworkGossipFull, add(&table, .beacon_attestation, root));
    const checks = table.claimChecks(1, p.GossipProcessor.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 2), table.snapshot(1).waiting);
    try t.expectEqual(@as(u64, 2), table.refusals[@intFromEnum(p.limits.Kind.beacon_attestation)][@intFromEnum(p.GossipProcessor.Refusal.dependency_full)]);
    try t.expectEqual([_]u64{ 0, 2, 0, 0 }, table.occupancy(.beacon_attestation));
    const block = try add(&table, .beacon_block, null);
    const batch = table.claimDemand(1, .{ .ordinary = false });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(block, batch.tokens[0]);
    table.finish(&batch, true);
    try t.expectEqual([_]u64{ 0, 0, 0, 1 }, table.occupancy(.beacon_block));
    table.notifyBlock(root);
    table.maintain(2, 0);
    const retry = table.claimChecks(2, p.GossipProcessor.batch_max);
    try t.expectEqual(@as(usize, 2), retry.len);
}

test "gossip processor dependency notification cannot race a negative check" {
    const limits: p.limits.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(2);
    const token = try add(&table, .beacon_attestation, root);
    _ = table.claimChecks(1, p.GossipProcessor.batch_max);
    table.notifyBlock(root);
    try t.expect(table.classify(token, false));
    try t.expectEqual(p.GossipProcessor.State.needs_check, table.get(token).?.state);
    _ = table.claimChecks(2, p.GossipProcessor.batch_max);
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
    const limits: p.limits.Limits = @splat(.{ .items = 2, .bytes = 8192 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const token = try table.reserve(.beacon_block, payload.len);
    table.get(token).?.deadline = 100;
    table.get(token).?.id = @splat(1);
    table.install(token, &payload);
    const batch = table.claim(1);
    var bytes: [payload.len]u8 = undefined;
    table.copyPayload(table.get(token).?, &bytes);
    try t.expectEqualSlices(u8, &payload, &bytes);
    table.finish(&batch, false);
    try t.expectEqual(@as(usize, 0), table.snapshot(1).executing);
    try t.expectEqual(p.GossipProcessor.State.queued, table.get(token).?.state);
    try t.expectEqual(p.limits.bytes(&limits) / 4096 - 2, table.store.free_pages);
}

test "gossip processor claims an item larger than the demand bytes alone" {
    const payload: [4097]u8 = @splat(9);
    const limits: p.limits.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    var blocks: [2]p.GossipProcessor.Token = undefined;
    for (&blocks) |*block| {
        block.* = try table.reserve(.beacon_block, payload.len);
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
    const limits: p.limits.Limits = @splat(.{ .items = 64, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const first = try table.reserve(.beacon_attestation, 1);
    const second = try table.reserve(.beacon_attestation, 1);
    for ([_]p.GossipProcessor.Token{ first, second }) |token| {
        const cell = table.get(token).?;
        cell.metadata.group = @splat(3);
        cell.topic_len = @intCast(topic_mod.buildCanonical(.{ .digest = cell.fork_digest, .name = .{ .kind = .beacon_attestation } }, &cell.topic).len);
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
    const limits: p.limits.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(2);
    for (0..3) |_| {
        const token = try add(&table, .beacon_attestation, root);
        table.get(token).?.source = .{ .index = 0, .generation = 1 };
    }
    const checks = table.claimChecks(1, p.GossipProcessor.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 2), table.snapshot(1).waiting);
    table.notifyBlock(root);
    table.maintain(1, 0);
    try t.expectEqual(@as(u16, 0), table.waiting_per_peer[0][@intFromEnum(p.limits.Kind.beacon_attestation)]);
}

test "gossip processor new attestation groups cannot postpone a mature group" {
    const limits: p.limits.Limits = @splat(.{ .items = 64, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const older = try table.reserve(.beacon_attestation, 1);
    const newer = try table.reserve(.beacon_attestation, 1);
    for ([_]p.GossipProcessor.Token{ older, newer }, 0..) |token, i| {
        const cell = table.get(token).?;
        cell.metadata.group = @splat(@intCast(i));
        cell.topic_len = @intCast(topic_mod.buildCanonical(.{ .digest = cell.fork_digest, .name = .{ .kind = .beacon_attestation } }, &cell.topic).len);
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
        const limits: p.limits.Limits = @splat(.{ .items = 4, .bytes = 4096 });
        var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
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

test "gossip processor holds a delivered message's cell until an exchange acknowledges its owner disposition" {
    const limits: p.limits.Limits = @splat(.{ .items = 8, .bytes = 32768 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const applied = try add(&table, .beacon_block, null);
    const late = try add(&table, .beacon_block, null);
    const expired = try add(&table, .beacon_block, null);
    table.finish(&table.claim(1), true);
    for ([_]p.GossipProcessor.Token{ applied, late, expired }) |token| try t.expectEqual(p.GossipProcessor.State.delivered, table.get(token).?.state);
    const unseen = try add(&table, .beacon_block, null);

    // The owner applies one verdict; the host reports another after expiry, and a third expires while pending.
    try t.expect(table.report(applied, .accept, 2));
    table.retire(applied);
    try t.expect(table.report(expired, .ignore, 2));
    table.get(unseen).?.deadline = 200;
    table.expire(100);
    try t.expect(!table.report(late, .reject, 101));
    // A message the host was never handed frees at once.
    table.ignore(table.get(unseen).?);
    table.retire(unseen);

    // Each disposition holds only its cell: payload, charges and occupancy are released.
    try t.expectEqual(@as(usize, 3), table.diag.acknowledging);
    try t.expectEqual(@as(usize, 0), table.diag.occupied);
    try t.expectEqual(@as(usize, 0), table.diag.payloadBytes);
    try t.expect(!table.report(applied, .accept, 101));
    var out: [4]p.GossipProcessor.Token = undefined;
    try t.expectEqual(@as(usize, 3), table.acknowledgements(&out));
    for (out[0..3]) |token| try t.expect(std.meta.eql(token, applied) or std.meta.eql(token, late) or std.meta.eql(token, expired));
    try t.expectEqual(@as(usize, 1), table.acknowledgements(out[0..1]));

    // Acknowledged cells return; a reused cell ignores its previous generation's acknowledgement.
    table.acknowledge(applied);
    table.acknowledge(applied);
    try t.expectEqual(@as(usize, 2), table.diag.acknowledging);
    var reused = try add(&table, .beacon_block, null);
    for (0..limits[0].items) |_| {
        if (reused.index == applied.index) break;
        reused = try add(&table, .beacon_block, null);
    }
    try t.expectEqual(applied.index, reused.index);
    try t.expect(reused.generation > applied.generation);
    table.acknowledge(applied);
    try t.expectEqual(p.GossipProcessor.State.queued, table.get(reused).?.state);

    // Close drops outstanding acknowledgements.
    table.close();
    try t.expectEqual(@as(usize, 0), table.diag.acknowledging);
    try t.expectEqual(@as(usize, 0), table.acknowledgements(&out));
}

test "gossip processor expired execution diagnostics track delivered work until actual completion" {
    const limits: p.limits.Limits = @splat(.{ .items = 8, .bytes = 16384 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
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
    const limits: p.limits.Limits = @splat(.{ .items = 128, .bytes = 1 << 20 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const rows = table.dependencies.rows.len;
    for (0..40) |i| _ = try add(&table, .beacon_attestation, @splat(@intCast(i)));
    const checks = table.claimChecks(1, p.GossipProcessor.batch_max);
    for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    try t.expectEqual(@as(usize, 40), table.snapshot(1).waiting);
    // A negative check in flight when the recheck lands retries instead of waiting.
    const late = try add(&table, .beacon_attestation, @splat(99));
    _ = table.claimChecks(1, p.GossipProcessor.batch_max);
    table.recheck();
    try t.expect(table.classify(late, false));
    try t.expectEqual(p.GossipProcessor.State.needs_check, table.get(late).?.state);
    // A second recheck during the pass lets it finish, then walks every row once more.
    table.recheck();
    var turns: usize = 0;
    for (0..2 * rows) |_| {
        if (!table.dependencies.rechecking()) break;
        table.maintain(1, 0);
        turns += 1;
    }
    try t.expect(!table.pending(true));
    try t.expectEqual(@as(usize, 0), table.snapshot(1).waiting);
    // Each pass walks every row and spends one step ending.
    try t.expectEqual((2 * (rows + 1) + p.GossipProcessor.batch_max - 1) / p.GossipProcessor.batch_max, turns);
}

fn blockOptions(block: p.limits.Limit) p.GossipProcessor.Options {
    var limits: p.limits.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    limits[@intFromEnum(p.limits.Kind.beacon_block)] = block;
    return .{ .limits = limits, .execution = limits };
}

test "gossip processor skips exhausted generations and rejects stale handles" {
    var table = try p.GossipProcessor.init(std.testing.allocator, blockOptions(.{ .items = 64, .bytes = 64 * 4096 }));
    defer table.deinit();
    const token = try table.reserve(.beacon_block, 10);
    table.retire(token);
    table.cells[0].generation = std.math.maxInt(u64);
    const next = try table.reserve(.beacon_block, 10);
    try std.testing.expectEqual(@as(u16, 1), next.index);
    try std.testing.expect(table.get(token) == null);
    table.retire(next);
}

test "gossip table and payload allocation prefixes unwind shared reservation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationPrefix, .{});
}
fn allocationPrefix(allocator: std.mem.Allocator) !void {
    var table = try p.GossipProcessor.init(allocator, blockOptions(.{ .items = 1024, .bytes = 64 * 1024 * 1024 }));
    defer table.deinit();
    const token = try table.reserve(.beacon_block, 10);
    defer table.retire(token);
    table.install(token, "0123456789");
}

test "gossip batch bounds, rollback and expiry keep pins until full completion" {
    var table = try p.GossipProcessor.init(std.testing.allocator, blockOptions(.{ .items = 1024, .bytes = 64 * 1024 * 1024 }));
    defer table.deinit();
    const data = try std.testing.allocator.alloc(u8, 10 * 1024 * 1024);
    defer std.testing.allocator.free(data);
    @memset(data, 7);
    const first = try table.reserve(.beacon_block, data.len);
    table.get(first).?.deadline = 100;
    table.install(first, data);
    const second = try table.reserve(.beacon_block, 7 * 1024 * 1024);
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
        const token = try table.reserve(.beacon_block, 1);
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

test "gossip processor retains expired verdicts until acknowledgement and rejects stale generations" {
    var table = try p.GossipProcessor.init(std.testing.allocator, blockOptions(.{ .items = 64, .bytes = 64 * 4096 }));
    defer table.deinit();
    var handles: [64]p.GossipProcessor.Token = undefined;
    for (&handles) |*token| {
        token.* = try table.reserve(.beacon_block, 1);
        table.get(token.*).?.deadline = 100;
        table.install(token.*, "x");
    }
    try std.testing.expectError(error.NetworkGossipFull, table.reserve(.beacon_block, 1));
    const batch = table.claim(1);
    table.finish(&batch, true);
    for (handles) |token| {
        try std.testing.expect(table.report(token, .accept, 2));
        try std.testing.expect(!table.report(token, .reject, 2));
    }
    try std.testing.expectEqual(@as(usize, 64), table.snapshot(1).pendingVerdicts);
    try std.testing.expect(table.pending(true));
    table.expire(100);
    try std.testing.expect(!table.pending(true) and table.deadline() == null);
    // Expiry disposed of every delivered message; each cell returns once an exchange acknowledges it.
    try std.testing.expectEqual(@as(usize, 64), table.snapshot(1).acknowledging);
    try std.testing.expectError(error.NetworkGossipFull, table.reserve(.beacon_block, 1));
    var acknowledged: [64]p.GossipProcessor.Token = undefined;
    try std.testing.expectEqual(@as(usize, 64), table.acknowledgements(&acknowledged));
    for (acknowledged) |token| table.acknowledge(token);
    const replacement = try table.reserve(.beacon_block, 1);
    table.get(replacement).?.deadline = 200;
    table.install(replacement, "y");
    try std.testing.expect(!table.report(handles[0], .accept, 101));
    table.close();
}

test "gossip processor groups attestation data across subnets only within the same fork" {
    const limits: p.limits.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .limits = limits });
    defer table.deinit();
    defer table.close();
    const topics = [_]topic_mod.Canonical{
        .{ .digest = .{ 1, 2, 3, 4 }, .name = .{ .kind = .beacon_attestation, .subnet = 0 } },
        .{ .digest = .{ 1, 2, 3, 4 }, .name = .{ .kind = .beacon_attestation, .subnet = 1 } },
        .{ .digest = .{ 5, 6, 7, 8 }, .name = .{ .kind = .beacon_attestation, .subnet = 0 } },
    };
    for (topics, 0..) |canonical, i| {
        var wire: [topic_mod.topic_max_len]u8 = undefined;
        try table.capture(&.{
            .handle = .{ .index = @intCast(i), .generation = 1 },
            .id = @splat(@intCast(i)),
            .peer = .{ .index = 0, .generation = 1 },
            .identity = .{ .bytes = @splat(1) },
            .topic = topic_mod.buildCanonical(canonical, &wire),
            .bytes = "x",
            .admitted_ms = 1,
            .deadline = 100,
        }, canonical, &.{ .group = @splat(3) }, true, 1);
    }
    table.maintain(51, 0);
    const batch = table.claim(51);
    defer table.finish(&batch, true);
    try t.expectEqual(@as(usize, 3), batch.len);
    try t.expectEqual(@as(usize, 2), batch.job_count);
    try t.expectEqual(@as(usize, 1), batch.jobs[0].len);
    try t.expectEqual(@as(usize, 2), batch.jobs[1].len);
    for (batch.jobs[0..batch.job_count]) |job| {
        try t.expect(job.grouped);
        for (batch.tokens[job.start..][0..job.len]) |token| {
            const cell = table.get(token).?;
            const canonical = topic_mod.parseCanonical(cell.topic[0..cell.topic_len]).?;
            try t.expectEqual(if (job.len == 2) topics[0].digest else topics[2].digest, canonical.digest);
        }
    }
}
