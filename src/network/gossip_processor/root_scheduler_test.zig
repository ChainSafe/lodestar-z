const std = @import("std");
const t = std.testing;
const p = @import("root.zig");
const lists = @import("../index_list.zig");
const Kind = p.limits_mod.Kind;

fn add(table: *p.GossipProcessor, kind: Kind, now: u64, metadata: p.metadata_mod.Metadata) !p.Token {
    const token = try table.reserveKind(kind, 4);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = now + 100;
    cell.admitted_ms = now;
    cell.metadata = metadata;
    @memset(&cell.topic, 0);
    table.install(token, "data");
    return token;
}

fn verify(table: *const p.GossipProcessor) !void {
    var occupied: usize = 0;
    var executing: usize = 0;
    var payload: usize = 0;
    for (table.cells, 0..) |cell, i| {
        occupied += @intFromBool(cell.state != .free);
        executing += @intFromBool(cell.executing);
        payload += cell.input.len;
        if (cell.state != .free) try t.expectEqual(cell.state_link.linked, true);
        if (cell.group_index != lists.none) {
            try t.expectEqual(p.State.queued, cell.state);
            try t.expect(cell.group_link.linked);
            try t.expectEqual(cell.group_index, table.groups.index.find(table.groups.rows, &table.groups.rows[cell.group_index].key).?);
        }
        if (cell.root_index != lists.none) {
            try t.expectEqual(p.State.waiting, cell.state);
            try t.expect(cell.root_link.linked);
        }
        if (cell.expiry_link.next != lists.none) try t.expect(cell.deadline <= table.cells[cell.expiry_link.next].deadline);
        if (cell.state_link.next != lists.none) try t.expectEqual(@as(u32, @intCast(i)), table.cells[cell.state_link.next].state_link.previous);
    }
    for (table.queues) |kind| for (kind, 0..) |queue, state| {
        var next = queue.head;
        var count: usize = 0;
        for (0..table.cells.len) |_| {
            if (next == lists.none) break;
            try t.expectEqual(state, @intFromEnum(table.cells[next].state));
            next = table.cells[next].state_link.next;
            count += 1;
        }
        try t.expectEqual(lists.none, next);
        try t.expectEqual(queue.len, count);
    };
    for (table.groups.timers[0..table.groups.timer_count], 0..) |index, slot| {
        try t.expectEqual(slot, table.groups.rows[index].timer);
        if (slot > 0) try t.expect(table.groups.rows[table.groups.timers[(slot - 1) / 2]].due <= table.groups.rows[index].due);
    }
    try t.expectEqual(occupied, table.diag.occupied);
    try t.expectEqual(executing, table.diag.executing);
    try t.expectEqual(payload, table.diag.payloadBytes);
}

test "gossip scheduler batches kinds as separate validator jobs in native priority order" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 64, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    _ = try add(&table, .voluntary_exit, 1, .{});
    _ = try add(&table, .voluntary_exit, 1, .{});
    const first_attestation = try add(&table, .beacon_attestation, 1, .{ .group = @splat(7) });
    _ = try add(&table, .beacon_attestation, 1, .{ .group = @splat(7) });
    _ = try add(&table, .beacon_block, 1, .{});
    try t.expect(!table.groups.rows[table.get(first_attestation).?.group_index].ready);
    table.maintain(51, 0);
    const batch = table.claim(51);
    try t.expectEqual(@as(usize, 5), batch.len);
    try t.expectEqual(@as(usize, 4), batch.job_count);
    try t.expectEqualSlices(p.Job, &.{
        .{ .kind = .beacon_block, .start = 0, .len = 1, .grouped = false },
        .{ .kind = .voluntary_exit, .start = 1, .len = 1, .grouped = false },
        .{ .kind = .voluntary_exit, .start = 2, .len = 1, .grouped = false },
        .{ .kind = .beacon_attestation, .start = 3, .len = 2, .grouped = true },
    }, batch.jobs[0..batch.job_count]);
    table.finish(&batch, false);
    try verify(&table);
}

test "gossip scheduler keeps execution charged across timeout until real completion" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    table.execution.?[0].items = 1;
    const first = try add(&table, .beacon_block, 1, .{});
    const batch = table.claim(1);
    table.finish(&batch, true);
    const second = try add(&table, .beacon_block, 50, .{});
    table.expire(101);
    try t.expectEqual(@as(usize, 0), table.claim(101).len);
    try t.expectEqual(@as(usize, 4), table.snapshot(101).executingBytes);
    try t.expect(!table.report(first, .accept, 101));
    const ready = table.claim(101);
    try t.expectEqual(second, ready.tokens[0]);
    table.finish(&ready, true);
    try t.expect(table.report(second, .accept, 102));
    try t.expectEqual(@as(usize, 0), table.diag.executing);
    try verify(&table);
}

test "gossip scheduler budgets mass expiry and root promotion without releasing detached waiters early" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 512, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const root: [32]u8 = @splat(3);
    for (0..130) |_| _ = try add(&table, .beacon_attestation, 1, .{ .slot = 1, .root = root, .await_block = true });
    for (0..3) |_| {
        const checks = table.claimChecks(1, p.batch_max);
        for (checks.tokens[0..checks.len]) |token| try t.expect(table.classify(token, false));
    }
    table.notifyBlock(root);
    try t.expectEqual(@as(usize, 130), table.diag.waiting);
    table.maintain(1, 0);
    try t.expectEqual(@as(usize, 66), table.diag.waiting);
    try t.expect(table.pending() or table.deadline().? <= 1);
    table.maintain(1, 0);
    try t.expectEqual(@as(usize, 2), table.diag.waiting);
    table.maintain(1, 0);
    try t.expectEqual(@as(usize, 0), table.diag.waiting);
    table.expire(101);
    try t.expectEqual(@as(usize, 66), table.diag.occupied);
    try t.expect(table.pending() or table.deadline().? <= 101);
    table.expire(101);
    table.expire(101);
    try t.expectEqual(@as(usize, 0), table.diag.occupied);
    try verify(&table);
}

const lifecycle_kinds = [_]Kind{ .beacon_block, .beacon_attestation, .voluntary_exit };

/// One step of a scripted lifecycle: an arrival of `kind`, maintenance, checks, a claim, expiry, reports and
/// retirement. Returns the claim.
fn lifecycleStep(table: *p.GossipProcessor, kind: Kind, step: usize) !p.Batch {
    const now: u64 = @intCast(step);
    if (table.hasCapacity(kind, 4)) {
        const root: ?[32]u8 = if (kind == .beacon_attestation and step % 3 == 0) @splat(7) else null;
        const group: ?[128]u8 = if (kind == .beacon_attestation) @splat(@intCast(step % 5)) else null;
        _ = try add(table, kind, now, .{ .root = root, .group = group, .await_block = root != null, .slot = 1 });
    }
    table.maintain(now, 0);
    const checks = table.claimChecks(now, p.batch_max);
    if (step % 7 == 0) table.notifyBlock(@splat(7));
    for (checks.tokens[0..checks.len]) |token| _ = table.classify(token, step % 2 == 0);
    const batch = table.claimDemand(now, .{ .items = 3, .ordinary = step % 4 != 0 });
    if (step % 13 == 0) table.expire(now + 1);
    table.finish(&batch, step % 3 != 0);
    for (lifecycle_kinds) |selected| {
        const queue = table.queues[@intFromEnum(selected)][@intFromEnum(p.State.delivered)];
        if (queue.head != lists.none and step % 4 != 0) _ = table.report(.{ .index = @intCast(queue.head), .generation = table.cells[queue.head].generation }, .accept, now);
    }
    for (0..p.batch_max) |_| table.retire(table.nextVerdict() orelse break);
    return batch;
}

test "gossip scheduler indexes survive bounded randomized lifecycle interleavings" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 16, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    var random = std.Random.DefaultPrng.init(19);
    for (0..2000) |step| {
        _ = try lifecycleStep(&table, lifecycle_kinds[random.random().uintLessThan(usize, lifecycle_kinds.len)], step);
        try verify(&table);
    }
}

test "gossip scheduler stage clock changes no claim, credit or state" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 16, .bytes = 4096 });
    var timed = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer timed.deinit();
    defer timed.close();
    var untimed = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer untimed.deinit();
    defer untimed.close();
    // Tight execution credits, so claims stop on them and credit waits open and close.
    for ([_]*p.GossipProcessor{ &timed, &untimed }) |table| for (&table.execution.?) |*limit| {
        limit.items = 2;
    };
    var random = std.Random.DefaultPrng.init(23);
    for (0..2000) |step| {
        const kind = lifecycle_kinds[random.random().uintLessThan(usize, lifecycle_kinds.len)];
        timed.stages.tick(step * std.time.ns_per_ms + random.random().uintLessThan(u64, std.time.ns_per_ms));
        const claimed = try lifecycleStep(&timed, kind, step);
        const reference = try lifecycleStep(&untimed, kind, step);
        try t.expectEqualSlices(p.Token, reference.tokens[0..reference.len], claimed.tokens[0..claimed.len]);
        try t.expectEqualSlices(p.Job, reference.jobs[0..reference.job_count], claimed.jobs[0..claimed.job_count]);
        try t.expectEqualDeep(untimed.queues, timed.queues);
        try t.expectEqualDeep(untimed.executing_items, timed.executing_items);
        try t.expectEqualDeep(untimed.executing_bytes, timed.executing_bytes);
        try t.expectEqualDeep(untimed.diag, timed.diag);
        try t.expectEqual(untimed.readiness(), timed.readiness());
    }
    var claimed: u64 = 0;
    var credit_stops: u64 = 0;
    for (timed.stages.intervals, timed.stages.stops) |intervals, stops| {
        claimed += intervals[@intFromEnum(p.stages_mod.Interval.ready_other_wait)].count;
        credit_stops += stops[@intFromEnum(p.stages_mod.Stop.item_credit)];
    }
    try t.expect(claimed > 0);
    try t.expect(credit_stops > 0);
    try t.expect(timed.stages.blocked(.beacon_block) > 0);
    try verify(&timed);
}

fn expectStage(table: *const p.GossipProcessor, kind: Kind, interval: p.stages_mod.Interval, count: u64, sum_ns: u64) !void {
    const value = &table.stages.intervals[@intFromEnum(kind)][@intFromEnum(interval)];
    try t.expectEqual(count, value.count);
    try t.expectEqual(@as(u128, sum_ns), value.sum);
}

test "gossip scheduler times each claimed message's stages, credit waits and claim stops" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const ms = std.time.ns_per_ms;
    const Stop = p.stages_mod.Stop;
    const column = @intFromEnum(Kind.data_column_sidecar);
    table.execution.?[column].items = 1;
    table.stages.tick(1000 * ms);
    const first = try add(&table, .data_column_sidecar, 999, .{});
    const second = try add(&table, .data_column_sidecar, 999, .{});
    table.stages.tick(1002 * ms);
    const claimed = table.claimDemand(1002, .{ .ordinary = false });
    try t.expectEqualSlices(p.Token, &.{first}, claimed.tokens[0..claimed.len]);
    try t.expectEqual(@as(u64, 1), table.stages.stops[column][@intFromEnum(Stop.item_credit)]);
    table.finish(&claimed, true);
    table.stages.tick(1010 * ms);
    // The host settled its validation 3 ms before calling the exchange that entered 1 ms ago and applies it now.
    table.timeVerdict(first, 3 * ms, 1009 * ms);
    try t.expect(table.report(first, .accept, 1010));
    table.timeVerdict(first, 3 * ms, 1009 * ms);
    table.stages.tick(1012 * ms);
    table.forwarded(table.get(first).?);
    table.stages.tick(1015 * ms);
    const next = table.claimDemand(1015, .{ .ordinary = false });
    try t.expectEqualSlices(p.Token, &.{second}, next.tokens[0..next.len]);
    table.finish(&next, true);
    // Both were ready 1 ms after receipt. The second waited 8 ms on the first's credit, then 7 ms for a claim.
    try expectStage(&table, .data_column_sidecar, .receipt_to_ready, 2, 2 * ms);
    try expectStage(&table, .data_column_sidecar, .ready_credit_blocked, 2, 8 * ms);
    try expectStage(&table, .data_column_sidecar, .ready_other_wait, 2, 2 * ms + 7 * ms);
    try expectStage(&table, .data_column_sidecar, .claimed_to_applied, 1, 8 * ms);
    // Only the verdict that reached a delivered message is timed.
    try expectStage(&table, .data_column_sidecar, .completed_to_exchange, 1, 3 * ms);
    try expectStage(&table, .data_column_sidecar, .completed_to_applied, 1, 4 * ms);
    try expectStage(&table, .data_column_sidecar, .applied_to_forwarded, 1, 2 * ms);
    try t.expectEqual(8 * ms, table.stages.blocked(.data_column_sidecar));
    try t.expectEqual(@as(u128, 8 * ms), table.stages.item_ns[column]);
    try t.expectEqual(@as(u128, 4 * 8 * ms), table.stages.byte_ns[column]);

    // One claim leaves a block on its byte credit, a blob sidecar on the claim's item bound and an exit on the
    // ordinary gate.
    table.execution.?[@intFromEnum(Kind.beacon_block)].bytes = 6;
    for (0..2) |_| {
        _ = try add(&table, .beacon_block, 1015, .{});
        _ = try add(&table, .blob_sidecar, 1015, .{});
    }
    _ = try add(&table, .voluntary_exit, 1015, .{});
    const bounded = table.claimDemand(1015, .{ .items = 2, .ordinary = false });
    try t.expectEqual(@as(usize, 2), bounded.len);
    table.finish(&bounded, true);
    for ([_]struct { Kind, Stop }{ .{ .beacon_block, .byte_credit }, .{ .blob_sidecar, .claim_bound }, .{ .voluntary_exit, .ordinary_gate } }) |expected| {
        for (table.stages.stops[@intFromEnum(expected[0])], 0..) |count, reason| {
            try t.expectEqual(@as(u64, @intFromBool(reason == @intFromEnum(expected[1]))), count);
        }
    }
    try verify(&table);
}

test "gossip scheduler source limits cover unfinished execution and survive peer slot reuse" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const source: p.Source = .{ .index = 0, .generation = 1 };
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    var message: @import("../gossipsub/root.zig").MessageEvent = .{
        .source = source,
        .handle = .{ .index = 0, .generation = 1 },
        .id = @splat(1),
        .peer = .{ .index = 0, .generation = 1 },
        .topic = topic,
        .bytes = "data",
        .identity = .{ .bytes = @splat(1) },
        .admitted_ms = 1,
        .deadline = 101,
    };
    try table.capture(&message, &.{}, false, 1);
    try table.capture(&message, &.{}, false, 1);
    try t.expectError(error.NetworkGossipFull, table.capture(&message, &.{}, false, 1));
    try t.expect(table.sourceRoom(.{ .index = 1, .generation = 1 }, .beacon_block, 4));
    const batch = table.claim(1);
    table.finish(&batch, true);
    table.expire(101);
    try t.expect(!table.sourceRoom(source, .beacon_block, 4));
    try t.expect(!table.report(batch.tokens[0], .accept, 102));
    try t.expect(table.sourceRoom(source, .beacon_block, 4));
    message.source.?.generation = 2;
    message.admitted_ms = 102;
    message.deadline = 202;
    try table.capture(&message, &.{}, false, 102);
    try t.expect(!table.report(batch.tokens[1], .ignore, 103));
    try t.expectEqual(@as(usize, 1), table.sources[0].items[0]);
    try verify(&table);
}

test "gossip scheduler freshness replacement never selects copying or executing jobs" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const oldest = try add(&table, .beacon_attestation, 1, .{});
    const newest = try add(&table, .beacon_attestation, 2, .{});
    const batch = table.claimDemand(2, .{ .items = 1 });
    try t.expectEqual(newest, batch.tokens[0]);
    try t.expectEqual(oldest, table.freshnessVictim(.beacon_attestation).?);
    table.finish(&batch, true);
    table.retire(oldest);
    try t.expect(table.freshnessVictim(.beacon_attestation) == null);
    _ = try add(&table, .beacon_block, 3, .{});
    try t.expect(table.freshnessVictim(.beacon_block) == null);
    try verify(&table);
}

test "gossip readiness reports checks and executable urgent and ordinary jobs" {
    const limits: p.limits_mod.Limits = @splat(.{ .items = 8, .bytes = 4096 });
    var table = try p.GossipProcessor.init(t.allocator, .{ .capacity = p.limits_mod.items(&limits), .bytes = p.limits_mod.bytes(&limits), .limits = limits });
    defer table.deinit();
    defer table.close();
    const Work = p.GossipProcessor.Work;
    table.execution.?[@intFromEnum(Kind.data_column_sidecar)].items = 1;
    try t.expectEqual(Work{}, table.readiness());
    _ = try add(&table, .voluntary_exit, 1, .{});
    try t.expectEqual(Work{ .ordinary = true }, table.readiness());
    // A claim of urgent kinds only leaves ordinary work reported.
    try t.expectEqual(@as(usize, 0), table.claimDemand(1, .{ .ordinary = false }).len);
    try t.expectEqual(Work{ .ordinary = true }, table.readiness());
    _ = try add(&table, .data_column_sidecar, 1, .{});
    _ = try add(&table, .data_column_sidecar, 1, .{});
    _ = try add(&table, .beacon_attestation, 1, .{ .slot = 1, .root = @splat(4), .await_block = true });
    try t.expectEqual(Work{ .checks = true, .urgent = true, .ordinary = true }, table.readiness());
    // The column kind at its execution limit reports its second job as not claimable.
    const batch = table.claimDemand(1, .{ .ordinary = false });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(Work{ .checks = true, .ordinary = true }, table.readiness());
    table.finish(&batch, true);
    const checks = table.claimChecks(1, p.batch_max);
    try t.expectEqual(@as(usize, 1), checks.len);
    try t.expectEqual(Work{ .ordinary = true }, table.readiness());
    try t.expect(table.report(batch.tokens[0], .accept, 1));
    try t.expectEqual(Work{ .urgent = true, .ordinary = true }, table.readiness());
    try verify(&table);
}
