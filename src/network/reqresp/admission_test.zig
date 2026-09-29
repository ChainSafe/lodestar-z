const std = @import("std");
const a = @import("admission.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const ForkSeq = @import("config").ForkSeq;
const Protocol = @import("protocol.zig").Protocol;
const limiter = @import("limiter.zig");

const quotas = @import("admission_fixture.zig").quotas;
const first: PeerId = .{ .bytes = @splat(1) };
const second: PeerId = .{ .bytes = @splat(2) };
const third: PeerId = .{ .bytes = @splat(3) };
const method: Protocol = .blocks_by_root_v2;

test "reqresp request starts retain identity debt and isolate control from application churn" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(10, 1000), .global = quotas(20, 1000), .starts = .{ .tokens = 2, .period_ms = 1000 } });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.start(&first, false, 499));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, true, 499));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&second, false, 499));
    try std.testing.expectEqual(a.Decision.identity_capacity, owner.start(&third, false, 499));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 500));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&third, false, 1000));
}

test "reqresp request start hints name the first admitting millisecond without reserving it" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(10, 1000), .global = quotas(20, 1000), .starts = .{ .tokens = 2, .period_ms = 1000 } });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), owner.startAt(&first, false, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 0));
    for (0..3) |_| try std.testing.expectEqual(@as(u64, 500), owner.startAt(&first, false, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.start(&first, false, 499));
    try std.testing.expectEqual(@as(u64, 500), owner.startAt(&first, false, 499));
    try std.testing.expectEqual(@as(u64, 499), owner.startAt(&first, true, 499));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&first, false, 500));
    try std.testing.expectEqual(@as(u64, 1000), owner.startAt(&first, false, 500));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&second, false, 500));
    try std.testing.expectEqual(@as(u64, 1000), owner.startAt(&third, false, 600));
    try std.testing.expect(owner.tracks(&first, 600) and !owner.tracks(&third, 600) and owner.tracks(&third, 1000));
    try std.testing.expectEqual(a.Decision.identity_capacity, owner.start(&third, false, 999));
    try std.testing.expectEqual(a.Decision.allowed, owner.start(&third, false, 1000));

    var rounded = try a.Limiter.init(std.testing.allocator, .{ .identities = 1, .peer = quotas(10, 1000), .global = quotas(20, 1000), .starts = .{ .tokens = 3, .period_ms = 1000 } });
    defer rounded.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, rounded.start(&first, false, 0));
    try std.testing.expectEqual(a.Decision.allowed, rounded.start(&first, false, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, rounded.start(&first, false, 0));
    try std.testing.expectEqual(@as(u64, 1), rounded.startAt(&first, false, 0));
    try std.testing.expectEqual(a.Decision.allowed, rounded.start(&first, false, 1));
}

test "reqresp request eligibility predicts peer and aggregate refill without charging queued work" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(2, 1000), .global = quotas(2, 1000) });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 2, .fulu, 0));
    try std.testing.expectEqual(@as(?u64, 500), owner.eligibleAt(&second, method, 1, .fulu, 0));
    try std.testing.expectEqual(@as(?u64, 500), owner.eligibleAt(&first, method, 1, .fulu, 499));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&second, method, 1, .fulu, 500));
    try std.testing.expectEqual(@as(?u64, 1000), owner.eligibleAt(&first, method, 1, .fulu, 500));
    try std.testing.expectEqual(@as(u128, 2), owner.requestCost(method, 3, .fulu));
}

test "reqresp request admission can accumulate an expensive request's credit alongside small requests" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(4, 1000), .global = quotas(4, 1000) });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&second, method, 4, .fulu, 0));
    var paid: u128 = 0;
    for (1..8) |tick| {
        const now: u64 = @intCast(tick * 250);
        if (tick % 2 == 1) {
            const credit = owner.grant(&first, method, 4 - paid, .fulu, now);
            try std.testing.expectEqual(@as(u128, 1), credit);
            paid += credit;
        } else {
            try std.testing.expectEqual(@as(u128, 1), owner.grant(&second, method, 1, .fulu, now));
        }
        try std.testing.expectEqual(@as(u128, 0), owner.grant(&second, method, 1, .fulu, now));
        try std.testing.expectEqual(@as(?u64, now + 250), owner.eligibleAt(&first, method, 1, .fulu, now));
    }
    try std.testing.expectEqual(@as(u128, 4), paid);
}

test "reqresp request admission identity debt expiry and bounded reclaim" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(2, 1000), .global = quotas(100, 1000) });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 500));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&second, method, 1, .fulu, 500));
    try std.testing.expectEqual(a.Decision.identity_capacity, owner.take(&third, method, 1, .fulu, 999));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&third, method, 1, .fulu, 1000));
    try std.testing.expect(owner.memoryPlan().allocated_bytes > 0);
}

test "reqresp request admission aggregate refusal is atomic and impossible cost creates no row" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 1, .peer = quotas(2, 1000), .global = quotas(1, 1000) });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.peer_quota, owner.take(&first, method, @as(u128, std.math.maxInt(u32)) + 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.global_quota, owner.take(&first, method, 2, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&second, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.global_quota, owner.take(&second, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&second, .ping_v1, 1, .fulu, 0));
    const row = &owner.rows[0];
    try std.testing.expectEqual(@as(u128, 500_000_000), row.debt[@intFromEnum(method)]);
}

test "reqresp request admission fork quota changes retain nanosecond debt" {
    var peer = quotas(2, 1000);
    peer[@intFromEnum(ForkSeq.fulu)] = @splat(.{ .tokens = 4, .period_ms = 1000 });
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 1, .peer = peer, .global = quotas(100, 1000) });
    defer owner.deinit(std.testing.allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 2, .deneb, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 250));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 4, .fulu, std.math.maxInt(u64)));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.take(&first, method, 1, .fulu, std.math.maxInt(u64)));
}

fn allocation(allocator: std.mem.Allocator) !void {
    var owner = try a.Limiter.init(allocator, .{ .identities = 2, .peer = quotas(2, 1000), .global = quotas(100, 1000) });
    defer owner.deinit(allocator);
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 0));
}

test "reqresp request admission allocation prefixes and invalid numeric configuration" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocation, .{});
    for ([_]u16{ 0, 4097 }) |count| try std.testing.expectError(error.InvalidOptions, a.Limiter.init(std.testing.allocator, .{ .identities = count, .peer = quotas(2, 1000), .global = quotas(2, 1000) }));
    try std.testing.expectError(error.InvalidQuota, a.Limiter.init(std.testing.allocator, .{ .identities = 1, .peer = quotas(0, 1000), .global = quotas(2, 1000) }));
    for ([_]u64{ 0, 86_400_001, std.math.maxInt(u64) }) |period| try std.testing.expectError(error.InvalidQuota, a.Limiter.init(std.testing.allocator, .{ .identities = 1, .peer = quotas(2, 1000), .global = quotas(2, period) }));
}

test "reqresp request admission integer rounding never grants extra work and full bytes distinguish identities" {
    var owner = try a.Limiter.init(std.testing.allocator, .{ .identities = 2, .peer = quotas(3, 1000), .global = quotas(100, 1000) });
    defer owner.deinit(std.testing.allocator);
    var similar = first;
    similar.bytes[similar.bytes.len - 1] = 2;
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.peer_quota, owner.take(&first, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&similar, method, 1, .fulu, 0));
    try std.testing.expectEqual(a.Decision.identity_capacity, owner.take(&third, method, 1, .fulu, 333));
    try std.testing.expectEqual(a.Decision.allowed, owner.take(&third, method, 1, .fulu, 334));
}
