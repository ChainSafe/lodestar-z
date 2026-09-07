const std = @import("std");
const a = @import("admission.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const ForkSeq = @import("config").ForkSeq;
const Protocol = @import("protocol.zig").Protocol;
const limiter = @import("limiter.zig");

pub fn quotas(tokens: u32, period: u64) a.ByFork {
    return @splat(@as(limiter.Quotas, @splat(.{ .tokens = tokens, .period_ms = period })));
}
const first: PeerId = .{ .bytes = @splat(1) };
const second: PeerId = .{ .bytes = @splat(2) };
const third: PeerId = .{ .bytes = @splat(3) };
const method: Protocol = .blocks_by_root_v2;

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
