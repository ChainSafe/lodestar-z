const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const PeerId = @import("../wire/peer_id.zig").PeerId;
const Protocol = @import("protocol.zig").Protocol;
const limiter = @import("limiter.zig");

pub const ByFork = [ForkSeq.count]limiter.Quotas;
pub const Options = struct { identities: u16, peer: ByFork, global: ByFork };
pub const Decision = enum { allowed, peer_quota, global_quota, identity_capacity };
pub const InitError = error{ InvalidOptions, InvalidQuota } || std.mem.Allocator.Error;
pub const identities_max = 4096;
const ns_per_ms = 1_000_000;

const Row = struct {
    identity: PeerId = undefined,
    occupied: bool = false,
    debt: [Protocol.count]u128 = @splat(0),
    expires_ns: u128 = 0,
};

pub const Limiter = struct {
    rows: []Row,
    options: Options,
    global: [Protocol.count]u128 = @splat(0),

    pub fn validate(options: *const Options) error{ InvalidOptions, InvalidQuota }!void {
        if (options.identities == 0 or options.identities > identities_max) return error.InvalidOptions;
        for ([_]*const ByFork{ &options.peer, &options.global }) |table| {
            for (table) |quotas| for (quotas) |quota| {
                if (quota.tokens == 0 or quota.period_ms == 0 or quota.period_ms > 86_400_000) return error.InvalidQuota;
            };
        }
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Limiter {
        try validate(&options);
        const rows = try allocator.alloc(Row, options.identities);
        @memset(rows, .{});
        return .{ .rows = rows, .options = options };
    }

    pub fn deinit(self: *Limiter, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn memoryPlan(self: *const Limiter) struct { allocated_bytes: usize } {
        return .{ .allocated_bytes = self.rows.len * @sizeOf(Row) };
    }

    pub fn take(self: *Limiter, identity: *const PeerId, which: Protocol, cost: u128, fork: ForkSeq, now_ms: u64) Decision {
        std.debug.assert(cost > 0);
        const index = @intFromEnum(which);
        const peer_quota = self.options.peer[@intFromEnum(fork)][index];
        const global_quota = self.options.global[@intFromEnum(fork)][index];
        if (cost > peer_quota.tokens) return .peer_quota;
        if (cost > global_quota.tokens) return .global_quota;
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        var found: ?*Row = null;
        var reclaim: ?*Row = null;
        for (self.rows) |*row| {
            if (row.occupied and row.identity.eql(identity)) {
                found = row;
                break;
            }
            if (reclaim == null and (!row.occupied or row.expires_ns <= now_ns)) reclaim = row;
        }
        const row = found orelse reclaim orelse return .identity_capacity;
        const previous = if (found != null) row.debt[index] else 0;
        const peer_next = next(previous, cost, peer_quota, now_ns) orelse return .peer_quota;
        const global_next = next(self.global[index], cost, global_quota, now_ns) orelse return .global_quota;
        if (found == null) row.* = .{ .identity = identity.*, .occupied = true };
        row.debt[index] = peer_next;
        row.expires_ns = @max(row.expires_ns, peer_next);
        self.global[index] = global_next;
        return .allowed;
    }
};

fn next(previous: u128, cost: u128, quota: limiter.Quota, now_ns: u128) ?u128 {
    std.debug.assert(cost > 0 and cost <= quota.tokens);
    const period_ns = @as(u128, quota.period_ms) * ns_per_ms;
    const charge_ns = (cost * period_ns + quota.tokens - 1) / quota.tokens;
    const result = @max(now_ns, previous) + charge_ns;
    return if (result <= now_ns + period_ns) result else null;
}
