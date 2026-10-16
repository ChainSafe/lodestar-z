const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const PeerId = @import("../wire/peer_id.zig").PeerId;
const Protocol = @import("protocol.zig").Protocol;
const quota_config = @import("quotas.zig");
const ByFork = quota_config.ByFork;
const Options = quota_config.Options;
pub const Decision = enum { allowed, peer_quota, global_quota, identity_capacity };
pub const InitError = error{ InvalidOptions, InvalidQuota } || std.mem.Allocator.Error;
pub const identities_max = 4096;
const ns_per_ms = 1_000_000;

const Row = struct {
    identity: PeerId = undefined,
    occupied: bool = false,
    connections: u16 = 0,
    expires_ns: u128 = 0,
    starts_ns: u128 = 0,

    fn reusable(self: *const Row, now_ns: u128) bool {
        return self.connections == 0 and (!self.occupied or self.expires_ns <= now_ns);
    }
};

pub const Limiter = struct {
    rows: []Row,
    options: Options,
    protocols: Protocol.Set,
    debts: []u128,
    global: []u128,

    pub fn validate(options: *const Options) error{ InvalidOptions, InvalidQuota }!void {
        if (options.identities == 0 or options.identities > identities_max) return error.InvalidOptions;
        if (options.starts.tokens == 0 or options.starts.period_ms == 0 or options.starts.period_ms > 86_400_000) return error.InvalidQuota;
        for ([_]*const ByFork{ &options.peer, &options.global }) |table| {
            for (table) |quotas| for (quotas) |quota| {
                if (quota.tokens == 0 or quota.period_ms == 0 or quota.period_ms > 86_400_000) return error.InvalidQuota;
            };
        }
    }

    pub fn init(allocator: std.mem.Allocator, protocols: Protocol.Set, options: Options) InitError!Limiter {
        try validate(&options);
        if (protocols.len() == 0) return error.InvalidOptions;
        const rows = try allocator.alloc(Row, options.identities);
        errdefer allocator.free(rows);
        @memset(rows, .{});
        const debts = try allocator.alloc(u128, (@as(usize, options.identities) + 1) * protocols.len());
        @memset(debts, 0);
        return .{ .rows = rows, .options = options, .protocols = protocols, .debts = debts, .global = debts[0..protocols.len()] };
    }

    pub fn deinit(self: *Limiter, allocator: std.mem.Allocator) void {
        allocator.free(self.debts);
        allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn memoryPlan(self: *const Limiter) struct { allocated_bytes: usize } {
        return .{ .allocated_bytes = self.rows.len * @sizeOf(Row) + self.debts.len * @sizeOf(u128) };
    }

    fn debtRow(self: *const Limiter, index: usize) []u128 {
        std.debug.assert(index < self.rows.len);
        return self.debts[(index + 1) * self.protocols.len() ..][0..self.protocols.len()];
    }

    fn claim(self: *Limiter, index: usize, identity: *const PeerId) void {
        self.rows[index] = .{ .identity = identity.*, .occupied = true };
        @memset(self.debtRow(index), 0);
    }

    /// Holds identity bookkeeping through connection retirement, without refunding existing debt.
    pub fn retain(self: *Limiter, identity: *const PeerId, now_ms: u64) ?u16 {
        var reclaim: ?u16 = null;
        for (self.rows, 0..) |*row, index| {
            if (row.occupied and row.identity.eql(identity)) {
                std.debug.assert(row.connections < std.math.maxInt(u16));
                row.connections += 1;
                return @intCast(index);
            }
            if (reclaim == null and row.reusable(@as(u128, now_ms) * ns_per_ms)) reclaim = @intCast(index);
        }
        const index = reclaim orelse return null;
        self.claim(index, identity);
        self.rows[index].connections = 1;
        return index;
    }

    pub fn release(self: *Limiter, index: u16) void {
        const row = &self.rows[index];
        std.debug.assert(row.occupied and row.connections > 0);
        row.connections -= 1;
    }

    pub fn start(self: *Limiter, identity: *const PeerId, now_ms: u64) Decision {
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        var reclaim: ?usize = null;
        var found: ?usize = null;
        for (self.rows, 0..) |*row, row_index| {
            if (row.occupied and row.identity.eql(identity)) {
                found = row_index;
                break;
            }
            if (reclaim == null and row.reusable(now_ns)) reclaim = row_index;
        }
        const row_index = found orelse reclaim orelse return .identity_capacity;
        const row = &self.rows[row_index];
        const due = next(if (found != null) row.starts_ns else 0, 1, self.options.starts, now_ns) orelse return .peer_quota;
        if (found == null) self.claim(row_index, identity);
        row.starts_ns = due;
        row.expires_ns = @max(row.expires_ns, due);
        return .allowed;
    }

    /// Whether the identity has a row or one is free for it, so `start` would not refuse
    /// `identity_capacity`. Charges nothing.
    pub fn tracks(self: *const Limiter, identity: *const PeerId, now_ms: u64) bool {
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        for (self.rows) |*row| {
            if (row.reusable(now_ns) or (row.occupied and row.identity.eql(identity))) return true;
        }
        return false;
    }

    /// When `start` next admits the identity, in the style of `eligibleAt`: a retry hint
    /// that reserves nothing, so a waiting request rechecks then. Without a free row, the
    /// earliest row expiry.
    pub fn startAt(self: *const Limiter, identity: *const PeerId, now_ms: u64) u64 {
        const quota = self.options.starts;
        var previous: u128 = 0;
        var room = false;
        var expires: u128 = std.math.maxInt(u128);
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        for (self.rows) |*row| {
            if (row.occupied and row.identity.eql(identity)) {
                previous = row.starts_ns;
                room = true;
                break;
            }
            room = room or row.reusable(now_ns);
            if (row.connections == 0) expires = @min(expires, row.expires_ns);
        }
        const period_ns = @as(u128, quota.period_ms) * ns_per_ms;
        const charge = (period_ns + quota.tokens - 1) / quota.tokens;
        const due = @max(if (room) 0 else expires, previous + charge -| period_ns);
        return @max(now_ms, std.math.cast(u64, (due +| (ns_per_ms - 1)) / ns_per_ms) orelse std.math.maxInt(u64));
    }

    pub fn eligibleAt(self: *const Limiter, identity: *const PeerId, which: Protocol, cost: u128, fork: ForkSeq, now_ms: u64) ?u64 {
        const index = @intFromEnum(which);
        const peer = self.options.peer[@intFromEnum(fork)][index];
        const global = self.options.global[@intFromEnum(fork)][index];
        if (cost > peer.tokens or cost > global.tokens) return null;
        var debt: u128 = 0;
        var room = false;
        var expires: u128 = std.math.maxInt(u128);
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        for (self.rows, 0..) |*row, row_index| {
            if (row.occupied and row.identity.eql(identity)) {
                debt = self.debtRow(row_index)[self.protocols.index(which).?];
                room = true;
                break;
            }
            room = room or row.reusable(now_ns);
            if (row.connections == 0) expires = @min(expires, row.expires_ns);
        }
        const peer_charge = (cost * peer.period_ms * ns_per_ms + peer.tokens - 1) / peer.tokens;
        const global_charge = (cost * global.period_ms * ns_per_ms + global.tokens - 1) / global.tokens;
        const due = @max(if (room) 0 else expires, debt + peer_charge -| (@as(u128, peer.period_ms) * ns_per_ms), self.global[self.protocols.index(which).?] + global_charge -| (@as(u128, global.period_ms) * ns_per_ms));
        return @max(now_ms, std.math.cast(u64, (due +| (ns_per_ms - 1)) / ns_per_ms) orelse std.math.maxInt(u64));
    }

    /// Legal requests can exceed a configured burst; admission reserves at most one full burst.
    pub fn requestCost(self: *const Limiter, which: Protocol, cost: u128, fork: ForkSeq) u128 {
        const index = @intFromEnum(which);
        return @min(cost, self.options.peer[@intFromEnum(fork)][index].tokens, self.options.global[@intFromEnum(fork)][index].tokens);
    }

    /// Ready requests accumulate credit so smaller requests cannot consume every refill.
    pub fn grant(self: *Limiter, identity: *const PeerId, which: Protocol, remaining: u128, fork: ForkSeq, now_ms: u64) u128 {
        const index = @intFromEnum(which);
        const peer = self.options.peer[@intFromEnum(fork)][index];
        const global = self.options.global[@intFromEnum(fork)][index];
        var debt: u128 = 0;
        for (self.rows, 0..) |*row, row_index| if (row.occupied and row.identity.eql(identity)) {
            debt = self.debtRow(row_index)[self.protocols.index(which).?];
            break;
        };
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        const cost = @min(remaining, available(debt, peer, now_ns), available(self.global[self.protocols.index(which).?], global, now_ns));
        if (cost == 0 or self.take(identity, which, cost, fork, now_ms) != .allowed) return 0;
        return cost;
    }

    pub fn take(self: *Limiter, identity: *const PeerId, which: Protocol, cost: u128, fork: ForkSeq, now_ms: u64) Decision {
        std.debug.assert(cost > 0);
        const index = @intFromEnum(which);
        const peer_quota = self.options.peer[@intFromEnum(fork)][index];
        const global_quota = self.options.global[@intFromEnum(fork)][index];
        if (cost > peer_quota.tokens) return .peer_quota;
        if (cost > global_quota.tokens) return .global_quota;
        const now_ns = @as(u128, now_ms) * ns_per_ms;
        var found: ?usize = null;
        var reclaim: ?usize = null;
        for (self.rows, 0..) |*row, row_index| {
            if (row.occupied and row.identity.eql(identity)) {
                found = row_index;
                break;
            }
            if (reclaim == null and row.reusable(now_ns)) reclaim = row_index;
        }
        const row_index = found orelse reclaim orelse return .identity_capacity;
        const row = &self.rows[row_index];
        const previous = if (found != null) self.debtRow(row_index)[self.protocols.index(which).?] else 0;
        const peer_next = next(previous, cost, peer_quota, now_ns) orelse return .peer_quota;
        const global_next = next(self.global[self.protocols.index(which).?], cost, global_quota, now_ns) orelse return .global_quota;
        if (found == null) self.claim(row_index, identity);
        self.debtRow(row_index)[self.protocols.index(which).?] = peer_next;
        row.expires_ns = @max(row.expires_ns, peer_next);
        self.global[self.protocols.index(which).?] = global_next;
        return .allowed;
    }
};

fn available(debt: u128, quota: quota_config.Quota, now_ns: u128) u128 {
    const period = @as(u128, quota.period_ms) * ns_per_ms;
    const room = (now_ns + period) -| @max(now_ns, debt);
    return room * quota.tokens / period;
}

fn next(previous: u128, cost: u128, quota: quota_config.Quota, now_ns: u128) ?u128 {
    std.debug.assert(cost > 0 and cost <= quota.tokens);
    const period_ns = @as(u128, quota.period_ms) * ns_per_ms;
    const charge_ns = (cost * period_ns + quota.tokens - 1) / quota.tokens;
    const result = @max(now_ns, previous) + charge_ns;
    return if (result <= now_ns + period_ns) result else null;
}

test {
    _ = @import("admission_test.zig");
}
