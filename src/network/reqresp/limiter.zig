const std = @import("std");
const constants = @import("constants.zig");
const protocol = @import("protocol.zig");

const assert = std.debug.assert;
const Protocol = protocol.Protocol;

pub const Quota = struct {
    tokens: u32,
    period_ms: u64,
};

pub const Bucket = struct {
    tokens: u32 = 0,
    refilled_ms: u64 = 0,
    credit: u64 = 0,
};

pub const Quotas = [Protocol.count]Quota;

pub fn defaultQuotas() Quotas {
    var out: Quotas = undefined;
    inline for (@typeInfo(Protocol).@"enum".fields, 0..) |field, index| {
        const bounds = @as(Protocol, @enumFromInt(field.value)).info();
        out[index] = .{ .tokens = bounds.quota_tokens, .period_ms = bounds.quota_period_ms };
    }
    return out;
}

const Handle = @import("../quic/api.zig").Handle;
pub const InitError = error{ InvalidOptions, InvalidQuota } || std.mem.Allocator.Error;

pub const Limiter = struct {
    buckets: []Bucket,
    generations: []?u32,
    peers: u16,
    quotas: Quotas,
    global_quotas: Quotas,
    global: [Protocol.count]Bucket,

    pub fn init(allocator: std.mem.Allocator, peers: u16, quotas: ?Quotas) InitError!Limiter {
        return initWithGlobal(allocator, peers, quotas, null);
    }

    pub fn initWithGlobal(
        allocator: std.mem.Allocator,
        peers: u16,
        quotas: ?Quotas,
        global_quotas: ?Quotas,
    ) InitError!Limiter {
        if (peers == 0 or peers > constants.slots_ceiling) return error.InvalidOptions;
        const table = quotas orelse defaultQuotas();
        const aggregate = global_quotas orelse table;
        try validate(table);
        try validate(aggregate);
        const buckets = try allocator.alloc(Bucket, @as(usize, peers) * Protocol.count);
        errdefer allocator.free(buckets);
        const generations = try allocator.alloc(?u32, peers);
        @memset(generations, null);
        var global: [Protocol.count]Bucket = undefined;
        for (&global, aggregate) |*bucket, quota| bucket.* = .{ .tokens = quota.tokens };
        @memset(buckets, .{});
        return .{
            .buckets = buckets,
            .generations = generations,
            .peers = peers,
            .quotas = table,
            .global_quotas = aggregate,
            .global = global,
        };
    }

    pub fn validate(quotas: Quotas) error{InvalidQuota}!void {
        for (quotas) |quota| {
            if (quota.tokens == 0 or quota.period_ms == 0) return error.InvalidQuota;
        }
    }

    pub fn deinit(self: *Limiter, allocator: std.mem.Allocator) void {
        allocator.free(self.generations);
        allocator.free(self.buckets);
        self.* = undefined;
    }

    /// Bind only on admission after validating the handle against the attached Engine.
    pub fn bind(self: *Limiter, peer: Handle, now_ms: u64) void {
        assert(peer.index < self.peers);
        if (self.matches(peer)) return;
        self.generations[peer.index] = peer.generation;
        const base = @as(usize, peer.index) * Protocol.count;
        for (self.buckets[base..][0..Protocol.count], self.quotas) |*bucket, quota| {
            bucket.* = .{ .tokens = quota.tokens, .refilled_ms = now_ms };
        }
    }

    pub fn matches(self: *const Limiter, peer: Handle) bool {
        return peer.index < self.peers and self.generations[peer.index] == peer.generation;
    }

    pub fn take(self: *Limiter, peer: Handle, which: Protocol, cost: u32, now_ms: u64) bool {
        assert(cost > 0);
        if (!self.matches(peer)) return false;
        const bucket = self.bucketFor(peer.index, which);
        const index = @intFromEnum(which);
        refill(bucket, self.quotas[index], now_ms);
        refill(&self.global[index], self.global_quotas[index], now_ms);
        if (cost > bucket.tokens or cost > self.global[index].tokens) return false;
        bucket.tokens -= cost;
        self.global[index].tokens -= cost;
        return true;
    }

    pub fn peerAvailable(self: *Limiter, peer: Handle, which: Protocol, now_ms: u64) u32 {
        if (!self.matches(peer)) return 0;
        const bucket = self.bucketFor(peer.index, which);
        refill(bucket, self.quotas[@intFromEnum(which)], now_ms);
        return bucket.tokens;
    }

    pub fn nextToken(self: *Limiter, peer: Handle, which: Protocol, now_ms: u64) ?u64 {
        if (!self.matches(peer)) return null;
        const bucket = self.bucketFor(peer.index, which);
        const index = @intFromEnum(which);
        refill(bucket, self.quotas[index], now_ms);
        refill(&self.global[index], self.global_quotas[index], now_ms);
        return now_ms +| @max(
            waitMs(bucket, self.quotas[index]),
            waitMs(&self.global[index], self.global_quotas[index]),
        );
    }

    fn bucketFor(self: *Limiter, peer: u16, which: Protocol) *Bucket {
        return &self.buckets[@as(usize, peer) * Protocol.count + @intFromEnum(which)];
    }
};

fn waitMs(bucket: *const Bucket, quota: Quota) u64 {
    if (bucket.tokens > 0) return 0;
    const needed = @as(u128, quota.period_ms) - bucket.credit;
    return @intCast((needed + quota.tokens - 1) / quota.tokens);
}

fn refill(bucket: *Bucket, quota: Quota, now_ms: u64) void {
    assert(bucket.tokens <= quota.tokens);
    if (now_ms <= bucket.refilled_ms) return;
    const elapsed = now_ms - bucket.refilled_ms;
    const credit = std.math.mulWide(u64, elapsed, quota.tokens) + bucket.credit;
    const granted = credit / quota.period_ms;
    bucket.refilled_ms = now_ms;
    const room = quota.tokens - bucket.tokens;
    if (granted >= room) {
        bucket.tokens = quota.tokens;
        bucket.credit = 0;
    } else {
        bucket.tokens += @intCast(granted);
        bucket.credit = @intCast(credit % quota.period_ms);
    }
    assert(bucket.tokens <= quota.tokens);
    assert(bucket.refilled_ms <= now_ms);
}
