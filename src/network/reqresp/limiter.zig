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

pub const Limiter = struct {
    buckets: []Bucket,
    peers: u16,
    quotas: Quotas,

    pub fn init(
        allocator: std.mem.Allocator,
        peers: u16,
        quotas: ?Quotas,
    ) std.mem.Allocator.Error!Limiter {
        assert(peers > 0);
        assert(peers <= constants.slots_ceiling);
        const table = quotas orelse defaultQuotas();
        for (table) |quota| {
            assert(quota.tokens > 0);
            assert(quota.period_ms > 0);
        }
        const buckets = try allocator.alloc(Bucket, @as(usize, peers) * Protocol.count);
        for (buckets, 0..) |*bucket, index| {
            bucket.* = .{ .tokens = table[index % Protocol.count].tokens, .refilled_ms = 0 };
        }
        return .{ .buckets = buckets, .peers = peers, .quotas = table };
    }

    pub fn deinit(self: *Limiter, allocator: std.mem.Allocator) void {
        assert(self.buckets.len == @as(usize, self.peers) * Protocol.count);
        allocator.free(self.buckets);
        self.* = undefined;
    }

    pub fn take(self: *Limiter, peer: u16, which: Protocol, cost: u32, now_ms: u64) bool {
        assert(peer < self.peers);
        assert(cost > 0);
        const bucket = self.bucketFor(peer, which);
        const quota = self.quotas[@intFromEnum(which)];
        refill(bucket, quota, now_ms);
        if (cost > bucket.tokens) return false;
        bucket.tokens -= cost;
        assert(bucket.tokens <= quota.tokens);
        return true;
    }

    pub fn available(self: *Limiter, peer: u16, which: Protocol, now_ms: u64) u32 {
        assert(peer < self.peers);
        const bucket = self.bucketFor(peer, which);
        refill(bucket, self.quotas[@intFromEnum(which)], now_ms);
        assert(bucket.tokens <= self.quotas[@intFromEnum(which)].tokens);
        return bucket.tokens;
    }

    pub fn reset(self: *Limiter, peer: u16, now_ms: u64) void {
        assert(peer < self.peers);
        const base = @as(usize, peer) * Protocol.count;
        for (self.buckets[base..][0..Protocol.count], 0..) |*bucket, index| {
            bucket.* = .{ .tokens = self.quotas[index].tokens, .refilled_ms = now_ms };
        }
        assert(self.buckets[base].tokens == self.quotas[0].tokens);
    }

    fn bucketFor(self: *Limiter, peer: u16, which: Protocol) *Bucket {
        const index = @as(usize, peer) * Protocol.count + @intFromEnum(which);
        assert(index < self.buckets.len);
        return &self.buckets[index];
    }
};

fn refill(bucket: *Bucket, quota: Quota, now_ms: u64) void {
    assert(bucket.tokens <= quota.tokens);
    if (now_ms <= bucket.refilled_ms) return;
    const elapsed = now_ms - bucket.refilled_ms;
    const granted = std.math.mulWide(u64, elapsed, quota.tokens) / quota.period_ms;
    if (granted == 0) return;
    const room = quota.tokens - bucket.tokens;
    if (granted >= room) {
        bucket.tokens = quota.tokens;
        bucket.refilled_ms = now_ms;
    } else {
        bucket.tokens += @intCast(granted);
        bucket.refilled_ms += @intCast(granted * quota.period_ms / quota.tokens);
    }
    assert(bucket.tokens <= quota.tokens);
    assert(bucket.refilled_ms <= now_ms);
}

comptime {
    assert(Protocol.count > 0);
}
