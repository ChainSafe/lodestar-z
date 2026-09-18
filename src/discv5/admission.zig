const std = @import("std");
const types = @import("types.zig");

pub const source_capacity = 256;
pub const Stage = enum { challenge, handshake };
pub const Outcome = enum { allowed, source_limit, global_limit, source_capacity };
pub const stage_count = std.meta.fields(Stage).len;
pub const outcome_count = std.meta.fields(Outcome).len;
pub const Counts = [stage_count][outcome_count]u64;

const Quota = struct { interval_ms: u64, burst: u16 };
pub const source_quota: Quota = .{ .interval_ms = 250, .burst = 4 };
pub const global_quota: Quota = .{ .interval_ms = 50, .burst = 20 };

const Bucket = struct {
    charged_until_ms: u64 = 0,

    fn next(self: Bucket, quota: Quota, now_ms: u64) ?u64 {
        const proposed = std.math.add(u64, @max(self.charged_until_ms, now_ms), quota.interval_ms) catch return null;
        if (proposed > now_ms +| (quota.interval_ms * quota.burst)) return null;
        return proposed;
    }
};

const Source = struct {
    address: types.Address = .unspecified,
    buckets: [stage_count]Bucket = @splat(.{}),

    fn reusable(self: *const Source, now_ms: u64) bool {
        for (self.buckets) |bucket| if (bucket.charged_until_ms > now_ms) return false;
        return true;
    }
};

pub const Admission = struct {
    sources: []Source,
    global: [stage_count]Bucket = @splat(.{}),
    counts: Counts = @splat(@splat(0)),

    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Admission {
        const sources = try allocator.alloc(Source, source_capacity);
        @memset(sources, .{});
        return .{ .sources = sources };
    }

    pub fn deinit(self: *Admission, allocator: std.mem.Allocator) void {
        allocator.free(self.sources);
        self.* = undefined;
    }

    pub fn allow(self: *Admission, stage: Stage, address: *const types.Address, now_ms: u64) bool {
        const outcome = self.charge(stage, address, now_ms);
        self.counts[@intFromEnum(stage)][@intFromEnum(outcome)] +|= 1;
        return outcome == .allowed;
    }

    fn charge(self: *Admission, stage: Stage, address: *const types.Address, now_ms: u64) Outcome {
        const index = @intFromEnum(stage);
        const global_next = self.global[index].next(global_quota, now_ms) orelse return .global_limit;
        const source = self.findSource(address, now_ms) orelse return .source_capacity;
        const matching = source.address.sameSourceGroup(address.*);
        const bucket: Bucket = if (matching) source.buckets[index] else .{};
        const source_next = bucket.next(source_quota, now_ms) orelse return .source_limit;
        if (!matching) source.* = .{ .address = address.* };
        source.buckets[index].charged_until_ms = source_next;
        self.global[index].charged_until_ms = global_next;
        return .allowed;
    }

    fn findSource(self: *Admission, address: *const types.Address, now_ms: u64) ?*Source {
        var available: ?*Source = null;
        for (self.sources) |*source| {
            if (source.address.sameSourceGroup(address.*)) return source;
            // Only fully replenished entries can be replaced; churn cannot refund spent credit.
            if (available == null and source.reusable(now_ms)) available = source;
        }
        return available;
    }
};

comptime {
    std.debug.assert(source_quota.interval_ms * source_quota.burst == 1_000);
    std.debug.assert(global_quota.interval_ms * global_quota.burst == 1_000);
    std.debug.assert(@sizeOf(Source) <= 64);
}

test {
    _ = @import("admission_test.zig");
}
