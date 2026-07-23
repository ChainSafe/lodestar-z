const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

/// 10% headroom so nearby-but-larger later requests don't each reallocate.
fn grownSize(size: usize) usize {
    return size +| size / 10;
}

pub const AllocSource = enum {
    persistent_checkpoints_cache_validators,
    persistent_checkpoints_cache_state,
    archive_state,
};

pub const BufferPool = struct {
    allocator: Allocator,
    buffer: []u8,
    in_use: bool,
    /// Bumped per lease so a stale lease releasing after a newer one is a no-op.
    current_key: u64,

    pub fn init(allocator: Allocator, size: usize) !BufferPool {
        return .{
            .allocator = allocator,
            .buffer = try allocator.alloc(u8, grownSize(size)),
            .in_use = false,
            .current_key = 0,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.allocator.free(self.buffer);
    }

    pub fn capacity(self: *const BufferPool) usize {
        return self.buffer.len;
    }

    pub fn busy(self: *const BufferPool) bool {
        return self.in_use;
    }

    /// Null if a lease is already outstanding.
    pub fn alloc(self: *BufferPool, size: usize, source: AllocSource) !?BufferLease {
        return self.doAlloc(size, source, false);
    }

    /// Like `alloc` but the leased bytes are not zeroed.
    pub fn allocUnsafe(self: *BufferPool, size: usize, source: AllocSource) !?BufferLease {
        return self.doAlloc(size, source, true);
    }

    fn doAlloc(self: *BufferPool, size: usize, source: AllocSource, unsafe: bool) !?BufferLease {
        if (self.in_use) {
            try buffer_pool_metrics.misses.incr(.{ .source = source });
            return null;
        }

        // Grow before marking busy so a failed grow leaves the pool free (not wedged in_use).
        if (size > self.buffer.len) {
            const new_buffer = try self.allocator.alloc(u8, grownSize(size));
            self.allocator.free(self.buffer);
            self.buffer = new_buffer;
            buffer_pool_metrics.grows.incr();
        }

        try buffer_pool_metrics.hits.incr(.{ .source = source });
        self.in_use = true;
        self.current_key += 1;
        const bytes = self.buffer[0..size];
        if (!unsafe) @memset(bytes, 0);
        return .{ .bytes = bytes, .key = self.current_key, .pool = self };
    }

    fn free(self: *BufferPool, key: u64) void {
        if (key == self.current_key) self.in_use = false;
    }
};

pub const BufferLease = struct {
    bytes: []u8,
    key: u64,
    pool: *BufferPool,

    pub fn release(self: BufferLease) void {
        self.pool.free(self.key);
    }
};

const SourceLabel = struct { source: AllocSource };

pub const BufferPoolMetrics = struct {
    length: Gauge,
    hits: SourceCounter,
    misses: SourceCounter,
    grows: Count,

    const Gauge = m.Gauge(u64);
    const Count = m.Counter(u64);
    const SourceCounter = m.CounterVec(u64, SourceLabel);

    pub fn deinit(self: *BufferPoolMetrics) void {
        self.hits.deinit();
        self.misses.deinit();
    }
};

/// Noop by default so the pool is usable before `initMetrics`.
pub var buffer_pool_metrics = m.initializeNoop(BufferPoolMetrics);

/// Call once on startup.
pub fn initMetrics(allocator: Allocator, io: std.Io, comptime opts: m.RegistryOpts) !void {
    var hits = try BufferPoolMetrics.SourceCounter.init(
        allocator,
        io,
        "lodestar_buffer_pool_hits_total",
        .{ .help = "Total number of buffer pool hits" },
        opts,
    );
    errdefer hits.deinit();

    var misses = try BufferPoolMetrics.SourceCounter.init(
        allocator,
        io,
        "lodestar_buffer_pool_misses_total",
        .{ .help = "Total number of buffer pool misses" },
        opts,
    );
    errdefer misses.deinit();

    buffer_pool_metrics.deinit();

    buffer_pool_metrics = .{
        .length = BufferPoolMetrics.Gauge.init(
            "lodestar_buffer_pool_length",
            .{ .help = "Buffer pool length" },
            opts,
        ),
        .hits = hits,
        .misses = misses,
        .grows = BufferPoolMetrics.Count.init(
            "lodestar_buffer_pool_grows_total",
            .{ .help = "Total number of buffer pool length increases" },
            opts,
        ),
    };
}

/// Reset to noop after freeing so a later use of the freed maps is a no-op, not a use-after-free.
pub fn deinitMetrics() void {
    buffer_pool_metrics.deinit();
    buffer_pool_metrics = m.initializeNoop(BufferPoolMetrics);
}

/// Pull-refresh `length` from the pool's live capacity before serializing metrics.
pub fn refreshMetrics(pool: *const BufferPool) void {
    buffer_pool_metrics.length.set(pool.capacity());
}

const testing = std.testing;

test "BufferPool init sizes the buffer by the grow ratio" {
    var pool = try BufferPool.init(testing.allocator, 100);
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 110), pool.capacity());
    try testing.expect(!pool.busy());
}

test "BufferPool lease lifecycle: alloc, use, release, re-alloc" {
    var pool = try BufferPool.init(testing.allocator, 64);
    defer pool.deinit();

    const lease = (try pool.alloc(64, .archive_state)).?;
    try testing.expectEqual(@as(usize, 64), lease.bytes.len);
    try testing.expect(pool.busy());

    lease.release();
    try testing.expect(!pool.busy());

    const lease2 = (try pool.alloc(32, .archive_state)).?;
    try testing.expectEqual(@as(usize, 32), lease2.bytes.len);
    lease2.release();
}

test "BufferPool alloc returns null while a lease is outstanding" {
    var pool = try BufferPool.init(testing.allocator, 64);
    defer pool.deinit();

    const lease = (try pool.alloc(16, .archive_state)).?;
    try testing.expect((try pool.alloc(16, .archive_state)) == null);
    try testing.expect((try pool.alloc(8, .archive_state)) == null);

    lease.release();
    const lease2 = (try pool.alloc(16, .archive_state)).?;
    lease2.release();
}

test "BufferPool grows only when a request exceeds capacity" {
    var pool = try BufferPool.init(testing.allocator, 10);
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 11), pool.capacity());

    // Within capacity: no grow.
    var lease = (try pool.alloc(11, .archive_state)).?;
    try testing.expectEqual(@as(usize, 11), pool.capacity());
    lease.release();

    // Exceeds capacity: grows to floor(size * 1.1).
    lease = (try pool.alloc(100, .archive_state)).?;
    try testing.expectEqual(@as(usize, 110), pool.capacity());
    lease.release();

    // Below the grown capacity: reused, no further grow.
    lease = (try pool.alloc(50, .archive_state)).?;
    try testing.expectEqual(@as(usize, 110), pool.capacity());
    lease.release();
}

test "BufferPool bytes written through a lease are readable until release" {
    var pool = try BufferPool.init(testing.allocator, 8);
    defer pool.deinit();

    const lease = (try pool.alloc(4, .archive_state)).?;
    @memcpy(lease.bytes, &[_]u8{ 1, 2, 3, 4 });
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, lease.bytes);
    lease.release();
}

test "BufferPool alloc zeroes the leased bytes on reuse; allocUnsafe does not" {
    var pool = try BufferPool.init(testing.allocator, 4);
    defer pool.deinit();

    const dirty = (try pool.alloc(4, .archive_state)).?;
    @memset(dirty.bytes, 0xFF);
    dirty.release();

    // The zeroing variant clears the reused region.
    const clean = (try pool.alloc(4, .archive_state)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, clean.bytes);
    @memset(clean.bytes, 0xFF);
    clean.release();

    // The unsafe variant hands back the same reused (still dirty) region.
    const unsafe = (try pool.allocUnsafe(4, .archive_state)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, unsafe.bytes);
    unsafe.release();
}

test "BufferPool release of a stale lease does not free a newer lease" {
    var pool = try BufferPool.init(testing.allocator, 16);
    defer pool.deinit();

    const first = (try pool.alloc(8, .archive_state)).?;
    first.release();

    const second = (try pool.alloc(8, .archive_state)).?;
    // A double release of the now-stale first lease must not mark the pool free while `second` holds it.
    first.release();
    try testing.expect(pool.busy());
    try testing.expect((try pool.alloc(8, .archive_state)) == null);

    second.release();
    try testing.expect(!pool.busy());
}

/// Reads a labeled counter's current value from the metric's internal map (0 if unseen). Only the
/// tests reach into the impl; production code just increments.
fn labeledCount(vec: *BufferPoolMetrics.SourceCounter, source: AllocSource) u64 {
    return switch (vec.*) {
        .noop => 0,
        .impl => |*impl| if (impl.values.getPtr(.{ .source = source })) |v| v.count else 0,
    };
}

test "BufferPool records a hit on lease and a miss on a busy alloc" {
    var pool = try BufferPool.init(testing.allocator, 64);
    defer pool.deinit();

    try initMetrics(testing.allocator, testing.io, .{});
    defer deinitMetrics();

    const src = AllocSource.persistent_checkpoints_cache_state;
    const lease = (try pool.alloc(64, src)).?;
    try testing.expectEqual(@as(u64, 1), labeledCount(&buffer_pool_metrics.hits, src));
    try testing.expectEqual(@as(u64, 0), labeledCount(&buffer_pool_metrics.misses, src));

    // A second alloc while the first lease is live is a miss and returns null.
    try testing.expect((try pool.alloc(16, src)) == null);
    try testing.expectEqual(@as(u64, 1), labeledCount(&buffer_pool_metrics.hits, src));
    try testing.expectEqual(@as(u64, 1), labeledCount(&buffer_pool_metrics.misses, src));

    lease.release();
}

test "BufferPool grow increments grows; length refreshes to capacity" {
    var pool = try BufferPool.init(testing.allocator, 10);
    defer pool.deinit();

    try initMetrics(testing.allocator, testing.io, .{});
    defer deinitMetrics();

    const src = AllocSource.persistent_checkpoints_cache_validators;

    // Within the initial capacity (11): no grow.
    var lease = (try pool.alloc(11, src)).?;
    try testing.expectEqual(@as(u64, 0), buffer_pool_metrics.grows.impl.count);
    lease.release();

    // Exceeds capacity: one grow.
    lease = (try pool.alloc(100, src)).?;
    try testing.expectEqual(@as(u64, 1), buffer_pool_metrics.grows.impl.count);
    lease.release();

    // `length` is a pull gauge: refresh reads the pool's live capacity.
    refreshMetrics(&pool);
    try testing.expectEqual(pool.capacity(), buffer_pool_metrics.length.impl.value);
}

test "BufferPool records hits under distinct source labels" {
    var pool = try BufferPool.init(testing.allocator, 64);
    defer pool.deinit();

    try initMetrics(testing.allocator, testing.io, .{});
    defer deinitMetrics();

    const a = AllocSource.persistent_checkpoints_cache_validators;
    const b = AllocSource.archive_state;

    const l1 = (try pool.alloc(16, a)).?;
    l1.release();
    const l2 = (try pool.alloc(16, b)).?;
    l2.release();
    const l3 = (try pool.alloc(16, b)).?;
    l3.release();

    try testing.expectEqual(@as(u64, 1), labeledCount(&buffer_pool_metrics.hits, a));
    try testing.expectEqual(@as(u64, 2), labeledCount(&buffer_pool_metrics.hits, b));
}

test "BufferPool re-init frees the prior counters" {
    // Init TWICE under the testing allocator: the second init's guard must free the first init's
    // counter maps, so a leak would trip the allocator.
    try initMetrics(testing.allocator, testing.io, .{});
    try initMetrics(testing.allocator, testing.io, .{});
    defer deinitMetrics();

    try buffer_pool_metrics.hits.incr(.{ .source = AllocSource.archive_state });
}
