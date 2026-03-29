//! PayloadId cache for the Engine API.
//!
//! Caches PayloadId values returned by forkchoiceUpdated keyed by a hash
//! of the PayloadAttributes. Used during block production: forkchoiceUpdated
//! returns a payload_id, then getPayload uses it to retrieve the built block.
//!
//! LRU cache with TTL (default 2 slots = 24 seconds at 12s slot time).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("engine_api_types.zig");

pub const PayloadAttributesV1 = types.PayloadAttributesV1;
pub const PayloadAttributesV2 = types.PayloadAttributesV2;
pub const PayloadAttributesV3 = types.PayloadAttributesV3;

/// A payload ID (8 bytes), as returned by the EL on forkchoiceUpdated.
pub const PayloadId = [8]u8;

/// Default TTL: 2 slots (24 seconds at 12s slot time).
pub const DEFAULT_TTL_SLOTS: u64 = 2;
/// Seconds per slot.
pub const SECONDS_PER_SLOT: u64 = 12;
/// Default TTL in seconds.
pub const DEFAULT_TTL_SECONDS: u64 = DEFAULT_TTL_SLOTS * SECONDS_PER_SLOT;
/// Default maximum cache entries.
pub const DEFAULT_MAX_ENTRIES: usize = 10;

/// A single cache entry.
const Entry = struct {
    /// Hash of the PayloadAttributes used as the cache key.
    key: [32]u8,
    /// The cached PayloadId.
    payload_id: PayloadId,
    /// Insertion timestamp (Unix seconds). Used for TTL eviction.
    inserted_at: u64,
};

/// LRU cache mapping PayloadAttributes hash → PayloadId.
///
/// Entries expire after `ttl_seconds` and the cache is bounded to
/// `max_entries` items (oldest evicted first when full).
pub const PayloadIdCache = struct {
    allocator: Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    /// Maximum number of live entries.
    max_entries: usize,
    /// TTL in seconds. Entries older than this are considered stale.
    ttl_seconds: u64,

    pub fn init(allocator: Allocator) PayloadIdCache {
        return initWithOptions(allocator, DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS);
    }

    pub fn initWithOptions(
        allocator: Allocator,
        max_entries: usize,
        ttl_seconds: u64,
    ) PayloadIdCache {
        return .{
            .allocator = allocator,
            .entries = .empty,
            .max_entries = max_entries,
            .ttl_seconds = ttl_seconds,
        };
    }

    pub fn deinit(self: *PayloadIdCache) void {
        self.entries.deinit(self.allocator);
    }

    /// Add a payload ID to the cache keyed by the V1 attributes.
    pub fn addV1(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV1,
        payload_id: PayloadId,
        now_seconds: u64,
    ) !void {
        const key = hashAttributesV1(attrs);
        return self.addEntry(key, payload_id, now_seconds);
    }

    /// Add a payload ID to the cache keyed by the V2 attributes.
    pub fn addV2(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV2,
        payload_id: PayloadId,
        now_seconds: u64,
    ) !void {
        const key = hashAttributesV2(attrs);
        return self.addEntry(key, payload_id, now_seconds);
    }

    /// Add a payload ID to the cache keyed by the V3 attributes.
    pub fn addV3(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV3,
        payload_id: PayloadId,
        now_seconds: u64,
    ) !void {
        const key = hashAttributesV3(attrs);
        return self.addEntry(key, payload_id, now_seconds);
    }

    /// Look up a payload ID by V1 attributes. Returns null if not found or expired.
    pub fn getV1(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV1,
        now_seconds: u64,
    ) ?PayloadId {
        const key = hashAttributesV1(attrs);
        return self.getEntry(key, now_seconds);
    }

    /// Look up a payload ID by V2 attributes. Returns null if not found or expired.
    pub fn getV2(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV2,
        now_seconds: u64,
    ) ?PayloadId {
        const key = hashAttributesV2(attrs);
        return self.getEntry(key, now_seconds);
    }

    /// Look up a payload ID by V3 attributes. Returns null if not found or expired.
    pub fn getV3(
        self: *PayloadIdCache,
        attrs: PayloadAttributesV3,
        now_seconds: u64,
    ) ?PayloadId {
        const key = hashAttributesV3(attrs);
        return self.getEntry(key, now_seconds);
    }

    /// Remove all entries older than `ttl_seconds` relative to `now_seconds`.
    pub fn prune(self: *PayloadIdCache, now_seconds: u64) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const entry = self.entries.items[i];
            if (isExpired(entry, now_seconds, self.ttl_seconds)) {
                _ = self.entries.orderedRemove(i);
                // Don't increment i — the next element shifted into this slot.
            } else {
                i += 1;
            }
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn addEntry(
        self: *PayloadIdCache,
        key: [32]u8,
        payload_id: PayloadId,
        now_seconds: u64,
    ) !void {
        // Update existing entry if the key is already present.
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.key, &key)) {
                e.payload_id = payload_id;
                e.inserted_at = now_seconds;
                return;
            }
        }

        // Evict oldest entry if at capacity.
        if (self.entries.items.len >= self.max_entries) {
            _ = self.entries.orderedRemove(0);
        }

        try self.entries.append(self.allocator, .{
            .key = key,
            .payload_id = payload_id,
            .inserted_at = now_seconds,
        });
    }

    fn getEntry(
        self: *const PayloadIdCache,
        key: [32]u8,
        now_seconds: u64,
    ) ?PayloadId {
        // Search from most recent (end) to oldest (start) — LRU convention.
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.entries.items[i];
            if (!std.mem.eql(u8, &entry.key, &key)) continue;
            if (isExpired(entry, now_seconds, self.ttl_seconds)) return null;
            return entry.payload_id;
        }
        return null;
    }

    fn isExpired(entry: Entry, now_seconds: u64, ttl_seconds: u64) bool {
        if (now_seconds < entry.inserted_at) return false; // clock went backwards
        return (now_seconds - entry.inserted_at) > ttl_seconds;
    }
};

// ── Hashing helpers ───────────────────────────────────────────────────────────

/// Hash PayloadAttributesV1 into a 32-byte key using SHA256.
fn hashAttributesV1(attrs: PayloadAttributesV1) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    // timestamp (8 bytes, little-endian)
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, attrs.timestamp, .little);
    h.update(&ts);
    // prev_randao
    h.update(&attrs.prev_randao);
    // suggested_fee_recipient
    h.update(&attrs.suggested_fee_recipient);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Hash PayloadAttributesV2 into a 32-byte key using SHA256.
fn hashAttributesV2(attrs: PayloadAttributesV2) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, attrs.timestamp, .little);
    h.update(&ts);
    h.update(&attrs.prev_randao);
    h.update(&attrs.suggested_fee_recipient);
    // Hash each withdrawal deterministically.
    for (attrs.withdrawals) |w| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, w.index, .little);
        h.update(&buf);
        std.mem.writeInt(u64, &buf, w.validator_index, .little);
        h.update(&buf);
        h.update(&w.address);
        std.mem.writeInt(u64, &buf, w.amount, .little);
        h.update(&buf);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Hash PayloadAttributesV3 into a 32-byte key using SHA256.
fn hashAttributesV3(attrs: PayloadAttributesV3) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, attrs.timestamp, .little);
    h.update(&ts);
    h.update(&attrs.prev_randao);
    h.update(&attrs.suggested_fee_recipient);
    for (attrs.withdrawals) |w| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, w.index, .little);
        h.update(&buf);
        std.mem.writeInt(u64, &buf, w.validator_index, .little);
        h.update(&buf);
        h.update(&w.address);
        std.mem.writeInt(u64, &buf, w.amount, .little);
        h.update(&buf);
    }
    h.update(&attrs.parent_beacon_block_root);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "PayloadIdCache: add and get V3 entry" {
    var cache = PayloadIdCache.init(testing.allocator);
    defer cache.deinit();

    const attrs = PayloadAttributesV3{
        .timestamp = 1_000_000,
        .prev_randao = [_]u8{0xab} ** 32,
        .suggested_fee_recipient = [_]u8{0xcd} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xef} ** 32,
    };
    const pid = [8]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    try cache.addV3(attrs, pid, 1_700_000_000);
    const result = cache.getV3(attrs, 1_700_000_000);
    try testing.expect(result != null);
    try testing.expectEqual(pid, result.?);
}

test "PayloadIdCache: get returns null for unknown key" {
    var cache = PayloadIdCache.init(testing.allocator);
    defer cache.deinit();

    const attrs = PayloadAttributesV3{
        .timestamp = 2_000_000,
        .prev_randao = [_]u8{0x11} ** 32,
        .suggested_fee_recipient = [_]u8{0x22} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0x33} ** 32,
    };

    const result = cache.getV3(attrs, 1_700_000_000);
    try testing.expect(result == null);
}

test "PayloadIdCache: TTL expiry" {
    var cache = PayloadIdCache.initWithOptions(testing.allocator, 10, 24);
    defer cache.deinit();

    const attrs = PayloadAttributesV3{
        .timestamp = 100,
        .prev_randao = [_]u8{0xaa} ** 32,
        .suggested_fee_recipient = [_]u8{0xbb} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xcc} ** 32,
    };
    const pid = [_]u8{0x01} ** 8;

    try cache.addV3(attrs, pid, 1_000);
    // Within TTL: should find entry.
    try testing.expect(cache.getV3(attrs, 1_020) != null);
    // Past TTL: should return null.
    try testing.expect(cache.getV3(attrs, 1_025) == null);
}

test "PayloadIdCache: prune removes expired entries" {
    var cache = PayloadIdCache.initWithOptions(testing.allocator, 10, 24);
    defer cache.deinit();

    const attrs1 = PayloadAttributesV3{
        .timestamp = 100,
        .prev_randao = [_]u8{0x01} ** 32,
        .suggested_fee_recipient = [_]u8{0x01} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0x01} ** 32,
    };
    const attrs2 = PayloadAttributesV3{
        .timestamp = 200,
        .prev_randao = [_]u8{0x02} ** 32,
        .suggested_fee_recipient = [_]u8{0x02} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0x02} ** 32,
    };

    try cache.addV3(attrs1, [_]u8{0x01} ** 8, 1_000);
    try cache.addV3(attrs2, [_]u8{0x02} ** 8, 1_020);

    // Prune at t=1026: attrs1 (inserted at 1000, age=26) expires; attrs2 (age=6) lives.
    cache.prune(1_026);
    try testing.expectEqual(@as(usize, 1), cache.entries.items.len);
    try testing.expect(cache.getV3(attrs2, 1_026) != null);
    try testing.expect(cache.getV3(attrs1, 1_026) == null);
}

test "PayloadIdCache: LRU eviction when full" {
    var cache = PayloadIdCache.initWithOptions(testing.allocator, 2, 1000);
    defer cache.deinit();

    const make_attrs = struct {
        fn call(ts: u64) PayloadAttributesV3 {
            return .{
                .timestamp = ts,
                .prev_randao = [_]u8{0x00} ** 32,
                .suggested_fee_recipient = [_]u8{0x00} ** 20,
                .withdrawals = &.{},
                .parent_beacon_block_root = [_]u8{0x00} ** 32,
            };
        }
    }.call;

    const a1 = make_attrs(1);
    const a2 = make_attrs(2);
    const a3 = make_attrs(3);

    try cache.addV3(a1, [_]u8{0x01} ** 8, 1_000);
    try cache.addV3(a2, [_]u8{0x02} ** 8, 1_000);
    // Adding a third evicts the oldest (a1).
    try cache.addV3(a3, [_]u8{0x03} ** 8, 1_000);

    try testing.expectEqual(@as(usize, 2), cache.entries.items.len);
    try testing.expect(cache.getV3(a1, 1_000) == null); // evicted
    try testing.expect(cache.getV3(a2, 1_000) != null);
    try testing.expect(cache.getV3(a3, 1_000) != null);
}

test "PayloadIdCache: updating existing key refreshes timestamp" {
    var cache = PayloadIdCache.initWithOptions(testing.allocator, 10, 24);
    defer cache.deinit();

    const attrs = PayloadAttributesV3{
        .timestamp = 500,
        .prev_randao = [_]u8{0xff} ** 32,
        .suggested_fee_recipient = [_]u8{0xee} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xdd} ** 32,
    };
    const pid1 = [_]u8{0x01} ** 8;
    const pid2 = [_]u8{0x02} ** 8;

    try cache.addV3(attrs, pid1, 1_000);
    try cache.addV3(attrs, pid2, 1_020); // update same key

    try testing.expectEqual(@as(usize, 1), cache.entries.items.len);
    const result = cache.getV3(attrs, 1_040);
    try testing.expect(result != null);
    try testing.expectEqual(pid2, result.?);
}

test "PayloadIdCache: V1 attributes" {
    var cache = PayloadIdCache.init(testing.allocator);
    defer cache.deinit();

    const attrs = PayloadAttributesV1{
        .timestamp = 100,
        .prev_randao = [_]u8{0xaa} ** 32,
        .suggested_fee_recipient = [_]u8{0xbb} ** 20,
    };
    const pid = [_]u8{0xaa} ** 8;
    try cache.addV1(attrs, pid, 1_000);
    try testing.expectEqual(pid, cache.getV1(attrs, 1_000).?);
}

test "PayloadIdCache: V2 attributes" {
    var cache = PayloadIdCache.init(testing.allocator);
    defer cache.deinit();

    const attrs = PayloadAttributesV2{
        .timestamp = 200,
        .prev_randao = [_]u8{0x11} ** 32,
        .suggested_fee_recipient = [_]u8{0x22} ** 20,
        .withdrawals = &.{},
    };
    const pid = [_]u8{0xbb} ** 8;
    try cache.addV2(attrs, pid, 2_000);
    try testing.expectEqual(pid, cache.getV2(attrs, 2_000).?);
}
