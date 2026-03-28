//! Status cache for quick response to incoming Status requests.
//!
//! Caches the local node's view of the chain head (fork_digest, finalized_root,
//! finalized_epoch, head_root, head_slot) so req/resp handlers can respond to
//! Status requests without re-computing from chain state.
//!
//! Updated on each new head event from the chain. Protected by a spin mutex
//! (std.atomic.Mutex) for thread safety.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#status

const std = @import("std");
const testing = std.testing;

const log = std.log.scoped(.status_cache);

// ── Types ─────────────────────────────────────────────────────────────────────

/// Fork digest: 4-byte identifier for the current fork.
pub const ForkDigest = [4]u8;

/// 32-byte root hash.
pub const Root = [32]u8;

/// Epoch number.
pub const Epoch = u64;

/// Slot number.
pub const Slot = u64;

/// A cached Status message matching the consensus spec StatusMessage type.
///
/// This is a plain struct (no SSZ dependency) for easy use within the networking layer.
/// Use the networking/messages.zig StatusMessage for wire encoding.
pub const CachedStatus = struct {
    fork_digest: ForkDigest,
    finalized_root: Root,
    finalized_epoch: Epoch,
    head_root: Root,
    head_slot: Slot,
};

/// Chain head information provided when updating the cache.
pub const StatusInfo = struct {
    fork_digest: ForkDigest,
    finalized_root: Root,
    finalized_epoch: Epoch,
    head_root: Root,
    head_slot: Slot,
};

// ── StatusCache ───────────────────────────────────────────────────────────────

/// Thread-safe cache for the local node's status.
///
/// Uses a spin mutex (std.atomic.Mutex) to protect concurrent access.
///
/// The cache starts empty (null). Callers should check `get()` and handle
/// the null case (e.g., during startup before the first head event).
pub const StatusCache = struct {
    /// The cached status. Null until first update.
    status: ?CachedStatus,
    /// Spin mutex protecting concurrent read/write.
    mutex: std.atomic.Mutex,
    /// Total number of updates applied.
    update_count: u64,

    pub fn init() StatusCache {
        return .{
            .status = null,
            .mutex = .unlocked,
            .update_count = 0,
        };
    }

    /// Acquire the spin mutex (busy-waits until locked).
    fn acquire(self: *StatusCache) void {
        while (!self.mutex.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    /// Update the cached status from a new chain head.
    ///
    /// Called on each new-head event from the fork choice / chain subsystem.
    pub fn update(self: *StatusCache, info: StatusInfo) void {
        self.acquire();
        defer self.mutex.unlock();

        const prev_slot = if (self.status) |s| s.head_slot else 0;
        self.status = CachedStatus{
            .fork_digest = info.fork_digest,
            .finalized_root = info.finalized_root,
            .finalized_epoch = info.finalized_epoch,
            .head_root = info.head_root,
            .head_slot = info.head_slot,
        };
        self.update_count += 1;

        log.debug("status cache updated: head_slot={} finalized_epoch={} (was slot={})", .{
            info.head_slot,
            info.finalized_epoch,
            prev_slot,
        });
    }

    /// Get the current cached status. Returns null if not yet populated.
    ///
    /// The returned value is a copy — safe to use without holding the lock.
    pub fn get(self: *StatusCache) ?CachedStatus {
        self.acquire();
        defer self.mutex.unlock();
        return self.status;
    }

    /// Returns the current head slot, or 0 if not yet populated.
    pub fn headSlot(self: *StatusCache) Slot {
        self.acquire();
        defer self.mutex.unlock();
        return if (self.status) |s| s.head_slot else 0;
    }

    /// Returns the current finalized epoch, or 0 if not yet populated.
    pub fn finalizedEpoch(self: *StatusCache) Epoch {
        self.acquire();
        defer self.mutex.unlock();
        return if (self.status) |s| s.finalized_epoch else 0;
    }

    /// Returns the current fork digest, or null if not yet populated.
    pub fn forkDigest(self: *StatusCache) ?ForkDigest {
        self.acquire();
        defer self.mutex.unlock();
        return if (self.status) |s| s.fork_digest else null;
    }

    /// Whether the cache has been populated at least once.
    pub fn isReady(self: *StatusCache) bool {
        self.acquire();
        defer self.mutex.unlock();
        return self.status != null;
    }

    /// Reset the cache (e.g., on fork transition).
    pub fn reset(self: *StatusCache) void {
        self.acquire();
        defer self.mutex.unlock();
        self.status = null;
        log.debug("status cache reset", .{});
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "StatusCache: initially empty" {
    var cache = StatusCache.init();
    try testing.expect(!cache.isReady());
    try testing.expect(cache.get() == null);
    try testing.expectEqual(@as(Slot, 0), cache.headSlot());
    try testing.expectEqual(@as(Epoch, 0), cache.finalizedEpoch());
    try testing.expect(cache.forkDigest() == null);
}

test "StatusCache: update populates cache" {
    var cache = StatusCache.init();

    const info = StatusInfo{
        .fork_digest = .{ 0xde, 0xad, 0xbe, 0xef },
        .finalized_root = [_]u8{0xaa} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xbb} ** 32,
        .head_slot = 3200,
    };
    cache.update(info);

    try testing.expect(cache.isReady());
    try testing.expectEqual(@as(Slot, 3200), cache.headSlot());
    try testing.expectEqual(@as(Epoch, 100), cache.finalizedEpoch());

    const digest = cache.forkDigest().?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &digest);
}

test "StatusCache: get returns copy of status" {
    var cache = StatusCache.init();

    cache.update(.{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 50,
        .head_root = [_]u8{0xff} ** 32,
        .head_slot = 1600,
    });

    const s = cache.get().?;
    try testing.expectEqual(@as(Slot, 1600), s.head_slot);
    try testing.expectEqual(@as(Epoch, 50), s.finalized_epoch);
    try testing.expectEqualSlices(u8, &([_]u8{0xff} ** 32), &s.head_root);
}

test "StatusCache: multiple updates advance head_slot" {
    var cache = StatusCache.init();

    cache.update(.{
        .fork_digest = .{ 0, 0, 0, 1 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 1,
        .head_root = [_]u8{1} ** 32,
        .head_slot = 100,
    });

    cache.update(.{
        .fork_digest = .{ 0, 0, 0, 1 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 2,
        .head_root = [_]u8{2} ** 32,
        .head_slot = 200,
    });

    try testing.expectEqual(@as(Slot, 200), cache.headSlot());
    try testing.expectEqual(@as(Epoch, 2), cache.finalizedEpoch());
    try testing.expectEqual(@as(u64, 2), cache.update_count);
}

test "StatusCache: reset clears cache" {
    var cache = StatusCache.init();

    cache.update(.{
        .fork_digest = .{ 0, 0, 0, 1 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 320,
    });
    try testing.expect(cache.isReady());

    cache.reset();
    try testing.expect(!cache.isReady());
    try testing.expect(cache.get() == null);
}
