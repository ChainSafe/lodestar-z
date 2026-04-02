//! Validator index tracker for the Validator Client.
//!
//! Maintains the mapping from BLS public key → beacon chain validator index.
//! Duties are assigned by validator index, so the VC must resolve its pubkeys
//! before it can fetch duties.
//!
//! TS equivalent: packages/validator/src/services/indices.ts (IndicesService)
//!
//! Algorithm:
//!   1. On startup: call resolveIndices() for all tracked pubkeys.
//!   2. On each epoch boundary: call onEpoch() to catch newly activated validators.
//!   3. Services call getIndex(pubkey) to look up the index for a given key.
//!
//! Resolves via POST /eth/v1/beacon/states/head/validators.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const mutex_mod = @import("mutex.zig");

const log = std.log.scoped(.index_tracker);

// ---------------------------------------------------------------------------
// IndexEntry
// ---------------------------------------------------------------------------

const IndexEntry = struct {
    pubkey: [48]u8,
    /// Validator index on the beacon chain (null until resolved).
    index: ?u64,
};

// ---------------------------------------------------------------------------
// IndexTracker
// ---------------------------------------------------------------------------

pub const IndexTracker = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    /// All tracked entries.
    entries: std.array_list.Managed(IndexEntry),
    /// Mutex for thread-safe access from multiple services.
    mutex: mutex_mod.Mutex,

    // -----------------------------------------------------------------------
    // Init / deinit
    // -----------------------------------------------------------------------

    pub fn init(allocator: Allocator, api: *BeaconApiClient) IndexTracker {
        return .{
            .allocator = allocator,
            .api = api,
            .entries = std.array_list.Managed(IndexEntry).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *IndexTracker) void {
        self.entries.deinit();
    }

    // -----------------------------------------------------------------------
    // Pubkey tracking
    // -----------------------------------------------------------------------

    /// Add a pubkey to track.
    ///
    /// No-op if already tracked.
    ///
    /// TS: IndicesService.pollValidatorIndices adds newly discovered keys
    pub fn trackPubkey(self: *IndexTracker, pubkey: [48]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return;
        }
        self.entries.append(.{
            .pubkey = pubkey,
            .index = null,
        }) catch |err| {
            log.err("trackPubkey: OOM {s}", .{@errorName(err)});
        };
        log.debug("tracking pubkey 0x{x}", .{pubkey[0..4]});
    }

    /// Remove a pubkey from tracking (e.g. key deleted via keymanager API).
    pub fn untrackPubkey(self: *IndexTracker, pubkey: [48]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                _ = self.entries.swapRemove(i);
                log.debug("untracked pubkey 0x{x}", .{pubkey[0..4]});
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Index lookup
    // -----------------------------------------------------------------------

    /// Get the validator index for a given pubkey.
    ///
    /// Returns null if the pubkey is not tracked or its index has not yet been
    /// resolved. Call resolveIndices() first.
    ///
    /// TS: indicesService.getValidatorIndex(pubkeyHex)
    pub fn getIndex(self: *IndexTracker, pubkey: [48]u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return e.index;
        }
        return null;
    }

    /// Get all currently resolved (pubkey, index) pairs.
    ///
    /// Caller must free the returned slice.
    pub fn allResolvedIndices(self: *IndexTracker, allocator: Allocator) ![]u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = std.array_list.Managed(u64).init(allocator);
        errdefer result.deinit();

        for (self.entries.items) |e| {
            if (e.index) |idx| try result.append(idx);
        }
        return result.toOwnedSlice();
    }

    // -----------------------------------------------------------------------
    // Resolution
    // -----------------------------------------------------------------------

    /// Resolve indices for all tracked pubkeys via the beacon node API.
    ///
    /// Calls POST /eth/v1/beacon/states/head/validators with all pubkeys that
    /// don't yet have a resolved index. Resolved indices are stored in the
    /// entries map and also applied to the validator store.
    ///
    /// TS: IndicesService.pollValidatorIndices()
    pub fn resolveIndices(self: *IndexTracker, io: Io) !void {
        // Collect unresolved pubkeys (under lock).
        var unresolved = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();

            var list = std.array_list.Managed([48]u8).init(self.allocator);
            errdefer list.deinit();

            for (self.entries.items) |e| {
                if (e.index == null) try list.append(e.pubkey);
            }
            break :blk list;
        };
        defer unresolved.deinit();

        if (unresolved.items.len == 0) return;

        log.debug("resolving {d} validator indices", .{unresolved.items.len});

        const results = self.api.getValidatorIndices(io, unresolved.items) catch |err| {
            log.warn("getValidatorIndices failed: {s} — will retry next epoch", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(results);

        var resolved_count: usize = 0;

        // Apply resolved indices (under lock).
        self.mutex.lock();
        defer self.mutex.unlock();

        for (results) |r| {
            for (self.entries.items) |*e| {
                if (std.mem.eql(u8, &e.pubkey, &r.pubkey)) {
                    if (e.index == null) {
                        e.index = r.index;
                        resolved_count += 1;
                        log.info("validator index resolved pubkey=0x{s} index={d}", .{
                            std.fmt.bytesToHex(e.pubkey[0..4], .lower),
                            r.index,
                        });
                    }
                    break;
                }
            }
        }

        if (resolved_count > 0) {
            log.info("resolved {d} new validator indices (total tracked={d})", .{
                resolved_count,
                self.entries.items.len,
            });
        }
    }

    /// Called on each epoch boundary — re-resolves to catch newly activated validators.
    ///
    /// Also re-resolves previously resolved validators in case their status changed
    /// (e.g. exits, slashing). This is cheaper than it sounds since the BN
    /// will just return the same index for active validators.
    ///
    /// TS: IndicesService.pollValidatorIndices (runs every epoch)
    pub fn onEpoch(self: *IndexTracker, io: Io, epoch: u64) void {
        log.debug("index tracker epoch={d}: resolving indices", .{epoch});
        self.resolveIndices(io) catch |err| {
            log.err("resolveIndices epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "IndexTracker: trackPubkey and getIndex" {
    var api = BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x01} ** 48;
    tracker.trackPubkey(pk);

    // Index not yet resolved.
    try testing.expectEqual(@as(?u64, null), tracker.getIndex(pk));
}

test "IndexTracker: untrackPubkey" {
    var api = BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x02} ** 48;
    tracker.trackPubkey(pk);
    tracker.untrackPubkey(pk);

    // Should no longer be tracked.
    try testing.expectEqual(@as(?u64, null), tracker.getIndex(pk));
    try testing.expectEqual(@as(usize, 0), tracker.entries.items.len);
}

test "IndexTracker: duplicate trackPubkey is idempotent" {
    var api = BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x03} ** 48;
    tracker.trackPubkey(pk);
    tracker.trackPubkey(pk); // second call — should be no-op
    try testing.expectEqual(@as(usize, 1), tracker.entries.items.len);
}
