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
const validator_types = @import("types.zig");
const ValidatorStatus = validator_types.ValidatorStatus;

const log = std.log.scoped(.index_tracker);

// ---------------------------------------------------------------------------
// IndexEntry
// ---------------------------------------------------------------------------

const IndexEntry = struct {
    pubkey: [48]u8,
    /// Validator index on the beacon chain (null until resolved).
    index: ?u64,
    status: ValidatorStatus,
};

pub const ResolvedIndexEntry = struct {
    pubkey: [48]u8,
    index: u64,
    status: ValidatorStatus,
};

// ---------------------------------------------------------------------------
// IndexTracker
// ---------------------------------------------------------------------------

pub const IndexTracker = struct {
    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    /// All tracked entries.
    entries: std.array_list.Managed(IndexEntry),
    /// Mutex for thread-safe access from multiple services.
    mutex: std.Io.Mutex,

    // -----------------------------------------------------------------------
    // Init / deinit
    // -----------------------------------------------------------------------

    pub fn init(allocator: Allocator, io: Io, api: *BeaconApiClient) IndexTracker {
        return .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .entries = std.array_list.Managed(IndexEntry).init(allocator),
            .mutex = .init,
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
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return;
        }
        self.entries.append(.{
            .pubkey = pubkey,
            .index = null,
            .status = .unknown,
        }) catch |err| {
            log.err("trackPubkey: OOM {s}", .{@errorName(err)});
        };
        log.debug("tracking pubkey 0x{x}", .{pubkey[0..4]});
    }

    /// Remove a pubkey from tracking (e.g. key deleted via keymanager API).
    pub fn untrackPubkey(self: *IndexTracker, pubkey: [48]u8) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

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
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return e.index;
        }
        return null;
    }

    pub fn allResolvedEntries(self: *IndexTracker, allocator: Allocator) ![]ResolvedIndexEntry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.index != null) count += 1;
        }

        const result = try allocator.alloc(ResolvedIndexEntry, count);
        var out_idx: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.index) |idx| {
                result[out_idx] = .{
                    .pubkey = entry.pubkey,
                    .index = idx,
                    .status = entry.status,
                };
                out_idx += 1;
            }
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Resolution
    // -----------------------------------------------------------------------

    /// Refresh indices and lifecycle statuses for all tracked pubkeys via the
    /// beacon node API.
    ///
    /// This is intentionally not "unresolved only". The validator runtime uses
    /// BN-reported status to decide who is duty-eligible, so pending/exiting/
    /// withdrawn transitions must be observed after initial index resolution too.
    ///
    /// TS: IndicesService.pollValidatorIndices()
    pub fn resolveIndices(self: *IndexTracker, io: Io) !void {
        // Snapshot all tracked pubkeys so runtime key add/remove does not race
        // the outbound BN request.
        var tracked = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);

            var list = std.array_list.Managed([48]u8).init(self.allocator);
            errdefer list.deinit();

            for (self.entries.items) |e| {
                try list.append(e.pubkey);
            }
            break :blk list;
        };
        defer tracked.deinit();

        if (tracked.items.len == 0) return;

        log.debug("refreshing {d} validator indices", .{tracked.items.len});

        const results = self.api.getValidatorIndices(io, tracked.items) catch |err| {
            log.warn("getValidatorIndices failed: {s} — will retry next epoch", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(results);

        var updated_count: usize = 0;

        // Apply refreshed indices and statuses under lock.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (results) |r| {
            for (self.entries.items) |*e| {
                if (std.mem.eql(u8, &e.pubkey, &r.pubkey)) {
                    const status = validator_types.parseValidatorStatus(r.statusStr());
                    if (e.index == null or e.index.? != r.index or e.status != status) {
                        e.index = r.index;
                        e.status = status;
                        updated_count += 1;
                        log.debug("validator index status updated pubkey=0x{s} index={d} status={s}", .{
                            std.fmt.bytesToHex(e.pubkey[0..4], .lower),
                            r.index,
                            @tagName(status),
                        });
                    }
                    break;
                }
            }
        }

        if (updated_count > 0) {
            log.debug("updated {d} validator index/status entries (total tracked={d})", .{
                updated_count,
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
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, testing.io, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x01} ** 48;
    tracker.trackPubkey(pk);

    // Index not yet resolved.
    try testing.expectEqual(@as(?u64, null), tracker.getIndex(pk));
}

test "IndexTracker: untrackPubkey" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, testing.io, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x02} ** 48;
    tracker.trackPubkey(pk);
    tracker.untrackPubkey(pk);

    // Should no longer be tracked.
    try testing.expectEqual(@as(?u64, null), tracker.getIndex(pk));
    try testing.expectEqual(@as(usize, 0), tracker.entries.items.len);
}

test "IndexTracker: duplicate trackPubkey is idempotent" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();

    var tracker = IndexTracker.init(testing.allocator, testing.io, &api);
    defer tracker.deinit();

    const pk = [_]u8{0x03} ** 48;
    tracker.trackPubkey(pk);
    tracker.trackPubkey(pk); // second call — should be no-op
    try testing.expectEqual(@as(usize, 1), tracker.entries.items.len);
}
