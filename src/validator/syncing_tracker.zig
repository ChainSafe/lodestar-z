//! Syncing status tracker for the Validator Client.
//!
//! Monitors the Beacon Node's sync status and pauses signing operations when
//! the node is syncing with a large sync distance. Prevents signing with stale
//! state data which could result in slashable attestations.
//!
//! TS equivalent: packages/validator/src/services/syncingStatusTracker.ts (SyncingStatusTracker)
//!
//! Algorithm:
//!   1. Poll GET /eth/v1/node/syncing each slot (or every ~6 seconds).
//!   2. If is_syncing=true AND sync_distance > SYNCING_THRESHOLD: set paused=true.
//!   3. If is_syncing=false OR sync_distance <= SYNCING_THRESHOLD: set paused=false.
//!   4. On transition paused→resumed: log "beacon node synced — resuming duties".
//!   5. On transition resumed→paused: log "beacon node syncing — pausing validator duties".
//!
//! Services check isSynced() before producing duties; if false they skip the slot.
//!
//! Safety: This is CRITICAL — attesting to a block on a stale/non-canonical chain
//! can double-vote and produce slashable attestations.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const BeaconApiClient = @import("api_client.zig").BeaconApiClient;

const log = std.log.scoped(.syncing_tracker);

/// Slots of sync distance above which we consider the node out-of-sync.
///
/// TS: SYNC_TOLERANCE_EPOCHS = 0 (strict) but many impls use 4–8 slots.
/// We use 5 slots as a reasonable default.
pub const SYNCING_THRESHOLD: u64 = 5;

// ---------------------------------------------------------------------------
// SyncingStatusTracker
// ---------------------------------------------------------------------------

pub const SyncingTracker = struct {
    allocator: Allocator,
    api: *BeaconApiClient,

    /// True when the BN is synced enough for signing.
    synced: std.atomic.Value(bool),
    /// Last poll resulted in an error (BN unreachable).
    last_poll_error: std.atomic.Value(bool),
    /// Monotonic timestamp (ns) of last successful poll.
    last_success_ns: std.atomic.Value(u64),

    pub fn init(allocator: Allocator, api: *BeaconApiClient) SyncingTracker {
        return .{
            .allocator = allocator,
            .api = api,
            // Start optimistic: if BN is unreachable on the first poll we'll find out.
            .synced = std.atomic.Value(bool).init(true),
            .last_poll_error = std.atomic.Value(bool).init(false),
            .last_success_ns = std.atomic.Value(u64).init(0),
        };
    }

    /// Returns true when the BN is synced enough for validator duties.
    ///
    /// Called by every service before signing. If false, the service skips
    /// the current slot/epoch to avoid signing with stale state.
    ///
    /// TS: SyncingStatusTracker.syncingStatus == "synced"
    pub fn isSynced(self: *const SyncingTracker) bool {
        return self.synced.load(.acquire);
    }

    /// Poll the BN sync status and update internal state.
    ///
    /// Called from the slot clock callback in validator.zig.
    ///
    /// TS: SyncingStatusTracker.pollSyncingStatus()
    pub fn poll(self: *SyncingTracker, io: Io) void {
        const was_synced = self.synced.load(.acquire);

        const resp = self.api.getNodeSyncing(io) catch |err| {
            log.warn("failed to poll BN sync status: {s}", .{@errorName(err)});
            self.last_poll_error.store(true, .release);
            // Don't change synced state on transient network error — keep previous.
            return;
        };

        self.last_poll_error.store(false, .release);
        self.last_success_ns.store(@intCast(std.time.nanoTimestamp()), .release);

        // Determine if we're synced enough to sign.
        const now_synced = !resp.is_syncing or resp.sync_distance <= SYNCING_THRESHOLD;

        self.synced.store(now_synced, .release);

        // Log state transitions.
        if (was_synced and !now_synced) {
            log.warn(
                "beacon node syncing — pausing validator duties (sync_distance={d} head_slot={d})",
                .{ resp.sync_distance, resp.head_slot },
            );
        } else if (!was_synced and now_synced) {
            log.info(
                "beacon node synced — resuming validator duties (head_slot={d})",
                .{resp.head_slot},
            );
        }
    }

    /// Called at each slot boundary.
    ///
    /// TS: SyncingStatusTracker runs via clockService.runEverySlot
    pub fn onSlot(self: *SyncingTracker, io: Io, slot: u64) void {
        _ = slot;
        self.poll(io);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "SyncingTracker: starts synced" {
    var api = BeaconApiClient.init(testing.allocator, "http://localhost:5052");
    defer api.deinit();
    const tracker = SyncingTracker.init(testing.allocator, &api);
    try testing.expect(tracker.isSynced());
}

test "SyncingTracker: isSynced reflects atomic store" {
    var api = BeaconApiClient.init(testing.allocator, "http://localhost:5052");
    defer api.deinit();
    var tracker = SyncingTracker.init(testing.allocator, &api);

    tracker.synced.store(false, .release);
    try testing.expect(!tracker.isSynced());

    tracker.synced.store(true, .release);
    try testing.expect(tracker.isSynced());
}
