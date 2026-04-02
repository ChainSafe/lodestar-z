//! Syncing status tracker for the Validator Client.
//!
//! Monitors the Beacon Node's readiness for validator duties and fails closed
//! when the node is syncing, optimistic, EL-offline, or unreachable.
//!
//! TS equivalent: packages/validator/src/services/syncingStatusTracker.ts

const std = @import("std");
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const NodeSyncingResponse = api_client.NodeSyncingResponse;
const metrics_mod = @import("metrics.zig");
const BeaconHealth = metrics_mod.BeaconHealth;
const ValidatorMetrics = metrics_mod.ValidatorMetrics;
const time = @import("time.zig");

const log = std.log.scoped(.syncing_tracker);

pub const SyncingTracker = struct {
    pub const ResyncedCallback = struct {
        ctx: *anyopaque,
        fn_ptr: *const fn (ctx: *anyopaque, slot: u64, io: Io) void,

        pub fn call(self: ResyncedCallback, slot: u64, io: Io) void {
            self.fn_ptr(self.ctx, slot, io);
        }
    };

    api: *BeaconApiClient,
    metrics: *ValidatorMetrics,

    /// True when the BN is ready for validator duties.
    synced: std.atomic.Value(bool),
    /// Last poll resulted in an error (BN unreachable).
    last_poll_error: std.atomic.Value(bool),
    /// Monotonic timestamp (ns) of last successful poll.
    last_success_ns: std.atomic.Value(u64),
    resynced_callbacks: [8]ResyncedCallback,
    resynced_callback_count: usize,

    pub fn init(api: *BeaconApiClient, metrics: *ValidatorMetrics) SyncingTracker {
        var tracker: SyncingTracker = .{
            .api = api,
            .metrics = metrics,
            // Start fail-closed until the first successful readiness poll.
            .synced = std.atomic.Value(bool).init(false),
            .last_poll_error = std.atomic.Value(bool).init(false),
            .last_success_ns = std.atomic.Value(u64).init(0),
            .resynced_callbacks = undefined,
            .resynced_callback_count = 0,
        };
        tracker.metrics.setBeaconHealth(.syncing);
        return tracker;
    }

    pub fn onResynced(self: *SyncingTracker, cb: ResyncedCallback) void {
        self.resynced_callbacks[self.resynced_callback_count] = cb;
        self.resynced_callback_count += 1;
    }

    /// Returns true when the BN is ready for validator duties.
    pub fn isSynced(self: *const SyncingTracker) bool {
        return self.synced.load(.acquire);
    }

    pub fn poll(self: *SyncingTracker, io: Io, slot: u64) void {
        const resp = self.api.getNodeSyncing(io) catch |err| {
            self.applyPollError(err);
            return;
        };

        self.applySyncStatus(io, slot, resp);
    }

    pub fn onSlot(self: *SyncingTracker, io: Io, slot: u64) void {
        self.poll(io, slot);
    }

    fn evaluateStatus(resp: NodeSyncingResponse) BeaconHealth {
        if (!resp.is_syncing and !resp.is_optimistic and !resp.el_offline) return .ready;
        return .syncing;
    }

    fn applyPollError(self: *SyncingTracker, err: anyerror) void {
        const was_synced = self.synced.load(.acquire);
        const had_poll_error = self.last_poll_error.load(.acquire);

        self.last_poll_error.store(true, .release);
        self.synced.store(false, .release);
        self.metrics.setBeaconHealth(.err);

        if (was_synced or !had_poll_error) {
            log.warn("failed to poll BN sync status: {s} — pausing validator duties", .{@errorName(err)});
        }
    }

    fn applySyncStatus(self: *SyncingTracker, io: Io, slot: u64, resp: NodeSyncingResponse) void {
        const was_synced = self.synced.load(.acquire);
        const had_poll_error = self.last_poll_error.load(.acquire);
        const health = evaluateStatus(resp);
        const now_synced = health == .ready;

        self.last_poll_error.store(false, .release);
        self.last_success_ns.store(time.awakeNanoseconds(io), .release);
        self.synced.store(now_synced, .release);
        self.metrics.setBeaconHealth(health);

        if (was_synced and !now_synced) {
            log.warn(
                "beacon node not ready — pausing validator duties (is_syncing={} sync_distance={d} is_optimistic={} el_offline={} head_slot={d})",
                .{ resp.is_syncing, resp.sync_distance, resp.is_optimistic, resp.el_offline, resp.head_slot },
            );
        } else if ((!was_synced or had_poll_error) and now_synced) {
            log.info("beacon node ready — resuming validator duties (head_slot={d})", .{resp.head_slot});
            for (self.resynced_callbacks[0..self.resynced_callback_count]) |cb| {
                cb.call(slot, io);
            }
        }
    }
};

const testing = std.testing;

test "SyncingTracker: starts fail-closed" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();
    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();

    const tracker = SyncingTracker.init(&api, &metrics);
    try testing.expect(!tracker.isSynced());
    try testing.expectEqual(@as(u64, @intFromEnum(BeaconHealth.syncing)), tracker.metrics.beacon_health.impl.value);
}

test "SyncingTracker: isSynced reflects atomic store" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();
    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();
    var tracker = SyncingTracker.init(&api, &metrics);

    tracker.synced.store(false, .release);
    try testing.expect(!tracker.isSynced());

    tracker.synced.store(true, .release);
    try testing.expect(tracker.isSynced());
}

test "SyncingTracker: optimistic node is not ready" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();
    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();
    var tracker = SyncingTracker.init(&api, &metrics);

    tracker.applySyncStatus(testing.io, 0, .{
        .head_slot = 123,
        .sync_distance = 0,
        .is_syncing = false,
        .is_optimistic = true,
        .el_offline = false,
    });

    try testing.expect(!tracker.isSynced());
    try testing.expectEqual(@as(u64, @intFromEnum(BeaconHealth.syncing)), tracker.metrics.beacon_health.impl.value);
}

test "SyncingTracker: EL offline node is not ready" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();
    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();
    var tracker = SyncingTracker.init(&api, &metrics);

    tracker.applySyncStatus(testing.io, 0, .{
        .head_slot = 123,
        .sync_distance = 0,
        .is_syncing = false,
        .is_optimistic = false,
        .el_offline = true,
    });

    try testing.expect(!tracker.isSynced());
    try testing.expectEqual(@as(u64, @intFromEnum(BeaconHealth.syncing)), tracker.metrics.beacon_health.impl.value);
}

test "SyncingTracker: poll error fails closed" {
    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://localhost:5052");
    defer api.deinit();
    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();
    var tracker = SyncingTracker.init(&api, &metrics);

    tracker.synced.store(true, .release);
    tracker.applyPollError(error.ConnectionRefused);

    try testing.expect(!tracker.isSynced());
    try testing.expect(tracker.last_poll_error.load(.acquire));
    try testing.expectEqual(@as(u64, @intFromEnum(BeaconHealth.err)), tracker.metrics.beacon_health.impl.value);
}
