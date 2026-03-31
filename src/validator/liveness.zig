//! Validator liveness tracker for the Validator Client.
//!
//! Tracks whether each local validator successfully performed its duties each epoch.
//! Logs warnings for validators missing multiple consecutive epochs and exposes
//! per-validator participation metrics.
//!
//! TS equivalent: loosely maps to MetaDataService / duty tracking in TS Lodestar
//!
//! Metrics exposed:
//!   - `validator_attestation_hit_rate`  (per validator, rolling window)
//!   - `validator_sync_participation_rate` (per validator, rolling window)

const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.validator_liveness);

/// Number of epochs to retain in the rolling history window.
const HISTORY_WINDOW: usize = 10;

/// Warn if a validator misses this many consecutive epochs.
const CONSECUTIVE_MISS_WARN_THRESHOLD: u64 = 2;

// ---------------------------------------------------------------------------
// Per-validator liveness state
// ---------------------------------------------------------------------------

pub const DutyKind = enum { attestation, sync_committee };

pub const EpochDutyResult = struct {
    epoch: u64,
    performed: bool,
};

pub const ValidatorLivenessEntry = struct {
    pubkey: [48]u8,
    /// Rolling window of attestation results.
    attestation_history: [HISTORY_WINDOW]?EpochDutyResult,
    att_history_head: usize,
    /// Rolling window of sync committee results.
    sync_history: [HISTORY_WINDOW]?EpochDutyResult,
    sync_history_head: usize,
    /// Number of consecutive missed attestation epochs.
    consecutive_missed_attestations: u64,
    /// Number of consecutive missed sync epochs.
    consecutive_missed_sync: u64,

    pub fn init(pubkey: [48]u8) ValidatorLivenessEntry {
        return .{
            .pubkey = pubkey,
            .attestation_history = [_]?EpochDutyResult{null} ** HISTORY_WINDOW,
            .att_history_head = 0,
            .sync_history = [_]?EpochDutyResult{null} ** HISTORY_WINDOW,
            .sync_history_head = 0,
            .consecutive_missed_attestations = 0,
            .consecutive_missed_sync = 0,
        };
    }

    /// Record attestation duty outcome for an epoch.
    pub fn recordAttestation(self: *ValidatorLivenessEntry, epoch: u64, performed: bool) void {
        self.attestation_history[self.att_history_head] = .{ .epoch = epoch, .performed = performed };
        self.att_history_head = (self.att_history_head + 1) % HISTORY_WINDOW;

        if (performed) {
            self.consecutive_missed_attestations = 0;
        } else {
            self.consecutive_missed_attestations += 1;
        }
    }

    /// Record sync committee duty outcome for an epoch.
    pub fn recordSync(self: *ValidatorLivenessEntry, epoch: u64, performed: bool) void {
        self.sync_history[self.sync_history_head] = .{ .epoch = epoch, .performed = performed };
        self.sync_history_head = (self.sync_history_head + 1) % HISTORY_WINDOW;

        if (performed) {
            self.consecutive_missed_sync = 0;
        } else {
            self.consecutive_missed_sync += 1;
        }
    }

    /// Compute attestation hit rate over the history window (0.0..1.0).
    pub fn attestationHitRate(self: *const ValidatorLivenessEntry) f64 {
        return hitRate(&self.attestation_history);
    }

    /// Compute sync participation rate over the history window (0.0..1.0).
    pub fn syncParticipationRate(self: *const ValidatorLivenessEntry) f64 {
        return hitRate(&self.sync_history);
    }
};

fn hitRate(history: *const [HISTORY_WINDOW]?EpochDutyResult) f64 {
    var total: u64 = 0;
    var hits: u64 = 0;
    for (history) |maybe| {
        if (maybe) |r| {
            total += 1;
            if (r.performed) hits += 1;
        }
    }
    if (total == 0) return 1.0; // no data → assume healthy
    return @as(f64, @floatFromInt(hits)) / @as(f64, @floatFromInt(total));
}

// ---------------------------------------------------------------------------
// LivenessTracker
// ---------------------------------------------------------------------------

pub const LivenessTracker = struct {
    allocator: Allocator,
    entries: std.ArrayList(ValidatorLivenessEntry),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: Allocator) LivenessTracker {
        return .{
            .allocator = allocator,
            .entries = std.ArrayList(ValidatorLivenessEntry).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *LivenessTracker) void {
        self.entries.deinit();
    }

    /// Register a validator for liveness tracking.
    ///
    /// Idempotent — no-op if already registered.
    pub fn register(self: *LivenessTracker, pubkey: [48]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return;
        }
        self.entries.append(ValidatorLivenessEntry.init(pubkey)) catch |err| {
            log.err("register liveness entry OOM: {s}", .{@errorName(err)});
        };
    }

    /// Remove a validator from liveness tracking.
    pub fn unregister(self: *LivenessTracker, pubkey: [48]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                _ = self.entries.swapRemove(i);
                return;
            }
        }
    }

    /// Record that a validator performed (or missed) an attestation duty.
    ///
    /// TS: MetaDataService tracks attestation outcome per epoch.
    pub fn recordAttestationDuty(self: *LivenessTracker, pubkey: [48]u8, epoch: u64, performed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                e.recordAttestation(epoch, performed);

                if (!performed) {
                    if (e.consecutive_missed_attestations >= CONSECUTIVE_MISS_WARN_THRESHOLD) {
                        log.warn(
                            "validator 0x{} missed attestation for {d} consecutive epoch(s) (epoch={d})",
                            .{ std.fmt.fmtSliceHexLower(pubkey[0..4]), e.consecutive_missed_attestations, epoch },
                        );
                    }
                } else {
                    log.debug("validator 0x{} attested epoch={d}", .{
                        std.fmt.fmtSliceHexLower(pubkey[0..4]),
                        epoch,
                    });
                }

                // Log metrics.
                log.debug(
                    "attestation_hit_rate validator=0x{} rate={d:.3}",
                    .{ std.fmt.fmtSliceHexLower(pubkey[0..4]), e.attestationHitRate() },
                );
                return;
            }
        }
        log.warn("recordAttestationDuty: unknown validator 0x{}", .{std.fmt.fmtSliceHexLower(pubkey[0..4])});
    }

    /// Record that a validator performed (or missed) a sync committee duty.
    ///
    /// TS: SyncCommitteeService tracks participation per epoch.
    pub fn recordSyncDuty(self: *LivenessTracker, pubkey: [48]u8, epoch: u64, performed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                e.recordSync(epoch, performed);

                if (!performed) {
                    if (e.consecutive_missed_sync >= CONSECUTIVE_MISS_WARN_THRESHOLD) {
                        log.warn(
                            "validator 0x{} missed sync committee duty for {d} consecutive epoch(s) (epoch={d})",
                            .{ std.fmt.fmtSliceHexLower(pubkey[0..4]), e.consecutive_missed_sync, epoch },
                        );
                    }
                }

                log.debug(
                    "sync_participation_rate validator=0x{} rate={d:.3}",
                    .{ std.fmt.fmtSliceHexLower(pubkey[0..4]), e.syncParticipationRate() },
                );
                return;
            }
        }
        log.warn("recordSyncDuty: unknown validator 0x{}", .{std.fmt.fmtSliceHexLower(pubkey[0..4])});
    }

    /// Log a summary of all tracked validator liveness.
    ///
    /// Called at session end or periodically.
    pub fn logSummary(self: *LivenessTracker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items) |e| {
            log.info(
                "liveness summary validator=0x{} att_rate={d:.3} sync_rate={d:.3} missed_att_streak={d} missed_sync_streak={d}",
                .{
                    std.fmt.fmtSliceHexLower(e.pubkey[0..4]),
                    e.attestationHitRate(),
                    e.syncParticipationRate(),
                    e.consecutive_missed_attestations,
                    e.consecutive_missed_sync,
                },
            );
        }
    }

    /// Log an epoch effectiveness summary line.
    ///
    /// Emitted at each epoch boundary by the validator's index tracker callback.
    ///
    /// Example output:
    ///   [info] [validator] Epoch 12345 summary: 2 validators active,
    ///     2/2 attestations (100.0%), 0/0 blocks proposed, 0/0 sync committee (100.0%)
    ///
    /// TS: ValidatorMonitor.scrapeSlot logs similar per-epoch metrics.
    pub fn logEpochSummary(
        self: *LivenessTracker,
        epoch: u64,
        total_validators: usize,
        missed_blocks: u64,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total_att: u64 = 0;
        var hit_att: u64 = 0;
        var total_sync: u64 = 0;
        var hit_sync: u64 = 0;
        var missed_att_validators: u64 = 0;

        for (self.entries.items) |*e| {
            // Check if this validator had an attestation result for this epoch.
            var att_this_epoch: ?bool = null;
            var sync_this_epoch: ?bool = null;

            // Scan history window for this epoch.
            for (e.attestation_history) |maybe| {
                if (maybe) |r| {
                    if (r.epoch == epoch) {
                        att_this_epoch = r.performed;
                        break;
                    }
                }
            }
            for (e.sync_history) |maybe| {
                if (maybe) |r| {
                    if (r.epoch == epoch) {
                        sync_this_epoch = r.performed;
                        break;
                    }
                }
            }

            if (att_this_epoch) |performed| {
                total_att += 1;
                if (performed) hit_att += 1 else missed_att_validators += 1;
            }
            if (sync_this_epoch) |performed| {
                total_sync += 1;
                if (performed) hit_sync += 1;
            }
        }

        const att_pct: f64 = if (total_att > 0)
            @as(f64, @floatFromInt(hit_att)) / @as(f64, @floatFromInt(total_att)) * 100.0
        else
            100.0;
        const sync_pct: f64 = if (total_sync > 0)
            @as(f64, @floatFromInt(hit_sync)) / @as(f64, @floatFromInt(total_sync)) * 100.0
        else
            100.0;

        log.info(
            "Epoch {d} summary: {d} validators active, {d}/{d} attestations ({d:.1}%), " ++
                "{d} blocks missed, {d}/{d} sync committee ({d:.1}%)",
            .{
                epoch,
                total_validators,
                hit_att,
                total_att,
                att_pct,
                missed_blocks,
                hit_sync,
                total_sync,
                sync_pct,
            },
        );
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "LivenessTracker: attestation hit rate" {
    var tracker = LivenessTracker.init(testing.allocator);
    defer tracker.deinit();

    const pk = [_]u8{0x01} ** 48;
    tracker.register(pk);

    // 3 hits, 1 miss → 75%.
    tracker.recordAttestationDuty(pk, 1, true);
    tracker.recordAttestationDuty(pk, 2, true);
    tracker.recordAttestationDuty(pk, 3, true);
    tracker.recordAttestationDuty(pk, 4, false);

    const entry = tracker.entries.items[0];
    const rate = entry.attestationHitRate();
    try testing.expectApproxEqAbs(0.75, rate, 0.01);
    try testing.expectEqual(@as(u64, 1), entry.consecutive_missed_attestations);
}

test "LivenessTracker: consecutive miss resets on success" {
    var tracker = LivenessTracker.init(testing.allocator);
    defer tracker.deinit();

    const pk = [_]u8{0x02} ** 48;
    tracker.register(pk);

    tracker.recordAttestationDuty(pk, 1, false);
    tracker.recordAttestationDuty(pk, 2, false);
    tracker.recordAttestationDuty(pk, 3, true); // success resets streak

    const entry = tracker.entries.items[0];
    try testing.expectEqual(@as(u64, 0), entry.consecutive_missed_attestations);
}

test "LivenessTracker: no data returns 1.0 hit rate" {
    var tracker = LivenessTracker.init(testing.allocator);
    defer tracker.deinit();

    const pk = [_]u8{0x03} ** 48;
    tracker.register(pk);

    const entry = tracker.entries.items[0];
    try testing.expectApproxEqAbs(1.0, entry.attestationHitRate(), 0.001);
}
