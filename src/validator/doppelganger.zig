//! Doppelganger detection for the Validator Client.
//!
//! Checks whether our validators are already active on the network before
//! allowing signing to proceed. Prevents double-signing when two instances
//! of the same validator key are running simultaneously.
//!
//! TS equivalent: packages/validator/src/services/doppelgangerService.ts (DoppelgangerService)
//!
//! Algorithm (from TS):
//!   1. Before signing, all validators start as Unverified.
//!   2. Each epoch: call /eth/v1/validator/liveness/{epoch} for all indices.
//!   3. If any validator is seen live (is_live=true), it's a doppelganger → halt.
//!   4. After DEFAULT_REMAINING_DETECTION_EPOCHS clean epochs, mark as VerifiedSafe.
//!
//! Detection logic is fully implemented and wired into all signing paths.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const ValidatorLiveness = api_client.ValidatorLiveness;
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;
const SlashingProtectionDb = @import("slashing_protection_db.zig").SlashingProtectionDb;

const log = std.log.scoped(.doppelganger);

/// Number of clean epochs before we allow signing.
pub const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 1;
const REMAINING_EPOCHS_IF_DOPPELGANGER = std.math.maxInt(u64);
const REMAINING_EPOCHS_IF_SKIPPED: u64 = 0;

// ---------------------------------------------------------------------------
// Doppelganger status
// ---------------------------------------------------------------------------

pub const DoppelgangerStatus = enum {
    /// Validator has been verified safe — no other instance seen.
    verified_safe,
    /// Validator is registered but has not yet completed detection epochs.
    unverified,
    /// Another active instance was detected — halt signing.
    doppelganger_detected,
    /// Validator index not known yet — skip detection.
    unknown,
};

pub const DoppelgangerState = struct {
    /// Next epoch to check liveness for.
    next_epoch_to_check: u64,
    /// Remaining clean epochs required before verified_safe.
    remaining_epochs: u64,
    status: DoppelgangerStatus,
};

// ---------------------------------------------------------------------------
// DoppelgangerService
// ---------------------------------------------------------------------------

/// Per-validator state tracked by doppelganger service.
pub const DoppelgangerEntry = struct {
    pubkey: [48]u8,
    /// Validator index — null until resolved.
    index: ?u64,
    state: DoppelgangerState,
};

/// Optional shutdown callback: called when doppelganger is detected.
pub const ShutdownCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque) void,

    pub fn call(self: ShutdownCallback) void {
        self.fn_ptr(self.ctx);
    }
};

pub const DoppelgangerService = struct {
    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    metrics: *ValidatorMetrics,
    slashing_db: *const SlashingProtectionDb,
    mutex: std.Io.Mutex,
    /// Per-validator entries.
    entries: std.array_list.Managed(DoppelgangerEntry),
    /// Optional shutdown callback — called on doppelganger detection.
    shutdown_callback: ?ShutdownCallback,

    pub fn init(
        allocator: Allocator,
        io: Io,
        api: *BeaconApiClient,
        metrics: *ValidatorMetrics,
        slashing_db: *const SlashingProtectionDb,
    ) DoppelgangerService {
        var service: DoppelgangerService = .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .metrics = metrics,
            .slashing_db = slashing_db,
            .mutex = .init,
            .entries = std.array_list.Managed(DoppelgangerEntry).init(allocator),
            .shutdown_callback = null,
        };
        service.refreshMetrics();
        return service;
    }

    pub fn deinit(self: *DoppelgangerService) void {
        self.entries.deinit();
    }

    /// Set a shutdown callback to be called when doppelganger is detected.
    ///
    /// TS: DoppelgangerService.processShutdownCallback
    pub fn setShutdownCallback(self: *DoppelgangerService, cb: ShutdownCallback) void {
        self.shutdown_callback = cb;
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a validator pubkey for doppelganger monitoring.
    ///
    /// TS: DoppelgangerService.registerValidator(pubkeyHex)
    pub fn registerValidator(self: *DoppelgangerService, current_epoch: u64, pubkey: [48]u8) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        // Check for duplicate.
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return;
        }

        var remaining_epochs = if (current_epoch == 0)
            REMAINING_EPOCHS_IF_SKIPPED
        else
            DEFAULT_REMAINING_DETECTION_EPOCHS;
        const next_epoch_to_check = current_epoch + 1;

        if (remaining_epochs > 0) {
            const previous_epoch = current_epoch - 1;
            if (self.slashing_db.hasAttestedInEpoch(pubkey, previous_epoch)) {
                remaining_epochs = REMAINING_EPOCHS_IF_SKIPPED;
                log.info(
                    "doppelganger detection skipped for validator because restart was detected pubkey=0x{x} previous_epoch={d}",
                    .{ pubkey[0..4], previous_epoch },
                );
            } else {
                log.info(
                    "registered validator for doppelganger detection pubkey=0x{x} remaining_epochs={d} next_epoch_to_check={d}",
                    .{ pubkey[0..4], remaining_epochs, next_epoch_to_check },
                );
            }
        } else {
            log.info(
                "doppelganger detection skipped for validator initialized before or at genesis pubkey=0x{x} current_epoch={d}",
                .{ pubkey[0..4], current_epoch },
            );
        }

        try self.entries.append(.{
            .pubkey = pubkey,
            .index = null,
            .state = .{
                .next_epoch_to_check = next_epoch_to_check,
                .remaining_epochs = remaining_epochs,
                .status = if (remaining_epochs == 0) .verified_safe else .unverified,
            },
        });
        self.refreshMetricsLocked();
    }

    /// Remove a validator from doppelganger monitoring.
    pub fn unregisterValidator(self: *DoppelgangerService, pubkey: [48]u8) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                _ = self.entries.swapRemove(i);
                log.debug("unregistered validator from doppelganger detection pubkey=0x{s}", .{
                    std.fmt.bytesToHex(pubkey[0..4], .lower),
                });
                self.refreshMetricsLocked();
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Status check
    // -----------------------------------------------------------------------

    /// Returns true if the validator is allowed to sign (verified safe or protection disabled).
    ///
    /// TS: DoppelgangerService.getStatus(pubkeyHex) == VerifiedSafe
    pub fn isSigningAllowed(self: *const DoppelgangerService, pubkey: [48]u8) bool {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                return e.state.status == .verified_safe;
            }
        }
        return true; // unknown → allow (protection not configured for this key)
    }

    /// Returns the current status for a validator pubkey.
    pub fn getStatus(self: *const DoppelgangerService, pubkey: [48]u8) DoppelgangerStatus {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return e.state.status;
        }
        return .unknown;
    }

    pub fn updateIndex(self: *DoppelgangerService, pubkey: [48]u8, index: ?u64) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, &entry.pubkey, &pubkey)) continue;
            entry.index = index;
            return;
        }
    }

    // -----------------------------------------------------------------------
    // Epoch poll (clock callback)
    // -----------------------------------------------------------------------

    /// Called each epoch to check liveness and advance detection state.
    ///
    /// TS: DoppelgangerService.pollLiveness (clock.runEveryEpoch)
    pub fn onEpoch(self: *DoppelgangerService, io: Io, epoch: u64) void {
        self.pollLivenessForEpoch(io, epoch) catch |err| {
            log.err("pollLiveness epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    pub fn pollLivenessForEpoch(self: *DoppelgangerService, io: Io, current_epoch: u64) !void {
        if (current_epoch == 0) return;

        // Step 1: resolve pubkey → index for any entries that don't have one yet.
        const needs_resolution = self.hasUnresolvedEntries();

        if (needs_resolution) {
            try self.resolveIndices(io);
        }

        // Step 2: collect indices of validators still being monitored.
        var indices = std.array_list.Managed(u64).init(self.allocator);
        defer indices.deinit();

        try self.collectIndicesToCheck(&indices, current_epoch);
        if (indices.items.len == 0) return;

        const previous_epoch = current_epoch - 1;
        const previous_liveness = try self.api.getLiveness(io, previous_epoch, indices.items);
        defer self.allocator.free(previous_liveness);

        const current_liveness = try self.api.getLiveness(io, current_epoch, indices.items);
        defer self.allocator.free(current_liveness);

        if (self.applyLivenessCheck(current_epoch, previous_epoch, previous_liveness, current_liveness)) |cb| {
            log.err("triggering shutdown due to doppelganger detection", .{});
            cb.call();
            return error.DoppelgangerDetected;
        }
    }

    /// Resolve pubkey → validator index for entries that don't have one.
    ///
    /// Calls api.getValidatorIndices() with all unresolved pubkeys.
    fn resolveIndices(self: *DoppelgangerService, io: Io) !void {
        var unresolved = std.array_list.Managed([48]u8).init(self.allocator);
        defer unresolved.deinit();

        try self.collectUnresolvedPubkeys(&unresolved);
        if (unresolved.items.len == 0) return;

        log.debug("resolving {d} validator indices for doppelganger detection", .{unresolved.items.len});

        const results = self.api.getValidatorIndices(io, unresolved.items) catch |err| {
            log.warn("getValidatorIndices failed: {s} — will retry next epoch", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(results);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (results) |r| {
            for (self.entries.items) |*e| {
                if (std.mem.eql(u8, &e.pubkey, &r.pubkey)) {
                    e.index = r.index;
                    log.debug("resolved validator index={d} for doppelganger monitoring", .{r.index});
                    break;
                }
            }
        }
    }

    fn refreshMetrics(self: *const DoppelgangerService) void {
        var verified_safe: u64 = 0;
        var unverified: u64 = 0;
        var unknown: u64 = 0;
        var detected: u64 = 0;

        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        for (self.entries.items) |entry| {
            switch (entry.state.status) {
                .verified_safe => verified_safe += 1,
                .unverified => unverified += 1,
                .unknown => unknown += 1,
                .doppelganger_detected => detected += 1,
            }
        }
        mutex_ptr.unlock(self.io);

        self.metrics.setDoppelgangerStatusCount("VerifiedSafe", verified_safe);
        self.metrics.setDoppelgangerStatusCount("Unverified", unverified);
        self.metrics.setDoppelgangerStatusCount("Unknown", unknown);
        self.metrics.setDoppelgangerStatusCount("DoppelgangerDetected", detected);
    }

    fn hasUnresolvedEntries(self: *const DoppelgangerService) bool {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        for (self.entries.items) |e| {
            if (e.state.status == .unverified and e.state.remaining_epochs > 0 and e.index == null) {
                return true;
            }
        }
        return false;
    }

    fn collectUnresolvedPubkeys(
        self: *const DoppelgangerService,
        out: *std.array_list.Managed([48]u8),
    ) !void {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        for (self.entries.items) |e| {
            if (e.index == null and e.state.status == .unverified and e.state.remaining_epochs > 0) {
                try out.append(e.pubkey);
            }
        }
    }

    fn collectIndicesToCheck(
        self: *const DoppelgangerService,
        out: *std.array_list.Managed(u64),
        current_epoch: u64,
    ) !void {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        for (self.entries.items) |e| {
            if (e.state.status == .unverified and e.state.remaining_epochs > 0 and e.state.next_epoch_to_check <= current_epoch) {
                if (e.index) |idx| {
                    try out.append(idx);
                }
            }
        }
    }

    fn applyLivenessCheck(
        self: *DoppelgangerService,
        current_epoch: u64,
        previous_epoch: u64,
        previous_liveness: []const ValidatorLiveness,
        current_liveness: []const ValidatorLiveness,
    ) ?ShutdownCallback {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var detected = false;
        for (previous_liveness) |live| {
            if (!live.is_live) continue;
            for (self.entries.items) |*e| {
                if (e.index == live.index and e.state.status == .unverified and e.state.next_epoch_to_check <= previous_epoch) {
                    log.err("DOPPELGANGER DETECTED: validator index={d} is live on the network at epoch={d}!", .{
                        live.index,
                        previous_epoch,
                    });
                    detected = true;
                    break;
                }
            }
        }
        for (current_liveness) |live| {
            if (!live.is_live) continue;
            for (self.entries.items) |*e| {
                if (e.index == live.index and e.state.status == .unverified and e.state.next_epoch_to_check <= current_epoch) {
                    log.err("DOPPELGANGER DETECTED: validator index={d} is live on the network at epoch={d}!", .{
                        live.index,
                        current_epoch,
                    });
                    detected = true;
                    break;
                }
            }
        }

        if (detected) {
            for (self.entries.items) |*e| {
                if (e.state.status == .unverified) {
                    e.state.remaining_epochs = REMAINING_EPOCHS_IF_DOPPELGANGER;
                    e.state.status = .doppelganger_detected;
                }
            }
            const cb = self.shutdown_callback;
            self.refreshMetricsLocked();
            return cb;
        }

        for (previous_liveness) |live| {
            if (live.is_live) continue;
            for (self.entries.items) |*e| {
                if (e.index == live.index and e.state.status == .unverified and e.state.next_epoch_to_check <= previous_epoch) {
                    if (e.state.remaining_epochs > 0) {
                        e.state.remaining_epochs -= 1;
                    }
                    e.state.next_epoch_to_check = current_epoch;
                    self.metrics.incrDoppelgangerEpochsChecked();
                    if (e.state.remaining_epochs == 0) {
                        e.state.status = .verified_safe;
                        log.info("doppelganger detection complete pubkey=0x{x} epoch={d}", .{
                            e.pubkey[0..4],
                            current_epoch,
                        });
                    } else {
                        log.info("found no doppelganger pubkey=0x{x} remaining_epochs={d} next_epoch_to_check={d}", .{
                            e.pubkey[0..4],
                            e.state.remaining_epochs,
                            e.state.next_epoch_to_check,
                        });
                    }
                    break;
                }
            }
        }

        self.refreshMetricsLocked();
        return null;
    }

    fn refreshMetricsLocked(self: *const DoppelgangerService) void {
        var verified_safe: u64 = 0;
        var unverified: u64 = 0;
        var unknown: u64 = 0;
        var detected: u64 = 0;

        for (self.entries.items) |entry| {
            switch (entry.state.status) {
                .verified_safe => verified_safe += 1,
                .unverified => unverified += 1,
                .unknown => unknown += 1,
                .doppelganger_detected => detected += 1,
            }
        }

        self.metrics.setDoppelgangerStatusCount("VerifiedSafe", verified_safe);
        self.metrics.setDoppelgangerStatusCount("Unverified", unverified);
        self.metrics.setDoppelgangerStatusCount("Unknown", unknown);
        self.metrics.setDoppelgangerStatusCount("DoppelgangerDetected", detected);
    }
};

const testing = std.testing;

test "registerValidator skips doppelganger detection before or at genesis" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://127.0.0.1:5052");
    defer api.deinit();

    var metrics = ValidatorMetrics.initNoop();
    var service = DoppelgangerService.init(testing.allocator, testing.io, &api, &metrics, &db);
    defer service.deinit();

    const pubkey = [_]u8{0x11} ** 48;
    try service.registerValidator(0, pubkey);

    try testing.expectEqual(DoppelgangerStatus.verified_safe, service.getStatus(pubkey));
    try testing.expectEqual(@as(u64, 0), service.entries.items[0].state.remaining_epochs);
}

test "registerValidator skips doppelganger detection after restart attestation" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey = [_]u8{0x22} ** 48;
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 2, [_]u8{0xAA} ** 32));

    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://127.0.0.1:5052");
    defer api.deinit();

    var metrics = ValidatorMetrics.initNoop();
    var service = DoppelgangerService.init(testing.allocator, testing.io, &api, &metrics, &db);
    defer service.deinit();

    try service.registerValidator(3, pubkey);

    try testing.expectEqual(DoppelgangerStatus.verified_safe, service.getStatus(pubkey));
    try testing.expectEqual(@as(u64, 0), service.entries.items[0].state.remaining_epochs);
}

test "doppelganger metrics export status counts" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    var api = try BeaconApiClient.init(testing.allocator, testing.io, "http://127.0.0.1:5052");
    defer api.deinit();

    var metrics = try ValidatorMetrics.init(testing.allocator);
    defer metrics.deinit();

    var service = DoppelgangerService.init(testing.allocator, testing.io, &api, &metrics, &db);
    defer service.deinit();

    try service.registerValidator(1, [_]u8{0x33} ** 48);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try metrics.write(&out.writer);

    const buf = out.writer.buffered();
    try testing.expect(std.mem.indexOf(u8, buf, "vc_doppelganger_validator_status_count") != null);
    try testing.expect(std.mem.indexOf(u8, buf, "Unverified") != null);
    try testing.expect(std.mem.indexOf(u8, buf, "VerifiedSafe") != null);
    try testing.expect(std.mem.indexOf(u8, buf, "DoppelgangerDetected") != null);
}
