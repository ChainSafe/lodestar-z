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

const BeaconApiClient = @import("api_client.zig").BeaconApiClient;

const log = std.log.scoped(.doppelganger);

/// Number of clean epochs before we allow signing.
pub const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 1;

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
    api: *BeaconApiClient,
    /// Per-validator entries.
    entries: std.array_list.Managed(DoppelgangerEntry),
    /// Optional shutdown callback — called on doppelganger detection.
    shutdown_callback: ?ShutdownCallback,

    pub fn init(allocator: Allocator, api: *BeaconApiClient) DoppelgangerService {
        return .{
            .allocator = allocator,
            .api = api,
            .entries = std.array_list.Managed(DoppelgangerEntry).init(allocator),
            .shutdown_callback = null,
        };
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
    pub fn registerValidator(self: *DoppelgangerService, pubkey: [48]u8) !void {
        // Check for duplicate.
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return;
        }
        try self.entries.append(.{
            .pubkey = pubkey,
            .index = null,
            .state = .{
                .next_epoch_to_check = 0,
                .remaining_epochs = DEFAULT_REMAINING_DETECTION_EPOCHS,
                .status = .unverified,
            },
        });
        log.debug("registered validator for doppelganger detection pubkey=0x{x}", .{pubkey[0..4]});
    }

    /// Remove a validator from doppelganger monitoring.
    pub fn unregisterValidator(self: *DoppelgangerService, pubkey: [48]u8) void {
        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                _ = self.entries.swapRemove(i);
                log.debug("unregistered validator from doppelganger detection pubkey=0x{s}", .{
                    std.fmt.bytesToHex(pubkey[0..4], .lower),
                });
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
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) {
                return e.state.status == .verified_safe;
            }
        }
        return true; // unknown → allow (protection not configured for this key)
    }

    /// Returns the current status for a validator pubkey.
    pub fn getStatus(self: *const DoppelgangerService, pubkey: [48]u8) DoppelgangerStatus {
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return e.state.status;
        }
        return .unknown;
    }

    // -----------------------------------------------------------------------
    // Epoch poll (clock callback)
    // -----------------------------------------------------------------------

    /// Called each epoch to check liveness and advance detection state.
    ///
    /// TS: DoppelgangerService.pollLiveness (clock.runEveryEpoch)
    pub fn onEpoch(self: *DoppelgangerService, io: Io, epoch: u64) void {
        self.pollLiveness(io, epoch) catch |err| {
            log.err("pollLiveness epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    fn pollLiveness(self: *DoppelgangerService, io: Io, epoch: u64) !void {
        // Step 1: resolve pubkey → index for any entries that don't have one yet.
        var needs_resolution = false;
        for (self.entries.items) |e| {
            if (e.state.status == .unverified and e.index == null) {
                needs_resolution = true;
                break;
            }
        }

        if (needs_resolution) {
            try self.resolveIndices(io);
        }

        // Step 2: collect indices of validators still being monitored.
        var indices = std.array_list.Managed(u64).init(self.allocator);
        defer indices.deinit();

        for (self.entries.items) |e| {
            if (e.state.status == .unverified) {
                if (e.index) |idx| {
                    try indices.append(idx);
                }
                // If index still unknown after resolution, skip this epoch.
            }
        }
        if (indices.items.len == 0) return;

        const liveness = try self.api.getLiveness(io, epoch, indices.items);
        defer self.allocator.free(liveness);

        var detected = false;
        for (liveness) |live| {
            if (live.is_live) {
                log.err("DOPPELGANGER DETECTED: validator index={d} is live on the network at epoch={d}!", .{ live.index, epoch });
                detected = true;
                // Mark the specific validator as detected.
                for (self.entries.items) |*e| {
                    if (e.index == live.index) {
                        e.state.status = .doppelganger_detected;
                    }
                }
            }
        }

        if (detected) {
            // Trigger shutdown callback if registered.
            if (self.shutdown_callback) |cb| {
                log.err("triggering shutdown due to doppelganger detection", .{});
                cb.call();
            }
            return error.DoppelgangerDetected;
        }

        // Clean epoch — decrement remaining and promote to verified_safe if done.
        for (self.entries.items) |*e| {
            if (e.state.status == .unverified) {
                if (e.state.remaining_epochs > 0) {
                    e.state.remaining_epochs -= 1;
                }
                if (e.state.remaining_epochs == 0) {
                    e.state.status = .verified_safe;
                    log.info("doppelganger check passed for pubkey=0x{x} — validator now allowed to sign", .{e.pubkey[0..4]});
                }
            }
        }
    }

    /// Resolve pubkey → validator index for entries that don't have one.
    ///
    /// Calls api.getValidatorIndices() with all unresolved pubkeys.
    fn resolveIndices(self: *DoppelgangerService, io: Io) !void {
        var unresolved = std.array_list.Managed([48]u8).init(self.allocator);
        defer unresolved.deinit();

        for (self.entries.items) |e| {
            if (e.index == null and e.state.status == .unverified) {
                try unresolved.append(e.pubkey);
            }
        }
        if (unresolved.items.len == 0) return;

        log.debug("resolving {d} validator indices for doppelganger detection", .{unresolved.items.len});

        const results = self.api.getValidatorIndices(io, unresolved.items) catch |err| {
            log.warn("getValidatorIndices failed: {s} — will retry next epoch", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(results);

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
};
