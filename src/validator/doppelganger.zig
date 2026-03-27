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
//! This file is a stub — the interface is defined but detection logic is not wired up.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const BeaconApiClient = @import("api_client.zig").BeaconApiClient;

const log = std.log.scoped(.doppelganger);

/// Number of clean epochs before we allow signing.
const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 1;

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

pub const DoppelgangerService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    /// Map: pubkey (hex string) → DoppelgangerState.
    states: std.StringHashMap(DoppelgangerState),

    pub fn init(allocator: Allocator, api: *BeaconApiClient) DoppelgangerService {
        return .{
            .allocator = allocator,
            .api = api,
            .states = std.StringHashMap(DoppelgangerState).init(allocator),
        };
    }

    pub fn deinit(self: *DoppelgangerService) void {
        self.states.deinit();
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a validator pubkey for doppelganger monitoring.
    ///
    /// TS: DoppelgangerService.registerValidator(pubkeyHex)
    pub fn registerValidator(self: *DoppelgangerService, pubkey: [48]u8) !void {
        const key = try std.fmt.allocPrint(self.allocator, "{}", .{std.fmt.fmtSliceHexLower(&pubkey)});
        try self.states.put(key, .{
            .next_epoch_to_check = 0,
            .remaining_epochs = DEFAULT_REMAINING_DETECTION_EPOCHS,
            .status = .unverified,
        });
        log.debug("registered validator for doppelganger detection pubkey=0x{s}", .{key[0..8]});
    }

    // -----------------------------------------------------------------------
    // Status check
    // -----------------------------------------------------------------------

    /// Returns true if the validator is allowed to sign (verified safe or protection disabled).
    ///
    /// TS: DoppelgangerService.getStatus(pubkeyHex) == VerifiedSafe
    pub fn isSigningAllowed(self: *const DoppelgangerService, pubkey: [48]u8) bool {
        var key_buf: [96]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{}", .{std.fmt.fmtSliceHexLower(&pubkey)}) catch return false;
        const state = self.states.get(key) orelse return true; // unknown → allow (protection not configured)
        return state.status == .verified_safe;
    }

    /// Returns the current status for a validator pubkey.
    pub fn getStatus(self: *const DoppelgangerService, pubkey: [48]u8) DoppelgangerStatus {
        var key_buf: [96]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{}", .{std.fmt.fmtSliceHexLower(&pubkey)}) catch return .unknown;
        const state = self.states.get(key) orelse return .unknown;
        return state.status;
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
        // Collect indices of validators still being monitored.
        var indices_buf: [256]u64 = undefined;
        var count: usize = 0;

        var it = self.states.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .unverified) {
                // TODO: resolve pubkey → index lookup.
                _ = entry;
                indices_buf[count] = 0; // stub
                count += 1;
                if (count >= indices_buf.len) break;
            }
        }
        if (count == 0) return;

        const liveness = try self.api.getLiveness(io, epoch, indices_buf[0..count]);
        defer self.allocator.free(liveness);

        for (liveness) |live| {
            if (live.is_live) {
                // Doppelganger detected — halt.
                log.err("DOPPELGANGER DETECTED: validator index={d} is live on the network!", .{live.index});
                // TODO: trigger shutdown callback (TS: processShutdownCallback).
                // Mark all as detected.
                var state_it = self.states.iterator();
                while (state_it.next()) |entry| {
                    entry.value_ptr.status = .doppelganger_detected;
                }
                return error.DoppelgangerDetected;
            }
        }

        // Clean epoch — decrement remaining.
        var state_it = self.states.iterator();
        while (state_it.next()) |entry| {
            if (entry.value_ptr.status == .unverified) {
                if (entry.value_ptr.remaining_epochs > 0) {
                    entry.value_ptr.remaining_epochs -= 1;
                }
                if (entry.value_ptr.remaining_epochs == 0) {
                    entry.value_ptr.status = .verified_safe;
                    log.info("doppelganger check passed — validator now signing", .{});
                }
            }
        }
    }
};
