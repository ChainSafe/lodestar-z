//! Slot clock for the Validator Client.
//!
//! Computes the current slot from genesis time and provides
//! slot/epoch boundary notifications for scheduling VC duties.
//!
//! TS equivalent: packages/validator/src/util/clock.ts (Clock / IClock)
//!
//! Design (Zig 0.16):
//!   - All timing is wall-clock based (std.time.nanoTimestamp).
//!   - Callbacks are registered and called synchronously in the run loop.
//!   - `run()` drives the clock loop using std.Io for sleeping.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const log = std.log.scoped(.vc_clock);

/// Maximum number of per-slot and per-epoch callbacks.
const MAX_CALLBACKS = 16;

/// Callback invoked on each slot boundary.
pub const SlotCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, slot: u64) void,

    pub fn call(self: SlotCallback, slot: u64) void {
        self.fn_ptr(self.ctx, slot);
    }
};

/// Callback invoked on each epoch boundary.
pub const EpochCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, epoch: u64) void,

    pub fn call(self: EpochCallback, epoch: u64) void {
        self.fn_ptr(self.ctx, epoch);
    }
};

/// Slot clock: computes slots from wall time and drives the duty scheduling loop.
pub const ValidatorSlotTicker = struct {
    genesis_time_ns: u64,
    seconds_per_slot: u64,
    slots_per_epoch: u64,

    slot_callbacks: [MAX_CALLBACKS]SlotCallback,
    slot_callback_count: usize,
    epoch_callbacks: [MAX_CALLBACKS]EpochCallback,
    epoch_callback_count: usize,

    /// Shutdown flag — set by requestShutdown(), checked in run() each iteration.
    shutdown_requested: std.atomic.Value(bool),

    pub fn init(
        genesis_time_unix_secs: u64,
        seconds_per_slot: u64,
        slots_per_epoch: u64,
    ) ValidatorSlotTicker {
        return .{
            .genesis_time_ns = genesis_time_unix_secs * std.time.ns_per_s,
            .seconds_per_slot = seconds_per_slot,
            .slots_per_epoch = slots_per_epoch,
            .slot_callbacks = undefined,
            .slot_callback_count = 0,
            .epoch_callbacks = undefined,
            .epoch_callback_count = 0,
            .shutdown_requested = std.atomic.Value(bool).init(false),
        };
    }

    /// Register a callback to run at every slot boundary.
    ///
    /// TS: clock.runEverySlot(fn)
    pub fn onSlot(self: *ValidatorSlotTicker, cb: SlotCallback) void {
        self.slot_callbacks[self.slot_callback_count] = cb;
        self.slot_callback_count += 1;
    }

    /// Register a callback to run at every epoch boundary.
    ///
    /// TS: clock.runEveryEpoch(fn)
    pub fn onEpoch(self: *ValidatorSlotTicker, cb: EpochCallback) void {
        self.epoch_callbacks[self.epoch_callback_count] = cb;
        self.epoch_callback_count += 1;
    }

    /// Request the run() loop to stop at the next iteration.
    ///
    /// Safe to call from any thread (uses atomic store).
    pub fn requestShutdown(self: *ValidatorSlotTicker) void {
        self.shutdown_requested.store(true, .seq_cst);
    }

    /// Return the current slot number (0-based from genesis).
    ///
    /// TS: clock.getCurrentSlot()
    pub fn currentSlot(self: *const ValidatorSlotTicker) u64 {
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());
        if (now_ns < self.genesis_time_ns) return 0;
        const elapsed_ns = now_ns - self.genesis_time_ns;
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        return elapsed_ns / slot_duration_ns;
    }

    /// Return the current epoch (slot / slots_per_epoch).
    pub fn currentEpoch(self: *const ValidatorSlotTicker) u64 {
        return self.currentSlot() / self.slots_per_epoch;
    }

    /// Nanoseconds until the start of `slot`.
    ///
    /// Returns 0 if the slot has already started.
    ///
    /// TS: clock.msToSlot(slot) (we use nanoseconds)
    pub fn nsUntilSlot(self: *const ValidatorSlotTicker, slot: u64) u64 {
        const slot_start_ns = self.genesis_time_ns + slot * self.seconds_per_slot * std.time.ns_per_s;
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());
        if (now_ns >= slot_start_ns) return 0;
        return slot_start_ns - now_ns;
    }

    /// Nanoseconds elapsed since the start of `slot`.
    ///
    /// TS: clock.msFromSlot(slot) (we use nanoseconds)
    pub fn nsFromSlot(self: *const ValidatorSlotTicker, slot: u64) u64 {
        const slot_start_ns = self.genesis_time_ns + slot * self.seconds_per_slot * std.time.ns_per_s;
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());
        if (now_ns <= slot_start_ns) return 0;
        return now_ns - slot_start_ns;
    }

    /// Start the slot clock loop (blocking).
    ///
    /// Wakes at each slot boundary, fires slot callbacks, and at epoch
    /// boundaries fires epoch callbacks too.
    ///
    /// TS: clock.start(signal) which calls runAtMostEvery in a loop.
    pub fn run(self: *ValidatorSlotTicker, io: Io) !void {
        var last_slot: u64 = 0;

        while (!self.shutdown_requested.load(.seq_cst)) {
            const slot = self.currentSlot();

            if (slot > last_slot) {
                last_slot = slot;
                log.debug("slot {d}", .{slot});

                // Fire per-slot callbacks.
                for (self.slot_callbacks[0..self.slot_callback_count]) |cb| {
                    cb.call(slot);
                }

                // Fire per-epoch callbacks at epoch boundary (slot 0 of epoch).
                if (slot % self.slots_per_epoch == 0) {
                    const epoch = slot / self.slots_per_epoch;
                    for (self.epoch_callbacks[0..self.epoch_callback_count]) |cb| {
                        cb.call(epoch);
                    }
                }
            }

            // Sleep until the next slot boundary.
            const next_slot = last_slot + 1;
            const wait_ns = self.nsUntilSlot(next_slot);
            if (wait_ns > 0) {
                // Use Io.Timeout.sleep — Zig 0.16 evented sleep (io_uring / GCD).
                // See: src/networking/p2p_service.zig for the pattern.
                const t: Io.Timeout = .{ .duration = .{
                    .raw = Io.Duration.fromNanoseconds(@intCast(wait_ns)),
                    .clock = .awake,
                } };
                t.sleep(io) catch |err| {
                    log.err("sleep error: {s}", .{@errorName(err)});
                    return err;
                };
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ValidatorSlotTicker.currentSlot before genesis" {
    // Genesis in the far future → slot 0.
    const future = @as(u64, @intCast(std.time.timestamp())) + 9999;
    const clock = ValidatorSlotTicker.init(future, 12, 32);
    try testing.expectEqual(@as(u64, 0), clock.currentSlot());
}

test "ValidatorSlotTicker.currentEpoch" {
    // Genesis 100 slots ago at 12 s/slot.
    const now_secs: u64 = @intCast(std.time.timestamp());
    const genesis = now_secs -| (100 * 12);
    const clock = ValidatorSlotTicker.init(genesis, 12, 32);
    const slot = clock.currentSlot();
    const epoch = clock.currentEpoch();
    try testing.expectEqual(slot / 32, epoch);
}
