//! Slot clock for the Validator Client.
//!
//! Computes the current slot from genesis time and provides
//! slot/epoch boundary notifications for scheduling VC duties.
//!
//! TS equivalent: packages/validator/src/util/clock.ts (Clock / IClock)
//!
//! Design (Zig 0.16):
//!   - All timing is wall-clock based via `std.Io.Clock.real`.
//!   - Per-slot / per-epoch work is dispatched via `std.Io` concurrent tasks.
//!   - `run()` drives the clock loop using std.Io for sleeping.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const time = @import("time.zig");

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
    skip_slots: bool,

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
        skip_slots: bool,
    ) ValidatorSlotTicker {
        return .{
            .genesis_time_ns = genesis_time_unix_secs * std.time.ns_per_s,
            .seconds_per_slot = seconds_per_slot,
            .slots_per_epoch = slots_per_epoch,
            .skip_slots = skip_slots,
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
    pub fn currentSlot(self: *const ValidatorSlotTicker, io: Io) u64 {
        const now_ns = time.realNanoseconds(io);
        if (now_ns < self.genesis_time_ns) return 0;
        const elapsed_ns = now_ns - self.genesis_time_ns;
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        return elapsed_ns / slot_duration_ns;
    }

    /// Return the current epoch (slot / slots_per_epoch).
    pub fn currentEpoch(self: *const ValidatorSlotTicker, io: Io) u64 {
        return self.currentSlot(io) / self.slots_per_epoch;
    }

    /// Nanoseconds until the start of `slot`.
    ///
    /// Returns 0 if the slot has already started.
    ///
    /// TS: clock.msToSlot(slot) (we use nanoseconds)
    pub fn nsUntilSlot(self: *const ValidatorSlotTicker, io: Io, slot: u64) u64 {
        const slot_start_ns = self.genesis_time_ns + slot * self.seconds_per_slot * std.time.ns_per_s;
        const now_ns = time.realNanoseconds(io);
        if (now_ns >= slot_start_ns) return 0;
        return slot_start_ns - now_ns;
    }

    /// Nanoseconds elapsed since the start of `slot`.
    ///
    /// TS: clock.msFromSlot(slot) (we use nanoseconds)
    pub fn nsFromSlot(self: *const ValidatorSlotTicker, io: Io, slot: u64) u64 {
        const slot_start_ns = self.genesis_time_ns + slot * self.seconds_per_slot * std.time.ns_per_s;
        const now_ns = time.realNanoseconds(io);
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
        const start_slot = self.currentSlot(io);
        var last_slot: u64 = if (self.skip_slots and start_slot > 0) start_slot - 1 else start_slot;
        var first_iteration = true;

        while (!self.shutdown_requested.load(.seq_cst)) {
            const current_slot = self.currentSlot(io);
            const slot = if (self.skip_slots or first_iteration)
                current_slot
            else
                @max(last_slot, @min(current_slot, last_slot + 1));

            if (slot > last_slot or first_iteration or (!self.skip_slots and slot == last_slot)) {
                if (!first_iteration or slot > last_slot) {
                    last_slot = slot;
                }
                log.debug("slot {d}", .{slot});

                // Fire per-epoch callbacks before per-slot callbacks at startup and
                // on epoch boundaries. This ensures duties/registrations for the new
                // epoch are ready before slot work starts, eliminating a race where
                // the first slot of the epoch could run against stale or empty caches.
                if (first_iteration or slot % self.slots_per_epoch == 0) {
                    const epoch = slot / self.slots_per_epoch;
                    try self.dispatchEpochCallbacks(io, epoch);
                }

                // Fire per-slot callbacks concurrently after the epoch refresh completes.
                // This preserves the "epoch duties first, then slot work" ordering at
                // epoch boundaries without spawning OS threads on every tick.
                try self.dispatchSlotCallbacks(io, slot);

                first_iteration = false;
            }

            // Sleep until the next slot boundary.
            const next_slot = if (self.skip_slots) last_slot + 1 else last_slot + 1;
            const wait_ns = self.nsUntilSlot(io, next_slot);
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

    fn dispatchEpochCallbacks(self: *ValidatorSlotTicker, io: Io, epoch: u64) !void {
        var group: Io.Group = .init;
        errdefer group.cancel(io);

        for (self.epoch_callbacks[0..self.epoch_callback_count]) |cb| {
            try group.concurrent(io, runEpochCallback, .{ cb, epoch });
        }

        try group.await(io);
    }

    fn dispatchSlotCallbacks(self: *ValidatorSlotTicker, io: Io, slot: u64) !void {
        var group: Io.Group = .init;
        errdefer group.cancel(io);

        for (self.slot_callbacks[0..self.slot_callback_count]) |cb| {
            try group.concurrent(io, runSlotCallback, .{ cb, slot });
        }

        try group.await(io);
    }

    fn runEpochCallback(callback: EpochCallback, epoch: u64) Io.Cancelable!void {
        callback.call(epoch);
    }

    fn runSlotCallback(callback: SlotCallback, slot: u64) Io.Cancelable!void {
        callback.call(slot);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ValidatorSlotTicker.currentSlot before genesis" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Genesis in the far future → slot 0.
    const future = time.realSeconds(io) + 9999;
    const clock = ValidatorSlotTicker.init(future, 12, 32, true);
    try testing.expectEqual(@as(u64, 0), clock.currentSlot(io));
}

test "ValidatorSlotTicker.currentEpoch" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Genesis 100 slots ago at 12 s/slot.
    const now_secs = time.realSeconds(io);
    const genesis = now_secs -| (100 * 12);
    const clock = ValidatorSlotTicker.init(genesis, 12, 32, true);
    const slot = clock.currentSlot(io);
    const epoch = clock.currentEpoch(io);
    try testing.expectEqual(slot / 32, epoch);
}
