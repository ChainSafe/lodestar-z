const std = @import("std");
const slot_utils = @import("./slot.zig");
const preset = @import("preset").preset;

const ChainConfig = @import("config").ChainConfig;
const Epoch = @import("consensus_types").primitive.Epoch.Type;
const Slot = @import("consensus_types").primitive.Slot.Type;
const ClockCallbacks = @import("./runner.zig").ClockCallbacks;

fn computeEpochAtSlot(slot: Slot) Epoch {
    return @divFloor(slot, preset.SLOTS_PER_EPOCH);
}

pub const Clock = struct {
    genesis_time: u64,
    current_slot: Slot,
    _internal_slot: Slot, // TODO: check if this is necessary. (in lodestar it's _currentSlot)
    config: ChainConfig,

    pub fn init(config: ChainConfig, genesis_time: u64) !Clock {
        const initial_slot = try slot_utils.getCurrentSlot(config, genesis_time);
        return Clock{
            .genesis_time = genesis_time,
            .config = config,
            .current_slot = initial_slot,
            ._internal_slot = initial_slot,
        };
    }

    pub fn getCurrentSlot(self: *Clock, callbacks: ?*const ClockCallbacks) !Slot {
        const clock_slot = try slot_utils.getCurrentSlot(self.config, self.genesis_time);

        if (clock_slot > self._internal_slot) {
            if (callbacks) |cb| {
                try self.onNextSlot(cb);
            } else {
                // Update without callbacks
                self._internal_slot = clock_slot;
                self.current_slot = clock_slot;
            }
        }

        return self.current_slot;
    }

    pub fn getCurrentSlotWithGossipDisparity(self: *Clock) !Slot {
        const current_slot = self.current_slot;
        const next_slot_time_in_ms = slot_utils.computeTimeAtSlot(self.config, current_slot + 1, self.genesis_time) * 1000;
        // TODO: we have to add MAXIMUM_GOSSIP_CLOCK_DISPARITY in ChainConfig
        return if (next_slot_time_in_ms - std.time.milliTimestamp() < 500) current_slot + 1 else current_slot;
    }

    pub fn getCurrentEpoch(self: *Clock) Epoch {
        return computeEpochAtSlot(self.current_slot);
    }

    pub fn slotWithFutureTolerance(self: *Clock, toleranceSec: u64) !Slot {
        return try slot_utils.getCurrentSlot(self.config, self.genesis_time - toleranceSec);
    }

    pub fn slotWithPastTolerance(self: *Clock, toleranceSec: u64) !Slot {
        return try slot_utils.getCurrentSlot(self.config, self.genesis_time + toleranceSec);
    }

    pub fn isCurrentSlotGivenGossipDisparity(self: *Clock, slot: Slot) bool {
        const current_slot = self.current_slot;
        if (current_slot == slot) {
            return true;
        }
        const next_slot_time_in_ms = slot_utils.computeTimeAtSlot(self.config, current_slot + 1, self.genesis_time) * 1000;
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        // TODO: add MAXIMUM_GOSSIP_CLOCK_DISPARITY in ChainConfig
        if (next_slot_time_in_ms - now_ms < 500) {
            return slot == current_slot + 1;
        }

        const current_slot_time = slot_utils.computeTimeAtSlot(self.config, current_slot, self.genesis_time);
        const now: u64 = @intCast(std.time.timestamp());
        if (now - current_slot_time < 500) {
            return slot == current_slot - 1;
        }
        return false;
    }

    // TODO: implement waitForSlot
    // pub fn waitForSlot(self: *Clock, slot: Slot) void {
    // }

    pub fn onNextSlot(self: *Clock, callbacks: *const ClockCallbacks) !void {
        const clock_slot = try slot_utils.getCurrentSlot(self.config, self.genesis_time);

        // Process multiple clock slots in case the main thread has been saturated
        while (self._internal_slot < clock_slot) {
            const previous_slot = self._internal_slot;
            self._internal_slot += 1;

            if (callbacks.onSlot) |cb| {
                cb(self._internal_slot, callbacks.ctx);
            }

            const previous_epoch = computeEpochAtSlot(previous_slot);
            const current_epoch = computeEpochAtSlot(self._internal_slot);

            if (previous_epoch < current_epoch) {
                if (callbacks.onEpoch) |cb| {
                    cb(current_epoch, callbacks.ctx);
                }
            }
        }
        self.current_slot = self._internal_slot;
    }

    pub fn secFromSlot(self: *Clock, slot: Slot, to_sec: u64) u64 {
        return to_sec - slot_utils.computeTimeAtSlot(self.config, slot, self.genesis_time);
    }

    pub fn msFromSlot(self: *Clock, slot: Slot, to_ms: u64) u64 {
        return to_ms - slot_utils.computeTimeAtSlot(self.config, slot, self.genesis_time) * 1000;
    }

    pub fn msUntilNextSlot(self: *Clock) u64 {
        const ms_per_slot = self.config.SECONDS_PER_SLOT * 1000;
        const now_in_ms: u64 = @intCast(std.time.milliTimestamp());
        const genesis_time_in_ms: u64 = @intCast(self.genesis_time * 1000);
        const diff_in_ms: u64 = now_in_ms - genesis_time_in_ms;
        return ms_per_slot - (diff_in_ms % ms_per_slot);
    }
};
