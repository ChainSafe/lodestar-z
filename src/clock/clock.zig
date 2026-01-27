const std = @import("std");
const slot_utils = @import("./slot.zig");
const state_transition = @import("state_transition");

const ChainConfig = @import("config").ChainConfig;
const Epoch = @import("consensus_types").primitive.Epoch.Type;
const Slot = @import("consensus_types").primitive.Slot.Type;

pub const Clock = struct {
    genesis_time: Slot,
    current_slot: Slot,
    config: ChainConfig,
    timeout_id: u64,

    pub fn init(config: ChainConfig, genesis_time: u64) !Clock {
        return Clock{
            .genesis_time = genesis_time,
            .config = config,
            .timeoutId = 0,
            .current_slot = slot_utils.getCurrentSlot(config, genesis_time),
        };
    }

    pub fn getCurrentSlot(self: *Clock) Slot {
        const computed_slot = slot_utils.getCurrentSlot(self.config, self.genesis_time);
        // if (slot > self.currentSlot) {}
        // skip the timeout for now
        return computed_slot;
    }

    pub fn getCurrentSlotWithGossipDisparity(self: *Clock) Slot {
        const current_slot = self.current_slot;
        const next_slot_time_in_ms = slot_utils.computeTimeAtSlot(self.config, current_slot + 1, self.genesis_time) * 1000;
        // TODO: we have to add MAXIMUM_GOSSIP_CLOCK_DISPARITY in ChainConfig
        return if (next_slot_time_in_ms - std.time.milliTimestamp() < 500) current_slot + 1 else current_slot;
    }

    pub fn getCurrentEpoch(self: *Clock) Epoch {
        return state_transition.state_transition.computeEpochAtSlot(self.currentSlot);
    }

    pub fn slotWithFutureTolerance(self: *Clock, toleranceSec: u64) Slot {
        return slot_utils.getCurrentSlot(self.config, self.genesis_time - toleranceSec);
    }

    pub fn slotWithPastTolerance(self: *Clock, toleranceSec: u64) Slot {
        return slot_utils.getCurrentSlot(self.config, self.genesis_time + toleranceSec);
    }

    pub fn isCurrentSlotGivenGossipDisparity(self: *Clock, slot: Slot) bool {
        const current_slot = self.current_slot;
        if (current_slot == slot) {
            return true;
        }
        const next_slot_time_in_ms = slot_utils.computeTimeAtSlot(self.config, current_slot + 1, self.genesis_time) * 1000;
        // TODO: add MAXIMUM_GOSSIP_CLOCK_DISPARITY in ChainConfig
        if (next_slot_time_in_ms - std.time.milliTimestamp() < 500) {
            return slot == current_slot + 1;
        }

        const current_slot_time = slot_utils.computeTimeAtSlot(self.config, current_slot, self.genesis_time);
        if (std.time.timestamp() - current_slot_time < 500) {
            return slot == current_slot - 1;
        }
        return false;
    }

    // TODO: implement waitForSlot

    pub fn secFromSlot(self: *Clock, slot: Slot, to_sec: u64) u64 {
        return to_sec - slot_utils.computeTimeAtSlot(self.config, slot, self.genesis_time);
    }

    pub fn msFromSlot(self: *Clock, slot: Slot, to_ms: u64) u64 {
        return to_ms - slot_utils.computeTimeAtSlot(self.config, slot, self.genesis_time) * 1000;
    }

    // TODO: implement onNextSlot

    fn msUntilNextSlot(self: *Clock) u64 {
        const ms_per_slot = self.config.SECONDS_PER_SLOT * 1000;
        const now_in_ms: u64 = @intCast(std.time.milliTimestamp());
        const genesis_time_in_ms: u64 = @intCast(self.genesis_time * 1000);
        const diff_in_ms: u64 = now_in_ms - genesis_time_in_ms;
        return ms_per_slot - (diff_in_ms % ms_per_slot);
    }
};
