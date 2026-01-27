const std = @import("std");
const constant = @import("constants");
const types = @import("consensus_types");

const ChainConfig = @import("config").ChainConfig;
const Slot = @import("consensus_types").primitive.Slot.Type;

// use u64 to be compatible with genesisTime in "./state_transition/types/beacon_state.zig";
// TODO: should we have to add a type of TimeSeconds and use it as u64?
pub fn getSlotsSinceGenesis(config: ChainConfig, genesisTime: u64) !Slot {
    const current_time_in_seconds: u64 = @intCast(std.time.timestamp());
    const diff_in_seconds = current_time_in_seconds - genesisTime;
    return @intCast(diff_in_seconds / config.SECONDS_PER_SLOT);
}

pub fn getCurrentSlot(config: ChainConfig, genesisTime: u64) !Slot {
    return config.GENESIS_SLOT + getSlotsSinceGenesis(config, genesisTime);
}

// Compute the time in "seconds" at a given slot
pub fn computeTimeAtSlot(config: ChainConfig, slot: Slot, genesisTime: u64) u64 {
    return genesisTime + slot * config.SECONDS_PER_SLOT;
}
