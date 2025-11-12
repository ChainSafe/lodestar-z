const ct = @import("consensus_types");
const preset = @import("preset").preset;
const Root = ct.primitive.Root.Type;
const Slot = ct.primitive.Slot.Type;
const Epoch = ct.primitive.Epoch.Type;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const SLOTS_PER_HISTORICAL_ROOT = preset.SLOTS_PER_HISTORICAL_ROOT;
const computeStartSlotAtEpoch = @import("./epoch.zig").computeStartSlotAtEpoch;

pub fn getBlockRootAtSlot(state: *const BeaconStateAllForks, slot: Slot) !Root {
    const state_slot = state.slot();
    if (slot >= state_slot) {
        return error.SlotTooBig;
    }

    const oldestStoredSlot = if (state_slot > SLOTS_PER_HISTORICAL_ROOT) state_slot - SLOTS_PER_HISTORICAL_ROOT else 0;

    if (slot < oldestStoredSlot) {
        return error.SlotTooSmall;
    }

    return state.blockRoots()[slot % SLOTS_PER_HISTORICAL_ROOT];
}

pub fn getBlockRoot(state: *const BeaconStateAllForks, epoch: Epoch) !Root {
    return getBlockRootAtSlot(state, computeStartSlotAtEpoch(epoch));
}

// TODO: getTemporaryBlockHeader

// TODO: signedBlockToSignedHeader
