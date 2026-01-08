const types = @import("consensus_types");
const preset = @import("preset").preset;
const Root = types.primitive.Root.Type;
const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const SLOTS_PER_HISTORICAL_ROOT = preset.SLOTS_PER_HISTORICAL_ROOT;
const computeStartSlotAtEpoch = @import("./epoch.zig").computeStartSlotAtEpoch;

pub fn getBlockRootAtSlot(state: *const BeaconState, slot: Slot) !*const [32]u8 {
    const state_slot = try state.slot();
    if (slot >= state_slot) {
        return error.SlotTooBig;
    }

    const oldestStoredSlot = if (state_slot > SLOTS_PER_HISTORICAL_ROOT) state_slot - SLOTS_PER_HISTORICAL_ROOT else 0;

    if (slot < oldestStoredSlot) {
        return error.SlotTooSmall;
    }

    return try (try state.blockRoots()).getRoot(slot % SLOTS_PER_HISTORICAL_ROOT);
}

pub fn getBlockRoot(state: *const BeaconState, epoch: Epoch) !*const [32]u8 {
    return getBlockRootAtSlot(state, computeStartSlotAtEpoch(epoch));
}

// TODO: getTemporaryBlockHeader

// TODO: signedBlockToSignedHeader
