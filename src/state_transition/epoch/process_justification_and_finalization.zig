const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const JustificationBits = types.phase0.JustificationBits.Type;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const getBlockRoot = @import("../utils/block_root.zig").getBlockRoot;

/// Update justified and finalized checkpoints depending on network participation.
///
/// PERF: Very low (constant) cost. Persist small objects to the tree.
pub fn processJustificationAndFinalization(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    // Initial FFG checkpoint values have a `0x00` stub for `root`.
    // Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if (cache.current_epoch <= GENESIS_EPOCH + 1) {
        return;
    }
    try weighJustificationAndFinalization(cached_state, cache.total_active_stake_by_increment, cache.prev_epoch_unslashed_stake_target_by_increment, cache.curr_epoch_unslashed_target_stake_by_increment);
}

pub fn weighJustificationAndFinalization(cached_state: *CachedBeaconState, total_active_balance: u64, previous_epoch_target_balance: u64, current_epoch_target_balance: u64) !void {
    const state = &cached_state.state;
    const current_epoch = computeEpochAtSlot(try state.slot());
    const previous_epoch = if (current_epoch == GENESIS_EPOCH) GENESIS_EPOCH else current_epoch - 1;

    var previous_justified_checkpoint_view = try state.previousJustifiedCheckpoint();
    var current_justified_checkpoint_view = try state.currentJustifiedCheckpoint();
    var finalized_checkpoint_view = try state.finalizedCheckpoint();

    var old_previous_justified_checkpoint: Checkpoint = undefined;
    var old_current_justified_checkpoint: Checkpoint = undefined;
    try previous_justified_checkpoint_view.toValue(cached_state.allocator, &old_previous_justified_checkpoint);
    try current_justified_checkpoint_view.toValue(cached_state.allocator, &old_current_justified_checkpoint);

    // Process justifications
    try previous_justified_checkpoint_view.set("epoch", old_current_justified_checkpoint.epoch);
    try previous_justified_checkpoint_view.setValue("root", &old_current_justified_checkpoint.root);

    var justification_bits_view = try state.justificationBits();
    var bits = [_]bool{false} ** JustificationBits.length;
    try justification_bits_view.toBoolArrayInto(&bits);

    // Rotate bits
    var idx: usize = bits.len - 1;
    while (idx > 0) : (idx -= 1) {
        bits[idx] = bits[idx - 1];
    }
    bits[0] = false;

    if (previous_epoch_target_balance * 3 > total_active_balance * 2) {
        const root = try getBlockRoot(state, previous_epoch);
        try current_justified_checkpoint_view.set("epoch", previous_epoch);
        try current_justified_checkpoint_view.setValue("root", &root);
        bits[1] = true;
    }

    if (current_epoch_target_balance * 3 > total_active_balance * 2) {
        const root = try getBlockRoot(state, current_epoch);
        try current_justified_checkpoint_view.set("epoch", current_epoch);
        try current_justified_checkpoint_view.setValue("root", &root);
        bits[0] = true;
    }

    for (0..bits.len) |i| {
        try justification_bits_view.set(i, bits[i]);
    }

    // TODO: Consider rendering bits as array of boolean for faster repeated access here

    // Process finalizations
    // The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the 4th as source
    if (bits[1] and bits[2] and bits[3] and old_previous_justified_checkpoint.epoch + 3 == current_epoch) {
        try finalized_checkpoint_view.set("epoch", old_previous_justified_checkpoint.epoch);
        try finalized_checkpoint_view.setValue("root", &old_previous_justified_checkpoint.root);
    }
    // The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd as source
    if (bits[1] and bits[2] and old_previous_justified_checkpoint.epoch + 2 == current_epoch) {
        try finalized_checkpoint_view.set("epoch", old_previous_justified_checkpoint.epoch);
        try finalized_checkpoint_view.setValue("root", &old_previous_justified_checkpoint.root);
    }
    // The 1st/2nd/3rd most recent epochs are all justified, the 1st using the 3rd as source
    if (bits[0] and bits[1] and bits[2] and old_current_justified_checkpoint.epoch + 2 == current_epoch) {
        try finalized_checkpoint_view.set("epoch", old_current_justified_checkpoint.epoch);
        try finalized_checkpoint_view.setValue("root", &old_current_justified_checkpoint.root);
    }
    // The 1st/2nd most recent epochs are both justified, the 1st using the 2nd as source
    if (bits[0] and bits[1] and old_current_justified_checkpoint.epoch + 1 == current_epoch) {
        try finalized_checkpoint_view.set("epoch", old_current_justified_checkpoint.epoch);
        try finalized_checkpoint_view.setValue("root", &old_current_justified_checkpoint.root);
    }
}
