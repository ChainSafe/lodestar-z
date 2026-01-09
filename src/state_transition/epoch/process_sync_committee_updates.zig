const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BLSPubkey = types.primitive.BLSPubkey.Type;
const getNextSyncCommitteeIndices = @import("../utils/sync_committee.zig").getNextSyncCommitteeIndices;
const blst = @import("blst");

pub fn processSyncCommitteeUpdates(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var state = &cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const next_epoch = epoch_cache.epoch + 1;
    if (next_epoch % preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0) {
        const active_validator_indices = epoch_cache.getNextEpochShuffling().active_indices;
        const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();
        var next_sync_committee_indices: [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex = undefined;
        try getNextSyncCommitteeIndices(allocator, state, active_validator_indices, effective_balance_increments, &next_sync_committee_indices);
        var validators_view = try state.validators();

        // Using the index2pubkey cache is slower because it needs the serialized pubkey.
        var next_sync_committee_pubkeys: [preset.SYNC_COMMITTEE_SIZE]BLSPubkey = undefined;
        var next_sync_committee_pubkeys_slices: [preset.SYNC_COMMITTEE_SIZE]blst.PublicKey = undefined;
        for (next_sync_committee_indices, 0..next_sync_committee_indices.len) |index, i| {
            var validator_view = try validators_view.get(index);
            var validator: types.phase0.Validator.Type = undefined;
            try validator_view.toValue(allocator, &validator);
            next_sync_committee_pubkeys[i] = validator.pubkey;
            next_sync_committee_pubkeys_slices[i] = try blst.PublicKey.uncompress(&next_sync_committee_pubkeys[i]);
        }

        var next_sync_committee_view = try state.nextSyncCommittee();
        var next_sync_committee: types.altair.SyncCommittee.Type = undefined;
        try next_sync_committee_view.toValue(allocator, &next_sync_committee);

        // Rotate syncCommittee in state
        try state.setCurrentSyncCommittee(&next_sync_committee);

        const aggregated_pk = try blst.AggregatePublicKey.aggregate(&next_sync_committee_pubkeys_slices, false);
        const new_next_sync_committee: types.altair.SyncCommittee.Type = .{
            .pubkeys = next_sync_committee_pubkeys,
            .aggregate_pubkey = aggregated_pk.toPublicKey().compress(),
        };
        try state.setNextSyncCommittee(&new_next_sync_committee);

        // Rotate syncCommittee cache
        // next_sync_committee_indices ownership is transferred to epoch_cache
        try epoch_cache.rotateSyncCommitteeIndexed(allocator, &next_sync_committee_indices);
    }
}
