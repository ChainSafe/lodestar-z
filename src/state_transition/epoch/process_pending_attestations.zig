const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const getBlockRootAtSlot = @import("../utils/block_root.zig").getBlockRootAtSlot;

const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const PendingAttestation = types.phase0.PendingAttestation.Type;

pub fn processPendingAttestations(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    proposer_indices: []usize,
    validator_count: usize,
    inclusion_delays: []usize,
    flags: []u8,
    attestations: []const PendingAttestation,
    epoch: Epoch,
    source_flag: u8,
    target_flag: u8,
    head_flag: u8,
) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const state_slot = state.slot();
    const prev_epoch = epoch_cache.getPreviousShuffling().epoch;
    if (attestations.len == 0) {
        return;
    }

    const actual_target_block_root = try getBlockRootAtSlot(state, computeStartSlotAtEpoch(epoch));
    for (0..attestations.len) |i| {
        const att = attestations[i];
        // Ignore empty BitArray, from spec test minimal/phase0/epoch_processing/participation_record_updates updated_participation_record
        // See https://github.com/ethereum/consensus-specs/issues/2825
        if (att.aggregation_bits.bit_len == 0) {
            continue;
        }

        const att_data = att.data;
        const inclusion_delay = att.inclusion_delay;
        const proposer_index = att.proposer_index;
        const att_slot = att_data.slot;
        const att_voted_target_root = std.mem.eql(u8, att_data.target.root[0..], actual_target_block_root[0..]);
        const att_voted_head_root = att_slot < state_slot and std.mem.eql(u8, att_data.beacon_block_root[0..], &(try getBlockRootAtSlot(state, att_slot)));
        const committee = @as([]const u64, try epoch_cache.getBeaconCommittee(att_slot, att_data.index));
        var participants = try att.aggregation_bits.intersectValues(ValidatorIndex, allocator, committee);
        defer participants.deinit();
        for (committee, 0..) |validator_index, bit_index| {
            if (try att.aggregation_bits.get(bit_index)) {
                try participants.append(validator_index);
            }
        }

        if (epoch == prev_epoch) {
            for (participants.items) |p| {
                if (proposer_indices[p] == validator_count or inclusion_delays[p] > inclusion_delay) {
                    proposer_indices[p] = proposer_index;
                    inclusion_delays[p] = inclusion_delay;
                }
            }
        }

        for (participants.items) |p| {
            flags[p] |= source_flag;
            if (att_voted_target_root) {
                flags[p] |= target_flag;
                if (att_voted_head_root) {
                    flags[p] |= head_flag;
                }
            }
        }
    }
}
