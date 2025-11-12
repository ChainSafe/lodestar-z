const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const SignedBlock = @import("../types/signed_block.zig").SignedBlock;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const Root = ssz.primitive.Root.Type;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
const c = @import("constants");
const blst = @import("blst");
const BLSPubkey = ssz.primitive.BLSPubkey.Type;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifyAggregatedSignatureSet = @import("../utils/signature_sets.zig").verifyAggregatedSignatureSet;
const balance_utils = @import("../utils/balance.zig");
const increaseBalance = balance_utils.increaseBalance;
const decreaseBalance = balance_utils.decreaseBalance;

pub fn processSyncAggregate(
    allocator: Allocator,
    cached_state: *CachedBeaconStateAllForks,
    block: *const SignedBlock,
    verify_signatures: bool,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const committee_indices = @as(*const [preset.SYNC_COMMITTEE_SIZE]u64, @ptrCast(epoch_cache.current_sync_committee_indexed.get().getValidatorIndices()));

    // different from the spec but not sure how to get through signature verification for default/empty SyncAggregate in the spec test
    if (verify_signatures) {
        const participant_indices = try block.beaconBlockBody().syncAggregate().sync_committee_bits.intersectValues(
            ValidatorIndex,
            allocator,
            committee_indices,
        );
        defer participant_indices.deinit();
        const signature_set = try getSyncCommitteeSignatureSet(allocator, cached_state, block, participant_indices.items);
        // When there's no participation we consider the signature valid and just ignore it
        if (signature_set) |set| {
            if (!try verifyAggregatedSignatureSet(&set)) {
                return error.SyncCommitteeSignatureInvalid;
            }
        }
    }

    const sync_participant_reward = epoch_cache.sync_participant_reward;
    const sync_proposer_reward = epoch_cache.sync_proposer_reward;
    const sync_comittee_bits = block.beaconBlockBody().syncAggregate().sync_committee_bits;
    const proposer_index = try epoch_cache.getBeaconProposer(state.slot());
    const balances = state.balances();
    var proposer_balance = balances.items[proposer_index];

    for (0..preset.SYNC_COMMITTEE_SIZE) |i| {
        const index = committee_indices[i];

        if (try sync_comittee_bits.get(i)) {
            // Positive rewards for participants
            if (index == proposer_index) {
                proposer_balance += sync_participant_reward;
            } else {
                increaseBalance(state, index, sync_participant_reward);
            }

            // Proposer reward
            proposer_balance += sync_proposer_reward;
            // TODO: proposer_rewards inside state
        } else {
            // Negative rewards for non participants
            if (index == proposer_index) {
                proposer_balance = @max(0, proposer_balance - sync_participant_reward);
            } else {
                decreaseBalance(state, index, sync_participant_reward);
            }
        }
    }

    // Apply proposer balance
    balances.items[proposer_index] = proposer_balance;
}

/// Consumers should deinit the returned pubkeys
pub fn getSyncCommitteeSignatureSet(allocator: Allocator, cached_state: *const CachedBeaconStateAllForks, block: *const SignedBlock, participant_indices: ?[]usize) !?AggregatedSignatureSet {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const sync_aggregate = block.beaconBlockBody().syncAggregate();
    const signature = sync_aggregate.sync_committee_signature;

    const participant_indices_ = if (participant_indices) |pi| pi else blk: {
        const committee_indices = @as(*const [preset.SYNC_COMMITTEE_SIZE]u64, @ptrCast(epoch_cache.current_sync_committee_indexed.get().getValidatorIndices()));
        break :blk (try sync_aggregate.sync_committee_bits.intersectValues(ValidatorIndex, allocator, committee_indices)).items;
    };
    // When there's no participation we consider the signature valid and just ignore it
    if (participant_indices_.len == 0) {
        // Must set signature as G2_POINT_AT_INFINITY when participating bits are empty
        // https://github.com/ethereum/eth2.0-specs/blob/30f2a076377264677e27324a8c3c78c590ae5e20/specs/altair/bls.md#eth2_fast_aggregate_verify
        if (std.mem.eql(u8, &signature, &G2_POINT_AT_INFINITY)) {
            return null;
        }
        return error.EmptySyncCommitteeSignatureIsNotInfinity;
    }

    // The spec uses the state to get the previous slot
    // ```python
    // previous_slot = max(state.slot, Slot(1)) - Slot(1)
    // ```
    // However we need to run the function getSyncCommitteeSignatureSet() for all the blocks in a epoch
    // with the same state when verifying blocks in batch on RangeSync. Therefore we use the block.slot.
    const previous_slot = @max(block.slot(), 1) - 1;

    // The spec uses the state to get the root at previousSlot
    // ```python
    // get_block_root_at_slot(state, previous_slot)
    // ```
    // However we need to run the function getSyncCommitteeSignatureSet() for all the blocks in a epoch
    // with the same state when verifying blocks in batch on RangeSync.
    //
    // On skipped slots state block roots just copy the latest block, so using the parentRoot here is equivalent.
    // So getSyncCommitteeSignatureSet() can be called with a state in any slot (with the correct shuffling)
    const root_signed = block.parentRoot();

    const domain = try cached_state.config.getDomain(state.slot(), c.DOMAIN_SYNC_COMMITTEE, previous_slot);

    const pubkeys = try allocator.alloc(blst.PublicKey, participant_indices_.len);
    for (0..participant_indices_.len) |i| {
        pubkeys[i] = epoch_cache.index_to_pubkey.items[participant_indices_[i]];
    }
    var signing_root: Root = undefined;
    try computeSigningRoot(ssz.primitive.Root, &root_signed, domain, &signing_root);

    return .{
        .pubkeys = pubkeys,
        .signing_root = signing_root,
        .signature = signature,
    };
}
