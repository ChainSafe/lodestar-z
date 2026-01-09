const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const ssz = @import("ssz");
const hex = @import("hex");
const Slot = types.primitive.Slot.Type;
const preset = @import("preset").preset;
const state_transition = @import("../root.zig");
const Root = types.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;
const CachedBeaconState = state_transition.CachedBeaconState;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;

/// Generate a valid electra block for the given pre-state.
pub fn generateElectraBlock(allocator: Allocator, cached_state: *const CachedBeaconState, out: *types.electra.SignedBeaconBlock.Type) !void {
    const state = cached_state.state;
    var attestations = types.electra.Attestations.default_value;
    // no need to fill up to MAX_ATTESTATIONS_ELECTRA
    const att_slot: Slot = (try state.slot()) - 2;
    const att_index = 0;
    const att_block_root = try getBlockRootAtSlot(&state, att_slot);
    const target_epoch = cached_state.getEpochCache().epoch;
    const target_epoch_slot = computeStartSlotAtEpoch(target_epoch);
    var source_checkpoint_view = try state.currentJustifiedCheckpoint();
    var source_checkpoint: types.phase0.Checkpoint.Type = undefined;
    try source_checkpoint_view.toValue(allocator, &source_checkpoint);

    const att_target_root = try getBlockRootAtSlot(&state, target_epoch_slot);
    const att_data: types.phase0.AttestationData.Type = .{
        .slot = att_slot,
        .index = att_index,
        .beacon_block_root = att_block_root.*,
        .source = source_checkpoint,
        .target = .{
            .epoch = target_epoch,
            .root = att_target_root.*,
        },
    };
    const committee_count = try cached_state.getEpochCache().getCommitteeCountPerSlot(target_epoch);
    var total_committee_size: usize = 0;
    for (0..committee_count) |committee_index| {
        const committee = try cached_state.getEpochCache().getBeaconCommittee(att_slot, committee_index);
        total_committee_size += committee.len;
    }

    var aggregation_bits = try ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT).Type.fromBitLen(allocator, total_committee_size);
    // TODO: why this does not work
    // var aggregation_bits = @field(types.electra.Attestation.Fields, "aggregation_bits").Type.fromBitLen(allocator, total_committee_size);
    for (0..total_committee_size) |i| {
        try aggregation_bits.set(allocator, i, true);
    }

    var committee_bits = ssz.BitVectorType(preset.MAX_COMMITTEES_PER_SLOT).default_value;
    // var committee_bits = @field(types.electra.Attestation.Fields, "committee_bits").default_value;
    for (0..committee_count) |i| {
        try committee_bits.set(i, true);
    }

    try attestations.append(allocator, .{
        .aggregation_bits = aggregation_bits,
        .data = att_data,
        .signature = types.primitive.BLSSignature.default_value,
        .committee_bits = committee_bits,
    });

    var execution_payload = types.electra.ExecutionPayload.default_value;
    execution_payload.timestamp = 1737111896;

    out.* = .{
        .message = .{
            .slot = (try state.slot()) + 1,
            // value is generated after running real state transition int test
            .proposer_index = 41,
            .parent_root = try hex.hexToRoot("0x4e647394b6f96c1cd44938483ddf14d89b35d3f67586a59cbfd410a56efbb2b1"),
            // this could be computed later
            .state_root = [_]u8{0} ** 32,
            .body = .{
                .randao_reveal = [_]u8{0} ** 96,
                .eth1_data = types.phase0.Eth1Data.default_value,
                .graffiti = [_]u8{0} ** 32,
                // TODO: populate data to test other operations
                .proposer_slashings = types.phase0.ProposerSlashings.default_value,
                .attester_slashings = types.phase0.AttesterSlashings.default_value,
                .attestations = attestations,
                .deposits = types.phase0.Deposits.default_value,
                .voluntary_exits = types.phase0.VoluntaryExits.default_value,
                .sync_aggregate = .{
                    .sync_committee_bits = ssz.BitVectorType(preset.SYNC_COMMITTEE_SIZE).default_value,
                    .sync_committee_signature = types.primitive.BLSSignature.default_value,
                },
                .execution_payload = execution_payload,
                .bls_to_execution_changes = types.capella.SignedBLSToExecutionChanges.default_value,
                .blob_kzg_commitments = types.electra.BlobKzgCommitments.default_value,
                .execution_requests = types.electra.ExecutionRequests.default_value,
            },
        },
        .signature = types.primitive.BLSSignature.default_value,
    };
}
