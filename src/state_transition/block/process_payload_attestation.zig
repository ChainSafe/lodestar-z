const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconConfig = @import("config").BeaconConfig;
const isValidIndexedPayloadAttestation = @import("./is_valid_indexed_payload_attestation.zig").isValidIndexedPayloadAttestation;

pub fn processPayloadAttestation(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    payload_attestation: *const types.gloas.PayloadAttestation.Type,
) !void {
    const data = &payload_attestation.data;

    var latest_block_header = try state.latestBlockHeader();
    const parent_root = try latest_block_header.getFieldRoot("parent_root");
    if (!std.mem.eql(u8, &data.beacon_block_root, parent_root)) {
        return error.PayloadAttestationWrongBlock;
    }

    if (data.slot + 1 != try state.slot()) {
        return error.PayloadAttestationNotFromPreviousSlot;
    }

    var indexed_payload_attestation = try epoch_cache.getIndexedPayloadAttestation(allocator, state, data.slot, payload_attestation);
    defer indexed_payload_attestation.attesting_indices.deinit(allocator);

    if (!(try isValidIndexedPayloadAttestation(allocator, config, epoch_cache, &indexed_payload_attestation, true))) {
        return error.InvalidPayloadAttestation;
    }
}
