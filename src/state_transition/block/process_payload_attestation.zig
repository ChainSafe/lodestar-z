const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconConfig = @import("config").BeaconConfig;
const isValidIndexedPayloadAttestation = @import("./is_valid_indexed_payload_attestation.zig").isValidIndexedPayloadAttestation;

pub fn processPayloadAttestation(
    allocator: Allocator,
    io: std.Io,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    payload_attestation: *const types.gloas.PayloadAttestation.Type,
    verify_signature: bool,
) !void {
    const data = &payload_attestation.data;

    var latest_block_header = try state.latestBlockHeader();
    const parent_root = try latest_block_header.getFieldRoot("parent_root");
    if (!std.mem.eql(u8, &data.beacon_block_root, parent_root)) {
        return error.PayloadAttestationWrongBlock;
    }

    const state_slot = try state.slot();
    if (state_slot == 0 or data.slot != state_slot - 1) {
        return error.PayloadAttestationNotFromPreviousSlot;
    }

    var committee: types.gloas.PayloadTimelinessCommittee.Type = undefined;
    try @import("../utils/gloas.zig").getPayloadTimelinessCommittee(config, state, data.slot, &committee);
    var indices_buf: [@import("preset").preset.PTC_SIZE]u64 = undefined;
    var indexed = types.gloas.IndexedPayloadAttestation.default_value;
    indexed.data = data.*;
    indexed.signature = payload_attestation.signature;
    indexed.attesting_indices = .initBuffer(&indices_buf);
    for (committee, 0..) |index, i| {
        if (try payload_attestation.aggregation_bits.get(i)) indexed.attesting_indices.appendAssumeCapacity(index);
    }
    std.mem.sort(u64, indexed.attesting_indices.items, {}, std.sort.asc(u64));
    if (!(try isValidIndexedPayloadAttestation(allocator, io, config, epoch_cache, &indexed, verify_signature))) return error.InvalidPayloadAttestation;
}
