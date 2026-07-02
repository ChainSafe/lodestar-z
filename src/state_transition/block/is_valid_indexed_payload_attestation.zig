const std = @import("std");
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const getIndexedPayloadAttestationSignatureSet = @import("../signature_sets/indexed_payload_attestation.zig").getIndexedPayloadAttestationSignatureSet;
const verifyAggregatedSignatureSet = @import("../utils/signature_sets.zig").verifyAggregatedSignatureSet;

/// Validate an IndexedPayloadAttestation: check that attesting indices are non-empty,
/// sorted, and (optionally) that the aggregate BLS signature is valid.
pub fn isValidIndexedPayloadAttestation(
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    indexed_payload_attestation: *const types.gloas.IndexedPayloadAttestation.Type,
    verify_signature: bool,
) !bool {
    const attesting_indices = indexed_payload_attestation.attesting_indices.items;

    if (attesting_indices.len == 0) return false;

    var prev: ValidatorIndex = 0;
    for (attesting_indices, 0..) |index, i| {
        if (i >= 1 and index < prev) {
            return false;
        }
        prev = index;
    }

    if (!verify_signature) return true;

    const sig_set = try getIndexedPayloadAttestationSignatureSet(allocator, config, epoch_cache, indexed_payload_attestation);
    defer allocator.free(sig_set.pubkeys);
    return verifyAggregatedSignatureSet(&sig_set);
}
