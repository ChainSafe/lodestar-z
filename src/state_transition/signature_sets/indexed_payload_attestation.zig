const std = @import("std");
const Allocator = std.mem.Allocator;
const bls = @import("bls");
const PublicKey = bls.PublicKey;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const createAggregateSignatureSetFromComponents = @import("../utils/signature_sets.zig").createAggregateSignatureSetFromComponents;

pub fn getPayloadAttestationDataSigningRoot(config: *const BeaconConfig, data: *const types.gloas.PayloadAttestationData.Type, out: *[32]u8) !void {
    const domain = try config.getDomain(computeEpochAtSlot(data.slot), c.DOMAIN_PTC_ATTESTER, null);

    try computeSigningRoot(types.gloas.PayloadAttestationData, data, domain, out);
}

/// Consumer needs to free the returned pubkeys array.
pub fn getIndexedPayloadAttestationSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    indexed_payload_attestation: *const types.gloas.IndexedPayloadAttestation.Type,
) !AggregatedSignatureSet {
    const attesting_indices = indexed_payload_attestation.attesting_indices.items;

    const pubkeys = try allocator.alloc(PublicKey, attesting_indices.len);
    errdefer allocator.free(pubkeys);
    for (attesting_indices, 0..) |index, i| {
        pubkeys[i] = epoch_cache.index_to_pubkey.items[index];
    }

    var signing_root: Root = undefined;
    try getPayloadAttestationDataSigningRoot(config, &indexed_payload_attestation.data, &signing_root);

    return createAggregateSignatureSetFromComponents(pubkeys, signing_root, indexed_payload_attestation.signature);
}
