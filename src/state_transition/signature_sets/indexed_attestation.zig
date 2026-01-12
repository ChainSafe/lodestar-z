const std = @import("std");
const Allocator = std.mem.Allocator;
const blst = @import("blst");
const PublicKey = blst.PublicKey;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const SignedBeaconBlock = @import("../types/beacon_block.zig").SignedBeaconBlock;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const types = @import("consensus_types");
const AttestationData = types.phase0.AttestationData.Type;
const Attestation = types.primitive.Attestation.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const Root = types.primitive.Root.Type;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const createAggregateSignatureSetFromComponents = @import("../utils/signature_sets.zig").createAggregateSignatureSetFromComponents;
const IndexedAttestation = @import("../types/attestation.zig").IndexedAttestation;

pub fn getAttestationDataSigningRoot(cached_state: *const CachedBeaconStateAllForks, data: *const AttestationData, out: *[32]u8) !void {
    const slot = computeStartSlotAtEpoch(data.target.epoch);
    const config = cached_state.config;
    const state = cached_state.state;
    const domain = try config.getDomain(state.slot(), c.DOMAIN_BEACON_ATTESTER, slot);

    try computeSigningRoot(types.phase0.AttestationData, data, domain, out);
}

/// Consumer need to free the returned pubkeys array
pub fn getAttestationWithIndicesSignatureSet(
    allocator: Allocator,
    cached_state: *const CachedBeaconStateAllForks,
    data: *const AttestationData,
    signature: BLSSignature,
    attesting_indices: []u64,
) !AggregatedSignatureSet {
    const epoch_cache = cached_state.getEpochCache();
    const pubkeys = try allocator.alloc(PublicKey, attesting_indices.len);
    errdefer allocator.free(pubkeys);
    for (0..attesting_indices.len) |i| {
        pubkeys[i] = epoch_cache.index_to_pubkey.items[@intCast(attesting_indices[i])];
    }

    var signing_root: Root = undefined;
    try getAttestationDataSigningRoot(cached_state, data, &signing_root);

    return createAggregateSignatureSetFromComponents(pubkeys, signing_root, signature);
}

/// Consumer need to free the returned pubkeys array
pub fn getIndexedAttestationSignatureSet(comptime IA: type, allocator: Allocator, cached_state: *const CachedBeaconStateAllForks, indexed_attestation: *const IA) !AggregatedSignatureSet {
    return try getAttestationWithIndicesSignatureSet(allocator, cached_state, &indexed_attestation.data, indexed_attestation.signature, indexed_attestation.attesting_indices.items);
}

/// Appends to out all the AggregatedSignatureSet for each attestation in the signed_block
/// Consumer need to free the pubkeys arrays in each AggregatedSignatureSet in out
/// TODO: consume in https://github.com/ChainSafe/state-transition-z/issues/72
pub fn attestationsSignatureSets(allocator: Allocator, cached_state: *const CachedBeaconStateAllForks, signed_block: *const SignedBeaconBlock, out: std.ArrayList(AggregatedSignatureSet)) !void {
    const epoch_cache = cached_state.getEpochCache();
    const attestation_items = signed_block.beaconBlock().beaconBlockBody().attestations().items();

    switch (attestation_items) {
        .phase0 => |phase0_attestations| {
            for (phase0_attestations) |*attestation| {
                const indexed_attestation = try epoch_cache.computeIndexedAttestationPhase0(attestation);
                var attesting_indices = indexed_attestation.attesting_indices;
                defer attesting_indices.deinit(allocator);
                const signature_set = try getIndexedAttestationSignatureSet(allocator, cached_state, indexed_attestation);
                try out.append(signature_set);
            }
        },
        .electra => |electra_attestations| {
            for (electra_attestations) |*attestation| {
                const indexed_attestation = try epoch_cache.computeIndexedAttestationElectra(attestation);
                var attesting_indices = indexed_attestation.attesting_indices;
                defer attesting_indices.deinit(allocator);
                const signature_set = try getIndexedAttestationSignatureSet(allocator, cached_state, indexed_attestation);
                try out.append(signature_set);
            }
        },
    }
}
