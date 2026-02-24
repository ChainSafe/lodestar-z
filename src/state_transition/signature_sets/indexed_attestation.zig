const std = @import("std");
const Allocator = std.mem.Allocator;
const blst = @import("blst");
const PublicKey = blst.PublicKey;
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const AttestationData = types.phase0.AttestationData.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const Root = types.primitive.Root.Type;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const ForkTypes = @import("fork_types").ForkTypes;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const createAggregateSignatureSetFromComponents = @import("../utils/signature_sets.zig").createAggregateSignatureSetFromComponents;

pub fn getAttestationDataSigningRoot(config: *const BeaconConfig, state_epoch: Epoch, data: *const AttestationData, out: *[32]u8) !void {
    const slot = computeStartSlotAtEpoch(data.target.epoch);
    const domain = try config.getDomain(state_epoch, c.DOMAIN_BEACON_ATTESTER, slot);

    try computeSigningRoot(types.phase0.AttestationData, data, domain, out);
}

/// Consumer need to free the returned pubkeys array
pub fn getAttestationWithIndicesSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    data: *const AttestationData,
    signature: BLSSignature,
    attesting_indices: []u64,
) !AggregatedSignatureSet {
    const pubkeys = try allocator.alloc(PublicKey, attesting_indices.len);
    errdefer allocator.free(pubkeys);
    for (0..attesting_indices.len) |i| {
        pubkeys[i] = epoch_cache.index_to_pubkey.items[@intCast(attesting_indices[i])];
    }

    var signing_root: Root = undefined;
    try getAttestationDataSigningRoot(config, epoch_cache.epoch, data, &signing_root);

    return createAggregateSignatureSetFromComponents(pubkeys, signing_root, signature);
}

/// Consumer need to free the returned pubkeys array
pub fn getIndexedAttestationSignatureSet(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    indexed_attestation: *const ForkTypes(fork).IndexedAttestation.Type,
) !AggregatedSignatureSet {
    return try getAttestationWithIndicesSignatureSet(
        allocator,
        config,
        epoch_cache,
        &indexed_attestation.data,
        indexed_attestation.signature,
        indexed_attestation.attesting_indices.items,
    );
}

/// Appends to out all the AggregatedSignatureSet for each attestation in the signed_block
/// Consumer need to free the pubkeys arrays in each AggregatedSignatureSet in out
/// TODO: consume in https://github.com/ChainSafe/state-transition-z/issues/72
pub fn attestationsSignatureSets(allocator: Allocator, cached_state: *const CachedBeaconState, signed_block: *const AnySignedBeaconBlock, out: std.ArrayList(AggregatedSignatureSet)) !void {
    const epoch_cache = cached_state.epoch_cache;
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
