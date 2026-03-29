const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const c = @import("constants");
const bls = @import("bls");
const computeSigningRootVariable = @import("../utils/signing_root.zig").computeSigningRootVariable;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const createSingleSignatureSetFromComponents = @import("../utils/signature_sets.zig").createSingleSignatureSetFromComponents;

pub fn getExecutionPayloadEnvelopeSigningRoot(
    allocator: Allocator,
    config: *const BeaconConfig,
    envelope: *const types.gloas.ExecutionPayloadEnvelope.Type,
) ![32]u8 {
    const domain = try config.getDomain(computeEpochAtSlot(envelope.slot), c.DOMAIN_BEACON_BUILDER, null);

    var out: [32]u8 = undefined;
    try computeSigningRootVariable(types.gloas.ExecutionPayloadEnvelope, allocator, envelope, domain, &out);
    return out;
}

pub fn getExecutionPayloadEnvelopeSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    signed_envelope: *const types.gloas.SignedExecutionPayloadEnvelope.Type,
) !SingleSignatureSet {
    const envelope = &signed_envelope.message;

    // Get the pubkey: proposer key for self-builds, builder key otherwise
    const proposer_index: u64 = try state.latestBlockHeader().get("proposer_index");
    const pubkey = if (envelope.builder_index == c.BUILDER_INDEX_SELF_BUILD)
        epoch_cache.index_to_pubkey.items[proposer_index]
    else blk: {
        var builders = try state.inner.get("builders");
        var builder: types.gloas.Builder.Type = undefined;
        try builders.getValue(allocator, envelope.builder_index, &builder);
        break :blk bls.PublicKey.uncompress(&builder.pubkey) catch return error.InvalidBuilderPubkey;
    };

    const signing_root = try getExecutionPayloadEnvelopeSigningRoot(allocator, config, envelope);
    return createSingleSignatureSetFromComponents(&pubkey, signing_root, signed_envelope.signature);
}
