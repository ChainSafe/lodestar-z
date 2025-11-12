const std = @import("std");
const types = @import("consensus_types");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;
const BeaconConfig = @import("config").BeaconConfig;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const ForkSeq = @import("config").ForkSeq;
const c = @import("constants");
const blst = @import("blst");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const Root = types.primitive.Root.Type;
const SignedBeaconBlock = @import("../types/beacon_block.zig").SignedBeaconBlock;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;

pub fn verifyBlsToExecutionChangeSignature(cached_state: *const CachedBeaconStateAllForks, signed_bls_to_execution_change: *const SignedBLSToExecutionChange) !bool {
    const config = cached_state.config;
    const signature_set = try getBlsToExecutionChangeSignatureSet(config, signed_bls_to_execution_change);
    return verifySingleSignatureSet(&signature_set);
}

pub fn getBlsToExecutionChangeSignatureSet(config: *const BeaconConfig, signed_bls_to_execution_change: *const SignedBLSToExecutionChange) !SingleSignatureSet {
    // signatureFork for signing domain is fixed
    const domain = try config.getDomainByForkSeq(.phase0, c.DOMAIN_BLS_TO_EXECUTION_CHANGE);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.capella.BLSToExecutionChange, &signed_bls_to_execution_change.message, domain, &signing_root);

    return SingleSignatureSet{
        .pubkey = try blst.PublicKey.uncompress(&signed_bls_to_execution_change.message.from_bls_pubkey),
        .signing_root = signing_root,
        .signature = signed_bls_to_execution_change.signature,
    };
}

pub fn getBlsToExecutionChangeSignatureSets(config: *const BeaconConfig, signed_block: *const SignedBeaconBlock, out: std.ArrayList(SingleSignatureSet)) !void {
    const bls_to_execution_changes = signed_block.beaconBlock().beaconBlockBody().blsToExecutionChanges().items;
    for (bls_to_execution_changes) |signed_bls_to_execution_change| {
        const signature_set = try getBlsToExecutionChangeSignatureSet(config, signed_bls_to_execution_change);
        try out.append(signature_set);
    }
}
