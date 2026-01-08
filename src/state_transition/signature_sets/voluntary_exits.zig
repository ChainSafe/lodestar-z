const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const SignedBeaconBlock = @import("../types/beacon_block.zig").SignedBeaconBlock;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const types = @import("consensus_types");
const Root = types.primitive.Root;
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;

pub fn verifyVoluntaryExitSignature(cached_state: *const CachedBeaconState, signed_voluntary_exit: *const SignedVoluntaryExit) !bool {
    const signature_set = try getVoluntaryExitSignatureSet(cached_state, signed_voluntary_exit);
    return try verifySingleSignatureSet(&signature_set);
}

pub fn getVoluntaryExitSignatureSet(cached_state: *const CachedBeaconState, signed_voluntary_exit: *const SignedVoluntaryExit) !SingleSignatureSet {
    const config = cached_state.config;
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();

    const slot = computeStartSlotAtEpoch(signed_voluntary_exit.message.epoch);
    const domain = try config.getDomainForVoluntaryExit(state.slot(), slot);
    var signing_root: [32]u8 = undefined;
    try computeSigningRoot(types.phase0.VoluntaryExit, &signed_voluntary_exit.message, domain, &signing_root);

    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[signed_voluntary_exit.message.validator_index],
        .signing_root = signing_root,
        .signature = signed_voluntary_exit.signature,
    };
}

pub fn voluntaryExitsSignatureSets(cached_state: *const CachedBeaconState, signed_block: *const SignedBeaconBlock, out: std.ArrayList(SingleSignatureSet)) !void {
    const voluntary_exits = signed_block.beaconBlock().beaconBlockBody().voluntaryExits().items;
    for (voluntary_exits) |signed_voluntary_exit| {
        const signature_set = getVoluntaryExitSignatureSet(cached_state, &signed_voluntary_exit);
        try out.append(signature_set);
    }
}
