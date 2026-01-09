const types = @import("consensus_types");
const Slot = types.primitive.Slot.Type;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const Root = types.primitive.Root.Type;
const Epoch = types.primitive.Epoch.Type;
const Body = @import("../types/block.zig").Body;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;

pub fn verifyRandaoSignature(
    state: *const CachedBeaconState,
    body: Body,
    slot: Slot,
    proposer_idx: u64,
) !bool {
    const signature_set = try randaoRevealSignatureSet(state, body, slot, proposer_idx);
    return verifySingleSignatureSet(&signature_set);
}

pub fn randaoRevealSignatureSet(
    cached_state: *const CachedBeaconState,
    body: Body,
    slot: Slot,
    proposer_idx: u64,
) !SingleSignatureSet {
    const epoch_cache = cached_state.getEpochCache();
    const state = &cached_state.state;
    const config = cached_state.config;

    // should not get epoch from epoch_cache
    const epoch = computeEpochAtSlot(slot);
    const domain = try config.getDomain(try state.slot(), c.DOMAIN_RANDAO, slot);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.primitive.Epoch, &epoch, domain, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[proposer_idx],
        .signing_root = signing_root,
        .signature = body.randaoReveal(),
    };
}
