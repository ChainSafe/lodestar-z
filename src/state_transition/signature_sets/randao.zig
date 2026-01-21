const types = @import("consensus_types");
const Slot = types.primitive.Slot.Type;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const Root = types.primitive.Root.Type;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;

pub fn verifyRandaoSignature(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *const ForkBeaconState(fork),
    comptime block_type: BlockType,
    body: ForkBeaconBlockBody(fork, block_type),
    slot: Slot,
    proposer_idx: u64,
) !bool {
    const signature_set = try randaoRevealSignatureSet(fork, config, epoch_cache, state, block_type, body, slot, proposer_idx);
    return verifySingleSignatureSet(&signature_set);
}

pub fn randaoRevealSignatureSet(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *const ForkBeaconState(fork),
    comptime block_type: BlockType,
    body: ForkBeaconBlockBody(fork, block_type),
    slot: Slot,
    proposer_idx: u64,
) !SingleSignatureSet {
    // should not get epoch from epoch_cache
    const epoch = computeEpochAtSlot(slot);
    const domain = try config.getDomain(try state.slot(), c.DOMAIN_RANDAO, slot);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.primitive.Epoch, &epoch, domain, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[proposer_idx],
        .signing_root = signing_root,
        .signature = body.inner.randao_reveal,
    };
}
