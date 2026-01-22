const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const c = @import("constants");
const types = @import("consensus_types");
const Root = types.primitive.Root;
const computeBlockSigningRoot = @import("../utils/signing_root.zig").computeBlockSigningRoot;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifySignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

pub fn verifyProposerSignature(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_block: AnySignedBeaconBlock,
) !bool {
    const signature_set = try getBlockProposerSignatureSet(
        allocator,
        config,
        epoch_cache,
        signed_block,
    );
    return try verifySignatureSet(&signature_set);
}

pub fn getBlockProposerSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_block: AnySignedBeaconBlock,
) !SingleSignatureSet {
    const block = signed_block.beaconBlock();
    const domain = try config.getDomain(epoch_cache.epoch, c.DOMAIN_BEACON_PROPOSER, block.slot());
    // var signing_root: Root = undefined;
    var signing_root_buf: [32]u8 = undefined;
    try computeBlockSigningRoot(allocator, block, domain, &signing_root_buf);

    // Root.uncompressFromBytes(&signing_root_buf, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[block.proposerIndex()],
        .signing_root = signing_root_buf,
        .signature = signed_block.signature().*,
    };
}

pub fn getBlockHeaderProposerSignatureSet(
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_block_header: *const types.phase0.SignedBeaconBlockHeader.Type,
) SingleSignatureSet {
    const domain = config.getDomain(epoch_cache.epoch, c.DOMAIN_BEACON_PROPOSER, signed_block_header.message.slot);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.phase0.SignedBeaconBlockHeader, signed_block_header, domain, &signing_root);

    return .{
        .pubkey = epoch_cache.index_to_pubkey(signed_block_header.message.proposerIndex),
        .signing_root = signing_root,
        .signature = signed_block_header.signature,
    };
}
