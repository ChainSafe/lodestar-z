const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;

const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const bls = @import("bls");
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const gloas_utils = @import("../utils/gloas.zig");
const isActiveBuilder = gloas_utils.isActiveBuilder;
const canBuilderCoverBid = gloas_utils.canBuilderCoverBid;
const verify = @import("../utils/bls.zig").verify;
const getExecutionPayloadBidSigningRoot = @import("../signature_sets/execution_payload_bid.zig").getExecutionPayloadBidSigningRoot;
const getBlockRootAtSlot = @import("../utils/block_root.zig").getBlockRootAtSlot;

pub fn processExecutionPayloadBid(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    signed_bid: *const types.gloas.SignedExecutionPayloadBid.Type,
) !void {
    const bid = &signed_bid.message;
    const builder_index = bid.builder_index;
    const amount = bid.value;
    const state_slot = try state.slot();

    if (builder_index == c.BUILDER_INDEX_SELF_BUILD) {
        if (amount != 0) return error.SelfBuildNonZeroAmount;
        if (!std.mem.eql(u8, &signed_bid.signature, &c.G2_POINT_AT_INFINITY)) return error.SelfBuildNonZeroSignature;
    } else {
        var builders = try state.inner.get("builders");
        var builder: types.gloas.Builder.Type = undefined;
        try builders.getValue(allocator, builder_index, &builder);

        const finalized_epoch = try state.finalizedEpoch();
        if (!isActiveBuilder(&builder, finalized_epoch)) return error.BuilderNotActive;
        if (builder.version != c.PAYLOAD_BUILDER_VERSION) return error.InvalidBuilderVersion;

        if (!(try canBuilderCoverBid(allocator, state, builder_index, amount))) return error.BuilderInsufficientBalance;

        if (!(try verifyExecutionPayloadBidSignature(allocator, config, state_slot, &builder.pubkey, signed_bid))) return error.InvalidBidSignature;
    }

    if (bid.slot != state_slot) return error.BidSlotMismatch;
    if (state_slot <= c.GENESIS_SLOT) return error.ExecutionPayloadBidAtGenesis;

    const latest_block_hash = try state.inner.getFieldRoot("latest_block_hash");
    if (!std.mem.eql(u8, &bid.parent_block_hash, latest_block_hash)) return error.BidParentBlockHashMismatch;

    const parent_block_root = try getBlockRootAtSlot(.gloas, state, state_slot - 1);
    if (!std.mem.eql(u8, &bid.parent_block_root, parent_block_root)) return error.BidParentBlockRootMismatch;

    const current_epoch = computeEpochAtSlot(state_slot);
    const state_randao = try getRandaoMix(.gloas, state, current_epoch);
    if (!std.mem.eql(u8, &bid.prev_randao, state_randao)) return error.BidPrevRandaoMismatch;

    // Verify commitments are under limit
    const max_blobs_per_block = config.getMaxBlobsPerBlock(current_epoch);
    if (bid.blob_kzg_commitments.items.len > max_blobs_per_block) return error.TooManyBlobCommitments;

    if (amount > 0) {
        const pending_payment = types.gloas.BuilderPendingPayment.Type{
            .weight = 0,
            .withdrawal = .{
                .fee_recipient = bid.fee_recipient,
                .amount = amount,
                .builder_index = builder_index,
            },
            .proposer_index = try epoch_cache.getBeaconProposer(state_slot),
        };
        var builder_pending_payments = try state.inner.get("builder_pending_payments");
        const payment_index = preset.SLOTS_PER_EPOCH + (bid.slot % preset.SLOTS_PER_EPOCH);
        try builder_pending_payments.setValue(payment_index, &pending_payment);
    }

    try state.inner.setValue("latest_execution_payload_bid", bid);
}

fn verifyExecutionPayloadBidSignature(
    allocator: Allocator,
    config: *const BeaconConfig,
    state_slot: u64,
    pubkey: *const [48]u8,
    signed_bid: *const types.gloas.SignedExecutionPayloadBid.Type,
) !bool {
    const signing_root = try getExecutionPayloadBidSigningRoot(allocator, config, state_slot, &signed_bid.message);

    const public_key = bls.PublicKey.uncompress(pubkey) catch return false;
    const signature = bls.Signature.uncompress(&signed_bid.signature) catch return false;
    verify(&signing_root, &public_key, &signature, .{}) catch return false;
    return true;
}
