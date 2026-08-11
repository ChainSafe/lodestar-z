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

const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const interopSign = @import("../test_utils/root.zig").interopSign;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;

fn addTestBuilder(state: *BeaconState(.gloas), amount: u64) !void {
    var validators = try state.validators();
    var validator: types.phase0.Validator.Type = undefined;
    try validators.getValue(undefined, 0, &validator);

    const builder = types.gloas.Builder.Type{
        .pubkey = validator.pubkey,
        .version = c.PAYLOAD_BUILDER_VERSION,
        .execution_address = [_]u8{0x42} ** 20,
        .balance = preset.MIN_DEPOSIT_AMOUNT + amount,
        .deposit_epoch = 0,
        .withdrawable_epoch = c.FAR_FUTURE_EPOCH,
    };
    var builders = try state.inner.get("builders");
    try builders.pushValue(&builder);
    try state.inner.set("builders", builders);
    try state.commit();
}

fn makeSignedTestBid(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    amount: u64,
) !types.gloas.SignedExecutionPayloadBid.Type {
    const slot = try state.slot();
    const parent_block_hash = try state.inner.getFieldRoot("latest_block_hash");
    const parent_block_root = try getBlockRootAtSlot(.gloas, state, slot - 1);
    const prev_randao = try getRandaoMix(.gloas, state, epoch_cache.epoch);

    var signed_bid = types.gloas.SignedExecutionPayloadBid.default_value;
    signed_bid.message.parent_block_hash = parent_block_hash.*;
    signed_bid.message.parent_block_root = parent_block_root.*;
    signed_bid.message.prev_randao = prev_randao.*;
    signed_bid.message.builder_index = 0;
    signed_bid.message.slot = slot;
    signed_bid.message.value = amount;
    try signed_bid.message.blob_kzg_commitments.append(
        allocator,
        types.primitive.KZGCommitment.default_value,
    );

    const signing_root = try getExecutionPayloadBidSigningRoot(allocator, config, slot, &signed_bid.message);
    signed_bid.signature = (try interopSign(0, &signing_root)).compress();
    return signed_bid;
}

fn tryExternalBuilderBid(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    baseline: *BeaconState(.gloas),
    signed_bid: *const types.gloas.SignedExecutionPayloadBid.Type,
) !void {
    var state = try baseline.clone(.{ .transfer_cache = false });
    defer state.deinit();
    try processExecutionPayloadBid(allocator, config, epoch_cache, &state, signed_bid);
}

test "Gloas external builder bid - OOM does not leak or double-free transient allocations" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.initGloas(allocator, &pool, 256);
    defer test_state.deinit();
    const state = test_state.cached_state.state.castToFork(.gloas);
    const bid_amount = 1;
    try addTestBuilder(state, bid_amount);

    var signed_bid = try makeSignedTestBid(
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        state,
        bid_amount,
    );
    defer types.gloas.SignedExecutionPayloadBid.deinit(allocator, &signed_bid);

    var saw_oom = false;
    var saw_success = false;
    var fail_at: usize = 0;
    while (fail_at < 128) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();

        tryExternalBuilderBid(
            oom.allocator(),
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            state,
            &signed_bid,
        ) catch |err| switch (err) {
            error.OutOfMemory => {
                saw_oom = true;
                try std.testing.expect(!oom.double_free);
                continue;
            },
            else => return err,
        };

        try std.testing.expect(!oom.double_free);
        saw_success = true;
        break;
    }

    try std.testing.expect(saw_oom);
    try std.testing.expect(saw_success);
}
