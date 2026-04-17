const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const getBlockRootAtSlot = @import("./block_root.zig").getBlockRootAtSlot;
const computeEpochAtSlot = @import("./epoch.zig").computeEpochAtSlot;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const computePayloadTimelinessCommitteeForSlot = @import("./seed.zig").computePayloadTimelinessCommitteeForSlot;
const computePayloadTimelinessCommitteesForEpoch = @import("./seed.zig").computePayloadTimelinessCommitteesForEpoch;
const getSeed = @import("./seed.zig").getSeed;
const Sha256 = std.crypto.hash.sha2.Sha256;
const EpochShuffling = @import("./epoch_shuffling.zig").EpochShuffling;
const computeEpochShuffling = @import("./epoch_shuffling.zig").computeEpochShuffling;
const isActiveValidator = @import("./validator.zig").isActiveValidator;
const computeStartSlotAtEpoch = @import("./epoch.zig").computeStartSlotAtEpoch;
const RootCache = @import("../cache/root_cache.zig").RootCache;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const isValidDepositSignature = @import("../block/process_deposit.zig").isValidDepositSignature;

const BLSPubkey = ct.primitive.BLSPubkey.Type;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

pub fn isBuilderWithdrawalCredential(withdrawal_credentials: *const [32]u8) bool {
    return withdrawal_credentials[0] == c.BUILDER_WITHDRAWAL_PREFIX;
}

pub fn getBuilderPaymentQuorumThreshold(epoch_cache: *const EpochCache) u64 {
    const quorum = (epoch_cache.total_active_balance_increments * preset.EFFECTIVE_BALANCE_INCREMENT / preset.SLOTS_PER_EPOCH) *
        c.BUILDER_PAYMENT_THRESHOLD_NUMERATOR;
    return quorum / c.BUILDER_PAYMENT_THRESHOLD_DENOMINATOR;
}

fn hasBuilderIndexFlag(index: u64) bool {
    return (index & c.BUILDER_INDEX_FLAG) != 0;
}

pub fn isBuilderIndex(validator_index: u64) bool {
    return hasBuilderIndexFlag(validator_index);
}

pub fn convertBuilderIndexToValidatorIndex(builder_index: u64) u64 {
    return if (hasBuilderIndexFlag(builder_index)) builder_index else builder_index | c.BUILDER_INDEX_FLAG;
}

pub fn convertValidatorIndexToBuilderIndex(validator_index: u64) u64 {
    return if (hasBuilderIndexFlag(validator_index)) validator_index & ~c.BUILDER_INDEX_FLAG else validator_index;
}

pub fn isActiveBuilder(builder: *const ct.gloas.Builder.Type, finalized_epoch: u64) bool {
    return builder.deposit_epoch < finalized_epoch and builder.withdrawable_epoch == c.FAR_FUTURE_EPOCH;
}

pub fn getPendingBalanceToWithdrawForBuilder(allocator: Allocator, state: *BeaconState(.gloas), builder_index: u64) !u64 {
    var pending_balance: u64 = 0;

    var withdrawals = try state.inner.get("builder_pending_withdrawals");
    const withdrawals_len = try withdrawals.length();
    var w_it = withdrawals.iteratorReadonly(0);
    for (0..withdrawals_len) |_| {
        const w = try w_it.nextValue(allocator);
        if (w.builder_index == builder_index) {
            pending_balance += w.amount;
        }
    }

    var payments = try state.inner.get("builder_pending_payments");
    const payments_len = ct.gloas.BeaconState.getFieldType("builder_pending_payments").length;
    for (0..payments_len) |i| {
        var p: ct.gloas.BuilderPendingPayment.Type = undefined;
        try payments.getValue(allocator, i, &p);
        if (p.withdrawal.builder_index == builder_index) {
            pending_balance += p.withdrawal.amount;
        }
    }

    return pending_balance;
}

pub fn canBuilderCoverBid(allocator: Allocator, state: *BeaconState(.gloas), builder_index: u64, bid_amount: u64) !bool {
    var builders = try state.inner.get("builders");
    var builder: ct.gloas.Builder.Type = undefined;
    try builders.getValue(allocator, builder_index, &builder);

    const pending_balance = try getPendingBalanceToWithdrawForBuilder(allocator, state, builder_index);
    const min_balance = preset.MIN_DEPOSIT_AMOUNT + pending_balance;

    if (builder.balance < min_balance) return false;
    return builder.balance - min_balance >= bid_amount;
}

pub fn initiateBuilderExit(config: *const BeaconConfig, state: *BeaconState(.gloas), allocator: Allocator, builder_index: u64) !void {
    var builders = try state.inner.get("builders");
    var builder: ct.gloas.Builder.Type = undefined;
    try builders.getValue(allocator, builder_index, &builder);

    if (builder.withdrawable_epoch != c.FAR_FUTURE_EPOCH) return;

    const current_epoch = computeEpochAtSlot(try state.slot());
    builder.withdrawable_epoch = current_epoch + config.chain.MIN_BUILDER_WITHDRAWABILITY_DELAY;
    try builders.setValue(builder_index, &builder);
}

pub fn findBuilderIndexByPubkey(allocator: Allocator, state: *BeaconState(.gloas), pubkey: *const BLSPubkey) !?usize {
    var builders = try state.inner.get("builders");
    const len = try builders.length();
    for (0..len) |i| {
        var b: ct.gloas.Builder.Type = undefined;
        try builders.getValue(allocator, i, &b);
        if (std.mem.eql(u8, &b.pubkey, pubkey)) return i;
    }
    return null;
}

pub fn isAttestationSameSlot(state: *BeaconState(.gloas), data: *const ct.phase0.AttestationData.Type) !bool {
    if (data.slot == 0) return true;

    const block_root = try getBlockRootAtSlot(.gloas, state, data.slot);
    const is_matching = std.mem.eql(u8, &data.beacon_block_root, block_root);

    const prev_block_root = try getBlockRootAtSlot(.gloas, state, data.slot - 1);
    const is_current = !std.mem.eql(u8, &data.beacon_block_root, prev_block_root);

    return is_matching and is_current;
}

pub fn isAttestationSameSlotRootCache(root_cache: *RootCache(.gloas), data: *const ct.phase0.AttestationData.Type) !bool {
    if (data.slot == 0) return true;

    const block_root = try root_cache.getBlockRootAtSlot(data.slot);
    const is_matching = std.mem.eql(u8, &data.beacon_block_root, block_root);

    const prev_block_root = try root_cache.getBlockRootAtSlot(data.slot - 1);
    const is_current = !std.mem.eql(u8, &data.beacon_block_root, prev_block_root);

    return is_matching and is_current;
}

// TODO: Need to check if these are used at all
/// computePayloadTimelinessCommitteeIndices uses the optimized increments-based check instead.
pub fn isBalanceWeightedAcceptance(effective_balance: u64, random_value: u64) bool {
    const MAX_RANDOM_VALUE: u64 = 0xFFFF;
    return effective_balance * MAX_RANDOM_VALUE >= preset.MAX_EFFECTIVE_BALANCE_ELECTRA * random_value;
}

// TODO: Need to check if these are used at all
/// computePayloadTimelinessCommitteeIndices inlines this logic with increments instead of full Gwei balances.
pub fn computeBalanceWeightedAcceptance(effective_balance: u64, seed: *const [32]u8, i: u64) bool {
    var hash_input: [40]u8 = undefined;
    @memcpy(hash_input[0..32], seed);
    std.mem.writeInt(u64, hash_input[32..][0..8], i / 16, .little);

    var random_bytes: [32]u8 = undefined;
    Sha256.hash(&hash_input, &random_bytes, .{});

    const offset: usize = @intCast((i % 16) * 2);
    const random_value: u64 = std.mem.readInt(u16, random_bytes[offset..][0..2], .little);

    return isBalanceWeightedAcceptance(effective_balance, random_value);
}

pub fn isParentBlockFull(state: *BeaconState(.gloas)) !bool {
    var bid = try state.inner.get("latest_execution_payload_bid");
    const bid_block_hash = try bid.getFieldRoot("block_hash");
    const latest_block_hash = try state.inner.getFieldRoot("latest_block_hash");
    return std.mem.eql(u8, bid_block_hash, latest_block_hash);
}

pub fn isPubkeyInList(list: []const BLSPubkey, pubkey: *const BLSPubkey) bool {
    for (list) |p| {
        if (std.mem.eql(u8, &p, pubkey)) return true;
    }
    return false;
}

pub fn isPendingValidator(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *BeaconState(fork),
    pubkey: *const BLSPubkey,
) !bool {
    var pending_deposits = try state.pendingDeposits();
    const pending_deposits_len = try pending_deposits.length();
    var pending_it = pending_deposits.iteratorReadonly(0);

    for (0..pending_deposits_len) |_| {
        const pending_deposit = try pending_it.nextValue(allocator);
        if (!std.mem.eql(u8, &pending_deposit.pubkey, pubkey)) {
            continue;
        }

        if (isValidDepositSignature(
            config,
            &pending_deposit.pubkey,
            &pending_deposit.withdrawal_credentials,
            pending_deposit.amount,
            pending_deposit.signature,
        )) {
            return true;
        }
    }

    return false;
}

pub fn computePtc(
    allocator: Allocator,
    state: *BeaconState(.gloas),
    slot: u64,
    shuffling: ?*EpochShuffling,
    effective_balance_increments: []const u16,
) ![ct.gloas.PtcWindow.Element.length]ValidatorIndex {
    const epoch = computeEpochAtSlot(slot);

    const epoch_shuffling = if (shuffling) |s| s else blk: {
        var validators = try state.validators();
        const validator_count = try validators.length();
        var active_indices = std.ArrayList(ValidatorIndex).init(allocator);
        for (0..validator_count) |i| {
            var validator: ct.phase0.Validator.Type = undefined;
            try validators.getValue(undefined, i, &validator);
            if (isActiveValidator(&validator, epoch)) {
                try active_indices.append(@intCast(i));
            }
        }
        var any_state = AnyBeaconState{ .gloas = state.inner };
        break :blk try computeEpochShuffling(allocator, &any_state, try active_indices.toOwnedSlice(), epoch);
    };
    defer if (shuffling == null) epoch_shuffling.deinit();

    var epoch_seed: [32]u8 = undefined;
    try getSeed(.gloas, state, epoch, c.DOMAIN_PTC_ATTESTER, &epoch_seed);

    var slot_seed_input: [40]u8 = undefined;
    @memcpy(slot_seed_input[0..32], &epoch_seed);
    std.mem.writeInt(u64, slot_seed_input[32..][0..8], slot, .little);

    var slot_seed: [32]u8 = undefined;
    Sha256.hash(&slot_seed_input, &slot_seed, .{});

    const slot_committees = epoch_shuffling.committees[slot % preset.SLOTS_PER_EPOCH];
    return computePayloadTimelinessCommitteeForSlot(allocator, &slot_seed, slot_committees, effective_balance_increments);
}

pub fn initializePtcWindow(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
) ![ct.gloas.PtcWindow.length][ct.gloas.PtcWindow.Element.length]ValidatorIndex {
    const PtcSize = ct.gloas.PtcWindow.Element.length;
    const PtcWindowLen = ct.gloas.PtcWindow.length;

    const empty_previous_epoch = [_][PtcSize]ValidatorIndex{
        [_]ValidatorIndex{0} ** PtcSize,
    } ** preset.SLOTS_PER_EPOCH;

    const current_epoch = computeEpochAtSlot(try state.slot());
    var current_and_lookahead: [(1 + preset.MIN_SEED_LOOKAHEAD) * preset.SLOTS_PER_EPOCH][PtcSize]ValidatorIndex = undefined;
    for (0..1 + preset.MIN_SEED_LOOKAHEAD) |epoch_offset| {
        const epoch = current_epoch + epoch_offset;
        const epoch_committees = try computePayloadTimelinessCommitteesForEpoch(
            fork,
            allocator,
            state,
            epoch,
            epoch_cache,
        );
        for (0..preset.SLOTS_PER_EPOCH) |slot_index| {
            current_and_lookahead[epoch_offset * preset.SLOTS_PER_EPOCH + slot_index] = epoch_committees[slot_index];
        }
    }

    // return empty_previous_epoch + current_and_lookahead
    var ptc_window: [PtcWindowLen][PtcSize]ValidatorIndex = undefined;
    @memcpy(ptc_window[0..preset.SLOTS_PER_EPOCH], &empty_previous_epoch);
    @memcpy(ptc_window[preset.SLOTS_PER_EPOCH..], &current_and_lookahead);

    return ptc_window;
}
