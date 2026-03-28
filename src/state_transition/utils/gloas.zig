const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const getBlockRootAtSlot = @import("./block_root.zig").getBlockRootAtSlot;
const computeEpochAtSlot = @import("./epoch.zig").computeEpochAtSlot;
const RootCache = @import("../cache/root_cache.zig").RootCache;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;

const BLSPubkey = ct.primitive.BLSPubkey.Type;

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

pub fn initiateBuilderExit(state: *BeaconState(.gloas), allocator: Allocator, builder_index: u64) !void {
    var builders = try state.inner.get("builders");
    var builder: ct.gloas.Builder.Type = undefined;
    try builders.getValue(allocator, builder_index, &builder);

    if (builder.withdrawable_epoch != c.FAR_FUTURE_EPOCH) return;

    const current_epoch = computeEpochAtSlot(try state.slot());
    builder.withdrawable_epoch = current_epoch + c.MIN_BUILDER_WITHDRAWABILITY_DELAY;
    try builders.setValue(builder_index, &builder);
}

pub fn findBuilderIndexByPubkey(allocator: Allocator, state: *BeaconState(.gloas), pubkey: *const BLSPubkey) !?usize {
    var builders = try state.inner.get("builders");
    const len = try builders.length();
    var it = builders.iteratorReadonly(0);
    for (0..len) |i| {
        const b = try it.nextValue(allocator);
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

