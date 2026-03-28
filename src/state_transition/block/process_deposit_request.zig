const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const DepositRequest = types.electra.DepositRequest.Type;
const PendingDeposit = types.electra.PendingDeposit.Type;
const Builder = types.gloas.Builder;
const BLSPubkey = types.primitive.BLSPubkey.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const c = @import("constants");
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const gloas_utils = @import("../utils/gloas.zig");
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const isBuilderWithdrawalCredential = gloas_utils.isBuilderWithdrawalCredential;
const isValidDepositSignature = @import("./process_deposit.zig").isValidDepositSignature;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;

pub fn processDepositRequest(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    deposit_request: *const DepositRequest,
) !void {
    const pubkey = &deposit_request.pubkey;
    const withdrawal_credentials = &deposit_request.withdrawal_credentials;
    const amount = deposit_request.amount;
    const signature = deposit_request.signature;

    // Check if this is a builder or validator deposit
    if (fork.gte(.gloas)) {
        const builder_index = try findBuilderIndexByPubkey(allocator, state, pubkey);
        const validator_index = epoch_cache.getValidatorIndex(pubkey);

        const is_builder = builder_index != null;
        const is_validator = validator_index != null;
        const is_builder_prefix = isBuilderWithdrawalCredential(withdrawal_credentials);

        // Route to builder if it's an existing builder OR has builder prefix and is not a validator
        if (is_builder or (is_builder_prefix and !is_validator)) {
            // Apply builder deposits immediately
            try applyDepositForBuilder(allocator, config, state, pubkey, withdrawal_credentials, amount, signature, try state.slot());
            return;
        }
    }

    // Only set deposit_requests_start_index in Electra fork, not after EIP-7732
    if (comptime fork.lt(.gloas)) {
        const deposit_requests_start_index = try state.depositRequestsStartIndex();
        if (deposit_requests_start_index == c.UNSET_DEPOSIT_REQUESTS_START_INDEX) {
            try state.setDepositRequestsStartIndex(deposit_request.index);
        }
    }

    // Add validator deposits to the queue
    const pending_deposit = PendingDeposit{
        .pubkey = deposit_request.pubkey,
        .withdrawal_credentials = deposit_request.withdrawal_credentials,
        .amount = deposit_request.amount,
        .signature = deposit_request.signature,
        .slot = try state.slot(),
    };

    var pending_deposits = try state.pendingDeposits();
    try pending_deposits.pushValue(&pending_deposit);
}

pub fn applyDepositForBuilder(
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *BeaconState(.gloas),
    pubkey: *const BLSPubkey,
    withdrawal_credentials: *const [32]u8,
    amount: u64,
    signature: BLSSignature,
    slot: u64,
) !void {
    const builderIndex = try findBuilderIndexByPubkey(allocator, state, pubkey);

    if (builderIndex) |idx| {
        var builders = try state.inner.get("builders");
        var existing: Builder.Type = undefined;
        try builders.getValue(allocator, idx, &existing);
        existing.balance += amount;
        try builders.setValue(idx, &existing);
    } else {
        if (!isValidDepositSignature(config, pubkey, withdrawal_credentials, amount, signature)) return;
        try addBuilderToRegistry(allocator, state, pubkey, withdrawal_credentials, amount, slot);
    }
}

fn addBuilderToRegistry(
    allocator: Allocator,
    state: *BeaconState(.gloas),
    pubkey: *const BLSPubkey,
    withdrawal_credentials: *const [32]u8,
    amount: u64,
    slot: u64,
) !void {
    var builders = try state.inner.get("builders");
    const len = try builders.length();
    const current_epoch = computeEpochAtSlot(try state.slot());

    var builderIndex: ?usize = null;
    var it = builders.iteratorReadonly(0);
    for (0..len) |i| {
        const b = try it.nextValue(allocator);
        if (b.withdrawable_epoch <= current_epoch and b.balance == 0) {
            builderIndex = i;
            break;
        }
    }

    const new_builder = Builder.Type{
        .pubkey = pubkey.*,
        .version = withdrawal_credentials[0],
        .execution_address = withdrawal_credentials[12..32].*,
        .balance = amount,
        .deposit_epoch = computeEpochAtSlot(slot),
        .withdrawable_epoch = c.FAR_FUTURE_EPOCH,
    };

    if (builderIndex) |idx| {
        try builders.setValue(idx, &new_builder);
    } else {
        try builders.pushValue(&new_builder);
    }
}
