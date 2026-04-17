const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;

const ExecutionPayloadBid = ct.gloas.ExecutionPayloadBid;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const BLSPubkey = ct.primitive.BLSPubkey.Type;
const BitVector = @import("ssz").BitVector;
const ExecPayloadAvailability = BitVector(preset.SLOTS_PER_HISTORICAL_ROOT);
const isValidatorKnown = @import("../utils/electra.zig").isValidatorKnown;
const isValidDepositSignature = @import("../block/process_deposit.zig").isValidDepositSignature;
const applyDepositForBuilder = @import("../block/process_deposit_request.zig").applyDepositForBuilder;
const gloas_utils = @import("../utils/gloas.zig");
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const isBuilderWithdrawalCredential = gloas_utils.isBuilderWithdrawalCredential;
const isPubkeyInList = gloas_utils.isPubkeyInList;
const initializePtcWindow = gloas_utils.initializePtcWindow;

pub fn upgradeStateToGloas(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    fulu_state: *BeaconState(.fulu),
) !BeaconState(.gloas) {
    const block_hash_ptr = try fulu_state.latestExecutionPayloadHeaderBlockHash();
    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, block_hash_ptr);

    var state = try fulu_state.upgradeUnsafe();
    errdefer state.deinit();

    const new_fork = ct.phase0.Fork.Type{
        .previous_version = try fulu_state.forkCurrentVersion(),
        .current_version = config.chain.GLOAS_FORK_VERSION,
        .epoch = epoch_cache.epoch,
    };
    try state.setFork(&new_fork);

    var bid = ExecutionPayloadBid.default_value;
    bid.block_hash = block_hash;
    try state.inner.setValue("latest_execution_payload_bid", &bid);

    try state.inner.setValue("latest_block_hash", &block_hash);

    const availability = ExecPayloadAvailability{ .data = [_]u8{0xFF} ** @divExact(ExecPayloadAvailability.length, 8) };
    try state.inner.setValue("execution_payload_availability", &availability);

    const ptc_window = try initializePtcWindow(.gloas, allocator, epoch_cache, &state);
    try state.inner.setValue("ptc_window", &ptc_window);

    try onboardBuildersFromPendingDeposits(allocator, config, epoch_cache, &state);

    fulu_state.deinit();
    return state;
}

fn onboardBuildersFromPendingDeposits(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
) !void {
    var remaining_pending_deposits = std.ArrayList(PendingDeposit).init(allocator);
    defer remaining_pending_deposits.deinit();

    var new_validator_pubkeys = std.ArrayList(BLSPubkey).init(allocator);
    defer new_validator_pubkeys.deinit();

    var pending_deposits = try state.pendingDeposits();
    const pending_deposits_len = try pending_deposits.length();
    var pending_it = pending_deposits.iteratorReadonly(0);

    for (0..pending_deposits_len) |_| {
        const deposit = try pending_it.nextValue(allocator);

        const validator_index = epoch_cache.getValidatorIndex(&deposit.pubkey);
        if ((try isValidatorKnown(.gloas, state, validator_index)) or
            isPubkeyInList(new_validator_pubkeys.items, &deposit.pubkey))
        {
            try remaining_pending_deposits.append(deposit);
            continue;
        }

        const is_existing_builder = (try findBuilderIndexByPubkey(allocator, state, &deposit.pubkey)) != null;
        if (is_existing_builder or isBuilderWithdrawalCredential(&deposit.withdrawal_credentials)) {
            try applyDepositForBuilder(allocator, config, state, &deposit.pubkey, &deposit.withdrawal_credentials, deposit.amount, deposit.signature, deposit.slot);
            continue;
        }

        if (isValidDepositSignature(config, &deposit.pubkey, &deposit.withdrawal_credentials, deposit.amount, deposit.signature)) {
            try new_validator_pubkeys.append(deposit.pubkey);
            try remaining_pending_deposits.append(deposit);
        }
    }

    var new_pending = try pending_deposits.sliceFrom(pending_deposits_len);
    for (remaining_pending_deposits.items) |dep| {
        try new_pending.pushValue(&dep);
    }
    try state.setPendingDeposits(new_pending);
}
