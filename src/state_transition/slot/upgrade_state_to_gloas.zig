const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");

const ExecutionPayloadBid = ct.gloas.ExecutionPayloadBid;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const BitVector = @import("ssz").BitVector;
const ExecPayloadAvailability = BitVector(preset.SLOTS_PER_HISTORICAL_ROOT);
const isValidatorKnown = @import("../utils/electra.zig").isValidatorKnown;
const validateDepositSignature = @import("../block/process_deposit.zig").validateDepositSignature;
const gloas_utils = @import("../utils/gloas.zig");
const addBuilderToRegistry = gloas_utils.addBuilderToRegistry;
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const isBuilderWithdrawalCredential = gloas_utils.isBuilderWithdrawalCredential;
const initializePtcWindow = gloas_utils.initializePtcWindow;
const PendingDepositsLookup = @import("../utils/pending_deposits_lookup.zig").PendingDepositsLookup;

pub fn upgradeStateToGloas(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    fulu_state: *BeaconState(.fulu),
) !BeaconState(.gloas) {
    const block_hash_ptr = try fulu_state.latestExecutionPayloadHeaderBlockHash();
    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, block_hash_ptr);

    var latest_execution_payload_header = ct.fulu.ExecutionPayloadHeader.default_value;
    try fulu_state.latestExecutionPayloadHeader(allocator, &latest_execution_payload_header);
    defer ct.fulu.ExecutionPayloadHeader.deinit(allocator, &latest_execution_payload_header);

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
    bid.gas_limit = latest_execution_payload_header.gas_limit;
    try ct.gloas.ExecutionRequests.hashTreeRoot(allocator, &ct.gloas.ExecutionRequests.default_value, &bid.execution_requests_root);
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
    var remaining_pending_deposits: std.ArrayList(PendingDeposit) = .empty;
    defer remaining_pending_deposits.deinit(allocator);

    var pending_deposits_lookup = PendingDepositsLookup.buildEmpty(allocator);
    defer pending_deposits_lookup.deinit();

    var pending_deposits = try state.pendingDeposits();
    const pending_deposits_len = try pending_deposits.length();
    var pending_it = pending_deposits.iteratorReadonly(0);

    for (0..pending_deposits_len) |_| {
        const deposit = try pending_it.nextValue(allocator);

        const validator_index = epoch_cache.getValidatorIndex(&deposit.pubkey);
        if (try isValidatorKnown(.gloas, state, validator_index)) {
            try remaining_pending_deposits.append(allocator, deposit);
            try pending_deposits_lookup.add(&deposit);
            continue;
        }

        const builder_index = try findBuilderIndexByPubkey(allocator, state, &deposit.pubkey);
        if (builder_index) |idx| {
            var builders = try state.inner.get("builders");
            var builder: ct.gloas.Builder.Type = undefined;
            try builders.getValue(allocator, idx, &builder);
            builder.balance += deposit.amount;
            try builders.setValue(idx, &builder);
            continue;
        } else {
            if (!isBuilderWithdrawalCredential(&deposit.withdrawal_credentials)) {
                try remaining_pending_deposits.append(allocator, deposit);
                try pending_deposits_lookup.add(&deposit);
                continue;
            }

            if (try pending_deposits_lookup.hasPendingValidator(config, &deposit.pubkey)) {
                try remaining_pending_deposits.append(allocator, deposit);
                try pending_deposits_lookup.add(&deposit);
                continue;
            }
        }

        validateDepositSignature(config, &deposit.pubkey, &deposit.withdrawal_credentials, deposit.amount, deposit.signature) catch continue;

        var execution_address: ct.primitive.ExecutionAddress.Type = undefined;
        @memcpy(&execution_address, deposit.withdrawal_credentials[12..32]);
        try addBuilderToRegistry(
            allocator,
            state,
            &deposit.pubkey,
            c.PAYLOAD_BUILDER_VERSION,
            &execution_address,
            deposit.amount,
            deposit.slot,
        );
    }

    var new_pending = try pending_deposits.sliceFrom(pending_deposits_len);
    for (remaining_pending_deposits.items) |dep| {
        try new_pending.pushValue(&dep);
    }
    try state.setPendingDeposits(new_pending);
}
