const std = @import("std");
const Allocator = std.mem.Allocator;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const preset = @import("preset").preset;
const c = @import("constants");
const ForkSeq = @import("config").ForkSeq;
const Withdrawals = types.capella.Withdrawals.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const ExecutionAddress = types.primitive.ExecutionAddress.Type;
const hasExecutionWithdrawalCredential = @import("../utils/electra.zig").hasExecutionWithdrawalCredential;
const hasEth1WithdrawalCredential = @import("../utils/capella.zig").hasEth1WithdrawalCredential;
const getMaxEffectiveBalance = @import("../utils/validator.zig").getMaxEffectiveBalance;
const isFullyWithdrawableValidator = @import("../utils/validator.zig").isFullyWithdrawableValidator;
const isPartiallyWithdrawableValidator = @import("../utils/validator.zig").isPartiallyWithdrawableValidator;
const decreaseBalance = @import("../utils/balance.zig").decreaseBalance;
const gloas_utils = @import("../utils/gloas.zig");
const isBuilderIndex = gloas_utils.isBuilderIndex;
const convertBuilderIndexToValidatorIndex = gloas_utils.convertBuilderIndexToValidatorIndex;
const convertValidatorIndexToBuilderIndex = gloas_utils.convertValidatorIndexToBuilderIndex;
const isParentBlockFull = gloas_utils.isParentBlockFull;
const Node = @import("persistent_merkle_tree").Node;
const Withdrawal = types.capella.Withdrawal.Type;
const Epoch = types.primitive.Epoch.Type;

pub const WithdrawalsResult = struct {
    withdrawals: Withdrawals,
    processed_validator_sweep_count: usize = 0,
    processed_partial_withdrawals_count: usize = 0,
    // processedBuilderWithdrawalsCount is withdrawals coming from builder payment since EIP-7732
    processed_builder_withdrawals_count: usize = 0,
    // processedBuildersSweepCount is withdrawals from builder sweep since EIP-7732
    processed_builders_sweep_count: usize = 0,
};

/// right now for the implementation we pass in processBlock()
/// for the spec, we pass in params from operations.zig
/// TODO: spec and implementation should be the same
/// refer to https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-process_withdrawals
pub fn processWithdrawals(
    comptime fork: ForkSeq,
    allocator: Allocator,
    state: *BeaconState(fork),
    expected_withdrawals_result: WithdrawalsResult,
    payload_withdrawals_root: Root,
) !void {
    // [New in EIP-7732] Return early if parent block is empty
    if (comptime fork.gte(.gloas)) {
        if (!(try isParentBlockFull(state))) return;
    }

    const expected_withdrawals = expected_withdrawals_result.withdrawals.items;

    // After EIP-7732, withdrawals are verified later in processExecutionPayloadEnvelope
    if (comptime fork.lt(.gloas)) {
        var expected_withdrawals_root: [32]u8 = undefined;
        try types.capella.Withdrawals.hashTreeRoot(allocator, &expected_withdrawals_result.withdrawals, &expected_withdrawals_root);
        if (!std.mem.eql(u8, &expected_withdrawals_root, &payload_withdrawals_root)) {
            return error.WithdrawalsRootMismatch;
        }
    }

    try applyWithdrawals(fork, allocator, state, expected_withdrawals);
    // Update pending_partial_withdrawals (electra+)
    if (comptime fork.gte(.electra)) {
        var pending_partial_withdrawals = try state.pendingPartialWithdrawals();
        const truncated = try pending_partial_withdrawals.sliceFrom(expected_withdrawals_result.processed_partial_withdrawals_count);
        try state.setPendingPartialWithdrawals(truncated);
    }

    if (comptime fork.gte(.gloas)) {
        // Store expected withdrawals for verification in processExecutionPayloadEnvelope
        var payload_expected_withdrawals = try state.inner.get("payload_expected_withdrawals");
        const current_len = try payload_expected_withdrawals.length();
        var new_list = try payload_expected_withdrawals.sliceFrom(current_len);
        for (expected_withdrawals) |w| {
            try new_list.pushValue(&w);
        }
        try state.inner.set("payload_expected_withdrawals", new_list);

        // Update builder pending withdrawals queue
        const processed_builder_withdrawals_count = expected_withdrawals_result.processed_builder_withdrawals_count;
        if (processed_builder_withdrawals_count > 0) {
            var builder_pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
            const truncated = try builder_pending_withdrawals.sliceFrom(processed_builder_withdrawals_count);
            try state.inner.set("builder_pending_withdrawals", truncated);
        }

        // Update next builder index for sweep
        var builders = try state.inner.get("builders");
        const builders_len: u64 = try builders.length();
        if (builders_len > 0) {
            const current_builder_index: u64 = try state.inner.get("next_withdrawal_builder_index");
            const processed_builders_sweep_count: u64 = @intCast(expected_withdrawals_result.processed_builders_sweep_count);
            const next_builder_index = (current_builder_index + processed_builders_sweep_count) % builders_len;
            try state.inner.set("next_withdrawal_builder_index", next_builder_index);
        }
    }

    // Update the nextWithdrawalIndex
    const latest_withdrawal = if (expected_withdrawals.len > 0) expected_withdrawals[expected_withdrawals.len - 1] else null;
    if (latest_withdrawal) |lw| {
        try state.setNextWithdrawalIndex(lw.index + 1);
    }

    // Update the next_withdrawal_validator_index
    const validators_len: u64 = @intCast(try state.validatorsCount());
    const next_withdrawal_validator_index = try state.nextWithdrawalValidatorIndex();
    if (latest_withdrawal != null and expected_withdrawals.len == preset.MAX_WITHDRAWALS_PER_PAYLOAD) {
        // All slots filled, next_withdrawal_validator_index should be validatorIndex having next turn
        try state.setNextWithdrawalValidatorIndex(
            (latest_withdrawal.?.validator_index + 1) % validators_len,
        );
    } else {
        // expected withdrawals came up short in the bound, so we move next_withdrawal_validator_index to
        // the next post the bound
        try state.setNextWithdrawalValidatorIndex(
            (next_withdrawal_validator_index + preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) % validators_len,
        );
    }
}

// Consumer should deinit WithdrawalsResult with .deinit() after use
pub fn getExpectedWithdrawals(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    withdrawals_result: *WithdrawalsResult,
    withdrawal_balances: *std.AutoHashMap(ValidatorIndex, usize),
) !void {
    if (comptime fork.lt(.capella)) {
        return error.InvalidForkSequence;
    }

    const epoch = epoch_cache.epoch;
    var withdrawal_index = try state.nextWithdrawalIndex();

    // Separate maps to track balances after applying withdrawals
    var builder_balance_after_withdrawals = std.AutoHashMap(u64, i64).init(allocator);
    defer builder_balance_after_withdrawals.deinit();

    // partialWithdrawalsCount is withdrawals coming from EL since electra (EIP-7002)
    var processed_partial_withdrawals_count: u64 = 0;
    // builderWithdrawalsCount is withdrawals coming from builder payments since EIP-7732
    var processed_builder_withdrawals_count: u64 = 0;
    // buildersSweepCount is withdrawals from builder sweep since EIP-7732
    var processed_builders_sweep_count: u64 = 0;

    // [New in EIP-7732] get_builder_withdrawals
    if (comptime fork.gte(.gloas)) {
        const result = try getBuilderWithdrawals(
            allocator,
            state,
            &withdrawal_index,
            withdrawals_result.withdrawals.items.len,
            &builder_balance_after_withdrawals,
        );
        defer result.withdrawals.deinit();
        for (result.withdrawals.items) |w| {
            try withdrawals_result.withdrawals.append(allocator, w);
        }
        processed_builder_withdrawals_count = result.processed_count;
    }

    // get_pending_partial_withdrawals (electra+)
    if (comptime fork.gte(.electra)) {
        const result = try getPendingPartialWithdrawals(
            fork,
            allocator,
            epoch,
            state,
            &withdrawal_index,
            withdrawals_result.withdrawals.items.len,
            withdrawal_balances,
        );
        defer result.withdrawals.deinit();
        for (result.withdrawals.items) |w| {
            try withdrawals_result.withdrawals.append(allocator, w);
        }
        processed_partial_withdrawals_count = result.processed_count;
    }

    // [New in EIP-7732] get_builders_sweep_withdrawals
    if (comptime fork.gte(.gloas)) {
        const result = try getBuildersSweepWithdrawals(
            allocator,
            state,
            epoch,
            &withdrawal_index,
            withdrawals_result.withdrawals.items.len,
            &builder_balance_after_withdrawals,
        );
        defer result.withdrawals.deinit();
        for (result.withdrawals.items) |w| {
            try withdrawals_result.withdrawals.append(allocator, w);
        }
        processed_builders_sweep_count = result.processed_count;
    }

    // get_validators_sweep_withdrawals
    {
        const result = try getValidatorsSweepWithdrawals(
            fork,
            allocator,
            epoch,
            state,
            &withdrawal_index,
            withdrawals_result.withdrawals.items.len,
            withdrawal_balances,
        );
        defer result.withdrawals.deinit();
        for (result.withdrawals.items) |w| {
            try withdrawals_result.withdrawals.append(allocator, w);
        }
        withdrawals_result.processed_validator_sweep_count = result.processed_count;
    }

    withdrawals_result.processed_partial_withdrawals_count = processed_partial_withdrawals_count;
    withdrawals_result.processed_builder_withdrawals_count = @intCast(processed_builder_withdrawals_count);
    withdrawals_result.processed_builders_sweep_count = @intCast(processed_builders_sweep_count);
}

/// [Modified in EIP-7732] apply_withdrawals handles builder indices
fn applyWithdrawals(
    comptime fork: ForkSeq,
    allocator: Allocator,
    state: *BeaconState(fork),
    withdrawals: []const Withdrawal,
) !void {
    for (withdrawals) |withdrawal| {
        if (fork.gte(.gloas) and isBuilderIndex(withdrawal.validator_index)) {
            // Handle builder withdrawal
            const builder_index = convertValidatorIndexToBuilderIndex(withdrawal.validator_index);
            var builders = try state.inner.get("builders");
            var builder: types.gloas.Builder.Type = undefined;
            try builders.getValue(allocator, builder_index, &builder);
            builder.balance -= @min(withdrawal.amount, builder.balance);
            try builders.setValue(builder_index, &builder);
        } else {
            // Handle validator withdrawal
            try decreaseBalance(fork, state, withdrawal.validator_index, withdrawal.amount);
        }
    }
}

fn getPendingPartialWithdrawals(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch: Epoch,
    state: *BeaconState(fork),
    withdrawal_index: *u64,
    num_prior_withdrawals: usize,
    validator_balance_after_withdrawals: *std.AutoHashMap(ValidatorIndex, usize),
) !struct { withdrawals: std.ArrayList(Withdrawal), processed_count: usize } {
    var pending_partial_withdrawals_result = std.ArrayList(Withdrawal).init(allocator);
    errdefer pending_partial_withdrawals_result.deinit();

    var validators = try state.validators();
    var balances = try state.balances();

    // MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = 8, PENDING_PARTIAL_WITHDRAWALS_LIMIT: 134217728
    // so we lazily iterate. pendingPartialWithdrawals comes from EIP-7002 smart contract
    // where it takes fee so it's more likely than not validator is in correct condition to withdraw.
    // Also we may break early if withdrawableEpoch > epoch.
    var pending_partial_withdrawals = try state.pendingPartialWithdrawals();
    var pending_partial_withdrawals_it = pending_partial_withdrawals.iteratorReadonly(0);
    const pending_partial_withdrawals_len = try pending_partial_withdrawals.length();

    // In pre-EIP-7732, partialWithdrawalBound == MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP
    const partial_withdrawal_bound = @min(
        num_prior_withdrawals + preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
        preset.MAX_WITHDRAWALS_PER_PAYLOAD - 1,
    );
    // There must be at least one space reserved for validator sweep withdrawals
    if (num_prior_withdrawals > partial_withdrawal_bound) {
        return error.PriorWithdrawalsExceedLimit;
    }

    // EIP-7002: Execution layer triggerable withdrawals
    var processed_count: usize = 0;
    for (0..pending_partial_withdrawals_len) |_| {
        const withdrawal = try pending_partial_withdrawals_it.nextValue(undefined);
        if (withdrawal.withdrawable_epoch > epoch or pending_partial_withdrawals_result.items.len + num_prior_withdrawals >= partial_withdrawal_bound) {
            break;
        }
        var validator: types.phase0.Validator.Type = undefined;
        try validators.getValue(undefined, withdrawal.validator_index, &validator);

        const balance_gop = try validator_balance_after_withdrawals.getOrPut(withdrawal.validator_index);
        if (!balance_gop.found_existing) {
            balance_gop.value_ptr.* = try balances.get(withdrawal.validator_index);
        }
        const balance: u64 = balance_gop.value_ptr.*;

        if (validator.exit_epoch == c.FAR_FUTURE_EPOCH and
            validator.effective_balance >= preset.MIN_ACTIVATION_BALANCE and
            balance > preset.MIN_ACTIVATION_BALANCE)
        {
            const balance_over_min_activation_balance = balance - preset.MIN_ACTIVATION_BALANCE;
            const withdrawable_balance = if (balance_over_min_activation_balance < withdrawal.amount) balance_over_min_activation_balance else withdrawal.amount;
            var execution_address: ExecutionAddress = undefined;
            @memcpy(&execution_address, validator.withdrawal_credentials[12..]);
            try pending_partial_withdrawals_result.append(.{
                .index = withdrawal_index.*,
                .validator_index = withdrawal.validator_index,
                .address = execution_address,
                .amount = withdrawable_balance,
            });
            withdrawal_index.* += 1;
            try validator_balance_after_withdrawals.put(withdrawal.validator_index, balance - withdrawable_balance);
        }
        processed_count += 1;
    }

    return .{ .withdrawals = pending_partial_withdrawals_result, .processed_count = processed_count };
}

fn getValidatorsSweepWithdrawals(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch: Epoch,
    state: *BeaconState(fork),
    withdrawal_index: *u64,
    num_prior_withdrawals: usize,
    validator_balance_after_withdrawals: *std.AutoHashMap(ValidatorIndex, usize),
) !struct { withdrawals: std.ArrayList(Withdrawal), processed_count: usize } {
    // There must be at least one space reserved for validator sweep withdrawals
    if (num_prior_withdrawals >= preset.MAX_WITHDRAWALS_PER_PAYLOAD) {
        return error.PriorWithdrawalsExceedLimit;
    }

    var sweep_withdrawals = std.ArrayList(Withdrawal).init(allocator);
    errdefer sweep_withdrawals.deinit();

    const validators = try state.validators();
    var balances = try state.balances();
    const next_withdrawal_validator_index = try state.nextWithdrawalValidatorIndex();
    const validators_count = try validators.length();
    if (next_withdrawal_validator_index >= validators_count) {
        return error.InvalidNextWithdrawalValidatorIndex;
    }
    const validators_limit = @min(validators_count, preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);

    // Just run a bounded loop max iterating over all withdrawals
    // however breaks out once we have MAX_WITHDRAWALS_PER_PAYLOAD
    var processed_count: usize = 0;
    for (0..validators_limit) |n| {
        if (sweep_withdrawals.items.len + num_prior_withdrawals >= preset.MAX_WITHDRAWALS_PER_PAYLOAD) {
            break;
        }

        // Get next validator in turn
        const validator_index = (next_withdrawal_validator_index + n) % validators_count;
        var validator = try validators.get(validator_index);

        const balance_gop = try validator_balance_after_withdrawals.getOrPut(validator_index);
        if (!balance_gop.found_existing) {
            balance_gop.value_ptr.* = try balances.get(validator_index);
        }
        const balance: u64 = balance_gop.value_ptr.*;

        const withdrawable_epoch = try validator.get("withdrawable_epoch");
        const withdrawal_credentials = try validator.getFieldRoot("withdrawal_credentials");
        const effective_balance = try validator.get("effective_balance");

        if (isFullyWithdrawableValidator(fork, withdrawal_credentials, balance, withdrawable_epoch, epoch)) {
            var execution_address: ExecutionAddress = undefined;
            @memcpy(&execution_address, withdrawal_credentials[12..]);
            try sweep_withdrawals.append(.{
                .index = withdrawal_index.*,
                .validator_index = validator_index,
                .address = execution_address,
                .amount = balance,
            });
            withdrawal_index.* += 1;
            balance_gop.value_ptr.* = 0;
        } else if (isPartiallyWithdrawableValidator(fork, withdrawal_credentials, effective_balance, balance)) {
            const max_effective_balance = if (comptime fork.gte(.electra)) getMaxEffectiveBalance(withdrawal_credentials) else preset.MAX_EFFECTIVE_BALANCE;
            const partial_amount = balance - max_effective_balance;
            var execution_address: ExecutionAddress = undefined;
            @memcpy(&execution_address, withdrawal_credentials[12..]);
            try sweep_withdrawals.append(.{
                .index = withdrawal_index.*,
                .validator_index = validator_index,
                .address = execution_address,
                .amount = partial_amount,
            });
            withdrawal_index.* += 1;
            balance_gop.value_ptr.* = balance - partial_amount;
        }

        processed_count += 1;
    }

    return .{ .withdrawals = sweep_withdrawals, .processed_count = processed_count };
}

fn getBuilderWithdrawals(
    allocator: Allocator,
    state: *BeaconState(.gloas),
    withdrawal_index: *u64,
    prior_withdrawals_len: usize,
    builder_balance_after_withdrawals: *std.AutoHashMap(u64, i64),
) !struct { withdrawals: std.ArrayList(Withdrawal), processed_count: usize } {
    const withdrawals_limit = preset.MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    if (prior_withdrawals_len > withdrawals_limit) {
        return error.PriorWithdrawalsExceedLimit;
    }
    var builder_withdrawals = std.ArrayList(Withdrawal).init(allocator);
    errdefer builder_withdrawals.deinit();

    var builder_pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
    const builder_pending_withdrawals_len = try builder_pending_withdrawals.length();
    var bw_it = builder_pending_withdrawals.iteratorReadonly(0);

    var processed_count: usize = 0;
    for (0..builder_pending_withdrawals_len) |_| {
        // Check combined length against limit
        const all_withdrawals = prior_withdrawals_len + builder_withdrawals.items.len;
        if (all_withdrawals >= withdrawals_limit) break;

        const bw = try bw_it.nextValue(allocator);
        const builder_index = bw.builder_index;

        // Get builder balance (from builder.balance, not state.balances)
        const balance_gop = try builder_balance_after_withdrawals.getOrPut(builder_index);
        if (!balance_gop.found_existing) {
            var builders = try state.inner.get("builders");
            var builder: types.gloas.Builder.Type = undefined;
            try builders.getValue(allocator, builder_index, &builder);
            balance_gop.value_ptr.* = @intCast(builder.balance);
        }

        // Use the withdrawal amount directly as specified in the spec
        try builder_withdrawals.append(.{
            .index = withdrawal_index.*,
            .validator_index = convertBuilderIndexToValidatorIndex(builder_index),
            .address = bw.fee_recipient,
            .amount = bw.amount,
        });
        withdrawal_index.* += 1;
        balance_gop.value_ptr.* -= @as(i64, @intCast(bw.amount));

        processed_count += 1;
    }

    return .{ .withdrawals = builder_withdrawals, .processed_count = processed_count };
}

fn getBuildersSweepWithdrawals(
    allocator: Allocator,
    state: *BeaconState(.gloas),
    epoch: u64,
    withdrawal_index: *u64,
    num_prior_withdrawals: usize,
    builder_balance_after_withdrawals: *std.AutoHashMap(u64, i64),
) !struct { withdrawals: std.ArrayList(Withdrawal), processed_count: usize } {
    const withdrawals_limit = preset.MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    if (num_prior_withdrawals > withdrawals_limit) {
        return error.PriorWithdrawalsExceedLimit;
    }
    var builders_sweep_withdrawals = std.ArrayList(Withdrawal).init(allocator);
    errdefer builders_sweep_withdrawals.deinit();

    var builders = try state.inner.get("builders");
    const builders_len: u64 = try builders.length();

    // Return early if no builders
    if (builders_len == 0) {
        return .{ .withdrawals = builders_sweep_withdrawals, .processed_count = 0 };
    }

    const builders_limit = @min(builders_len, preset.MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
    const next_withdrawal_builder_index: u64 = try state.inner.get("next_withdrawal_builder_index");
    if (next_withdrawal_builder_index >= builders_len) {
        return error.InvalidNextWithdrawalBuilderIndex;
    }
    var processed_count: usize = 0;

    for (0..builders_limit) |n| {
        if (builders_sweep_withdrawals.items.len + num_prior_withdrawals >= withdrawals_limit) break;

        // Get next builder in turn
        const builder_index: u64 = (next_withdrawal_builder_index + n) % builders_len;
        var builder: types.gloas.Builder.Type = undefined;
        try builders.getValue(allocator, builder_index, &builder);

        // Get builder balance (may have been decremented by builder withdrawals above)
        const balance_gop = try builder_balance_after_withdrawals.getOrPut(builder_index);
        if (!balance_gop.found_existing) {
            balance_gop.value_ptr.* = @intCast(builder.balance);
        }
        const balance = balance_gop.value_ptr.*;

        // Check if builder is withdrawable and has balance
        if (builder.withdrawable_epoch <= epoch and balance > 0) {
            // Withdraw full balance to builder's execution address
            try builders_sweep_withdrawals.append(.{
                .index = withdrawal_index.*,
                .validator_index = convertBuilderIndexToValidatorIndex(builder_index),
                .address = builder.execution_address,
                .amount = @intCast(balance),
            });
            withdrawal_index.* += 1;
            balance_gop.value_ptr.* = 0;
        }

        processed_count += 1;
    }

    return .{ .withdrawals = builders_sweep_withdrawals, .processed_count = processed_count };
}
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "process withdrawals - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var withdrawals_result = WithdrawalsResult{
        .withdrawals = try Withdrawals.initCapacity(
            allocator,
            preset.MAX_WITHDRAWALS_PER_PAYLOAD,
        ),
    };
    defer withdrawals_result.withdrawals.deinit(allocator);
    var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
    defer withdrawal_balances.deinit();

    var root: Root = undefined;
    try types.capella.Withdrawals.hashTreeRoot(allocator, &withdrawals_result.withdrawals, &root);

    try getExpectedWithdrawals(
        .electra,
        allocator,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        &withdrawals_result,
        &withdrawal_balances,
    );
    try processWithdrawals(
        .electra,
        allocator,
        test_state.cached_state.state.castToFork(.electra),
        withdrawals_result,
        root,
    );
}
