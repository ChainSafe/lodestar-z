const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const c = @import("constants");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const WithdrawalRequest = types.electra.WithdrawalRequest.Type;
const PendingPartialWithdrawal = types.electra.PendingPartialWithdrawal.Type;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;
const hasExecutionWithdrawalCredential = @import("../utils/electra.zig").hasExecutionWithdrawalCredential;
const isActiveValidatorView = @import("../utils/validator.zig").isActiveValidatorView;
const getPendingBalanceToWithdraw = @import("../utils/validator.zig").getPendingBalanceToWithdraw;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;
const computeExitEpochAndUpdateChurn = @import("../utils/epoch.zig").computeExitEpochAndUpdateChurn;

pub fn processWithdrawalRequest(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    withdrawal_request: *const WithdrawalRequest,
) !void {
    const amount = withdrawal_request.amount;
    // no need to use unfinalized pubkey cache from 6110 as validator won't be active anyway
    const pubkey_to_index = epoch_cache.pubkey_to_index;
    const is_full_exit_request = amount == c.FULL_EXIT_REQUEST_AMOUNT;

    var pending_partial_withdrawals = try state.pendingPartialWithdrawals();

    // If partial withdrawal queue is full, only full exits are processed
    if (try pending_partial_withdrawals.length() >= preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT and
        !is_full_exit_request)
    {
        return;
    }

    // bail out if validator is not in beacon state
    // note that we don't need to check for 6110 unfinalized vals as they won't be eligible for withdraw/exit anyway
    const validator_index = pubkey_to_index.get(withdrawal_request.validator_pubkey) orelse return;

    var validators = try state.validators();
    if (validator_index >= try validators.length()) return;
    const validator = try validators.get(@intCast(validator_index));
    if (!(try isValidatorEligibleForWithdrawOrExit(
        config,
        epoch_cache.epoch,
        validator,
        &withdrawal_request.source_address,
    ))) {
        return;
    }

    // TODO Electra: Consider caching pendingPartialWithdrawals
    const pending_balance_to_withdraw = try getPendingBalanceToWithdraw(fork, state, validator_index);
    var balances = try state.balances();
    const validator_balance = try balances.get(@intCast(validator_index));

    if (is_full_exit_request) {
        // only exit validator if it has no pending withdrawals in the queue
        if (pending_balance_to_withdraw == 0) {
            try initiateValidatorExit(fork, config, epoch_cache, state, validator);
        }
        return;
    }

    // partial withdrawal request
    const effective_balance = try validator.get("effective_balance");
    const withdrawal_credentials = try validator.getFieldRoot("withdrawal_credentials");

    const has_sufficient_effective_balance = effective_balance >= preset.MIN_ACTIVATION_BALANCE;
    const has_excess_balance = validator_balance > preset.MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

    // Only allow partial withdrawals with compounding withdrawal credentials
    if (hasCompoundingWithdrawalCredential(withdrawal_credentials) and
        has_sufficient_effective_balance and
        has_excess_balance)
    {
        const amount_to_withdraw = @min(validator_balance - preset.MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw, amount);
        const exit_queue_epoch = try computeExitEpochAndUpdateChurn(fork, epoch_cache, state, amount_to_withdraw);
        const withdrawable_epoch = exit_queue_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

        const pending_partial_withdrawal = PendingPartialWithdrawal{
            .validator_index = validator_index,
            .amount = amount_to_withdraw,
            .withdrawable_epoch = withdrawable_epoch,
        };
        try pending_partial_withdrawals.pushValue(&pending_partial_withdrawal);
    }
}

fn isValidatorEligibleForWithdrawOrExit(
    config: *const BeaconConfig,
    current_epoch: u64,
    validator: *types.phase0.Validator.TreeView,
    source_address: []const u8,
) !bool {
    const withdrawal_credentials = try validator.getFieldRoot("withdrawal_credentials");
    const address = withdrawal_credentials[12..];

    const activation_epoch = try validator.get("activation_epoch");
    const exit_epoch = try validator.get("exit_epoch");

    return (hasExecutionWithdrawalCredential(withdrawal_credentials) and
        std.mem.eql(u8, address, source_address) and
        (try isActiveValidatorView(validator, current_epoch)) and
        exit_epoch == c.FAR_FUTURE_EPOCH and
        current_epoch >= activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD);
}

// ──── Tests ────

const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/generate_state.zig").TestCachedBeaconState;

fn makeWithdrawalRequest(
    source_address: [20]u8,
    validator_pubkey: [48]u8,
    amount: u64,
) WithdrawalRequest {
    return WithdrawalRequest{
        .source_address = source_address,
        .validator_pubkey = validator_pubkey,
        .amount = amount,
    };
}

fn getValidatorPubkey(state: anytype, index: u64) ![48]u8 {
    var validators = try state.validators();
    var validator = try validators.get(index);
    var pubkey_view = try validator.get("pubkey");
    var pubkey: [48]u8 = undefined;
    _ = try pubkey_view.getAllInto(&pubkey);
    return pubkey;
}

fn setExecutionCredentials(state: anytype, index: u64, address: [20]u8) !void {
    var validators = try state.validators();
    var validator = try validators.get(index);
    var wc: [32]u8 = [_]u8{0} ** 32;
    wc[0] = 1; // ETH1_ADDRESS_WITHDRAWAL_PREFIX
    @memcpy(wc[12..32], &address);
    try validator.setValue("withdrawal_credentials", &wc);
}

fn setCompoundingCredentials(state: anytype, index: u64, address: [20]u8) !void {
    var validators = try state.validators();
    var validator = try validators.get(index);
    var wc: [32]u8 = [_]u8{0} ** 32;
    wc[0] = 2; // COMPOUNDING_WITHDRAWAL_PREFIX
    @memcpy(wc[12..32], &address);
    try validator.setValue("withdrawal_credentials", &wc);
}

test "withdrawal request - unknown validator pubkey is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const unknown_pubkey: [48]u8 = [_]u8{0xFF} ** 48;
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    const request = makeWithdrawalRequest(source_address, unknown_pubkey, c.FULL_EXIT_REQUEST_AMOUNT);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // No-op: pending partial withdrawals should remain empty
    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "withdrawal request - validator without execution credentials is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // Default credentials are BLS (0x00) — not execution
    const request = makeWithdrawalRequest(source_address, pubkey, c.FULL_EXIT_REQUEST_AMOUNT);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "withdrawal request - mismatched source address is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const correct_address: [20]u8 = [_]u8{0xAA} ** 20;
    const wrong_address: [20]u8 = [_]u8{0xBB} ** 20;

    try setExecutionCredentials(state, 0, correct_address);

    const request = makeWithdrawalRequest(wrong_address, pubkey, c.FULL_EXIT_REQUEST_AMOUNT);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "withdrawal request - full exit sets exit epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);

    const request = makeWithdrawalRequest(source_address, pubkey, c.FULL_EXIT_REQUEST_AMOUNT);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // Validator should have exit_epoch set (no longer FAR_FUTURE_EPOCH)
    var validators = try state.validators();
    var validator = try validators.get(0);
    const exit_epoch = try validator.get("exit_epoch");
    try testing.expect(exit_epoch != c.FAR_FUTURE_EPOCH);

    // No partial withdrawal added
    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "withdrawal request - already exiting validator is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);

    // Set exit_epoch to something other than FAR_FUTURE_EPOCH
    var validators = try state.validators();
    var validator = try validators.get(0);
    try validator.set("exit_epoch", 100);

    const request = makeWithdrawalRequest(source_address, pubkey, c.FULL_EXIT_REQUEST_AMOUNT);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // exit_epoch should remain unchanged
    var validators2 = try state.validators();
    var validator2 = try validators2.get(0);
    const exit_epoch = try validator2.get("exit_epoch");
    try testing.expectEqual(@as(u64, 100), exit_epoch);
}

test "withdrawal request - partial withdrawal with compounding credentials" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // Set compounding credentials (0x02 prefix)
    try setCompoundingCredentials(state, 0, source_address);

    // Give the validator excess balance
    var balances = try state.balances();
    try balances.set(0, preset.MIN_ACTIVATION_BALANCE + 5_000_000_000);

    const request_amount: u64 = 1_000_000_000;
    const request = makeWithdrawalRequest(source_address, pubkey, request_amount);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // Should have added a pending partial withdrawal
    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 1), try pending.length());

    // Validator should NOT be exiting
    var validators = try state.validators();
    var validator = try validators.get(0);
    const exit_epoch = try validator.get("exit_epoch");
    try testing.expectEqual(@as(u64, c.FAR_FUTURE_EPOCH), exit_epoch);
}

test "withdrawal request - partial withdrawal with eth1 credentials is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // ETH1 credentials (0x01) — NOT compounding, so partial withdrawal should be rejected
    try setExecutionCredentials(state, 0, source_address);

    var balances = try state.balances();
    try balances.set(0, preset.MIN_ACTIVATION_BALANCE + 5_000_000_000);

    const request_amount: u64 = 1_000_000_000;
    const request = makeWithdrawalRequest(source_address, pubkey, request_amount);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // No partial withdrawal should be added (ETH1 creds, not compounding)
    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "withdrawal request - partial withdrawal capped at excess balance" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setCompoundingCredentials(state, 0, source_address);

    // Set balance to MIN_ACTIVATION_BALANCE + 2 gwei excess
    const excess: u64 = 2_000_000_000;
    var balances = try state.balances();
    try balances.set(0, preset.MIN_ACTIVATION_BALANCE + excess);

    // Request more than the excess
    const request_amount: u64 = 10_000_000_000;
    const request = makeWithdrawalRequest(source_address, pubkey, request_amount);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // Should be added but capped at the excess
    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 1), try pending.length());
    var ppw = try pending.get(0);
    try testing.expectEqual(excess, try ppw.get("amount"));
}

test "withdrawal request - insufficient effective balance for partial is no-op" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setCompoundingCredentials(state, 0, source_address);

    // Set effective_balance below MIN_ACTIVATION_BALANCE
    var validators = try state.validators();
    var validator = try validators.get(0);
    try validator.set("effective_balance", preset.MIN_ACTIVATION_BALANCE - 1);

    var balances = try state.balances();
    try balances.set(0, preset.MIN_ACTIVATION_BALANCE + 5_000_000_000);

    const request = makeWithdrawalRequest(source_address, pubkey, 1_000_000_000);
    try processWithdrawalRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingPartialWithdrawals();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}
