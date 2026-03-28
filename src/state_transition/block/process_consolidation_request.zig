const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const FAR_FUTURE_EPOCH = @import("constants").FAR_FUTURE_EPOCH;
const ConsolidationRequest = types.electra.ConsolidationRequest.Type;
const PendingConsolidation = types.electra.PendingConsolidation.Type;
const hasEth1WithdrawalCredential = @import("../utils/capella.zig").hasEth1WithdrawalCredential;
const electra_utils = @import("../utils/electra.zig");
const hasCompoundingWithdrawalCredential = electra_utils.hasCompoundingWithdrawalCredential;
const hasExecutionWithdrawalCredential = electra_utils.hasExecutionWithdrawalCredential;
const isPubkeyKnown = electra_utils.isPubkeyKnown;
const switchToCompoundingValidator = electra_utils.switchToCompoundingValidator;
const computeConsolidationEpochAndUpdateChurn = @import("../utils/epoch.zig").computeConsolidationEpochAndUpdateChurn;
const validator_utils = @import("../utils/validator.zig");
const getConsolidationChurnLimit = validator_utils.getConsolidationChurnLimit;
const getPendingBalanceToWithdraw = validator_utils.getPendingBalanceToWithdraw;
const isActiveValidatorView = validator_utils.isActiveValidatorView;

// TODO Electra: Clean up necessary as there is a lot of overlap with isValidSwitchToCompoundRequest
pub fn processConsolidationRequest(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    consolidation: *const ConsolidationRequest,
) !void {
    const source_pubkey = consolidation.source_pubkey;
    const target_pubkey = consolidation.target_pubkey;
    const source_address = consolidation.source_address;

    if (!(try isPubkeyKnown(fork, epoch_cache, state, source_pubkey))) return;
    if (!(try isPubkeyKnown(fork, epoch_cache, state, target_pubkey))) return;

    const source_index = epoch_cache.pubkey_to_index.get(source_pubkey) orelse return;
    const target_index = epoch_cache.pubkey_to_index.get(target_pubkey) orelse return;

    if (try isValidSwitchToCompoundRequest(fork, epoch_cache, state, consolidation)) {
        try switchToCompoundingValidator(fork, state, source_index);
        // Early return since we have already switched validator to compounding
        return;
    }

    // Verify that source != target, so a consolidation cannot be used as an exit.
    if (source_index == target_index) {
        return;
    }

    // If the pending consolidations queue is full, consolidation requests are ignored
    var pending_consolidations = try state.pendingConsolidations();
    if (try pending_consolidations.length() >= preset.PENDING_CONSOLIDATIONS_LIMIT) {
        return;
    }

    // If there is too little available consolidation churn limit, consolidation requests are ignored
    if (getConsolidationChurnLimit(epoch_cache) <= preset.MIN_ACTIVATION_BALANCE) {
        return;
    }

    var validators = try state.validators();
    var source_validator = try validators.get(@intCast(source_index));
    var target_validator = try validators.get(@intCast(target_index));
    const source_withdrawal_credentials = try source_validator.getFieldRoot("withdrawal_credentials");
    const target_withdrawal_credentials = try target_validator.getFieldRoot("withdrawal_credentials");
    const source_withdrawal_address = source_withdrawal_credentials[12..];
    const current_epoch = epoch_cache.epoch;

    // Verify source withdrawal credentials
    const has_correct_credential = hasExecutionWithdrawalCredential(source_withdrawal_credentials);
    const is_correct_source_address = std.mem.eql(u8, source_withdrawal_address, &source_address);
    if (!(has_correct_credential and is_correct_source_address)) {
        return;
    }

    // Verify that target has compounding withdrawal credentials
    if (!hasCompoundingWithdrawalCredential(target_withdrawal_credentials)) {
        return;
    }

    // Verify the source and the target are active
    if (!(try isActiveValidatorView(source_validator, current_epoch)) or !(try isActiveValidatorView(target_validator, current_epoch))) {
        return;
    }

    // Verify exits for source and target have not been initiated
    const source_exit_epoch = try source_validator.get("exit_epoch");
    const target_exit_epoch = try target_validator.get("exit_epoch");
    if (source_exit_epoch != FAR_FUTURE_EPOCH or target_exit_epoch != FAR_FUTURE_EPOCH) {
        return;
    }

    // Verify the source has been active long enough
    const source_activation_epoch = try source_validator.get("activation_epoch");
    if (current_epoch < source_activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD) {
        return;
    }

    // Verify the source has no pending withdrawals in the queue
    if (try getPendingBalanceToWithdraw(fork, state, source_index) > 0) {
        return;
    }

    // Initiate source validator exit and append pending consolidation
    const effective_balance = try source_validator.get("effective_balance");
    const exit_epoch = try computeConsolidationEpochAndUpdateChurn(fork, epoch_cache, state, effective_balance);
    try source_validator.set("exit_epoch", exit_epoch);
    try source_validator.set("withdrawable_epoch", exit_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY);

    const pending_consolidation = PendingConsolidation{
        .source_index = source_index,
        .target_index = target_index,
    };
    try pending_consolidations.pushValue(&pending_consolidation);
}

fn isValidSwitchToCompoundRequest(
    comptime fork: ForkSeq,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    consolidation: *const ConsolidationRequest,
) !bool {
    // this check is mainly to make the compiler happy, pubkey is checked by the consumer already
    const source_index = epoch_cache.pubkey_to_index.get(consolidation.source_pubkey) orelse return false;
    const target_index = epoch_cache.pubkey_to_index.get(consolidation.target_pubkey) orelse return false;

    // Switch to compounding requires source and target be equal
    if (source_index != target_index) {
        return false;
    }

    var validators = try state.validators();
    var source_validator = try validators.get(@intCast(source_index));
    const source_withdrawal_credentials = try source_validator.getFieldRoot("withdrawal_credentials");
    const source_withdrawal_address = source_withdrawal_credentials[12..];

    // Verify request has been authorized
    if (std.mem.eql(u8, source_withdrawal_address, &consolidation.source_address) == false) {
        return false;
    }

    // Verify source withdrawal credentials
    if (!hasEth1WithdrawalCredential(source_withdrawal_credentials)) {
        return false;
    }

    // Verify the source is active
    if (!try isActiveValidatorView(source_validator, epoch_cache.epoch)) {
        return false;
    }

    // Verify exit for source has not been initiated
    if (try source_validator.get("exit_epoch") != FAR_FUTURE_EPOCH) {
        return false;
    }

    return true;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/generate_state.zig").TestCachedBeaconState;

fn makeConsolidationRequest(
    source_pubkey: [48]u8,
    target_pubkey: [48]u8,
    source_address: [20]u8,
) ConsolidationRequest {
    return ConsolidationRequest{
        .source_address = source_address,
        .source_pubkey = source_pubkey,
        .target_pubkey = target_pubkey,
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

fn setCompoundingCredentials(state: anytype, index: u64) !void {
    var validators = try state.validators();
    var validator = try validators.get(index);
    var wc: [32]u8 = [_]u8{0} ** 32;
    wc[0] = 2; // COMPOUNDING_WITHDRAWAL_PREFIX
    try validator.setValue("withdrawal_credentials", &wc);
}

test "consolidation request - unknown source pubkey" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const unknown_pubkey: [48]u8 = [_]u8{0xFF} ** 48;
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    const request = makeConsolidationRequest(unknown_pubkey, target_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // No-op: pending consolidations should remain empty
    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - unknown target pubkey" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const unknown_pubkey: [48]u8 = [_]u8{0xFF} ** 48;
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);

    const request = makeConsolidationRequest(source_pubkey, unknown_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - valid switch to compounding" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // Set ETH1 credentials with matching address (source == target triggers switch-to-compounding)
    try setExecutionCredentials(state, 0, source_address);

    const request = makeConsolidationRequest(source_pubkey, source_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // Should have switched to compounding credentials (0x02 prefix)
    var validators = try state.validators();
    var validator = try validators.get(0);
    const wc = try validator.getFieldRoot("withdrawal_credentials");
    try testing.expectEqual(@as(u8, 2), wc[0]);

    // No pending consolidation added (early return after switch)
    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - source equals target without eth1 credentials" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // Default credentials are BLS (0x00) — isValidSwitchToCompoundRequest will fail,
    // then source_index == target_index check causes return
    const request = makeConsolidationRequest(source_pubkey, source_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // No-op
    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - incorrect source address" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const correct_address: [20]u8 = [_]u8{0xAA} ** 20;
    const wrong_address: [20]u8 = [_]u8{0xBB} ** 20;

    try setExecutionCredentials(state, 0, correct_address);
    try setCompoundingCredentials(state, 1);

    // Request uses wrong_address
    const request = makeConsolidationRequest(source_pubkey, target_pubkey, wrong_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - target without compounding credentials" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);
    // Target has ETH1 (0x01) instead of compounding (0x02)
    try setExecutionCredentials(state, 1, [_]u8{0xBB} ** 20);

    const request = makeConsolidationRequest(source_pubkey, target_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - source already exited" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);
    try setCompoundingCredentials(state, 1);

    // Set source exit_epoch to non-FAR_FUTURE
    var validators = try state.validators();
    var source_validator = try validators.get(0);
    const current_epoch = test_state.cached_state.epoch_cache.epoch;
    try source_validator.set("exit_epoch", current_epoch + 100);

    const request = makeConsolidationRequest(source_pubkey, target_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - source not active long enough" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    try setExecutionCredentials(state, 0, source_address);
    try setCompoundingCredentials(state, 1);

    // Set source activation_epoch to current_epoch so SHARD_COMMITTEE_PERIOD not met
    var validators = try state.validators();
    var source_validator = try validators.get(0);
    const current_epoch = test_state.cached_state.epoch_cache.epoch;
    try source_validator.set("activation_epoch", current_epoch);

    const request = makeConsolidationRequest(source_pubkey, target_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 0), try pending.length());
}

test "consolidation request - valid consolidation" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);
    const source_pubkey = try getValidatorPubkey(state, 0);
    const target_pubkey = try getValidatorPubkey(state, 1);
    const source_address: [20]u8 = [_]u8{0xAA} ** 20;

    // Source: execution credentials with matching address
    try setExecutionCredentials(state, 0, source_address);
    // Target: compounding credentials
    try setCompoundingCredentials(state, 1);

    // Override total_active_balance_increments so consolidation churn limit > MIN_ACTIVATION_BALANCE.
    // With mainnet preset and only 256 validators, the churn limit is 0 (not enough stake).
    // In production this requires ~500k+ validators; for tests we fake the balance.
    test_state.cached_state.epoch_cache.total_active_balance_increments = 20_000_000;

    const request = makeConsolidationRequest(source_pubkey, target_pubkey, source_address);
    try processConsolidationRequest(.electra, test_state.config, test_state.cached_state.epoch_cache, state, &request);

    // Source should have exit_epoch set (no longer FAR_FUTURE)
    var validators = try state.validators();
    var source_validator = try validators.get(0);
    const exit_epoch = try source_validator.get("exit_epoch");
    try testing.expect(exit_epoch != FAR_FUTURE_EPOCH);

    // Pending consolidation should be added
    var pending = try state.pendingConsolidations();
    try testing.expectEqual(@as(u64, 1), try pending.length());

    // Verify the pending consolidation has correct source/target
    var consolidation = try pending.get(0);
    try testing.expectEqual(@as(u64, 0), try consolidation.get("source_index"));
    try testing.expectEqual(@as(u64, 1), try consolidation.get("target_index"));
}

