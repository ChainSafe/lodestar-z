const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BLSPubkey = types.primitive.BLSPubkey.Type;
const WithdrawalCredentials = types.primitive.Root.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const DepositMessage = types.phase0.DepositMessage.Type;
const Domain = types.primitive.Domain.Type;
const Root = types.primitive.Root.Type;
const types = @import("consensus_types");
const c = @import("constants");
const preset = @import("preset").preset;
const DOMAIN_DEPOSIT = c.DOMAIN_DEPOSIT;
const ZERO_HASH = @import("constants").ZERO_HASH;
const computeDomain = @import("../utils/domain.zig").computeDomain;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const bls = @import("bls");
const verify = @import("../utils/bls.zig").verify;
const getMaxEffectiveBalance = @import("../utils/validator.zig").getMaxEffectiveBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;
const verifyMerkleBranch = @import("../utils/verify_merkle_branch.zig").verifyMerkleBranch;

pub const DepositData = union(enum) {
    phase0: types.phase0.DepositData.Type,
    electra: types.electra.DepositRequest.Type,

    pub fn pubkey(self: *const DepositData) *const BLSPubkey {
        return switch (self.*) {
            .phase0 => |*data| &data.pubkey,
            .electra => |*data| &data.pubkey,
        };
    }

    pub fn withdrawalCredentials(self: *const DepositData) *const WithdrawalCredentials {
        return switch (self.*) {
            .phase0 => |*data| &data.withdrawal_credentials,
            .electra => |*data| &data.withdrawal_credentials,
        };
    }

    pub fn amount(self: *const DepositData) u64 {
        return switch (self.*) {
            .phase0 => |data| data.amount,
            .electra => |data| data.amount,
        };
    }

    pub fn signature(self: *const DepositData) BLSSignature {
        return switch (self.*) {
            .phase0 => |data| data.signature,
            .electra => |data| data.signature,
        };
    }
};

pub fn processDeposit(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    deposit: *const types.phase0.Deposit.Type,
) !void {
    // verify the merkle branch
    var deposit_data_root: Root = undefined;
    try types.phase0.DepositData.hashTreeRoot(&deposit.data, &deposit_data_root);

    var eth1_data = try state.eth1Data();
    const deposit_root = try eth1_data.getFieldRoot("deposit_root");
    if (!verifyMerkleBranch(
        deposit_data_root,
        &deposit.proof,
        c.DEPOSIT_CONTRACT_TREE_DEPTH + 1,
        @intCast(try state.eth1DepositIndex()),
        deposit_root.*,
    )) {
        return error.InvalidMerkleProof;
    }

    // deposits must be processed in order
    try state.incrementEth1DepositIndex();
    try applyDeposit(fork, allocator, config, epoch_cache, state, &.{
        .phase0 = deposit.data,
    });
}

/// Adds a new validator into the registry. Or increase balance if already exist.
/// Follows applyDeposit() in consensus spec. Will be used by processDeposit() and processDepositRequest()
pub fn applyDeposit(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    deposit: *const DepositData,
) !void {
    const pubkey = deposit.pubkey();
    const withdrawal_credentials = deposit.withdrawalCredentials();
    const amount = deposit.amount();
    const signature = deposit.signature();

    const cached_index = epoch_cache.getValidatorIndex(pubkey);
    const is_new_validator = cached_index == null or cached_index.? >= try state.validatorsCount();

    if (comptime fork.lt(.electra)) {
        if (is_new_validator) {
            if (validateDepositSignature(config, pubkey, withdrawal_credentials, amount, signature)) {
                try addValidatorToRegistry(fork, allocator, epoch_cache, state, pubkey, withdrawal_credentials, amount);
            } else |_| {
                // invalid deposit signature, ignore the deposit
                // TODO may be a useful metric to track
            }
        } else {
            // increase balance by deposit amount right away pre-electra
            const index = cached_index.?;
            try increaseBalance(fork, state, index, amount);
        }
    } else {
        const pending_deposit = types.electra.PendingDeposit.Type{
            .pubkey = pubkey.*,
            .withdrawal_credentials = withdrawal_credentials.*,
            .amount = amount,
            .signature = signature,
            .slot = c.GENESIS_SLOT, // Use GENESIS_SLOT to distinguish from a pending deposit request
        };

        var pending_deposits = try state.pendingDeposits();
        if (is_new_validator) {
            if (validateDepositSignature(config, pubkey, withdrawal_credentials, amount, signature)) {
                try addValidatorToRegistry(fork, allocator, epoch_cache, state, pubkey, withdrawal_credentials, 0);
                try pending_deposits.pushValue(&pending_deposit);
            } else |_| {
                // invalid deposit signature, ignore the deposit
                // TODO may be a useful metric to track
            }
        } else {
            try pending_deposits.pushValue(&pending_deposit);
        }
    }
}

pub fn addValidatorToRegistry(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    pubkey: *const BLSPubkey,
    withdrawal_credentials: *const WithdrawalCredentials,
    amount: u64,
) !void {
    var validators = try state.validators();
    // add validator and balance entries
    const effective_balance = @min(
        amount - (amount % preset.EFFECTIVE_BALANCE_INCREMENT),
        if (comptime fork.lt(.electra)) preset.MAX_EFFECTIVE_BALANCE else getMaxEffectiveBalance(withdrawal_credentials),
    );

    const validator: types.phase0.Validator.Type = .{
        .pubkey = pubkey.*,
        .withdrawal_credentials = withdrawal_credentials.*,
        .activation_eligibility_epoch = c.FAR_FUTURE_EPOCH,
        .activation_epoch = c.FAR_FUTURE_EPOCH,
        .exit_epoch = c.FAR_FUTURE_EPOCH,
        .withdrawable_epoch = c.FAR_FUTURE_EPOCH,
        .effective_balance = effective_balance,
        .slashed = false,
    };
    try validators.pushValue(&validator);

    const validator_index = (try validators.length()) - 1;
    // In Electra, new validators start with amount=0 (actual deposit goes through pendingDeposits)
    // Updating here is better than updating at once on epoch transition
    // - Simplify genesis fn applyDeposits(): effectiveBalanceIncrements is populated immediately
    // - Keep related code together to reduce risk of breaking this cache
    // - Should have equal performance since it sets a value in a flat array
    try epoch_cache.effectiveBalanceIncrementsSet(allocator, validator_index, effective_balance);

    // now that there is a new validator, update the epoch context with the new pubkey
    try epoch_cache.addPubkey(validator_index, pubkey);

    // Only after altair:
    if (comptime fork.gte(.altair)) {
        var inactivity_scores = try state.inactivityScores();
        try inactivity_scores.push(0);

        // add participation caches
        var previous_epoch_participation = try state.previousEpochParticipation();
        try previous_epoch_participation.push(0);
        var state_current_epoch_participation = try state.currentEpochParticipation();
        try state_current_epoch_participation.push(0);
    }
    var balances = try state.balances();
    try balances.push(amount);
}

/// Refer to https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#new-is_valid_deposit_signature
pub fn validateDepositSignature(
    config: *const BeaconConfig,
    pubkey: *const BLSPubkey,
    withdrawal_credentials: *const WithdrawalCredentials,
    amount: u64,
    deposit_signature: BLSSignature,
) !void {
    // verify the deposit signature (proof of posession) which is not checked by the deposit contract
    const deposit_message = DepositMessage{
        .pubkey = pubkey.*,
        .withdrawal_credentials = withdrawal_credentials.*,
        .amount = amount,
    };

    const GENESIS_FORK_VERSION = config.chain.GENESIS_FORK_VERSION;

    // fork-agnostic domain since deposits are valid across forks
    var domain: Domain = undefined;
    try computeDomain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, ZERO_HASH, &domain);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.phase0.DepositMessage, &deposit_message, &domain, &signing_root);

    // Pubkeys must be checked for group + inf. This must be done only once when the validator deposit is processed
    const public_key = try bls.PublicKey.uncompress(pubkey);
    try public_key.validate();
    const signature = try bls.Signature.uncompress(&deposit_signature);
    try signature.validate(true);
    try verify(&signing_root, &public_key, &signature, null, null);
}

// Tests
const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const interopPubkeysCached = @import("../test_utils/interop_pubkeys.zig").interopPubkeysCached;
const interopSign = @import("../test_utils/interop_pubkeys.zig").interopSign;

test "deposit data - phase0 accessors return correct values" {
    const pubkey_bytes = [_]u8{1} ** 48;
    const withdrawal_creds = [_]u8{2} ** 32;
    const sig = [_]u8{3} ** 96;
    const deposit = DepositData{ .phase0 = .{
        .pubkey = pubkey_bytes,
        .withdrawal_credentials = withdrawal_creds,
        .amount = 32_000_000_000,
        .signature = sig,
    } };

    try testing.expectEqual(pubkey_bytes, deposit.pubkey().*);
    try testing.expectEqual(withdrawal_creds, deposit.withdrawalCredentials().*);
    try testing.expectEqual(@as(u64, 32_000_000_000), deposit.amount());
    try testing.expectEqual(sig, deposit.signature());
}

test "deposit data - electra accessors return correct values" {
    const pubkey_bytes = [_]u8{4} ** 48;
    const withdrawal_creds = [_]u8{5} ** 32;
    const sig = [_]u8{6} ** 96;
    const deposit = DepositData{ .electra = .{
        .pubkey = pubkey_bytes,
        .withdrawal_credentials = withdrawal_creds,
        .amount = 64_000_000_000,
        .signature = sig,
        .index = 42,
    } };

    try testing.expectEqual(pubkey_bytes, deposit.pubkey().*);
    try testing.expectEqual(withdrawal_creds, deposit.withdrawalCredentials().*);
    try testing.expectEqual(@as(u64, 64_000_000_000), deposit.amount());
    try testing.expectEqual(sig, deposit.signature());
}

test "addValidatorToRegistry - new validator has correct fields and entries" {
    const allocator = testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Use interop key 256 — a valid pubkey not already in the state.
    var new_pubkeys: [257]BLSPubkey = undefined;
    try interopPubkeysCached(257, &new_pubkeys);
    const new_pubkey = new_pubkeys[256];

    const withdrawal_creds = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const amount: u64 = 32_000_000_000;

    var validators_before = try state.validators();
    const count_before = try validators_before.length();
    var balances_before = try state.balances();
    const balances_count_before = try balances_before.length();

    try addValidatorToRegistry(
        .electra,
        allocator,
        test_state.cached_state.epoch_cache,
        state,
        &new_pubkey,
        &withdrawal_creds,
        amount,
    );

    // Validator count increased by one.
    var validators_after = try state.validators();
    const count_after = try validators_after.length();
    try testing.expectEqual(count_before + 1, count_after);

    // Balance entry was added with the deposit amount.
    var balances_after = try state.balances();
    const balances_count_after = try balances_after.length();
    try testing.expectEqual(balances_count_before + 1, balances_count_after);
    const new_balance = try balances_after.get(count_before);
    try testing.expectEqual(amount, new_balance);

    // Effective balance is correctly computed: min(amount rounded down, max_effective).
    const expected_effective = @min(
        amount - (amount % preset.EFFECTIVE_BALANCE_INCREMENT),
        preset.MIN_ACTIVATION_BALANCE,
    );
    var new_validator = try validators_after.get(count_before);
    const effective_bal = try new_validator.get("effective_balance");
    try testing.expectEqual(expected_effective, effective_bal);

    // Activation/exit epochs are set to FAR_FUTURE_EPOCH.
    const activation_epoch = try new_validator.get("activation_eligibility_epoch");
    try testing.expectEqual(c.FAR_FUTURE_EPOCH, activation_epoch);
    const exit_epoch = try new_validator.get("exit_epoch");
    try testing.expectEqual(c.FAR_FUTURE_EPOCH, exit_epoch);

    // Inactivity score, participation entries were added (electra >= altair).
    var inactivity_scores = try state.inactivityScores();
    const inactivity_count = try inactivity_scores.length();
    try testing.expectEqual(count_after, inactivity_count);

    var prev_participation = try state.previousEpochParticipation();
    const prev_count = try prev_participation.length();
    try testing.expectEqual(count_after, prev_count);

    var curr_participation = try state.currentEpochParticipation();
    const curr_count = try curr_participation.length();
    try testing.expectEqual(count_after, curr_count);
}

test "applyDeposit electra - existing validator creates pending deposit" {
    const allocator = testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Get the pubkey for validator 0 (already in the state).
    var pubkeys: [1]BLSPubkey = undefined;
    try interopPubkeysCached(1, &pubkeys);
    const existing_pubkey = pubkeys[0];

    const withdrawal_creds = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const deposit_amount: u64 = 1_000_000_000;

    var validators_before = try state.validators();
    const count_before = try validators_before.length();
    var balances_before = try state.balances();
    const balance_before = try balances_before.get(0);

    var pending_before = try state.pendingDeposits();
    const pending_count_before = try pending_before.length();

    const deposit = DepositData{ .phase0 = .{
        .pubkey = existing_pubkey,
        .withdrawal_credentials = withdrawal_creds,
        .amount = deposit_amount,
        .signature = [_]u8{0} ** 96,
    } };

    try applyDeposit(
        .electra,
        allocator,
        test_state.config,
        test_state.cached_state.epoch_cache,
        state,
        &deposit,
    );

    // Validator count unchanged — existing validator, no new registration.
    var validators_after = try state.validators();
    const count_after = try validators_after.length();
    try testing.expectEqual(count_before, count_after);

    // Balance unchanged — electra defers deposit to pending.
    var balances_after = try state.balances();
    const balance_after = try balances_after.get(0);
    try testing.expectEqual(balance_before, balance_after);

    // A pending deposit was created.
    var pending_after = try state.pendingDeposits();
    const pending_count_after = try pending_after.length();
    try testing.expectEqual(pending_count_before + 1, pending_count_after);
}

test "applyDeposit electra - invalid signature skips new validator" {
    const allocator = testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Use a new pubkey not in the state. Generate interop key 256.
    var new_pubkeys: [257]BLSPubkey = undefined;
    try interopPubkeysCached(257, &new_pubkeys);
    const new_pubkey = new_pubkeys[256];

    const withdrawal_creds = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const deposit_amount: u64 = 32_000_000_000;

    // Invalid signature — all zeros is not a valid BLS signature.
    const invalid_sig = [_]u8{0} ** 96;

    var validators_before = try state.validators();
    const count_before = try validators_before.length();

    var pending_before = try state.pendingDeposits();
    const pending_count_before = try pending_before.length();

    const deposit = DepositData{ .phase0 = .{
        .pubkey = new_pubkey,
        .withdrawal_credentials = withdrawal_creds,
        .amount = deposit_amount,
        .signature = invalid_sig,
    } };

    try applyDeposit(
        .electra,
        allocator,
        test_state.config,
        test_state.cached_state.epoch_cache,
        state,
        &deposit,
    );

    // No new validator added — invalid signature was rejected.
    var validators_after = try state.validators();
    const count_after = try validators_after.length();
    try testing.expectEqual(count_before, count_after);

    // No pending deposit created either — the deposit was entirely skipped.
    var pending_after = try state.pendingDeposits();
    const pending_count_after = try pending_after.length();
    try testing.expectEqual(pending_count_before, pending_count_after);
}

test "applyDeposit electra - valid signature adds validator and pending deposit" {
    const allocator = testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Use interop key 256 — a new validator not already in the state.
    const new_validator_index: usize = 256;
    var all_pubkeys: [257]BLSPubkey = undefined;
    try interopPubkeysCached(257, &all_pubkeys);
    const new_pubkey = all_pubkeys[new_validator_index];

    const withdrawal_creds = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const deposit_amount: u64 = 32_000_000_000;

    // Construct a valid deposit signature using the interop secret key.
    const deposit_message = DepositMessage{
        .pubkey = new_pubkey,
        .withdrawal_credentials = withdrawal_creds,
        .amount = deposit_amount,
    };
    const GENESIS_FORK_VERSION = test_state.config.chain.GENESIS_FORK_VERSION;
    var domain: Domain = undefined;
    try computeDomain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, ZERO_HASH, &domain);
    var signing_root: Root = undefined;
    try computeSigningRoot(types.phase0.DepositMessage, &deposit_message, &domain, &signing_root);
    const sig = try interopSign(new_validator_index, &signing_root);
    const compressed_sig = sig.compress();

    var validators_before = try state.validators();
    const count_before = try validators_before.length();

    var pending_before = try state.pendingDeposits();
    const pending_count_before = try pending_before.length();

    const deposit = DepositData{ .phase0 = .{
        .pubkey = new_pubkey,
        .withdrawal_credentials = withdrawal_creds,
        .amount = deposit_amount,
        .signature = compressed_sig,
    } };

    try applyDeposit(
        .electra,
        allocator,
        test_state.config,
        test_state.cached_state.epoch_cache,
        state,
        &deposit,
    );

    // New validator was added to the registry.
    var validators_after = try state.validators();
    const count_after = try validators_after.length();
    try testing.expectEqual(count_before + 1, count_after);

    // In electra, new validators start with balance = 0 in the registry.
    var balances_after = try state.balances();
    const new_balance = try balances_after.get(count_before);
    try testing.expectEqual(@as(u64, 0), new_balance);

    // A pending deposit was created for the actual amount.
    var pending_after = try state.pendingDeposits();
    const pending_count_after = try pending_after.length();
    try testing.expectEqual(pending_count_before + 1, pending_count_after);
}
