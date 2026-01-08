const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
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
const blst = @import("blst");
const verify = @import("../utils/bls.zig").verify;
const ForkSeq = types.primitive.ForkSeq.Type;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const getMaxEffectiveBalance = @import("../utils/validator.zig").getMaxEffectiveBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;
const verifyMerkleBranch = @import("../utils/verify_merkle_branch.zig").verifyMerkleBranch;

pub const DepositData = union(enum) {
    phase0: types.phase0.DepositData.Type,
    electra: types.electra.DepositRequest.Type,

    pub fn pubkey(self: *const DepositData) BLSPubkey {
        return switch (self.*) {
            .phase0 => |data| data.pubkey,
            .electra => |data| data.pubkey,
        };
    }

    pub fn withdrawalCredentials(self: *const DepositData) WithdrawalCredentials {
        return switch (self.*) {
            .phase0 => |data| data.withdrawal_credentials,
            .electra => |data| data.withdrawal_credentials,
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

pub fn processDeposit(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, deposit: *const types.phase0.Deposit.Type) !void {
    const state = cached_state.state;
    // verify the merkle branch
    var deposit_data_root: Root = undefined;
    try types.phase0.DepositData.hashTreeRoot(&deposit.data, &deposit_data_root);
    if (!verifyMerkleBranch(
        deposit_data_root,
        &deposit.proof,
        c.DEPOSIT_CONTRACT_TREE_DEPTH + 1,
        state.eth1DepositIndex(),
        state.eth1Data().deposit_root,
    )) {
        return error.InvalidMerkleProof;
    }

    // deposits must be processed in order
    const state_eth1_deposit_index = state.eth1DepositIndexPtr();
    state_eth1_deposit_index.* += 1;
    try applyDeposit(allocator, cached_state, &.{
        .phase0 = deposit.data,
    });
}

/// Adds a new validator into the registry. Or increase balance if already exist.
/// Follows applyDeposit() in consensus spec. Will be used by processDeposit() and processDepositRequest()
pub fn applyDeposit(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, deposit: *const DepositData) !void {
    const config = cached_state.config;
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const pubkey = deposit.pubkey();
    const withdrawal_credentials = deposit.withdrawalCredentials();
    const amount = deposit.amount();
    const signature = deposit.signature();

    const cached_index = epoch_cache.getValidatorIndex(&pubkey);
    const is_new_validator = cached_index == null or cached_index.? >= state.validators().items.len;

    if (state.isPreElectra()) {
        if (is_new_validator) {
            if (isValidDepositSignature(config, pubkey, withdrawal_credentials, amount, signature)) {
                try addValidatorToRegistry(allocator, cached_state, pubkey, withdrawal_credentials, amount);
            }
        } else {
            // increase balance by deposit amount right away pre-electra
            const index = cached_index.?;
            increaseBalance(state, index, amount);
        }
    } else {
        const pending_deposit = types.electra.PendingDeposit.Type{
            .pubkey = pubkey,
            .withdrawal_credentials = withdrawal_credentials,
            .amount = amount,
            .signature = signature,
            .slot = c.GENESIS_SLOT, // Use GENESIS_SLOT to distinguish from a pending deposit request
        };

        if (is_new_validator) {
            if (isValidDepositSignature(config, pubkey, withdrawal_credentials, amount, signature)) {
                try addValidatorToRegistry(allocator, cached_state, pubkey, withdrawal_credentials, 0);
                try state.pendingDeposits().append(allocator, pending_deposit);
            }
        } else {
            try state.pendingDeposits().append(allocator, pending_deposit);
        }
    }
}

pub fn addValidatorToRegistry(
    allocator: Allocator,
    cached_state: *CachedBeaconStateAllForks,
    pubkey: BLSPubkey,
    withdrawal_credentials: WithdrawalCredentials,
    amount: u64,
) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const validators = state.validators();
    // add validator and balance entries
    const effective_balance = @min(
        amount - (amount % preset.EFFECTIVE_BALANCE_INCREMENT),
        if (state.isPreElectra()) preset.MAX_EFFECTIVE_BALANCE else getMaxEffectiveBalance(withdrawal_credentials),
    );

    try validators.append(allocator, .{
        .pubkey = pubkey,
        .withdrawal_credentials = withdrawal_credentials,
        .activation_eligibility_epoch = c.FAR_FUTURE_EPOCH,
        .activation_epoch = c.FAR_FUTURE_EPOCH,
        .exit_epoch = c.FAR_FUTURE_EPOCH,
        .withdrawable_epoch = c.FAR_FUTURE_EPOCH,
        .effective_balance = effective_balance,
        .slashed = false,
    });

    const validator_index = validators.items.len - 1;
    // TODO Electra: Review this
    // Updating here is better than updating at once on epoch transition
    // - Simplify genesis fn applyDeposits(): effectiveBalanceIncrements is populated immediately
    // - Keep related code together to reduce risk of breaking this cache
    // - Should have equal performance since it sets a value in a flat array
    try epoch_cache.effectiveBalanceIncrementsSet(allocator, validator_index, effective_balance);

    // now that there is a new validator, update the epoch context with the new pubkey
    try epoch_cache.addPubkey(validator_index, pubkey);

    // Only after altair:
    if (state.isPostAltair()) {
        const inactivity_scores = state.inactivityScores();
        try inactivity_scores.append(allocator, 0);

        // add participation caches
        try state.previousEpochParticipations().append(allocator, 0);
        const state_current_epoch_participations = state.currentEpochParticipations();
        try state_current_epoch_participations.append(allocator, 0);
    }
    const balances = state.balances();

    try balances.append(allocator, amount);
}

/// refer to https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#new-is_valid_deposit_signature
/// no need to return error union since consumer does not care about the reason of failure
pub fn isValidDepositSignature(config: *const BeaconConfig, pubkey: BLSPubkey, withdrawal_credential: WithdrawalCredentials, amount: u64, deposit_signature: BLSSignature) bool {
    // verify the deposit signature (proof of posession) which is not checked by the deposit contract
    const deposit_message = DepositMessage{
        .pubkey = pubkey,
        .withdrawal_credentials = withdrawal_credential,
        .amount = amount,
    };

    const GENESIS_FORK_VERSION = config.chain.GENESIS_FORK_VERSION;

    // fork-agnostic domain since deposits are valid across forks
    var domain: Domain = undefined;
    computeDomain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, ZERO_HASH, &domain) catch return false;
    var signing_root: Root = undefined;
    computeSigningRoot(types.phase0.DepositMessage, &deposit_message, &domain, &signing_root) catch return false;

    // Pubkeys must be checked for group + inf. This must be done only once when the validator deposit is processed
    const public_key = blst.PublicKey.uncompress(&pubkey) catch return false;
    public_key.validate() catch return false;
    const signature = blst.Signature.uncompress(&deposit_signature) catch return false;
    signature.validate(true) catch return false;
    return verify(&signing_root, &public_key, &signature, null, null);
}
