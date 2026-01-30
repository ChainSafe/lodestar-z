const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const BlockType = @import("fork_types").BlockType;
const BeaconBlockBody = @import("fork_types").BeaconBlockBody;
const ForkTypes = @import("fork_types").ForkTypes;
const ct = @import("consensus_types");
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;

const getEth1DepositCount = @import("../utils/deposit.zig").getEth1DepositCount;
const processAttestations = @import("./process_attestations.zig").processAttestations;
const processAttesterSlashing = @import("./process_attester_slashing.zig").processAttesterSlashing;
const processBlsToExecutionChange = @import("./process_bls_to_execution_change.zig").processBlsToExecutionChange;
const processConsolidationRequest = @import("./process_consolidation_request.zig").processConsolidationRequest;
const processDeposit = @import("./process_deposit.zig").processDeposit;
const processDepositRequest = @import("./process_deposit_request.zig").processDepositRequest;
const processProposerSlashing = @import("./process_proposer_slashing.zig").processProposerSlashing;
const processVoluntaryExit = @import("./process_voluntary_exit.zig").processVoluntaryExit;
const processWithdrawalRequest = @import("./process_withdrawal_request.zig").processWithdrawalRequest;
const Node = @import("persistent_merkle_tree").Node;
const ProcessBlockOpts = @import("./process_block.zig").ProcessBlockOpts;

pub fn processOperations(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *SlashingsCache,
    comptime block_type: BlockType,
    body: *const BeaconBlockBody(block_type, fork),
    opts: ProcessBlockOpts,
) !void {
    // verify that outstanding deposits are processed up to the maximum number of deposits
    const max_deposits = try getEth1DepositCount(fork, state, null);
    if (body.inner.deposits.items.len != max_deposits) {
        return error.InvalidDepositCount;
    }

    const current_epoch = epoch_cache.epoch;

    for (body.inner.proposer_slashings.items) |*proposer_slashing| {
        try processProposerSlashing(fork, config, epoch_cache, state, slashings_cache, proposer_slashing, opts.verify_signature);
    }

    for (body.inner.attester_slashings.items) |*attester_slashing| {
        try processAttesterSlashing(
            fork,
            allocator,
            config,
            epoch_cache,
            state,
            slashings_cache,
            current_epoch,
            attester_slashing,
            opts.verify_signature,
        );
    }

    try processAttestations(fork, allocator, config, epoch_cache, state, slashings_cache, body.inner.attestations.items, opts.verify_signature);

    for (body.inner.deposits.items) |*deposit| {
        try processDeposit(fork, allocator, config, epoch_cache, state, deposit);
    }

    for (body.inner.voluntary_exits.items) |*voluntary_exit| {
        try processVoluntaryExit(fork, config, epoch_cache, state, voluntary_exit, opts.verify_signature);
    }

    if (comptime fork.gte(.capella)) {
        for (body.inner.bls_to_execution_changes.items) |*bls_to_execution_change| {
            try processBlsToExecutionChange(fork, config, state, bls_to_execution_change);
        }
    }

    if (comptime fork.gte(.electra)) {
        const execution_requests = &body.inner.execution_requests;
        for (execution_requests.deposits.items) |*deposit_request| {
            try processDepositRequest(fork, state, deposit_request);
        }

        for (execution_requests.withdrawals.items) |*withdrawal_request| {
            try processWithdrawalRequest(fork, config, epoch_cache, state, withdrawal_request);
        }

        for (execution_requests.consolidations.items) |*consolidation_request| {
            try processConsolidationRequest(fork, config, epoch_cache, state, consolidation_request);
        }
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const AnyBeaconBlock = @import("fork_types").AnyBeaconBlock;

test "process operations" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var electra_block = ct.electra.BeaconBlock.default_value;
    const beacon_block = AnyBeaconBlock{ .full_electra = &electra_block };

    try processOperations(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.getEpochCache(),
        try test_state.cached_state.state.tryCastToFork(.electra),
        &test_state.cached_state.slashings_cache,
        .full,
        beacon_block.beaconBlockBody().castToFork(.full, .electra),
        .{},
    );
}
