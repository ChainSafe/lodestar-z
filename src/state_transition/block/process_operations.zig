const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const ForkTypes = @import("fork_types").ForkTypes;
const ct = @import("consensus_types");

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
const ProcessBlockOpts = @import("./process_block.zig").ProcessBlockOpts;

pub fn processOperations(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    comptime block_type: BlockType,
    body: *const ForkBeaconBlockBody(fork, block_type),
    opts: ProcessBlockOpts,
) !void {
    // verify that outstanding deposits are processed up to the maximum number of deposits
    const max_deposits = try getEth1DepositCount(fork, state, null);
    if (body.inner.deposits.items.len != max_deposits) {
        return error.InvalidDepositCount;
    }

    const current_epoch = epoch_cache.epoch;

    for (body.inner.proposer_slashings.items) |*proposer_slashing| {
        try processProposerSlashing(fork, config, epoch_cache, state, proposer_slashing, opts.verify_signature);
    }

    for (body.inner.attester_slashings.items) |*attester_slashing| {
        try processAttesterSlashing(fork, allocator, config, epoch_cache, state, current_epoch, attester_slashing, opts.verify_signature);
    }

    try processAttestations(fork, allocator, config, epoch_cache, state, body.inner.attestations.items, opts.verify_signature);

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
const Block = @import("../types/block.zig").Block;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Node = @import("persistent_merkle_tree").Node;

test "process operations" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const electra_block = ct.electra.BeaconBlock.default_value;
    const beacon_block = BeaconBlock{ .electra = &electra_block };

    const block = Block{ .regular = beacon_block };
    const config = test_state.cached_state.config;
    const epoch_cache = test_state.cached_state.getEpochCache();
    const fork_state = switch (test_state.cached_state.state.*) {
        .electra => |*state_view| @as(*ForkBeaconState(.electra), @ptrCast(state_view)),
        else => return error.UnexpectedForkSeq,
    };
    const body = @as(*const ForkBeaconBlockBody(.electra, .full), @ptrCast(block.beaconBlockBody()));
    try processOperations(.electra, allocator, config, epoch_cache, fork_state, .full, body, .{});
}
