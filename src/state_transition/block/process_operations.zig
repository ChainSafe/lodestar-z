const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Body = @import("../types/block.zig").Body;

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
    allocator: std.mem.Allocator,
    cached_state: *CachedBeaconState,
    body: Body,
    opts: ProcessBlockOpts,
) !void {
    const state = cached_state.state;

    // verify that outstanding deposits are processed up to the maximum number of deposits
    const max_deposits = try getEth1DepositCount(cached_state, null);
    if (body.deposits().len != max_deposits) {
        return error.InvalidDepositCount;
    }

    for (body.proposerSlashings()) |*proposer_slashing| {
        try processProposerSlashing(cached_state, proposer_slashing, opts.verify_signature);
    }

    const attester_slashings = body.attesterSlashings().items();
    switch (attester_slashings) {
        .phase0 => |attester_slashings_phase0| {
            for (attester_slashings_phase0) |*attester_slashing| {
                try processAttesterSlashing(types.phase0.AttesterSlashing.Type, cached_state, attester_slashing, opts.verify_signature);
            }
        },
        .electra => |attester_slashings_electra| {
            for (attester_slashings_electra) |*attester_slashing| {
                try processAttesterSlashing(types.electra.AttesterSlashing.Type, cached_state, attester_slashing, opts.verify_signature);
            }
        },
    }

    try processAttestations(allocator, cached_state, body.attestations(), opts.verify_signature);

    for (body.deposits()) |*deposit| {
        try processDeposit(allocator, cached_state, deposit);
    }

    for (body.voluntaryExits()) |*voluntary_exit| {
        try processVoluntaryExit(cached_state, voluntary_exit, opts.verify_signature);
    }

    if (state.forkSeq().gte(.capella)) {
        for (body.blsToExecutionChanges()) |*bls_to_execution_change| {
            try processBlsToExecutionChange(cached_state, bls_to_execution_change);
        }
    }

    if (state.forkSeq().gte(.electra)) {
        for (body.depositRequests()) |*deposit_request| {
            try processDepositRequest(cached_state, deposit_request);
        }

        for (body.withdrawalRequests()) |*withdrawal_request| {
            try processWithdrawalRequest(cached_state, withdrawal_request);
        }

        for (body.consolidationRequests()) |*consolidation_request| {
            try processConsolidationRequest(cached_state, consolidation_request);
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

    const electra_block = types.electra.BeaconBlock.default_value;
    const beacon_block = BeaconBlock{ .electra = &electra_block };

    const block = Block{ .regular = beacon_block };
    try processOperations(allocator, test_state.cached_state, block.beaconBlockBody(), .{});
}
