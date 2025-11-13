const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Body = @import("../types/signed_block.zig").Body;

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
    cached_state: *CachedBeaconStateAllForks,
    body: Body,
    opts: ProcessBlockOpts,
) !void {
    const state = cached_state.state;

    // verify that outstanding deposits are processed up to the maximum number of deposits
    const max_deposits = getEth1DepositCount(cached_state, null);
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

    if (state.isPostCapella()) {
        for (body.blsToExecutionChanges()) |*bls_to_execution_change| {
            try processBlsToExecutionChange(cached_state, bls_to_execution_change);
        }
    }

    if (state.isPostElectra()) {
        for (body.depositRequests()) |*deposit_request| {
            try processDepositRequest(allocator, cached_state, deposit_request);
        }

        for (body.withdrawalRequests()) |*withdrawal_request| {
            try processWithdrawalRequest(allocator, cached_state, withdrawal_request);
        }

        for (body.consolidationRequests()) |*consolidation_request| {
            try processConsolidationRequest(allocator, cached_state, consolidation_request);
        }
    }
}
