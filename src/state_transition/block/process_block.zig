const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Block = @import("../types/block.zig").Block;
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;
const Withdrawals = types.capella.Withdrawals.Type;
const WithdrawalsResult = @import("./process_withdrawals.zig").WithdrawalsResult;
const processBlobKzgCommitments = @import("./process_blob_kzg_commitments.zig").processBlobKzgCommitments;
const processBlockHeader = @import("./process_block_header.zig").processBlockHeader;
const processEth1Data = @import("./process_eth1_data.zig").processEth1Data;
const processExecutionPayload = @import("./process_execution_payload.zig").processExecutionPayload;
const processOperations = @import("./process_operations.zig").processOperations;
const processRandao = @import("./process_randao.zig").processRandao;
const processSyncAggregate = @import("./process_sync_committee.zig").processSyncAggregate;
const processWithdrawals = @import("./process_withdrawals.zig").processWithdrawals;
const getExpectedWithdrawals = @import("./process_withdrawals.zig").getExpectedWithdrawals;
const isExecutionEnabled = @import("../utils/execution.zig").isExecutionEnabled;
// TODO: proposer reward api
// const ProposerRewardType = @import("../types/proposer_reward.zig").ProposerRewardType;

pub const ProcessBlockOpts = struct {
    verify_signature: bool = true,
};

pub fn processBlock(
    allocator: Allocator,
    cached_state: *CachedBeaconStateAllForks,
    block: Block,
    external_data: BlockExternalData,
    opts: ProcessBlockOpts,
    // TODO: metrics
) !void {
    const state = cached_state.state;
    const body = block.beaconBlockBody();

    try processBlockHeader(allocator, cached_state, block);

    // The call to the process_execution_payload must happen before the call to the process_randao as the former depends
    // on the randao_mix computed with the reveal of the previous block.
    if (state.isPostBellatrix() and isExecutionEnabled(cached_state.state, block)) {
        // TODO Deneb: Allow to disable withdrawals for interop testing
        // https://github.com/ethereum/consensus-specs/blob/b62c9e877990242d63aa17a2a59a49bc649a2f2e/specs/eip4844/beacon-chain.md#disabling-withdrawals
        if (state.isPostCapella()) {
            // TODO: given max withdrawals of MAX_WITHDRAWALS_PER_PAYLOAD, can use fixed size array instead of heap alloc
            var withdrawals_result = WithdrawalsResult{ .withdrawals = try Withdrawals.initCapacity(
                allocator,
                preset.MAX_WITHDRAWALS_PER_PAYLOAD,
            ) };
            var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
            defer withdrawal_balances.deinit();

            try getExpectedWithdrawals(allocator, &withdrawals_result, &withdrawal_balances, cached_state);
            defer withdrawals_result.withdrawals.deinit(allocator);

            const payload_withdrawals_root = switch (body) {
                .regular => |b| blk: {
                    const actual_withdrawals = b.executionPayload().getWithdrawals();
                    std.debug.assert(withdrawals_result.withdrawals.items.len == actual_withdrawals.items.len);
                    var root: Root = undefined;
                    try types.capella.Withdrawals.hashTreeRoot(allocator, &actual_withdrawals, &root);
                    break :blk root;
                },
                .blinded => |b| b.executionPayloadHeader().getWithdrawalsRoot(),
            };
            try processWithdrawals(allocator, cached_state, withdrawals_result, payload_withdrawals_root);
        }

        try processExecutionPayload(
            allocator,
            cached_state,
            body,
            external_data,
        );
    }

    try processRandao(cached_state, body, block.proposerIndex(), opts.verify_signature);
    try processEth1Data(allocator, cached_state, body.eth1Data());
    try processOperations(allocator, cached_state, body, opts);
    if (state.isPostAltair()) {
        try processSyncAggregate(allocator, cached_state, block, opts.verify_signature);
    }

    if (state.isPostDeneb()) {
        try processBlobKzgCommitments(external_data);
        // Only throw PreData so beacon can also sync/process blocks optimistically
        // and let forkChoice handle it
        if (external_data.data_availability_status == .pre_data) {
            return error.DataAvailabilityPreData;
        }
    }
}
