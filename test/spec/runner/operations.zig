const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ssz = @import("consensus_types");
const Root = ssz.primitive.Root.Type;
const ForkSeq = @import("config").ForkSeq;
const preset = @import("preset").preset;
const active_preset = @import("preset").active_preset;
const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const BeaconState = state_transition.BeaconState;
const Withdrawals = ssz.capella.Withdrawals.Type;
const WithdrawalsResult = state_transition.WithdrawalsResult;
const test_case = @import("../test_case.zig");
const TestCaseUtils = test_case.TestCaseUtils;
const loadSszValue = test_case.loadSszSnappyValue;
const loadBlsSetting = test_case.loadBlsSetting;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;
const BlsSetting = test_case.BlsSetting;

/// See https://github.com/ethereum/consensus-specs/tree/master/tests/formats/operations#operations-tests
pub const Operation = enum {
    attestation,
    attester_slashing,
    block_header,
    bls_to_execution_change,
    consolidation_request,
    deposit,
    deposit_request,
    execution_payload,
    proposer_slashing,
    sync_aggregate,
    voluntary_exit,
    withdrawal_request,
    withdrawals,

    pub fn inputName(self: Operation) []const u8 {
        return switch (self) {
            .block_header => "block",
            .bls_to_execution_change => "address_change",
            .execution_payload => "body",
            .withdrawals => "execution_payload",
            else => @tagName(self),
        };
    }

    pub fn operationObject(self: Operation) []const u8 {
        return switch (self) {
            .attestation => "Attestation",
            .attester_slashing => "AttesterSlashing",
            .block_header => "BeaconBlock",
            .bls_to_execution_change => "SignedBLSToExecutionChange",
            .consolidation_request => "ConsolidationRequest",
            .deposit => "Deposit",
            .deposit_request => "DepositRequest",
            .execution_payload => "BeaconBlockBody",
            .proposer_slashing => "ProposerSlashing",
            .sync_aggregate => "SyncAggregate",
            .voluntary_exit => "SignedVoluntaryExit",
            .withdrawal_request => "WithdrawalRequest",
            .withdrawals => "ExecutionPayload",
        };
    }

    pub fn suiteName(self: Operation) []const u8 {
        return @tagName(self) ++ "/pyspec_tests";
    }
};

pub const Handler = Operation;

pub fn TestCase(comptime fork: ForkSeq, comptime operation: Operation) type {
    const ForkTypes = @field(ssz, fork.name());
    const tc_utils = TestCaseUtils(fork);
    const OpType = @field(ForkTypes, operation.operationObject());

    return struct {
        pre: TestCachedBeaconState,
        // a null post state means the test is expected to fail
        post: ?*BeaconState,
        op: OpType.Type,
        bls_setting: BlsSetting,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            const pool_size = if (active_preset == .mainnet) 10_000_000 else 1_000_000;
            var pool = try Node.Pool.init(allocator, pool_size);
            defer pool.deinit();

            var tc = try Self.init(allocator, &pool, dir);
            defer {
                tc.deinit();
                state_transition.deinitStateTransition();
            }

            try tc.runTest();
        }

        pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .post = undefined,
                .op = OpType.default_value,
                .bls_setting = loadBlsSetting(allocator, dir),
            };

            // load pre state
            tc.pre = try tc_utils.loadPreState(allocator, pool, dir);
            errdefer tc.pre.deinit();

            // load pre state
            tc.post = try tc_utils.loadPostState(allocator, pool, dir);

            // load the op
            try loadSszValue(OpType, allocator, dir, comptime operation.inputName() ++ ".ssz_snappy", &tc.op);
            errdefer {
                if (comptime @hasDecl(OpType, "deinit")) {
                    OpType.deinit(allocator, &tc.op);
                }
            }

            return tc;
        }

        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(OpType, "deinit")) {
                OpType.deinit(self.pre.allocator, &self.op);
            }
            self.pre.deinit();
            if (self.post) |post| {
                post.deinit();
                self.pre.allocator.destroy(post);
            }
        }

        pub fn process(self: *Self) !void {
            const verify = self.bls_setting.verify();
            const allocator = self.pre.allocator;

            switch (operation) {
                .attestation => {
                    const attestations_fork: ForkSeq = if (fork.gte(.electra)) .electra else .phase0;
                    var attestations = @field(ssz, attestations_fork.name()).Attestations.default_value;
                    defer attestations.deinit(allocator);
                    const attestation: *@field(ssz, attestations_fork.name()).Attestation.Type = @ptrCast(@alignCast(&self.op));
                    try attestations.append(allocator, attestation.*);
                    const atts = attestations;
                    const attestations_wrapper: state_transition.Attestations = if (fork.gte(.electra))
                        .{ .electra = &atts }
                    else
                        .{ .phase0 = &atts };

                    try state_transition.processAttestations(allocator, self.pre.cached_state, attestations_wrapper, verify);
                },
                .attester_slashing => {
                    try state_transition.processAttesterSlashing(OpType.Type, self.pre.cached_state, &self.op, verify);
                },
                .block_header => {
                    const block = state_transition.Block{ .regular = @unionInit(state_transition.BeaconBlock, @tagName(fork), &self.op) };
                    try state_transition.processBlockHeader(allocator, self.pre.cached_state, block);
                },
                .bls_to_execution_change => {
                    try state_transition.processBlsToExecutionChange(self.pre.cached_state, &self.op);
                },
                .consolidation_request => {
                    try state_transition.processConsolidationRequest(self.pre.cached_state, &self.op);
                },
                .deposit => {
                    try state_transition.processDeposit(allocator, self.pre.cached_state, &self.op);
                },
                .deposit_request => {
                    try state_transition.processDepositRequest(self.pre.cached_state, &self.op);
                },
                .execution_payload => {
                    try state_transition.processExecutionPayload(
                        allocator,
                        self.pre.cached_state,
                        .{ .regular = @unionInit(state_transition.BeaconBlockBody, @tagName(fork), &self.op) },
                        .{ .data_availability_status = .available, .execution_payload_status = if (self.post != null) .valid else .invalid },
                    );
                },
                .proposer_slashing => {
                    try state_transition.processProposerSlashing(self.pre.cached_state, &self.op, verify);
                },
                .sync_aggregate => {
                    try state_transition.processSyncAggregate(allocator, self.pre.cached_state, &self.op, verify);
                },
                .voluntary_exit => {
                    try state_transition.processVoluntaryExit(self.pre.cached_state, &self.op, verify);
                },
                .withdrawal_request => {
                    try state_transition.processWithdrawalRequest(self.pre.cached_state, &self.op);
                },
                .withdrawals => {
                    var withdrawals_result = WithdrawalsResult{
                        .withdrawals = try Withdrawals.initCapacity(
                            allocator,
                            preset.MAX_WITHDRAWALS_PER_PAYLOAD,
                        ),
                    };

                    var withdrawal_balances = std.AutoHashMap(u64, usize).init(allocator);
                    defer withdrawal_balances.deinit();

                    try state_transition.getExpectedWithdrawals(allocator, &withdrawals_result, &withdrawal_balances, self.pre.cached_state);
                    defer withdrawals_result.withdrawals.deinit(allocator);

                    var payload_withdrawals_root: Root = undefined;
                    // self.op is ExecutionPayload in this case
                    try ssz.capella.Withdrawals.hashTreeRoot(allocator, &self.op.withdrawals, &payload_withdrawals_root);

                    try state_transition.processWithdrawals(allocator, self.pre.cached_state, withdrawals_result, payload_withdrawals_root);
                },
            }
        }

        pub fn runTest(self: *Self) !void {
            if (self.post) |post| {
                try self.process();
                try expectEqualBeaconStates(post, self.pre.cached_state.state);
            } else {
                self.process() catch |err| {
                    if (err == error.SkipZigTest) {
                        return err;
                    }
                    return;
                };
                return error.ExpectedError;
            }
        }
    };
}
