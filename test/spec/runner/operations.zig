const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ssz = @import("consensus_types");
const Root = ssz.primitive.Root.Type;
const ForkSeq = @import("config").ForkSeq;
const preset = @import("preset").preset;
const active_preset = @import("preset").active_preset;
const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const BeaconBlock = @import("fork_types").BeaconBlock;
const BeaconBlockBody = @import("fork_types").BeaconBlockBody;
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
    execution_payload_bid,
    payload_attestation,
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
            .execution_payload_bid => "block",
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
            .execution_payload_bid => "BeaconBlock",
            .payload_attestation => "PayloadAttestation",
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

fn loadExecutionValid(allocator: std.mem.Allocator, dir: std.fs.Dir) bool {
    var file = dir.openFile("execution.yaml", .{}) catch return true;
    defer file.close();
    const contents = file.readToEndAlloc(allocator, 1024) catch return true;
    defer allocator.free(contents);
    // Parse "{execution_valid: false}" or "{execution_valid: true}"
    if (std.mem.indexOf(u8, contents, "false")) |_| return false;
    return true;
}

pub fn TestCase(comptime fork: ForkSeq, comptime operation: Operation) type {
    const ForkTypes = @field(ssz, fork.name());
    const tc_utils = TestCaseUtils(fork);
    // After EIP-7732, gloas execution_payload tests use SignedExecutionPayloadEnvelope
    const is_gloas_exec_payload = comptime (operation == .execution_payload and fork.gte(.gloas));
    const OpType = if (is_gloas_exec_payload)
        ForkTypes.SignedExecutionPayloadEnvelope
    else
        @field(ForkTypes, operation.operationObject());

    return struct {
        pre: TestCachedBeaconState,
        // a null post state means the test is expected to fail
        post: ?*AnyBeaconState,
        op: OpType.Type,
        bls_setting: BlsSetting,
        execution_valid: bool,

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
                .execution_valid = loadExecutionValid(allocator, dir),
            };

            // load pre state
            tc.pre = try tc_utils.loadPreState(allocator, pool, dir);
            errdefer tc.pre.deinit();

            // load pre state
            tc.post = try tc_utils.loadPostState(allocator, pool, dir);

            // load the op
            // After EIP-7732, gloas withdrawals tests don't have an execution_payload input file
            const input_name = comptime if (is_gloas_exec_payload)
                "signed_envelope"
            else
                operation.inputName();
            if (comptime !(operation == .withdrawals and fork.gte(.gloas))) {
                try loadSszValue(OpType, allocator, dir, input_name ++ ".ssz_snappy", &tc.op);
            }
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
            const cached_state = self.pre.cached_state;
            const state = cached_state.state.castToFork(fork);

            switch (operation) {
                .attestation => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    var attestations = [_]ForkTypes.Attestation.Type{self.op};
                    try state_transition.processAttestations(
                        fork,
                        allocator,
                        config,
                        epoch_cache,
                        state,
                        &cached_state.slashings_cache,
                        attestations[0..],
                        verify,
                    );
                },
                .attester_slashing => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    const current_epoch = epoch_cache.epoch;
                    try state_transition.processAttesterSlashing(
                        fork,
                        allocator,
                        config,
                        epoch_cache,
                        state,
                        &cached_state.slashings_cache,
                        current_epoch,
                        &self.op,
                        verify,
                    );
                },
                .block_header => {
                    const epoch_cache = cached_state.epoch_cache;
                    const fork_block = BeaconBlock(.full, fork){ .inner = self.op };
                    try state_transition.processBlockHeader(
                        fork,
                        allocator,
                        epoch_cache,
                        state,
                        .full,
                        &fork_block,
                    );
                },
                .bls_to_execution_change => {
                    const config = cached_state.config;
                    try state_transition.processBlsToExecutionChange(fork, config, state, &self.op);
                },
                .consolidation_request => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processConsolidationRequest(fork, config, epoch_cache, state, &self.op);
                },
                .deposit => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processDeposit(fork, allocator, config, epoch_cache, state, &self.op);
                },
                .deposit_request => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processDepositRequest(fork, allocator, config, epoch_cache, state, &self.op);
                },
                .execution_payload => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    if (comptime is_gloas_exec_payload) {
                        // After EIP-7732, execution_payload tests use processExecutionPayloadEnvelope
                        if (!self.execution_valid) {
                            return error.ExecutionPayloadInvalid;
                        }
                        try state_transition.processExecutionPayloadEnvelope(
                            allocator,
                            config,
                            epoch_cache,
                            state,
                            &self.op,
                            .{ .verify_signature = true, .verify_state_root = true },
                        );
                    } else {
                        const current_epoch = epoch_cache.epoch;
                        const fork_body = BeaconBlockBody(.full, fork){ .inner = self.op };
                        try state_transition.processExecutionPayload(
                            fork,
                            allocator,
                            config,
                            state,
                            current_epoch,
                            .full,
                            &fork_body,
                            .{
                                .data_availability_status = .available,
                                .execution_payload_status = if (self.post != null) .valid else .invalid,
                            },
                        );
                    }
                },
                .execution_payload_bid => {
                    const config = cached_state.config;
                    const fork_block = BeaconBlock(.full, fork){ .inner = self.op };
                    try state_transition.processExecutionPayloadBid(allocator, config, state, &fork_block);
                },
                .payload_attestation => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processPayloadAttestation(allocator, config, epoch_cache, state, &self.op);
                },
                .proposer_slashing => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processProposerSlashing(
                        fork,
                        allocator,
                        config,
                        epoch_cache,
                        state,
                        &cached_state.slashings_cache,
                        &self.op,
                        verify,
                    );
                },
                .sync_aggregate => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processSyncAggregate(
                        fork,
                        allocator,
                        config,
                        epoch_cache,
                        state,
                        &self.op,
                        verify,
                    );
                },
                .voluntary_exit => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processVoluntaryExit(
                        fork,
                        allocator,
                        config,
                        epoch_cache,
                        state,
                        &self.op,
                        verify,
                    );
                },
                .withdrawal_request => {
                    const config = cached_state.config;
                    const epoch_cache = cached_state.epoch_cache;
                    try state_transition.processWithdrawalRequest(fork, config, epoch_cache, state, &self.op);
                },
                .withdrawals => {
                    const epoch_cache = cached_state.epoch_cache;
                    var withdrawals_result = WithdrawalsResult{
                        .withdrawals = try Withdrawals.initCapacity(
                            allocator,
                            preset.MAX_WITHDRAWALS_PER_PAYLOAD,
                        ),
                    };
                    defer withdrawals_result.withdrawals.deinit(allocator);

                    var withdrawal_balances = std.AutoHashMap(u64, usize).init(allocator);
                    defer withdrawal_balances.deinit();

                    try state_transition.getExpectedWithdrawals(
                        fork,
                        allocator,
                        epoch_cache,
                        state,
                        &withdrawals_result,
                        &withdrawal_balances,
                    );

                    // After EIP-7732, gloas withdrawals don't use payload verification
                    var payload_withdrawals_root: Root = undefined;
                    if (comptime fork.lt(.gloas)) {
                        // self.op is ExecutionPayload in this case
                        try ssz.capella.Withdrawals.hashTreeRoot(allocator, &self.op.withdrawals, &payload_withdrawals_root);
                    }

                    try state_transition.processWithdrawals(
                        fork,
                        allocator,
                        state,
                        withdrawals_result,
                        payload_withdrawals_root,
                    );
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
