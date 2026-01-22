const Node = @import("persistent_merkle_tree").Node;
const ForkSeq = @import("config").ForkSeq;
const active_preset = @import("preset").active_preset;
const std = @import("std");
const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const test_case = @import("../test_case.zig");
const TestCaseUtils = test_case.TestCaseUtils;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;

pub const EpochProcessingFn = enum {
    effective_balance_updates,
    eth1_data_reset,
    historical_roots_update,
    inactivity_updates,
    justification_and_finalization,
    participation_flag_updates,
    participation_record_updates,
    randao_mixes_reset,
    registry_updates,
    rewards_and_penalties,
    slashings,
    slashings_reset,
    sync_committee_updates,
    historical_summaries_update,
    pending_deposits,
    pending_consolidations,
    proposer_lookahead,

    pub fn suiteName(self: EpochProcessingFn) []const u8 {
        return @tagName(self) ++ "/pyspec_tests";
    }
};

pub fn TestCase(comptime fork: ForkSeq, comptime epoch_process_fn: EpochProcessingFn) type {
    const tc_utils = TestCaseUtils(fork);

    return struct {
        pre: TestCachedBeaconState,
        // a null post state means the test is expected to fail
        post: ?*AnyBeaconState,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            const pool_size = if (active_preset == .mainnet) 10_000_000 else 1_000_000;
            var pool = try Node.Pool.init(allocator, pool_size);
            defer pool.deinit();

            var tc = try Self.init(allocator, &pool, dir);
            defer tc.deinit();

            try tc.runTest();
        }

        pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .post = undefined,
            };

            // load pre state
            tc.pre = try tc_utils.loadPreState(allocator, pool, dir);
            errdefer tc.pre.deinit();

            // load pre state
            tc.post = try tc_utils.loadPostState(allocator, pool, dir);

            return tc;
        }

        pub fn deinit(self: *Self) void {
            self.pre.deinit();
            if (self.post) |post| {
                post.deinit();
                self.pre.allocator.destroy(post);
            }
            state_transition.deinitStateTransition();
        }

        fn runTest(self: *Self) !void {
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

        fn process(self: *Self) !void {
            const pre = self.pre.cached_state;
            const allocator = self.pre.allocator;
            var epoch_transition_cache = try EpochTransitionCache.init(allocator, self.pre.cached_state);
            defer {
                epoch_transition_cache.deinit();
                allocator.destroy(epoch_transition_cache);
            }

            switch (epoch_process_fn) {
                .effective_balance_updates => _ = try state_transition.processEffectiveBalanceUpdates(allocator, pre, epoch_transition_cache),
                .eth1_data_reset => try state_transition.processEth1DataReset(pre, epoch_transition_cache),
                .historical_roots_update => try state_transition.processHistoricalRootsUpdate(pre, epoch_transition_cache),
                .inactivity_updates => try state_transition.processInactivityUpdates(pre, epoch_transition_cache),
                .justification_and_finalization => try state_transition.processJustificationAndFinalization(pre, epoch_transition_cache),
                .participation_flag_updates => try state_transition.processParticipationFlagUpdates(pre),
                .participation_record_updates => try state_transition.processParticipationRecordUpdates(pre),
                .randao_mixes_reset => try state_transition.processRandaoMixesReset(pre, epoch_transition_cache),
                .registry_updates => try state_transition.processRegistryUpdates(pre, epoch_transition_cache),
                .rewards_and_penalties => try state_transition.processRewardsAndPenalties(allocator, pre, epoch_transition_cache),
                .slashings => try state_transition.processSlashings(allocator, pre, epoch_transition_cache),
                .slashings_reset => try state_transition.processSlashingsReset(pre, epoch_transition_cache),
                .sync_committee_updates => try state_transition.processSyncCommitteeUpdates(allocator, pre),
                .historical_summaries_update => try state_transition.processHistoricalSummariesUpdate(pre, epoch_transition_cache),
                .pending_deposits => try state_transition.processPendingDeposits(allocator, pre, epoch_transition_cache),
                .pending_consolidations => try state_transition.processPendingConsolidations(pre, epoch_transition_cache),
                .proposer_lookahead => {
                    try state_transition.processProposerLookahead(allocator, pre, epoch_transition_cache);
                },
            }
        }
    };
}
