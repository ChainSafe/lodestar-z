const std = @import("std");
const ct = @import("consensus_types");
const ssz = @import("ssz");
const ForkSeq = @import("config").ForkSeq;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const TestCaseUtils = @import("../test_case.zig").TestCaseUtils;
const loadSszValue = @import("../test_case.zig").loadSszSnappyValue;

const EpochTransitionCache = state_transition.EpochTransitionCache;
const getRewardsAndPenaltiesFn = state_transition.getRewardsAndPenalties;

const preset = @import("preset").preset;

pub const Handler = enum {
    basic,
    leak,
    random,

    pub inline fn suiteName(comptime self: Handler) []const u8 {
        return @tagName(self) ++ "/pyspec_tests";
    }
};

pub fn TestCase(comptime fork: ForkSeq) type {
    const Balances = ssz.FixedListType(ct.primitive.Gwei, preset.VALIDATOR_REGISTRY_LIMIT);
    const DeltasType = ssz.VariableVectorType(Balances, 2);
    const tc_utils = TestCaseUtils(fork);

    return struct {
        pre: TestCachedBeaconStateAllForks,
        source_deltas: DeltasType.Type,
        target_deltas: DeltasType.Type,
        head_deltas: DeltasType.Type,
        inclusion_delay_deltas: DeltasType.Type,
        has_inclusion_delay_deltas: bool,
        inactivity_penalty_deltas: DeltasType.Type,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit();
            defer state_transition.deinitStateTransition();

            try tc.runTest();
        }

        fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .source_deltas = DeltasType.default_value,
                .target_deltas = DeltasType.default_value,
                .head_deltas = DeltasType.default_value,
                .inclusion_delay_deltas = DeltasType.default_value,
                .has_inclusion_delay_deltas = false,
                .inactivity_penalty_deltas = DeltasType.default_value,
            };

            tc.pre = try tc_utils.loadPreState(allocator, dir);
            errdefer tc.pre.deinit();

            const cache_allocator = tc.pre.allocator;

            tc.source_deltas = try Self.loadDeltas(cache_allocator, dir, "source_deltas.ssz_snappy");
            errdefer DeltasType.deinit(cache_allocator, &tc.source_deltas);

            tc.target_deltas = try Self.loadDeltas(cache_allocator, dir, "target_deltas.ssz_snappy");
            errdefer DeltasType.deinit(cache_allocator, &tc.target_deltas);

            tc.head_deltas = try Self.loadDeltas(cache_allocator, dir, "head_deltas.ssz_snappy");
            errdefer DeltasType.deinit(cache_allocator, &tc.head_deltas);

            if (try Self.loadOptionalDeltas(cache_allocator, dir, "inclusion_delay_deltas.ssz_snappy")) |deltas| {
                tc.inclusion_delay_deltas = deltas;
                tc.has_inclusion_delay_deltas = true;
                errdefer DeltasType.deinit(cache_allocator, &tc.inclusion_delay_deltas);
            }

            tc.inactivity_penalty_deltas = try Self.loadDeltas(cache_allocator, dir, "inactivity_penalty_deltas.ssz_snappy");
            errdefer DeltasType.deinit(cache_allocator, &tc.inactivity_penalty_deltas);

            return tc;
        }

        fn deinit(self: *Self) void {
            const allocator = self.pre.allocator;
            DeltasType.deinit(allocator, &self.source_deltas);
            DeltasType.deinit(allocator, &self.target_deltas);
            DeltasType.deinit(allocator, &self.head_deltas);
            DeltasType.deinit(allocator, &self.inclusion_delay_deltas);
            DeltasType.deinit(allocator, &self.inactivity_penalty_deltas);
            self.pre.deinit();
        }

        fn loadDeltas(allocator: std.mem.Allocator, dir: std.fs.Dir, comptime filename: []const u8) !DeltasType.Type {
            var deltas = DeltasType.default_value;
            loadSszValue(DeltasType, allocator, dir, filename, &deltas) catch |err| {
                if (comptime @hasDecl(DeltasType, "deinit")) {
                    DeltasType.deinit(allocator, &deltas);
                }
                return err;
            };
            return deltas;
        }

        fn loadOptionalDeltas(allocator: std.mem.Allocator, dir: std.fs.Dir, comptime filename: []const u8) !?DeltasType.Type {
            var deltas = DeltasType.default_value;
            loadSszValue(DeltasType, allocator, dir, filename, &deltas) catch |err| switch (err) {
                error.FileNotFound => {
                    if (comptime @hasDecl(DeltasType, "deinit")) {
                        DeltasType.deinit(allocator, &deltas);
                    }
                    return null;
                },
                else => {
                    if (comptime @hasDecl(DeltasType, "deinit")) {
                        DeltasType.deinit(allocator, &deltas);
                    }
                    return err;
                },
            };
            return deltas;
        }

        fn runTest(self: *Self) !void {
            const allocator = self.pre.allocator;
            const cloned_state = try self.pre.cached_state.clone(allocator);
            defer {
                cloned_state.deinit();
                allocator.destroy(cloned_state);
            }

            var epoch_cache = try EpochTransitionCache.init(allocator, cloned_state);
            defer {
                epoch_cache.deinit();
                allocator.destroy(epoch_cache);
            }

            try getRewardsAndPenaltiesFn(allocator, cloned_state, epoch_cache, epoch_cache.rewards, epoch_cache.penalties);

            const validator_count = self.pre.cached_state.state.validators().items.len;
            const rewards = epoch_cache.rewards;
            const penalties = epoch_cache.penalties;

            const expected_rewards = try allocator.alloc(u64, validator_count);
            defer allocator.free(expected_rewards);
            const expected_penalties = try allocator.alloc(u64, validator_count);
            defer allocator.free(expected_penalties);
            @memset(expected_rewards, 0);
            @memset(expected_penalties, 0);

            try Self.accumulateDeltas(expected_rewards, expected_penalties, &self.source_deltas);
            try Self.accumulateDeltas(expected_rewards, expected_penalties, &self.target_deltas);
            try Self.accumulateDeltas(expected_rewards, expected_penalties, &self.head_deltas);
            if (self.has_inclusion_delay_deltas) {
                try Self.accumulateDeltas(expected_rewards, expected_penalties, &self.inclusion_delay_deltas);
            }
            try Self.accumulateDeltas(expected_rewards, expected_penalties, &self.inactivity_penalty_deltas);

            try std.testing.expectEqualSlices(u64, expected_rewards, rewards);
            try std.testing.expectEqualSlices(u64, expected_penalties, penalties);
        }

        fn accumulateDeltas(expected_rewards: []u64, expected_penalties: []u64, deltas: *const DeltasType.Type) !void {
            const values = deltas.*;
            const rewards = values[0].items;
            const penalties = values[1].items;

            if (rewards.len != expected_rewards.len or penalties.len != expected_penalties.len) {
                return error.InvalidDeltaLength;
            }

            for (rewards, 0..) |value, i| {
                expected_rewards[i] += value;
            }
            for (penalties, 0..) |value, i| {
                expected_penalties[i] += value;
            }
        }
    };
}
