const std = @import("std");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const state_transition = @import("state_transition");
const EpochTransitionCache = state_transition.EpochTransitionCache;
const Node = @import("persistent_merkle_tree").Node;

pub const TestOpt = struct {
    alloc: bool = false,
    err_return: bool = false,
    void_return: bool = false,
    fulu: bool = false,
};

pub fn TestRunner(process_epoch_fn: anytype, opt: TestOpt) type {
    return struct {
        pub fn testProcessEpochFn() !void {
            const allocator = std.testing.allocator;
            const validator_count_arr = &.{ 256, 10_000 };

            var pool = try Node.Pool.init(allocator, 1024);
            defer pool.deinit();

            inline for (validator_count_arr) |validator_count| {
                var test_state = try TestCachedBeaconState.init(allocator, &pool, validator_count);
                defer test_state.deinit();

                if (opt.fulu) {
                    try state_transition.upgradeStateToFulu(allocator, test_state.cached_state);
                }

                var epoch_transition_cache = try EpochTransitionCache.init(
                    allocator,
                    test_state.cached_state,
                );
                defer {
                    epoch_transition_cache.deinit();
                    allocator.destroy(epoch_transition_cache);
                }

                if (opt.void_return) {
                    if (opt.err_return) {
                        // with try
                        if (opt.alloc) {
                            try process_epoch_fn(allocator, test_state.cached_state, epoch_transition_cache);
                        } else {
                            try process_epoch_fn(test_state.cached_state, epoch_transition_cache);
                        }
                    } else {
                        // no try
                        if (opt.alloc) {
                            process_epoch_fn(allocator, test_state.cached_state, epoch_transition_cache);
                        } else {
                            process_epoch_fn(test_state.cached_state, epoch_transition_cache);
                        }
                    }
                } else {
                    if (opt.err_return) {
                        // with try
                        if (opt.alloc) {
                            _ = try process_epoch_fn(allocator, test_state.cached_state, epoch_transition_cache);
                        } else {
                            _ = try process_epoch_fn(test_state.cached_state, epoch_transition_cache);
                        }
                    } else {
                        // no try
                        if (opt.alloc) {
                            _ = process_epoch_fn(allocator, test_state.cached_state, epoch_transition_cache);
                        } else {
                            _ = process_epoch_fn(test_state.cached_state, epoch_transition_cache);
                        }
                    }
                }
            }
        }
    };
}
