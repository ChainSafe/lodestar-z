const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const upgradeStateToFulu = @import("../slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;
const TestCachedBeaconState = @import("generate_state.zig").TestCachedBeaconState;
const BeaconConfig = @import("config").BeaconConfig;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
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
                    try upgradeStateToFulu(allocator, test_state.cached_state);
                }

                var epoch_transition_cache = try EpochTransitionCache.init(
                    allocator,
                    test_state.cached_state.config,
                    test_state.cached_state.getEpochCache(),
                    test_state.cached_state.state,
                );
                defer {
                    epoch_transition_cache.deinit();
                    allocator.destroy(epoch_transition_cache);
                }

                const state = test_state.cached_state.state;
                const config = test_state.cached_state.config;
                const epoch_cache = test_state.cached_state.getEpochCache();
                const FnType = @TypeOf(process_epoch_fn);
                const fn_info = @typeInfo(FnType).@"fn";
                const Args = std.meta.ArgsTuple(FnType);

                switch (state.forkSeq()) {
                    inline else => |f| {
                        const fork_state = &@field(state, @tagName(f));
                        const ForkStatePtr = @TypeOf(fork_state);
                        const ForkStateVal = @TypeOf(fork_state.*);
                        var args: Args = undefined;

                        inline for (fn_info.params, 0..) |param, i| {
                            const ptype = param.type orelse @compileError("TestRunner does not support anytype params");
                            const field_name = comptime std.fmt.comptimePrint("{d}", .{i});

                            if (ptype == ForkSeq) {
                                @field(args, field_name) = f;
                            } else if (ptype == Allocator) {
                                @field(args, field_name) = allocator;
                            } else if (ptype == *const BeaconConfig or ptype == *BeaconConfig) {
                                @field(args, field_name) = config;
                            } else if (ptype == *const EpochCache or ptype == *EpochCache) {
                                @field(args, field_name) = epoch_cache;
                            } else if (ptype == ForkStatePtr or ptype == *const ForkStateVal) {
                                @field(args, field_name) = fork_state;
                            } else if (ptype == ForkStateVal) {
                                @field(args, field_name) = fork_state.*;
                            } else if (ptype == *const EpochTransitionCache or ptype == *EpochTransitionCache) {
                                @field(args, field_name) = epoch_transition_cache;
                            } else {
                                @compileError("TestRunner unsupported param type: " ++ @typeName(ptype));
                            }
                        }

                        if (opt.void_return) {
                            if (opt.err_return) {
                                try @call(.auto, process_epoch_fn, args);
                            } else {
                                @call(.auto, process_epoch_fn, args);
                            }
                        } else {
                            if (opt.err_return) {
                                _ = try @call(.auto, process_epoch_fn, args);
                            } else {
                                _ = @call(.auto, process_epoch_fn, args);
                            }
                        }
                    },
                }
            }
        }
    };
}
