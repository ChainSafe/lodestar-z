const std = @import("std");
const napi = @import("zapi:zapi").napi;
const st = @import("state_transition");

const EnvironmentState = struct {
    allocator: std.mem.Allocator,
    reused_epoch_transition_cache: ?st.ReusedEpochTransitionCache = null,

    fn finalize(_: napi.Env, state: *EnvironmentState, _: ?*anyopaque) void {
        if (state.reused_epoch_transition_cache) |*reused_cache| {
            reused_cache.deinit();
        }
        const allocator = state.allocator;
        allocator.destroy(state);
    }
};

fn getOrCreate(env: napi.Env, allocator: std.mem.Allocator) !*EnvironmentState {
    if (try env.getInstanceData(EnvironmentState)) |state| return state;

    const state = try allocator.create(EnvironmentState);
    errdefer allocator.destroy(state);

    state.* = .{ .allocator = allocator };

    try env.setInstanceData(EnvironmentState, state, EnvironmentState.finalize, null);
    return state;
}

pub fn getReusedEpochTransitionCache(
    env: napi.Env,
    allocator: std.mem.Allocator,
    cached_state: *st.CachedBeaconState,
) !*st.ReusedEpochTransitionCache {
    const state = try getOrCreate(env, allocator);
    if (state.reused_epoch_transition_cache == null) {
        var reused_cache: st.ReusedEpochTransitionCache = undefined;
        try reused_cache.init(state.allocator, try cached_state.state.validatorsCount());
        state.reused_epoch_transition_cache = reused_cache;
    }
    return &state.reused_epoch_transition_cache.?;
}

pub fn deinitReusedEpochTransitionCache(env: napi.Env) !void {
    const state = try env.getInstanceData(EnvironmentState) orelse return;
    if (state.reused_epoch_transition_cache) |*reused_cache| {
        reused_cache.deinit();
        state.reused_epoch_transition_cache = null;
    }
}
