const std = @import("std");
const napi = @import("zapi:zapi");
const pool = @import("./pool.zig");
const pubkeys = @import("./pubkeys.zig");
const config = @import("./config.zig");
const shuffle = @import("./shuffle.zig");
const metrics = @import("./metrics.zig");
const BeaconStateView = @import("./BeaconStateView.zig");
const blst = @import("./blst.zig");
const state_transition = @import("./state_transition.zig");

comptime {
    napi.module.register(register);
}

/// Tracks how many NAPI environments reference the shared module state.
/// Shared state (pool, pubkeys, config) is initialized on the first register
/// and torn down only when the last environment exits.
var env_refcount: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Guards shared state initialization so that concurrent `register` calls
/// (e.g. from Node.js Worker threads) cannot observe partially-initialized state.
var init_mutex: std.Thread.Mutex = .{};

const EnvCleanup = struct {
    fn hook(_: *EnvCleanup) void {
        init_mutex.lock();
        defer init_mutex.unlock();
        if (env_refcount.fetchSub(1, .acq_rel) == 1) {
            // Last environment — tear down shared state.
            config.state.deinit();
            pubkeys.state.deinit();
            pool.state.deinit();
            metrics.deinit();
        }
    }
};

var env_cleanup: EnvCleanup = .{};

fn register(env: napi.Env, exports: napi.Value) !void {
    {
        init_mutex.lock();
        defer init_mutex.unlock();
        if (env_refcount.fetchAdd(1, .monotonic) == 0) {
            // First environment — initialize shared state.
            // On failure, roll back the refcount so the next caller retries.
            errdefer {
                const old = env_refcount.fetchSub(1, .monotonic);
                std.debug.assert(old == 1);
            }
            try pool.state.init();
            try pubkeys.state.init();
            config.state.init();
        }
    }

    try env.addEnvCleanupHook(EnvCleanup, &env_cleanup, EnvCleanup.hook);

    try pool.register(env, exports);
    try pubkeys.register(env, exports);
    try config.register(env, exports);
    try shuffle.register(env, exports);
    try BeaconStateView.register(env, exports);
    try blst.register(env, exports);
    try state_transition.register(env, exports);
    try metrics.register(env, exports);
}
