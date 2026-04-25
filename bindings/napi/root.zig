const std = @import("std");
const napi = @import("zapi:zapi");
const pool = @import("./pool.zig");
const pubkeys = @import("./pubkeys.zig");
const config = @import("./config.zig");
const options = @import("bls_options");
const shuffle = @import("./shuffle.zig");
const metrics = @import("./metrics.zig");
const BeaconStateView = @import("./BeaconStateView.zig");
const blst = @import("./blst.zig");
const state_transition = @import("./state_transition.zig");
const napi_io = @import("./io.zig");

comptime {
    napi.module.register(register);
}

/// Tracks how many NAPI environments reference the shared module state.
/// Shared state (pool, pubkeys, config) is initialized on the first register
/// and torn down only when the last environment exits.
var env_refcount: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

const EnvCleanup = struct {
    fn hook(_: *EnvCleanup) void {
        if (env_refcount.fetchSub(1, .acq_rel) == 1) {
            // Last environment — tear down shared state in reverse init order.
            blst.deinitThreadPool();
            config.state.deinit();
            pubkeys.state.deinit();
            pool.state.deinit();
            metrics.deinit();
            napi_io.deinit();
        }
    }
};

var env_cleanup: EnvCleanup = .{};

fn register(env: napi.Env, exports: napi.Value) !void {
    if (env_refcount.fetchAdd(1, .monotonic) == 0) {
        // First environment — initialize shared state.
        // `io` must come first — downstream shared state may take it as input.
        try napi_io.init();
        errdefer napi_io.deinit();

        var cpu_count: usize = options.thread_count;
        if (options.thread_count == 0) {
            std.debug.print("Note: no -Dthread-count set, will use runtime CPU count minus 1: {}\n", .{cpu_count});
            cpu_count = @max((try std.Thread.getCpuCount()) - 1, 1);
        }

        const n_workers = @min(cpu_count, @import("bls").ThreadPool.MAX_WORKERS);
        try blst.initThreadPool(@intCast(n_workers));
        try pool.state.init();
        try pubkeys.state.init();
        config.state.init();
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
