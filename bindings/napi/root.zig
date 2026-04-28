const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
pub const pool = @import("./pool.zig");
pub const shuffle = @import("./shuffle.zig");
pub const config = @import("./config.zig");
pub const metrics = @import("./metrics.zig");
pub const stateTransition = @import("./stateTransition.zig");

const pubkeys = @import("./pubkeys.zig");
const blst = @import("./blst.zig");
const options = @import("bls_options");
const BeaconStateView = @import("./BeaconStateView.zig");
const napi_io = @import("./io.zig");

fn init(old_ref_count: u32) !void {
    if (old_ref_count == 0) {
        // First environment — initialize shared state in your threadpool init.
        try napi_io.init();
        errdefer napi_io.deinit();

        var cpu_count: u64 = options.thread_count;
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
}

fn cleanup(new_ref_count: u32) void {
    if (new_ref_count == 0) {
        // Last environment — tear down shared state.
        config.state.deinit();
        pubkeys.state.deinit();
        pool.state.deinit();
        metrics.deinit();
        blst.deinitThreadPool();
        napi_io.deinit();
    }
}

fn register(env: napi.Env, exports: napi.Value) !void {
    try blst.register(env, exports);
    try BeaconStateView.register(env, exports);
    try pubkeys.register(env, exports);
}

comptime {
    js.exportModule(@This(), .{ .init = init, .cleanup = cleanup, .register = register });
}
