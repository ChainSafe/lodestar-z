const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
pub const pool = @import("./pool.zig");
pub const shuffle = @import("./shuffle.zig");
pub const config = @import("./config.zig");
pub const metrics = @import("./metrics.zig");
pub const stateTransition = @import("./stateTransition.zig");
pub const BeaconStateView = @import("./BeaconStateView.zig");
pub const blst = @import("./blst.zig");
pub const pubkeys = @import("./pubkeys.zig");

const options = @import("bls_options");
const napi_io = @import("./io.zig");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

fn init(old_ref_count: u32) !void {
    if (old_ref_count == 0) {
        // First environment — initialize shared state in your threadpool init.
        try napi_io.init();
        errdefer napi_io.deinit();

        var cpu_count: u64 = options.thread_count;
        if (options.thread_count == 0) {
            cpu_count = @max(try detectCpuCount(), 2) - 1;
            std.log.debug(
                "Note: no -Dthread-count set, using cgroup-aware CPU count minus 1: {}\n",
                .{cpu_count},
            );
        }

        const n_workers = @min(cpu_count, @import("bls").ThreadPool.MAX_WORKERS);
        try blst.lifecycle.initThreadPool(@intCast(n_workers));
        try pool.state.init();
        try pubkeys.state.init();
        config.state.init();
    }
}

/// cgroup-aware CPU count for sizing the BLS pool. A detection failure must
/// not prevent the module from loading: warn and fall back to the affinity
/// count (what `std.Thread.getCpuCount()` reports).
fn detectCpuCount() !usize {
    return @import("cpu_count").getNumCpus(allocator, napi_io.get()) catch |err| {
        std.log.debug(
            "Warning: cgroup CPU detection failed ({s}), using affinity count\n",
            .{@errorName(err)},
        );
        return std.Thread.getCpuCount();
    };
}

fn cleanup(new_ref_count: u32) void {
    if (new_ref_count == 0) {
        // Last environment — tear down shared state.
        blst.lifecycle.deinitThreadPool();
        config.state.deinit();
        pubkeys.state.deinit();
        pool.state.deinit();
        metrics.deinit();
        napi_io.deinit();
    }
}

comptime {
    js.exportModule(@This(), .{ .init = init, .cleanup = cleanup });
}
