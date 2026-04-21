const std = @import("std");
const zapi = @import("zapi");
const js = zapi.js;
const napi = zapi.napi;
pub const pool = @import("./pool.zig");
pub const shuffle = @import("./shuffle.zig");
pub const config = @import("./config.zig");

pub const metrics = @import("./metrics.zig");
pub const stateTransition = @import("./state_transition.zig");

const pubkeys = @import("./pubkeys.zig");
const blst = @import("./blst.zig");
const BeaconStateView = @import("./BeaconStateView.zig");

fn init(old_ref_count: u32) !void {
    if (old_ref_count == 0) {
        // First environment — initialize shared state.
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
    }
}

fn setup(env: napi.Env, exports: napi.Value) !void {
    try blst.register(env, exports);
    try BeaconStateView.register(env, exports);
    try pubkeys.register(env, exports);
}

comptime {
    js.exportModule(@This(), .{ .init = init, .cleanup = cleanup, .register = setup });
}
