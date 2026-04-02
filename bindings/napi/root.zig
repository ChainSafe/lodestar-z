const std = @import("std");
const zapi = @import("zapi");
const napi = zapi.napi;
const js = zapi.js;
pub const pool = @import("./pool.zig");
pub const shuffle = @import("./shuffle.zig");
pub const config = @import("./config.zig");
pub const pubkeys = @import("./pubkeys.zig");
pub const metrics = @import("./metrics.zig");

const BeaconStateView = @import("./BeaconStateView.zig");
const state_transition = @import("./state_transition.zig");
const blst = @import("./blst.zig");

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

/// Manual registration for modules not yet converted to DSL.
fn register(env: napi.Env, exports: napi.Value) !void {
    try blst.register(env, exports);
    try BeaconStateView.register(env, exports);
    try state_transition.register(env, exports);
}

comptime {
    js.exportModule(@This(), .{
        .init = init,
        .cleanup = cleanup,
        .register = register,
    });
}
