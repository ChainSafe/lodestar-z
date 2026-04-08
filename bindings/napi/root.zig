const std = @import("std");
const zapi = @import("zapi");
const js = zapi.js;
pub const pool = @import("./pool.zig");
pub const shuffle = @import("./shuffle.zig");
pub const config = @import("./config.zig");
pub const pubkeys = @import("./pubkeys.zig");
pub const metrics = @import("./metrics.zig");
pub const blst = @import("./blst.zig");
pub const BeaconStateView = @import("./BeaconStateView.zig").BeaconStateView;
pub const stateTransition = @import("./state_transition.zig");

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

comptime {
    js.exportModule(@This(), .{
        .init = init,
        .cleanup = cleanup,
    });
}
