const js = @import("zapi:zapi").js;
const environment_state = @import("environment_state.zig");

pub fn deinitReusedEpochTransitionCache() !void {
    try environment_state.deinitReusedEpochTransitionCache(js.env());
}
