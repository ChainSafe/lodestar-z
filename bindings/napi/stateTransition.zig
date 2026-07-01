const napi_io = @import("./io.zig");
const st = @import("state_transition");

pub fn deinitReusedEpochTransitionCache() void {
    st.deinitReusedEpochTransitionCache(napi_io.get());
}
