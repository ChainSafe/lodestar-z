const napi_io = @import("./io.zig");
const st = @import("state_transition");

pub fn deinitStateTransition() void {
    st.deinitStateTransition(napi_io.get());
}
