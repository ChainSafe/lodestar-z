const js = @import("zapi:zapi").js;
const st = @import("state_transition");

pub fn deinitReusedEpochTransitionCache() void {
    st.deinitReusedEpochTransitionCache(js.io());
}
