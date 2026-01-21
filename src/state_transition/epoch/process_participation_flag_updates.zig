const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;

pub fn processParticipationFlagUpdates(cached_state: *CachedBeaconState) !void {
    const state = cached_state.state;

    if (state.forkSeq().lt(.altair)) return;
    try state.rotateEpochParticipation();
}
