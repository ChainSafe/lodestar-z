const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;

pub fn processParticipationRecordUpdates(cached_state: *CachedBeaconState) !void {
    var state = cached_state.state;
    // rotate current/previous epoch attestations
    try state.rotateEpochPendingAttestations();
}
