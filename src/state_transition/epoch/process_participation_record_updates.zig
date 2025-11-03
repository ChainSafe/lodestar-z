const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;

pub fn processParticipationRecordUpdates(cached_state: *CachedBeaconStateAllForks, allocator: Allocator) void {
    const state = cached_state.state;
    // rotate current/previous epoch attestations
    state.rotateEpochPendingAttestations(allocator);
}
