const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;

pub fn processParticipationRecordUpdates(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) void {
    const state = cached_state.state;
    // rotate current/previous epoch attestations
    state.rotateEpochPendingAttestations(allocator);
}
