const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;

pub fn processParticipationRecordUpdates(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
) !void {
    if (comptime fork != .phase0) return;
    // rotate current/previous epoch attestations
    try state.rotateEpochPendingAttestations();
}
