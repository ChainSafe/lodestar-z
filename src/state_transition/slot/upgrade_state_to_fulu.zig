const Allocator = @import("std").mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ct = @import("consensus_types");
const initializeProposerLookahead = @import("../utils/process_proposer_lookahead.zig").initializeProposerLookahead;

pub fn upgradeStateToFulu(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var electra_state = cached_state.state;
    if (electra_state.forkSeq() != .electra) {
        return error.StateIsNotElectra;
    }

    var state = try electra_state.upgradeUnsafe();

    // Update fork version
    const new_fork = ct.phase0.Fork.Type{
        .previous_version = try electra_state.forkCurrentVersion(),
        .current_version = cached_state.config.chain.FULU_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };
    try state.setFork(&new_fork);

    var proposer_lookahead = ct.fulu.ProposerLookahead.default_value;
    try initializeProposerLookahead(
        allocator,
        cached_state,
        &proposer_lookahead,
    );
    try state.setProposerLookahead(&proposer_lookahead);

    electra_state.deinit();
    cached_state.state.* = state;
}
