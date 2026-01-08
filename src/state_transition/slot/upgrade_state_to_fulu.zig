const Allocator = @import("std").mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ct = @import("consensus_types");
const initializeProposerLookahead = @import("../utils/process_proposer_lookahead.zig").initializeProposerLookahead;

pub fn upgradeStateToFulu(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var electra_state = cached_state.state;
    if (electra_state.forkSeq() != .electra) {
        return error.StateIsNotElectra;
    }

    const state = try electra_state.upgradeUnsafe(allocator);
    defer electra_state.deinit();

    // Update fork version
    try state.setFork(.{
        .previous_version = try electra_state.fork().getValue("current_version"),
        .current_version = cached_state.config.chain.FULU_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    });

    var proposer_lookahead = ct.fulu.ProposerLookahead.default_value;
    try initializeProposerLookahead(
        allocator,
        cached_state,
        &proposer_lookahead,
    );
    try state.setProposerLookahead(proposer_lookahead);
}
