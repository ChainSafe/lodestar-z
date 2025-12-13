const Allocator = @import("std").mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ssz = @import("consensus_types");
const initializeProposerLookahead = @import("../utils/process_proposer_lookahead.zig").initializeProposerLookahead;

pub fn upgradeStateToFulu(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    var state = cached_state.state;
    if (!state.isElectra()) {
        return error.StateIsNotElectra;
    }

    const electra_state = state.electra;
    const previous_fork_version = electra_state.fork.current_version;

    defer {
        ssz.electra.BeaconState.deinit(allocator, electra_state);
        allocator.destroy(electra_state);
    }

    _ = try state.upgradeUnsafe(allocator);

    // Update fork version
    state.forkPtr().* = .{
        .previous_version = previous_fork_version,
        .current_version = cached_state.config.chain.FULU_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    try initializeProposerLookahead(
        allocator,
        cached_state,
        &state.fulu.proposer_lookahead,
    );
}
