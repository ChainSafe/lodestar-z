const Allocator = @import("std").mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const ct = @import("consensus_types");
const initializeProposerLookahead = @import("../utils/process_proposer_lookahead.zig").initializeProposerLookahead;

pub fn upgradeStateToFulu(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    electra_state: *ForkBeaconState(.electra),
) !ForkBeaconState(.fulu) {
    var state = try electra_state.upgradeUnsafe();
    errdefer state.deinit();

    // Update fork version
    const new_fork = ct.phase0.Fork.Type{
        .previous_version = try electra_state.forkCurrentVersion(),
        .current_version = config.chain.FULU_FORK_VERSION,
        .epoch = epoch_cache.epoch,
    };
    try state.setFork(&new_fork);

    var proposer_lookahead = ct.fulu.ProposerLookahead.default_value;
    try initializeProposerLookahead(
        .fulu,
        allocator,
        epoch_cache,
        &state,
        proposer_lookahead[0..],
    );
    try state.setProposerLookahead(&proposer_lookahead);

    electra_state.deinit();
    return state;
}
