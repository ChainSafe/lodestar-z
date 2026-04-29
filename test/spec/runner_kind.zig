pub const RunnerKind = enum {
    epoch_processing,
    fast_confirmation,
    fork,
    fork_choice,
    finality,
    merkle_proof,
    operations,
    random,
    rewards,
    sanity,
    transition,
    shuffling,

    pub fn hasSuiteCase(comptime self: RunnerKind) bool {
        return switch (self) {
            .merkle_proof, .fast_confirmation => true,
            else => false,
        };
    }
};
