const std = @import("std");

pub const RunnerKind = enum {
    epoch_processing,
    finality,
    operations,
    random,
    rewards,
    sanity,
    transition,
    shuffling,
};
