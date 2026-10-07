//! Deterministic simulator for the decoupled consensus protocol of
//! `fradamt/verified-consensus` (research; not part of the client). The
//! first slice ports the Goldfish layer and one scripted attack.

const std = @import("std");

pub const limits = @import("limits.zig");
pub const types = @import("types.zig");
pub const schedule = @import("schedule.zig");
pub const block_tree = @import("block_tree.zig");
pub const vote_pool = @import("vote_pool.zig");
pub const goldfish = @import("goldfish.zig");
pub const store = @import("store.zig");
pub const invariants = @import("invariants.zig");
pub const event = @import("sim/event.zig");
pub const scheduler = @import("sim/scheduler.zig");
pub const node = @import("sim/node.zig");
pub const runner = @import("sim/runner.zig");
pub const state_hash = @import("sim/state_hash.zig");
pub const ex_ante_reorg = @import("scenarios/ex_ante_reorg.zig");

test {
    std.testing.refAllDecls(@This());
}
