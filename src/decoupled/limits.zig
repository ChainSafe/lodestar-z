//! Compile-time bounds for the decoupled consensus simulator. Every loop,
//! pool and queue in the module is sized from these values. The sizes fit a
//! research run of a few dozen validators, not a mainnet validator set.

const std = @import("std");

pub const max_validators: u32 = 64;
pub const max_committee: u32 = 16;
pub const max_slots: u32 = 64;
pub const max_blocks: u32 = 256;
pub const max_votes_per_slot: u32 = 2 * max_committee;
pub const max_votes_per_block: u32 = max_votes_per_slot;
pub const max_vote_set: u32 = 2 * max_validators;
pub const max_nodes: u32 = max_validators;
pub const max_pending: u32 = 8192;
/// The paper puts slot `s` at `4Δs`. One tick is one `Δ`.
pub const slot_ticks: u32 = 4;
pub const max_time: u32 = max_slots * slot_ticks;

comptime {
    std.debug.assert(max_committee <= max_validators);
    std.debug.assert(max_votes_per_slot <= max_vote_set);
    std.debug.assert(max_votes_per_block <= max_votes_per_slot);
    std.debug.assert(max_blocks >= max_slots);
}
