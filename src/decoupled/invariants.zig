//! The `Consensus` bundle fields of `verified-consensus`, as runtime checks.
//! The first slice has two: `nested`, and the confirmed half of `available`.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const types = @import("types.zig");
const Store = @import("store.zig").Store;

pub const Proposal = struct {
    root: types.Root,
    slot: types.Slot,
};

pub const Violation = error{
    NestedViolated,
    ProposalMissing,
    ConfirmedAvailabilityViolated,
};

/// `nested`: `F ⪯ get_stable ⪯ get_confirmed`.
pub fn checkNested(store: *const Store) Violation!void {
    assert(store.tree.count >= 1);
    const stable = store.getStable();
    const confirmed = store.getConfirmed();
    if (!store.tree.isAncestorOrSelf(store.finalized, stable)) return error.NestedViolated;
    if (!store.tree.isAncestorOrSelf(stable, confirmed)) return error.NestedViolated;
}

/// `available`, confirmed part: an honest proposal of slot `s` is in every
/// honest confirmed read at `t_s + 6Δ`. Checked only when the slot's
/// committee has an honest majority, which is the claim's premise.
pub fn checkConfirmedAvailability(run: anytype, proposal: *const Proposal) Violation!void {
    assert(proposal.slot > 0);
    assert(run.now == types.slotStart(proposal.slot) + 6);
    if (!run.schedule.honestMajority(proposal.slot)) return;
    for (run.nodes[0..run.node_count]) |*node| {
        const store = node.store;
        const index = store.tree.find(&proposal.root) orelse return error.ProposalMissing;
        if (!store.tree.isAncestorOrSelf(index, store.getConfirmed())) {
            return error.ConfirmedAvailabilityViolated;
        }
    }
}

test "nested holds on a fresh store" {
    const Schedule = @import("schedule.zig").Schedule;
    const schedule = Schedule.blank(1);
    const store = try std.testing.allocator.create(Store);
    defer std.testing.allocator.destroy(store);
    store.init(&schedule, .goldfish);
    try checkNested(store);
    try std.testing.expectEqual(@as(u32, 1), store.tree.count);
}
