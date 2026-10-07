//! An honest node: one store, one validator index, and the slot duties of
//! `on_tick` (PROTOCOL.md figure `alg:store`). Emitted objects go to the
//! outbox; the runner broadcasts them.

const std = @import("std");
const assert = std.debug.assert;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("../limits.zig");
const types = @import("../types.zig");
const block_tree = @import("../block_tree.zig");
const Store = @import("../store.zig").Store;
const event = @import("event.zig");

pub const Node = struct {
    store: *Store,
    val_index: types.ValidatorIndex,
    /// The head of the latest `goldfish_vote` duty, on or off the committee.
    last_head: block_tree.BlockIndex = block_tree.genesis_index,
    outbox: BoundedArray(event.Payload, 2) = .{},

    pub fn tick(self: *Node, t: types.Time) void {
        self.outbox.count = 0;
        const store = self.store;
        store.setTime(t);
        const s = store.s;
        if (s == 0) return;
        const offset = t - types.slotStart(s);
        assert(offset < 4);
        if (offset == 0 and store.schedule.proposer[s] == self.val_index) {
            const block = store.proposeBlock(self.val_index);
            const accepted = store.onBlock(&block);
            assert(accepted);
            self.outbox.push(.{ .block = block });
        }
        if (offset == 1) {
            self.last_head = store.voteHead();
            if (store.schedule.inCommittee(s, self.val_index)) {
                const vote: types.GoldfishVote = .{
                    .val_index = self.val_index,
                    .slot = s,
                    .head = store.tree.block(self.last_head).root,
                };
                const accepted = store.onGoldfishVote(&vote);
                assert(accepted);
                self.outbox.push(.{ .vote = vote });
            }
        }
        if (offset == 2) store.updateConfirmation(s - 1);
        assert(self.outbox.count <= 1);
    }

    pub fn deliver(self: *Node, payload: *const event.Payload) void {
        assert(self.store.t < limits.max_time);
        assert(self.val_index < self.store.schedule.validator_count);
        switch (payload.*) {
            .block => |*block| _ = self.store.onBlock(block),
            .vote => |*vote| _ = self.store.onGoldfishVote(vote),
        }
    }
};
