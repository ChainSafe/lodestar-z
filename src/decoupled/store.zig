//! The Goldfish part of the node store `Σ` (PROTOCOL.md §1.1, figures
//! `alg:store`, `alg:fc-full` and `alg:duties`). The stabilization and
//! finality gadgets are not ported yet: the SG root and the FG root are
//! genesis, every block is viable, and `latest_stable` never moves.
//!
//! `ForkChoiceRule.lmd_ghost` is the control experiment of the plan's first
//! slice: the store accepts votes of any age, the fork choice reads each
//! validator's latest vote, and the walk takes the heaviest child without
//! the majority gate. That is LMD-GHOST as the post describes it. Nothing in
//! the paper has this mode.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const types = @import("types.zig");
const block_tree = @import("block_tree.zig");
const vote_pool = @import("vote_pool.zig");
const goldfish = @import("goldfish.zig");
const Schedule = @import("schedule.zig").Schedule;

const Block = types.Block;
const BlockIndex = block_tree.BlockIndex;
const BlockTree = block_tree.BlockTree;
const GoldfishVote = types.GoldfishVote;
const Slot = types.Slot;
const Time = types.Time;
const ValidatorIndex = types.ValidatorIndex;
const VoteSet = goldfish.VoteSet;

const freeze_offset: Time = 3;
const support_cutoff_offset: Time = 2;
const confirmation_offset: Time = 6;

comptime {
    assert(freeze_offset < limits.slot_ticks);
    assert(confirmation_offset == limits.slot_ticks + support_cutoff_offset);
}

pub const ForkChoiceRule = enum {
    goldfish,
    lmd_ghost,
};

pub const Store = struct {
    t: Time,
    s: Slot,
    tree: BlockTree,
    pool: vote_pool.VotePool,
    live_confirmed: BlockIndex,
    latest_confirmed: BlockIndex,
    latest_stable: BlockIndex,
    finalized: BlockIndex,
    schedule: *const Schedule,
    rule: ForkChoiceRule,

    pub fn init(self: *Store, schedule: *const Schedule, rule: ForkChoiceRule) void {
        self.t = 0;
        self.s = 0;
        self.tree.init();
        self.pool.init();
        self.live_confirmed = block_tree.genesis_index;
        self.latest_confirmed = block_tree.genesis_index;
        self.latest_stable = block_tree.genesis_index;
        self.finalized = block_tree.genesis_index;
        self.schedule = schedule;
        self.rule = rule;
        assert(self.tree.count == 1);
        assert(self.getConfirmed() == block_tree.genesis_index);
    }

    pub fn setTime(self: *Store, t: Time) void {
        assert(t >= self.t);
        assert(t < limits.max_time);
        self.t = t;
        self.s = types.slotOf(t);
    }

    pub fn getStable(self: *const Store) BlockIndex {
        if (self.tree.isAncestorOrSelf(self.finalized, self.latest_stable)) return self.latest_stable;
        return self.finalized;
    }

    pub fn getConfirmed(self: *const Store) BlockIndex {
        const stable = self.getStable();
        if (self.tree.isAncestorOrSelf(stable, self.latest_confirmed)) return self.latest_confirmed;
        return stable;
    }

    fn sgRoot(self: *const Store) BlockIndex {
        assert(self.finalized < self.tree.count);
        return self.finalized;
    }

    /// `resolution_time` for a Goldfish vote. `null` is `+∞`: the head is not
    /// held, or is from a later slot than the vote (the Lean's A.3 rule).
    pub fn resolutionTime(self: *const Store, entry: *const vote_pool.VoteEntry) ?Time {
        const head = self.tree.find(&entry.vote.head) orelse return null;
        if (self.tree.block(head).slot > entry.vote.slot) return null;
        const resolved = @max(entry.timestamp, self.tree.timestamp(head));
        assert(resolved >= entry.timestamp);
        return resolved;
    }

    /// `on_block`. Returns whether the block entered the tree.
    pub fn onBlock(self: *Store, block: *const Block) bool {
        if (block.slot > self.s) return false;
        if (block.slot == 0) return false;
        if (self.tree.contains(&block.root)) return false;
        if (self.tree.full()) return false;
        const parent = self.tree.find(&block.parent) orelse return false;
        if (!self.tree.isAncestorOrSelf(self.finalized, parent)) return false;
        if (block.proposer != self.schedule.proposer[block.slot]) return false;
        for (block.votes.constSlice()) |*vote| {
            if (vote.slot >= limits.max_slots) return false;
            if (vote.val_index >= self.schedule.validator_count) return false;
            if (!self.schedule.inCommittee(vote.slot, vote.val_index)) return false;
        }
        const index = self.tree.insert(block, parent, self.t);
        assert(index > block_tree.genesis_index);
        for (block.votes.constSlice()) |*vote| _ = self.onGoldfishVote(vote);
        return true;
    }

    /// `on_goldfish_vote`. Returns whether the vote entered the pool.
    pub fn onGoldfishVote(self: *Store, vote: *const GoldfishVote) bool {
        if (vote.slot > self.s) return false;
        if (self.rule == .goldfish and vote.slot + 1 < self.s) return false;
        if (vote.slot >= limits.max_slots) return false;
        if (vote.val_index >= self.schedule.validator_count) return false;
        if (!self.schedule.inCommittee(vote.slot, vote.val_index)) return false;
        const pool = self.pool.slot(vote.slot);
        if (pool.contains(vote)) return false;
        if (pool.countByValidator(vote.val_index) >= 2) return false;
        if (pool.entries.full()) return false;
        pool.add(vote, self.t);
        assert(pool.contains(vote));
        return true;
    }

    fn addToSet(self: *const Store, set: *VoteSet, vote: *const GoldfishVote, supported: bool) void {
        switch (self.rule) {
            .goldfish => set.add(vote, supported),
            .lmd_ghost => set.addLatest(vote, supported),
        }
    }

    fn headRule(self: *const Store, set: *const VoteSet) goldfish.Eligibility {
        assert(self.s > 0);
        return .{
            .voters_count = set.votersCount(),
            .current_slot = self.s,
            .majority_gate = self.rule == .goldfish,
        };
    }

    /// Votes the fork choice reads for vote slot `k`: slot `k` alone under
    /// Goldfish, every slot up to `k` in the LMD-GHOST control. `cutoff`
    /// applies to receipt and resolution, as the voter's freeze does.
    fn collect(self: *const Store, set: *VoteSet, k: Slot, cutoff: ?Time) void {
        assert(k < limits.max_slots);
        const first: Slot = if (self.rule == .goldfish) k else 0;
        var slot = first;
        while (slot <= k) : (slot += 1) {
            for (self.pool.slotConst(slot).entries.constSlice()) |*entry| {
                if (cutoff) |c| {
                    if (entry.timestamp >= c) continue;
                }
                const resolved = self.resolutionTime(entry);
                var supported = resolved != null;
                if (cutoff) |c| {
                    if (resolved) |r| supported = r < c;
                }
                self.addToSet(set, &entry.vote, supported);
            }
        }
        assert(set.votes.count <= limits.max_vote_set);
    }

    /// `propose_block` at `t_s`. The caller broadcasts and calls `onBlock`.
    pub fn proposeBlock(self: *const Store, val_index: ValidatorIndex) Block {
        const s = self.s;
        assert(s > 0);
        assert(self.t == types.slotStart(s));
        assert(self.schedule.proposer[s] == val_index);
        var set: VoteSet = .{};
        self.collect(&set, s - 1, null);
        const mask = goldfish.allBlocks(&self.tree);
        const head = goldfish.ghost(&self.tree, &mask, &set, self.headRule(&set), self.sgRoot());

        var block: Block = .{ .slot = s, .parent = self.tree.block(head).root, .proposer = val_index };
        for (self.pool.slotConst(s - 1).entries.constSlice(), 0..) |*entry, i| {
            block.support[i] = self.resolutionTime(entry) != null;
            block.votes.push(entry.vote);
        }
        block.seal();
        assert(block.votes.count == self.pool.slotConst(s - 1).entries.count);
        return block;
    }

    /// View merge for the slot-`s` voter (PROTOCOL.md A.4).
    fn voterVotes(self: *const Store, set: *VoteSet, s: Slot) void {
        assert(s > 0);
        const freeze = types.slotStart(s - 1) + freeze_offset;
        self.collect(set, s - 1, freeze);
        for (0..self.tree.count) |i| {
            const index: BlockIndex = @intCast(i);
            const block = self.tree.block(index);
            if (block.slot != s) continue;
            for (block.votes.constSlice(), 0..) |*vote, j| {
                if (vote.slot + 1 != s) continue;
                const supported = block.support[j] and self.tree.contains(&vote.head);
                self.addToSet(set, vote, supported);
            }
        }
        assert(set.votes.count <= limits.max_vote_set);
    }

    /// `voter_processed_block_tree`: blocks held before the previous freeze,
    /// plus every ancestor of a slot-`s` proposal.
    fn voterMask(self: *const Store, s: Slot) goldfish.BlockMask {
        assert(s > 0);
        const freeze = types.slotStart(s - 1) + freeze_offset;
        var mask: goldfish.BlockMask = [_]bool{false} ** limits.max_blocks;
        for (0..self.tree.count) |i| {
            const index: BlockIndex = @intCast(i);
            if (self.tree.timestamp(index) < freeze) mask[index] = true;
            if (self.tree.block(index).slot == s) self.tree.markAncestorsAndSelf(index, &mask);
        }
        assert(mask[block_tree.genesis_index]);
        return mask;
    }

    /// The head of `goldfish_vote` at `t_s + Δ`. The caller decides whether
    /// `val_index` sits on the committee and broadcasts.
    pub fn voteHead(self: *const Store) BlockIndex {
        const s = self.s;
        assert(s > 0);
        assert(self.t == types.slotStart(s) + 1);
        var set: VoteSet = .{};
        self.voterVotes(&set, s);
        const mask = self.voterMask(s);
        const head = goldfish.ghost(&self.tree, &mask, &set, self.headRule(&set), self.sgRoot());
        assert(mask[head]);
        return head;
    }

    fn advance(self: *const Store, old: BlockIndex, candidate: ?BlockIndex) BlockIndex {
        assert(old < self.tree.count);
        const c = candidate orelse return old;
        if (self.tree.isAncestorOrSelf(c, old)) return old;
        return c;
    }

    /// `update_confirmation(Σ, s)` at `t_s + 6Δ`, then the two user records.
    pub fn updateConfirmation(self: *Store, s: Slot) void {
        assert(self.t == types.slotStart(s) + confirmation_offset);
        const early = types.slotStart(s) + support_cutoff_offset;
        const late = self.t;
        const pool = self.pool.slotConst(s);

        var voters: VoteSet = .{};
        var support: VoteSet = .{};
        for (pool.entries.constSlice()) |*entry| {
            if (entry.timestamp >= late) continue;
            voters.add(&entry.vote, false);
        }
        for (pool.entries.constSlice()) |*entry| {
            const resolved = self.resolutionTime(entry) orelse continue;
            if (resolved >= early) continue;
            if (voters.isEquivocator(entry.vote.val_index)) continue;
            support.add(&entry.vote, true);
        }
        assert(support.votes.count <= voters.votes.count);

        const mask = goldfish.allBlocks(&self.tree);
        const rule: goldfish.Eligibility = .{
            .voters_count = voters.votersCount(),
            .current_slot = null,
            .majority_gate = true,
        };
        const head = goldfish.ghost(&self.tree, &mask, &support, rule, self.sgRoot());
        var candidate: ?BlockIndex = null;
        if (goldfish.eligible(&self.tree, &support, rule, head)) {
            self.live_confirmed = head;
            candidate = head;
        } else {
            self.live_confirmed = self.finalized;
        }
        self.updateUserRecords(candidate);
    }

    /// `update_user_confirmation_records`. The stable root is the FG root
    /// until the grades are ported.
    fn updateUserRecords(self: *Store, candidate: ?BlockIndex) void {
        const confirmed = self.advance(self.latest_confirmed, candidate);
        self.latest_stable = self.advance(self.latest_stable, self.finalized);
        if (self.tree.isAncestorOrSelf(self.latest_stable, confirmed)) {
            self.latest_confirmed = confirmed;
        } else if (!self.tree.isAncestorOrSelf(self.latest_stable, self.latest_confirmed)) {
            self.latest_confirmed = self.latest_stable;
        }
        assert(self.tree.isAncestorOrSelf(self.latest_stable, self.latest_confirmed));
        assert(self.tree.isAncestorOrSelf(self.finalized, self.getStable()));
    }
};

test {
    _ = @import("store_test.zig");
}
