//! Goldfish score, eligibility and the GHOST walk (PROTOCOL.md A.5 and
//! figure `alg:fc-full`). A `VoteSet` is the pair (`votes`, `support_votes`)
//! of the paper: every entry participates, and flagged entries support.
//! An equivocator counts for every block, so finding an equivocation can
//! never make an eligible block ineligible.

const std = @import("std");
const assert = std.debug.assert;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("limits.zig");
const types = @import("types.zig");
const block_tree = @import("block_tree.zig");

const BlockIndex = block_tree.BlockIndex;
const BlockTree = block_tree.BlockTree;
const GoldfishVote = types.GoldfishVote;
const Slot = types.Slot;
const ValidatorIndex = types.ValidatorIndex;

pub const BlockMask = [limits.max_blocks]bool;

pub const VoteSet = struct {
    votes: BoundedArray(GoldfishVote, limits.max_vote_set) = .{},
    support: [limits.max_vote_set]bool = [_]bool{false} ** limits.max_vote_set,

    pub fn indexOf(self: *const VoteSet, vote: *const GoldfishVote) ?u32 {
        for (self.votes.constSlice(), 0..) |*held, i| {
            if (held.eql(vote)) {
                const index: u32 = @intCast(i);
                return index;
            }
        }
        return null;
    }

    /// Adds a vote; a repeat only widens its support flag.
    pub fn add(self: *VoteSet, vote: *const GoldfishVote, supported: bool) void {
        assert(self.votes.count <= limits.max_vote_set);
        if (self.indexOf(vote)) |i| {
            if (supported) self.support[i] = true;
            return;
        }
        assert(!self.votes.full());
        self.support[self.votes.count] = supported;
        self.votes.push(vote.*);
    }

    /// LMD variant for the control run: keeps only each validator's votes
    /// from its latest slot.
    pub fn addLatest(self: *VoteSet, vote: *const GoldfishVote, supported: bool) void {
        var i: u32 = 0;
        var scanned: u32 = 0;
        while (i < self.votes.count) : (scanned += 1) {
            assert(scanned <= limits.max_vote_set);
            const held = &self.votes.buffer[i];
            if (held.val_index != vote.val_index) {
                i += 1;
            } else if (held.slot > vote.slot) {
                return;
            } else if (held.slot < vote.slot) {
                self.removeAt(i);
            } else {
                i += 1;
            }
        }
        self.add(vote, supported);
    }

    fn removeAt(self: *VoteSet, i: u32) void {
        assert(i < self.votes.count);
        const last = self.votes.count - 1;
        self.votes.buffer[i] = self.votes.buffer[last];
        self.support[i] = self.support[last];
        self.votes.count = last;
        assert(self.votes.count == last);
    }

    pub fn countByValidator(self: *const VoteSet, v: ValidatorIndex) u32 {
        var count: u32 = 0;
        for (self.votes.constSlice()) |*vote| {
            if (vote.val_index == v) count += 1;
        }
        return count;
    }

    pub fn isEquivocator(self: *const VoteSet, v: ValidatorIndex) bool {
        return self.countByValidator(v) >= 2;
    }

    fn firstIndexByValidator(self: *const VoteSet, v: ValidatorIndex) u32 {
        for (self.votes.constSlice(), 0..) |*vote, i| {
            if (vote.val_index == v) {
                const index: u32 = @intCast(i);
                return index;
            }
        }
        unreachable;
    }

    /// `|{ v : votes holds a vote by v }|`.
    pub fn votersCount(self: *const VoteSet) u32 {
        var count: u32 = 0;
        for (self.votes.constSlice(), 0..) |*vote, i| {
            if (self.firstIndexByValidator(vote.val_index) == i) count += 1;
        }
        assert(count <= self.votes.count);
        return count;
    }
};

pub const Eligibility = struct {
    voters_count: u32,
    /// `B.slot = Σ.s` makes a current-slot proposal eligible without votes.
    /// `null` drops that clause, as `update_confirmation` does.
    current_slot: ?Slot,
    /// `2 · score > voters_count`. Off only in the LMD-GHOST control run,
    /// where the walk takes the heaviest child.
    majority_gate: bool,
};

/// `goldfish_score`: equivocators plus non-equivocating supporters whose
/// supported head descends from `b`.
pub fn score(tree: *const BlockTree, set: *const VoteSet, b: BlockIndex) u32 {
    assert(b < tree.count);
    var total: u32 = 0;
    for (set.votes.constSlice(), 0..) |*vote, i| {
        if (set.isEquivocator(vote.val_index)) {
            if (set.firstIndexByValidator(vote.val_index) == i) total += 1;
            continue;
        }
        if (!set.support[i]) continue;
        const head = tree.find(&vote.head) orelse continue;
        if (tree.isAncestorOrSelf(b, head)) total += 1;
    }
    assert(total <= set.votersCount());
    return total;
}

pub fn eligible(tree: *const BlockTree, set: *const VoteSet, rule: Eligibility, b: BlockIndex) bool {
    assert(b < tree.count);
    if (rule.current_slot) |s| {
        if (tree.block(b).slot == s) return true;
    }
    if (!rule.majority_gate) return true;
    return 2 * score(tree, set, b) > rule.voters_count;
}

pub fn allBlocks(tree: *const BlockTree) BlockMask {
    var mask: BlockMask = [_]bool{false} ** limits.max_blocks;
    for (0..tree.count) |i| mask[i] = true;
    assert(mask[block_tree.genesis_index]);
    return mask;
}

/// `ghost(anchor, tree, score, eligible)`: descends through eligible children
/// inside `mask`, highest score first, ties to the greater root.
pub fn ghost(tree: *const BlockTree, mask: *const BlockMask, set: *const VoteSet, rule: Eligibility, anchor: BlockIndex) BlockIndex {
    assert(anchor < tree.count);
    var head = anchor;
    var steps: u32 = 0;
    while (steps < limits.max_blocks) : (steps += 1) {
        var best: ?BlockIndex = null;
        var best_score: u32 = 0;
        for (0..tree.count) |i| {
            const child: BlockIndex = @intCast(i);
            if (child == block_tree.genesis_index) continue;
            if (tree.parentOf(child) != head) continue;
            if (!mask[child]) continue;
            if (!eligible(tree, set, rule, child)) continue;
            const child_score = score(tree, set, child);
            if (best) |current| {
                if (child_score < best_score) continue;
                if (child_score == best_score) {
                    const order = types.rootOrder(&tree.block(child).root, &tree.block(current).root);
                    if (order != .gt) continue;
                }
            }
            best = child;
            best_score = child_score;
        }
        const next = best orelse return head;
        assert(tree.parentOf(next) == head);
        head = next;
    }
    unreachable;
}

test {
    _ = @import("goldfish_test.zig");
}
