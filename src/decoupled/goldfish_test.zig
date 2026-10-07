//! Tests for `goldfish.zig`.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const block_tree = @import("block_tree.zig");
const goldfish = @import("goldfish.zig");

const Block = types.Block;
const GoldfishVote = types.GoldfishVote;
const BlockTree = block_tree.BlockTree;
const VoteSet = goldfish.VoteSet;

const Fixture = struct {
    tree: BlockTree,
    a: block_tree.BlockIndex,
    b: block_tree.BlockIndex,
    c: block_tree.BlockIndex,

    /// genesis -> a (slot 1) -> b (slot 2); genesis -> c (slot 2).
    fn build(self: *Fixture) void {
        self.tree.init();
        var a: Block = .{ .slot = 1, .parent = types.genesis_root, .proposer = 0 };
        a.seal();
        self.a = self.tree.insert(&a, block_tree.genesis_index, 0);
        var b: Block = .{ .slot = 2, .parent = a.root, .proposer = 1 };
        b.seal();
        self.b = self.tree.insert(&b, self.a, 4);
        var c: Block = .{ .slot = 2, .parent = types.genesis_root, .proposer = 1 };
        c.seal();
        self.c = self.tree.insert(&c, block_tree.genesis_index, 4);
    }

    fn vote(self: *const Fixture, v: u32, slot: u32, index: block_tree.BlockIndex) GoldfishVote {
        return .{ .val_index = v, .slot = slot, .head = self.tree.block(index).root };
    }
};

test "score counts supporters in the subtree and equivocators everywhere" {
    var f: Fixture = undefined;
    f.build();
    var set: VoteSet = .{};
    set.add(&f.vote(0, 2, f.b), true);
    set.add(&f.vote(1, 2, f.c), true);
    set.add(&f.vote(2, 2, f.b), false);
    set.add(&f.vote(3, 2, f.b), true);
    set.add(&f.vote(3, 2, f.c), true);
    try testing.expectEqual(@as(u32, 4), set.votersCount());
    try testing.expectEqual(@as(u32, 2), goldfish.score(&f.tree, &set, f.a));
    try testing.expectEqual(@as(u32, 2), goldfish.score(&f.tree, &set, f.b));
    try testing.expectEqual(@as(u32, 2), goldfish.score(&f.tree, &set, f.c));
    try testing.expectEqual(@as(u32, 3), goldfish.score(&f.tree, &set, block_tree.genesis_index));
}

test "ghost needs a majority unless the block is from the current slot" {
    var f: Fixture = undefined;
    f.build();
    const mask = goldfish.allBlocks(&f.tree);
    var set: VoteSet = .{};
    set.add(&f.vote(0, 2, f.b), true);
    set.add(&f.vote(1, 2, f.b), true);
    set.add(&f.vote(2, 2, f.c), true);
    const majority: goldfish.Eligibility = .{ .voters_count = set.votersCount(), .current_slot = null, .majority_gate = true };
    try testing.expectEqual(f.b, goldfish.ghost(&f.tree, &mask, &set, majority, block_tree.genesis_index));

    var tie: VoteSet = .{};
    tie.add(&f.vote(0, 2, f.b), true);
    tie.add(&f.vote(1, 2, f.c), true);
    const no_majority: goldfish.Eligibility = .{ .voters_count = tie.votersCount(), .current_slot = null, .majority_gate = true };
    try testing.expectEqual(block_tree.genesis_index, goldfish.ghost(&f.tree, &mask, &tie, no_majority, block_tree.genesis_index));

    // `a` is from slot 1 and has one vote of two: not eligible. `c` is a
    // slot-2 block, so the current-slot clause admits it without votes.
    const current: goldfish.Eligibility = .{ .voters_count = tie.votersCount(), .current_slot = 2, .majority_gate = true };
    try testing.expectEqual(f.c, goldfish.ghost(&f.tree, &mask, &tie, current, block_tree.genesis_index));

    // Without the gate the walk takes the heaviest child at every step.
    const heaviest: goldfish.Eligibility = .{ .voters_count = tie.votersCount(), .current_slot = null, .majority_gate = false };
    const head = goldfish.ghost(&f.tree, &mask, &tie, heaviest, block_tree.genesis_index);
    try testing.expect(head == f.b or head == f.c);
}

test "mask hides blocks from the walk" {
    var f: Fixture = undefined;
    f.build();
    var mask = goldfish.allBlocks(&f.tree);
    mask[f.b] = false;
    var set: VoteSet = .{};
    set.add(&f.vote(0, 2, f.b), true);
    set.add(&f.vote(1, 2, f.b), true);
    const rule: goldfish.Eligibility = .{ .voters_count = set.votersCount(), .current_slot = null, .majority_gate = true };
    try testing.expectEqual(f.a, goldfish.ghost(&f.tree, &mask, &set, rule, block_tree.genesis_index));
}

test "addLatest keeps the newest slot per validator" {
    var f: Fixture = undefined;
    f.build();
    var set: VoteSet = .{};
    set.addLatest(&f.vote(0, 1, f.a), true);
    set.addLatest(&f.vote(0, 2, f.b), true);
    set.addLatest(&f.vote(0, 1, f.c), true);
    try testing.expectEqual(@as(u32, 1), set.votes.count);
    try testing.expectEqual(@as(u32, 2), set.votes.buffer[0].slot);
    set.addLatest(&f.vote(0, 2, f.c), true);
    try testing.expect(set.isEquivocator(0));
    try testing.expectEqual(@as(u32, 1), set.votersCount());
}
