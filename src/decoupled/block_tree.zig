//! The processed block tree `Σ.𝒯` as a flat array with parent indices, the
//! same shape as proto-array in `src/fork_choice`. Genesis is index 0 and
//! carries timestamp 0; the paper gives it `−∞`, and every cutoff in a run
//! is at least `1`, so `0` compares the same way.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const types = @import("types.zig");

const Block = types.Block;
const Root = types.Root;
const Time = types.Time;

pub const BlockIndex = u32;
pub const genesis_index: BlockIndex = 0;

pub const Node = struct {
    block: Block,
    parent: BlockIndex,
    depth: u32,
    timestamp: Time,
};

pub const BlockTree = struct {
    nodes: [limits.max_blocks]Node,
    count: u32,

    pub fn init(self: *BlockTree) void {
        self.count = 1;
        self.nodes[genesis_index] = .{
            .block = Block.genesis(),
            .parent = genesis_index,
            .depth = 0,
            .timestamp = 0,
        };
        assert(self.count == 1);
        assert(std.mem.eql(u8, &self.nodes[0].block.root, &types.genesis_root));
    }

    pub fn full(self: *const BlockTree) bool {
        assert(self.count <= limits.max_blocks);
        return self.count == limits.max_blocks;
    }

    pub fn find(self: *const BlockTree, root: *const Root) ?BlockIndex {
        assert(self.count >= 1);
        for (0..self.count) |i| {
            if (std.mem.eql(u8, &self.nodes[i].block.root, root)) {
                const index: BlockIndex = @intCast(i);
                return index;
            }
        }
        return null;
    }

    pub fn contains(self: *const BlockTree, root: *const Root) bool {
        return self.find(root) != null;
    }

    /// Inserts a block whose parent is already held. Returns the new index.
    pub fn insert(self: *BlockTree, new_block: *const Block, parent: BlockIndex, received_at: Time) BlockIndex {
        assert(!self.full());
        assert(parent < self.count);
        assert(self.find(&new_block.root) == null);
        assert(std.mem.eql(u8, &self.nodes[parent].block.root, &new_block.parent));
        const index: BlockIndex = self.count;
        self.nodes[index] = .{
            .block = new_block.*,
            .parent = parent,
            .depth = self.nodes[parent].depth + 1,
            .timestamp = received_at,
        };
        self.count += 1;
        assert(self.nodes[index].depth > self.nodes[parent].depth);
        return index;
    }

    pub fn node(self: *const BlockTree, index: BlockIndex) *const Node {
        assert(index < self.count);
        return &self.nodes[index];
    }

    pub fn block(self: *const BlockTree, index: BlockIndex) *const Block {
        return &self.node(index).block;
    }

    pub fn parentOf(self: *const BlockTree, index: BlockIndex) BlockIndex {
        assert(index < self.count);
        assert(index != genesis_index);
        return self.nodes[index].parent;
    }

    pub fn timestamp(self: *const BlockTree, index: BlockIndex) Time {
        return self.node(index).timestamp;
    }

    /// `a ⪯ b`: `a` is `b` or an ancestor of `b`.
    pub fn isAncestorOrSelf(self: *const BlockTree, a: BlockIndex, b: BlockIndex) bool {
        assert(a < self.count);
        assert(b < self.count);
        const depth_a = self.nodes[a].depth;
        var cursor = b;
        var steps: u32 = 0;
        while (self.nodes[cursor].depth > depth_a) : (steps += 1) {
            assert(steps < limits.max_blocks);
            cursor = self.nodes[cursor].parent;
        }
        assert(self.nodes[cursor].depth <= depth_a);
        return cursor == a;
    }

    /// Walks from `index` to genesis and sets `mask` on every block visited.
    pub fn markAncestorsAndSelf(self: *const BlockTree, index: BlockIndex, mask: *[limits.max_blocks]bool) void {
        assert(index < self.count);
        var cursor = index;
        var steps: u32 = 0;
        while (true) : (steps += 1) {
            assert(steps < limits.max_blocks);
            mask[cursor] = true;
            if (cursor == genesis_index) break;
            cursor = self.nodes[cursor].parent;
        }
        assert(mask[genesis_index]);
    }
};

test "ancestry follows parent indices" {
    var tree: BlockTree = undefined;
    tree.init();
    var a: Block = .{ .slot = 1, .parent = types.genesis_root, .proposer = 0 };
    a.seal();
    const ia = tree.insert(&a, genesis_index, 0);
    var b: Block = .{ .slot = 2, .parent = a.root, .proposer = 1 };
    b.seal();
    const ib = tree.insert(&b, ia, 4);
    var c: Block = .{ .slot = 2, .parent = types.genesis_root, .proposer = 1 };
    c.seal();
    const ic = tree.insert(&c, genesis_index, 4);
    try std.testing.expect(tree.isAncestorOrSelf(genesis_index, ib));
    try std.testing.expect(tree.isAncestorOrSelf(ia, ib));
    try std.testing.expect(tree.isAncestorOrSelf(ib, ib));
    try std.testing.expect(!tree.isAncestorOrSelf(ib, ia));
    try std.testing.expect(!tree.isAncestorOrSelf(ia, ic));
    try std.testing.expectEqual(ia, tree.find(&a.root).?);
    try std.testing.expectEqual(@as(?BlockIndex, null), tree.find(&[_]u8{7} ** 32));
}
