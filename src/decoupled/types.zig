//! Wire objects of the Goldfish layer (PROTOCOL.md A.2). Roots are a SHA-256
//! over the block fields, not an SSZ hash tree root: the model has no
//! cryptography, and the root only needs to be collision-free in a run.

const std = @import("std");
const assert = std.debug.assert;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("limits.zig");

pub const Root = [32]u8;
pub const Time = u32;
pub const Slot = u32;
pub const ValidatorIndex = u32;

pub const genesis_root: Root = [_]u8{0} ** 32;

pub fn slotStart(s: Slot) Time {
    assert(s < limits.max_slots);
    const t = s * limits.slot_ticks;
    assert(t < limits.max_time);
    return t;
}

pub fn slotOf(t: Time) Slot {
    assert(t < limits.max_time);
    const s = t / limits.slot_ticks;
    assert(s < limits.max_slots);
    return s;
}

pub fn rootOrder(a: *const Root, b: *const Root) std.math.Order {
    return std.mem.order(u8, a, b);
}

pub const GoldfishVote = extern struct {
    val_index: ValidatorIndex,
    slot: Slot,
    head: Root,

    pub fn eql(a: *const GoldfishVote, b: *const GoldfishVote) bool {
        if (a.val_index != b.val_index) return false;
        if (a.slot != b.slot) return false;
        return std.mem.eql(u8, &a.head, &b.head);
    }
};

pub const BlockVotes = BoundedArray(GoldfishVote, limits.max_votes_per_block);

pub const Block = struct {
    root: Root = genesis_root,
    slot: Slot,
    parent: Root,
    proposer: ValidatorIndex,
    /// Previous-slot votes the proposer held (`B.votes`).
    votes: BlockVotes = .{},
    /// `B.support_votes`, as a flag per entry of `votes`.
    support: [limits.max_votes_per_block]bool = [_]bool{false} ** limits.max_votes_per_block,

    pub fn genesis() Block {
        return .{ .slot = 0, .parent = genesis_root, .proposer = 0 };
    }

    /// Computes `root` from every other field. Call once, after the fields
    /// are final.
    pub fn seal(self: *Block) void {
        assert(self.slot > 0);
        assert(self.votes.count <= limits.max_votes_per_block);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, self.slot, .little);
        hasher.update(&word);
        hasher.update(&self.parent);
        std.mem.writeInt(u32, &word, self.proposer, .little);
        hasher.update(&word);
        for (self.votes.constSlice(), 0..) |*vote, i| {
            std.mem.writeInt(u32, &word, vote.val_index, .little);
            hasher.update(&word);
            std.mem.writeInt(u32, &word, vote.slot, .little);
            hasher.update(&word);
            hasher.update(&vote.head);
            const flag: u8 = @intFromBool(self.support[i]);
            hasher.update(&[_]u8{flag});
        }
        hasher.final(&self.root);
        assert(!std.mem.eql(u8, &self.root, &genesis_root));
    }
};

test "seal is deterministic and separates blocks" {
    var a: Block = .{ .slot = 1, .parent = genesis_root, .proposer = 3 };
    var b: Block = .{ .slot = 1, .parent = genesis_root, .proposer = 3 };
    var c: Block = .{ .slot = 2, .parent = genesis_root, .proposer = 3 };
    a.seal();
    b.seal();
    c.seal();
    try std.testing.expect(std.mem.eql(u8, &a.root, &b.root));
    try std.testing.expect(!std.mem.eql(u8, &a.root, &c.root));
    try std.testing.expectEqual(std.math.Order.eq, rootOrder(&a.root, &b.root));
}
