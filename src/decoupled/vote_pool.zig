//! `Σ.gf_votes[k]`: processed Goldfish votes per slot, with the time each
//! one entered the store. A slot keeps at most two distinct votes per
//! validator (PROTOCOL.md §1.1).

const std = @import("std");
const assert = std.debug.assert;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("limits.zig");
const types = @import("types.zig");

const GoldfishVote = types.GoldfishVote;
const Slot = types.Slot;
const Time = types.Time;
const ValidatorIndex = types.ValidatorIndex;

pub const VoteEntry = struct {
    vote: GoldfishVote,
    timestamp: Time,
};

pub const SlotPool = struct {
    entries: BoundedArray(VoteEntry, limits.max_votes_per_slot) = .{},

    pub fn contains(self: *const SlotPool, vote: *const GoldfishVote) bool {
        for (self.entries.constSlice()) |*entry| {
            if (entry.vote.eql(vote)) return true;
        }
        return false;
    }

    pub fn countByValidator(self: *const SlotPool, v: ValidatorIndex) u32 {
        var count: u32 = 0;
        for (self.entries.constSlice()) |*entry| {
            if (entry.vote.val_index == v) count += 1;
        }
        assert(count <= 2);
        return count;
    }

    pub fn add(self: *SlotPool, vote: *const GoldfishVote, timestamp: Time) void {
        assert(!self.contains(vote));
        assert(self.countByValidator(vote.val_index) < 2);
        self.entries.push(.{ .vote = vote.*, .timestamp = timestamp });
    }
};

pub const VotePool = struct {
    slots: [limits.max_slots]SlotPool,

    pub fn init(self: *VotePool) void {
        for (&self.slots) |*pool| pool.* = .{};
        assert(self.slots[0].entries.empty());
        assert(self.slots[limits.max_slots - 1].entries.empty());
    }

    pub fn slot(self: *VotePool, s: Slot) *SlotPool {
        assert(s < limits.max_slots);
        return &self.slots[s];
    }

    pub fn slotConst(self: *const VotePool, s: Slot) *const SlotPool {
        assert(s < limits.max_slots);
        return &self.slots[s];
    }
};

test "a slot pool keeps at most two distinct votes per validator" {
    var pool: SlotPool = .{};
    const first: GoldfishVote = .{ .val_index = 3, .slot = 1, .head = [_]u8{1} ** 32 };
    const second: GoldfishVote = .{ .val_index = 3, .slot = 1, .head = [_]u8{2} ** 32 };
    pool.add(&first, 5);
    try std.testing.expect(pool.contains(&first));
    try std.testing.expect(!pool.contains(&second));
    pool.add(&second, 6);
    try std.testing.expectEqual(@as(u32, 2), pool.countByValidator(3));
    try std.testing.expectEqual(@as(u32, 0), pool.countByValidator(4));
}
