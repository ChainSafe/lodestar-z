const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;

const Slot = primitives.Slot.Type;

/// Sentinel for "validator has no valid vote" (e.g., vote target was pruned).
/// Uses u32 (not ?u32) for SoA cache efficiency: 4 bytes vs 8 bytes per slot.
/// Safe because 0xFFFFFFFF / slots-per-year > 1,634 years of non-finalized network.
pub const NULL_VOTE_INDEX: u32 = std.math.maxInt(u32);

/// Tracks a single validator's fork choice vote.
///
/// Gloas spec: LatestMessage { slot, root }.
/// Payload status (EMPTY vs FULL) is encoded in the node index itself — different
/// variants have different ProtoArray indices, so no separate payload_present field is needed.
/// Fields are laid out for SoA storage via MultiArrayList:
/// - `current_index` and `next_index` are accessed together in computeDeltas (hot path).
/// - `next_slot` is only accessed in onAttestation (cold path).
pub const VoteTracker = struct {
    /// Index of the block this validator currently votes for (after last computeDeltas).
    current_index: u32 = NULL_VOTE_INDEX,
    /// Index of the block this validator will vote for (on next computeDeltas).
    next_index: u32 = NULL_VOTE_INDEX,
    /// Slot of the validator's latest vote. Used by onAttestation to reject stale votes.
    next_slot: Slot = 0,
};

/// SoA storage for per-validator fork choice votes.
///
/// Wraps `MultiArrayList(VoteTracker)` to provide cache-efficient access:
/// - `computeDeltas` iterates only `current_index[]` and `next_index[]` arrays,
///   fitting 16 entries per cache line instead of 4 with AoS.
/// - `onAttestation` accesses all fields for a single validator (random access).
///
/// Memory is owned; caller provides allocator for init/deinit/resize.
pub const Votes = struct {
    /// SoA storage. Each field stored as a separate contiguous array.
    multi_list: std.MultiArrayList(VoteTracker) = .empty,

    /// Release all memory. Caller must pass the same allocator used for resize.
    pub fn deinit(self: *Votes, allocator: Allocator) void {
        self.multi_list.deinit(allocator);
        self.* = undefined;
    }

    /// Number of vote slots (one per validator index).
    pub fn len(self: *const Votes) u32 {
        const raw_len = self.multi_list.len;
        assert(raw_len < NULL_VOTE_INDEX);
        return @intCast(raw_len);
    }

    /// Ensure capacity for at least `validator_count` validators.
    /// New slots are initialized to VoteTracker defaults.
    pub fn ensureValidatorCount(self: *Votes, allocator: Allocator, validator_count: u32) Allocator.Error!void {
        const current_len = self.multi_list.len;
        if (validator_count <= current_len) {
            return;
        }

        try self.multi_list.ensureTotalCapacity(allocator, validator_count);
        // Initialize new slots to defaults.
        self.multi_list.resize(allocator, validator_count) catch unreachable; // capacity already ensured
        const current_indices = self.multi_list.items(.current_index);
        const next_indices = self.multi_list.items(.next_index);
        const next_slots = self.multi_list.items(.next_slot);
        @memset(current_indices[current_len..validator_count], NULL_VOTE_INDEX);
        @memset(next_indices[current_len..validator_count], NULL_VOTE_INDEX);
        @memset(next_slots[current_len..validator_count], 0);
    }

    /// Get the raw SoA arrays for direct field access.
    /// Returns separate contiguous arrays for cache-efficient iteration.
    pub fn fields(self: *Votes) struct {
        current_indices: []u32,
        next_indices: []u32,
        next_slots: []Slot,
    } {
        assert(self.multi_list.len > 0 or self.multi_list.capacity == 0);
        return .{
            .current_indices = self.multi_list.items(.current_index),
            .next_indices = self.multi_list.items(.next_index),
            .next_slots = self.multi_list.items(.next_slot),
        };
    }
};

// ── Tests ──

test "VoteTracker default is null votes" {
    const vote: VoteTracker = .{};
    try testing.expectEqual(NULL_VOTE_INDEX, vote.current_index);
    try testing.expectEqual(NULL_VOTE_INDEX, vote.next_index);
    try testing.expectEqual(@as(Slot, 0), vote.next_slot);
}

test "VoteTracker size" {
    // 4 (current_index) + 4 (next_index) + 8 (next_slot)
    try testing.expectEqual(16, @sizeOf(VoteTracker));
}

test "Votes ensureValidatorCount grow sequence" {
    var votes: Votes = .{};
    defer votes.deinit(testing.allocator);

    const Step = struct { grow_to: u32, expected_len: u32 };
    const steps = [_]Step{
        .{ .grow_to = 0, .expected_len = 0 }, // empty
        .{ .grow_to = 4, .expected_len = 4 }, // grow from 0
        .{ .grow_to = 2, .expected_len = 4 }, // no-op (already large enough)
        .{ .grow_to = 8, .expected_len = 8 }, // grow again
    };

    for (steps) |step| {
        try votes.ensureValidatorCount(testing.allocator, step.grow_to);
        try testing.expectEqual(step.expected_len, votes.len());
    }

    // Verify all slots are defaults after growing.
    const s = votes.fields();
    for (0..votes.len()) |i| {
        try testing.expectEqual(NULL_VOTE_INDEX, s.current_indices[i]);
        try testing.expectEqual(NULL_VOTE_INDEX, s.next_indices[i]);
        try testing.expectEqual(@as(Slot, 0), s.next_slots[i]);
    }
}

test "Votes ensureValidatorCount preserves existing data" {
    var votes: Votes = .{};
    defer votes.deinit(testing.allocator);

    try votes.ensureValidatorCount(testing.allocator, 2);

    // Modify validator 0.
    var s = votes.fields();
    s.next_indices[0] = 5;
    s.next_slots[0] = 10;

    // Grow — validator 0 must be preserved.
    try votes.ensureValidatorCount(testing.allocator, 4);
    const s2 = votes.fields();
    try testing.expectEqual(@as(u32, 5), s2.next_indices[0]);
    try testing.expectEqual(@as(Slot, 10), s2.next_slots[0]);

    // New slots are defaults.
    try testing.expectEqual(NULL_VOTE_INDEX, s2.next_indices[2]);
}
