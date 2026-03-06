const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;

const Epoch = primitives.Epoch.Type;

const proto_node = @import("proto_node.zig");

/// Sentinel for "validator has no valid vote" (e.g., vote target was pruned).
/// Uses u32 (not ?u32) for SoA cache efficiency: 4 bytes vs 8 bytes per slot.
/// Safe because 0xFFFFFFFF / slots-per-year > 1,634 years of non-finalized network.
pub const NULL_VOTE_INDEX: u32 = 0xFFFFFFFF;

/// Tracks a single validator's fork choice vote.
///
/// Fields are laid out for SoA storage via MultiArrayList:
/// - `current_index` and `next_index` are accessed together in computeDeltas (hot path).
/// - `next_epoch` is only accessed in onAttestation (cold path).
pub const VoteTracker = struct {
    /// Index of the block this validator currently votes for (after last computeDeltas).
    current_index: u32,
    /// Index of the block this validator will vote for (on next computeDeltas).
    next_index: u32,
    /// Epoch of the validator's latest vote. Used by onAttestation to reject stale gossip.
    next_epoch: Epoch,

    pub const DEFAULT: VoteTracker = .{
        .current_index = NULL_VOTE_INDEX,
        .next_index = NULL_VOTE_INDEX,
        .next_epoch = 0,
    };
};

/// SoA storage for per-validator fork choice votes.
///
/// Wraps `MultiArrayList(VoteTracker)` to provide cache-efficient access:
/// - `computeDeltas` iterates only `current_index[]` and `next_index[]` arrays,
///   fitting 16 entries per cache line instead of 4 with AoS.
/// - `onAttestation` accesses all three fields for a single validator (random access).
///
/// Memory is owned; caller provides allocator for init/deinit/resize.
pub const Votes = struct {
    /// SoA storage. Each field stored as a separate contiguous array.
    multi_list: std.MultiArrayList(VoteTracker),

    /// Create an empty Votes with no allocation.
    pub fn init() Votes {
        return .{ .multi_list = .empty };
    }

    /// Release all memory. Caller must pass the same allocator used for resize.
    pub fn deinit(self: *Votes, allocator: Allocator) void {
        self.multi_list.deinit(allocator);
        self.* = undefined;
    }

    /// Number of vote slots (one per validator index).
    pub fn len(self: *const Votes) u32 {
        const raw_len = self.multi_list.len;
        assert(raw_len <= std.math.maxInt(u32));
        return @intCast(raw_len);
    }

    /// Ensure capacity for at least `validator_count` validators.
    /// New slots are initialized to VoteTracker.DEFAULT.
    pub fn ensureValidatorCount(self: *Votes, allocator: Allocator, validator_count: u32) Allocator.Error!void {
        const current_len = self.multi_list.len;
        if (validator_count <= current_len) {
            return;
        }

        try self.multi_list.ensureTotalCapacity(allocator, validator_count);
        // Initialize new slots to DEFAULT.
        self.multi_list.resize(allocator, validator_count) catch unreachable; // capacity already ensured
        const current_indices = self.multi_list.items(.current_index);
        const next_indices = self.multi_list.items(.next_index);
        const next_epochs = self.multi_list.items(.next_epoch);
        @memset(current_indices[current_len..validator_count], NULL_VOTE_INDEX);
        @memset(next_indices[current_len..validator_count], NULL_VOTE_INDEX);
        @memset(next_epochs[current_len..validator_count], 0);
    }

    /// Get the raw SoA arrays for direct field access.
    /// Returns separate contiguous arrays for cache-efficient iteration.
    pub fn fields(self: *Votes) struct {
        current_indices: []u32,
        next_indices: []u32,
        next_epochs: []Epoch,
    } {
        assert(self.multi_list.len > 0 or self.multi_list.capacity == 0);
        return .{
            .current_indices = self.multi_list.items(.current_index),
            .next_indices = self.multi_list.items(.next_index),
            .next_epochs = self.multi_list.items(.next_epoch),
        };
    }
};

// ── Tests ──

test "VoteTracker DEFAULT is null votes" {
    const vote = VoteTracker.DEFAULT;
    try testing.expectEqual(NULL_VOTE_INDEX, vote.current_index);
    try testing.expectEqual(NULL_VOTE_INDEX, vote.next_index);
    try testing.expectEqual(@as(Epoch, 0), vote.next_epoch);
}

test "VoteTracker size is 16 bytes" {
    // 4 (current_index) + 4 (next_index) + 8 (next_epoch) = 16
    try testing.expectEqual(16, @sizeOf(VoteTracker));
}

test "Votes init and deinit" {
    var votes = Votes.init();
    defer votes.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 0), votes.len());
}

test "Votes ensureValidatorCount initializes defaults" {
    var votes = Votes.init();
    defer votes.deinit(testing.allocator);

    try votes.ensureValidatorCount(testing.allocator, 4);
    try testing.expectEqual(@as(u32, 4), votes.len());

    // All slots should be DEFAULT.
    const s = votes.fields();
    for (0..4) |i| {
        try testing.expectEqual(NULL_VOTE_INDEX, s.current_indices[i]);
        try testing.expectEqual(NULL_VOTE_INDEX, s.next_indices[i]);
        try testing.expectEqual(@as(Epoch, 0), s.next_epochs[i]);
    }
}

test "Votes ensureValidatorCount grows preserving existing" {
    var votes = Votes.init();
    defer votes.deinit(testing.allocator);

    try votes.ensureValidatorCount(testing.allocator, 2);

    // Simulate a vote change on validator 0.
    var s = votes.fields();
    s.next_indices[0] = 5;
    s.next_epochs[0] = 10;

    // Grow to 4.
    try votes.ensureValidatorCount(testing.allocator, 4);
    try testing.expectEqual(@as(u32, 4), votes.len());

    // Validator 0 vote preserved.
    const s2 = votes.fields();
    try testing.expectEqual(@as(u32, 5), s2.next_indices[0]);
    try testing.expectEqual(@as(Epoch, 10), s2.next_epochs[0]);

    // New validators are DEFAULT.
    try testing.expectEqual(NULL_VOTE_INDEX, s2.next_indices[2]);
    try testing.expectEqual(NULL_VOTE_INDEX, s2.next_indices[3]);
}

test "Votes ensureValidatorCount no-op when already large enough" {
    var votes = Votes.init();
    defer votes.deinit(testing.allocator);

    try votes.ensureValidatorCount(testing.allocator, 4);
    try votes.ensureValidatorCount(testing.allocator, 2); // should be no-op
    try testing.expectEqual(@as(u32, 4), votes.len());
}

test "Votes fields returns empty arrays when no validators" {
    var votes = Votes.init();
    defer votes.deinit(testing.allocator);

    const s = votes.fields();
    try testing.expectEqual(@as(usize, 0), s.current_indices.len);
    try testing.expectEqual(@as(usize, 0), s.next_indices.len);
    try testing.expectEqual(@as(usize, 0), s.next_epochs.len);
}
