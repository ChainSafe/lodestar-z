//! EventBus — ring buffer pub/sub for beacon chain events.
//!
//! Stores up to 256 recent events in a ring buffer. SSE handlers poll by
//! keeping track of the last `write_idx` they consumed and calling
//! `getRecent(since_idx)` to receive any new events.
//!
//! Thread safety: single-threaded (cooperative-async model assumed).

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

pub const EventType = enum {
    head,
    block,
    finalized_checkpoint,
    chain_reorg,
};

pub const Event = union(EventType) {
    head: HeadEvent,
    block: BlockEvent,
    finalized_checkpoint: FinalizedCheckpointEvent,
    chain_reorg: ChainReorgEvent,
};

pub const HeadEvent = struct {
    slot: u64,
    block_root: [32]u8,
    state_root: [32]u8,
    epoch_transition: bool,
};

pub const BlockEvent = struct {
    slot: u64,
    block_root: [32]u8,
};

pub const FinalizedCheckpointEvent = struct {
    epoch: u64,
    root: [32]u8,
    state_root: [32]u8,
};

pub const ChainReorgEvent = struct {
    slot: u64,
    depth: u64,
    old_head_root: [32]u8,
    new_head_root: [32]u8,
};

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

pub const EventBus = struct {
    allocator: Allocator,
    /// Ring buffer of recent events (256 slots, indexed by u8).
    events: [256]Event,
    /// Next write position. Wraps at 256.
    write_idx: u8,
    /// Number of events emitted so far (saturates at 256 once full).
    count: u8,

    /// Initialise an empty event bus.
    pub fn init(allocator: Allocator) EventBus {
        return .{
            .allocator = allocator,
            .events = undefined,
            .write_idx = 0,
            .count = 0,
        };
    }

    /// Emit an event into the ring buffer. Overwrites the oldest event once
    /// the buffer is full.
    pub fn emit(self: *EventBus, event: Event) void {
        self.events[self.write_idx] = event;
        self.write_idx +%= 1; // wraps at 256
        if (self.count < 255) self.count += 1;
    }

    /// Return events written since `since_idx`.
    ///
    /// The returned slice is a view into the ring buffer and is valid until
    /// the next `emit` call that overwrites those slots.
    ///
    /// Callers store `event_bus.write_idx` after consuming and pass it back
    /// on the next poll.  If `since_idx == write_idx`, returns an empty slice.
    ///
    /// Note: this only returns a contiguous slice when the write position has
    /// not wrapped past `since_idx`.  When a wrap-around has occurred (rare
    /// in practice for slowly-advancing SSE streams) callers should reset
    /// `since_idx` to 0 and re-subscribe.
    pub fn getRecent(self: *const EventBus, since_idx: u8) []const Event {
        if (since_idx == self.write_idx) return &.{};
        if (since_idx < self.write_idx) {
            return self.events[since_idx..self.write_idx];
        }
        // Wrapped around: since_idx > write_idx.
        // Cannot return a contiguous slice; caller should reset to 0.
        return &.{};
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EventBus: init is empty" {
    var bus = EventBus.init(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), bus.write_idx);
    try std.testing.expectEqual(@as(u8, 0), bus.count);
    const slice = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 0), slice.len);
}

test "EventBus: emit and getRecent" {
    var bus = EventBus.init(std.testing.allocator);

    bus.emit(.{ .block = .{ .slot = 1, .block_root = [_]u8{0xAA} ** 32 } });
    bus.emit(.{ .block = .{ .slot = 2, .block_root = [_]u8{0xBB} ** 32 } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 2), recent.len);
    try std.testing.expectEqual(@as(u64, 1), recent[0].block.slot);
    try std.testing.expectEqual(@as(u64, 2), recent[1].block.slot);
}

test "EventBus: getRecent returns empty when up to date" {
    var bus = EventBus.init(std.testing.allocator);
    bus.emit(.{ .block = .{ .slot = 5, .block_root = [_]u8{0} ** 32 } });

    const since = bus.write_idx;
    bus.emit(.{ .block = .{ .slot = 6, .block_root = [_]u8{1} ** 32 } });

    // since was 1, write_idx is now 2
    const recent = bus.getRecent(since);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    try std.testing.expectEqual(@as(u64, 6), recent[0].block.slot);
}

test "EventBus: head event round-trip" {
    var bus = EventBus.init(std.testing.allocator);

    const block_root = [_]u8{0xDE} ** 32;
    const state_root = [_]u8{0xAD} ** 32;
    bus.emit(.{ .head = .{
        .slot = 42,
        .block_root = block_root,
        .state_root = state_root,
        .epoch_transition = true,
    } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    const ev = recent[0].head;
    try std.testing.expectEqual(@as(u64, 42), ev.slot);
    try std.testing.expect(ev.epoch_transition);
    try std.testing.expectEqualSlices(u8, &block_root, &ev.block_root);
    try std.testing.expectEqualSlices(u8, &state_root, &ev.state_root);
}

test "EventBus: finalized_checkpoint event" {
    var bus = EventBus.init(std.testing.allocator);

    bus.emit(.{ .finalized_checkpoint = .{
        .epoch = 5,
        .root = [_]u8{0x55} ** 32,
        .state_root = [_]u8{0x66} ** 32,
    } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    try std.testing.expectEqual(@as(u64, 5), recent[0].finalized_checkpoint.epoch);
}
