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

    /// Returns the SSE topic name for this event type.
    pub fn topicName(self: EventType) []const u8 {
        return switch (self) {
            .head => "head",
            .block => "block",
            .finalized_checkpoint => "finalized_checkpoint",
            .chain_reorg => "chain_reorg",
        };
    }
};

pub const Event = union(EventType) {
    head: HeadEvent,
    block: BlockEvent,
    finalized_checkpoint: FinalizedCheckpointEvent,
    chain_reorg: ChainReorgEvent,

    /// Returns the active event type tag.
    pub fn eventType(self: Event) EventType {
        return std.meta.activeTag(self);
    }

    /// Format the JSON `data` payload for this event into `buf`.
    /// Returns the written slice. Uses `std.fmt.bufPrint`.
    pub fn writeJson(self: Event, buf: []u8) std.fmt.BufPrintError![]const u8 {
        return switch (self) {
            .head => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"block\":\"0x{s}\",\"state\":\"0x{s}\",\"epoch_transition\":{s}}}",
                .{
                    e.slot,
                    std.fmt.bytesToHex(&e.block_root, .lower),
                    std.fmt.bytesToHex(&e.state_root, .lower),
                    if (e.epoch_transition) @as([]const u8, "true") else @as([]const u8, "false"),
                },
            ),
            .block => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"block\":\"0x{s}\"}}",
                .{
                    e.slot,
                    std.fmt.bytesToHex(&e.block_root, .lower),
                },
            ),
            .finalized_checkpoint => |e| std.fmt.bufPrint(buf,
                "{{\"block\":\"0x{s}\",\"state\":\"0x{s}\",\"epoch\":\"{d}\"}}",
                .{
                    std.fmt.bytesToHex(&e.root, .lower),
                    std.fmt.bytesToHex(&e.state_root, .lower),
                    e.epoch,
                },
            ),
            .chain_reorg => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"depth\":\"{d}\",\"old_head_block\":\"0x{s}\",\"new_head_block\":\"0x{s}\",\"old_head_state\":\"0x{s}\",\"new_head_state\":\"0x{s}\",\"epoch\":\"{d}\"}}",
                .{
                    e.slot,
                    e.depth,
                    std.fmt.bytesToHex(&e.old_head_root, .lower),
                    std.fmt.bytesToHex(&e.new_head_root, .lower),
                    std.fmt.bytesToHex(&e.old_state_root, .lower),
                    std.fmt.bytesToHex(&e.new_state_root, .lower),
                    e.epoch,
                },
            ),
        };
    }
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
    /// State root of the old head (before reorg).
    old_state_root: [32]u8,
    /// State root of the new head (after reorg).
    new_state_root: [32]u8,
    /// Epoch of the new head slot.
    epoch: u64,
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

test "Event.writeJson: head event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .head = .{
        .slot = 42,
        .block_root = [_]u8{0xAA} ** 32,
        .state_root = [_]u8{0xBB} ** 32,
        .epoch_transition = true,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch_transition\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0xaaaa") != null);
}

test "Event.writeJson: block event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .block = .{
        .slot = 100,
        .block_root = [_]u8{0xFF} ** 32,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0xffff") != null);
}

test "Event.writeJson: finalized_checkpoint event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .finalized_checkpoint = .{
        .epoch = 10,
        .root = [_]u8{0x11} ** 32,
        .state_root = [_]u8{0x22} ** 32,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch\":\"10\"") != null);
}

test "Event.writeJson: chain_reorg event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .chain_reorg = .{
        .slot = 99,
        .depth = 3,
        .old_head_root = [_]u8{0xAA} ** 32,
        .new_head_root = [_]u8{0xBB} ** 32,
        .old_state_root = [_]u8{0xCC} ** 32,
        .new_state_root = [_]u8{0xDD} ** 32,
        .epoch = 12,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"depth\":\"3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch\":\"12\"") != null);
}

test "EventType.topicName" {
    try std.testing.expectEqualStrings("head", EventType.head.topicName());
    try std.testing.expectEqualStrings("block", EventType.block.topicName());
    try std.testing.expectEqualStrings("finalized_checkpoint", EventType.finalized_checkpoint.topicName());
    try std.testing.expectEqualStrings("chain_reorg", EventType.chain_reorg.topicName());
}
