//! Generic bounded queue implementations for the BeaconProcessor.
//!
//! Two queue types, both fixed-capacity ring buffers backed by caller-provided
//! slices (no heap allocation after init):
//!
//! - `FifoQueue(T)` — First-in-first-out. Drops new items when full.
//!   Used for blocks, slashings, and anything where ordering matters.
//!
//! - `LifoQueue(T)` — Last-in-first-out. Drops oldest items when full.
//!   Used for attestations and sync committee messages where newer data
//!   is more valuable than older data.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Fixed-capacity FIFO queue backed by a caller-provided slice.
///
/// When full, `push` returns `false` and the item is not enqueued.
/// The caller is responsible for logging/metrics on drops.
pub fn FifoQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        buffer: []T,
        head: u32, // Next read position.
        tail: u32, // Next write position.
        len: u32,
        capacity: u32,

        /// Initialise a FIFO queue backed by the given slice.
        /// The slice must have length > 0.
        pub fn init(buffer: []T) Self {
            assert(buffer.len > 0);
            assert(buffer.len <= std.math.maxInt(u32));
            return .{
                .buffer = buffer,
                .head = 0,
                .tail = 0,
                .len = 0,
                .capacity = @intCast(buffer.len),
            };
        }

        /// Push an item to the back of the queue.
        /// Returns `true` on success, `false` if the queue is full.
        pub fn push(self: *Self, item: T) bool {
            if (self.len == self.capacity) return false;
            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % self.capacity;
            self.len += 1;
            return true;
        }

        /// Pop an item from the front of the queue (oldest first).
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const item = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;
            return item;
        }

        /// Returns true if the queue is empty.
        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        /// Returns true if the queue is at capacity.
        pub fn isFull(self: *const Self) bool {
            return self.len == self.capacity;
        }

        /// Discard all items.
        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
            self.len = 0;
        }
    };
}

/// Fixed-capacity LIFO queue backed by a caller-provided slice.
///
/// When full, `push` drops the oldest item (back of the queue) to make room.
/// This means `push` always succeeds — ideal for attestations where the newest
/// data is most valuable.
///
/// Internally, items are stored in a ring buffer. The "front" (head) is the
/// most recently pushed item; the "back" (tail end) is the oldest.
pub fn LifoQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        buffer: []T,
        head: u32, // Points to the most recently pushed item.
        len: u32,
        capacity: u32,

        /// Initialise a LIFO queue backed by the given slice.
        /// The slice must have length > 0.
        pub fn init(buffer: []T) Self {
            assert(buffer.len > 0);
            assert(buffer.len <= std.math.maxInt(u32));
            return .{
                .buffer = buffer,
                .head = 0,
                .len = 0,
                .capacity = @intCast(buffer.len),
            };
        }

        /// Push an item. If the queue is full, the oldest item is returned so
        /// the caller can account for and clean it up.
        pub fn push(self: *Self, item: T) ?T {
            var dropped: ?T = null;
            if (self.len == self.capacity) {
                // Overwrite the oldest item (at the tail end).
                // Head will advance backwards to the new slot.
                // The oldest item is at position (head + len - 1) % cap
                // but since len == cap, the slot we're about to write into
                // is the oldest.  We decrement len first, then push normally.
                const tail_index = (self.head + self.len - 1) % self.capacity;
                dropped = self.buffer[tail_index];
                self.len -= 1;
            }
            // Advance head backwards (wrapping) and write the new item there.
            if (self.head == 0) {
                self.head = self.capacity - 1;
            } else {
                self.head -= 1;
            }
            self.buffer[self.head] = item;
            self.len += 1;
            return dropped;
        }

        /// Pop the most recently pushed item (LIFO order).
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const item = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;
            return item;
        }

        /// Pop up to `out.len` items into the provided slice (LIFO order).
        /// Returns the number of items actually popped.
        pub fn popBatch(self: *Self, out: []T) u32 {
            var count: u32 = 0;
            const max: u32 = @intCast(out.len);
            while (count < max) {
                if (self.pop()) |item| {
                    out[count] = item;
                    count += 1;
                } else break;
            }
            return count;
        }

        /// Returns true if the queue is empty.
        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        /// Returns true if the queue is at capacity.
        pub fn isFull(self: *const Self) bool {
            return self.len == self.capacity;
        }

        /// Discard all items.
        pub fn clear(self: *Self) void {
            self.head = 0;
            self.len = 0;
        }
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "FifoQueue: basic push/pop ordering" {
    var buf: [4]u32 = undefined;
    var q = FifoQueue(u32).init(&buf);

    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(u32, 0), q.len);

    try testing.expect(q.push(10));
    try testing.expect(q.push(20));
    try testing.expect(q.push(30));
    try testing.expectEqual(@as(u32, 3), q.len);

    // FIFO: oldest comes out first.
    try testing.expectEqual(@as(u32, 10), q.pop().?);
    try testing.expectEqual(@as(u32, 20), q.pop().?);
    try testing.expectEqual(@as(u32, 30), q.pop().?);
    try testing.expectEqual(@as(?u32, null), q.pop());
    try testing.expect(q.isEmpty());
}

test "FifoQueue: drops new item when full" {
    var buf: [2]u32 = undefined;
    var q = FifoQueue(u32).init(&buf);

    try testing.expect(q.push(1));
    try testing.expect(q.push(2));
    try testing.expect(q.isFull());

    // Third push should fail.
    try testing.expect(!q.push(3));
    try testing.expectEqual(@as(u32, 2), q.len);

    // Original items still intact.
    try testing.expectEqual(@as(u32, 1), q.pop().?);
    try testing.expectEqual(@as(u32, 2), q.pop().?);
}

test "FifoQueue: wrap-around" {
    var buf: [3]u32 = undefined;
    var q = FifoQueue(u32).init(&buf);

    // Fill queue.
    try testing.expect(q.push(1));
    try testing.expect(q.push(2));
    try testing.expect(q.push(3));

    // Pop two, freeing space at head.
    try testing.expectEqual(@as(u32, 1), q.pop().?);
    try testing.expectEqual(@as(u32, 2), q.pop().?);

    // Push two more — these wrap around the ring.
    try testing.expect(q.push(4));
    try testing.expect(q.push(5));
    try testing.expectEqual(@as(u32, 3), q.len);

    // Should come out in order: 3, 4, 5.
    try testing.expectEqual(@as(u32, 3), q.pop().?);
    try testing.expectEqual(@as(u32, 4), q.pop().?);
    try testing.expectEqual(@as(u32, 5), q.pop().?);
    try testing.expect(q.isEmpty());
}

test "FifoQueue: clear" {
    var buf: [4]u32 = undefined;
    var q = FifoQueue(u32).init(&buf);

    try testing.expect(q.push(1));
    try testing.expect(q.push(2));
    q.clear();
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(?u32, null), q.pop());

    // Can reuse after clear.
    try testing.expect(q.push(99));
    try testing.expectEqual(@as(u32, 99), q.pop().?);
}

test "LifoQueue: basic push/pop ordering" {
    var buf: [4]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    try testing.expect(q.isEmpty());

    _ = q.push(10);
    _ = q.push(20);
    _ = q.push(30);
    try testing.expectEqual(@as(u32, 3), q.len);

    // LIFO: newest comes out first.
    try testing.expectEqual(@as(u32, 30), q.pop().?);
    try testing.expectEqual(@as(u32, 20), q.pop().?);
    try testing.expectEqual(@as(u32, 10), q.pop().?);
    try testing.expectEqual(@as(?u32, null), q.pop());
}

test "LifoQueue: drops oldest when full" {
    var buf: [3]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(1);
    _ = q.push(2);
    _ = q.push(3);
    try testing.expect(q.isFull());

    // Push 4 — should drop 1 (oldest).
    _ = q.push(4);
    try testing.expectEqual(@as(u32, 3), q.len);

    // Pop all: 4 (newest), 3, 2 — item 1 was dropped.
    try testing.expectEqual(@as(u32, 4), q.pop().?);
    try testing.expectEqual(@as(u32, 3), q.pop().?);
    try testing.expectEqual(@as(u32, 2), q.pop().?);
    try testing.expectEqual(@as(?u32, null), q.pop());
}

test "LifoQueue: drops oldest repeatedly when full" {
    var buf: [2]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(1);
    _ = q.push(2);

    // Push 3, 4, 5 — each should drop the oldest.
    _ = q.push(3);
    _ = q.push(4);
    _ = q.push(5);
    try testing.expectEqual(@as(u32, 2), q.len);

    // Only the two newest should remain: 5, 4.
    try testing.expectEqual(@as(u32, 5), q.pop().?);
    try testing.expectEqual(@as(u32, 4), q.pop().?);
    try testing.expectEqual(@as(?u32, null), q.pop());
}

test "LifoQueue: popBatch" {
    var buf: [8]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    // Push 1..6.
    var i: u32 = 1;
    while (i <= 6) : (i += 1) {
        _ = q.push(i);
    }
    try testing.expectEqual(@as(u32, 6), q.len);

    // Pop batch of 4 — should get 6, 5, 4, 3 (LIFO).
    var batch: [4]u32 = undefined;
    const count = q.popBatch(&batch);
    try testing.expectEqual(@as(u32, 4), count);
    try testing.expectEqual(@as(u32, 6), batch[0]);
    try testing.expectEqual(@as(u32, 5), batch[1]);
    try testing.expectEqual(@as(u32, 4), batch[2]);
    try testing.expectEqual(@as(u32, 3), batch[3]);

    // Two items remain: 2, 1.
    try testing.expectEqual(@as(u32, 2), q.len);
    try testing.expectEqual(@as(u32, 2), q.pop().?);
    try testing.expectEqual(@as(u32, 1), q.pop().?);
}

test "LifoQueue: popBatch when fewer items than requested" {
    var buf: [4]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(10);
    _ = q.push(20);

    var batch: [8]u32 = undefined;
    const count = q.popBatch(&batch);
    try testing.expectEqual(@as(u32, 2), count);
    try testing.expectEqual(@as(u32, 20), batch[0]);
    try testing.expectEqual(@as(u32, 10), batch[1]);
    try testing.expect(q.isEmpty());
}

test "LifoQueue: wrap-around with push and pop interleaved" {
    var buf: [3]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(1);
    _ = q.push(2);
    // Pop one (newest = 2).
    try testing.expectEqual(@as(u32, 2), q.pop().?);

    _ = q.push(3);
    _ = q.push(4);
    // Queue has: 4 (newest), 3, 1 (oldest). len=3.
    try testing.expectEqual(@as(u32, 3), q.len);

    try testing.expectEqual(@as(u32, 4), q.pop().?);
    try testing.expectEqual(@as(u32, 3), q.pop().?);
    try testing.expectEqual(@as(u32, 1), q.pop().?);
    try testing.expect(q.isEmpty());
}

test "LifoQueue: clear" {
    var buf: [4]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(1);
    _ = q.push(2);
    q.clear();
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(?u32, null), q.pop());

    // Can reuse after clear.
    _ = q.push(99);
    try testing.expectEqual(@as(u32, 99), q.pop().?);
}

test "FifoQueue: capacity of 1" {
    var buf: [1]u32 = undefined;
    var q = FifoQueue(u32).init(&buf);

    try testing.expect(q.push(42));
    try testing.expect(q.isFull());
    try testing.expect(!q.push(43));
    try testing.expectEqual(@as(u32, 42), q.pop().?);
    try testing.expect(q.isEmpty());
}

test "LifoQueue: capacity of 1" {
    var buf: [1]u32 = undefined;
    var q = LifoQueue(u32).init(&buf);

    _ = q.push(42);
    try testing.expect(q.isFull());
    _ = q.push(99); // Should drop 42.
    try testing.expectEqual(@as(u32, 1), q.len);
    try testing.expectEqual(@as(u32, 99), q.pop().?);
    try testing.expect(q.isEmpty());
}
