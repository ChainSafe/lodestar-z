//! FIFO queue of owned events, shared by the protocol and service layers.
//!
//! Backed by an `ArrayList` with a moving head index so `pop` is O(1) without
//! shifting on every read. Consumed entries are reclaimed lazily by `compact`,
//! which only shifts once the consumed prefix is large enough that copying is
//! cheaper than the space it reclaims.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Only shift live entries to the front once at least this many have been
/// consumed; below the threshold the wasted slots are cheaper than the copy.
const compact_min_head = 64;
const default_max_pending = 1024;

pub const PushError = Allocator.Error || error{QueueFull};

/// `T` must expose `pub fn deinit(self: *T, alloc: Allocator) void` so the queue
/// can release any events still buffered when it is torn down.
pub fn EventQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        events: std.ArrayListUnmanaged(T) = .empty,
        head: usize = 0,
        max_pending: usize = default_max_pending,

        pub fn deinit(self: *Self, alloc: Allocator) void {
            for (self.events.items[self.head..]) |*event| event.deinit(alloc);
            self.events.deinit(alloc);
        }

        pub fn push(self: *Self, alloc: Allocator, event: T) PushError!void {
            if (self.pending() >= self.max_pending) return error.QueueFull;
            try self.events.append(alloc, event);
        }

        pub fn pop(self: *Self) ?T {
            if (self.head >= self.events.items.len) {
                self.events.clearRetainingCapacity();
                self.head = 0;
                return null;
            }

            const event = self.events.items[self.head];
            self.head += 1;
            self.compact();
            return event;
        }

        /// Number of events pushed but not yet popped.
        pub fn pending(self: *const Self) usize {
            return self.events.items.len - self.head;
        }

        fn compact(self: *Self) void {
            if (self.head == 0) return;
            const remaining = self.events.items.len - self.head;
            if (remaining == 0) {
                self.events.clearRetainingCapacity();
                self.head = 0;
                return;
            }
            if (self.head < compact_min_head and self.head * 2 < self.events.items.len) return;

            std.mem.copyForwards(
                T,
                self.events.items[0..remaining],
                self.events.items[self.head..],
            );
            self.events.items.len = remaining;
            self.head = 0;
        }
    };
}

const TestEvent = struct {
    value: u32,
    deinit_calls: *usize,

    fn deinit(self: *TestEvent, _: Allocator) void {
        self.deinit_calls.* += 1;
    }
};

test "EventQueue preserves FIFO order" {
    const alloc = std.testing.allocator;
    var calls: usize = 0;
    var queue: EventQueue(TestEvent) = .{};
    defer queue.deinit(alloc);

    try queue.push(alloc, .{ .value = 1, .deinit_calls = &calls });
    try queue.push(alloc, .{ .value = 2, .deinit_calls = &calls });
    try std.testing.expectEqual(@as(usize, 2), queue.pending());

    try std.testing.expectEqual(@as(u32, 1), queue.pop().?.value);
    try std.testing.expectEqual(@as(u32, 2), queue.pop().?.value);
    try std.testing.expect(queue.pop() == null);
    try std.testing.expectEqual(@as(usize, 0), queue.pending());
}

test "EventQueue deinit releases buffered events" {
    const alloc = std.testing.allocator;
    var calls: usize = 0;
    var queue: EventQueue(TestEvent) = .{};

    try queue.push(alloc, .{ .value = 1, .deinit_calls = &calls });
    try queue.push(alloc, .{ .value = 2, .deinit_calls = &calls });
    _ = queue.pop();
    queue.deinit(alloc);

    // Only the un-popped event should be released by the queue.
    try std.testing.expectEqual(@as(usize, 1), calls);
}

test "EventQueue compacts after consuming a large prefix" {
    const alloc = std.testing.allocator;
    var calls: usize = 0;
    var queue: EventQueue(TestEvent) = .{};
    defer queue.deinit(alloc);

    var i: u32 = 0;
    while (i < compact_min_head * 2) : (i += 1) {
        try queue.push(alloc, .{ .value = i, .deinit_calls = &calls });
    }
    i = 0;
    while (i < compact_min_head) : (i += 1) _ = queue.pop();

    // Head has been folded back to the front; remaining items stay in order.
    try std.testing.expectEqual(@as(usize, compact_min_head), queue.pending());
    try std.testing.expectEqual(@as(u32, compact_min_head), queue.pop().?.value);
}

test "EventQueue bounds pending events" {
    const alloc = std.testing.allocator;
    var calls: usize = 0;
    var queue: EventQueue(TestEvent) = .{ .max_pending = 1 };
    defer queue.deinit(alloc);

    try queue.push(alloc, .{ .value = 1, .deinit_calls = &calls });
    try std.testing.expectError(error.QueueFull, queue.push(alloc, .{ .value = 2, .deinit_calls = &calls }));
    try std.testing.expectEqual(@as(usize, 1), queue.pending());
}
