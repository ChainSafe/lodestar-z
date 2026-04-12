const std = @import("std");
const builtin = @import("builtin");

/// L1 cache line size. 128 covers x86-64 (64B) and Apple Silicon (128B).
pub const cache_line = 128;

/// Inline buffer threshold (SBO). Messages at or below this size are stored
/// inline in the ring slot with zero heap allocation. Larger messages spill
/// to the heap automatically via `fromSliceAlloc`.
pub const max_message_size = 4096;

/// Fixed-size byte buffer for sending formatted log messages through the ring.
///
/// Uses Small Buffer Optimization (SBO): messages ≤ max_message_size live in
/// an inline `data` array (zero-alloc fast path). Larger messages are heap-
/// allocated and the pointer is stored in the `storage` tag. The `data` array
/// is always present so the ring slot stays fixed-size.
pub const ByteMessage = struct {
    const Storage = union(enum) {
        /// Data lives in the `data` field (inline).
        inline_buf: void,
        /// Data lives on the heap.
        heap: struct {
            ptr: [*]u8,
            capacity: usize,
            allocator: std.mem.Allocator,
        },
    };

    len: usize = 0,
    data: [max_message_size]u8 = undefined,
    storage: Storage = .{ .inline_buf = {} },

    /// Zero-alloc path: copies up to max_message_size bytes inline.
    /// Truncates if `src.len > max_message_size`.
    pub fn fromSlice(src: []const u8) ByteMessage {
        var msg: ByteMessage = .{};
        const n = @min(src.len, max_message_size);
        @memcpy(msg.data[0..n], src[0..n]);
        msg.len = n;
        return msg;
    }

    /// Alloc-capable path: uses inline storage for small messages, heap for large.
    /// On allocation failure, gracefully degrades to truncated inline.
    pub fn fromSliceAlloc(allocator: std.mem.Allocator, src: []const u8) ByteMessage {
        if (src.len <= max_message_size) {
            return fromSlice(src);
        }
        const heap_buf = allocator.alloc(u8, src.len) catch {
            // OOM: degrade to truncated inline.
            return fromSlice(src);
        };
        @memcpy(heap_buf, src);
        return .{
            .len = src.len,
            .storage = .{ .heap = .{
                .ptr = heap_buf.ptr,
                .capacity = src.len,
                .allocator = allocator,
            } },
        };
    }

    pub fn bytes(self: *const ByteMessage) []const u8 {
        return switch (self.storage) {
            .inline_buf => self.data[0..self.len],
            .heap => |h| h.ptr[0..self.len],
        };
    }

    /// Returns true if this message uses heap-allocated storage.
    pub fn isHeap(self: *const ByteMessage) bool {
        return self.storage == .heap;
    }

    /// Free heap storage if present. No-op for inline messages.
    /// Must be called by the consumer before releasing the ring slot
    /// when the message may have been created via `fromSliceAlloc`.
    pub fn deinit(self: *ByteMessage) void {
        switch (self.storage) {
            .heap => |h| {
                h.allocator.free(h.ptr[0..h.capacity]);
                self.storage = .{ .inline_buf = {} };
                self.len = 0;
            },
            .inline_buf => {},
        }
    }
};

/// Condition-variable waiter with fast-path check.
/// Only signals when threads are actually parked, avoiding unnecessary syscalls.
const Waiter = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    parked: std.atomic.Value(u32) align(cache_line) = std.atomic.Value(u32).init(0),

    fn notifyOne(self: *Waiter) void {
        if (self.parked.load(.monotonic) != 0) {
            @branchHint(.cold);
            self.cond.signal();
        }
    }

    fn broadcast(self: *Waiter) void {
        if (self.parked.load(.monotonic) != 0) {
            @branchHint(.cold);
            self.cond.broadcast();
        }
    }
};

/// Bounded MPMC ring buffer for fixed-size items of type `T`.
///
/// Sequence-per-slot design (LMAX Disruptor / Vyukov style):
///   - Pre-allocated slots via allocator (zero allocation on hot path)
///   - Cache-line aligned cursors prevent false sharing
///   - Epoch-based condvar parking for low-latency wakeup
///   - Blocking send (default) and non-blocking push with drop-on-full
///   - Blocking recv and non-blocking tryPop
///   - Wrapping arithmetic for correctness over long uptimes
pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        /// A single slot in the ring buffer.
        /// Sequence field is cache-line aligned to prevent false sharing between
        /// adjacent slots.
        const Slot = struct {
            sequence: std.atomic.Value(usize) align(cache_line),
            data: T,
        };

        slots: []Slot,
        mask: usize,
        head: std.atomic.Value(usize) align(cache_line) = std.atomic.Value(usize).init(0),
        tail: std.atomic.Value(usize) align(cache_line) = std.atomic.Value(usize).init(0),
        epoch: std.atomic.Value(usize) align(cache_line) = std.atomic.Value(usize).init(0),
        closed: std.atomic.Value(bool) align(cache_line) = std.atomic.Value(bool).init(false),
        consumer_waiter: Waiter align(cache_line) = .{},
        producer_waiter: Waiter align(cache_line) = .{},
        allocator: std.mem.Allocator,

        // Debug-only counters for invariant checking. Zero cost in release builds.
        pushed: if (builtin.mode == .Debug) std.atomic.Value(usize) else void =
            if (builtin.mode == .Debug) std.atomic.Value(usize).init(0) else {},
        popped: if (builtin.mode == .Debug) std.atomic.Value(usize) else void =
            if (builtin.mode == .Debug) std.atomic.Value(usize).init(0) else {},

        /// Pre-allocate ring buffer with `size` slots. Size must be a power of two.
        pub fn init(allocator: std.mem.Allocator, size: u32) !Self {
            std.debug.assert(size > 0 and (size & (size - 1)) == 0);

            const slots = try allocator.alloc(Slot, size);
            for (slots, 0..) |*slot, i| {
                slot.sequence = std.atomic.Value(usize).init(i);
                slot.data = undefined;
            }

            return .{
                .slots = slots,
                .mask = size - 1,
                .allocator = allocator,
            };
        }

        /// Free the pre-allocated slot array.
        /// Poisons the struct in debug mode for use-after-free detection.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        /// Non-blocking push. Returns true if enqueued, false if full (dropped).
        pub fn push(self: *Self, item: T) bool {
            var head = self.head.load(.monotonic);
            while (true) {
                const slot = &self.slots[head & self.mask];
                const seq = slot.sequence.load(.acquire);

                if (seq == head) {
                    @branchHint(.likely);
                    if (self.head.cmpxchgWeak(head, head +% 1, .monotonic, .monotonic)) |updated| {
                        head = updated;
                        continue;
                    }
                    self.writeSlot(slot, head, item);
                    return true;
                }

                // Wrapping diff avoids @intCast trap on long-running systems.
                const diff = @as(isize, @bitCast(seq -% head));
                if (diff < 0) {
                    @branchHint(.cold);
                    return false; // Full — drop.
                }
                head = self.head.load(.monotonic);
            }
        }

        /// Blocking push. Waits until space is available or the ring is closed.
        /// Returns true if enqueued, false if closed.
        pub fn send(self: *Self, item: T) bool {
            while (true) {
                if (self.closed.load(.acquire)) return false;
                if (self.push(item)) return true;
                self.parkProducer();
            }
        }

        fn writeSlot(self: *Self, slot: *Slot, head: usize, item: T) void {
            slot.data = item;
            slot.sequence.store(head +% 1, .release);
            _ = self.epoch.fetchAdd(1, .release);
            if (builtin.mode == .Debug) _ = self.pushed.fetchAdd(1, .monotonic);
            self.consumer_waiter.notifyOne();
        }

        /// A borrowed reference to a consumed item.
        /// Caller MUST call `release()` after processing to recycle the slot.
        pub const Message = struct {
            ring: *Self,
            index: usize,
            tail: usize,

            /// The item payload (valid until `release()` is called).
            /// Returns mutable pointer — the consumer exclusively owns the
            /// slot between tryPop/recv and release, so mutation (e.g.
            /// calling deinit on ByteMessage) is safe.
            pub fn get(self: Message) *T {
                return &self.ring.slots[self.index].data;
            }

            /// Recycle the slot back to the ring buffer for reuse by producers.
            pub fn release(self: Message) void {
                self.ring.slots[self.index].sequence.store(
                    self.tail +% self.ring.mask +% 1,
                    .release,
                );
                self.ring.producer_waiter.notifyOne();
            }
        };

        /// Non-blocking pop. Returns a `Message` with borrowed data, or null if empty.
        /// Caller MUST call `Message.release()` after processing.
        pub fn tryPop(self: *Self) ?Message {
            const tail = self.tail.load(.monotonic);
            const slot = &self.slots[tail & self.mask];
            const seq = slot.sequence.load(.acquire);

            if (seq == tail +% 1) {
                @branchHint(.likely);
                if (self.tail.cmpxchgWeak(tail, tail +% 1, .monotonic, .monotonic)) |_| {
                    return null;
                }
                if (builtin.mode == .Debug) _ = self.popped.fetchAdd(1, .monotonic);
                return .{
                    .ring = self,
                    .index = tail & self.mask,
                    .tail = tail,
                };
            }
            return null;
        }

        /// Blocking pop. Waits until a message is available or the ring is closed.
        /// Returns null only when closed and fully drained.
        pub fn recv(self: *Self) ?Message {
            while (true) {
                if (self.tryPop()) |msg| return msg;
                if (self.closed.load(.acquire)) {
                    // Drain: one last check after seeing close flag.
                    return self.tryPop();
                }
                self.park();
            }
        }

        /// Check if there's a readable message without claiming it.
        pub fn peekReadable(self: *Self) bool {
            const tail = self.tail.load(.monotonic);
            const slot = &self.slots[tail & self.mask];
            const seq = slot.sequence.load(.acquire);
            return seq == tail +% 1;
        }

        /// Signal closure (no more pushes expected). Wakes all parked threads.
        pub fn close(self: *Self) void {
            self.closed.store(true, .release);
            _ = self.epoch.fetchAdd(1, .release);
            self.consumer_waiter.broadcast();
            self.producer_waiter.broadcast();
        }

        pub fn isClosed(self: *Self) bool {
            return self.closed.load(.acquire);
        }

        /// Epoch-based condvar park for consumers. Blocks until readable, closed, or epoch changes.
        pub fn park(self: *Self) void {
            const e0 = self.epoch.load(.acquire);

            self.consumer_waiter.mutex.lock();
            defer self.consumer_waiter.mutex.unlock();

            _ = self.consumer_waiter.parked.fetchAdd(1, .monotonic);
            defer _ = self.consumer_waiter.parked.fetchSub(1, .monotonic);

            while (true) {
                if (self.closed.load(.acquire)) {
                    @branchHint(.cold);
                    return;
                }
                if (self.peekReadable()) return;
                if (self.epoch.load(.acquire) != e0) return;
                self.consumer_waiter.cond.wait(&self.consumer_waiter.mutex);
            }
        }

        /// Park a producer until space is available or the ring is closed.
        fn parkProducer(self: *Self) void {
            self.producer_waiter.mutex.lock();
            defer self.producer_waiter.mutex.unlock();

            _ = self.producer_waiter.parked.fetchAdd(1, .monotonic);
            defer _ = self.producer_waiter.parked.fetchSub(1, .monotonic);

            while (true) {
                if (self.closed.load(.acquire)) return;
                if (!self.isFull()) return;
                self.producer_waiter.cond.wait(&self.producer_waiter.mutex);
            }
        }

        /// Check if the ring buffer is full.
        fn isFull(self: *Self) bool {
            const head = self.head.load(.monotonic);
            const tail = self.tail.load(.monotonic);
            return (head -% tail) >= (self.mask + 1);
        }

        /// Validate internal accounting. Debug-only; safe only when no threads are active.
        pub fn checkInvariants(self: *Self) void {
            if (builtin.mode != .Debug) return;
            const head = self.head.load(.acquire);
            const tail = self.tail.load(.acquire);
            std.debug.assert(head -% tail <= self.mask + 1);
            std.debug.assert(self.pushed.load(.acquire) == head);
            std.debug.assert(self.popped.load(.acquire) == tail);
        }
    };
}

// ==== Tests ====

const ByteRing = RingBuffer(ByteMessage);

test "RingBuffer push and pop" {
    var ring = try ByteRing.init(std.testing.allocator, 16);
    defer ring.deinit();

    try std.testing.expect(ring.push(ByteMessage.fromSlice("hello")));
    try std.testing.expect(ring.push(ByteMessage.fromSlice("world")));

    const msg1 = ring.tryPop().?;
    try std.testing.expectEqualStrings("hello", msg1.get().bytes());
    msg1.release();

    const msg2 = ring.tryPop().?;
    try std.testing.expectEqualStrings("world", msg2.get().bytes());
    msg2.release();

    try std.testing.expect(ring.tryPop() == null);
}

test "RingBuffer drops when full" {
    var ring = try ByteRing.init(std.testing.allocator, 4);
    defer ring.deinit();

    // Fill all 4 slots.
    try std.testing.expect(ring.push(ByteMessage.fromSlice("a")));
    try std.testing.expect(ring.push(ByteMessage.fromSlice("b")));
    try std.testing.expect(ring.push(ByteMessage.fromSlice("c")));
    try std.testing.expect(ring.push(ByteMessage.fromSlice("d")));

    // 5th push should fail — full.
    try std.testing.expect(!ring.push(ByteMessage.fromSlice("e")));

    // Pop one, then push succeeds again.
    const msg = ring.tryPop().?;
    msg.release();
    try std.testing.expect(ring.push(ByteMessage.fromSlice("f")));
}

test "RingBuffer truncates long messages" {
    var ring = try ByteRing.init(std.testing.allocator, 4);
    defer ring.deinit();

    var long_msg: [max_message_size + 100]u8 = undefined;
    @memset(&long_msg, 'X');

    try std.testing.expect(ring.push(ByteMessage.fromSlice(&long_msg)));

    const msg = ring.tryPop().?;
    try std.testing.expectEqual(@as(usize, max_message_size), msg.get().bytes().len);
    try std.testing.expectEqual(@as(u8, 'X'), msg.get().bytes()[0]);
    msg.release();
}

test "RingBuffer close wakes parked consumer" {
    var ring = try ByteRing.init(std.testing.allocator, 4);
    defer ring.deinit();

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(r: *ByteRing) void {
            r.park();
        }
    }.run, .{&ring});

    // Give the thread time to park.
    std.time.sleep(20_000_000); // 20ms

    ring.close();
    thread.join();

    try std.testing.expect(ring.isClosed());
}

test "RingBuffer FIFO ordering" {
    var ring = try ByteRing.init(std.testing.allocator, 8);
    defer ring.deinit();

    for (0..5) |i| {
        var buf: [16]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "msg{d}", .{i}) catch "?";
        try std.testing.expect(ring.push(ByteMessage.fromSlice(s)));
    }

    for (0..5) |i| {
        var expected_buf: [16]u8 = undefined;
        const expected = std.fmt.bufPrint(&expected_buf, "msg{d}", .{i}) catch "?";
        const msg = ring.tryPop().?;
        try std.testing.expectEqualStrings(expected, msg.get().bytes());
        msg.release();
    }
}

test "RingBuffer peekReadable" {
    var ring = try ByteRing.init(std.testing.allocator, 4);
    defer ring.deinit();

    try std.testing.expect(!ring.peekReadable());
    try std.testing.expect(ring.push(ByteMessage.fromSlice("data")));
    try std.testing.expect(ring.peekReadable());

    const msg = ring.tryPop().?;
    msg.release();
    try std.testing.expect(!ring.peekReadable());
}

// ==== Concurrent Stress Tests ====

test "RingBuffer SPSC concurrent" {
    var ring = try ByteRing.init(std.testing.allocator, 64);
    defer ring.deinit();

    const n: u32 = 1000;

    const producer = try std.Thread.spawn(.{}, struct {
        fn run(r: *ByteRing, count: u32) void {
            for (0..count) |i| {
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @as(u32, @intCast(i)), .little);
                while (!r.push(ByteMessage.fromSlice(&buf))) std.atomic.spinLoopHint();
            }
        }
    }.run, .{ &ring, n });

    var received = [_]bool{false} ** n;
    var count: u32 = 0;
    var prev: ?u32 = null;

    while (count < n) {
        if (ring.tryPop()) |msg| {
            const id = std.mem.readInt(u32, msg.get().bytes()[0..4], .little);
            msg.release();
            try std.testing.expect(id < n);
            try std.testing.expect(!received[id]);
            received[id] = true;
            // SPSC preserves FIFO ordering.
            if (prev) |p| try std.testing.expect(id == p + 1);
            prev = id;
            count += 1;
        }
    }

    producer.join();
    ring.checkInvariants();
    for (received) |v| try std.testing.expect(v);
}

test "RingBuffer MPSC concurrent" {
    var ring = try ByteRing.init(std.testing.allocator, 64);
    defer ring.deinit();

    const num_producers: u32 = 4;
    const items_per_producer: u32 = 500;
    const total: u32 = num_producers * items_per_producer;

    var producers: [num_producers]std.Thread = undefined;
    for (&producers, 0..) |*t, p| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(r: *ByteRing, pid: u32, ipp: u32) void {
                for (0..ipp) |i| {
                    var buf: [4]u8 = undefined;
                    std.mem.writeInt(u32, &buf, pid * ipp + @as(u32, @intCast(i)), .little);
                    while (!r.push(ByteMessage.fromSlice(&buf))) std.atomic.spinLoopHint();
                }
            }
        }.run, .{ &ring, @as(u32, @intCast(p)), items_per_producer });
    }

    const consumed = try std.testing.allocator.alloc(bool, total);
    defer std.testing.allocator.free(consumed);
    @memset(consumed, false);

    var count: u32 = 0;
    while (count < total) {
        if (ring.tryPop()) |msg| {
            const id = std.mem.readInt(u32, msg.get().bytes()[0..4], .little);
            msg.release();
            try std.testing.expect(id < total);
            try std.testing.expect(!consumed[id]);
            consumed[id] = true;
            count += 1;
        }
    }

    for (&producers) |*t| t.join();
    ring.checkInvariants();
    for (consumed) |v| try std.testing.expect(v);
}

test "RingBuffer MPMC concurrent" {
    var ring = try ByteRing.init(std.testing.allocator, 128);
    defer ring.deinit();

    const num_producers: usize = 4;
    const num_consumers: usize = 4;
    const items_per_producer: u32 = 1000;
    const total: usize = num_producers * items_per_producer;

    const flags = try std.testing.allocator.alloc(std.atomic.Value(bool), total);
    defer std.testing.allocator.free(flags);
    for (flags) |*f| f.* = std.atomic.Value(bool).init(false);

    var consumed_count = std.atomic.Value(usize).init(0);

    var producers: [num_producers]std.Thread = undefined;
    var consumers: [num_consumers]std.Thread = undefined;

    for (&producers, 0..) |*t, p| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(r: *ByteRing, pid: u32, ipp: u32) void {
                for (0..ipp) |i| {
                    var buf: [4]u8 = undefined;
                    std.mem.writeInt(u32, &buf, pid * ipp + @as(u32, @intCast(i)), .little);
                    while (!r.push(ByteMessage.fromSlice(&buf))) std.atomic.spinLoopHint();
                }
            }
        }.run, .{ &ring, @as(u32, @intCast(p)), items_per_producer });
    }

    for (&consumers) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(
                r: *ByteRing,
                f: []std.atomic.Value(bool),
                count: *std.atomic.Value(usize),
                total_items: usize,
            ) void {
                while (count.load(.monotonic) < total_items) {
                    if (r.tryPop()) |msg| {
                        const id: usize = std.mem.readInt(u32, msg.get().bytes()[0..4], .little);
                        msg.release();
                        std.debug.assert(id < f.len);
                        const was = f[id].swap(true, .acq_rel);
                        if (was) std.debug.panic("DUPLICATE: item {} consumed twice!", .{id});
                        _ = count.fetchAdd(1, .monotonic);
                    }
                }
            }
        }.run, .{ &ring, flags, &consumed_count, total });
    }

    for (&producers) |*t| t.join();
    ring.close();
    for (&consumers) |*t| t.join();

    ring.checkInvariants();
    for (flags, 0..) |f, i| {
        if (!f.load(.acquire)) std.debug.panic("MISSING: item {} never consumed!", .{i});
    }
    try std.testing.expectEqual(total, consumed_count.load(.acquire));
}

test "RingBuffer fuzz MPMC" {
    const base_seed: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    for (0..5) |i| {
        try fuzzMpmcRound(std.testing.allocator, base_seed +% i);
    }
}

fn fuzzMpmcRound(allocator: std.mem.Allocator, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    const ring_size: u32 = @as(u32, 1) << random.intRangeAtMost(u5, 4, 8);
    const num_producers: usize = random.intRangeAtMost(usize, 1, 6);
    const num_consumers: usize = random.intRangeAtMost(usize, 1, 6);
    const items_per_producer: u32 = random.intRangeAtMost(u32, 100, 2000);
    const total: usize = num_producers * @as(usize, items_per_producer);

    var ring = try ByteRing.init(allocator, ring_size);
    defer ring.deinit();

    const flags = try allocator.alloc(std.atomic.Value(bool), total);
    defer allocator.free(flags);
    for (flags) |*f| f.* = std.atomic.Value(bool).init(false);

    var consumed_count = std.atomic.Value(usize).init(0);
    var error_flag = std.atomic.Value(bool).init(false);

    const producers = try allocator.alloc(std.Thread, num_producers);
    defer allocator.free(producers);
    const consumers = try allocator.alloc(std.Thread, num_consumers);
    defer allocator.free(consumers);

    for (producers, 0..) |*t, p| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(r: *ByteRing, pid: u32, ipp: u32) void {
                for (0..ipp) |i| {
                    var buf: [4]u8 = undefined;
                    std.mem.writeInt(u32, &buf, pid * ipp + @as(u32, @intCast(i)), .little);
                    while (!r.push(ByteMessage.fromSlice(&buf))) std.atomic.spinLoopHint();
                }
            }
        }.run, .{ &ring, @as(u32, @intCast(p)), items_per_producer });
    }

    for (consumers) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(
                r: *ByteRing,
                f: []std.atomic.Value(bool),
                count: *std.atomic.Value(usize),
                total_items: usize,
                err: *std.atomic.Value(bool),
            ) void {
                while (count.load(.monotonic) < total_items and !err.load(.monotonic)) {
                    if (r.tryPop()) |msg| {
                        const id: usize = std.mem.readInt(u32, msg.get().bytes()[0..4], .little);
                        msg.release();
                        if (id >= f.len) {
                            err.store(true, .release);
                            return;
                        }
                        if (f[id].swap(true, .acq_rel)) {
                            err.store(true, .release);
                            return;
                        }
                        _ = count.fetchAdd(1, .monotonic);
                    }
                }
            }
        }.run, .{ &ring, flags, &consumed_count, total, &error_flag });
    }

    for (producers) |p| p.join();
    ring.close();
    for (consumers) |c| c.join();

    if (error_flag.load(.acquire)) return error.FuzzError;
    for (flags) |f| {
        if (!f.load(.acquire)) return error.FuzzError;
    }
    if (consumed_count.load(.acquire) != total) return error.FuzzError;
}

test "RingBuffer with simple u32 type" {
    const U32Ring = RingBuffer(u32);
    var ring = try U32Ring.init(std.testing.allocator, 8);
    defer ring.deinit();

    try std.testing.expect(ring.push(@as(u32, 42)));
    try std.testing.expect(ring.push(@as(u32, 99)));

    const msg1 = ring.tryPop().?;
    try std.testing.expectEqual(@as(u32, 42), msg1.get().*);
    msg1.release();

    const msg2 = ring.tryPop().?;
    try std.testing.expectEqual(@as(u32, 99), msg2.get().*);
    msg2.release();
}

// ==== ByteMessage SBO Tests ====

test "ByteMessage fromSlice inline path" {
    const msg = ByteMessage.fromSlice("hello");
    try std.testing.expectEqualStrings("hello", msg.bytes());
    try std.testing.expect(!msg.isHeap());
}

test "ByteMessage fromSliceAlloc small message stays inline" {
    var msg = ByteMessage.fromSliceAlloc(std.testing.allocator, "small");
    defer msg.deinit(); // no-op for inline
    try std.testing.expectEqualStrings("small", msg.bytes());
    try std.testing.expect(!msg.isHeap());
}

test "ByteMessage fromSliceAlloc large message goes to heap" {
    const size = max_message_size + 500;
    const src = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(src);
    @memset(src, 'Z');

    var msg = ByteMessage.fromSliceAlloc(std.testing.allocator, src);
    defer msg.deinit();

    try std.testing.expect(msg.isHeap());
    try std.testing.expectEqual(size, msg.bytes().len);
    try std.testing.expectEqual(@as(u8, 'Z'), msg.bytes()[0]);
    try std.testing.expectEqual(@as(u8, 'Z'), msg.bytes()[size - 1]);
}

test "ByteMessage deinit is no-op for inline" {
    var msg = ByteMessage.fromSlice("inline");
    const len_before = msg.len;
    msg.deinit(); // should not crash, no state change
    try std.testing.expectEqual(len_before, msg.len);
    try std.testing.expect(!msg.isHeap());
}

test "ByteMessage deinit frees heap and resets to inline" {
    const size = max_message_size + 100;
    const src = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(src);
    @memset(src, 'A');

    var msg = ByteMessage.fromSliceAlloc(std.testing.allocator, src);
    try std.testing.expect(msg.isHeap());
    msg.deinit();
    try std.testing.expect(!msg.isHeap());
    try std.testing.expectEqual(@as(usize, 0), msg.len);
}

test "ByteMessage SBO through ring buffer round-trip" {
    var ring = try ByteRing.init(std.testing.allocator, 4);
    defer ring.deinit();

    // Large message via fromSliceAlloc → push → pop → deinit.
    const size = max_message_size + 200;
    const src = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(src);
    for (src, 0..) |*b, i| b.* = @as(u8, @truncate(i));

    // Push copies by value — heap pointer transfers into the slot.
    try std.testing.expect(ring.push(ByteMessage.fromSliceAlloc(std.testing.allocator, src)));

    const msg = ring.tryPop().?;
    try std.testing.expect(msg.get().isHeap());
    try std.testing.expectEqual(size, msg.get().bytes().len);
    // Verify content integrity.
    for (msg.get().bytes(), 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @truncate(i)), b);
    }
    // Consumer cleans up heap before releasing slot.
    msg.get().deinit();
    msg.release();
}
