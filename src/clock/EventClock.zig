//! Layer 2 – Event-driven beacon clock.
//!
//! Combines `SlotClock` with an async I/O loop to emit slot/epoch events
//! and dispatch waiters.  All public methods are safe to call from the
//! main thread; the internal loop runs as a single cooperative fiber.
//!
//! Designed for a cooperative single-fiber `std.Io` backend (e.g. zio).
//! `start()` and `waitForSlot()` use `std.Io.concurrent` so a backend
//! that can't guarantee concurrent execution surfaces as
//! `error.ConcurrencyUnavailable` rather than deadlocking.
//!
//! No mutex is used: under a single-fiber backend the only context switches
//! are at `await`/`sleep` yield points, and every read-modify of shared state
//! (listeners, waiter queue, `stopped`) completes synchronously between yields.
//! Two invariants make this safe:
//!   1. Listener callbacks must NOT yield (no `await`/`sleep`); they run to
//!      completion inside an emit so the listener/waiter state can't be mutated
//!      mid-emit. The snapshot copy further decouples iteration from `offSlot`.
//!   2. `cancel()` removes its waiter from the queue *before* it yields, so a
//!      concurrent `dispatchWaiters` can no longer observe it.
//! A multi-executor backend (zio with `executors > 1`, or `std.Io.Threaded`)
//! would break both and require real locking.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bounded_array = @import("bounded_array");
const slot_math = @import("slot_math.zig");
const SlotClock = @import("SlotClock.zig");
const time_source = @import("time_source.zig");

const EventClock = @This();

allocator: Allocator,
io: std.Io,
clock: SlotClock,

stopped: bool = false,
loop_future: ?std.Io.Future(void) = null,

next_listener_id: ListenerId = 1,
slot_listeners: bounded_array.BoundedArray(SlotListenerEntry, max_slot_listeners) = .{},
epoch_listeners: bounded_array.BoundedArray(EpochListenerEntry, max_epoch_listeners) = .{},
slot_snapshot: bounded_array.BoundedArray(SlotSnapshot, max_slot_listeners) = .{},
epoch_snapshot: bounded_array.BoundedArray(EpochSnapshot, max_epoch_listeners) = .{},

waiters: WaiterQueue,

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const ClockConfig = slot_math.ClockConfig;
pub const ListenerId = u64;
pub const TimeSource = time_source.TimeSource;

pub const max_slot_listeners: u32 = 16;
pub const max_epoch_listeners: u32 = 16;
pub const max_waiters: u32 = 1024;

pub const Error = error{
    InvalidConfig,
    OutOfMemory,
    ListenerLimitReached,
    WaiterLimitReached,
    Aborted,
    ConcurrencyUnavailable,
};

const WaitState = struct {
    io: std.Io,
    allocator: Allocator,
    event: std.Io.Event = .unset,
    aborted: bool = false,
};

const WaiterEntry = struct {
    target: Slot,
    state: *WaitState,
};

const SlotListenerEntry = struct {
    id: ListenerId,
    callback: *const fn (ctx: ?*anyopaque, slot: Slot) void,
    ctx: ?*anyopaque,
};

const EpochListenerEntry = struct {
    id: ListenerId,
    callback: *const fn (ctx: ?*anyopaque, epoch: Epoch) void,
    ctx: ?*anyopaque,
};

const SlotSnapshot = struct {
    callback: *const fn (ctx: ?*anyopaque, slot: Slot) void,
    ctx: ?*anyopaque,
};

const EpochSnapshot = struct {
    callback: *const fn (ctx: ?*anyopaque, epoch: Epoch) void,
    ctx: ?*anyopaque,
};

const WaiterQueue = std.PriorityQueue(WaiterEntry, void, struct {
    fn compare(_: void, a: WaiterEntry, b: WaiterEntry) std.math.Order {
        return std.math.order(a.target, b.target);
    }
}.compare);

pub fn init(self: *EventClock, allocator: Allocator, config: ClockConfig, io_handle: std.Io) Error!void {
    self.* = .{
        .allocator = allocator,
        .io = io_handle,
        .clock = undefined,
        .waiters = WaiterQueue.initContext({}),
    };
    self.clock = try SlotClock.init(config, .{ .real = .{ .io = io_handle } });
}

/// Start the auto-advance loop.  Idempotent; second call is a no-op.
pub fn start(self: *EventClock) Error!void {
    if (self.loop_future != null) return;
    self.loop_future = std.Io.concurrent(self.io, EventClock.runAutoLoop, .{self}) catch
        return error.ConcurrencyUnavailable;
}

/// Signal the loop to stop and abort all pending waiters.  Idempotent.
pub fn stop(self: *EventClock) void {
    if (self.stopped) return;
    self.stopped = true;
    self.abortAllWaiters();
}

/// Signal the loop to stop, cancel the fiber, and wait for it to finish.
pub fn join(self: *EventClock) void {
    self.stop();
    var maybe_future = self.loop_future;
    self.loop_future = null;
    if (maybe_future) |*future| {
        future.cancel(self.io);
        future.await(self.io);
    }
}

/// Release all resources.  Calls `stop()` + `join()` internally.
pub fn deinit(self: *EventClock) void {
    self.stop();
    self.join();
    self.waiters.deinit(self.allocator);
    self.* = undefined;
}

// Inside a callback, `offSlot` / `offEpoch` are safe; `onSlot` / `onEpoch`
// are not — they may overwrite the snapshot iterated by the active emit.

/// Register a slot listener.  Returns an ID for later removal via `offSlot`.
pub fn onSlot(
    self: *EventClock,
    callback: *const fn (ctx: ?*anyopaque, slot: Slot) void,
    ctx: ?*anyopaque,
) Error!ListenerId {
    if (self.slot_listeners.full()) return error.ListenerLimitReached;
    self.slot_listeners.push(.{
        .id = self.next_listener_id,
        .callback = callback,
        .ctx = ctx,
    });
    const id = self.next_listener_id;
    self.next_listener_id += 1;
    return id;
}

/// Unregister a slot listener.  Returns `true` if found and removed.
pub fn offSlot(self: *EventClock, id: ListenerId) bool {
    for (self.slot_listeners.slice(), 0..) |listener, i| {
        if (listener.id == id) {
            self.slot_listeners.orderedRemove(@intCast(i));
            return true;
        }
    }
    return false;
}

/// Register an epoch listener.  Returns an ID for later removal via `offEpoch`.
pub fn onEpoch(
    self: *EventClock,
    callback: *const fn (ctx: ?*anyopaque, epoch: Epoch) void,
    ctx: ?*anyopaque,
) Error!ListenerId {
    if (self.epoch_listeners.full()) return error.ListenerLimitReached;
    self.epoch_listeners.push(.{
        .id = self.next_listener_id,
        .callback = callback,
        .ctx = ctx,
    });
    const id = self.next_listener_id;
    self.next_listener_id += 1;
    return id;
}

/// Unregister an epoch listener.  Returns `true` if found and removed.
pub fn offEpoch(self: *EventClock, id: ListenerId) bool {
    for (self.epoch_listeners.slice(), 0..) |listener, i| {
        if (listener.id == id) {
            self.epoch_listeners.orderedRemove(@intCast(i));
            return true;
        }
    }
    return false;
}

// Accessors that expose "current" slot/epoch state call catchUp() first so
// reads emit any pending events before returning.  Pure time-arithmetic
// helpers (slotWithFutureToleranceMs, secFromSlot, …) do not.

pub fn currentSlot(self: *EventClock) ?Slot {
    self.catchUp();
    return self.clock.currentSlot();
}

pub fn currentEpoch(self: *EventClock) ?Epoch {
    self.catchUp();
    return self.clock.currentEpoch();
}

pub fn currentSlotOrGenesis(self: *EventClock) Slot {
    self.catchUp();
    return self.clock.currentSlotOrGenesis();
}

pub fn currentEpochOrGenesis(self: *EventClock) Epoch {
    self.catchUp();
    return self.clock.currentEpochOrGenesis();
}

pub fn currentSlotWithGossipDisparity(self: *EventClock) Slot {
    self.catchUp();
    return self.clock.currentSlotWithGossipDisparity();
}

pub fn isCurrentSlotGivenGossipDisparity(self: *EventClock, slot: Slot) bool {
    self.catchUp();
    return self.clock.isCurrentSlotGivenGossipDisparity(slot);
}

pub fn slotWithFutureToleranceMs(self: *EventClock, tolerance_ms: u64) ?Slot {
    return self.clock.slotWithFutureToleranceMs(tolerance_ms);
}

pub fn slotWithPastToleranceMs(self: *EventClock, tolerance_ms: u64) ?Slot {
    return self.clock.slotWithPastToleranceMs(tolerance_ms);
}

pub fn secFromSlot(self: *EventClock, slot: Slot, to_sec: ?u64) ?i64 {
    return self.clock.secFromSlot(slot, to_sec);
}

pub fn msFromSlot(self: *EventClock, slot: Slot, to_ms: ?u64) ?i64 {
    return self.clock.msFromSlot(slot, to_ms);
}

/// Return type from `waitForSlot`. The caller MUST either:
///   - call `await()` to wait for the target slot and release resources, OR
///   - call `cancel()` to abort and release resources, OR
///   - call `stop()` on the EventClock and THEN `await()` to get `error.Aborted`.
/// Dropping a WaitForSlotResult without calling `await` or `cancel` leaks
/// the internal WaitState.
///
/// Idiomatic usage with `errdefer`:
///   var fut = try ec.waitForSlot(target);
///   errdefer fut.cancel();
///   try fut.await(io);
pub const WaitForSlotResult = struct {
    inner: std.Io.Future(Error!void),
    state: ?*WaitState,
    clock: ?*EventClock,

    /// Create an immediately-resolved result (no async work needed).
    /// Relies on `std.Io.Future.await` returning `.result` when `.any_future == null`.
    fn immediate(result: Error!void) WaitForSlotResult {
        return .{ .inner = .{ .any_future = null, .result = result }, .state = null, .clock = null };
    }

    pub fn await(self: *WaitForSlotResult, io: std.Io) Error!void {
        const result = self.inner.await(io);
        // Free state only AFTER the fiber returns, so it can't observe a
        // freed `state.aborted` between event-wake and its own return.
        if (self.state) |s| s.allocator.destroy(s);
        self.state = null;
        self.clock = null;
        return result;
    }

    /// Abort a pending wait and release its resources.  Idempotent — safe
    /// to call on an already-awaited, already-cancelled, or immediate result.
    pub fn cancel(self: *WaitForSlotResult) void {
        const state = self.state orelse return;
        // Remove from waiter queue before freeing, so abortAllWaiters
        // won't dereference the freed state pointer.
        if (self.clock) |clock| {
            for (clock.waiters.items, 0..) |entry, i| {
                if (entry.state == state) {
                    _ = clock.waiters.popIndex(i);
                    break;
                }
            }
        }
        state.aborted = true;
        state.event.set(state.io);
        // Must await the fiber so it finishes before we free its state.
        // The fiber returns error.Aborted (expected) or {} (already dispatched).
        _ = self.inner.await(state.io) catch |err| {
            std.debug.assert(err == error.Aborted);
        };
        state.allocator.destroy(state);
        self.state = null;
        self.clock = null;
    }
};

/// Return a future that resolves when the clock reaches `target`.
/// See `WaitForSlotResult` for the caller's obligations.
pub fn waitForSlot(self: *EventClock, target: Slot) Error!WaitForSlotResult {
    if (self.stopped) {
        return WaitForSlotResult.immediate(error.Aborted);
    }
    self.catchUp();
    if (self.clock.current_slot) |slot| {
        if (slot >= target) {
            return WaitForSlotResult.immediate({});
        }
    }
    if (self.waiters.count() >= max_waiters) {
        return error.WaiterLimitReached;
    }

    const state = self.allocator.create(WaitState) catch return error.OutOfMemory;
    errdefer self.allocator.destroy(state);

    state.* = .{
        .io = self.io,
        .allocator = self.allocator,
    };

    if (self.stopped) {
        self.allocator.destroy(state);
        return WaitForSlotResult.immediate(error.Aborted);
    }
    self.waiters.push(self.allocator, .{ .target = target, .state = state }) catch return error.OutOfMemory;
    self.dispatchWaiters(self.clock.current_slot);

    const inner = std.Io.concurrent(self.io, waitForSlotFutureAwait, .{state}) catch {
        for (self.waiters.items, 0..) |entry, i| {
            if (entry.state == state) {
                _ = self.waiters.popIndex(i);
                break;
            }
        }
        return error.ConcurrencyUnavailable;
    };

    return .{
        .inner = inner,
        .state = state,
        .clock = self,
    };
}

/// Ensure event-clock state is caught up to wall-clock time.
/// Emits any intermediate slot/epoch events to listeners.
/// No-op if already caught up or pre-genesis (currentSlot() returns null).
fn catchUp(self: *EventClock) void {
    if (self.clock.currentSlot()) |wall_slot| {
        self.advanceAndDispatch(wall_slot);
    }
}

fn emitSlot(self: *EventClock, slot: Slot) void {
    self.slot_snapshot.clear();
    for (self.slot_listeners.slice()) |listener| {
        self.slot_snapshot.push(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }
    for (self.slot_snapshot.slice()) |listener| {
        listener.callback(listener.ctx, slot);
    }
}

fn emitEpoch(self: *EventClock, epoch: Epoch) void {
    self.epoch_snapshot.clear();
    for (self.epoch_listeners.slice()) |listener| {
        self.epoch_snapshot.push(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }
    for (self.epoch_snapshot.slice()) |listener| {
        listener.callback(listener.ctx, epoch);
    }
}

fn dispatchWaiters(self: *EventClock, current_slot: ?Slot) void {
    const slot = current_slot orelse return;
    while (self.waiters.peek()) |head| {
        if (head.target > slot) break;
        const waiter = self.waiters.pop().?;
        waiter.state.aborted = false;
        waiter.state.event.set(waiter.state.io);
    }
}

fn abortAllWaiters(self: *EventClock) void {
    while (self.waiters.pop()) |waiter| {
        waiter.state.aborted = true;
        waiter.state.event.set(waiter.state.io);
    }
}

fn advanceAndDispatch(self: *EventClock, target: Slot) void {
    var iter = self.clock.advanceTo(target);
    // Check `stopped` *before* iter.next() so a callback that calls stop()
    // can't leave current_slot one ahead of the last-emitted slot.
    while (true) {
        if (self.stopped) break;
        const event = iter.next() orelse break;
        switch (event) {
            .slot => |s| {
                self.emitSlot(s);
                self.dispatchWaiters(s);
            },
            .epoch => |e| self.emitEpoch(e),
        }
    }
    // Defensive: handles edge cases where advanceTo yields zero events
    // (already at target) but waiters were added between loop ticks.
    // In the normal case, this is a no-op because the last .slot event
    // already dispatched waiters at the same slot value.
    self.dispatchWaiters(self.clock.current_slot);
}

fn runAutoLoop(self: *EventClock) void {
    while (!self.stopped) {
        const now_ms = self.clock.time.nowMs();
        // Config validation guarantees sec→ms won't overflow, so null here
        // indicates a logic bug.  Break instead of spinning at 1ms.
        const next_ms = slot_math.msUntilNextSlot(self.clock.config, now_ms) orelse {
            std.log.err("EventClock: msUntilNextSlot returned null (config overflow?), stopping loop", .{});
            self.stop();
            break;
        };
        const sleep_ms = std.math.cast(i64, @max(@as(u64, 1), next_ms)) orelse std.math.maxInt(i64);

        // Sleep failure: cancellation (from join()) exits the loop;
        // other errors re-check the stopped flag.
        std.Io.sleep(
            self.io,
            std.Io.Duration.fromMilliseconds(sleep_ms),
            .awake,
        ) catch |err| {
            if (err == error.Canceled) break;
            std.log.debug("EventClock: sleep failed ({s}), retrying", .{@errorName(err)});
            continue;
        };

        if (self.stopped) break;
        // Only advance after genesis.  Before genesis currentSlot() returns
        // null — skipping here prevents emitting slot 0 prematurely.
        if (self.clock.currentSlot()) |slot| {
            self.advanceAndDispatch(slot);
        }
    }
    // Non-terminating event loop: exits only when `self.stopped` is set.
    //  - normal stop(): sets flag, next iteration's `!self.stopped` exits
    //  - overflow path: in-body break after self.stop()
    //  - join(): always calls stop() before cancelling the fiber, so the
    //    `error.Canceled` break also satisfies stopped == true
    std.debug.assert(self.stopped);
}

fn waitForSlotFutureAwait(state: *WaitState) Error!void {
    // Do NOT free state here — `state.aborted` is read after the wake,
    // and the caller (`WaitForSlotResult.await`) frees only once this fiber
    // has fully returned.
    state.event.waitUncancelable(state.io);
    if (state.aborted) return error.Aborted;
}

const testing = std.testing;
const zio = @import("zio");

fn runInRuntime(comptime body: anytype) !void {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();

    var handle = try rt.spawn(body, .{rt.io()});
    try handle.join();
}

fn nowSecAt(io_handle: std.Io) u64 {
    const sec = std.Io.Clock.real.now(io_handle).toSeconds();
    std.debug.assert(sec >= 0);
    return @intCast(sec);
}

fn nowMsAt(io_handle: std.Io) u64 {
    const ms = std.Io.Clock.real.now(io_handle).toMilliseconds();
    std.debug.assert(ms >= 0);
    return @intCast(ms);
}

const EventTraceState = struct {
    slots: [64]Slot = undefined,
    slot_len: usize = 0,
    epochs: [64]u64 = undefined,
    epoch_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *EventTraceState = @ptrCast(@alignCast(ctx.?));
        if (self.slot_len >= self.slots.len) return;
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
    }

    fn onEpoch(ctx: ?*anyopaque, epoch: u64) void {
        const self: *EventTraceState = @ptrCast(@alignCast(ctx.?));
        if (self.epoch_len >= self.epochs.len) return;
        self.epochs[self.epoch_len] = epoch;
        self.epoch_len += 1;
    }
};

test "lifecycle: init -> register -> start -> receive events -> stop" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            const base_now = nowSecAt(io_handle);

            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = base_now,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);

            try clock.start();

            const start_slot = clock.currentSlotOrGenesis();
            var fut = try clock.waitForSlot(start_slot + 1);
            errdefer fut.cancel();
            try fut.await(io_handle);

            try testing.expect(trace.slot_len > 0);
        }
    }.run);
}

test "waitForSlot resolves immediately when at target" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            const base_now = nowSecAt(io_handle);

            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = base_now,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            const current = clock.currentSlotOrGenesis();
            var fut = try clock.waitForSlot(current);
            errdefer fut.cancel();
            try fut.await(io_handle);
        }
    }.run);
}

test "waitForSlot returns aborted on stop" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 2,
                .slot_duration_ms = 2_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var fut = try clock.waitForSlot(100);
            errdefer fut.cancel();
            clock.stop();
            try testing.expectError(error.Aborted, fut.await(io_handle));
        }
    }.run);
}

test "offSlot/offEpoch stop event delivery" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 2,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            const slot_id = try clock.onSlot(EventTraceState.onSlot, &trace);
            const epoch_id = try clock.onEpoch(EventTraceState.onEpoch, &trace);
            try testing.expect(clock.offSlot(slot_id));
            try testing.expect(clock.offEpoch(epoch_id));

            clock.advanceAndDispatch(6);
            try testing.expectEqual(@as(usize, 0), trace.slot_len);
            try testing.expectEqual(@as(usize, 0), trace.epoch_len);
        }
    }.run);
}

test "stop/join are idempotent" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 2,
                .slot_duration_ms = 2_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            clock.stop();
            clock.stop();
            clock.join();
            clock.join();
        }
    }.run);
}

test "epoch event is delivered when crossing epoch boundary" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 2,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);
            _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

            clock.advanceAndDispatch(5);

            try testing.expect(trace.slot_len > 0);
            try testing.expect(trace.epoch_len > 0);
            try testing.expectEqual(@as(u64, 1), trace.epochs[0]);
        }
    }.run);
}

test "multiple waiters are dispatched in target-slot order" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 10,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var fut5 = try clock.waitForSlot(5);
            errdefer fut5.cancel();

            var fut3 = try clock.waitForSlot(3);
            errdefer fut3.cancel();

            var fut1 = try clock.waitForSlot(1);
            errdefer fut1.cancel();

            clock.advanceAndDispatch(3);

            try fut1.await(io_handle);
            try fut3.await(io_handle);

            clock.stop();
            try testing.expectError(error.Aborted, fut5.await(io_handle));
        }
    }.run);
}

test "cancel releases WaitState without awaiting" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 10,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            // testing.allocator detects a leak if cancel fails to free.
            var fut = try clock.waitForSlot(999);
            fut.cancel();
        }
    }.run);
}

test "real-time: no slot events emitted before genesis" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 5,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);

            try clock.start();

            std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(1500), .awake) catch {};

            try testing.expectEqual(@as(usize, 0), trace.slot_len);
        }
    }.run);
}

test "real-time: slot events fire with correct timing" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            const base_now = nowSecAt(io_handle);

            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = base_now,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);

            try clock.start();

            const start_slot = clock.currentSlotOrGenesis();
            const before_ms = nowMsAt(io_handle);
            var fut = try clock.waitForSlot(start_slot + 1);
            errdefer fut.cancel();
            try fut.await(io_handle);
            const elapsed = nowMsAt(io_handle) - before_ms;

            try testing.expect(elapsed < 2000);
            try testing.expect(trace.slot_len > 0);
            try testing.expect(trace.slots[trace.slot_len - 1] >= start_slot + 1);
        }
    }.run);
}

test "real-time: multi-slot advancement delivers ordered events" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            const base_now = nowSecAt(io_handle);

            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = base_now,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 8,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);

            try clock.start();

            const start_slot = clock.currentSlotOrGenesis();
            var fut = try clock.waitForSlot(start_slot + 2);
            errdefer fut.cancel();
            try fut.await(io_handle);

            try testing.expect(trace.slot_len >= 2);
            for (1..trace.slot_len) |i| {
                try testing.expect(trace.slots[i] > trace.slots[i - 1]);
            }
        }
    }.run);
}

test "real-time: stop+join cancels promptly" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 100,
                .slot_duration_ms = 12_000,
                .slots_per_epoch = 32,
            }, io_handle);
            defer clock.deinit();

            try clock.start();

            // Give the loop fiber time to enter its sleep.
            std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(50), .awake) catch {};

            const before_ms = nowMsAt(io_handle);
            clock.stop();
            clock.join();
            const elapsed = nowMsAt(io_handle) - before_ms;

            // join() cancels the sleeping future directly — should return
            // almost immediately, NOT after the full 12-second slot.
            try testing.expect(elapsed < 1500);
        }
    }.run);
}

test "real-time: epoch boundary event fires" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            const base_now = nowSecAt(io_handle);

            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = base_now,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 2,
            }, io_handle);
            defer clock.deinit();

            var trace = EventTraceState{};
            _ = try clock.onSlot(EventTraceState.onSlot, &trace);
            _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

            try clock.start();

            const start_slot = clock.currentSlotOrGenesis();
            var fut = try clock.waitForSlot(start_slot + 3);
            errdefer fut.cancel();
            try fut.await(io_handle);

            try testing.expect(trace.slot_len >= 3);
            try testing.expect(trace.epoch_len > 0);
        }
    }.run);
}

fn nopSlot(_: ?*anyopaque, _: Slot) void {}
fn nopEpoch(_: ?*anyopaque, _: Epoch) void {}

const ReentrancyCtx = struct {
    clock: *EventClock,
    self_id: ?ListenerId = null,
    fired_count: usize = 0,

    fn offSelf(ctx: ?*anyopaque, _: Slot) void {
        const self: *ReentrancyCtx = @ptrCast(@alignCast(ctx.?));
        self.fired_count += 1;
        if (self.self_id) |id| {
            _ = self.clock.offSlot(id);
            self.self_id = null;
        }
    }

    fn stopClock(ctx: ?*anyopaque, _: Slot) void {
        const self: *ReentrancyCtx = @ptrCast(@alignCast(ctx.?));
        self.fired_count += 1;
        self.clock.stop();
    }

    fn justCount(ctx: ?*anyopaque, _: Slot) void {
        const self: *ReentrancyCtx = @ptrCast(@alignCast(ctx.?));
        self.fired_count += 1;
    }
};

test "reentrancy: callback can offSlot itself mid-dispatch" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 1_000_000,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            var ctx_a = ReentrancyCtx{ .clock = &clock };
            var ctx_b = ReentrancyCtx{ .clock = &clock };
            const id_a = try clock.onSlot(ReentrancyCtx.offSelf, &ctx_a);
            ctx_a.self_id = id_a;
            _ = try clock.onSlot(ReentrancyCtx.justCount, &ctx_b);

            clock.advanceAndDispatch(0);
            clock.advanceAndDispatch(2);

            try testing.expectEqual(@as(usize, 1), ctx_a.fired_count);
            try testing.expectEqual(@as(usize, 3), ctx_b.fired_count);
        }
    }.run);
}

test "reentrancy: callback can stop the clock; no further slots emitted" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 1_000_000,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            var ctx = ReentrancyCtx{ .clock = &clock };
            _ = try clock.onSlot(ReentrancyCtx.stopClock, &ctx);

            clock.advanceAndDispatch(5);

            try testing.expectEqual(@as(usize, 1), ctx.fired_count);
            try testing.expect(clock.stopped);
            try testing.expectEqual(@as(?Slot, 0), clock.clock.current_slot);
        }
    }.run);
}

test "ListenerLimitReached: onSlot/onEpoch reject the (limit+1)th registration" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 1_000_000,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            for (0..max_slot_listeners) |_| {
                _ = try clock.onSlot(nopSlot, null);
            }
            try testing.expectError(error.ListenerLimitReached, clock.onSlot(nopSlot, null));

            for (0..max_epoch_listeners) |_| {
                _ = try clock.onEpoch(nopEpoch, null);
            }
            try testing.expectError(error.ListenerLimitReached, clock.onEpoch(nopEpoch, null));
        }
    }.run);
}

test "WaiterLimitReached: waitForSlot rejects the (limit+1)th waiter" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 1_000_000,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            var futs: [max_waiters]WaitForSlotResult = undefined;
            for (&futs) |*f| f.* = try clock.waitForSlot(999_999);
            try testing.expectError(error.WaiterLimitReached, clock.waitForSlot(999_999));
            for (&futs) |*f| f.cancel();
        }
    }.run);
}

test "many waiters at same target slot all resolve on advance" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var clock: EventClock = undefined;
            try clock.init(testing.allocator, .{
                .genesis_time_sec = nowSecAt(io_handle) + 1_000_000,
                .slot_duration_ms = 1_000,
                .slots_per_epoch = 4,
            }, io_handle);
            defer clock.deinit();

            const N = 16;
            var futs: [N]WaitForSlotResult = undefined;
            for (&futs) |*f| f.* = try clock.waitForSlot(5);

            clock.advanceAndDispatch(5);

            for (&futs) |*f| try f.await(io_handle);
        }
    }.run);
}

const PropertyTracker = struct {
    slot_events: std.ArrayListUnmanaged(Slot) = .empty,
    epoch_events: std.ArrayListUnmanaged(Epoch) = .empty,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *PropertyTracker = @ptrCast(@alignCast(ctx.?));
        self.slot_events.append(testing.allocator, slot) catch unreachable;
    }

    fn onEpoch(ctx: ?*anyopaque, epoch: Epoch) void {
        const self: *PropertyTracker = @ptrCast(@alignCast(ctx.?));
        self.epoch_events.append(testing.allocator, epoch) catch unreachable;
    }

    fn deinit(self: *PropertyTracker) void {
        self.slot_events.deinit(testing.allocator);
        self.epoch_events.deinit(testing.allocator);
    }
};

const PropertyOp = union(enum) {
    on_slot,
    on_epoch,
    off_slot: usize,
    off_epoch: usize,
    advance_by: u8,
    wait_for_slot_at_offset: i32,
    cancel_waiter: usize,
    stop,
};

const PropertyWaiter = struct {
    target: Slot,
    fut: WaitForSlotResult,
    expected_aborted: bool,
};

const PropertyState = struct {
    spe: u64,
    model_current_slot: ?Slot = null,
    model_stopped: bool = false,
    clock: *EventClock,

    slot_listener_ids: std.ArrayListUnmanaged(ListenerId) = .empty,
    slot_trackers: std.ArrayListUnmanaged(*PropertyTracker) = .empty,
    slot_expected: std.ArrayListUnmanaged(std.ArrayListUnmanaged(Slot)) = .empty,

    epoch_listener_ids: std.ArrayListUnmanaged(ListenerId) = .empty,
    epoch_trackers: std.ArrayListUnmanaged(*PropertyTracker) = .empty,
    epoch_expected: std.ArrayListUnmanaged(std.ArrayListUnmanaged(Epoch)) = .empty,

    waiters: std.ArrayListUnmanaged(PropertyWaiter) = .empty,

    const MAX_LISTENERS = 8;

    fn deinit(self: *PropertyState) void {
        const a = testing.allocator;
        for (self.slot_trackers.items) |t| {
            t.deinit();
            a.destroy(t);
        }
        for (self.epoch_trackers.items) |t| {
            t.deinit();
            a.destroy(t);
        }
        for (self.slot_expected.items) |*lst| lst.deinit(a);
        for (self.epoch_expected.items) |*lst| lst.deinit(a);
        self.slot_listener_ids.deinit(a);
        self.slot_trackers.deinit(a);
        self.slot_expected.deinit(a);
        self.epoch_listener_ids.deinit(a);
        self.epoch_trackers.deinit(a);
        self.epoch_expected.deinit(a);
        self.waiters.deinit(a);
    }

    fn applyOp(self: *PropertyState, op: PropertyOp) !void {
        const a = testing.allocator;
        switch (op) {
            .on_slot => {
                if (self.slot_listener_ids.items.len >= MAX_LISTENERS) return;
                const tracker = try a.create(PropertyTracker);
                tracker.* = .{};
                errdefer {
                    tracker.deinit();
                    a.destroy(tracker);
                }

                // Reserve before clock.onSlot so a subsequent append can't OOM
                // and leave the clock pointing at a tracker we then free.
                try self.slot_listener_ids.ensureUnusedCapacity(a, 1);
                try self.slot_trackers.ensureUnusedCapacity(a, 1);
                try self.slot_expected.ensureUnusedCapacity(a, 1);
                const id = try self.clock.onSlot(PropertyTracker.onSlot, tracker);
                self.slot_listener_ids.appendAssumeCapacity(id);
                self.slot_trackers.appendAssumeCapacity(tracker);
                self.slot_expected.appendAssumeCapacity(.empty);
            },
            .on_epoch => {
                if (self.epoch_listener_ids.items.len >= MAX_LISTENERS) return;
                const tracker = try a.create(PropertyTracker);
                tracker.* = .{};
                errdefer {
                    tracker.deinit();
                    a.destroy(tracker);
                }

                try self.epoch_listener_ids.ensureUnusedCapacity(a, 1);
                try self.epoch_trackers.ensureUnusedCapacity(a, 1);
                try self.epoch_expected.ensureUnusedCapacity(a, 1);
                const id = try self.clock.onEpoch(PropertyTracker.onEpoch, tracker);
                self.epoch_listener_ids.appendAssumeCapacity(id);
                self.epoch_trackers.appendAssumeCapacity(tracker);
                self.epoch_expected.appendAssumeCapacity(.empty);
            },
            .off_slot => |idx| {
                if (idx >= self.slot_listener_ids.items.len) return;
                const id = self.slot_listener_ids.items[idx];
                try testing.expect(self.clock.offSlot(id));
                _ = self.slot_listener_ids.orderedRemove(idx);
                const t = self.slot_trackers.orderedRemove(idx);
                var exp = self.slot_expected.orderedRemove(idx);
                try expectEqualSlices(Slot, exp.items, t.slot_events.items);
                exp.deinit(a);
                t.deinit();
                a.destroy(t);
            },
            .off_epoch => |idx| {
                if (idx >= self.epoch_listener_ids.items.len) return;
                const id = self.epoch_listener_ids.items[idx];
                try testing.expect(self.clock.offEpoch(id));
                _ = self.epoch_listener_ids.orderedRemove(idx);
                const t = self.epoch_trackers.orderedRemove(idx);
                var exp = self.epoch_expected.orderedRemove(idx);
                try expectEqualSlices(Epoch, exp.items, t.epoch_events.items);
                exp.deinit(a);
                t.deinit();
                a.destroy(t);
            },
            .advance_by => |k| {
                if (k == 0 or self.model_stopped) return;
                const begin = self.model_current_slot;
                const s_first: Slot = if (begin) |c| c + 1 else 0;
                const s_last: Slot = if (begin) |c| c + k else @as(Slot, k) - 1;

                var s: Slot = s_first;
                while (true) : (s += 1) {
                    for (self.slot_expected.items) |*lst| try lst.append(a, s);
                    if (s > 0) {
                        const prev_e = (s - 1) / self.spe;
                        const new_e = s / self.spe;
                        if (new_e > prev_e) {
                            for (self.epoch_expected.items) |*lst| try lst.append(a, new_e);
                        }
                    }
                    if (s == s_last) break;
                }
                self.model_current_slot = s_last;
                self.clock.advanceAndDispatch(s_last);

                for (self.waiters.items) |*w| {
                    if (w.target <= s_last) w.expected_aborted = false;
                }
            },
            .wait_for_slot_at_offset => |offset| {
                if (self.model_stopped) return;
                const base: i64 = if (self.model_current_slot) |c| @intCast(c) else -1;
                const target_signed = base + offset;
                if (target_signed < 0) return;
                const target: Slot = @intCast(target_signed);
                const fut = try self.clock.waitForSlot(target);
                const resolved_now = if (self.model_current_slot) |c| c >= target else false;
                try self.waiters.append(a, .{
                    .target = target,
                    .fut = fut,
                    .expected_aborted = !resolved_now,
                });
            },
            .cancel_waiter => |idx| {
                if (idx >= self.waiters.items.len) return;
                var w = self.waiters.orderedRemove(idx);
                w.fut.cancel();
            },
            .stop => {
                if (self.model_stopped) return;
                self.model_stopped = true;
                self.clock.stop();
            },
        }
    }

    fn finalize(self: *PropertyState, io: std.Io) !void {
        if (!self.model_stopped) {
            self.model_stopped = true;
            self.clock.stop();
        }

        for (self.slot_trackers.items, self.slot_expected.items) |t, exp| {
            try expectEqualSlices(Slot, exp.items, t.slot_events.items);
        }
        for (self.epoch_trackers.items, self.epoch_expected.items) |t, exp| {
            try expectEqualSlices(Epoch, exp.items, t.epoch_events.items);
        }

        for (self.waiters.items) |*w| {
            const result = w.fut.await(io);
            if (w.expected_aborted) {
                try testing.expectError(error.Aborted, result);
            } else {
                try result;
            }
        }
        self.waiters.clearRetainingCapacity();
    }
};

const expectEqualSlices = std.testing.expectEqualSlices;

fn genPropertyOp(rng: std.Random, state: *const PropertyState) PropertyOp {
    while (true) {
        const r = rng.uintLessThan(u32, 100);
        if (r < 18) return .on_slot;
        if (r < 32) return .on_epoch;
        if (r < 42) {
            if (state.slot_listener_ids.items.len == 0) continue;
            return .{ .off_slot = rng.uintLessThan(usize, state.slot_listener_ids.items.len) };
        }
        if (r < 52) {
            if (state.epoch_listener_ids.items.len == 0) continue;
            return .{ .off_epoch = rng.uintLessThan(usize, state.epoch_listener_ids.items.len) };
        }
        if (r < 80) return .{ .advance_by = @intCast(rng.uintLessThan(u32, 8) + 1) };
        if (r < 92) {
            const off: i32 = @as(i32, @intCast(rng.uintLessThan(u32, 12))) - 4;
            return .{ .wait_for_slot_at_offset = off };
        }
        if (r < 98) {
            if (state.waiters.items.len == 0) continue;
            return .{ .cancel_waiter = rng.uintLessThan(usize, state.waiters.items.len) };
        }
        return .stop;
    }
}

fn runPropertyScenario(seed: u64, op_count: u32, io: std.Io) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    const spe: u64 = 4;
    const now_sec = nowSecAt(io);
    var clock: EventClock = undefined;
    // Genesis far in future → wall-clock never advances; advanceAndDispatch owns time.
    try clock.init(testing.allocator, .{
        .genesis_time_sec = now_sec + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = spe,
    }, io);
    defer clock.deinit();

    var state = PropertyState{ .spe = spe, .clock = &clock };
    defer state.deinit();

    var i: u32 = 0;
    while (i < op_count) : (i += 1) {
        const op = genPropertyOp(rng, &state);
        try state.applyOp(op);
    }

    try state.finalize(io);
}

test "property: random op sequences match model" {
    try runInRuntime(struct {
        fn run(io_handle: std.Io) !void {
            var seed: u64 = 0;
            while (seed < 500) : (seed += 1) {
                runPropertyScenario(seed, 50, io_handle) catch |err| {
                    std.debug.print("property scenario failed at seed={d}: {s}\n", .{ seed, @errorName(err) });
                    return err;
                };
            }
        }
    }.run);
}
