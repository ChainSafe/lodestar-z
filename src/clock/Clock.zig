//! Event-driven beacon clock — the clock module's public clock type.
//!
//! Owns the stateful slot cursor (a cached `current_slot` over `slot_math`)
//! and an async I/O loop to emit slot/epoch events and dispatch waiters.
//! All public methods are safe to call from the main thread; the internal
//! loop runs as a single cooperative fiber.
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
//!      completion inside an emit. Safe from a callback: onSlot, offSlot,
//!      onEpoch, offEpoch, stop, all current*/isCurrent* accessors, and
//!      calling waitForSlot (awaiting or cancelling its result falls under
//!      the no-yield rule); the pure-read helpers below them are trivially
//!      safe (no catch-up, no yield).
//!      A query while the cached slot is behind the wall (a backlog)
//!      triggers a NESTED dispatch: later slots/epochs reach all listeners
//!      before the in-flight event's remaining deliveries complete, yet every
//!      (listener, event) pair is delivered exactly once. Each nested level
//!      consumes at least one slot of the pre-existing backlog, so nesting
//!      depth is bounded by the backlog size; levels beyond that require the
//!      wall to cross another slot boundary mid-cascade.
//!   2. `cancel()` removes its waiter from the queue *before* it yields, so a
//!      concurrent `dispatchWaiters` can no longer observe it.
//! A multi-executor backend (zio with `executors > 1`, or `std.Io.Threaded`)
//! would break both and require real locking.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bounded_array = @import("bounded_array");
const time = @import("time");
const slot_math = @import("slot_math.zig");

const Clock = @This();

allocator: Allocator,
io: std.Io,
config: ClockConfig,
current_slot: ?Slot = null,

stopped: bool = false,
loop_future: ?std.Io.Future(void) = null,

next_listener_id: ListenerId = 1,
slot_listeners: bounded_array.BoundedArray(SlotListenerEntry, max_slot_listeners) = .{},
epoch_listeners: bounded_array.BoundedArray(EpochListenerEntry, max_epoch_listeners) = .{},

waiters: WaiterQueue,

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const ClockConfig = slot_math.ClockConfig;
pub const ListenerId = u64;

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

const WaiterQueue = std.PriorityQueue(WaiterEntry, void, struct {
    fn compare(_: void, a: WaiterEntry, b: WaiterEntry) std.math.Order {
        return std.math.order(a.target, b.target);
    }
}.compare);

pub fn init(
    self: *Clock,
    allocator: Allocator,
    config: ClockConfig,
    io_handle: std.Io,
) Error!void {
    try config.validate();
    self.* = .{
        .allocator = allocator,
        .io = io_handle,
        .config = config,
        .current_slot = slot_math.slotAtMs(config, time.nowMs(io_handle)),
        .waiters = WaiterQueue.initContext({}),
    };
}

/// Start the auto-advance loop.  Idempotent; second call is a no-op.
pub fn start(self: *Clock) Error!void {
    if (self.loop_future != null) return;
    self.loop_future = std.Io.concurrent(self.io, Clock.runAutoLoop, .{self}) catch
        return error.ConcurrencyUnavailable;
}

/// Signal the loop to stop and abort all pending waiters.  Idempotent.
pub fn stop(self: *Clock) void {
    if (self.stopped) return;
    self.stopped = true;
    self.abortAllWaiters();
}

/// Signal the loop to stop, cancel the fiber, and wait for it to finish.
pub fn join(self: *Clock) void {
    self.stop();
    var maybe_future = self.loop_future;
    self.loop_future = null;
    if (maybe_future) |*future| {
        future.cancel(self.io);
        future.await(self.io);
    }
}

/// Release all resources.  Calls `stop()` + `join()` internally.
pub fn deinit(self: *Clock) void {
    self.stop();
    self.join();
    self.waiters.deinit(self.allocator);
    self.* = undefined;
}

// Each emit iterates its own stack snapshot, so callbacks may mutate the
// listener lists mid-dispatch: a listener added does not receive the event
// being emitted; one removed still receives it.

/// Register a slot listener.  Returns an ID for later removal via `offSlot`.
pub fn onSlot(
    self: *Clock,
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
pub fn offSlot(self: *Clock, id: ListenerId) bool {
    for (self.slot_listeners.slice(), 0..) |listener, i| {
        if (listener.id == id) {
            self.slot_listeners.orderedRemove(@intCast(i));
            return true;
        }
    }
    return false;
}

/// Register an epoch listener.  Returns an ID for later removal via `offEpoch`.
/// An epoch event fires once when the epoch of the advancing slot increases.
pub fn onEpoch(
    self: *Clock,
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
pub fn offEpoch(self: *Clock, id: ListenerId) bool {
    for (self.epoch_listeners.slice(), 0..) |listener, i| {
        if (listener.id == id) {
            self.epoch_listeners.orderedRemove(@intCast(i));
            return true;
        }
    }
    return false;
}

// The "current" accessors read the clock only through catchUp(), so each
// derives from its single wall reading rather than a second, possibly
// skewed clock read.

pub fn currentSlot(self: *Clock) ?Slot {
    return slot_math.slotAtMs(self.config, self.catchUp());
}

pub fn currentEpoch(self: *Clock) ?Epoch {
    const slot = slot_math.slotAtMs(self.config, self.catchUp()) orelse return null;
    return slot_math.epochAtSlot(self.config, slot);
}

pub fn currentSlotOrGenesis(self: *Clock) Slot {
    return self.currentSlot() orelse 0;
}

pub fn currentEpochOrGenesis(self: *Clock) Epoch {
    return self.currentEpoch() orelse 0;
}

pub fn currentSlotWithGossipDisparity(self: *Clock) ?Slot {
    return slot_math.slotWithGossipDisparity(self.config, self.catchUp());
}

pub fn isCurrentSlotGivenGossipDisparity(self: *Clock, slot: Slot) bool {
    return slot_math.isCurrentSlotGivenGossipDisparity(self.config, slot, self.catchUp());
}

// Unlike the catchUp-backed accessors above, the helpers below are pure
// reads: they never advance the cache and never emit events.

/// Returns the slot if the internal clock were advanced by `tolerance_ms`.
pub fn slotWithFutureToleranceMs(self: *const Clock, tolerance_ms: u64) ?Slot {
    return slot_math.slotWithFutureToleranceMs(self.config, time.nowMs(self.io), tolerance_ms);
}

/// Returns the slot if the internal clock were reversed by `tolerance_ms`.
pub fn slotWithPastToleranceMs(self: *const Clock, tolerance_ms: u64) Slot {
    return slot_math.slotWithPastToleranceMs(self.config, time.nowMs(self.io), tolerance_ms);
}

/// Returns the seconds from the start of `slot` to `to_sec` (or now).
pub fn secFromSlot(self: *const Clock, slot: Slot, to_sec: ?u64) i64 {
    return slot_math.secFromSlot(
        self.config,
        slot,
        to_sec orelse @divFloor(time.nowMs(self.io), 1000),
    );
}

/// Returns the milliseconds from the start of `slot` to `to_ms` (or now).
pub fn msFromSlot(self: *const Clock, slot: Slot, to_ms: ?u64) i64 {
    return slot_math.msFromSlot(self.config, slot, to_ms orelse time.nowMs(self.io));
}

/// Return type from `waitForSlot`. The caller MUST either:
///   - call `await()` to wait for the target slot and release resources, OR
///   - call `cancel()` to abort and release resources, OR
///   - call `stop()` on the Clock and THEN `await()` to get `error.Aborted`.
/// Dropping a WaitForSlotResult without calling `await` or `cancel` leaks
/// the internal WaitState.
///
/// Idiomatic usage with `errdefer`:
///   var fut = try clock.waitForSlot(target);
///   errdefer fut.cancel();
///   try fut.await(io);
pub const WaitForSlotResult = struct {
    inner: std.Io.Future(Error!void),
    state: ?*WaitState,
    clock: ?*Clock,

    /// Create an immediately-resolved result (no async work needed).
    /// Relies on `std.Io.Future.await` returning `.result` when `.any_future == null`.
    fn immediate(result: Error!void) WaitForSlotResult {
        return .{
            .inner = .{ .any_future = null, .result = result },
            .state = null,
            .clock = null,
        };
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
pub fn waitForSlot(self: *Clock, target: Slot) Error!WaitForSlotResult {
    if (self.stopped) {
        return WaitForSlotResult.immediate(error.Aborted);
    }
    _ = self.catchUp();
    if (self.current_slot) |slot| {
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
    self.waiters.push(
        self.allocator,
        .{ .target = target, .state = state },
    ) catch return error.OutOfMemory;
    self.dispatchWaiters(self.current_slot);

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

/// Advance to wall-clock time, emitting any pending slot/epoch events, and
/// return the reading used. Emits nothing if already caught up or pre-genesis.
///
/// Accessors must derive from this reading, not a fresh clock read: a slow
/// callback can cross a slot boundary mid-dispatch, so a second read could
/// name a slot the just-emitted events haven't reached.
fn catchUp(self: *Clock) u64 {
    const now_ms = time.nowMs(self.io);
    if (slot_math.slotAtMs(self.config, now_ms)) |wall_slot| {
        self.advanceAndDispatch(wall_slot);
    }
    return now_ms;
}

fn emitSlot(self: *Clock, slot: Slot) void {
    // By-value stack copy: a reentrant callback may add/remove listeners or
    // trigger a nested emit; those mutate only the member list, never the
    // snapshot this frame is iterating.
    var snapshot = self.slot_listeners;
    for (snapshot.slice()) |listener| {
        listener.callback(listener.ctx, slot);
    }
}

fn emitEpoch(self: *Clock, epoch: Epoch) void {
    var snapshot = self.epoch_listeners;
    for (snapshot.slice()) |listener| {
        listener.callback(listener.ctx, epoch);
    }
}

fn dispatchWaiters(self: *Clock, current_slot: ?Slot) void {
    const slot = current_slot orelse return;
    while (self.waiters.peek()) |head| {
        if (head.target > slot) break;
        const waiter = self.waiters.pop().?;
        waiter.state.aborted = false;
        waiter.state.event.set(waiter.state.io);
    }
}

fn abortAllWaiters(self: *Clock) void {
    while (self.waiters.pop()) |waiter| {
        // A reached target already satisfied the wait (waitForSlot resolves
        // once current_slot >= target); stopping only aborts slots that can
        // no longer be emitted.
        const reached = if (self.current_slot) |cs| waiter.target <= cs else false;
        waiter.state.aborted = !reached;
        waiter.state.event.set(waiter.state.io);
    }
}

const Event = union(enum) {
    slot: Slot,
    epoch: Epoch,
};

// Holds only what advancing needs — config and the slot cursor — so the
// iterator cannot dispatch (no listeners, waiters, or io in reach).
const AdvanceIterator = struct {
    config: ClockConfig,
    current_slot: *?Slot,
    target: Slot,
    pending_epoch: ?Epoch = null,

    /// Advances the clock one step at a time, yielding slot and epoch events.
    /// For each slot advancement: yields .slot first, then .epoch if an epoch
    /// boundary was crossed.
    /// Returns null when caught up to target.
    fn next(self: *AdvanceIterator) ?Event {
        if (self.pending_epoch) |epoch| {
            self.pending_epoch = null;
            return .{ .epoch = epoch };
        }

        const current = self.current_slot.*;
        if (current == null) {
            self.current_slot.* = 0;
            return .{ .slot = 0 };
        }

        const cur = current.?;
        if (cur >= self.target) return null;

        const next_slot = cur + 1;
        self.current_slot.* = next_slot;

        const prev_epoch = slot_math.epochAtSlot(self.config, cur);
        const new_epoch = slot_math.epochAtSlot(self.config, next_slot);
        if (prev_epoch < new_epoch) {
            self.pending_epoch = new_epoch;
        }

        return .{ .slot = next_slot };
    }
};

/// Advances the clock toward `target` one event at a time.  The caller may
/// drop the iterator mid-walk; the clock is then left at the last slot the
/// iterator returned (i.e. partial advancement is observable).
fn advanceTo(self: *Clock, target: Slot) AdvanceIterator {
    return .{
        .config = self.config,
        .current_slot = &self.current_slot,
        .target = target,
    };
}

fn advanceAndDispatch(self: *Clock, target: Slot) void {
    var iter = self.advanceTo(target);
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
}

fn runAutoLoop(self: *Clock) void {
    while (!self.stopped) {
        const now_ms = time.nowMs(self.io);
        const next_ms = slot_math.msUntilNextSlot(self.config, now_ms);
        const sleep_ms: i64 = @intCast(@max(@as(u64, 1), next_ms));

        // Sleep failure: cancellation (from join()) exits the loop;
        // other errors re-check the stopped flag.
        std.Io.sleep(
            self.io,
            std.Io.Duration.fromMilliseconds(sleep_ms),
            .awake,
        ) catch |err| {
            if (err == error.Canceled) break;
            std.log.debug("Clock: sleep failed ({s}), retrying", .{@errorName(err)});
            continue;
        };

        if (self.stopped) break;
        _ = self.catchUp();
    }
    // Non-terminating event loop: exits only when `self.stopped` is set.
    //  - normal stop(): sets flag, next iteration's `!self.stopped` exits
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
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
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

test "waitForSlot resolves immediately when at target" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
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

test "waitForSlot returns aborted on stop" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
        .slot_duration_ms = 2_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var fut = try clock.waitForSlot(100);
    errdefer fut.cancel();
    clock.stop();
    try testing.expectError(error.Aborted, fut.await(io_handle));
}

test "offSlot/offEpoch stop event delivery" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
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

test "stop/join are idempotent" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
        .slot_duration_ms = 2_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    clock.stop();
    clock.stop();
    clock.join();
    clock.join();
}

test "epoch event is delivered when crossing epoch boundary" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
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

test "multiple waiters are dispatched in target-slot order" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 10,
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

test "cancel releases WaitState without awaiting" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 10,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    // testing.allocator detects a leak if cancel fails to free.
    var fut = try clock.waitForSlot(999);
    fut.cancel();
}

test "real-time: no slot events emitted before genesis" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 5,
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

test "real-time: slot events fire with correct timing" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
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
    const before_ms = time.nowMs(io_handle);
    var fut = try clock.waitForSlot(start_slot + 1);
    errdefer fut.cancel();
    try fut.await(io_handle);
    const elapsed = time.nowMs(io_handle) - before_ms;

    try testing.expect(elapsed < 2000);
    try testing.expect(trace.slot_len > 0);
    try testing.expect(trace.slots[trace.slot_len - 1] >= start_slot + 1);
}

test "real-time: multi-slot advancement delivers ordered events" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
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

test "real-time: stop+join cancels promptly" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    }, io_handle);
    defer clock.deinit();

    try clock.start();

    // Give the loop fiber time to enter its sleep.
    std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(50), .awake) catch {};

    const before_ms = time.nowMs(io_handle);
    clock.stop();
    clock.join();
    const elapsed = time.nowMs(io_handle) - before_ms;

    // join() cancels the sleeping future directly — should return
    // almost immediately, NOT after the full 12-second slot.
    try testing.expect(elapsed < 1500);
}

test "real-time: epoch boundary event fires" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
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

fn nopSlot(_: ?*anyopaque, _: Slot) void {}
fn nopEpoch(_: ?*anyopaque, _: Epoch) void {}

const ReentrancyCtx = struct {
    clock: *Clock,
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
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
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

test "reentrancy: callback can stop the clock; no further slots emitted" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    }, io_handle);
    defer clock.deinit();

    var ctx = ReentrancyCtx{ .clock = &clock };
    _ = try clock.onSlot(ReentrancyCtx.stopClock, &ctx);

    clock.advanceAndDispatch(5);

    try testing.expectEqual(@as(usize, 1), ctx.fired_count);
    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, 0), clock.current_slot);
}

const StopAtSlotCtx = struct {
    clock: *Clock,
    stop_at: Slot,

    fn stopAt(ctx: ?*anyopaque, slot: Slot) void {
        const self: *StopAtSlotCtx = @ptrCast(@alignCast(ctx.?));
        if (slot == self.stop_at) self.clock.stop();
    }
};

test "reentrancy: stop() during emit resolves reached waiter, aborts future one" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    }, io_handle);
    defer clock.deinit();

    // Listener calls stop() while slot `target` is being emitted, i.e.
    // after current_slot reaches `target` but before dispatchWaiters runs.
    const target: Slot = 3;
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = target };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    var fut_reached = try clock.waitForSlot(target);
    errdefer fut_reached.cancel();
    var fut_future = try clock.waitForSlot(target + 1);
    errdefer fut_future.cancel();

    clock.advanceAndDispatch(target);

    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, target), clock.current_slot);
    // Reached slot happened, so the wait must resolve, not abort.
    try fut_reached.await(io_handle);
    // Future slot can never be emitted after stop, so it aborts.
    try testing.expectError(error.Aborted, fut_future.await(io_handle));
}

const WaitFromCallbackCtx = struct {
    clock: *Clock,
    fut: ?WaitForSlotResult = null,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *WaitFromCallbackCtx = @ptrCast(@alignCast(ctx.?));
        if (slot != 1) return;
        self.fut = self.clock.waitForSlot(2) catch unreachable;
    }
};

test "reentrancy: waitForSlot from a callback resolves via the ongoing dispatch" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    }, io_handle);
    defer clock.deinit();

    var ctx = WaitFromCallbackCtx{ .clock = &clock };
    _ = try clock.onSlot(WaitFromCallbackCtx.onSlot, &ctx);

    // The slot-1 callback registers a waiter for slot 2 and returns without
    // awaiting; the same dispatch's emit of slot 2 then resolves it, so the
    // await after advanceAndDispatch must succeed rather than abort.
    clock.advanceAndDispatch(2);

    try testing.expect(ctx.fut != null);
    errdefer ctx.fut.?.cancel();
    try ctx.fut.?.await(io_handle);
}

test "ListenerLimitReached: onSlot/onEpoch reject the (limit+1)th registration" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
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

test "WaiterLimitReached: waitForSlot rejects the (limit+1)th waiter" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    }, io_handle);
    defer clock.deinit();

    var futs: [max_waiters]WaitForSlotResult = undefined;
    for (&futs) |*f| f.* = try clock.waitForSlot(999_999);
    try testing.expectError(error.WaiterLimitReached, clock.waitForSlot(999_999));
    for (&futs) |*f| f.cancel();
}

test "many waiters at same target slot all resolve on advance" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
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

// Drives accessor and advance tests without start(): only the `now` vtable
// entry is exercised, and deinit is safe with no pending waiters.
const FakeClockIo = struct {
    ms: u64 = 0,
    fn vtableNow(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        _ = clock;
        const self: *const FakeClockIo = @ptrCast(@alignCast(userdata.?));
        return std.Io.Timestamp.fromNanoseconds(@as(i96, @intCast(self.ms)) * std.time.ns_per_ms);
    }
    const vtable: std.Io.VTable = blk: {
        var vt: std.Io.VTable = undefined;
        vt.now = vtableNow;
        break :blk vt;
    };
    fn io(self: *const FakeClockIo) std.Io {
        return .{ .userdata = @constCast(self), .vtable = &vtable };
    }
};

const test_cfg = ClockConfig{
    .genesis_time_sec = 100,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};

test "pre-genesis returns null, genesis fallback returns zero" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();

    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(?Epoch, null), clock.currentEpoch());
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotOrGenesis());
    try testing.expectEqual(@as(Epoch, 0), clock.currentEpochOrGenesis());
}

test "currentSlot at genesis and advancing" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();

    try testing.expectEqual(@as(?Slot, 0), clock.currentSlot());

    fake.ms = 112_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    fake.ms = 124_000;
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
}

test "currentEpoch" {
    var fake = FakeClockIo{ .ms = 100_000 + 32 * 12 * 1000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();

    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
}

test "advanceTo produces correct slot events" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(3);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 1);
    try testing.expect(events[1] == .slot and events[1].slot == 2);
    try testing.expect(events[2] == .slot and events[2].slot == 3);
    try testing.expectEqual(@as(?Slot, 3), clock.current_slot);
}

test "advanceTo across epoch boundary emits slot then epoch" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();
    clock.current_slot = 31;

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(33);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 32);
    try testing.expect(events[1] == .epoch and events[1].epoch == 1);
    try testing.expect(events[2] == .slot and events[2].slot == 33);
}

test "advanceTo from null (pre-genesis)" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();
    try testing.expectEqual(@as(?Slot, null), clock.current_slot);

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(2);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 0);
    try testing.expect(events[1] == .slot and events[1].slot == 1);
    try testing.expect(events[2] == .slot and events[2].slot == 2);
}

test "advanceTo already at target returns nothing" {
    var fake = FakeClockIo{ .ms = 112_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, test_cfg, fake.io());
    defer clock.deinit();

    var count: usize = 0;
    var iter = clock.advanceTo(1);
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 0), count);
}

const SlowCallbackCtx = struct {
    fake: *FakeClockIo,
    advance_ms: u64,
    last_emitted: ?Slot = null,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *SlowCallbackCtx = @ptrCast(@alignCast(ctx.?));
        self.last_emitted = slot;
        self.fake.ms += self.advance_ms;
    }
};

test "currentSlot returns the reading its catch-up flushed to" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    // Each emit burns 5 slots of wall time, simulating a slow callback.
    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5_000 };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // Wall slot 2: catch-up emits slots 1 and 2, burning the wall to
    // 112_000 ms (slot 12). The result must stay at the flushed reading.
    fake.ms = 102_000;
    const returned = clock.currentSlot();

    try testing.expectEqual(@as(?Slot, 2), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
    try testing.expect(ctx.last_emitted.? <= returned.?);
}

test "currentSlotWithGossipDisparity bases its slot on the caught-up reading" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5_000 };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // 300 ms into slot 2 — outside the 500 ms disparity window — while the
    // slow callbacks burn the wall to 112_300 ms (slot 12). The base slot
    // must come from the caught-up reading, not a fresh read.
    fake.ms = 102_300;
    const returned = clock.currentSlotWithGossipDisparity();

    try testing.expectEqual(@as(?Slot, 2), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "currentEpoch returns the epoch of the reading its catch-up flushed to" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    }, fake.io());
    defer clock.deinit();

    // Each emit burns 5 slots (2.5 epochs) of wall time.
    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5_000 };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // Wall slot 2 (epoch 1): catch-up emits slots 1 and 2, burning the wall
    // to 112_000 ms (slot 12, epoch 6). The result must stay at epoch 1.
    fake.ms = 102_000;
    const returned = clock.currentEpoch();

    try testing.expectEqual(@as(?Epoch, 1), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "isCurrentSlotGivenGossipDisparity judges the caught-up reading" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5_000 };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // 300 ms into slot 2 while the slow callbacks burn the wall to
    // 112_300 ms (slot 12); a fresh second read would judge slot 2 stale.
    fake.ms = 102_300;
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(2));
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "tolerance and from-slot forwards are pure reads: no catch-up" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    }, fake.io());
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Wall slot 1 with the cache at 0: a catchUp-backed accessor would flush
    // this backlog to the listener; the forwards must not.
    fake.ms = 112_000;
    try testing.expectEqual(@as(?Slot, 2), clock.slotWithFutureToleranceMs(12_000));
    try testing.expectEqual(@as(Slot, 0), clock.slotWithPastToleranceMs(12_000));

    fake.ms = 118_000;
    try testing.expectEqual(@as(i64, 6), clock.secFromSlot(1, null));
    try testing.expectEqual(@as(i64, 6_000), clock.msFromSlot(1, null));
    try testing.expectEqual(@as(i64, 0), clock.secFromSlot(1, 112));
    try testing.expectEqual(@as(i64, -12), clock.secFromSlot(1, 100));
    try testing.expectEqual(@as(i64, -12_000), clock.msFromSlot(1, 100_000));

    try testing.expectEqual(@as(usize, 0), trace.slot_len);
    try testing.expectEqual(@as(?Slot, 0), clock.current_slot);
}

const NestedDispatchCtx = struct {
    clock: *Clock,
    fake: *FakeClockIo,
    add_ctx: *EventTraceState,
    remove_id: ListenerId = 0,
    fired_once: bool = false,
    slots: [4]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *NestedDispatchCtx = @ptrCast(@alignCast(ctx.?));
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
        if (self.fired_once) return;
        self.fired_once = true;
        self.fake.ms += 1_000;
        _ = self.clock.offSlot(self.remove_id);
        _ = self.clock.onSlot(EventTraceState.onSlot, self.add_ctx) catch unreachable;
        _ = self.clock.currentSlot();
    }
};

test "nested dispatch during emit preserves the outer snapshot" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    var ctx_l2 = EventTraceState{};
    var ctx_l3 = EventTraceState{};
    var ctx_l4 = EventTraceState{};
    var ctx_l1 = NestedDispatchCtx{ .clock = &clock, .fake = &fake, .add_ctx = &ctx_l4 };
    _ = try clock.onSlot(NestedDispatchCtx.onSlot, &ctx_l1);
    const id_l2 = try clock.onSlot(EventTraceState.onSlot, &ctx_l2);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_l3);
    ctx_l1.remove_id = id_l2;

    // Wall slot 1: the outer emit of slot 1 snapshots [L1, L2, L3]. L1 burns
    // the wall into slot 2, removes L2, registers L4, and queries the clock —
    // the nested emit of slot 2 snapshots [L1, L3, L4]. The outer emit then
    // resumes: L2 still gets slot 1, L3 gets it exactly once, and L4 (absent
    // from the outer snapshot) records only slot 2.
    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2 }, ctx_l1.slots[0..ctx_l1.slot_len]);
    try expectEqualSlices(Slot, &.{1}, ctx_l2.slots[0..ctx_l2.slot_len]);
    try expectEqualSlices(Slot, &.{ 2, 1 }, ctx_l3.slots[0..ctx_l3.slot_len]);
    try expectEqualSlices(Slot, &.{2}, ctx_l4.slots[0..ctx_l4.slot_len]);
}

const EpochMutateCtx = struct {
    clock: *Clock,
    add_ctx: *EventTraceState,
    remove_id: ListenerId = 0,
    fired_once: bool = false,
    epochs: [4]Epoch = undefined,
    epoch_len: usize = 0,

    fn onEpoch(ctx: ?*anyopaque, epoch: Epoch) void {
        const self: *EpochMutateCtx = @ptrCast(@alignCast(ctx.?));
        self.epochs[self.epoch_len] = epoch;
        self.epoch_len += 1;
        if (self.fired_once) return;
        self.fired_once = true;
        _ = self.clock.offEpoch(self.remove_id);
        _ = self.clock.onEpoch(EventTraceState.onEpoch, self.add_ctx) catch unreachable;
    }
};

test "epoch listener mutations mid-emit preserve the epoch snapshot" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    }, fake.io());
    defer clock.deinit();

    var ctx_e2 = EventTraceState{};
    var ctx_e3 = EventTraceState{};
    var ctx_e1 = EpochMutateCtx{ .clock = &clock, .add_ctx = &ctx_e3 };
    _ = try clock.onEpoch(EpochMutateCtx.onEpoch, &ctx_e1);
    const id_e2 = try clock.onEpoch(EventTraceState.onEpoch, &ctx_e2);
    ctx_e1.remove_id = id_e2;

    // Wall slot 4 crosses two epoch boundaries. The epoch-1 emit snapshots
    // [E1, E2]; E1 removes E2 and registers E3 mid-emit, so E2 (in the
    // snapshot) still receives epoch 1 but misses epoch 2, while E3 (absent
    // from the snapshot) misses epoch 1 and receives epoch 2.
    fake.ms = 104_000;
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());

    try expectEqualSlices(Epoch, &.{ 1, 2 }, ctx_e1.epochs[0..ctx_e1.epoch_len]);
    try expectEqualSlices(Epoch, &.{1}, ctx_e2.epochs[0..ctx_e2.epoch_len]);
    try expectEqualSlices(Epoch, &.{2}, ctx_e3.epochs[0..ctx_e3.epoch_len]);
}

const QueryAtSlotCtx = struct {
    clock: *Clock,
    fake: *FakeClockIo,
    query_at: Slot,
    burn_to_ms: ?u64 = null,
    queried_slot: ?Slot = null,
    slots: [8]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *QueryAtSlotCtx = @ptrCast(@alignCast(ctx.?));
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
        if (slot != self.query_at) return;
        if (self.burn_to_ms) |ms| self.fake.ms = ms;
        self.queried_slot = self.clock.currentSlot();
    }
};

test "backlog query-from-callback delivers every (listener, slot) exactly once" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    var ctx_r = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_r);

    // Wall slot 3 with the cache at 0: the outer emit of slot 1 reaches Q
    // first; its query drains the remaining backlog (slots 2, 3) to both
    // listeners before the outer emit resumes and delivers slot 1 to R.
    fake.ms = 103_000;
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Slot, &.{ 2, 3, 1 }, ctx_r.slots[0..ctx_r.slot_len]);
    try testing.expectEqual(@as(?Slot, 3), ctx_q.queried_slot);
}

test "non-backlog query-from-callback is a no-op" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, fake.io());
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    var ctx_r = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_r);

    // The cache is already at the wall slot when Q queries, so the nested
    // catch-up has nothing to drain: plain single-slot delivery, and the
    // query returns exactly the slot being emitted.
    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{1}, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Slot, &.{1}, ctx_r.slots[0..ctx_r.slot_len]);
    try testing.expectEqual(@as(?Slot, 1), ctx_q.queried_slot);
}

test "epoch events under nested dispatch arrive out of order but exactly once" {
    var fake = FakeClockIo{ .ms = 102_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    }, fake.io());
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 4,
        .burn_to_ms = 108_000,
    };
    var trace = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Wall slot 4 with the cache at 2: the outer iterator emits slot 3, then
    // slot 4 — setting pending epoch 1, drained only on its NEXT next(). The
    // slot-4 callback burns the wall to slot 8 (epoch 2) and queries; the
    // nested iterator starts with no pending state, so it emits slots 5
    // through 8 and epoch 2 before the outer iterator resumes and drains
    // epoch 1.
    fake.ms = 104_000;
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 3, 4, 5, 6, 7, 8 }, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Epoch, &.{ 2, 1 }, trace.epochs[0..trace.epoch_len]);
    try testing.expectEqual(@as(?Slot, 8), ctx_q.queried_slot);
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
    clock: *Clock,

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
    const now_sec = time.nowSec(io);
    var clock: Clock = undefined;
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
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var seed: u64 = 0;
    while (seed < 500) : (seed += 1) {
        runPropertyScenario(seed, 50, io_handle) catch |err| {
            std.debug.print(
                "property scenario failed at seed={d}: {s}\n",
                .{ seed, @errorName(err) },
            );
            return err;
        };
    }
}
