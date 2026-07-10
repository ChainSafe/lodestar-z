//! Event-driven beacon clock.
//!
//! Owns the stateful slot cursor (a cached `current_slot` over `slot_math`)
//! and an async I/O loop to emit slot/epoch events and dispatch waiters.
//! All public methods are safe to call from the main thread; the internal
//! loop runs as a single cooperative fiber.
//!
//! Designed for a cooperative single-fiber `std.Io` backend (e.g. zio).
//!
//! No mutex is used: under a single-fiber backend the only context switches
//! are at `await`/`sleep` yield points, and every read-modify of shared state
//! (listeners, waiter queue, `stopped`) completes synchronously between yields.
//! Two invariants make this safe:
//!   1. Listener callbacks run to completion inside an emit and must NOT
//!      yield (no `await`/`sleep`). Safe to call from a callback:
//!        - onSlot / offSlot / onEpoch / offEpoch and stop;
//!        - any current* / isCurrent* accessor and the pure-read helpers.
//!      `waitForSlot` suspends the caller, so it must NEVER be called from a
//!      listener callback.
//!      A query while the cache lags the wall (a backlog) does not nest a
//!      dispatch. It returns the fresh wall time — possibly ahead of the
//!      events delivered so far — and the frame already emitting delivers
//!      the rest, in order, exactly once per (listener, event). E.g. the
//!      wall reaches slot 3 while slot 1 is still being emitted:
//!
//!        emit 1
//!          callback: currentSlot() returns 3; instead of emitting 2 and 3
//!                    itself, it stores pending_target = 3
//!        emit 2      ← the emitting frame sees pending_target and continues
//!        emit 3
//!   2. A wake-up pops its waiter from the queue *before* setting the event, so
//!      a resuming `waitForSlot` frame is never still referenced by the queue.
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
dispatching: bool = false,
pending_target: ?Slot = null,
loop_future: ?std.Io.Future(void) = null,

// IDs start at 1 so callers can use 0 as an unset sentinel.
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
    io_handle: std.Io,
    config: ClockConfig,
) Error!void {
    try config.validate();
    self.* = .{
        .allocator = allocator,
        .io = io_handle,
        .config = config,
        .current_slot = slot_math.slotAtMs(config, time.nowMs(io_handle)),
        .waiters = WaiterQueue.initContext({}),
    };
    // Reserve full waiter capacity up front so waitForSlot's push after the
    // limit check can neither allocate nor fail.
    try self.waiters.ensureTotalCapacity(allocator, max_waiters);
}

/// Start the auto-advance loop.  Idempotent.
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
    }
}

/// Release all resources.  Calls `stop()` + `join()` internally.
pub fn deinit(self: *Clock) void {
    self.stop();
    self.join();
    self.waiters.deinit(self.allocator);
    self.* = undefined;
}

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

// Each "current" accessor derives from catchUp()'s single wall-clock read; a
// separate time.nowMs (the pure-read shape below) could land in a slot whose
// events have not been delivered yet.

pub fn currentSlot(self: *Clock) ?Slot {
    return self.catchUp().slot;
}

pub fn currentEpoch(self: *Clock) ?Epoch {
    const slot = self.catchUp().slot orelse return null;
    return slot_math.epochAtSlot(self.config, slot);
}

pub fn currentSlotOrGenesis(self: *Clock) Slot {
    return self.currentSlot() orelse 0;
}

pub fn currentEpochOrGenesis(self: *Clock) Epoch {
    return self.currentEpoch() orelse 0;
}

pub fn currentSlotWithGossipDisparity(self: *Clock) ?Slot {
    return slot_math.slotWithGossipDisparity(self.config, self.catchUp().now_ms);
}

pub fn isCurrentSlotGivenGossipDisparity(self: *Clock, slot: Slot) bool {
    return slot_math.isCurrentSlotGivenGossipDisparity(self.config, slot, self.catchUp().now_ms);
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

/// Suspend the calling fiber until the clock reaches `target`, then return.
/// Returns immediately if `target` has already been reached, and
/// `error.Aborted` if the clock is stopped before or during the wait.
///
/// Reachable errors: {Aborted, WaiterLimitReached}.
///
/// The wait is not a cancellation point: an external fiber-cancel takes effect
/// only once the wait resolves via dispatch or stop(). A wait on a clock that
/// is never started and never read blocks until stop().
///
/// Must NEVER be called from a listener callback.
pub fn waitForSlot(self: *Clock, target: Slot) Error!void {
    if (self.stopped) return error.Aborted;
    _ = self.catchUp();
    // Reached is judged by the cursor, not the wall time catchUp returned. A
    // stop during the drain suppresses events past the cursor, and a wait for
    // a suppressed slot must abort rather than resolve.
    if (self.current_slot) |slot| {
        if (slot >= target) return;
    }
    if (self.waiters.count() >= max_waiters) return error.WaiterLimitReached;
    // A catchUp callback may have called stop(); checked after the
    // reached-check so a wait that reached its target still resolves.
    if (self.stopped) return error.Aborted;

    var waiter: WaitState = .{};
    // Capacity was reserved at init and count < max_waiters here.
    self.waiters.push(self.allocator, .{ .target = target, .state = &waiter }) catch unreachable;
    // Checks that waitForSlot was not called from a listener callback.
    if (self.current_slot) |cs| std.debug.assert(self.waiters.peek().?.target > cs);

    waiter.event.waitUncancelable(self.io);
    return if (waiter.aborted) error.Aborted else {};
}

const WallTime = struct { now_ms: u64, slot: ?Slot };

/// Advance to wall-clock time, emitting any pending slot/epoch events, and
/// return the wall time it used. Emits nothing if already caught up or pre-genesis.
///
/// Normally catchUp drains every pending event before returning, so the
/// returned slot is never ahead of delivery. The two exceptions are a query
/// from inside a listener callback (see the reentrancy notes in the module
/// header) and a stop() from a callback, which freezes the cursor and
/// suppresses the slots past it.
fn catchUp(self: *Clock) WallTime {
    const now_ms = time.nowMs(self.io);
    const slot = slot_math.slotAtMs(self.config, now_ms);
    const wall_time: WallTime = .{ .now_ms = now_ms, .slot = slot };
    const target = slot orelse return wall_time;

    if (self.dispatching) {
        // A reentrant query only records the target; the frame that set
        // `dispatching` drains it. @max: a wall step-back (NTP) must not
        // regress a recorded target.
        self.pending_target = @max(self.pending_target orelse target, target);
        return wall_time;
    }
    self.dispatching = true;
    defer self.dispatching = false;
    // The pending defer runs before the dispatching defer, so pending is null
    // whenever dispatching is false.
    std.debug.assert(self.pending_target == null);
    self.pending_target = target;
    // Backstop: a stopped exit leaves the loop with pending still set.
    defer self.pending_target = null;
    while (!self.stopped) {
        const drain_target = self.pending_target orelse break;
        self.pending_target = null;
        self.dispatchTo(drain_target);
    }
    return wall_time;
}

fn emitSlot(self: *Clock, slot: Slot) void {
    std.debug.assert(self.dispatching);
    var snapshot = self.slot_listeners;
    for (snapshot.slice()) |listener| {
        listener.callback(listener.ctx, slot);
    }
}

fn emitEpoch(self: *Clock, epoch: Epoch) void {
    std.debug.assert(self.dispatching);
    var snapshot = self.epoch_listeners;
    for (snapshot.slice()) |listener| {
        listener.callback(listener.ctx, epoch);
    }
}

fn dispatchWaiters(self: *Clock, current_slot: ?Slot) void {
    std.debug.assert(self.dispatching);
    const slot = current_slot orelse return;
    while (self.waiters.peek()) |head| {
        if (head.target > slot) break;
        const waiter = self.waiters.pop().?;
        // Checks that nothing set aborted while the entry was still queued.
        std.debug.assert(!waiter.state.aborted);
        waiter.state.event.set(self.io);
    }
}

fn abortAllWaiters(self: *Clock) void {
    while (self.waiters.pop()) |waiter| {
        // A reached target already satisfied the wait (waitForSlot resolves
        // once current_slot >= target); stopping only aborts slots that can
        // no longer be emitted.
        const reached = if (self.current_slot) |cs| waiter.target <= cs else false;
        waiter.state.aborted = !reached;
        waiter.state.event.set(self.io);
    }
}

const Event = union(enum) {
    slot: Slot,
    epoch: Epoch,
};

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

/// Advances the clock toward `target` one event at a time.  Stopping early
/// is legal: the cursor simply stays at the last slot the iterator yielded,
/// nothing rolls back.
fn advanceTo(self: *Clock, target: Slot) AdvanceIterator {
    return .{
        .config = self.config,
        .current_slot = &self.current_slot,
        .target = target,
    };
}

/// Walk the cursor to `target`, emitting each event. 
fn dispatchTo(self: *Clock, target: Slot) void {
    std.debug.assert(self.dispatching);
    var iter = self.advanceTo(target);
    // Check `stopped` before iter.next() so a callback that calls stop()
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

        // error.Canceled comes from join()'s fiber-cancel.
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
    // join() calls stop() before cancelling the fiber, so the Canceled break
    // also exits with stopped set.
    std.debug.assert(self.stopped);
}

const testing = std.testing;
const zio = @import("zio");

/// Poll until `expected` waiter fibers have suspended inside waitForSlot.
/// Deterministic under a single-executor zio runtime: sleeping yields to the
/// spawned fibers, each of which pushes one queue entry then suspends.
fn rendezvousWaiters(clock: *Clock, io: std.Io, expected: usize) !void {
    var polls: usize = 0;
    while (clock.waiters.count() < expected) : (polls += 1) {
        if (polls >= 10_000) return error.RendezvousTimeout;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
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
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = base_now,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    // The auto-loop advances the clock on its own fiber, so this direct wait
    // suspends the main fiber and is woken by the loop's dispatch.
    try clock.waitForSlot(start_slot + 1);

    try testing.expect(trace.slot_len > 0);
}

test "waitForSlot resolves immediately when at target" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const base_now = time.nowSec(io_handle);

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = base_now,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    const current = clock.currentSlotOrGenesis();
    try clock.waitForSlot(current);
}

test "waitForSlot returns aborted on stop" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
        .slot_duration_ms = 2_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var fut = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 100 });
    try rendezvousWaiters(&clock, io_handle, 1);
    clock.stop();
    try testing.expectError(error.Aborted, fut.await(io_handle));
}

test "waitForSlot on a stopped clock returns error.Aborted" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    clock.stop();
    // The stopped pre-check errors synchronously, before any enqueue or suspend.
    try testing.expectError(error.Aborted, clock.waitForSlot(1));
}

test "offSlot/offEpoch stop event delivery" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    const slot_id = try clock.onSlot(EventTraceState.onSlot, &trace);
    const epoch_id = try clock.onEpoch(EventTraceState.onEpoch, &trace);
    try testing.expect(clock.offSlot(slot_id));
    try testing.expect(clock.offEpoch(epoch_id));

    // Backlog slots 0..6 (epoch 1 at slot 4) with both listeners removed.
    fake.ms = 106_000;
    try testing.expectEqual(@as(?Slot, 6), clock.currentSlot());
    try testing.expectEqual(@as(usize, 0), trace.slot_len);
    try testing.expectEqual(@as(usize, 0), trace.epoch_len);
}

test "stop/join are idempotent" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 2,
        .slot_duration_ms = 2_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    clock.stop();
    clock.stop();
    clock.join();
    clock.join();
}

test "epoch event is delivered when crossing epoch boundary" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Backlog slots 0..5; the epoch-1 boundary is crossed at slot 4.
    fake.ms = 105_000;
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());

    try testing.expect(trace.slot_len > 0);
    try testing.expect(trace.epoch_len > 0);
    try testing.expectEqual(@as(u64, 1), trace.epochs[0]);
}

test "multiple waiters are dispatched in target-slot order" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var fake = FakeClockIo{ .ms = 99_000, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    // Spawn the waiters as fibers (targets out of order) and rendezvous so all
    // three have suspended before the clock advances.
    var fut5 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 5 });
    var fut3 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 3 });
    var fut1 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 1 });
    try rendezvousWaiters(&clock, io_handle, 3);

    fake.ms = 103_000;
    _ = clock.currentSlot();

    try fut1.await(io_handle);
    try fut3.await(io_handle);

    clock.stop();
    try testing.expectError(error.Aborted, fut5.await(io_handle));
}

test "real-time: no slot events emitted before genesis" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 5,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
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
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = base_now,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    const before_ms = time.nowMs(io_handle);
    try clock.waitForSlot(start_slot + 1);
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
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = base_now,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    try clock.waitForSlot(start_slot + 2);

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
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    });
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
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = base_now,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    try clock.waitForSlot(start_slot + 3);

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
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    var ctx_a = ReentrancyCtx{ .clock = &clock };
    var ctx_b = ReentrancyCtx{ .clock = &clock };
    const id_a = try clock.onSlot(ReentrancyCtx.offSelf, &ctx_a);
    ctx_a.self_id = id_a;
    _ = try clock.onSlot(ReentrancyCtx.justCount, &ctx_b);

    // Slot 0 fires both; A removes itself. Slots 1..2 then fire only B.
    fake.ms = 100_000;
    _ = clock.currentSlot();
    fake.ms = 102_000;
    _ = clock.currentSlot();

    try testing.expectEqual(@as(usize, 1), ctx_a.fired_count);
    try testing.expectEqual(@as(usize, 3), ctx_b.fired_count);
}

test "reentrancy: callback can stop the clock; no further slots emitted" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    var ctx = ReentrancyCtx{ .clock = &clock };
    _ = try clock.onSlot(ReentrancyCtx.stopClock, &ctx);

    // Backlog slots 0..5; the slot-0 callback stops the clock, so the drain
    // exits with the cursor still at 0 and no further slots emitted.
    fake.ms = 105_000;
    _ = clock.currentSlot();

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

    var fake = FakeClockIo{ .ms = 99_000, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    // Listener calls stop() while slot `target` is being emitted, i.e.
    // after current_slot reaches `target` but before dispatchWaiters runs.
    const target: Slot = 3;
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = target };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    var fut_reached = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target });
    var fut_future = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target + 1 });
    try rendezvousWaiters(&clock, io_handle, 2);

    fake.ms = slot_math.slotStartMs(clock.config, target);
    _ = clock.currentSlot();

    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, target), clock.current_slot);
    // Reached slot happened, so the wait must resolve, not abort.
    try fut_reached.await(io_handle);
    // Future slot can never be emitted after stop, so it aborts.
    try testing.expectError(error.Aborted, fut_future.await(io_handle));
}

test "ListenerLimitReached: onSlot/onEpoch reject the (limit+1)th registration" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: Clock = undefined;
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
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
    try clock.init(testing.allocator, io_handle, .{
        .genesis_time_sec = time.nowSec(io_handle) + 1_000_000,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    // Seed the queue to its limit directly rather than spawning 1024 fibers:
    // waitForSlot rejects synchronously once the queue is full, before any
    // suspend. deinit's abortAllWaiters then sets each dummy event harmlessly
    // on the real zio io.
    var dummies = [_]WaitState{.{}} ** max_waiters;
    for (&dummies) |*d| {
        clock.waiters.push(testing.allocator, .{ .target = 999_999, .state = d }) catch unreachable;
    }

    try testing.expectError(error.WaiterLimitReached, clock.waitForSlot(999_999));
}

test "many waiters at same target slot all resolve on advance" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    var fake = FakeClockIo{ .ms = 99_000, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
    defer clock.deinit();

    const N = 16;
    var futs: [N]std.Io.Future(Error!void) = undefined;
    for (&futs) |*f| f.* = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 5 });
    try rendezvousWaiters(&clock, io_handle, N);

    fake.ms = 105_000;
    _ = clock.currentSlot();

    for (&futs) |*f| try f.await(io_handle);
}

// Test io with a steerable wall clock. With `inner` null (the default) any
// call besides `now` crashes — the test must stay synchronous. Fiber tests
// set `inner` to a real zio io: the two futex entries forward to it so
// waitForSlot fibers genuinely suspend and wake; everything else still crashes.
const FakeClockIo = struct {
    ms: u64 = 0,
    inner: ?std.Io = null,

    fn vtableNow(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        _ = clock;
        const self: *const FakeClockIo = @ptrCast(@alignCast(userdata.?));
        return std.Io.Timestamp.fromNanoseconds(@as(i96, @intCast(self.ms)) * std.time.ns_per_ms);
    }
    fn vtableFutexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
        const self: *const FakeClockIo = @ptrCast(@alignCast(userdata.?));
        const inner = self.inner.?;
        inner.vtable.futexWaitUncancelable(inner.userdata, ptr, expected);
    }
    fn vtableFutexWake(userdata: ?*anyopaque, ptr: *const u32, max: u32) void {
        const self: *const FakeClockIo = @ptrCast(@alignCast(userdata.?));
        const inner = self.inner.?;
        inner.vtable.futexWake(inner.userdata, ptr, max);
    }
    const vtable: std.Io.VTable = blk: {
        var vt: std.Io.VTable = undefined;
        vt.now = vtableNow;
        vt.futexWaitUncancelable = vtableFutexWaitUncancelable;
        vt.futexWake = vtableFutexWake;
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
    try clock.init(testing.allocator, fake.io(), test_cfg);
    defer clock.deinit();

    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(?Epoch, null), clock.currentEpoch());
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotOrGenesis());
    try testing.expectEqual(@as(Epoch, 0), clock.currentEpochOrGenesis());
}

test "currentSlot at genesis and advancing" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), test_cfg);
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
    try clock.init(testing.allocator, fake.io(), test_cfg);
    defer clock.deinit();

    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
}

test "advanceTo produces correct slot events" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), test_cfg);
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
    try clock.init(testing.allocator, fake.io(), test_cfg);
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
    try clock.init(testing.allocator, fake.io(), test_cfg);
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
    try clock.init(testing.allocator, fake.io(), test_cfg);
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    });
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Wall slot 1 with the cache at 0: a catchUp-backed accessor would flush
    // this backlog to the listener; these pure-read helpers must not.
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

test "stop() from a catchUp callback aborts the wait before enqueue" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    // A slot listener stops the clock mid-catchUp, after current_slot has
    // advanced but before it reaches `target`. The post-catchUp re-check must
    // abort synchronously: reaching the enqueue+suspend would panic in
    // FakeClockIo's futex forwarder (`inner` is unset here).
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    // Backlog slots 1..5 so catchUp fires the listener while short of target 10.
    fake.ms = 105_000;
    try testing.expectError(error.Aborted, clock.waitForSlot(10));
    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, 1), clock.current_slot);
}

test "stop() from a catchUp callback still resolves a reached wait" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    // The listener stops the clock while slot 1 — the wait target — is being
    // emitted. The reached-check runs before the stopped re-check, so the wait
    // must return success synchronously, never suspending.
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    fake.ms = 101_000;
    try clock.waitForSlot(1);
    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, 1), clock.current_slot);
}

test "waitForSlot reached-check consults the cursor, not the catch-up reading" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    // Backlog to slot 3 with the listener stopping the clock at slot 1: the
    // catch-up reading (3) reaches the target but the cursor stops at 1, and
    // slot 2's event is suppressed. The reached-check must consult the cursor,
    // so the wait aborts synchronously instead of resolving.
    fake.ms = 103_000;
    try testing.expectError(error.Aborted, clock.waitForSlot(2));
    try testing.expect(clock.stopped);
    try testing.expectEqual(@as(?Slot, 1), clock.current_slot);
}

const MutateAndQueryCtx = struct {
    clock: *Clock,
    fake: *FakeClockIo,
    add_ctx: *EventTraceState,
    remove_id: ListenerId = 0,
    fired_once: bool = false,
    slots: [4]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *MutateAndQueryCtx = @ptrCast(@alignCast(ctx.?));
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

test "listener mutations mid-emit preserve the per-emit snapshot; a query defers delivery" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx_l2 = EventTraceState{};
    var ctx_l3 = EventTraceState{};
    var ctx_l4 = EventTraceState{};
    var ctx_l1 = MutateAndQueryCtx{ .clock = &clock, .fake = &fake, .add_ctx = &ctx_l4 };
    _ = try clock.onSlot(MutateAndQueryCtx.onSlot, &ctx_l1);
    const id_l2 = try clock.onSlot(EventTraceState.onSlot, &ctx_l2);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_l3);
    ctx_l1.remove_id = id_l2;

    // Wall slot 1: the emit snapshots [L1, L2, L3]. L1 burns the wall to
    // slot 2, removes L2, adds L4, and queries — recording target 2 without
    // nesting a dispatch. The drain then emits slot 2 to the post-mutation
    // list [L1, L3, L4].
    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2 }, ctx_l1.slots[0..ctx_l1.slot_len]);
    try expectEqualSlices(Slot, &.{1}, ctx_l2.slots[0..ctx_l2.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2 }, ctx_l3.slots[0..ctx_l3.slot_len]);
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
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    });
    defer clock.deinit();

    var ctx_e2 = EventTraceState{};
    var ctx_e3 = EventTraceState{};
    var ctx_e1 = EpochMutateCtx{ .clock = &clock, .add_ctx = &ctx_e3 };
    _ = try clock.onEpoch(EpochMutateCtx.onEpoch, &ctx_e1);
    const id_e2 = try clock.onEpoch(EventTraceState.onEpoch, &ctx_e2);
    ctx_e1.remove_id = id_e2;

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

test "backlog query-from-callback delivers every (listener, slot) exactly once in order" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    var ctx_r = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_r);

    // Q queries at slot 1 while slots 1..3 are backlogged; the query records
    // target 3 (and returns 3) but defers delivery. The drain then delivers 2
    // and 3 to every listener in order, so R sees 1, 2, 3.
    fake.ms = 103_000;
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, ctx_r.slots[0..ctx_r.slot_len]);
    try testing.expectEqual(@as(?Slot, 3), ctx_q.queried_slot);
}

test "non-backlog query-from-callback is a no-op" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    var ctx_r = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_r);

    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{1}, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Slot, &.{1}, ctx_r.slots[0..ctx_r.slot_len]);
    try testing.expectEqual(@as(?Slot, 1), ctx_q.queried_slot);
}

test "epoch events under deferred dispatch arrive in order exactly once" {
    var fake = FakeClockIo{ .ms = 102_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    });
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

    // Emitting slot 4 crosses into epoch 1; Q's query then burns to slot 8
    // (epoch 2), recording target 8. The epoch-1 event is delivered as the
    // outer emit finishes, and epoch 2 by the drain — so epochs arrive 1, 2.
    fake.ms = 104_000;
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 3, 4, 5, 6, 7, 8 }, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Epoch, &.{ 1, 2 }, trace.epochs[0..trace.epoch_len]);
    try testing.expectEqual(@as(?Slot, 8), ctx_q.queried_slot);
}

const BacklogWitnessCtx = struct {
    clock: *Clock,
    last_slot: Slot = 0,
    slot_count: u64 = 0,
    epoch_count: u64 = 0,
    order_ok: bool = true,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *BacklogWitnessCtx = @ptrCast(@alignCast(ctx.?));
        if (slot != self.last_slot + 1) self.order_ok = false;
        self.last_slot = slot;
        self.slot_count += 1;
        _ = self.clock.currentSlot();
    }

    fn onEpoch(ctx: ?*anyopaque, _: Epoch) void {
        const self: *BacklogWitnessCtx = @ptrCast(@alignCast(ctx.?));
        self.epoch_count += 1;
    }
};

test "big backlog drains in a flat loop without per-slot nesting" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 32,
    });
    defer clock.deinit();

    var ctx = BacklogWitnessCtx{ .clock = &clock };
    _ = try clock.onSlot(BacklogWitnessCtx.onSlot, &ctx);
    _ = try clock.onEpoch(BacklogWitnessCtx.onEpoch, &ctx);

    // A 32_768-slot backlog with a query on every callback: per-slot dispatch
    // recursion would overflow the fiber stack, so the drain must stay a flat
    // loop, delivering each slot once.
    const backlog: u64 = 32_768;
    fake.ms = 100_000 + backlog * 1_000;
    try testing.expectEqual(@as(?Slot, 32_768), clock.currentSlot());

    try testing.expect(ctx.order_ok);
    try testing.expectEqual(@as(u64, 32_768), ctx.slot_count);
    try testing.expectEqual(@as(u64, 1_024), ctx.epoch_count);
    try testing.expectEqual(@as(?Slot, 32_768), clock.current_slot);
}

const RunAheadLog = struct {
    const Tag = enum { a_slot, b_slot, a_query };
    const Entry = struct { tag: Tag, value: u64 };

    entries: [16]Entry = undefined,
    len: usize = 0,

    fn record(self: *RunAheadLog, tag: Tag, value: u64) void {
        if (self.len >= self.entries.len) return;
        self.entries[self.len] = .{ .tag = tag, .value = value };
        self.len += 1;
    }
};

const RunAheadA = struct {
    clock: *Clock,
    log: *RunAheadLog,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *RunAheadA = @ptrCast(@alignCast(ctx.?));
        self.log.record(.a_slot, slot);
        if (slot != 1) return;
        self.log.record(.a_query, self.clock.currentSlot().?);
    }
};

const RunAheadB = struct {
    log: *RunAheadLog,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *RunAheadB = @ptrCast(@alignCast(ctx.?));
        self.log.record(.b_slot, slot);
    }
};

test "a mid-emit query returns a reading ahead of deferred delivery" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var log = RunAheadLog{};
    var ctx_a = RunAheadA{ .clock = &clock, .log = &log };
    var ctx_b = RunAheadB{ .log = &log };
    _ = try clock.onSlot(RunAheadA.onSlot, &ctx_a);
    _ = try clock.onSlot(RunAheadB.onSlot, &ctx_b);

    // Backlog 1..3. While emitting slot 1, A queries: the reading returns 3
    // (the wall) though only slot 1 has been delivered. B then gets slot 1, and
    // the drain delivers 2 and 3 to both after A's callback returns.
    fake.ms = 103_000;
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    const E = RunAheadLog.Entry;
    try expectEqualSlices(E, &.{
        .{ .tag = .a_slot, .value = 1 },
        .{ .tag = .a_query, .value = 3 },
        .{ .tag = .b_slot, .value = 1 },
        .{ .tag = .a_slot, .value = 2 },
        .{ .tag = .b_slot, .value = 2 },
        .{ .tag = .a_slot, .value = 3 },
        .{ .tag = .b_slot, .value = 3 },
    }, log.entries[0..log.len]);
}

test "successive mid-emit queries coalesce to the furthest pending target" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx_l1 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = 103_000,
    };
    var ctx_l2 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = 105_000,
    };
    var ctx_l3 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = 104_000,
    };
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l1);
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l2);
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l3);

    // Emitting slot 1, the three queries burn the wall to slots 3, 5, then
    // BACK to 4. @max holds pending at 5: keeping the first target would
    // stall the drain at 3, and a plain overwrite would regress it to 4.
    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l1.slots[0..ctx_l1.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l2.slots[0..ctx_l2.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l3.slots[0..ctx_l3.slot_len]);
    try testing.expectEqual(@as(?Slot, 3), ctx_l1.queried_slot);
    try testing.expectEqual(@as(?Slot, 5), ctx_l2.queried_slot);
    try testing.expectEqual(@as(?Slot, 4), ctx_l3.queried_slot);
    try testing.expectEqual(@as(?Slot, 5), clock.current_slot);
}

const QueryThenStopCtx = struct {
    clock: *Clock,
    queried_slot: ?Slot = null,
    slots: [8]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *QueryThenStopCtx = @ptrCast(@alignCast(ctx.?));
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
        if (slot != 1) return;
        self.queried_slot = self.clock.currentSlot();
        self.clock.stop();
    }
};

test "stop() after a mid-emit query leaves no pending target behind" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var ctx = QueryThenStopCtx{ .clock = &clock };
    _ = try clock.onSlot(QueryThenStopCtx.onSlot, &ctx);

    // Backlog 1..3: at slot 1 the callback queries (recording pending target
    // 3, reading 3) and then stops. The exit backstop must clear the recorded
    // pending or the next accessor's catchUp would trip the
    // `pending_target == null` assert.
    fake.ms = 103_000;
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try testing.expectEqual(@as(?Slot, 3), ctx.queried_slot);

    // The post-stop accessor dispatches nothing and stays a pure reading:
    // cursor unchanged, suppressed slots 2..3 never delivered.
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try testing.expectEqual(@as(?Slot, 1), clock.current_slot);
    try expectEqualSlices(Slot, &.{1}, ctx.slots[0..ctx.slot_len]);
}

test "top-level wall step-back never regresses the cursor or emits" {
    var fake = FakeClockIo{ .ms = 100_000 };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    });
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Advance to slot 3, then step the wall back to slot 1. The returned slot
    // follows the wall down; the walk target is behind the cursor, so nothing
    // re-emits and the cursor holds at 3.
    fake.ms = 103_000;
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    fake.ms = 101_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try testing.expectEqual(@as(?Slot, 3), clock.current_slot);
    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, trace.slots[0..trace.slot_len]);
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
    stop,
};

const PropertyWaiter = struct {
    target: Slot,
    fut: std.Io.Future(Error!void),
    expected_aborted: bool,
};

const PropertyState = struct {
    spe: u64,
    io: std.Io,
    fake: *FakeClockIo,
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
                self.fake.ms = slot_math.slotStartMs(self.clock.config, s_last);
                _ = self.clock.currentSlot();

                for (self.waiters.items) |*w| {
                    if (w.target <= s_last) w.expected_aborted = false;
                }
            },
            .wait_for_slot_at_offset => |offset| {
                const base: i64 = if (self.model_current_slot) |c| @intCast(c) else -1;
                const target_signed = base + offset;
                if (target_signed < 0) return;
                const target: Slot = @intCast(target_signed);

                if (self.model_stopped) {
                    // Stopped clock: waitForSlot rejects synchronously, no suspend.
                    try testing.expectError(error.Aborted, self.clock.waitForSlot(target));
                    return;
                }
                const resolved_now = if (self.model_current_slot) |c| c >= target else false;
                if (resolved_now) {
                    // Already reached: resolves synchronously with success.
                    try self.clock.waitForSlot(target);
                    return;
                }
                // Future target: the call would suspend, so run it on its own
                // fiber and rendezvous so the queue entry lands before the next
                // model step (without it the push races an unpredictable yield).
                // It aborts at finalize unless a later advance reaches it.
                const target_count = self.clock.waiters.count() + 1;
                const fut = try std.Io.concurrent(
                    self.io,
                    Clock.waitForSlot,
                    .{ self.clock, target },
                );
                try rendezvousWaiters(self.clock, self.io, target_count);
                try self.waiters.append(a, .{
                    .target = target,
                    .fut = fut,
                    .expected_aborted = true,
                });
            },
            .stop => {
                if (self.model_stopped) return;
                self.model_stopped = true;
                self.clock.stop();
            },
        }
    }

    fn finalize(self: *PropertyState) !void {
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
            const result = w.fut.await(self.io);
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
        if (r < 98) {
            const off: i32 = @as(i32, @intCast(rng.uintLessThan(u32, 12))) - 4;
            return .{ .wait_for_slot_at_offset = off };
        }
        return .stop;
    }
}

fn runPropertyScenario(seed: u64, op_count: u32, io: std.Io) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    const spe: u64 = 4;
    var fake = FakeClockIo{ .ms = 99_000, .inner = io };
    var clock: Clock = undefined;
    // Fake time moves only inside .advance_by, so the model owns every advance.
    try clock.init(testing.allocator, fake.io(), .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = spe,
    });
    defer clock.deinit();

    var state = PropertyState{ .spe = spe, .io = io, .fake = &fake, .clock = &clock };
    defer state.deinit();

    var i: u32 = 0;
    while (i < op_count) : (i += 1) {
        const op = genPropertyOp(rng, &state);
        try state.applyOp(op);
    }

    try state.finalize();
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
