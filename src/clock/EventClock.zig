//! Layer 2 – Event-driven beacon clock.
//!
//! Combines `SlotClock` with an async I/O loop to emit slot/epoch events
//! and dispatch waiters.  All public methods are safe to call from the
//! main thread; the internal loop runs as a single cooperative fiber.

const std = @import("std");
const Allocator = std.mem.Allocator;
const slot_math = @import("slot_math.zig");
const SlotClock = @import("SlotClock.zig");
const time_source = @import("time_source.zig");

const EventClock = @This();

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const Config = slot_math.Config;
pub const ListenerId = u64;
pub const TimeSource = time_source.TimeSource;

pub const Error = error{
    InvalidConfig,
    OutOfMemory,
    ListenerLimitReached,
    Aborted,
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

allocator: Allocator,
io: std.Io,
clock: SlotClock,

stopped: bool = false,
loop_future: ?std.Io.Future(void) = null,

next_listener_id: ListenerId = 1,
slot_listeners: std.ArrayListUnmanaged(SlotListenerEntry) = .{},
epoch_listeners: std.ArrayListUnmanaged(EpochListenerEntry) = .{},
slot_snapshot: std.ArrayListUnmanaged(SlotSnapshot) = .{},
epoch_snapshot: std.ArrayListUnmanaged(EpochSnapshot) = .{},

waiters: WaiterQueue,

/// Initialise in-place.  Takes `*EventClock` (not returning by value)
/// because `TimeSource.fromIo` stores a pointer into `self.io`, making
/// the struct self-referential.
pub fn init(self: *EventClock, allocator: Allocator, config: Config, io_handle: std.Io) Error!void {
    self.* = .{
        .allocator = allocator,
        .io = io_handle,
        .clock = undefined,
        .waiters = WaiterQueue.initContext({}),
    };
    self.clock = SlotClock.init(config, TimeSource.fromIo(&self.io)) catch return error.InvalidConfig;
}

/// Start the auto-advance loop.  Idempotent; second call is a no-op.
pub fn start(self: *EventClock) void {
    if (self.loop_future != null) return;
    self.loop_future = std.Io.async(self.io, EventClock.runAutoLoop, .{self});
}

/// Signal the loop to stop and abort all pending waiters.  Idempotent.
pub fn stop(self: *EventClock) void {
    if (self.stopped) return;
    self.stopped = true;
    self.abortAllWaiters();
}

/// Cancel the loop fiber and wait for it to finish.
pub fn join(self: *EventClock) void {
    var maybe_future = self.loop_future;
    self.loop_future = null;
    if (maybe_future) |*future| {
        future.cancel(self.io);
    }
}

/// Release all resources.  Calls `stop()` + `join()` internally.
pub fn deinit(self: *EventClock) void {
    self.stop();
    self.join();
    self.slot_snapshot.deinit(self.allocator);
    self.epoch_snapshot.deinit(self.allocator);
    self.slot_listeners.deinit(self.allocator);
    self.epoch_listeners.deinit(self.allocator);
    self.waiters.deinit(self.allocator);
    self.* = undefined;
}

// ── Listener API ──
// NOTE: Listeners should be registered before calling `start()`.
// Adding listeners from within a callback may silently skip the new listener
// until the next slot, because snapshot buffers are pre-allocated at registration
// time and emitSlot/emitEpoch only use pre-allocated capacity.

/// Register a slot listener.  Returns an ID for later removal via `offSlot`.
pub fn onSlot(
    self: *EventClock,
    callback: *const fn (ctx: ?*anyopaque, slot: Slot) void,
    ctx: ?*anyopaque,
) Error!ListenerId {
    if (self.next_listener_id == std.math.maxInt(ListenerId))
        return error.ListenerLimitReached;
    // Pre-allocate snapshot buffer BEFORE appending the listener, so that
    // if OOM occurs we haven't modified any state yet.
    self.slot_snapshot.ensureTotalCapacity(
        self.allocator,
        self.slot_listeners.items.len + 1,
    ) catch return error.OutOfMemory;
    self.slot_listeners.append(self.allocator, .{
        .id = self.next_listener_id,
        .callback = callback,
        .ctx = ctx,
    }) catch return error.OutOfMemory;
    const id = self.next_listener_id;
    self.next_listener_id += 1;
    return id;
}

/// Unregister a slot listener.  Returns `true` if found and removed.
pub fn offSlot(self: *EventClock, id: ListenerId) bool {
    for (self.slot_listeners.items, 0..) |listener, i| {
        if (listener.id == id) {
            _ = self.slot_listeners.orderedRemove(i);
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
    if (self.next_listener_id == std.math.maxInt(ListenerId))
        return error.ListenerLimitReached;
    // Pre-allocate snapshot buffer BEFORE appending the listener, so that
    // if OOM occurs we haven't modified any state yet.
    self.epoch_snapshot.ensureTotalCapacity(
        self.allocator,
        self.epoch_listeners.items.len + 1,
    ) catch return error.OutOfMemory;
    self.epoch_listeners.append(self.allocator, .{
        .id = self.next_listener_id,
        .callback = callback,
        .ctx = ctx,
    }) catch return error.OutOfMemory;
    const id = self.next_listener_id;
    self.next_listener_id += 1;
    return id;
}

/// Unregister an epoch listener.  Returns `true` if found and removed.
pub fn offEpoch(self: *EventClock, id: ListenerId) bool {
    for (self.epoch_listeners.items, 0..) |listener, i| {
        if (listener.id == id) {
            _ = self.epoch_listeners.orderedRemove(i);
            return true;
        }
    }
    return false;
}

// ── Delegated read APIs ──
// Every public accessor that exposes "current" slot/epoch state calls catchUp()
// first, matching the TS version where `get currentSlot()` triggers event
// emission before returning.  Pure time-arithmetic helpers (slotWithFutureTolerance,
// secFromSlot, etc.) do NOT catch up, matching TS which doesn't go through
// `this.currentSlot` for those.

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

pub fn slotWithFutureTolerance(self: *EventClock, tolerance_ms: u64) ?Slot {
    return self.clock.slotWithFutureTolerance(tolerance_ms);
}

pub fn slotWithPastTolerance(self: *EventClock, tolerance_ms: u64) ?Slot {
    return self.clock.slotWithPastTolerance(tolerance_ms);
}

pub fn secFromSlot(self: *EventClock, slot: Slot, to_sec: ?slot_math.UnixSec) ?i64 {
    return self.clock.secFromSlot(slot, to_sec);
}

pub fn msFromSlot(self: *EventClock, slot: Slot, to_ms: ?slot_math.UnixMs) ?i64 {
    return self.clock.msFromSlot(slot, to_ms);
}

// ── waitForSlot ──

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
        // Free AFTER await returns — workaround for Zig futex use-after-free
        // where GCD still holds a reference to the event address after wake.
        if (self.state) |s| s.allocator.destroy(s);
        self.state = null;
        self.clock = null;
        return result;
    }

    /// Abort a pending wait and release its resources.  Idempotent — safe
    /// to call on an already-awaited, already-cancelled, or immediate result.
    ///
    /// Typical usage:
    ///   var fut = try ec.waitForSlot(target);
    ///   errdefer fut.cancel();
    ///   try fut.await(io);
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
    // Catch up events then check fast-path against advanced state.
    self.catchUp();
    if (self.clock.current_slot) |slot| {
        if (slot >= target) {
            return WaitForSlotResult.immediate({});
        }
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

    return .{
        .inner = std.Io.async(self.io, waitForSlotFutureAwait, .{state}),
        .state = state,
        .clock = self,
    };
}

// ── Private ──

/// Ensure event-clock state is caught up to wall-clock time.
/// Emits any intermediate slot/epoch events to listeners.
/// No-op if already caught up or pre-genesis (currentSlot() returns null).
/// Safe to call from any fiber — cooperative scheduling guarantees no
/// concurrent access (same model as TS's single-threaded event loop).
fn catchUp(self: *EventClock) void {
    if (self.clock.currentSlot()) |wall_slot| {
        self.advanceAndDispatch(wall_slot);
    }
}

fn emitSlot(self: *EventClock, slot: Slot) void {
    self.slot_snapshot.clearRetainingCapacity();
    // Use only pre-allocated capacity — no allocation in fiber context.
    const limit = @min(self.slot_listeners.items.len, self.slot_snapshot.capacity);
    for (self.slot_listeners.items[0..limit]) |listener| {
        self.slot_snapshot.appendAssumeCapacity(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }

    for (self.slot_snapshot.items) |listener| {
        listener.callback(listener.ctx, slot);
    }
}

fn emitEpoch(self: *EventClock, epoch: Epoch) void {
    self.epoch_snapshot.clearRetainingCapacity();
    // Use only pre-allocated capacity — no allocation in fiber context.
    const limit = @min(self.epoch_listeners.items.len, self.epoch_snapshot.capacity);
    for (self.epoch_listeners.items[0..limit]) |listener| {
        self.epoch_snapshot.appendAssumeCapacity(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }

    for (self.epoch_snapshot.items) |listener| {
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
    while (iter.next()) |event| {
        if (self.stopped) break;
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

        // Sleep failure (e.g., cancel from join()) is expected —
        // re-check `stopped` flag before continuing.
        std.Io.sleep(
            self.io,
            std.Io.Duration.fromMilliseconds(sleep_ms),
            .awake,
        ) catch |err| {
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
}

fn waitForSlotFutureAwait(state: *WaitState) Error!void {
    // NOTE: Do NOT free state here. The caller (WaitForSlotResult.await) frees
    // it AFTER this future completes — workaround for Zig futex use-after-free
    // where GCD still holds a reference to the event address after wake.
    state.event.waitUncancelable(state.io);
    if (state.aborted) return error.Aborted;
}

// ── Tests ──

const testing = std.testing;

const TestIo = struct {
    evented: std.Io.Evented = undefined,

    fn init(self: *TestIo) !void {
        self.* = .{ .evented = undefined };
        try self.evented.init(std.heap.page_allocator, .{});
    }

    fn deinit(self: *TestIo) void {
        self.evented.deinit();
    }

    fn io(self: *TestIo) std.Io {
        return self.evented.io();
    }
};

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
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();
    const base_now = nowSecAt(io_handle);

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = base_now,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(start_slot + 1);
    errdefer fut.cancel();
    try fut.await(io_handle);

    try testing.expect(trace.slot_len > 0);
}

test "waitForSlot resolves immediately when at target" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();
    const base_now = nowSecAt(io_handle);

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = base_now,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    const current = clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(current);
    errdefer fut.cancel();
    try fut.await(io_handle);
}

test "waitForSlot returns aborted on stop" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 2,
        .seconds_per_slot = 2,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var fut = try clock.waitForSlot(100);
    errdefer fut.cancel();
    clock.stop();
    try testing.expectError(error.Aborted, fut.await(io_handle));
}

test "offSlot/offEpoch stop event delivery" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 2,
        .seconds_per_slot = 1,
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
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 2,
        .seconds_per_slot = 2,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    clock.stop();
    clock.stop();
    clock.join();
    clock.join();
}

test "epoch event is delivered when crossing epoch boundary" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 2,
        .seconds_per_slot = 1,
        .slots_per_epoch = 4,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Advance from null through epoch boundary at slot 4
    clock.advanceAndDispatch(5);

    try testing.expect(trace.slot_len > 0);
    try testing.expect(trace.epoch_len > 0);
    try testing.expectEqual(@as(u64, 1), trace.epochs[0]);
}

test "multiple waiters are dispatched in target-slot order" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 10,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    // Register waiters for slots 5, 3, 1 (out of order)
    var fut5 = try clock.waitForSlot(5);
    errdefer fut5.cancel();
    var fut3 = try clock.waitForSlot(3);
    errdefer fut3.cancel();
    var fut1 = try clock.waitForSlot(1);
    errdefer fut1.cancel();

    // Advance to slot 3 — should dispatch slot 1 and slot 3, NOT slot 5
    clock.advanceAndDispatch(3);

    try fut1.await(io_handle);
    try fut3.await(io_handle);

    // fut5 should still be pending. Stop to abort it.
    clock.stop();
    try testing.expectError(error.Aborted, fut5.await(io_handle));
}

test "cancel releases WaitState without awaiting" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 10,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    // Create a waiter for a far-future slot and immediately cancel it.
    // testing.allocator will detect a leak if cancel fails to free.
    var fut = try clock.waitForSlot(999);
    fut.cancel();
}

// ── Real-time tests ──
// These tests exercise `runAutoLoop` (the production code path) by calling
// `clock.start()` and letting wall-clock time drive slot advancement.

test "real-time: no slot events emitted before genesis" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 5, // genesis 5s in the future
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    clock.start();

    // Sleep 1.5s — the loop will tick several times, all pre-genesis.
    std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(1500), .awake) catch {};

    // No slot events should have been emitted before genesis.
    try testing.expectEqual(@as(usize, 0), trace.slot_len);
}

test "real-time: slot events fire with correct timing" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();
    const base_now = nowSecAt(io_handle);

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = base_now,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    const before_ms = nowMsAt(io_handle);
    var fut = try clock.waitForSlot(start_slot + 1);
    errdefer fut.cancel();
    try fut.await(io_handle);
    const elapsed = nowMsAt(io_handle) - before_ms;

    // Should wait roughly 0-1s for the next slot boundary.
    // Generous upper bound avoids flaky CI.
    try testing.expect(elapsed < 2000);
    try testing.expect(trace.slot_len > 0);
    // The delivered slot number must match or exceed our target.
    try testing.expect(trace.slots[trace.slot_len - 1] >= start_slot + 1);
}

test "real-time: multi-slot advancement delivers ordered events" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();
    const base_now = nowSecAt(io_handle);

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = base_now,
        .seconds_per_slot = 1,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(start_slot + 2);
    errdefer fut.cancel();
    try fut.await(io_handle);

    // At least 2 slot events should have been emitted.
    try testing.expect(trace.slot_len >= 2);
    // Slots must be in strictly ascending order.
    for (1..trace.slot_len) |i| {
        try testing.expect(trace.slots[i] > trace.slots[i - 1]);
    }
}

test "real-time: stop+join cancels promptly" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 100, // far future
        .seconds_per_slot = 12, // long slot like mainnet
        .slots_per_epoch = 32,
    }, io_handle);
    defer clock.deinit();

    clock.start();

    // Give the loop fiber time to enter its sleep.
    std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(50), .awake) catch {};

    const before_ms = nowMsAt(io_handle);
    clock.stop();
    clock.join();
    const elapsed = nowMsAt(io_handle) - before_ms;

    // join() cancels the sleeping future directly, so it should return
    // almost immediately — NOT after the full 12-second slot duration.
    try testing.expect(elapsed < 1500);
}

test "real-time: epoch boundary event fires" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();
    const base_now = nowSecAt(io_handle);

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = base_now,
        .seconds_per_slot = 1,
        .slots_per_epoch = 2, // epoch boundary every 2 slots
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    // Wait enough slots to guarantee crossing at least one epoch boundary.
    var fut = try clock.waitForSlot(start_slot + 3);
    errdefer fut.cancel();
    try fut.await(io_handle);

    try testing.expect(trace.slot_len >= 3);
    // Must have seen at least one epoch transition.
    try testing.expect(trace.epoch_len > 0);
}
