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
    Canceled,
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

allocator: Allocator,
io: std.Io,
clock: SlotClock,

/// Coarse-grained mutex covering all mutable state below (waiters,
/// listeners, snapshots, next_listener_id, clock.current_slot via
/// advanceAndDispatch). Required when `io` is a multi-threaded backend
/// (`std.Io.Threaded`); cheap on a single-threaded fiber backend
/// (`std.Io.Evented`) — uncontended fast path is one atomic CAS.
///
/// Listener callbacks run OUTSIDE this mutex (see `advanceAndDispatch` —
/// each event snapshots the listener list under the mutex, then releases
/// before invoking callbacks). Callbacks may freely re-enter public API
/// methods such as `onSlot`, `offSlot`, `waitForSlot`, etc.
mutex: std.Io.Mutex = .init,

/// Serializes `advanceAndDispatch` callers so the shared snapshot buffers
/// have a single owner across the unlock/relock boundary, and so callback-
/// triggered re-entry into `advanceAndDispatch` (via `currentSlot` →
/// `catchUp`) returns immediately instead of recursing. CAS to true on
/// entry; first caller does the work, others observe true and return.
dispatching: std.atomic.Value(bool) = .init(false),

/// Read lock-free from `runAutoLoop` so the loop's sleep does not need
/// to hold the mutex.
stopped: std.atomic.Value(bool) = .init(false),
loop_future: ?std.Io.Future(void) = null,

next_listener_id: ListenerId = 1,
slot_listeners: std.ArrayListUnmanaged(SlotListenerEntry) = .empty,
epoch_listeners: std.ArrayListUnmanaged(EpochListenerEntry) = .empty,
slot_snapshot: std.ArrayListUnmanaged(SlotSnapshot) = .empty,
epoch_snapshot: std.ArrayListUnmanaged(EpochSnapshot) = .empty,

waiters: WaiterQueue,

/// Initialise in-place.
pub fn init(self: *EventClock, allocator: Allocator, config: Config, io_handle: std.Io) Error!void {
    self.* = .{
        .allocator = allocator,
        .io = io_handle,
        .clock = undefined,
        .waiters = WaiterQueue.initContext({}),
    };
    self.clock = SlotClock.init(config, .{ .real = .{ .io = io_handle } }) catch return error.InvalidConfig;
}

/// Start the auto-advance loop.  Idempotent; second call is a no-op.
///
/// Uses `std.Io.concurrent` (vs `async`) to guarantee the loop runs on a
/// fresh worker. `async` is allowed to run the function inline on
/// backends that can't spawn additional work (single-threaded build,
/// `Threaded` busy_count >= async_limit, OOM), which would block
/// `start()` indefinitely inside `runAutoLoop`.
pub fn start(self: *EventClock) Error!void {
    if (self.loop_future != null) return;
    self.loop_future = std.Io.concurrent(self.io, EventClock.runAutoLoop, .{self}) catch
        return error.ConcurrencyUnavailable;
}

/// Signal the loop to stop and abort all pending waiters.  Idempotent.
pub fn stop(self: *EventClock) void {
    if (self.stopped.swap(true, .acq_rel)) return;
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
    self.slot_snapshot.deinit(self.allocator);
    self.epoch_snapshot.deinit(self.allocator);
    self.slot_listeners.deinit(self.allocator);
    self.epoch_listeners.deinit(self.allocator);
    self.waiters.deinit(self.allocator);
    self.* = undefined;
}

// ── Listener API ──
// Listeners may be registered or removed at any time, including from within
// a callback. A listener added during dispatch becomes visible on the next
// event; one removed during dispatch may still receive the in-flight callback
// because the snapshot was already taken.

/// Register a slot listener.  Returns an ID for later removal via `offSlot`.
///
/// NOTE: snapshot buffer growth happens inside the dispatcher (see
/// `snapshotSlotListenersLocked`). This keeps `onSlot` from reallocating
/// `slot_snapshot` while the dispatcher iterates it outside the mutex.
pub fn onSlot(
    self: *EventClock,
    callback: *const fn (ctx: ?*anyopaque, slot: Slot) void,
    ctx: ?*anyopaque,
) Error!ListenerId {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
    if (self.next_listener_id == std.math.maxInt(ListenerId)) return error.ListenerLimitReached;
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
pub fn offSlot(self: *EventClock, id: ListenerId) Error!bool {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
    for (self.slot_listeners.items, 0..) |listener, i| {
        if (listener.id == id) {
            _ = self.slot_listeners.orderedRemove(i);
            return true;
        }
    }
    return false;
}

/// Register an epoch listener.  Returns an ID for later removal via `offEpoch`.
///
/// See `onSlot` for the snapshot ownership rules — `epoch_snapshot` is
/// resized exclusively by the dispatcher.
pub fn onEpoch(
    self: *EventClock,
    callback: *const fn (ctx: ?*anyopaque, epoch: Epoch) void,
    ctx: ?*anyopaque,
) Error!ListenerId {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
    if (self.next_listener_id == std.math.maxInt(ListenerId)) return error.ListenerLimitReached;
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
pub fn offEpoch(self: *EventClock, id: ListenerId) Error!bool {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
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

pub fn currentSlot(self: *EventClock) Error!?Slot {
    try self.catchUp();
    return self.clock.currentSlot();
}

pub fn currentEpoch(self: *EventClock) Error!?Epoch {
    try self.catchUp();
    return self.clock.currentEpoch();
}

pub fn currentSlotOrGenesis(self: *EventClock) Error!Slot {
    try self.catchUp();
    return self.clock.currentSlotOrGenesis();
}

pub fn currentEpochOrGenesis(self: *EventClock) Error!Epoch {
    try self.catchUp();
    return self.clock.currentEpochOrGenesis();
}

pub fn currentSlotWithGossipDisparity(self: *EventClock) Error!Slot {
    try self.catchUp();
    return self.clock.currentSlotWithGossipDisparity();
}

pub fn isCurrentSlotGivenGossipDisparity(self: *EventClock, slot: Slot) Error!bool {
    try self.catchUp();
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
///   try fut.await();
pub const WaitForSlotResult = union(enum) {
    immediate: Error!void,
    pending: Pending,

    pub const Pending = struct {
        inner: std.Io.Future(Error!void),
        state: *WaitState,
        clock: *EventClock,
    };

    pub fn await(self: *WaitForSlotResult) Error!void {
        switch (self.*) {
            .immediate => |r| return r,
            .pending => |*p| {
                // Use the io that created the future to avoid io-mismatch bugs.
                const result = p.inner.await(p.state.io);
                // Free AFTER await returns — workaround for Zig futex
                // use-after-free where GCD still holds a reference to the
                // event address after wake.
                p.state.allocator.destroy(p.state);
                self.* = .{ .immediate = result };
                return result;
            },
        }
    }

    /// Abort a pending wait and release its resources.  Idempotent — safe
    /// to call on an already-awaited, already-cancelled, or immediate result.
    pub fn cancel(self: *WaitForSlotResult) void {
        switch (self.*) {
            .immediate => return,
            .pending => |*p| {
                // Only write `state.aborted` if we actually own this waiter
                // (still in the queue under our mutex). If the dispatcher or
                // `abortAllWaiters` already popped it, they wrote the flag
                // themselves under the same mutex; racing them outside the
                // mutex would be a data race AND could turn a successfully
                // reached slot into `error.Aborted`.
                p.clock.mutex.lockUncancelable(p.clock.io);
                var canceled_in_place = false;
                for (p.clock.waiters.items, 0..) |entry, i| {
                    if (entry.state == p.state) {
                        _ = p.clock.waiters.popIndex(i);
                        p.state.aborted = true;
                        canceled_in_place = true;
                        break;
                    }
                }
                p.clock.mutex.unlock(p.clock.io);
                if (canceled_in_place) {
                    p.state.event.set(p.state.io);
                }
                // Must await the fiber so it finishes before we free its state.
                // Returns `error.Aborted` if WE flagged it, `error.Aborted` if
                // `abortAllWaiters` flagged it, or success if a slot dispatch
                // beat us.
                _ = p.inner.await(p.state.io) catch |err| {
                    std.debug.assert(err == error.Aborted);
                };
                p.state.allocator.destroy(p.state);
                self.* = .{ .immediate = error.Aborted };
            },
        }
    }
};

/// Return a future that resolves when the clock reaches `target`.
/// See `WaitForSlotResult` for the caller's obligations.
pub fn waitForSlot(self: *EventClock, target: Slot) Error!WaitForSlotResult {
    if (self.stopped.load(.acquire)) return .{ .immediate = error.Aborted };
    // Catch up events then check fast-path against advanced state.
    // catchUp invokes listener callbacks, so we must NOT hold the mutex
    // here — `advanceAndDispatch` takes it internally per state read.
    try self.catchUp();

    try self.mutex.lock(self.io);
    if (self.clock.current_slot) |slot| {
        if (slot >= target) {
            self.mutex.unlock(self.io);
            return .{ .immediate = {} };
        }
    }
    if (self.stopped.load(.acquire)) {
        self.mutex.unlock(self.io);
        return .{ .immediate = error.Aborted };
    }

    const state = self.allocator.create(WaitState) catch {
        self.mutex.unlock(self.io);
        return error.OutOfMemory;
    };
    state.* = .{
        .io = self.io,
        .allocator = self.allocator,
    };

    self.waiters.push(self.allocator, .{
        .target = target,
        .state = state,
    }) catch {
        self.allocator.destroy(state);
        self.mutex.unlock(self.io);
        return error.OutOfMemory;
    };
    self.dispatchWaitersLocked(self.clock.current_slot);
    // Release before spawning the task — `concurrent` must not be called
    // inside the EventClock mutex.
    self.mutex.unlock(self.io);

    // `concurrent` (vs `async`) guarantees the function runs on a fresh
    // worker; otherwise it returns `error.ConcurrencyUnavailable`. Without
    // this guarantee `std.Io.async` could legally invoke
    // `waitForSlotFutureAwait` inline (single-threaded build, OOM, or
    // `Threaded` busy_count >= async_limit), which would block the caller's
    // thread inside `event.waitUncancelable` and never return the
    // `WaitForSlotResult`.
    const future = std.Io.concurrent(self.io, waitForSlotFutureAwait, .{state}) catch {
        // Concurrent task couldn't be spawned. Undo our waiter registration
        // and free `state`. Use the uncancelable lock variant — this is a
        // cleanup path that must complete.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.waiters.items, 0..) |entry, i| {
            if (entry.state == state) {
                _ = self.waiters.popIndex(i);
                break;
            }
        }
        self.allocator.destroy(state);
        return error.ConcurrencyUnavailable;
    };

    return .{ .pending = .{
        .inner = future,
        .state = state,
        .clock = self,
    } };
}

// ── Private ──

/// Ensure event-clock state is caught up to wall-clock time.
/// Emits any intermediate slot/epoch events to listeners.
/// No-op if already caught up or pre-genesis (currentSlot() returns null).
fn catchUp(self: *EventClock) Error!void {
    if (self.clock.currentSlot()) |wall_slot| {
        try self.advanceAndDispatch(wall_slot);
    }
}

/// Caller must hold `self.mutex` and `self.dispatching` must be `true`
/// (snapshot buffer has a single writer at a time, namely the dispatcher).
fn snapshotSlotListenersLocked(self: *EventClock) error{OutOfMemory}!void {
    self.slot_snapshot.clearRetainingCapacity();
    try self.slot_snapshot.ensureTotalCapacity(self.allocator, self.slot_listeners.items.len);
    for (self.slot_listeners.items) |listener| {
        self.slot_snapshot.appendAssumeCapacity(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }
}

/// See `snapshotSlotListenersLocked`.
fn snapshotEpochListenersLocked(self: *EventClock) error{OutOfMemory}!void {
    self.epoch_snapshot.clearRetainingCapacity();
    try self.epoch_snapshot.ensureTotalCapacity(self.allocator, self.epoch_listeners.items.len);
    for (self.epoch_listeners.items) |listener| {
        self.epoch_snapshot.appendAssumeCapacity(.{
            .callback = listener.callback,
            .ctx = listener.ctx,
        });
    }
}

/// Caller must hold `self.mutex`.
fn dispatchWaitersLocked(self: *EventClock, current_slot: ?Slot) void {
    const slot = current_slot orelse return;
    while (self.waiters.peek()) |head| {
        if (head.target > slot) break;
        const waiter = self.waiters.pop().?;
        waiter.state.aborted = false;
        // event.set is thread-safe and does not need the mutex.
        waiter.state.event.set(waiter.state.io);
    }
}

fn abortAllWaiters(self: *EventClock) void {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    while (self.waiters.pop()) |waiter| {
        waiter.state.aborted = true;
        waiter.state.event.set(waiter.state.io);
    }
}

/// Advance the underlying clock to `target` and dispatch slot/epoch events.
///
/// Per event we hold the mutex only long enough to (a) advance one step via
/// `iter.next()`, (b) snapshot the listener list into the shared snapshot
/// buffer, and (c) wake any matching waiters. We then RELEASE the mutex
/// before invoking listener callbacks. This means callbacks may safely call
/// back into public `EventClock` methods (`onSlot`, `offSlot`,
/// `waitForSlot`, etc.) — those just take the mutex briefly and proceed.
///
/// Two concurrent dispatchers would race on the shared snapshot buffer
/// across the unlock/relock boundary. The `dispatching` atomic CAS makes
/// the second caller observe `true` and return immediately; the in-flight
/// dispatcher catches everyone up. It also short-circuits callback-driven
/// re-entry (callback → `currentSlot` → `catchUp` → here), preventing
/// recursion-style double dispatch.
fn advanceAndDispatch(self: *EventClock, target: Slot) Error!void {
    if (self.dispatching.cmpxchgStrong(false, true, .acq_rel, .monotonic) != null) {
        // Another fiber/thread is already advancing. We don't replay our
        // target on top of theirs, but the outer wall-clock recheck below
        // ensures that any time elapsed during their dispatch (including
        // anything WE just observed and wanted) is picked up before they
        // exit.
        return;
    }
    defer self.dispatching.store(false, .release);

    try self.mutex.lock(self.io);
    var current_target = target;
    while (true) {
        // Fresh iter per outer iteration. iter.next() returns null only
        // after draining its `pending_epoch` cursor, so recreating the
        // iter at this point cannot drop a queued epoch event.
        var iter = self.clock.advanceTo(current_target);
        while (true) {
            if (self.stopped.load(.acquire)) break;
            const event = iter.next() orelse break;
            switch (event) {
                .slot => |s| {
                    // OOM here happens AFTER iter.next() advanced the clock
                    // past `s`, so if we surface OOM the slot's listeners
                    // never fire. Acceptable: `runAutoLoop` stops the clock
                    // on OOM and the supervising layer restarts the process.
                    self.snapshotSlotListenersLocked() catch |err| {
                        self.mutex.unlock(self.io);
                        return err;
                    };
                    self.mutex.unlock(self.io);
                    for (self.slot_snapshot.items) |listener| {
                        listener.callback(listener.ctx, s);
                    }
                    try self.mutex.lock(self.io);
                    // Wake waiters AFTER listener callbacks have run, so a
                    // `waitForSlot(...).await()` resuming on another thread
                    // sees state the listener wrote. The relock provides
                    // release-acquire ordering.
                    self.dispatchWaitersLocked(s);
                },
                .epoch => |e| {
                    self.snapshotEpochListenersLocked() catch |err| {
                        self.mutex.unlock(self.io);
                        return err;
                    };
                    self.mutex.unlock(self.io);
                    for (self.epoch_snapshot.items) |listener| {
                        listener.callback(listener.ctx, e);
                    }
                    try self.mutex.lock(self.io);
                },
            }
        }
        if (self.stopped.load(.acquire)) break;
        // Wall-clock may have advanced during dispatch (slow callbacks, or
        // a concurrent caller wanted a higher target than ours and was
        // short-circuited via the dispatching CAS). Re-iter to cover it.
        const wall = self.clock.currentSlot() orelse break;
        if (wall > current_target) {
            current_target = wall;
            continue;
        }
        break;
    }
    // Defensive: handles the edge case where advanceTo yields zero events
    // (already at target) but waiters were added between loop ticks.
    self.dispatchWaitersLocked(self.clock.current_slot);
    self.mutex.unlock(self.io);
}

fn runAutoLoop(self: *EventClock) void {
    while (!self.stopped.load(.acquire)) {
        // Dispatch FIRST so that if a previous iteration's callbacks ran
        // longer than a slot, the slots that elapsed during them fire
        // immediately rather than waiting for the next boundary.
        // Pre-genesis currentSlot() returns null — skip dispatch and head
        // straight to the sleep that times us to the genesis boundary.
        if (self.clock.currentSlot()) |slot| {
            self.advanceAndDispatch(slot) catch |err| switch (err) {
                error.Canceled => break,
                // OOM is fail-fast: the listener snapshot grow is a tiny
                // alloc; if it fails the process is already in trouble.
                // Stop the clock and let the supervising layer restart.
                else => {
                    std.log.err("EventClock: dispatch failed ({s}), stopping loop", .{@errorName(err)});
                    self.stop();
                    break;
                },
            };
        }
        if (self.stopped.load(.acquire)) break;

        const now_ms = self.clock.time.nowMs();
        // Config validation guarantees sec→ms won't overflow, so null here
        // indicates a logic bug.  Break instead of spinning at 1ms.
        const next_ms = slot_math.msUntilNextSlot(self.clock.config, now_ms) orelse {
            std.log.err("EventClock: msUntilNextSlot returned null (config overflow?), stopping loop", .{});
            self.stop();
            break;
        };
        const sleep_ms = std.math.cast(i64, @max(@as(u64, 1), next_ms)) orelse std.math.maxInt(i64);

        // Sleep on `.boot` (monotonic + counts suspend) so a host suspend
        // doesn't leave us behind real chain time. `.awake` would freeze
        // the sleep across suspend even though `now_ms`/slot_math run on
        // wall-clock; resuming, we'd then wait the remaining pre-suspend
        // duration before catching up.
        // Sleep failure: cancellation (from join()) exits the loop;
        // other errors re-check the stopped flag.
        std.Io.sleep(
            self.io,
            std.Io.Duration.fromMilliseconds(sleep_ms),
            .boot,
        ) catch |err| {
            if (err == error.Canceled) break;
            std.log.debug("EventClock: sleep failed ({s}), retrying", .{@errorName(err)});
            continue;
        };
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
    threaded: std.Io.Threaded = undefined,

    fn init(self: *TestIo) !void {
        self.threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    }

    fn deinit(self: *TestIo) void {
        self.threaded.deinit();
    }

    fn io(self: *TestIo) std.Io {
        return self.threaded.io();
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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = try clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(start_slot + 1);
    errdefer fut.cancel();
    try fut.await();

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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    const current = try clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(current);
    errdefer fut.cancel();
    try fut.await();
}

test "waitForSlot returns aborted on stop" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

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
    try testing.expectError(error.Aborted, fut.await());
}

test "offSlot/offEpoch stop event delivery" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

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
    try testing.expect(try clock.offSlot(slot_id));
    try testing.expect(try clock.offEpoch(epoch_id));

    try clock.advanceAndDispatch(6);
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
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

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

    // Advance from null through epoch boundary at slot 4
    try clock.advanceAndDispatch(5);

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
        .slot_duration_ms = 1_000,
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
    try clock.advanceAndDispatch(3);

    try fut1.await();
    try fut3.await();

    // fut5 should still be pending. Stop to abort it.
    clock.stop();
    try testing.expectError(error.Aborted, fut5.await());
}

test "cancel releases WaitState without awaiting" {
    var rt: TestIo = undefined;
    try rt.init();
    defer rt.deinit();
    const io_handle = rt.io();

    var clock: EventClock = undefined;
    try clock.init(testing.allocator, .{
        .genesis_time_sec = nowSecAt(io_handle) + 10,
        .slot_duration_ms = 1_000,
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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = try clock.currentSlotOrGenesis();
    const before_ms = nowMsAt(io_handle);
    var fut = try clock.waitForSlot(start_slot + 1);
    errdefer fut.cancel();
    try fut.await();
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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = try clock.currentSlotOrGenesis();
    var fut = try clock.waitForSlot(start_slot + 2);
    errdefer fut.cancel();
    try fut.await();

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
        .slot_duration_ms = 12_000, // long slot like mainnet
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
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2, // epoch boundary every 2 slots
    }, io_handle);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    try clock.start();

    const start_slot = try clock.currentSlotOrGenesis();
    // Wait enough slots to guarantee crossing at least one epoch boundary.
    var fut = try clock.waitForSlot(start_slot + 3);
    errdefer fut.cancel();
    try fut.await();

    try testing.expect(trace.slot_len >= 3);
    // Must have seen at least one epoch transition.
    try testing.expect(trace.epoch_len > 0);
}
