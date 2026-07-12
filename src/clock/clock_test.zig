//! Scenario tests: reentrancy, drain, waiters, and the real-time auto-loop.

const std = @import("std");
const testing = std.testing;
const zio = @import("zio");
const time = @import("time");
const slot_math = @import("slot_math.zig");
const Clock = @import("Clock.zig");
const test_io = @import("test_io.zig");

const Slot = Clock.Slot;
const Epoch = Clock.Epoch;
const Error = Clock.Error;
const ListenerId = Clock.ListenerId;
const expectEqualSlices = std.testing.expectEqualSlices;

const FakeClockIo = test_io.FakeClockIo;
const EventTraceState = test_io.EventTraceState;
const rendezvousWaiters = test_io.rendezvousWaiters;

test "waitForSlot resolves immediately when at target" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    const current = clock.currentSlotOrGenesis();
    try clock.waitForSlot(current);
    // The count peek guards the fast path: a waiter enqueued here is a stack
    // local that would dangle once this frame returns.
    try testing.expectEqual(@as(usize, 0), clock.waiters.count());
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
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    clock.stop();
    // The stopped pre-check errors synchronously, before any enqueue or suspend.
    try testing.expectError(error.Aborted, clock.waitForSlot(1));
}

test "offSlot/offEpoch stop event delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    // One slot before genesis, so the cursor initializes to null.
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var trace = EventTraceState{};
    const slot_id = try clock.onSlot(EventTraceState.onSlot, &trace);
    const epoch_id = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Let the stream flow first: slots 0..4 cross into epoch 1 (spe = 4), so
    // both listeners provably receive events before removal.
    fake.ms = slot_math.slotStartMs(cfg, 4);
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());
    try testing.expectEqual(@as(usize, 5), trace.slot_len);
    try testing.expectEqual(@as(usize, 1), trace.epoch_len);

    try testing.expect(clock.offSlot(slot_id));
    try testing.expect(clock.offEpoch(epoch_id));

    // Draining on to slot 8 (epoch 2) must deliver nothing more to the
    // removed listeners, while the read still advances to the wall slot.
    fake.ms = slot_math.slotStartMs(cfg, 8);
    try testing.expectEqual(@as(?Slot, 8), clock.currentSlot());
    try testing.expectEqual(@as(usize, 5), trace.slot_len);
    try testing.expectEqual(@as(usize, 1), trace.epoch_len);
}

test "stop/join are idempotent" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    clock.stop();
    clock.stop();
    clock.join();
    clock.join();
}

test "epoch event is delivered when crossing epoch boundary" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Backlog slots 0..5; the epoch-1 boundary is crossed at slot 4.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());

    try testing.expect(trace.slot_len > 0);
    try testing.expect(trace.epoch_len > 0);
    try testing.expectEqual(@as(u64, 1), trace.epochs[0]);
}

fn nopSlot(_: ?*anyopaque, _: Slot) void {}
fn nopEpoch(_: ?*anyopaque, _: Epoch) void {}

test "ListenerLimitReached: onSlot/onEpoch reject the (limit+1)th registration" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    for (0..Clock.max_slot_listeners) |_| {
        _ = try clock.onSlot(nopSlot, null);
    }
    try testing.expectError(error.ListenerLimitReached, clock.onSlot(nopSlot, null));

    for (0..Clock.max_epoch_listeners) |_| {
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

    var futs: [Clock.max_waiters]std.Io.Future(Error!void) = undefined;
    for (&futs) |*f| {
        f.* = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 999_999 });
    }
    var polls: usize = 0;
    while (clock.waiters.count() < Clock.max_waiters) : (polls += 1) {
        if (polls >= 100_000) return error.RendezvousTimeout;
        std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }

    try testing.expectError(error.WaiterLimitReached, clock.waitForSlot(999_999));

    clock.stop();
    for (&futs) |*f| {
        try testing.expectError(error.Aborted, f.await(io_handle));
    }
}

test "multiple waiters are dispatched in target-slot order" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Spawn the waiters as fibers (targets out of order) and rendezvous so all
    // three have suspended before the clock advances.
    var fut5 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 5 });
    var fut3 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 3 });
    var fut1 = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 1 });
    try rendezvousWaiters(&clock, io_handle, 3);

    fake.ms = slot_math.slotStartMs(cfg, 3);
    _ = clock.currentSlot();

    try fut1.await(io_handle);
    try fut3.await(io_handle);

    clock.stop();
    try testing.expectError(error.Aborted, fut5.await(io_handle));
}

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
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx_a = ReentrancyCtx{ .clock = &clock };
    var ctx_b = ReentrancyCtx{ .clock = &clock };
    const id_a = try clock.onSlot(ReentrancyCtx.offSelf, &ctx_a);
    ctx_a.self_id = id_a;
    _ = try clock.onSlot(ReentrancyCtx.justCount, &ctx_b);

    // Slot 0 fires both; A removes itself. Slots 1..2 then fire only B.
    fake.ms = slot_math.slotStartMs(cfg, 0);
    _ = clock.currentSlot();
    fake.ms = slot_math.slotStartMs(cfg, 2);
    _ = clock.currentSlot();

    try testing.expectEqual(@as(usize, 1), ctx_a.fired_count);
    try testing.expectEqual(@as(usize, 3), ctx_b.fired_count);
}

test "reentrancy: callback can stop the clock; no further slots emitted" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = ReentrancyCtx{ .clock = &clock };
    _ = try clock.onSlot(ReentrancyCtx.stopClock, &ctx);

    // Backlog slots 0..5; the slot-0 callback stops the clock, so the drain
    // exits with the cursor still at 0 and no further slots emitted.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    _ = clock.currentSlot();

    try testing.expectEqual(@as(usize, 1), ctx.fired_count);
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

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Listener calls stop() while slot `target` is being emitted, i.e.
    // after current_slot reaches `target` but before dispatchWaiters runs.
    const target: Slot = 3;
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = target };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    var fut_reached = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target });
    var fut_future = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target + 1 });
    try rendezvousWaiters(&clock, io_handle, 2);

    fake.ms = slot_math.slotStartMs(cfg, target);
    _ = clock.currentSlot();

    // Reached slot happened, so the wait must resolve, not abort.
    try fut_reached.await(io_handle);
    // Future slot can never be emitted after stop, so it aborts.
    try testing.expectError(error.Aborted, fut_future.await(io_handle));
}

test "many waiters at same target slot all resolve on advance" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    const N = 16;
    var futs: [N]std.Io.Future(Error!void) = undefined;
    for (&futs) |*f| f.* = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, 5 });
    try rendezvousWaiters(&clock, io_handle, N);

    fake.ms = slot_math.slotStartMs(cfg, 5);
    _ = clock.currentSlot();

    for (&futs) |*f| try f.await(io_handle);
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

test "currentSlot returns the wall slot its catch-up flushed to" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Each emit burns 5 slots of wall time, simulating a slow callback.
    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5 * cfg.slot_duration_ms };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // Wall slot 2: catch-up emits slots 1 and 2, burning the wall to
    // 112_000 ms (slot 12). The result must stay at the wall slot it read.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    const returned = clock.currentSlot();

    try testing.expectEqual(@as(?Slot, 2), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
    try testing.expect(ctx.last_emitted.? <= returned.?);
}

test "currentSlotWithGossipDisparity bases its slot on the caught-up wall time" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5 * cfg.slot_duration_ms };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // 300 ms into slot 2 - outside the 500 ms disparity window - while the
    // slow callbacks burn the wall to 112_300 ms (slot 12). The base slot
    // must come from the caught-up wall time, not a fresh read.
    fake.ms = slot_math.slotStartMs(cfg, 2) + 300;
    const returned = clock.currentSlotWithGossipDisparity();

    try testing.expectEqual(@as(?Slot, 2), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "currentEpoch returns the epoch of the wall slot its catch-up flushed to" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Each emit burns 5 slots (2.5 epochs) of wall time.
    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5 * cfg.slot_duration_ms };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // Wall slot 2 (epoch 1): catch-up emits slots 1 and 2, burning the wall
    // to 112_000 ms (slot 12, epoch 6). The result must stay at epoch 1.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    const returned = clock.currentEpoch();

    try testing.expectEqual(@as(?Epoch, 1), returned);
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "isCurrentSlotGivenGossipDisparity judges the caught-up wall time" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = SlowCallbackCtx{ .fake = &fake, .advance_ms = 5 * cfg.slot_duration_ms };
    _ = try clock.onSlot(SlowCallbackCtx.onSlot, &ctx);

    // 300 ms into slot 2 while the slow callbacks burn the wall to
    // 112_300 ms (slot 12); a fresh second read would judge slot 2 stale.
    fake.ms = slot_math.slotStartMs(cfg, 2) + 300;
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(2));
    try testing.expectEqual(@as(?Slot, 2), ctx.last_emitted);
}

test "tolerance and from-slot forwards are pure reads: no catch-up" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Wall slot 1 with the cache at 0: a catchUp-backed accessor would flush
    // this backlog to the listener; these pure-read helpers must not.
    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 2), clock.slotWithFutureToleranceMs(cfg.slot_duration_ms));
    try testing.expectEqual(@as(Slot, 0), clock.slotWithPastToleranceMs(cfg.slot_duration_ms));

    fake.ms = slot_math.slotStartMs(cfg, 1) + 6_000;
    try testing.expectEqual(@as(i64, 6), clock.secFromSlot(1, null));
    try testing.expectEqual(@as(i64, 6_000), clock.msFromSlot(1, null));
    try testing.expectEqual(@as(i64, 0), clock.secFromSlot(1, slot_math.slotStartSec(cfg, 1)));
    try testing.expectEqual(@as(i64, -12), clock.secFromSlot(1, slot_math.slotStartSec(cfg, 0)));
    try testing.expectEqual(@as(i64, -12_000), clock.msFromSlot(1, slot_math.slotStartMs(cfg, 0)));

    try testing.expectEqual(@as(usize, 0), trace.slot_len);

    // Delivery is still at slot 0: currentSlot now catches up the intact
    // backlog, emitting only slot 1 - the pure reads advanced nothing.
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try expectEqualSlices(Slot, &.{1}, trace.slots[0..trace.slot_len]);
}

test "stop() from a catchUp callback aborts the wait before enqueue" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // A slot listener stops the clock mid-catchUp, after current_slot has
    // advanced but before it reaches `target`. The post-catchUp re-check must
    // abort synchronously: reaching the enqueue+suspend would panic in
    // FakeClockIo's futex forwarder (`inner` is unset here).
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    // Backlog slots 1..5 so catchUp fires the listener while short of target 10.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectError(error.Aborted, clock.waitForSlot(10));
}

test "stop() from a catchUp callback still resolves a reached wait" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // The listener stops the clock while slot 1 - the wait target - is being
    // emitted. The reached-check runs before the stopped re-check, so the wait
    // must return success synchronously, never suspending.
    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try clock.waitForSlot(1);
}

test "waitForSlot judges reached by delivery progress, not the wall clock" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = StopAtSlotCtx{ .clock = &clock, .stop_at = 1 };
    _ = try clock.onSlot(StopAtSlotCtx.stopAt, &ctx);

    // Backlog to slot 3 with the listener stopping the clock at slot 1: the
    // caught-up wall slot (3) reaches the target but delivery stops at slot 1,
    // and slot 2's event is suppressed. The reached-check must consult delivery
    // progress, so the wait aborts synchronously instead of resolving.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectError(error.Aborted, clock.waitForSlot(2));
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
        self.fake.ms += self.clock.config.slot_duration_ms;
        _ = self.clock.offSlot(self.remove_id);
        _ = self.clock.onSlot(EventTraceState.onSlot, self.add_ctx) catch unreachable;
        _ = self.clock.currentSlot();
    }
};

test "listener mutations mid-emit preserve the per-emit snapshot; a query defers delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
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
    // slot 2, removes L2, adds L4, and queries - recording target 2 without
    // nesting a dispatch. The drain then emits slot 2 to the post-mutation
    // list [L1, L3, L4].
    fake.ms = slot_math.slotStartMs(cfg, 1);
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
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx_e2 = EventTraceState{};
    var ctx_e3 = EventTraceState{};
    var ctx_e1 = EpochMutateCtx{ .clock = &clock, .add_ctx = &ctx_e3 };
    _ = try clock.onEpoch(EpochMutateCtx.onEpoch, &ctx_e1);
    const id_e2 = try clock.onEpoch(EventTraceState.onEpoch, &ctx_e2);
    ctx_e1.remove_id = id_e2;

    fake.ms = slot_math.slotStartMs(cfg, 4);
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

    fn onSlotThenStop(ctx: ?*anyopaque, slot: Slot) void {
        const self: *QueryAtSlotCtx = @ptrCast(@alignCast(ctx.?));
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
        if (slot != self.query_at) return;
        self.queried_slot = self.clock.currentSlot();
        self.clock.stop();
    }
};

test "non-backlog query-from-callback is a no-op" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    var ctx_r = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onSlot(EventTraceState.onSlot, &ctx_r);

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{1}, ctx_q.slots[0..ctx_q.slot_len]);
    try expectEqualSlices(Slot, &.{1}, ctx_r.slots[0..ctx_r.slot_len]);
    try testing.expectEqual(@as(?Slot, 1), ctx_q.queried_slot);
}

test "epoch events under deferred dispatch arrive in order exactly once" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 2) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx_q = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 4,
        .burn_to_ms = slot_math.slotStartMs(cfg, 8),
    };
    var trace = EventTraceState{};
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_q);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    // Emitting slot 4 crosses into epoch 1; Q's query then burns to slot 8
    // (epoch 2), recording target 8. The epoch-1 event is delivered as the
    // outer emit finishes, and epoch 2 by the drain - so epochs arrive 1, 2.
    fake.ms = slot_math.slotStartMs(cfg, 4);
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
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 32,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = BacklogWitnessCtx{ .clock = &clock };
    _ = try clock.onSlot(BacklogWitnessCtx.onSlot, &ctx);
    _ = try clock.onEpoch(BacklogWitnessCtx.onEpoch, &ctx);

    // A 32_768-slot backlog with a query on every callback: per-slot dispatch
    // recursion would overflow the fiber stack, so the drain must stay a flat
    // loop, delivering each slot once.
    const backlog: u64 = 32_768;
    fake.ms = slot_math.slotStartMs(cfg, backlog);
    try testing.expectEqual(@as(?Slot, 32_768), clock.currentSlot());

    try testing.expect(ctx.order_ok);
    try testing.expectEqual(@as(u64, 32_768), ctx.slot_count);
    try testing.expectEqual(@as(u64, 1_024), ctx.epoch_count);
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

test "a mid-emit query returns the wall slot ahead of deferred delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var log = RunAheadLog{};
    var ctx_a = RunAheadA{ .clock = &clock, .log = &log };
    var ctx_b = RunAheadB{ .log = &log };
    _ = try clock.onSlot(RunAheadA.onSlot, &ctx_a);
    _ = try clock.onSlot(RunAheadB.onSlot, &ctx_b);

    // Backlog 1..3. While emitting slot 1, A queries and gets 3
    // (the wall) though only slot 1 has been delivered. B then gets slot 1, and
    // the drain delivers 2 and 3 to both after A's callback returns.
    fake.ms = slot_math.slotStartMs(cfg, 3);
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

test "successive mid-emit queries drain to the furthest queried wall slot" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx_l1 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = slot_math.slotStartMs(cfg, 3),
    };
    var ctx_l2 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = slot_math.slotStartMs(cfg, 5),
    };
    var ctx_l3 = QueryAtSlotCtx{
        .clock = &clock,
        .fake = &fake,
        .query_at = 1,
        .burn_to_ms = slot_math.slotStartMs(cfg, 4),
    };
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l1);
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l2);
    _ = try clock.onSlot(QueryAtSlotCtx.onSlot, &ctx_l3);

    // Emitting slot 1, the three queries burn the wall to slots 3, 5, then
    // BACK to 4. @max holds the recorded target at 5: keeping the first target
    // would stall the drain at 3, and a plain overwrite would regress it to 4.
    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l1.slots[0..ctx_l1.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l2.slots[0..ctx_l2.slot_len]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, ctx_l3.slots[0..ctx_l3.slot_len]);
    try testing.expectEqual(@as(?Slot, 3), ctx_l1.queried_slot);
    try testing.expectEqual(@as(?Slot, 5), ctx_l2.queried_slot);
    try testing.expectEqual(@as(?Slot, 4), ctx_l3.queried_slot);
}

test "stop() after a mid-emit query leaves the next read clean" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var ctx = QueryAtSlotCtx{ .clock = &clock, .fake = &fake, .query_at = 1 };
    _ = try clock.onSlot(QueryAtSlotCtx.onSlotThenStop, &ctx);

    // Backlog 1..3: at slot 1 the callback queries (recording target 3,
    // returning 3) and then stops. The exit backstop must clear the recorded
    // target or the next accessor's catchUp would trip the
    // `pending_target == null` assert.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try testing.expectEqual(@as(?Slot, 3), ctx.queried_slot);

    // The post-stop accessor dispatches nothing and stays a pure read: it
    // returns the wall slot, and the suppressed slots 2..3 stay undelivered.
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try expectEqualSlices(Slot, &.{1}, ctx.slots[0..ctx.slot_len]);
}

test "top-level wall step-back never re-emits or regresses delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Advance to slot 3, then step the wall back to slot 1. The returned slot
    // follows the wall down, but the walk target is behind delivery, so the
    // step-back re-emits nothing.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, trace.slots[0..trace.slot_len]);

    // Advancing forward again resumes past slot 3: had the step-back regressed
    // delivery to slot 1, the drive to slot 5 would re-emit 2 and 3, so the
    // continued trace pins the intact ordered sequence.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, trace.slots[0..trace.slot_len]);
}

test "first delivery from a pre-genesis start begins at slot 0" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake = FakeClockIo{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Pre-genesis, so no slot is current yet and nothing has been delivered.
    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());

    var trace = EventTraceState{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    // Wall slot 2: the first catch-up from a pre-genesis start opens delivery
    // at slot 0, so the backlog arrives as 0, 1, 2.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 0, 1, 2 }, trace.slots[0..trace.slot_len]);
}

const SlotEpochLog = struct {
    const Tag = enum { slot, epoch };
    const Entry = struct { tag: Tag, value: u64 };

    entries: [16]Entry = undefined,
    len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        record(ctx, .slot, slot);
    }

    fn onEpoch(ctx: ?*anyopaque, epoch: Epoch) void {
        record(ctx, .epoch, epoch);
    }

    fn record(ctx: ?*anyopaque, tag: Tag, value: u64) void {
        const self: *SlotEpochLog = @ptrCast(@alignCast(ctx.?));
        if (self.len >= self.entries.len) return;
        self.entries[self.len] = .{ .tag = tag, .value = value };
        self.len += 1;
    }
};

test "epoch delivery interleaves after its boundary slot, before the next slot" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    };
    var fake = FakeClockIo{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var log = SlotEpochLog{};
    _ = try clock.onSlot(SlotEpochLog.onSlot, &log);
    _ = try clock.onEpoch(SlotEpochLog.onEpoch, &log);

    // Cursor starts at slot 0. Driving to slot 3 crosses the epoch-1 boundary
    // at slot 2: each slot is delivered first, then the epoch event once its
    // boundary is crossed - so slot 2 lands before epoch 1, and slot 3 after.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    const E = SlotEpochLog.Entry;
    try expectEqualSlices(E, &.{
        .{ .tag = .slot, .value = 1 },
        .{ .tag = .slot, .value = 2 },
        .{ .tag = .epoch, .value = 1 },
        .{ .tag = .slot, .value = 3 },
    }, log.entries[0..log.len]);
}
