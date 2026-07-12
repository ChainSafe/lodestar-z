//! Scenario tests, driven by fixtures shaped like the beacon node's listeners:
//! the fork-choice tick, the network processor, the attnets and sync services,
//! prepare-next-slot with its worker fiber, and the validator API's
//! `waitForSlot` callers.

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
const rendezvousWaiters = test_io.rendezvousWaiters;

/// One ordered log fed by a slot listener and an epoch listener, so the order
/// in which the two kinds of event reach the node is observable.
const DeliveryLog = struct {
    const Tag = enum { slot, epoch };
    const Entry = struct { tag: Tag, value: u64 };

    entries: [16]Entry = undefined,
    len: usize = 0,

    fn record(self: *DeliveryLog, tag: Tag, value: u64) void {
        if (self.len >= self.entries.len) return;
        self.entries[self.len] = .{ .tag = tag, .value = value };
        self.len += 1;
    }

    fn seen(self: *const DeliveryLog) []const Entry {
        return self.entries[0..self.len];
    }
};

/// The chain's fork-choice tick: it advances fork choice's own notion of time
/// and returns. Synchronous, and it never reads the clock. The network
/// processor's tick has the same shape, so a second instance stands in for it.
const ForkChoiceTicker = struct {
    log: ?*DeliveryLog = null,
    slots: [16]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *ForkChoiceTicker = @ptrCast(@alignCast(ctx.?));
        if (self.slot_len < self.slots.len) {
            self.slots[self.slot_len] = slot;
            self.slot_len += 1;
        }
        if (self.log) |log| log.record(.slot, slot);
    }

    fn seen(self: *const ForkChoiceTicker) []const Slot {
        return self.slots[0..self.slot_len];
    }
};

/// The attnets service. Its slot tick asks how far into the slot the node is:
/// `secFromSlot` is a pure read, so it must neither advance the cursor nor
/// emit. Its epoch tick recomputes the subnet subscriptions from the epoch it
/// reads back out of the clock.
const AttnetsService = struct {
    clock: *Clock,
    sec_into_slot: [8]i64 = undefined,
    slot_len: usize = 0,
    epochs: [8]Epoch = undefined,
    epoch_len: usize = 0,
    read_epoch: ?Epoch = null,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *AttnetsService = @ptrCast(@alignCast(ctx.?));
        if (self.slot_len >= self.sec_into_slot.len) return;
        self.sec_into_slot[self.slot_len] = self.clock.secFromSlot(slot, null);
        self.slot_len += 1;
    }

    fn onEpoch(ctx: ?*anyopaque, epoch: Epoch) void {
        const self: *AttnetsService = @ptrCast(@alignCast(ctx.?));
        self.read_epoch = self.clock.currentEpoch();
        if (self.epoch_len >= self.epochs.len) return;
        self.epochs[self.epoch_len] = epoch;
        self.epoch_len += 1;
    }

    fn secsSeen(self: *const AttnetsService) []const i64 {
        return self.sec_into_slot[0..self.slot_len];
    }
};

/// The sync service's epoch tick: it recomputes the node's sync state from the
/// clock, so it reads `currentSlot`/`currentEpoch` from inside the callback.
/// It reads before it records, so a dispatch nested inside that read would land
/// in the log ahead of its own entry.
const SyncService = struct {
    clock: *Clock,
    log: ?*DeliveryLog = null,
    epochs: [8]Epoch = undefined,
    read_slots: [8]?Slot = undefined,
    read_epochs: [8]?Epoch = undefined,
    epoch_len: usize = 0,

    fn onEpoch(ctx: ?*anyopaque, epoch: Epoch) void {
        const self: *SyncService = @ptrCast(@alignCast(ctx.?));
        const slot_now = self.clock.currentSlot();
        const epoch_now = self.clock.currentEpoch();
        if (self.epoch_len >= self.epochs.len) return;
        self.epochs[self.epoch_len] = epoch;
        self.read_slots[self.epoch_len] = slot_now;
        self.read_epochs[self.epoch_len] = epoch_now;
        self.epoch_len += 1;
        if (self.log) |log| log.record(.epoch, epoch);
    }

    fn seen(self: *const SyncService) []const Epoch {
        return self.epochs[0..self.epoch_len];
    }
};

/// The chain's slot tick on a saturated main thread: the work for `overrun_at`
/// runs past the slot boundary, so by the time the callback returns the wall
/// stands at `wall_after_ms` - which may be *behind* the wall it started from,
/// if NTP corrected the host clock while it ran. `onSlotThenRead` then asks the
/// clock which slot the node is really in now.
const SaturatedChainListener = struct {
    clock: *Clock,
    fake: *FakeClockIo,
    overrun_at: Slot,
    wall_after_ms: u64,
    wall_slot_seen: ?Slot = null,
    slots: [16]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *SaturatedChainListener = @ptrCast(@alignCast(ctx.?));
        self.record(slot);
        if (slot != self.overrun_at) return;
        self.fake.ms = self.wall_after_ms;
    }

    fn onSlotThenRead(ctx: ?*anyopaque, slot: Slot) void {
        const self: *SaturatedChainListener = @ptrCast(@alignCast(ctx.?));
        self.record(slot);
        if (slot != self.overrun_at) return;
        self.fake.ms = self.wall_after_ms;
        self.wall_slot_seen = self.clock.currentSlot();
    }

    fn record(self: *SaturatedChainListener, slot: Slot) void {
        if (self.slot_len >= self.slots.len) return;
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
    }

    fn seen(self: *const SaturatedChainListener) []const Slot {
        return self.slots[0..self.slot_len];
    }
};

/// The fork-choice tick hits an irrecoverable error at `fail_at`: it reads the
/// clock to record how far the wall had run, then shuts the node down from
/// inside the callback. `stop` is callback-safe; the drain must deliver nothing
/// past the slot that failed.
const ForkChoiceFailure = struct {
    clock: *Clock,
    fail_at: Slot,
    wall_slot_seen: ?Slot = null,
    slots: [16]Slot = undefined,
    slot_len: usize = 0,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *ForkChoiceFailure = @ptrCast(@alignCast(ctx.?));
        if (self.slot_len < self.slots.len) {
            self.slots[self.slot_len] = slot;
            self.slot_len += 1;
        }
        if (slot != self.fail_at) return;
        self.wall_slot_seen = self.clock.currentSlot();
        self.clock.stop();
    }

    fn seen(self: *const ForkChoiceFailure) []const Slot {
        return self.slots[0..self.slot_len];
    }
};

/// prepare-next-slot. The tick's synchronous prefix works out the slot to
/// prepare for and hands it to a worker fiber spawned when the node started:
/// `Event.set` does not yield, so the listeners behind it in this emit, and the
/// drain behind them, keep running. The preparation itself suspends (it waits
/// out most of the slot before building the block), which a callback may never
/// do - it runs on the emitting fiber's stack.
const PrepareNextSlot = struct {
    io: std.Io,
    handoff: std.Io.Event = .unset,
    /// The worker signals that it has taken the handoff and is about to suspend.
    took_handoff: std.Io.Event = .unset,
    prepare_slot: ?Slot = null,
    prepared_slot: ?Slot = null,

    fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *PrepareNextSlot = @ptrCast(@alignCast(ctx.?));
        self.prepare_slot = slot + 1;
        self.handoff.set(self.io);
    }

    /// Takes one handoff: waits for a slot, suspends the way the real
    /// preparation does, then records the slot it was handed.
    fn worker(self: *PrepareNextSlot) void {
        self.handoff.waitUncancelable(self.io);
        const slot = self.prepare_slot.?;
        self.took_handoff.set(self.io);
        std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        self.prepared_slot = slot;
    }
};

test "every listener receives every slot, in order, exactly once" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceTicker = .{};
    var network_processor: ForkChoiceTicker = .{};
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &network_processor);

    // Normal ticking: one slot at a time, the way the auto-loop drives it.
    for (1..4) |n| {
        fake.ms = slot_math.slotStartMs(cfg, @intCast(n));
        try testing.expectEqual(@as(?Slot, @intCast(n)), clock.currentSlot());
    }

    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, fork_choice.seen());
    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, network_processor.seen());
}

test "an epoch tick lands after its boundary slot and before the next slot" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var log: DeliveryLog = .{};
    var fork_choice: ForkChoiceTicker = .{ .log = &log };
    var sync: SyncService = .{ .clock = &clock, .log = &log };
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);
    _ = try clock.onEpoch(SyncService.onEpoch, &sync);

    // Normal ticking across the epoch-1 boundary at slot 2 (spe = 2). The sync
    // service reads the clock from inside its epoch tick - the common case,
    // with the cursor already at the wall: the read finds the boundary slot and
    // the new epoch, and changes nothing about delivery.
    for (1..4) |n| {
        fake.ms = slot_math.slotStartMs(cfg, @intCast(n));
        try testing.expectEqual(@as(?Slot, @intCast(n)), clock.currentSlot());
    }

    const E = DeliveryLog.Entry;
    try expectEqualSlices(E, &.{
        .{ .tag = .slot, .value = 1 },
        .{ .tag = .slot, .value = 2 },
        .{ .tag = .epoch, .value = 1 },
        .{ .tag = .slot, .value = 3 },
    }, log.seen());
    try testing.expectEqual(@as(?Slot, 2), sync.read_slots[0]);
    try testing.expectEqual(@as(?Epoch, 1), sync.read_epochs[0]);
}

test "an epoch tick reading mid-drain sees the wall, and delivery is undisturbed" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var log: DeliveryLog = .{};
    var fork_choice: ForkChoiceTicker = .{ .log = &log };
    var sync: SyncService = .{ .clock = &clock, .log = &log };
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);
    _ = try clock.onEpoch(SyncService.onEpoch, &sync);

    // The host was suspended for five slots, so one catch-up drains 1..5. The
    // sync service's epoch tick (fired right after slot 4) reads the clock and
    // legitimately sees slot 5 - a slot whose event has not gone out yet. The
    // read must not nest a dispatch: the frame already emitting delivers slot 5
    // afterwards, in order, exactly once.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());

    const E = DeliveryLog.Entry;
    try expectEqualSlices(E, &.{
        .{ .tag = .slot, .value = 1 },
        .{ .tag = .slot, .value = 2 },
        .{ .tag = .slot, .value = 3 },
        .{ .tag = .slot, .value = 4 },
        .{ .tag = .epoch, .value = 1 },
        .{ .tag = .slot, .value = 5 },
    }, log.seen());
    try testing.expectEqual(@as(?Slot, 5), sync.read_slots[0]);
    try testing.expectEqual(@as(?Epoch, 1), sync.read_epochs[0]);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, fork_choice.seen());
}

test "the attnets tick's pure read sees the wall without advancing delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // The chain's work for slot 1 overruns on a saturated main thread: by the
    // time attnets runs, the wall has reached slot 5.
    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 5),
    };
    var attnets: AttnetsService = .{ .clock = &clock };
    var fork_choice: ForkChoiceTicker = .{};
    _ = try clock.onSlot(SaturatedChainListener.onSlot, &chain);
    _ = try clock.onSlot(AttnetsService.onSlot, &attnets);
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    // attnets reads 4 s past the start of slot 1 - the wall as the overrun left
    // it. A pure read records no drain target, so delivery stops at slot 1 even
    // though the wall now says slot 5.
    try expectEqualSlices(i64, &.{4}, attnets.secsSeen());
    try expectEqualSlices(Slot, &.{1}, fork_choice.seen());

    // The next caught-up read delivers the backlog the pure reads left intact.
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, fork_choice.seen());
    try expectEqualSlices(i64, &.{ 4, 3, 2, 1, 0 }, attnets.secsSeen());
}

test "tolerance and from-slot forwards are pure reads: no catch-up" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceTicker = .{};
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    // Gossip validation and the duty math call these helpers between ticks.
    // Wall slot 1 with the cursor at 0: a catchUp-backed accessor would flush
    // that backlog to the listeners; these pure-read helpers must not.
    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 2), clock.slotWithFutureToleranceMs(cfg.slot_duration_ms));
    try testing.expectEqual(@as(Slot, 0), clock.slotWithPastToleranceMs(cfg.slot_duration_ms));

    fake.ms = slot_math.slotStartMs(cfg, 1) + 6_000;
    try testing.expectEqual(@as(i64, 6), clock.secFromSlot(1, null));
    try testing.expectEqual(@as(i64, 6_000), clock.msFromSlot(1, null));
    try testing.expectEqual(@as(i64, 0), clock.secFromSlot(1, slot_math.slotStartSec(cfg, 1)));
    try testing.expectEqual(@as(i64, -12), clock.secFromSlot(1, slot_math.slotStartSec(cfg, 0)));
    try testing.expectEqual(@as(i64, -12_000), clock.msFromSlot(1, slot_math.slotStartMs(cfg, 0)));

    try testing.expectEqual(@as(usize, 0), fork_choice.slot_len);

    // Delivery is still at slot 0: currentSlot now catches up the intact
    // backlog, emitting only slot 1 - the pure reads advanced nothing.
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try expectEqualSlices(Slot, &.{1}, fork_choice.seen());
}

test "currentSlot returns the wall slot its catch-up flushed to" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 12),
    };
    _ = try clock.onSlot(SaturatedChainListener.onSlot, &chain);

    // The wall says slot 2, so the catch-up emits slots 1 and 2 - but the tick
    // for slot 1 overruns and leaves the wall at slot 12. The accessor must
    // return the wall slot its catch-up read, not a fresh one.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2 }, chain.seen());
}

test "currentSlotWithGossipDisparity bases its slot on the caught-up wall time" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 12),
    };
    _ = try clock.onSlot(SaturatedChainListener.onSlot, &chain);

    // 300 ms into slot 2 - outside the 500 ms disparity window - while the
    // overrunning tick leaves the wall at slot 12. The base slot must come from
    // the wall time the catch-up read, not a fresh one.
    fake.ms = slot_math.slotStartMs(cfg, 2) + 300;
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlotWithGossipDisparity());
    try expectEqualSlices(Slot, &.{ 1, 2 }, chain.seen());
}

test "currentEpoch returns the epoch of the wall slot its catch-up flushed to" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 2,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 12),
    };
    _ = try clock.onSlot(SaturatedChainListener.onSlot, &chain);

    // Wall slot 2 is epoch 1 (spe = 2); the overrun leaves the wall at slot 12,
    // epoch 6. The result must stay at epoch 1.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
    try expectEqualSlices(Slot, &.{ 1, 2 }, chain.seen());
}

test "isCurrentSlotGivenGossipDisparity judges the caught-up wall time" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 12),
    };
    _ = try clock.onSlot(SaturatedChainListener.onSlot, &chain);

    // 300 ms into slot 2 while the overrunning tick leaves the wall at slot 12:
    // a fresh second read would judge the gossip on slot 2 stale.
    fake.ms = slot_math.slotStartMs(cfg, 2) + 300;
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(2));
    try expectEqualSlices(Slot, &.{ 1, 2 }, chain.seen());
}

test "a saturated emit drains to the furthest wall a tick saw; a step-back never lowers it" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var first: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 3),
    };
    var second: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 5),
    };
    var third: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 1,
        .wall_after_ms = slot_math.slotStartMs(cfg, 4),
    };
    _ = try clock.onSlot(SaturatedChainListener.onSlotThenRead, &first);
    _ = try clock.onSlot(SaturatedChainListener.onSlotThenRead, &second);
    _ = try clock.onSlot(SaturatedChainListener.onSlotThenRead, &third);

    // The main thread is saturated: each tick's work for slot 1 spans slot
    // boundaries, and each reads the clock afterwards to see where the wall now
    // stands. While the third one runs, NTP corrects the host clock backwards,
    // so it sees slot 4 where the second saw slot 5. Each read returns the wall
    // as it stood for that tick, and delivery must reach the furthest wall any
    // of them saw: a slot a listener has already observed must still arrive.
    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    try testing.expectEqual(@as(?Slot, 3), first.wall_slot_seen);
    try testing.expectEqual(@as(?Slot, 5), second.wall_slot_seen);
    try testing.expectEqual(@as(?Slot, 4), third.wall_slot_seen);
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, first.seen());
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, second.seen());
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, third.seen());
}

test "epoch events under a deferred drain arrive in order, exactly once" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 2) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var chain: SaturatedChainListener = .{
        .clock = &clock,
        .fake = &fake,
        .overrun_at = 4,
        .wall_after_ms = slot_math.slotStartMs(cfg, 8),
    };
    var sync: SyncService = .{ .clock = &clock };
    _ = try clock.onSlot(SaturatedChainListener.onSlotThenRead, &chain);
    _ = try clock.onEpoch(SyncService.onEpoch, &sync);

    // Slot 4 crosses into epoch 1 (spe = 4). The tick for it overruns to slot 8
    // (epoch 2) and reads the clock, which records target 8. The epoch-1 event
    // still goes out as the outer emit finishes, and epoch 2 once the drain
    // reaches slot 8 - so the epochs arrive 1 then 2, each exactly once.
    fake.ms = slot_math.slotStartMs(cfg, 4);
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 3, 4, 5, 6, 7, 8 }, chain.seen());
    try expectEqualSlices(Epoch, &.{ 1, 2 }, sync.seen());
    try testing.expectEqual(@as(?Slot, 8), chain.wall_slot_seen);
}

test "a long host suspend leaves a huge backlog that drains in a flat loop" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 32,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // The chain's ticks during the catch-up. Reading the clock on every slot is
    // the worst case for the drain: every callback can record a fresh target.
    const CatchUpTick = struct {
        clock: *Clock,
        last_slot: Slot = 0,
        slot_count: u64 = 0,
        epoch_count: u64 = 0,
        in_order: bool = true,

        fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (slot != self.last_slot + 1) self.in_order = false;
            self.last_slot = slot;
            self.slot_count += 1;
            _ = self.clock.currentSlot();
        }

        fn onEpoch(ctx: ?*anyopaque, _: Epoch) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.epoch_count += 1;
        }
    };
    var tick: CatchUpTick = .{ .clock = &clock };
    _ = try clock.onSlot(CatchUpTick.onSlot, &tick);
    _ = try clock.onEpoch(CatchUpTick.onEpoch, &tick);

    // The host slept for 32_768 slots (a laptop suspended overnight). A dispatch
    // that recursed per slot would need one fiber-stack frame per backlogged
    // slot - 32_768 of them, far past the stack a fiber has - so the drain must
    // stay a flat loop, delivering each slot once, in order.
    const backlog: u64 = 32_768;
    fake.ms = slot_math.slotStartMs(cfg, backlog);
    try testing.expectEqual(@as(?Slot, 32_768), clock.currentSlot());

    try testing.expect(tick.in_order);
    try testing.expectEqual(@as(u64, 32_768), tick.slot_count);
    try testing.expectEqual(@as(u64, 1_024), tick.epoch_count);
}

test "top-level wall step-back never re-emits or regresses delivery" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceTicker = .{};
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    // Delivery reaches slot 3, then NTP corrects the host clock back to slot 1.
    // The returned slot follows the wall down, but the walk target is behind
    // delivery, so the step-back re-emits nothing.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2, 3 }, fork_choice.seen());

    // Drive on to slot 5. Only 4 and 5 are new, so the stream ends 1,2,3,4,5.
    // Had the step-back rewound the cursor, this drive would resend 2 and 3.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectEqual(@as(?Slot, 5), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2, 3, 4, 5 }, fork_choice.seen());
}

test "first delivery from a pre-genesis start begins at slot 0" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceTicker = .{};
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    // The node started before genesis, so no slot is current yet and a read
    // delivers nothing.
    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(usize, 0), fork_choice.slot_len);

    // Wall slot 2: the first catch-up from a pre-genesis start opens delivery
    // at slot 0, so the backlog arrives as 0, 1, 2.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 0, 1, 2 }, fork_choice.seen());
}

test "a shutdown from inside a tick still delivers that slot to the services it unsubscribes" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // A synchronous shutdown started from inside a tick unsubscribes the other
    // services while their slot is still being delivered. `offSlot` is
    // callback-safe: the emit runs on a snapshot, so a service removed here
    // still receives the slot in flight, and no one receives it twice.
    const Shutdown = struct {
        clock: *Clock,
        remove: [2]ListenerId = .{ 0, 0 },
        slots: [4]Slot = undefined,
        slot_len: usize = 0,

        fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.slots[self.slot_len] = slot;
            self.slot_len += 1;
            for (self.remove) |id| _ = self.clock.offSlot(id);
        }
    };
    var shutdown: Shutdown = .{ .clock = &clock };
    var attnets: ForkChoiceTicker = .{};
    var fork_choice: ForkChoiceTicker = .{};
    _ = try clock.onSlot(Shutdown.onSlot, &shutdown);
    shutdown.remove[0] = try clock.onSlot(ForkChoiceTicker.onSlot, &attnets);
    shutdown.remove[1] = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    // Slot 0 reaches all three, and the shutdown unsubscribes the two behind
    // it. Slots 1 and 2 then reach the shutdown listener alone.
    fake.ms = slot_math.slotStartMs(cfg, 0);
    _ = clock.currentSlot();
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());

    try expectEqualSlices(Slot, &.{ 0, 1, 2 }, shutdown.slots[0..shutdown.slot_len]);
    try expectEqualSlices(Slot, &.{0}, attnets.seen());
    try expectEqualSlices(Slot, &.{0}, fork_choice.seen());
}

test "listeners removed at shutdown stop receiving events" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    // One slot before genesis, so the cursor initializes to null.
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var attnets: AttnetsService = .{ .clock = &clock };
    const slot_id = try clock.onSlot(AttnetsService.onSlot, &attnets);
    const epoch_id = try clock.onEpoch(AttnetsService.onEpoch, &attnets);

    // Let the stream flow first: slots 0..4 cross into epoch 1 (spe = 4), so
    // both of the service's listeners provably receive events before removal.
    fake.ms = slot_math.slotStartMs(cfg, 4);
    try testing.expectEqual(@as(?Slot, 4), clock.currentSlot());
    try testing.expectEqual(@as(usize, 5), attnets.slot_len);
    try testing.expectEqual(@as(usize, 1), attnets.epoch_len);

    try testing.expect(clock.offSlot(slot_id));
    try testing.expect(clock.offEpoch(epoch_id));

    // The service is shut down. Draining on to slot 8 (epoch 2) must deliver
    // nothing more to it, while the read still advances to the wall slot.
    fake.ms = slot_math.slotStartMs(cfg, 8);
    try testing.expectEqual(@as(?Slot, 8), clock.currentSlot());
    try testing.expectEqual(@as(usize, 5), attnets.slot_len);
    try testing.expectEqual(@as(usize, 1), attnets.epoch_len);
}

test "an irrecoverable fork-choice error stops the node from inside the tick" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceFailure = .{ .clock = &clock, .fail_at = 1 };
    var network_processor: ForkChoiceTicker = .{};
    _ = try clock.onSlot(ForkChoiceFailure.onSlot, &fork_choice);
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &network_processor);

    // Slots 1..3 are backlogged. Fork choice fails on slot 1: it reads the clock
    // (the wall says 3) and stops the node from inside the tick. The listeners
    // behind it still receive slot 1 - the emit in flight runs to the end of its
    // snapshot - but slots 2 and 3 are never delivered.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try testing.expectEqual(@as(?Slot, 3), fork_choice.wall_slot_seen);

    // Reading a stopped clock still reports the wall; it just delivers nothing.
    try testing.expectEqual(@as(?Slot, 3), clock.currentSlot());
    try expectEqualSlices(Slot, &.{1}, fork_choice.seen());
    try expectEqualSlices(Slot, &.{1}, network_processor.seen());
}

test "work that must await runs on its own fiber" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0), .inner = io_handle };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // The worker fiber exists before the clock ticks; the tick only hands it a
    // slot. The fork-choice ticker sits behind prepare-next-slot in the snapshot,
    // so it is the listener a suspending callback would have stalled.
    var prepare: PrepareNextSlot = .{ .io = io_handle };
    var fork_choice: ForkChoiceTicker = .{};
    var worker = try std.Io.concurrent(io_handle, PrepareNextSlot.worker, .{&prepare});
    _ = try clock.onSlot(PrepareNextSlot.onSlot, &prepare);
    _ = try clock.onSlot(ForkChoiceTicker.onSlot, &fork_choice);

    // Slot 1: prepare-next-slot hands slot 2 to the worker and returns.
    fake.ms = slot_math.slotStartMs(cfg, 1);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());
    try expectEqualSlices(Slot, &.{1}, fork_choice.seen());

    // Hand the fiber the runtime until it has taken the handoff and suspended.
    prepare.took_handoff.waitUncancelable(io_handle);

    // The clock keeps advancing while the worker is parked: slot 2 is delivered
    // and the worker has still not finished its work.
    fake.ms = slot_math.slotStartMs(cfg, 2);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
    try expectEqualSlices(Slot, &.{ 1, 2 }, fork_choice.seen());
    try testing.expectEqual(@as(?Slot, null), prepare.prepared_slot);

    // The worker eventually does the work for the slot it was handed.
    worker.await(io_handle);
    try testing.expectEqual(@as(?Slot, 2), prepare.prepared_slot);
}

test "waitForSlot resolves immediately when at target" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

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

    // A validator-API caller parks on its own fiber; shutdown aborts it.
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
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    clock.stop();
    // The stopped pre-check errors synchronously, before any enqueue or suspend.
    try testing.expectError(error.Aborted, clock.waitForSlot(1));
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
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Validator-API callers on their own fibers (targets out of order); the
    // rendezvous makes sure all three have suspended before the clock advances.
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

test "many waiters at same target slot all resolve on advance" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
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

test "stop() from a catchUp callback aborts the wait before enqueue" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // The catch-up this wait triggers runs the fork-choice tick, which fails on
    // slot 1 and stops the node - after current_slot has advanced but before it
    // reaches the target. The post-catchUp re-check must abort synchronously:
    // reaching the enqueue+suspend would panic in FakeClockIo's futex forwarder
    // (`inner` is unset here).
    var fork_choice: ForkChoiceFailure = .{ .clock = &clock, .fail_at = 1 };
    _ = try clock.onSlot(ForkChoiceFailure.onSlot, &fork_choice);

    // Backlog slots 1..5 so the catch-up fires the tick while short of target 10.
    fake.ms = slot_math.slotStartMs(cfg, 5);
    try testing.expectError(error.Aborted, clock.waitForSlot(10));
}

test "stop() from a catchUp callback still resolves a reached wait" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Fork choice fails while slot 1 - the wait's target - is being emitted. The
    // reached-check runs before the stopped re-check, so the wait must return
    // success synchronously, never suspending.
    var fork_choice: ForkChoiceFailure = .{ .clock = &clock, .fail_at = 1 };
    _ = try clock.onSlot(ForkChoiceFailure.onSlot, &fork_choice);

    fake.ms = slot_math.slotStartMs(cfg, 1);
    try clock.waitForSlot(1);
}

test "waitForSlot judges reached by delivery progress, not the wall clock" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = slot_math.slotStartMs(cfg, 0) };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    var fork_choice: ForkChoiceFailure = .{ .clock = &clock, .fail_at = 1 };
    _ = try clock.onSlot(ForkChoiceFailure.onSlot, &fork_choice);

    // Backlog to slot 3 with fork choice failing on slot 1: the caught-up wall
    // slot (3) reaches the target, but delivery stops at slot 1 and slot 2's
    // event is suppressed. The reached-check must consult delivery progress, so
    // the wait aborts synchronously instead of resolving.
    fake.ms = slot_math.slotStartMs(cfg, 3);
    try testing.expectError(error.Aborted, clock.waitForSlot(2));
}

test "stop() during emit resolves a reached waiter and aborts a future one" {
    const rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_handle = rt.io();

    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms, .inner = io_handle };
    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    // Fork choice fails while slot `target` is being emitted, i.e. after
    // current_slot reaches `target` but before dispatchWaiters runs.
    const target: Slot = 3;
    var fork_choice: ForkChoiceFailure = .{ .clock = &clock, .fail_at = target };
    _ = try clock.onSlot(ForkChoiceFailure.onSlot, &fork_choice);

    var fut_reached = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target });
    var fut_future = try std.Io.concurrent(io_handle, Clock.waitForSlot, .{ &clock, target + 1 });
    try rendezvousWaiters(&clock, io_handle, 2);

    fake.ms = slot_math.slotStartMs(cfg, target);
    _ = clock.currentSlot();

    // The target slot was delivered, so its wait resolves rather than aborting.
    try fut_reached.await(io_handle);
    // The next slot can never be emitted after the stop, so its wait aborts.
    try testing.expectError(error.Aborted, fut_future.await(io_handle));
}

fn nopSlot(_: ?*anyopaque, _: Slot) void {}
fn nopEpoch(_: ?*anyopaque, _: Epoch) void {}

test "ListenerLimitReached: onSlot/onEpoch reject the (limit+1)th registration" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 4,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

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

test "stop/join are idempotent" {
    const cfg: Clock.ClockConfig = .{
        .genesis_time_sec = 100,
        .slot_duration_ms = 1_000,
        .slots_per_epoch = 8,
    };
    var fake: FakeClockIo = .{ .ms = cfg.genesis_time_sec * 1000 - cfg.slot_duration_ms };

    var clock: Clock = undefined;
    try clock.init(testing.allocator, fake.io(), cfg);
    defer clock.deinit();

    clock.stop();
    clock.stop();
    clock.join();
    clock.join();
}
