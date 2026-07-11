//! Model-based property test: random op sequences against a reference model.

const std = @import("std");
const testing = std.testing;
const zio = @import("zio");
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
