//! Shared clock test scaffolding: steerable io, event recorder, rendezvous.

const std = @import("std");
const Clock = @import("Clock.zig");

const Slot = Clock.Slot;
const ClockConfig = Clock.ClockConfig;

// Test io with a steerable wall clock. With `inner` null (the default) any
// call besides `now` crashes - the test must stay synchronous. Fiber tests
// set `inner` to a real zio io: the two futex entries forward to it so
// waitForSlot fibers genuinely suspend and wake; everything else still crashes.
pub const FakeClockIo = struct {
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
    pub fn io(self: *const FakeClockIo) std.Io {
        return .{ .userdata = @constCast(self), .vtable = &vtable };
    }
};

pub const test_cfg: ClockConfig = .{
    .genesis_time_sec = 100,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};

pub const EventTraceState = struct {
    slots: [64]Slot = undefined,
    slot_len: usize = 0,
    epochs: [64]u64 = undefined,
    epoch_len: usize = 0,

    pub fn onSlot(ctx: ?*anyopaque, slot: Slot) void {
        const self: *EventTraceState = @ptrCast(@alignCast(ctx.?));
        if (self.slot_len >= self.slots.len) return;
        self.slots[self.slot_len] = slot;
        self.slot_len += 1;
    }

    pub fn onEpoch(ctx: ?*anyopaque, epoch: u64) void {
        const self: *EventTraceState = @ptrCast(@alignCast(ctx.?));
        if (self.epoch_len >= self.epochs.len) return;
        self.epochs[self.epoch_len] = epoch;
        self.epoch_len += 1;
    }
};

/// Poll until `expected` waiter fibers have suspended inside waitForSlot.
/// Deterministic under a single-executor zio runtime: sleeping yields to the
/// spawned fibers, each of which pushes one queue entry then suspends.
pub fn rendezvousWaiters(clock: *Clock, io: std.Io, expected: usize) !void {
    var polls: usize = 0;
    while (clock.waiters.count() < expected) : (polls += 1) {
        if (polls >= 10_000) return error.RendezvousTimeout;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}
