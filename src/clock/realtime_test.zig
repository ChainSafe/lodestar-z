//! Real-clock tests: the auto-loop under real zio scheduling and real wall
//! time. Assertions are bounds, not exact values.

const std = @import("std");
const testing = std.testing;
const zio = @import("zio");
const time = @import("time");
const slot_math = @import("slot_math.zig");
const Clock = @import("Clock.zig");
const test_io = @import("test_io.zig");

const Slot = Clock.Slot;
const EventTraceState = test_io.EventTraceState;

test "real-time: the auto-loop delivers ordered slot events promptly" {
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

    var trace: EventTraceState = .{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    const target = start_slot + 2;
    const before_ms = time.nowMs(io_handle);
    // The auto-loop advances the clock on its own fiber, so this direct wait
    // suspends the main fiber and is woken by the loop's dispatch.
    try clock.waitForSlot(target);
    const after_ms = time.nowMs(io_handle);

    // On wake-up the wall has reached the target slot's start.
    try testing.expect(after_ms >= slot_math.slotStartMs(clock.config, target));
    // With slot_duration_ms = 1 s, the two boundaries to the target pass in
    // under 2 s; the third second is scheduler headroom.
    try testing.expect(after_ms - before_ms < 3000);
    // The wait spans two slot boundaries, so at least two slots arrive.
    try testing.expect(trace.slot_len >= 2);
    // Delivery reached the target; a further boundary may have added more.
    try testing.expect(trace.slots[trace.slot_len - 1] >= target);
    // Slots arrive in order, each once.
    for (1..trace.slot_len) |i| {
        try testing.expect(trace.slots[i] > trace.slots[i - 1]);
    }
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

    var trace: EventTraceState = .{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);

    try clock.start();

    std.Io.sleep(io_handle, std.Io.Duration.fromMilliseconds(1500), .awake) catch {};

    try testing.expectEqual(@as(usize, 0), trace.slot_len);
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

    // join() cancels the sleeping future directly - should return
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

    var trace: EventTraceState = .{};
    _ = try clock.onSlot(EventTraceState.onSlot, &trace);
    _ = try clock.onEpoch(EventTraceState.onEpoch, &trace);

    try clock.start();

    const start_slot = clock.currentSlotOrGenesis();
    try clock.waitForSlot(start_slot + 3);

    try testing.expect(trace.slot_len >= 3);
    try testing.expect(trace.epoch_len > 0);
}
