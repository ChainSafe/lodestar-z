const std = @import("std");
const testing = std.testing;
const Clock = @import("./clock.zig").Clock;
const ClockRunner = @import("./runner.zig").ClockRunner;
const ClockCallbacks = @import("./runner.zig").ClockCallbacks;
const mainnet = @import("config").mainnet;
const Slot = @import("consensus_types").primitive.Slot.Type;
const Epoch = @import("consensus_types").primitive.Epoch.Type;

const TestContext = struct {
    slot_count: usize = 0,
    epoch_count: usize = 0,
    last_slot: ?Slot = null,
    last_epoch: ?Epoch = null,
    mutex: std.Thread.Mutex = .{},
};

fn onSlotTest(slot: Slot, ctx: ?*anyopaque) void {
    const test_ctx: *TestContext = @ptrCast(@alignCast(ctx.?));
    test_ctx.mutex.lock();
    defer test_ctx.mutex.unlock();

    test_ctx.slot_count += 1;
    test_ctx.last_slot = slot;
    std.debug.print("Test: Slot {} fired\n", .{slot});
}

fn onEpochTest(epoch: Epoch, ctx: ?*anyopaque) void {
    const test_ctx: *TestContext = @ptrCast(@alignCast(ctx.?));
    test_ctx.mutex.lock();
    defer test_ctx.mutex.unlock();

    test_ctx.epoch_count += 1;
    test_ctx.last_epoch = epoch;
    std.debug.print("Test: Epoch {} fired\n", .{epoch});
}

test "Clock should notify on new slot" {
    const config = mainnet.chain_config;

    const genesis_time: u64 = @intCast(std.time.timestamp());

    var my_clock = Clock{
        .genesis_time = genesis_time,
        .config = config,
        .current_slot = 0,
        ._internal_slot = 0,
    };

    var test_ctx = TestContext{};
    const callbacks = ClockCallbacks{
        .onSlot = onSlotTest,
        .onEpoch = null,
        .ctx = &test_ctx,
    };

    // TODO: find another way to do this because we have to wait 12 seconds in this test (maybe we set up the genesis time to 12 secs ago)
    std.time.sleep(12 * std.time.ns_per_s);

    const current_slot = try my_clock.getCurrentSlot(&callbacks);

    try testing.expectEqual(@as(usize, 1), test_ctx.slot_count);
    try testing.expectEqual(@as(Slot, 1), test_ctx.last_slot.?);
    try testing.expectEqual(@as(Slot, 1), current_slot);
}
