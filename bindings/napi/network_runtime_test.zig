const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const Stores = r.Stores;
const Owner = r.Owner;
const commands = r.commands;
const publications_mod = r.publications_mod;
const requests_mod = r.requests_mod;
const projection = r.projection;

/// The test executable links no Node runtime, so a notification only counts here.
var notifications = std.atomic.Value(u32).init(0);
fn napiCallThreadsafeFunction(_: ?*anyopaque, _: ?*anyopaque, _: c_uint) callconv(.c) c_uint {
    _ = notifications.fetchAdd(1, .acq_rel);
    return 0;
}
comptime {
    @export(&napiCallThreadsafeFunction, .{ .name = "napi_call_threadsafe_function" });
}

test {
    _ = commands;
    _ = publications_mod;
    _ = projection;
    _ = @import("network_peer_reports.zig");
    _ = @import("network_owner.zig");
}

test "application typed store allocation prefixes release all requested bytes" {
    for ([_]usize{ 64, 512 }) |capacity| {
        for (0..3) |prefix| {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = prefix });
            try std.testing.expectError(error.OutOfMemory, Stores.create(failing.allocator(), capacity));
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const stores = try Stores.create(measured.allocator(), capacity);
        try std.testing.expectEqual(Stores.bytes(capacity), measured.allocated_bytes);
        stores.destroy();
        try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
        std.debug.print("application bridge capacity={} stores={} shell={} owner={} lane={} store_prefixes={}\n", .{ capacity, Stores.bytes(capacity), @sizeOf(Runtime), @sizeOf(Owner), @sizeOf(projection.Lane), measured.alloc_index });
    }
}

test "authenticated connect completion latches before a later close in the borrowed batch" {
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{2}));
    const peer = n.PeerId.fromPublicKey(&key.publicKey());
    const handle: n.Handle = .{ .index = 3, .generation = 7 };
    const events = [_]n.Event{
        .{ .connected = .{ .conn = handle, .peer_id = peer, .direction = .outbound } },
        .{ .closed = .{ .conn = handle, .peer_id = peer, .direction = .outbound, .reason = .host } },
    };
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const token = try runtime.table.reserve(.connect);
    runtime.table.get(token).state = .waiting;
    runtime.table.cells[token.index].input.peer = peer;
    runtime.table.cells[token.index].deadline = 2;
    try std.testing.expect(commands.latchConnects(&runtime.table, &events, .{ .mono_ms = 3, .unix_s = 0 }));
    try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    try std.testing.expect(runtime.table.cells[token.index].failure == null);
    try std.testing.expect(!commands.latchConnects(&runtime.table, &events, .{ .mono_ms = 4, .unix_s = 0 }));
    try std.testing.expect(runtime.table.cells[token.index].failure == null);
    runtime.table.retire(token);
}

test "stop preserves latched success and cancels accepted nonterminal commands" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const success = try runtime.table.reserve(.getIdentity);
    const waiting = try runtime.table.reserve(.connect);
    const queued = try runtime.table.reserve(.getIdentity);
    const preparing = try runtime.table.reserve(.applyIntent);
    runtime.table.get(success).state = .terminal;
    runtime.table.get(waiting).state = .waiting;
    runtime.table.get(queued).state = .queued;
    runtime.cancelCommandsLocked();
    try std.testing.expect(runtime.table.cells[success.index].failure == null);
    try std.testing.expectEqual(error.NetworkClosed, runtime.table.cells[waiting.index].failure.?);
    try std.testing.expectEqual(error.NetworkClosed, runtime.table.cells[queued.index].failure.?);
    try std.testing.expectEqual(commands.State.preparing, runtime.table.get(preparing).state);
    for ([_]commands.Token{ success, waiting, queued, preparing }) |token| runtime.table.retire(token);
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
}

test {
    _ = requests_mod;
    _ = @import("network_incoming.zig");
}

test "request table storage retires only after physical quiescence and final pins" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    runtime.payload_budget.limit = 32 + 2 * n.reqresp.Protocol.blocks_by_root_v2.info().response_max;
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 1, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.cells.len);
    const token = try runtime.requests.?.reserve(.blocks_by_root_v2, 32);
    try runtime.requests.?.allocate(token, 32);
    const cell = runtime.requests.?.get(token).?;
    cell.state = .native;
    cell.copying = true;
    cell.chunk = .{ .len = 4, .fork = null };
    runtime.quiescent = true;
    requests_mod.closeLocked(&runtime);
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.cells.len);
    try std.testing.expect(cell.sink.len > 0);
    cell.copying = false;
    runtime.requests.?.retire(token);
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 0), runtime.requests.?.cells.len);
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.diag.capacity);
    try std.testing.expect(runtime.requests.?.get(token) == null);
}

test {
    _ = @import("network_gossip.zig");
}

test "one runtime is live per process until its last release" {
    const first = try r.create(undefined);
    try std.testing.expectError(error.NetworkAlreadyInitialized, r.create(undefined));
    first.release();
    const second = try r.create(undefined);
    second.release();
}

test "a payload release while the owner waits for budget wakes the owner once" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.wake = try @import("network_wake.zig").Wake.init();
    defer runtime.wake.?.deinit();
    runtime.payload_budget.limit = 64;
    var readable = [_]std.c.pollfd{.{ .fd = runtime.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 }};
    for ([_]bool{ false, true }) |waiting| {
        try runtime.payload_budget.reserve(.incoming, 32);
        runtime.lock();
        runtime.payload_budget.waiting = waiting;
        runtime.payload_budget.release(.incoming, 32);
        runtime.unlock();
        try std.testing.expectEqual(@as(c_int, @intFromBool(waiting)), std.c.poll(&readable, 1, 0));
        try std.testing.expect(!runtime.payload_budget.waiting and !runtime.payload_budget.released);
    }
    try runtime.wake.?.drain();
}

test "runtime mutex records JS waits under the calling entry and owner holds under the phase" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    const Holder = struct {
        held: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This(), target: *Runtime) void {
            target.lock();
            self.held.store(true, .release);
            std.Io.sleep(std.Io.Threaded.global_single_threaded.io(), .fromMilliseconds(5), .awake) catch {};
            target.unlock();
        }
    };
    var holder: Holder = .{};
    const thread = try std.Thread.spawn(.{}, Holder.run, .{ &holder, &runtime });
    for (0..10_000) |_| {
        if (holder.held.load(.acquire)) break;
        std.Thread.yield() catch {};
    }
    const call = r.call(&runtime, .report_gossip);
    runtime.lock();
    runtime.unlock();
    call.end();
    thread.join();
    const waits = &runtime.bridge.waits[@intFromEnum(r.bridge.Entry.report_gossip)];
    try std.testing.expectEqual(@as(u64, 1), waits.count);
    try std.testing.expectEqual(@as(u64, 0), waits.buckets[0]);
    const previous = r.phase(.gossip_flags);
    runtime.lock();
    runtime.unlock();
    r.restore(previous);
    runtime.lock();
    runtime.unlock();
    var snapshot: r.bridge.Snapshot = .{};
    runtime.bridge.snapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 1), snapshot.calls[@intFromEnum(r.bridge.Entry.report_gossip)].count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.holds[@intFromEnum(r.bridge.Phase.gossip_flags)].count);
    var holds: u64 = 0;
    for (snapshot.holds) |value| holds += value.count;
    var waited: u64 = 0;
    for (snapshot.waits) |value| waited += value.count;
    try std.testing.expectEqual(@as(u64, 1), holds);
    try std.testing.expectEqual(@as(u64, 1), waited);
}

test "a notification keeps the latch and leaves every completion for the host drain" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    const before = notifications.load(.acquire);
    const token = try runtime.table.reserve(.getIdentity);
    runtime.table.get(token).state = .terminal;
    runtime.lock();
    runtime.pingLocked();
    runtime.pingLocked();
    try std.testing.expect(runtime.noticeLocked());
    runtime.unlock();
    try std.testing.expectEqual(before + 1, notifications.load(.acquire));
    try std.testing.expect(runtime.notification_pending);
    try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    runtime.lock();
    try std.testing.expect(runtime.endDrainLocked());
    runtime.unlock();
    try std.testing.expect(runtime.notification_pending);
    runtime.table.retire(token);
    runtime.lock();
    try std.testing.expect(!runtime.endDrainLocked());
    try std.testing.expect(!runtime.notification_pending);
    runtime.pingLocked();
    runtime.unlock();
    try std.testing.expectEqual(before + 2, notifications.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), runtime.bridge.js_pings[@intFromEnum(r.bridge.Entry.settle)]);
}

test "owner work around the end of a host drain is never lost" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    const before = notifications.load(.acquire);
    runtime.lock();
    runtime.pingLocked();
    _ = runtime.noticeLocked();
    runtime.unlock();
    // Owner work between the drain's last read and its end: the latch suppresses the ping.
    runtime.lock();
    runtime.pingLocked();
    runtime.unlock();
    try std.testing.expectEqual(before + 1, notifications.load(.acquire));
    runtime.lock();
    try std.testing.expect(runtime.endDrainLocked());
    try std.testing.expect(!runtime.endDrainLocked());
    runtime.unlock();
    // Owner work after the end released the latch: the ping notifies again.
    runtime.lock();
    runtime.pingLocked();
    runtime.unlock();
    try std.testing.expectEqual(before + 2, notifications.load(.acquire));
    try std.testing.expect(runtime.notification_pending);
}

test "owner work that races the end of a host drain always reaches a later drain" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    const Producer = struct {
        produced: u32 = 0,
        done: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This(), target: *Runtime) void {
            for (0..5_000) |_| {
                target.lock();
                self.produced += 1;
                target.pingLocked();
                target.unlock();
                std.Thread.yield() catch {};
            }
            self.done.store(true, .release);
        }
    };
    var producer: Producer = .{};
    var delivered = notifications.load(.acquire);
    const thread = try std.Thread.spawn(.{}, Producer.run, .{ &producer, &runtime });
    var consumed: u32 = 0;
    var again = false;
    var drains: usize = 0;
    for (0..10_000_000) |_| {
        const done = producer.done.load(.acquire);
        const notified = notifications.load(.acquire) != delivered;
        if (notified) delivered += 1;
        if (notified or again) {
            // A drain reads its lanes and ends in separate critical sections.
            runtime.lock();
            if (notified) _ = runtime.noticeLocked();
            consumed = producer.produced;
            runtime.unlock();
            std.Thread.yield() catch {};
            runtime.lock();
            again = runtime.endDrainLocked();
            runtime.unlock();
            drains += 1;
        } else if (done) break;
        std.Thread.yield() catch {};
    }
    thread.join();
    try std.testing.expectEqual(@as(u32, 5_000), producer.produced);
    try std.testing.expectEqual(producer.produced, consumed);
    try std.testing.expect(!runtime.notification_pending and !runtime.notify_missed);
    try std.testing.expect(drains > 0);
}

test "pulls and retirements neither notify from the JS thread nor settle before the host drain" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    runtime.payload_budget.limit = 32 + 2 * n.reqresp.Protocol.blocks_by_root_v2.info().response_max;
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 1, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    const token = try runtime.requests.?.reserve(.blocks_by_root_v2, 32);
    try runtime.requests.?.allocate(token, 32);
    const cell = runtime.requests.?.get(token).?;
    cell.state = .native;
    cell.native = .{ .index = 0, .generation = 1, .direction = .outbound };
    cell.chunk = .{ .len = 4, .fork = null };
    const before = notifications.load(.acquire);
    const deferred: @import("zapi:zapi").napi.Deferred = undefined;
    const pull = r.call(&runtime, .request_pull);
    runtime.lock();
    try std.testing.expect(!runtime.settleableLocked());
    requests_mod.armPull(&runtime, cell, deferred);
    try std.testing.expect(runtime.settleableLocked());
    runtime.unlock();
    pull.end();
    try std.testing.expect(cell.pull != null and cell.chunk != null and !cell.delivered);
    const retire = r.call(&runtime, .request_retire);
    runtime.lock();
    requests_mod.armRetirement(&runtime, cell, deferred);
    runtime.unlock();
    retire.end();
    try std.testing.expect(cell.retiring and cell.cancel and cell.retirement != null);
    try std.testing.expectEqual(before, notifications.load(.acquire));
    try std.testing.expect(!runtime.notification_pending);
    for (runtime.bridge.js_pings) |count| try std.testing.expectEqual(@as(u64, 0), count);
    const ping = r.call(&runtime, .request_pull);
    runtime.lock();
    runtime.pingLocked();
    runtime.unlock();
    ping.end();
    try std.testing.expectEqual(@as(u64, 1), runtime.bridge.js_pings[@intFromEnum(r.bridge.Entry.request_pull)]);
    cell.native = null;
    cell.chunk = null;
    cell.pull = null;
    cell.retirement = null;
    runtime.requests.?.retire(token);
}
