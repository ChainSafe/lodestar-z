const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const Stores = r.Stores;
const Owner = r.Owner;
const commands = r.commands;
const publications_mod = r.publications_mod;
const requests_mod = r.requests_mod;
const incoming_mod = r.incoming_mod;
const gossip_mod = r.gossip_mod;
const projection = r.projection;
const napi = @import("zapi:zapi").napi;

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
    runtime.table.transition(runtime.table.get(token), .waiting);
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
    runtime.table.transition(runtime.table.get(success), .terminal);
    runtime.table.transition(runtime.table.get(waiting), .waiting);
    runtime.table.transition(runtime.table.get(queued), .queued);
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
    runtime.table.transition(runtime.table.get(token), .terminal);
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

fn expectLanes(runtime: *Runtime, expected: []const r.Lane) !void {
    var bits: u32 = 0;
    for (expected) |lane| bits |= lane.bit();
    runtime.lock();
    defer runtime.unlock();
    try std.testing.expectEqual(bits, runtime.lanesLocked());
}

fn admitGossip(table: *gossip_mod.Table, kind: n.gossip_processor.limits_mod.Kind, root: ?[32]u8) !void {
    const token = try table.reserveKind(kind, 4);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = 100;
    cell.metadata = .{ .slot = 1, .root = root, .await_block = root != null };
    @memset(&cell.topic, 0);
    table.install(token, "data");
}

test "host drain lanes report exactly the tables that hold work" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 1 << 20;
    runtime.incoming = try incoming_mod.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    const limits: n.gossip_processor.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    runtime.gossip = try gossip_mod.Table.init(std.testing.allocator, .{ .capacity = n.gossip_processor.limits_mod.items(&limits), .bytes = n.gossip_processor.limits_mod.bytes(&limits), .limits = limits });
    defer runtime.gossip.?.deinit();
    var lane: projection.Lane = .{};
    runtime.lane = &lane;
    try expectLanes(&runtime, &.{});

    const command = try runtime.table.reserve(.getIdentity);
    runtime.table.transition(runtime.table.get(command), .terminal);
    try expectLanes(&runtime, &.{.settle});
    runtime.table.retire(command);
    lane.publish(&.{.{ .closed = undefined }}, 1);
    try expectLanes(&runtime, &.{.peers});
    lane.commit(1);
    const request = try runtime.incoming.?.reserve(.blocks_by_root_v2, 32);
    try expectLanes(&runtime, &.{});
    runtime.incoming.?.get(request).?.native = true;
    try expectLanes(&runtime, &.{.incoming});

    const table = &runtime.gossip.?;
    try admitGossip(table, .voluntary_exit, null);
    try expectLanes(&runtime, &.{ .incoming, .gossip_ordinary });
    try admitGossip(table, .data_column_sidecar, null);
    try admitGossip(table, .beacon_attestation, @splat(3));
    try expectLanes(&runtime, &.{ .incoming, .gossip_checks, .gossip_urgent, .gossip_ordinary });
    const batch = table.claimDemand(1, .{ .ordinary = false });
    try std.testing.expectEqual(@as(usize, 1), batch.len);
    try expectLanes(&runtime, &.{ .incoming, .gossip_checks, .gossip_ordinary });
    table.finish(&batch, true);

    // Stopping ends takes and checks as their calls do; claims end once the owner quiesces.
    runtime.stop = true;
    try expectLanes(&runtime, &.{.gossip_ordinary});
    runtime.quiescent = true;
    lane.publish(&.{.{ .closed = undefined }}, 2);
    try expectLanes(&runtime, &.{ .settle, .peers });
    runtime.close_settled = true;
    try expectLanes(&runtime, &.{.peers});
    lane.commit(1);
    try expectLanes(&runtime, &.{});

    runtime.incoming.?.get(request).?.native = false;
    runtime.incoming.?.retire(request);
    table.close();
}

/// Checks each table's settle-able set against a scan of its cells, and the O(1) check against
/// the scan under every stop and dispose flag.
fn expectDueMatchesScan(runtime: *Runtime) !void {
    runtime.lock();
    defer runtime.unlock();
    var next: usize = 0;
    for (&runtime.table.cells, 0..) |*cell, i| if (cell.state == .terminal) {
        try std.testing.expectEqual(@as(?usize, i), runtime.table.nextTerminal(next));
        next = i + 1;
    };
    try std.testing.expectEqual(@as(?usize, null), runtime.table.nextTerminal(next));
    var any = next != 0;
    if (runtime.publications) |*table| {
        next = 0;
        for (table.cells, 0..) |*cell, i| if (cell.state == .terminal) {
            try std.testing.expectEqual(@as(?usize, i), table.nextTerminal(next));
            next = i + 1;
        };
        try std.testing.expectEqual(@as(?usize, null), table.nextTerminal(next));
        any = any or next != 0;
    }
    var incoming_any = false;
    if (runtime.incoming) |*table| {
        next = 0;
        for (table.cells, 0..) |*cell, i| if (incoming_mod.settleable(cell)) {
            try std.testing.expectEqual(@as(?usize, i), table.nextDue(next));
            next = i + 1;
        };
        try std.testing.expectEqual(@as(?usize, null), table.nextDue(next));
        incoming_any = next != 0;
    }
    const stop = runtime.stop;
    const disposed = runtime.disposed;
    defer {
        runtime.stop = stop;
        runtime.disposed = disposed;
    }
    for ([_]bool{ false, true }) |stopped| for ([_]bool{ false, true }) |dispose| {
        var requests_any = false;
        if (runtime.requests) |*table| {
            next = 0;
            for (table.cells, 0..) |*cell, i| if (requests_mod.settleable(cell, stopped, dispose)) {
                try std.testing.expectEqual(@as(?usize, i), table.nextDue(next, stopped, dispose));
                next = i + 1;
            };
            try std.testing.expectEqual(@as(?usize, null), table.nextDue(next, stopped, dispose));
            requests_any = next != 0;
        }
        runtime.stop = stopped;
        runtime.disposed = dispose;
        try std.testing.expectEqual(any or incoming_any or requests_any, runtime.settleableLocked());
    };
}

test "the O(1) settle-able state matches a full scan across state transitions" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 1 << 30;
    runtime.publications = try publications_mod.Table.init(std.testing.allocator, 4, &runtime.payload_budget);
    defer runtime.publications.?.deinit();
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    runtime.incoming = try incoming_mod.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    const deferred: napi.Deferred = undefined;
    try expectDueMatchesScan(&runtime);

    // Commands: queued, executing, waiting and terminal through the owner's transitions.
    const connect = try runtime.table.reserve(.connect);
    const identity = try runtime.table.reserve(.getIdentity);
    try runtime.queueCommand(connect);
    try runtime.queueCommand(identity);
    runtime.table.transition(runtime.table.get(connect), .waiting);
    runtime.table.get(connect).deadline = 5;
    try expectDueMatchesScan(&runtime);
    try std.testing.expect(commands.latchConnects(&runtime.table, &.{}, .{ .mono_ms = 5, .unix_s = 0 }));
    try expectDueMatchesScan(&runtime);
    runtime.cancelCommandsLocked();
    try expectDueMatchesScan(&runtime);
    runtime.table.transition(runtime.table.get(connect), .copying);
    try expectDueMatchesScan(&runtime);
    runtime.table.retire(connect);
    runtime.table.retire(identity);
    try expectDueMatchesScan(&runtime);

    // Publications: a queued publication turns terminal when the owner closes the table.
    const publications = &runtime.publications.?;
    const publication = try publications.reserve(.beacon_block, 8);
    publications.transition(publications.get(publication).?, .queued);
    try expectDueMatchesScan(&runtime);
    publications.close(error.NetworkClosed);
    try expectDueMatchesScan(&runtime);
    publications.transition(publications.get(publication).?, .copying);
    try expectDueMatchesScan(&runtime);
    publications.retire(publication);
    try expectDueMatchesScan(&runtime);

    // Requests: a pulled chunk, its copy, a retirement and the owner's close.
    const requests = &runtime.requests.?;
    const request = try requests.reserve(.blocks_by_root_v2, 32);
    try requests.allocate(request, 32);
    const cell = requests.get(request).?;
    cell.state = .queued;
    requests.refresh(cell);
    runtime.lock();
    requests_mod.armPull(&runtime, cell, deferred);
    runtime.unlock();
    try expectDueMatchesScan(&runtime);
    cell.state = .native;
    cell.native = .{ .index = 0, .generation = 1, .direction = .outbound };
    cell.chunk = .{ .len = 4, .fork = null };
    requests.refresh(cell);
    try expectDueMatchesScan(&runtime);
    cell.copying = true;
    requests.refresh(cell);
    try expectDueMatchesScan(&runtime);
    cell.copying = false;
    cell.pull = null;
    cell.delivered = true;
    requests.refresh(cell);
    try expectDueMatchesScan(&runtime);
    runtime.lock();
    requests_mod.armRetirement(&runtime, cell, deferred);
    runtime.unlock();
    try expectDueMatchesScan(&runtime);
    runtime.stop = true;
    try expectDueMatchesScan(&runtime);
    requests_mod.closeLocked(&runtime);
    try expectDueMatchesScan(&runtime);
    runtime.disposed = true;
    try expectDueMatchesScan(&runtime);
    cell.retirement = null;
    requests.retire(request);
    try expectDueMatchesScan(&runtime);
    runtime.stop = false;
    runtime.disposed = false;

    // Incoming: a taken request whose permission, acknowledgement and close settle.
    const incoming = &runtime.incoming.?;
    const served = try incoming.reserve(.blocks_by_root_v2, 32);
    const inbound = incoming.get(served).?;
    inbound.native = true;
    inbound.exposed = true;
    inbound.closed = deferred;
    inbound.state = .serving;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission = deferred;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission_ready = true;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission = null;
    inbound.permission_ready = false;
    inbound.pending = deferred;
    inbound.state = .response_native;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.ack = .sent;
    inbound.state = .serving;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.copying = true;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.copying = false;
    inbound.pending = null;
    inbound.ack = null;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    runtime.quiescent = true;
    incoming_mod.closeLocked(&runtime);
    try expectDueMatchesScan(&runtime);
    inbound.closed = null;
    incoming.retire(served);
    try expectDueMatchesScan(&runtime);
    runtime.quiescent = false;

    // Arbitrary interleavings of the fields the predicates read keep every set exact.
    var prng = std.Random.DefaultPrng.init(0x5e771e);
    const random = prng.random();
    const requested = [_]requests_mod.Token{ try requests.reserve(.blocks_by_root_v2, 32), try requests.reserve(.blocks_by_root_v2, 32) };
    const taken = [_]incoming_mod.Token{ try incoming.reserve(.blocks_by_root_v2, 32), try incoming.reserve(.blocks_by_root_v2, 32) };
    for (0..2_000) |_| {
        const outbound = requests.get(requested[random.uintLessThan(usize, 2)]).?;
        switch (random.uintLessThan(u8, 8)) {
            0 => outbound.state = random.enumValue(requests_mod.State),
            1 => outbound.copying = random.boolean(),
            2 => outbound.pull = if (random.boolean()) deferred else null,
            3 => outbound.chunk = if (random.boolean()) .{ .len = 1, .fork = null } else null,
            4 => outbound.delivered = random.boolean(),
            5 => outbound.retiring = random.boolean(),
            6 => outbound.terminal = if (random.boolean()) .done else null,
            else => outbound.native = if (random.boolean()) .{ .index = 0, .generation = 1, .direction = .outbound } else null,
        }
        if (outbound.state == .free) outbound.state = .terminal;
        requests.refresh(outbound);
        const inbound_cell = incoming.get(taken[random.uintLessThan(usize, 2)]).?;
        switch (random.uintLessThan(u8, 7)) {
            0 => inbound_cell.state = random.enumValue(incoming_mod.State),
            1 => inbound_cell.copying = random.boolean(),
            2 => inbound_cell.ack = if (random.boolean()) .sent else null,
            3 => inbound_cell.pending = if (random.boolean()) deferred else null,
            4 => inbound_cell.native = random.boolean(),
            5 => inbound_cell.closed = if (random.boolean()) deferred else null,
            else => {
                inbound_cell.permission = if (random.boolean()) deferred else null;
                inbound_cell.permission_ready = random.boolean();
            },
        }
        if (inbound_cell.state == .free) inbound_cell.state = .serving;
        incoming.refresh(inbound_cell);
        runtime.stop = random.boolean();
        runtime.disposed = random.boolean();
        try expectDueMatchesScan(&runtime);
    }
    runtime.stop = false;
    runtime.disposed = false;
    for (requested) |token| {
        const outbound = requests.get(token).?;
        outbound.* = .{ .state = .terminal, .generation = outbound.generation, .reservation = outbound.reservation };
        requests.retire(token);
    }
    for (taken) |token| {
        const inbound_cell = incoming.get(token).?;
        inbound_cell.* = .{ .state = .terminal, .generation = inbound_cell.generation, .reservation = inbound_cell.reservation, .input = inbound_cell.input };
        incoming.retire(token);
    }
    try expectDueMatchesScan(&runtime);
}
