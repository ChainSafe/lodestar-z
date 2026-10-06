const std = @import("std");
const Now = @import("network").Now;
const n = @import("network");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const commands = r.commands;
const publications_mod = r.publications_mod;
const requests_mod = r.requests_mod;
const incoming_mod = r.incoming_mod;
const projection = r.projection;
const support = @import("network_test_support.zig");
const exchange = @import("network_exchange.zig");
const network_wake = @import("network_wake.zig");

test "stop preserves latched success and cancels accepted nonterminal commands" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
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

test "request table storage retires only after physical quiescence and final pins" {
    var runtime: Runtime = .{ .env = undefined };
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

test "one runtime is live per process until its last release" {
    const first = try r.create(undefined);
    try std.testing.expectError(error.NetworkAlreadyInitialized, r.create(undefined));
    first.release();
    const second = try r.create(undefined);
    second.release();
}

test "a payload release while the owner waits for budget wakes the owner once" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
    runtime.wake = try network_wake.Wake.init();
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

test "abandon wakes an owner already stopping gracefully" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
    runtime.wake = try network_wake.Wake.init();
    defer runtime.wake.?.deinit();
    runtime.requestStop();
    try runtime.wake.?.drain();
    var readable = [_]std.c.pollfd{.{ .fd = runtime.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(c_int, 0), std.c.poll(&readable, 1, 0));
    runtime.abandon();
    try std.testing.expect(!runtime.graceful);
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&readable, 1, 0));
    try runtime.wake.?.drain();
}

test "a requested stop removes queued gossip from host delivery" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
    runtime.gossip = try n.gossip_processor.GossipProcessor.init(std.testing.allocator, .{
        .limits = @splat(.{ .items = 4, .bytes = 4096 }),
    });
    defer {
        runtime.gossip.?.close();
        runtime.gossip.?.deinit();
    }
    const table = &runtime.gossip.?;
    const topic = "/eth2/00000000/beacon_block/ssz_snappy";
    try table.capture(&.{
        .handle = .{ .index = 0, .generation = 1 },
        .id = @splat(1),
        .peer = .{ .index = 0, .generation = 1 },
        .topic = topic,
        .bytes = "x",
        .identity = .{ .bytes = @splat(1) },
        .admitted_ms = 1,
        .deadline = 101,
    }, n.gossipsub.topic.parseCanonical(topic).?, &.{}, false, 1);
    try std.testing.expectEqual(.payload, runtime.wantLocked(.gossip));
    runtime.requestStop();
    try std.testing.expectEqual(.none, runtime.wantLocked(.gossip));
    try std.testing.expect(!runtime.quiescent);
}

test "an owner completion notifies once while armed and leaves settlement to the exchange" {
    var runtime: Runtime = .{ .env = undefined };
    const before = support.notifications.load(.acquire);
    const token = try runtime.table.reserve(.getIdentity);
    runtime.table.transition(runtime.table.get(token), .terminal);
    runtime.lock();
    runtime.recomputeLocked(.completions);
    runtime.recomputeLocked(.completions);
    runtime.unlock();
    try std.testing.expectEqual(before + 1, support.notifications.load(.acquire));
    try std.testing.expect(!runtime.readiness.armed);
    try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    // Disarmed, a second completion adds to the queued row without another notification.
    const second = try runtime.table.reserve(.getIdentity);
    runtime.lock();
    runtime.table.transition(runtime.table.get(second), .terminal);
    runtime.recomputeLocked(.completions);
    try std.testing.expect(!runtime.readiness.arm());
    runtime.unlock();
    for ([_]commands.Token{ token, second }) |settled| runtime.table.retire(settled);
    runtime.lock();
    runtime.refreshLocked();
    try std.testing.expect(runtime.readiness.arm());
    runtime.unlock();
    try std.testing.expectEqual(before + 1, support.notifications.load(.acquire));
}

test "the first terminal failure is the close result's, also after a requested stop" {
    var runtime: Runtime = .{ .env = undefined };
    runtime.requestStop();
    try std.testing.expectEqual(r.Reason.requested, runtime.reason);
    // A notification the host cannot receive fails the stopping owner; a later failure keeps the first.
    support.status = 9;
    defer support.status = 0;
    runtime.lock();
    runtime.notifyLocked();
    const first = runtime.terminal_error.?;
    runtime.failLocked(error.NetworkWakeFailed);
    runtime.unlock();
    runtime.requestStop();
    try std.testing.expectEqual(r.Reason.failed, runtime.reason);
    try std.testing.expect(first != error.NetworkWakeFailed);
    try std.testing.expectEqual(first, runtime.terminal_error.?);
    try std.testing.expect(runtime.state == .failed);
}

/// An exchange host that builds only the peer count.
const PeerHost = struct {
    pub const Result = struct { peers: usize, more: bool };
    pub fn build(_: *PeerHost, selection: *exchange.Selection) !usize {
        return selection.peer_count;
    }
    pub fn finish(_: *PeerHost, peers: usize, outcome: exchange.Outcome) !Result {
        return .{ .peers = peers, .more = outcome.more };
    }
    pub fn keepAlive(_: *PeerHost) void {}
    pub fn idle(_: *PeerHost) void {}
    pub fn classify(_: *PeerHost, _: anyerror) exchange.Failure {
        unreachable;
    }
};

test "owner work that races an exchange's check and arm always reaches a later exchange" {
    var runtime: Runtime = .{ .env = undefined };
    var lane: projection.Lane = .{};
    runtime.lane = &lane;
    const Producer = struct {
        produced: u32 = 0,
        done: std.atomic.Value(bool) = .init(false),
        stop: std.atomic.Value(bool) = .init(false),
        /// Publishes into the peer lane as the owner does, until told to stop.
        fn run(self: *@This(), target: *Runtime) void {
            for (0..100_000_000) |_| {
                if (self.stop.load(.acquire)) break;
                target.lock();
                if (self.produced < 5_000 and target.lane.?.len < 64) {
                    target.lane.?.publish(&.{.{ .closed = undefined }}, self.produced);
                    self.produced += 1;
                    target.recomputeLocked(.peers);
                    if (self.produced == 5_000) self.done.store(true, .release);
                }
                target.unlock();
                std.Thread.yield() catch {};
            }
        }
    };
    var producer: Producer = .{};
    var delivered = support.notifications.load(.acquire);
    const thread = try std.Thread.spawn(.{}, Producer.run, .{ &producer, &runtime });
    defer thread.join();
    defer producer.stop.store(true, .release);
    const demand: exchange.Demand = .{ .settle = 32, .peers = 64, .checks = 0, .serving = 0, .messages = 0, .bytes = 0, .claim_ordinary = false, .capacity = null };
    var host: PeerHost = .{};
    var consumed: usize = 0;
    var again = false;
    var exchanges: usize = 0;
    for (0..10_000_000) |_| {
        const notified = support.notifications.load(.acquire) != delivered;
        if (notified) delivered += 1;
        if (notified or again) {
            const output = try exchange.run(&runtime, &.{}, &demand, 0, &host);
            consumed += output.peers;
            again = output.more;
            exchanges += 1;
        } else if (producer.done.load(.acquire) and consumed == 5_000) break;
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(@as(usize, 5_000), consumed);
    try std.testing.expect(runtime.readiness.armed);
    try std.testing.expect(exchanges > 0);
}

test "a pull that makes a completion due notifies once while armed, and only an exchange delivers it" {
    var runtime: Runtime = .{ .env = undefined };
    runtime.payload_budget.limit = 32 + 2 * n.reqresp.Protocol.blocks_by_root_v2.info().response_max;
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 1, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    const token = try runtime.requests.?.reserve(.blocks_by_root_v2, 32);
    try runtime.requests.?.allocate(token, 32);
    const cell = runtime.requests.?.get(token).?;
    cell.state = .native;
    cell.native = .{ .index = 0, .generation = 1, .direction = .outbound };
    cell.chunk = .{ .len = 4, .fork = null };
    const before = support.notifications.load(.acquire);
    runtime.lock();
    try std.testing.expect(!runtime.settleableLocked());
    requests_mod.armPull(&runtime, cell);
    try std.testing.expect(runtime.settleableLocked());
    runtime.unlock();
    try std.testing.expect(cell.pulling and cell.chunk != null and !cell.delivered);
    try std.testing.expectEqual(before + 1, support.notifications.load(.acquire));
    try std.testing.expect(!runtime.readiness.armed);
    // Disarmed, a retirement adds no notification. It wins over the undelivered chunk: the pull waits for the
    // cancellation's terminal outcome.
    runtime.lock();
    requests_mod.armRetirement(&runtime, cell, true);
    try std.testing.expect(!runtime.settleableLocked());
    runtime.unlock();
    try std.testing.expect(cell.retiring and cell.cancel and cell.retirement_awaited and cell.pulling);
    try std.testing.expectEqual(before + 1, support.notifications.load(.acquire));
    cell.native = null;
    cell.chunk = null;
    runtime.requests.?.retire(token);
}

/// Checks each table's settle-able set against a scan of its cells, and the O(1) check against
/// the scan under every stop and quiescent flag.
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
    const quiescent = runtime.quiescent;
    defer {
        runtime.stop = stop;
        runtime.quiescent = quiescent;
    }
    for ([_]bool{ false, true }) |stopped| for ([_]bool{ false, true }) |quiesced| {
        var requests_any = false;
        if (runtime.requests) |*table| {
            next = 0;
            for (table.cells, 0..) |*cell, i| if (requests_mod.settleable(cell, stopped, quiesced)) {
                try std.testing.expectEqual(@as(?usize, i), table.nextDue(next, stopped, quiesced));
                next = i + 1;
            };
            try std.testing.expectEqual(@as(?usize, null), table.nextDue(next, stopped, quiesced));
            requests_any = next != 0;
        }
        runtime.stop = stopped;
        runtime.quiescent = quiesced;
        try std.testing.expectEqual(any or incoming_any or requests_any, runtime.settleableLocked());
    };
}

test "the O(1) settle-able state matches a full scan across state transitions" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 1 << 30;
    runtime.publications = try publications_mod.Table.init(std.testing.allocator, 4, &runtime.payload_budget);
    defer runtime.publications.?.deinit();
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    runtime.incoming = try incoming_mod.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    try expectDueMatchesScan(&runtime);

    // Commands: queued, executing, waiting and terminal through the owner's transitions.
    const connect = try runtime.table.reserve(.connect);
    const identity = try runtime.table.reserve(.getIdentity);
    try runtime.queueCommand(connect);
    try runtime.queueCommand(identity);
    runtime.table.transition(runtime.table.get(connect), .waiting);
    runtime.table.get(connect).deadline = 5;
    try expectDueMatchesScan(&runtime);
    try std.testing.expect(commands.latchConnects(&runtime.table, &.{}, Now.fromMilliseconds(.{ .mono_ms = 5, .unix_s = 0 })));
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
    requests_mod.armPull(&runtime, cell);
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
    cell.pulling = false;
    cell.delivered = true;
    requests.refresh(cell);
    try expectDueMatchesScan(&runtime);
    runtime.lock();
    requests_mod.armRetirement(&runtime, cell, true);
    runtime.unlock();
    try expectDueMatchesScan(&runtime);
    runtime.stop = true;
    try expectDueMatchesScan(&runtime);
    requests_mod.closeLocked(&runtime);
    try expectDueMatchesScan(&runtime);
    runtime.quiescent = true;
    try expectDueMatchesScan(&runtime);
    requests.retire(request);
    try expectDueMatchesScan(&runtime);
    runtime.stop = false;
    runtime.quiescent = false;

    // Incoming: a taken request whose permission, acknowledgement and close are delivered.
    const incoming = &runtime.incoming.?;
    const served = try incoming.reserve(.blocks_by_root_v2, 32);
    const inbound = incoming.get(served).?;
    inbound.native = true;
    inbound.exposed = true;
    inbound.closed_awaited = true;
    inbound.state = .serving;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission_awaited = true;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission_ready = true;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    inbound.permission_awaited = false;
    inbound.permission_ready = false;
    inbound.response_awaited = true;
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
    inbound.response_awaited = false;
    inbound.ack = null;
    incoming.refresh(inbound);
    try expectDueMatchesScan(&runtime);
    runtime.quiescent = true;
    incoming_mod.closeLocked(&runtime);
    try expectDueMatchesScan(&runtime);
    inbound.closed_awaited = false;
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
            2 => outbound.pulling = random.boolean(),
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
            3 => inbound_cell.response_awaited = random.boolean(),
            4 => inbound_cell.native = random.boolean(),
            5 => inbound_cell.closed_awaited = random.boolean(),
            else => {
                inbound_cell.permission_awaited = random.boolean();
                inbound_cell.permission_ready = random.boolean();
            },
        }
        if (inbound_cell.state == .free) inbound_cell.state = .serving;
        incoming.refresh(inbound_cell);
        runtime.stop = random.boolean();
        runtime.quiescent = random.boolean();
        try expectDueMatchesScan(&runtime);
    }
    runtime.stop = false;
    runtime.quiescent = false;
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
