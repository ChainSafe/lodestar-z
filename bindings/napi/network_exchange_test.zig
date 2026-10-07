const std = @import("std");
const n = @import("network");
const exchange = @import("network_exchange.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const commands = @import("network_commands.zig");
const publications = @import("network_publications.zig");
const outgoing = @import("network_requests.zig");
const tsfn = @import("network_test_support.zig");
const fatal = @import("network_fatal.zig");
const Runtime = r.Runtime;
const Kind = n.gossip_processor.limits.Kind;
const limits_mod = n.gossip_processor.limits;
const State = n.gossip_processor.GossipProcessor.State;
const network_wake = @import("network_wake.zig");
const network_storage = @import("network_storage.zig");

const Part = enum { peers, serving, checks, gossip, acknowledged, completions, closed };

/// Builds a summary instead of JS values, fails at one part or while finishing when asked, and records a
/// contract failure's site instead of terminating. `during` runs where the build runs, as owner work racing phase C.
const Host = struct {
    runtime: *Runtime,
    clock: u64 = 1,
    fail: ?Part = null,
    fail_finish: bool = false,
    failure: exchange.Failure = .stopped,
    builds: usize = 0,
    kept_alive: usize = 0,
    idled: usize = 0,
    site: ?fatal.Site = null,
    /// Terminate on a contract failure, as the N-API host does.
    aborts: bool = false,
    during: ?*const fn (*Runtime) void = null,

    pub const Result = struct {
        peers: usize = 0,
        serving: [exchange.serving_max]incoming.Token = undefined,
        serving_count: usize = 0,
        checks: g.Batch = .{},
        gossip: ?g.Batch = null,
        acknowledged: [exchange.acknowledged_max]g.Token = undefined,
        acknowledged_count: usize = 0,
        publications: [exchange.completion_max]publications.Token = undefined,
        publication_count: usize = 0,
        commands: [commands.capacity]commands.Token = undefined,
        command_count: usize = 0,
        requests: [outgoing.capacity_max]outgoing.Completion = undefined,
        request_count: usize = 0,
        incoming: [incoming.capacity_max]incoming.Completion = undefined,
        incoming_count: usize = 0,
        closed: ?exchange.Closed = null,
        outcome: exchange.Outcome = .{},
    };

    fn failing(self: *const Host, part: Part) bool {
        return if (self.fail) |value| value == part else false;
    }
    fn failure_error(self: *const Host) anyerror {
        return if (self.failure == .stopped) error.PendingException else error.InvalidArg;
    }
    pub fn build(self: *Host, selection: *exchange.Selection) !Result {
        self.builds += 1;
        if (self.during) |during| during(self.runtime);
        if (self.failing(.peers) and selection.peer_count > 0) return self.failure_error();
        if (self.failing(.serving) and selection.serving_count > 0) return self.failure_error();
        if (self.failing(.checks) and selection.checks.len > 0) return self.failure_error();
        if (self.failing(.gossip) and selection.gossip != null) return self.failure_error();
        if (self.failing(.acknowledged) and selection.acknowledged_count > 0) return self.failure_error();
        if (self.failing(.completions) and selection.publication_count + selection.command_count + selection.request_count + selection.incoming_count > 0) return self.failure_error();
        if (self.failing(.closed) and selection.closed != null) return self.failure_error();
        return .{ .peers = selection.peer_count, .serving = selection.serving, .serving_count = selection.serving_count, .checks = selection.checks, .gossip = selection.gossip, .acknowledged = selection.acknowledged, .acknowledged_count = selection.acknowledged_count, .publications = selection.publications, .publication_count = selection.publication_count, .commands = selection.commands, .command_count = selection.command_count, .requests = selection.requests, .request_count = selection.request_count, .incoming = selection.incoming, .incoming_count = selection.incoming_count, .closed = selection.closed };
    }
    pub fn finish(self: *Host, output: Result, outcome: exchange.Outcome) !Result {
        if (self.fail_finish) return self.failure_error();
        var result = output;
        result.outcome = outcome;
        return result;
    }
    pub fn keepAlive(self: *Host) void {
        self.kept_alive += 1;
    }
    pub fn idle(self: *Host) void {
        self.idled += 1;
    }
    pub fn classify(self: *Host, _: anyerror) exchange.Failure {
        return self.failure;
    }
    pub fn terminate(self: *Host, site: fatal.Site, err: anyerror) anyerror {
        if (self.aborts) fatal.terminate(undefined, site, @errorName(err));
        self.site = site;
        return err;
    }

    fn turn(self: *Host, actions: []const exchange.Action, demand: exchange.Demand) !Result {
        return exchange.run(self.runtime, actions, &demand, self.clock, self);
    }
};

const deployed: exchange.Demand = .{ .delivery = .{ .capacity = .{ .incoming_request_slots = 32, .gossip_validation = .ready }, .serving_starts = 8, .claim_non_urgent_gossip = true } };
const control: exchange.Demand = .control;

fn admit(runtime: *Runtime, kind: Kind, root: ?[32]u8, payload: []const u8) !g.Token {
    const table = &runtime.bridge.gossip.?;
    const canonical: n.gossipsub.topic.Canonical = .{ .digest = @splat(0), .name = .{ .kind = kind } };
    var topic: [n.gossip_processor.GossipProcessor.topic_max]u8 = undefined;
    try table.capture(&.{
        .handle = .{ .index = 0, .generation = 1 },
        .id = @splat(1),
        .peer = .{ .index = 0, .generation = 1 },
        .topic = n.gossipsub.topic.buildCanonical(canonical, &topic),
        .bytes = payload,
        .identity = .{ .bytes = @splat(1) },
        .admitted_ms = 0,
        .deadline = 100,
    }, canonical, &.{ .slot = 1, .root = root }, false, 0);
    const index = table.expiry.tail;
    const token: g.Token = .{ .index = @intCast(index), .generation = table.cells[index].generation };
    runtime.lock();
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    return token;
}

fn queueRequest(runtime: *Runtime) !incoming.Token {
    const table = &runtime.bridge.incoming.?;
    const token = try table.reserve(.blocks_by_root_v2, 32);
    try table.allocate(token, &(.{7} ** 32));
    const cell = table.get(token).?;
    cell.native = true;
    table.refresh(cell);
    runtime.lock();
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    return token;
}

fn publishPeer(runtime: *Runtime) void {
    runtime.lock();
    defer runtime.unlock();
    runtime.bridge.peer_updates.?.publish(&.{.{ .closed = undefined }}, 1);
    runtime.notifyIfReadyLocked();
}

/// Ends a served stream the host was handed, as its close completion and release would.
fn retireServed(table: *incoming.Table, token: incoming.Token) void {
    const cell = table.get(token).?;
    cell.closed_awaited = false;
    cell.native = false;
    table.retire(token);
}

fn retireQueued(runtime: *Runtime) void {
    for (runtime.bridge.incoming.?.cells, 0..) |*cell, i| if (cell.state != .free) {
        cell.native = false;
        runtime.bridge.incoming.?.retire(.{ .index = @intCast(i), .generation = cell.generation });
    };
}

const Fixture = struct {
    runtime: Runtime,
    lane: projection.Lane = .{},

    /// A runtime with a lane, two serving cells and a small gossip table. `notified` makes its notifications
    /// reach the counting test notifier.
    fn init(self: *Fixture, notified: bool, serving: usize) !void {
        self.* = .{ .runtime = .{ .env = undefined, .bridge = .{ .env_alive = notified } } };
        self.runtime.bridge.payload_budget.limit = 64 << 20;
        self.runtime.bridge.peer_updates = &self.lane;
        self.runtime.bridge.incoming = try incoming.Table.init(std.testing.allocator, serving, &self.runtime.bridge.payload_budget);
        const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
        self.runtime.bridge.gossip = try g.Table.init(std.testing.allocator, .{ .limits = limits });
    }
    fn deinit(self: *Fixture) void {
        retireQueued(&self.runtime);
        self.runtime.bridge.incoming.?.deinit();
        self.runtime.bridge.gossip.?.close();
        self.runtime.bridge.gossip.?.deinit();
    }
};

fn stopAt(part: Part) !void {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    for (0..2) |_| publishPeer(runtime);
    const requests = [_]incoming.Token{ try queueRequest(runtime), try queueRequest(runtime) };
    const checked = try admit(runtime, .beacon_attestation, @splat(3), "data");
    const column = try admit(runtime, .data_column_sidecar, null, "data");
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    const completed = [_]commands.Token{ try completeCommand(runtime, .getIdentity), try completeCommand(runtime, .getIdentity) };

    var host: Host = .{ .runtime = runtime, .fail = part };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, deployed));
    try std.testing.expectEqual(null, host.site);
    // Every pinned item is back where it was, completed commands included.
    for (completed) |token| try std.testing.expectEqual(commands.State.terminal, runtime.bridge.commands.get(token).state);
    try std.testing.expectEqual(@as(u8, 2), fixture.lane.len);
    for (requests) |token| {
        const cell = runtime.bridge.incoming.?.get(token).?;
        try std.testing.expect(cell.state == .queued and !cell.copying and cell.native and cell.input.len == 32);
    }
    const table = &runtime.bridge.gossip.?;
    try std.testing.expectEqual(State.needs_check, table.get(checked).?.state);
    for ([_]g.Token{ column, exit }) |token| try std.testing.expectEqual(State.queued, table.get(token).?.state);
    try std.testing.expectEqual(@as(usize, 0), table.diag.executing);
    try std.testing.expectEqual(@as(usize, 0), table.diag.copying);
    try std.testing.expect(!runtime.bridge.notification_armed);
    for ([_]r.DeliveryKind{ .peers, .checks, .serving, .gossip }) |kind| try std.testing.expect(runtime.deliverableLocked(kind));

    // Were the environment still running, the next exchange would deliver the same items.
    host.fail = null;
    const delivered = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(@as(usize, 2), delivered.peers);
    try std.testing.expectEqual(@as(u8, 0), fixture.lane.len);
    try std.testing.expectEqualSlices(incoming.Token, &requests, delivered.serving[0..delivered.serving_count]);
    try std.testing.expectEqual(@as(usize, 1), host.kept_alive);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, delivered.checks.tokens[0..delivered.checks.len]);
    try std.testing.expectEqualSlices(g.Token, &.{ column, exit }, delivered.gossip.?.tokens[0..delivered.gossip.?.len]);
    try std.testing.expectEqualSlices(commands.Token, &completed, delivered.commands[0..delivered.command_count]);
    try std.testing.expectEqual(@as(u8, 0), runtime.bridge.commands.occupied);
    for (requests) |token| retireServed(&runtime.bridge.incoming.?, token);
}

test "a stopped environment during the build at any payload part restores the pins and never replays settlement" {
    inline for (.{ Part.peers, Part.serving, Part.checks, Part.gossip }) |part| try stopAt(part);
}

test "a stopped environment while finishing a built result shuts down locally, and a contract failure there is fatal" {
    inline for ([_]exchange.Failure{ .stopped, .contract }) |failure| {
        var fixture: Fixture = undefined;
        try fixture.init(false, 2);
        defer fixture.deinit();
        const runtime = &fixture.runtime;
        publishPeer(runtime);
        const exit = try admit(runtime, .voluntary_exit, null, "data");
        var host: Host = .{ .runtime = runtime, .fail_finish = true, .failure = failure };
        try std.testing.expectError(if (failure == .stopped) error.PendingException else error.InvalidArg, host.turn(&.{}, deployed));
        try std.testing.expectEqual(if (failure == .contract) fatal.Site.exchange_finish else null, host.site);
        // The delivery committed before finishing: its items belong to the host, and teardown reclaims them.
        try std.testing.expectEqual(@as(u8, 0), fixture.lane.len);
        try std.testing.expectEqual(State.delivered, runtime.bridge.gossip.?.get(exit).?.state);
        try std.testing.expect(runtime.bridge.notification_armed);
    }
}

test "a contract failure is not retried: the exchange terminates after one build" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    _ = try admit(runtime, .voluntary_exit, null, "data");
    var host: Host = .{ .runtime = runtime, .fail = .gossip, .failure = .contract };
    try std.testing.expectError(error.InvalidArg, host.turn(&.{}, deployed));
    try std.testing.expectEqual(@as(usize, 1), host.builds);
    try std.testing.expectEqual(fatal.Site.exchange_build, host.site);
    try std.testing.expectEqual(@as(usize, 0), runtime.bridge.gossip.?.diag.copying);
}

test "a contract failure terminates the process at the build site without a retry (child process)" {
    try tsfn.expectFatal(struct {
        fn run() void {
            var fixture: Fixture = undefined;
            fixture.init(false, 2) catch std.c._exit(2);
            _ = admit(&fixture.runtime, .voluntary_exit, null, "data") catch std.c._exit(2);
            var host: Host = .{ .runtime = &fixture.runtime, .fail = .gossip, .failure = .contract, .aborts = true };
            _ = host.turn(&.{}, deployed) catch {};
        }
    }.run, "FATAL ERROR: native network bridge exchange_build: InvalidArg\n");
}

test "control-only exchanges leave payload queued and arm for new completions" {
    var fixture: Fixture = undefined;
    try fixture.init(true, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    publishPeer(runtime);
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    for (0..commands.capacity - 1) |_| _ = try completeCommand(runtime, .getIdentity);
    var host: Host = .{ .runtime = runtime };
    var batches: usize = 0;
    const demand = control;
    for (0..8) |_| {
        const result = try host.turn(&.{}, demand);
        batches += 1;
        try std.testing.expect(result.peers == 0 and result.gossip == null);
        try std.testing.expectEqual(runtime.bridge.commands.occupied > 0, result.outcome.needs_another_exchange);
        if (!result.outcome.needs_another_exchange) break;
    }
    try std.testing.expectEqual(@as(usize, 1), batches);
    try std.testing.expectEqual(@as(u8, 1), fixture.lane.len);
    try std.testing.expect(runtime.bridge.notification_armed);
    const before = tsfn.notifications.load(.acquire);
    _ = try completeCommand(runtime, .getIdentity);
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    const result = try host.turn(&.{}, deployed);
    try std.testing.expect(result.peers == 1 and result.gossip != null and runtime.bridge.notification_armed);
    runtime.bridge.gossip.?.retire(exit);
}

test "blocked arrivals wait for host capacity while urgent arrivals still notify" {
    var fixture: Fixture = undefined;
    try fixture.init(true, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var host: Host = .{ .runtime = runtime };
    var demand = deployed;
    demand.delivery.capacity = .{};
    try std.testing.expect(!(try host.turn(&.{}, demand)).outcome.needs_another_exchange);
    try std.testing.expect(runtime.bridge.notification_armed);
    const before = tsfn.notifications.load(.acquire);
    const request = try queueRequest(runtime);
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    try std.testing.expectEqual(before, tsfn.notifications.load(.acquire));
    const parked = try host.turn(&.{}, demand);
    try std.testing.expect(!parked.outcome.needs_another_exchange);
    try std.testing.expect(parked.serving_count == 0 and parked.gossip == null and runtime.bridge.notification_armed);
    // An executable urgent admission notifies even while nonurgent work waits for capacity.
    const column = try admit(runtime, .data_column_sidecar, null, "data");
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    const urgent = try host.turn(&.{}, demand);
    try std.testing.expectEqualSlices(g.Token, &.{column}, urgent.gossip.?.tokens[0..urgent.gossip.?.len]);
    try std.testing.expect(!urgent.outcome.needs_another_exchange);
    // Returning capacity delivers the parked work.
    demand.delivery.capacity = .{ .incoming_request_slots = 1, .gossip_validation = .ready };
    const delivered = try host.turn(&.{}, demand);
    try std.testing.expectEqualSlices(incoming.Token, &.{request}, delivered.serving[0..delivered.serving_count]);
    try std.testing.expectEqualSlices(g.Token, &.{exit}, delivered.gossip.?.tokens[0..delivered.gossip.?.len]);
    try std.testing.expect(!delivered.outcome.needs_another_exchange);
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    retireServed(&runtime.bridge.incoming.?, request);
    for ([_]g.Token{ exit, column }) |token| runtime.bridge.gossip.?.retire(token);
}

test "a serving capacity of 32 under a quota of 8 takes four immediate exchanges and never parks" {
    var fixture: Fixture = undefined;
    try fixture.init(false, incoming.capacity_max);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    for (0..incoming.capacity_max) |_| _ = try queueRequest(runtime);
    var host: Host = .{ .runtime = runtime };
    var demand = deployed;
    for (0..4) |i| {
        const result = try host.turn(&.{}, demand);
        demand.delivery.capacity.incoming_request_slots -= exchange.serving_max;
        try std.testing.expectEqual(@as(usize, exchange.serving_max), result.serving_count);
        try std.testing.expectEqual(i < 3, result.outcome.needs_another_exchange);
        for (result.serving[0..result.serving_count]) |token| retireServed(&runtime.bridge.incoming.?, token);
    }
    try std.testing.expectEqual(@as(u32, 0), runtime.bridge.capacity.?.incoming_request_slots);
}

test "publications before phase B, during phase C and after phase D each reach an exchange" {
    var fixture: Fixture = undefined;
    try fixture.init(true, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var host: Host = .{ .runtime = runtime };
    const before = tsfn.notifications.load(.acquire);
    _ = try host.turn(&.{}, deployed);
    // Before phase B: armed, so the arrival notifies.
    publishPeer(runtime);
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    // Arrivals during copying remain queued and require another exchange.
    host.during = publishPeer;
    const racing = try host.turn(&.{}, deployed);
    try std.testing.expect(racing.peers == 1 and racing.outcome.needs_another_exchange and !runtime.bridge.notification_armed);
    try std.testing.expectEqual(@as(u8, 1), fixture.lane.len);
    host.during = null;
    try std.testing.expect(!(try host.turn(&.{}, deployed)).outcome.needs_another_exchange and runtime.bridge.notification_armed);
    // After phase D armed, the next arrival notifies; a full queue still leaves its undequeued notification.
    tsfn.status = napi_queue_full;
    publishPeer(runtime);
    tsfn.status = 0;
    try std.testing.expect(!runtime.bridge.notification_armed and runtime.bridge.notify_live and !runtime.bridge.stop);
    publishPeer(runtime);
    try std.testing.expectEqual(before + 2, tsfn.notifications.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), (try host.turn(&.{}, deployed)).peers);
}
const napi_queue_full = @import("zapi:zapi").napi.c.napi_queue_full;

test "a stop ends new host work while quiescence preserves terminal delivery" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const request = try queueRequest(runtime);
    const checked = try admit(runtime, .beacon_attestation, @splat(3), "data");
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    const command = try runtime.reserveCommand(.getIdentity);
    try runtime.queueCommand(command);
    runtime.bridge.stop = true;
    var host: Host = .{ .runtime = runtime };
    const stopped = try host.turn(&.{}, deployed);
    try std.testing.expect(stopped.serving_count == 0 and stopped.checks.len == 0);
    try std.testing.expect(stopped.gossip == null);
    try std.testing.expectEqual(State.queued, runtime.bridge.gossip.?.get(exit).?.state);
    try std.testing.expect(!runtime.deliverableLocked(.serving));
    try std.testing.expect(!runtime.deliverableLocked(.checks));
    try std.testing.expect(!runtime.deliverableLocked(.gossip));
    try std.testing.expectEqual(State.needs_check, runtime.bridge.gossip.?.get(checked).?.state);
    // Quiescence cancels the command, whose completion holds the close back: its exchange still delivers the peer
    // event but claims no gossip. The close then arrives alone.
    runtime.lock();
    runtime.bridge.quiescent = true;
    runtime.cancelCommandsLocked();
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    publishPeer(runtime);
    const quiescent = try host.turn(&.{}, deployed);
    try std.testing.expect(quiescent.peers == 1 and quiescent.gossip == null and quiescent.command_count == 1 and quiescent.closed == null);
    try std.testing.expect((try host.turn(&.{}, deployed)).closed != null);
    _ = request;
}

test "actions apply before selection, so a check classified in an exchange is claimed by it, and wake the owner once" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.wake = try network_wake.Wake.init();
    defer runtime.bridge.wake.?.deinit();
    var readable = [_]std.c.pollfd{.{ .fd = runtime.bridge.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 }};
    const checked = try admit(runtime, .beacon_attestation, @splat(3), "data");
    var host: Host = .{ .runtime = runtime };
    const checks = try host.turn(&.{}, deployed);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, checks.checks.tokens[0..checks.checks.len]);
    try runtime.bridge.wake.?.drain();
    const answered = try host.turn(&.{.{ .classify = .{ .token = checked, .available = true } }}, deployed);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, answered.gossip.?.tokens[0..answered.gossip.?.len]);
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&readable, 1, 0));
    try runtime.bridge.wake.?.drain();
    // An obligation-only batch wakes the owner for the verdict it leaves.
    const verdict = try host.turn(&.{.{ .verdict = .{ .token = checked, .verdict = .accept } }}, control);
    try std.testing.expect(!verdict.outcome.needs_another_exchange);
    try std.testing.expectEqual(State.verdict_pending, runtime.bridge.gossip.?.get(checked).?.state);
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&readable, 1, 0));
    try runtime.bridge.wake.?.drain();
    runtime.bridge.gossip.?.retire(checked);
}

test "a 128-column burst reaches the host within two exchanges under saturated ordinary gossip and serving" {
    var runtime: Runtime = .{ .env = undefined, .bridge = .{ .notify_live = false, .env_alive = false } };
    runtime.bridge.payload_budget.limit = 64 << 20;
    runtime.bridge.incoming = try incoming.Table.init(std.testing.allocator, incoming.capacity_max, &runtime.bridge.payload_budget);
    defer runtime.bridge.incoming.?.deinit();
    var limits: limits_mod.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    limits[@intFromEnum(Kind.data_column_sidecar)] = .{ .items = 256, .bytes = 4 << 20 };
    limits[@intFromEnum(Kind.voluntary_exit)] = .{ .items = 1024, .bytes = 1 << 20 };
    runtime.bridge.gossip = try g.Table.init(std.testing.allocator, .{ .limits = limits, .execution = limits });
    defer runtime.bridge.gossip.?.deinit();
    const table = &runtime.bridge.gossip.?;
    for (0..incoming.capacity_max) |_| _ = try queueRequest(&runtime);
    for (0..512) |_| _ = try admit(&runtime, .voluntary_exit, null, "exit");
    const column: [16 * 1024]u8 = @splat(5);
    for (0..128) |_| _ = try admit(&runtime, .data_column_sidecar, null, &column);

    var host: Host = .{ .runtime = &runtime };
    var columns: usize = 0;
    var turns: usize = 0;
    var demand = deployed;
    for (0..16) |_| {
        if (columns == 128) break;
        const delivered = try host.turn(&.{}, demand);
        turns += 1;
        try std.testing.expect(delivered.outcome.needs_another_exchange);
        try std.testing.expectEqual(@as(usize, exchange.serving_max), delivered.serving_count);
        // The host takes each delivery, and both kinds of traffic refill to saturation.
        for (delivered.serving[0..delivered.serving_count]) |token| {
            retireServed(&runtime.bridge.incoming.?, token);
            _ = try queueRequest(&runtime);
        }
        demand.delivery.capacity = .{ .incoming_request_slots = 32, .gossip_validation = .ready };
        const batch = delivered.gossip.?;
        try std.testing.expectEqual(@as(usize, g.batch_max), batch.len);
        for (batch.tokens[0..batch.len]) |token| {
            const kind = table.get(token).?.kind;
            columns += @intFromBool(kind == .data_column_sidecar);
            try std.testing.expect(table.report(token, .accept, host.clock));
            table.retire(token);
            if (kind == .voluntary_exit) _ = try admit(&runtime, .voluntary_exit, null, "exit");
        }
    }
    std.debug.print("exchange column_burst columns={d} turns={d}\n", .{ columns, turns });
    try std.testing.expectEqual(@as(usize, 128), columns);
    try std.testing.expectEqual(@as(usize, 2), turns);
    retireQueued(&runtime);
    table.close();
}

test "exchange acknowledges owner dispositions under any demand, once, without counting delivered items" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const table = &runtime.bridge.gossip.?;
    var tokens: [2]g.Token = undefined;
    for (&tokens) |*token| token.* = try admit(runtime, .voluntary_exit, null, "exit");
    var host: Host = .{ .runtime = runtime };
    const delivered = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(@as(usize, 2), delivered.gossip.?.len);

    // The exchange that reports the verdicts cannot acknowledge them: the owner has not applied them.
    var actions: [2]exchange.Action = undefined;
    for (&actions, tokens) |*action, token| action.* = .{ .verdict = .{ .token = token, .verdict = .accept } };
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&actions, control)).acknowledged_count);
    runtime.lock();
    for (tokens) |token| table.retire(token);
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    try std.testing.expect(runtime.deliverableLocked(.completions));

    // A failed build keeps them for the next exchange.
    host.fail = .acknowledged;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expectEqual(@as(usize, 2), table.diag.acknowledging);
    host.fail = null;
    const acknowledged = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 2), acknowledged.acknowledged_count);
    for (acknowledged.acknowledged[0..2], tokens) |got, token| try std.testing.expect(std.meta.eql(got, token));
    try std.testing.expect(!acknowledged.outcome.needs_another_exchange);
    try std.testing.expectEqual(@as(usize, 0), table.diag.acknowledging);
    for (tokens) |token| try std.testing.expect(table.get(token) == null);
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&.{}, control)).acknowledged_count);
}

/// A publication the owner completed at the lowest free cell, as execution leaves it.
fn completePublication(runtime: *Runtime) !publications.Token {
    const token = try runtime.reservePublication(.beacon_block, 0);
    runtime.lock();
    defer runtime.unlock();
    runtime.bridge.publications.?.transition(runtime.bridge.publications.?.get(token).?, .terminal);
    runtime.notifyIfReadyLocked();
    return token;
}

test "publication completions batch terminal cells while unfinished work stays admitted" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.publications = try publications.Table.init(std.testing.allocator, 4, &runtime.bridge.payload_budget);
    defer runtime.bridge.publications.?.deinit();
    const table = &runtime.bridge.publications.?;
    const low = try completePublication(runtime);
    // Two cells stay admitted but unfinished, so only the lowest and the highest complete.
    const unfinished = [_]publications.Token{ try runtime.reservePublication(.beacon_block, 0), try runtime.reservePublication(.beacon_block, 0) };
    const high = try completePublication(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    const demand = control;
    var delivered: [4]publications.Token = undefined;
    for (0..3) |pass| {
        // The lowest cell completes again whenever it was delivered, with the next generation.
        if (pass > 0 and table.get(.{ .index = 0, .generation = table.cells[0].generation }) == null) _ = try completePublication(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, if (pass == 0) 2 else 1), result.publication_count);
        try std.testing.expect(result.outcome.needs_another_exchange == (table.anyTerminal()));
        for (0..result.publication_count) |i| {
            const token = result.publications[i];
            delivered[if (pass == 0) i else pass + 1] = token;
            try std.testing.expect(table.get(token) == null);
        }
    }
    // Both terminal cells arrive together; refilling uses fresh generations.
    try std.testing.expectEqualSlices(publications.Token, &.{ low, high, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 3 } }, &delivered);
    // Unfinished publications keep the runtime busy.
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    for (unfinished) |token| runtime.retirePublication(token);
}

test "a stopped environment returns pinned publication completions, which the next exchange delivers" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.publications = try publications.Table.init(std.testing.allocator, 4, &runtime.bridge.payload_budget);
    defer runtime.bridge.publications.?.deinit();
    const tokens = [_]publications.Token{ try completePublication(runtime), try completePublication(runtime) };
    var host: Host = .{ .runtime = runtime, .fail = .completions };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    for (tokens) |token| try std.testing.expectEqual(publications.State.terminal, runtime.bridge.publications.?.get(token).?.state);
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    host.fail = null;
    const result = try host.turn(&.{}, control);
    try std.testing.expectEqualSlices(publications.Token, &tokens, result.publications[0..result.publication_count]);
    try std.testing.expect(!result.outcome.needs_another_exchange and runtime.bridge.publications.?.diag.occupied == 0);
    // Retiring the last admitted publication lets the event loop go; the restored exchange did not.
    try std.testing.expectEqual(@as(usize, 1), host.idled);
}

/// A command the owner completed at the lowest free cell, as execution leaves it.
fn completeCommand(runtime: *Runtime, command: commands.Command) !commands.Token {
    const token = try runtime.reserveCommand(command);
    runtime.lock();
    defer runtime.unlock();
    runtime.bridge.commands.transition(runtime.bridge.commands.get(token), .terminal);
    runtime.notifyIfReadyLocked();
    return token;
}

test "command completions batch terminal cells while unfinished work stays admitted, and retire their typed stores" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var stores = try network_storage.Stores.create(std.testing.allocator, 4);
    defer stores.destroy();
    runtime.bridge.stores = stores;
    defer runtime.bridge.stores = null;
    const low = try completeCommand(runtime, .getPeers);
    const unfinished = [_]commands.Token{ try runtime.reserveCommand(.getIdentity), try runtime.reserveCommand(.getIdentity) };
    const high = try completeCommand(runtime, .getDirectPeers);
    try std.testing.expectEqual(low.index + 3, high.index);
    var host: Host = .{ .runtime = runtime };
    const demand = control;
    var delivered: [4]commands.Token = undefined;
    for (0..3) |pass| {
        // The lowest cell completes again whenever it was delivered, taking the freed snapshot store.
        if (pass > 0 and runtime.bridge.commands.cells[low.index].state == .free) _ = try completeCommand(runtime, .getPeers);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, if (pass == 0) 2 else 1), result.command_count);
        for (0..result.command_count) |i| {
            const token = result.commands[i];
            delivered[if (pass == 0) i else pass + 1] = token;
            try std.testing.expectEqual(commands.State.free, runtime.bridge.commands.cells[token.index].state);
        }
    }
    try std.testing.expectEqualSlices(commands.Token, &.{ low, high, .{ .index = low.index, .generation = low.generation + 1 }, .{ .index = low.index, .generation = low.generation + 2 } }, &delivered);
    // Delivery freed each snapshot store, so both remain available.
    try std.testing.expect(!runtime.bridge.commands.stores[1][0] and !runtime.bridge.commands.stores[1][1]);
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    for (unfinished) |token| runtime.abortCommand(token);
}

/// A request admitted at the lowest free cell, holding the runtime as `requestStart` does.
fn admitRequest(runtime: *Runtime) !outgoing.Token {
    const table = &runtime.bridge.requests.?;
    const token = try table.reserve(.blocks_by_root_v2, 0);
    runtime.retain();
    try table.allocate(token, 0);
    table.get(token).?.state = .queued;
    return token;
}

/// Moves an admitted request to where the owner leaves it, and readiness with it.
fn ownerMoves(runtime: *Runtime, token: outgoing.Token, comptime move: fn (*outgoing.Cell) void) void {
    runtime.lock();
    defer runtime.unlock();
    const cell = runtime.bridge.requests.?.get(token).?;
    move(cell);
    runtime.bridge.requests.?.releasePayload(cell);
    runtime.bridge.requests.?.refresh(cell);
    runtime.notifyIfReadyLocked();
}

fn pulledDone(cell: *outgoing.Cell) void {
    cell.state = .terminal;
    cell.terminal = .done;
    cell.pulling = true;
}

fn pulledChunk(cell: *outgoing.Cell) void {
    cell.state = .native;
    cell.native = .{ .index = 0, .generation = 1, .direction = .outbound };
    cell.chunk = .{ .len = 4, .fork = null };
    cell.pulling = true;
}

/// Ends a request the owner still streams, and retires it.
fn retireStreaming(runtime: *Runtime, token: outgoing.Token) void {
    const cell = runtime.bridge.requests.?.get(token).?;
    cell.native = null;
    cell.chunk = null;
    cell.delivered = false;
    runtime.bridge.requests.?.retire(token);
    runtime.release();
}

/// A request whose terminal outcome awaits its pending pull, at the lowest free cell.
fn completeRequest(runtime: *Runtime) !outgoing.Token {
    const token = try admitRequest(runtime);
    ownerMoves(runtime, token, pulledDone);
    return token;
}

test "request completions batch terminal cells while unfinished work stays admitted" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.payload_budget.limit = 1 << 30;
    runtime.bridge.requests = try outgoing.Table.init(std.testing.allocator, 4, &runtime.bridge.payload_budget);
    defer runtime.bridge.requests.?.deinit();
    const table = &runtime.bridge.requests.?;
    const low = try completeRequest(runtime);
    // Two requests stay admitted with no pull, so only the lowest and the highest complete.
    const unpulled = [_]outgoing.Token{ try admitRequest(runtime), try admitRequest(runtime) };
    const high = try completeRequest(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    const demand = control;
    var delivered: [4]outgoing.Token = undefined;
    for (0..3) |pass| {
        // The lowest cell completes again whenever it was delivered, with the next generation.
        if (pass > 0 and table.cells[0].state == .free) _ = try completeRequest(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, if (pass == 0) 2 else 1), result.request_count);
        try std.testing.expectEqual(outgoing.Terminal.done, result.requests[0].value.terminal);
        for (0..result.request_count) |i| {
            const token = result.requests[i].token;
            delivered[if (pass == 0) i else pass + 1] = token;
            try std.testing.expect(table.get(token) == null);
        }
    }
    // Both terminal cells arrive together; refilling uses fresh generations.
    try std.testing.expectEqualSlices(outgoing.Token, &.{ low, high, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 3 } }, &delivered);
    // Once no pull awaits a completion, unpulled requests let the event loop go: after each exchange.
    try std.testing.expectEqual(@as(usize, 3), host.idled);
    for (unpulled) |token| {
        table.retire(token);
        runtime.release();
    }
}

test "a stopped environment returns pinned request chunks and outcomes, which the next exchange delivers" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.payload_budget.limit = 1 << 30;
    runtime.bridge.requests = try outgoing.Table.init(std.testing.allocator, 2, &runtime.bridge.payload_budget);
    defer runtime.bridge.requests.?.deinit();
    const table = &runtime.bridge.requests.?;
    const streaming = try admitRequest(runtime);
    ownerMoves(runtime, streaming, pulledChunk);
    const ended = try completeRequest(runtime);
    var host: Host = .{ .runtime = runtime, .fail = .completions };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    for ([_]outgoing.Token{ streaming, ended }) |token| {
        const cell = table.get(token).?;
        try std.testing.expect(!cell.copying and cell.pulling);
    }
    try std.testing.expectEqual(@as(u64, 0), table.diag.chunksCopied);
    host.fail = null;
    const result = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 2), result.request_count);
    try std.testing.expectEqual(streaming, result.requests[0].token);
    try std.testing.expectEqual(@as(usize, 4), result.requests[0].value.chunk.len);
    try std.testing.expectEqual(outgoing.Terminal.done, result.requests[1].value.terminal);
    // The delivered chunk waits for the next pull to consume it; the outcome retired its cell.
    const cell = table.get(streaming).?;
    try std.testing.expect(!cell.pulling and cell.delivered and cell.chunk != null);
    try std.testing.expect(table.get(ended) == null);
    try std.testing.expectEqual(@as(u64, 1), table.diag.chunksCopied);
    try std.testing.expect(!result.outcome.needs_another_exchange);
    retireStreaming(runtime, streaming);
}

test "an outcome the owner records while its chunk is copied survives the commit and waits for the next pull" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.payload_budget.limit = 1 << 30;
    runtime.bridge.requests = try outgoing.Table.init(std.testing.allocator, 1, &runtime.bridge.payload_budget);
    defer runtime.bridge.requests.?.deinit();
    const table = &runtime.bridge.requests.?;
    const token = try admitRequest(runtime);
    ownerMoves(runtime, token, pulledChunk);
    const Owner = struct {
        /// The stream's end, captured as the owner does while the chunk is pinned.
        fn ends(target: *Runtime) void {
            target.lock();
            defer target.unlock();
            const cell = &target.bridge.requests.?.cells[0];
            cell.native = null;
            cell.terminal = .done;
            cell.state = .terminal;
            target.bridge.requests.?.releasePayload(cell);
            target.bridge.requests.?.refresh(cell);
        }
    };
    var host: Host = .{ .runtime = runtime, .during = Owner.ends };
    const chunk = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 4), chunk.requests[0].value.chunk.len);
    const cell = table.get(token).?;
    try std.testing.expect(cell.terminal.? == .done and cell.chunk == null and !cell.delivered and !cell.pulling);
    // No pull awaits the outcome, so it stays with the cell.
    host.during = null;
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&.{}, control)).request_count);
    runtime.lock();
    outgoing.armPull(runtime, cell);
    runtime.unlock();
    const ended = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 1), ended.request_count);
    try std.testing.expectEqual(outgoing.Terminal.done, ended.requests[0].value.terminal);
    try std.testing.expect(table.get(token) == null);
}

/// A stream the host was handed, as a serving start's commit leaves it.
fn exposeStream(runtime: *Runtime) !incoming.Token {
    const token = try queueRequest(runtime);
    runtime.lock();
    defer runtime.unlock();
    const table = &runtime.bridge.incoming.?;
    const cell = table.get(token).?;
    table.releaseInput(cell);
    cell.exposed = true;
    cell.closed_awaited = true;
    cell.state = .serving;
    table.refresh(cell);
    runtime.notifyIfReadyLocked();
    return token;
}

/// Moves a handed stream to where the owner leaves it, and readiness with it.
fn streamMoves(runtime: *Runtime, token: incoming.Token, comptime move: fn (*incoming.Cell) void) void {
    runtime.lock();
    defer runtime.unlock();
    const table = &runtime.bridge.incoming.?;
    const cell = table.get(token).?;
    move(cell);
    table.releasePayload(cell);
    table.refresh(cell);
    runtime.notifyIfReadyLocked();
}

fn streamEnds(cell: *incoming.Cell) void {
    cell.native = false;
    cell.state = .terminal;
}

fn chunkSent(cell: *incoming.Cell) void {
    cell.response_awaited = true;
    cell.ack = .sent;
}

/// A handed stream that ended, whose close awaits delivery, at the lowest free cell.
fn endedStream(runtime: *Runtime) !incoming.Token {
    const token = try exposeStream(runtime);
    streamMoves(runtime, token, streamEnds);
    return token;
}

test "incoming completions batch terminal cells while unfinished work stays admitted" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 4);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const table = &runtime.bridge.incoming.?;
    const low = try endedStream(runtime);
    // Two streams still run, so only the lowest and the highest complete.
    const running = [_]incoming.Token{ try exposeStream(runtime), try exposeStream(runtime) };
    const high = try endedStream(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    const demand = control;
    var delivered: [4]incoming.Token = undefined;
    for (0..3) |pass| {
        // The lowest cell ends again whenever it was delivered, with the next generation.
        if (pass > 0 and table.cells[0].state == .free) _ = try endedStream(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, if (pass == 0) 2 else 1), result.incoming_count);
        try std.testing.expect(result.incoming[0].closed and result.incoming[0].ack == null and result.incoming[0].permission == null);
        for (0..result.incoming_count) |i| {
            const token = result.incoming[i].token;
            delivered[if (pass == 0) i else pass + 1] = token;
            try std.testing.expect(table.get(token) == null);
        }
    }
    try std.testing.expectEqualSlices(incoming.Token, &.{ low, high, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 3 } }, &delivered);
    // The running streams' closes keep the event loop alive.
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    for (running) |token| retireServed(table, token);
}

test "a stopped environment returns pinned incoming completions, which the next exchange delivers" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const table = &runtime.bridge.incoming.?;
    const acknowledged = try exposeStream(runtime);
    streamMoves(runtime, acknowledged, chunkSent);
    const ended = try endedStream(runtime);
    var host: Host = .{ .runtime = runtime, .fail = .completions };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    for ([_]incoming.Token{ acknowledged, ended }) |token| try std.testing.expect(!table.get(token).?.copying);
    try std.testing.expect(table.get(acknowledged).?.response_awaited and table.get(ended).?.closed_awaited);
    host.fail = null;
    const result = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 2), result.incoming_count);
    try std.testing.expectEqual(incoming.Ack.sent, result.incoming[0].ack.?);
    try std.testing.expect(!result.incoming[0].closed and result.incoming[1].closed);
    // The acknowledged stream still runs and awaits its close; the ended one retired.
    try std.testing.expect(!table.get(acknowledged).?.response_awaited and table.get(acknowledged).?.closed_awaited);
    try std.testing.expect(table.get(ended) == null);
    retireServed(table, acknowledged);
}

test "an acknowledgement and a close due together share one completion, and an end during its copy waits for the next" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const table = &runtime.bridge.incoming.?;
    // The stream ended before the exchange, so its acknowledgement and close are due in one cell.
    const together = try exposeStream(runtime);
    streamMoves(runtime, together, chunkSent);
    streamMoves(runtime, together, streamEnds);
    var host: Host = .{ .runtime = runtime };
    const both = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 1), both.incoming_count);
    try std.testing.expect(both.incoming[0].ack.? == .sent and both.incoming[0].closed);
    try std.testing.expect(table.get(together) == null);
    // The stream ends while its acknowledgement is copied: the close waits for the next exchange.
    const racing = try exposeStream(runtime);
    streamMoves(runtime, racing, chunkSent);
    const Owner = struct {
        fn ends(target: *Runtime) void {
            target.lock();
            defer target.unlock();
            const cell = &target.bridge.incoming.?.cells[0];
            streamEnds(cell);
            target.bridge.incoming.?.releasePayload(cell);
            target.bridge.incoming.?.refresh(cell);
        }
    };
    host.during = Owner.ends;
    const acknowledged = try host.turn(&.{}, control);
    try std.testing.expect(acknowledged.incoming[0].ack.? == .sent and !acknowledged.incoming[0].closed);
    host.during = null;
    const closed = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 1), closed.incoming_count);
    try std.testing.expect(closed.incoming[0].ack == null and closed.incoming[0].closed);
    try std.testing.expect(table.get(racing) == null);
}

test "the close result follows the last due completion alone, a stopped build keeps it for the next exchange, and a stopped finish leaves it delivered" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    _ = try completeCommand(runtime, .getIdentity);
    runtime.lock();
    runtime.bridge.stop = true;
    runtime.failLocked(error.NetworkWakeFailed);
    runtime.bridge.quiescent = true;
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    var host: Host = .{ .runtime = runtime };
    // The owner quiesced, but a completion is still due: it comes first, alone.
    const completion = try host.turn(&.{}, control);
    try std.testing.expect(completion.command_count == 1 and completion.closed == null and completion.outcome.needs_another_exchange);
    // JavaScript stops while the close result is built: nothing is delivered, and the next exchange takes it again.
    host.fail = .closed;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expect(!runtime.bridge.close_delivered);
    try std.testing.expect(runtime.deliverableLocked(.completions));
    host.fail = null;
    const closed = try host.turn(&.{}, control);
    try std.testing.expectEqual(exchange.Closed{ .reason = .failed, .failure = error.NetworkWakeFailed }, closed.closed.?);
    try std.testing.expect(runtime.bridge.close_delivered and !closed.outcome.needs_another_exchange);
    try std.testing.expectEqual(null, (try host.turn(&.{}, control)).closed);
    // A stopped finish after the commit loses the result with the environment; the close stays delivered.
    runtime.bridge.close_delivered = false;
    host.fail_finish = true;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expect(runtime.bridge.close_delivered);
    try std.testing.expectEqual(null, host.site);
}

test "the close result arrives alone although peer events wait under a peer demand, and takes none with it" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    for (0..5) |_| publishPeer(runtime);
    runtime.lock();
    runtime.bridge.stop = true;
    runtime.bridge.quiescent = true;
    runtime.notifyIfReadyLocked();
    runtime.unlock();
    try std.testing.expect(!runtime.deliverableLocked(.peers));
    var host: Host = .{ .runtime = runtime };
    const closed = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(exchange.Closed{ .reason = .requested, .failure = null }, closed.closed.?);
    try std.testing.expectEqual(@as(usize, 0), closed.peers);
    try std.testing.expect(!closed.outcome.needs_another_exchange);
    // Delivered, the close ends the peer events too: no exchange takes them.
    try std.testing.expect(!runtime.deliverableLocked(.peers));
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&.{}, deployed)).peers);
    try std.testing.expectEqual(@as(u8, 5), fixture.lane.len);
}

test "publication delivery bounds each exchange and reaches higher cells before refilled lower cells" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.bridge.publications = try publications.Table.init(std.testing.allocator, 64, &runtime.bridge.payload_budget);
    defer runtime.bridge.publications.?.deinit();
    for (0..64) |_| _ = try completePublication(runtime);
    var host: Host = .{ .runtime = runtime };
    const first = try host.turn(&.{}, control);
    try std.testing.expectEqual(exchange.completion_max, first.publication_count);
    try std.testing.expect(first.outcome.needs_another_exchange);
    const refilled = try completePublication(runtime);
    try std.testing.expectEqual(@as(u8, 0), refilled.index);
    const second = try host.turn(&.{}, control);
    try std.testing.expectEqual(exchange.completion_max, second.publication_count);
    for (second.publications[0..second.publication_count], 32..) |token, index| try std.testing.expectEqual(index, token.index);
    try std.testing.expect(second.outcome.needs_another_exchange);
    const last = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 1), last.publication_count);
    try std.testing.expectEqual(refilled, last.publications[0]);
    try std.testing.expect(!last.outcome.needs_another_exchange);
}

test "peer delivery uses bounded batches and rearms only after the remainder is delivered" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    for (0..40) |_| publishPeer(runtime);
    var host: Host = .{ .runtime = runtime };
    const first = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(exchange.peers_max, first.peers);
    try std.testing.expect(first.outcome.needs_another_exchange and !runtime.bridge.notification_armed);
    const last = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(@as(usize, 8), last.peers);
    try std.testing.expect(!last.outcome.needs_another_exchange and runtime.bridge.notification_armed);
}

test "a turn that defers nonurgent gossip still requests the next exchange" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const token = try admit(runtime, .voluntary_exit, null, "data");
    defer runtime.bridge.gossip.?.retire(token);
    var host: Host = .{ .runtime = runtime };
    var demand = deployed;
    demand.delivery.claim_non_urgent_gossip = false;
    const deferred = try host.turn(&.{}, demand);
    try std.testing.expect(deferred.gossip == null and deferred.outcome.needs_another_exchange);
    const delivered = try host.turn(&.{}, deployed);
    try std.testing.expect(delivered.gossip.?.len == 1 and !delivered.outcome.needs_another_exchange);
}
