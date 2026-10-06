const std = @import("std");
const n = @import("network");
const exchange = @import("network_exchange.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const readiness = @import("network_readiness.zig");
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
        publications: [publications.capacity_max]publications.Token = undefined,
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

const deployed: exchange.Demand = .{ .settle = 32, .peers = 32, .checks = 64, .serving = 8, .messages = 64, .bytes = 8 * 1024 * 1024, .claim_ordinary = true, .capacity = .{ .serving = 32, .ordinary = true } };
const control: exchange.Demand = .{ .settle = 32, .peers = 0, .checks = 0, .serving = 0, .messages = 0, .bytes = 0, .claim_ordinary = false, .capacity = null };

fn admit(runtime: *Runtime, kind: Kind, root: ?[32]u8, payload: []const u8) !g.Token {
    const table = &runtime.gossip.?;
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
    runtime.recomputeLocked(.checks);
    runtime.recomputeLocked(.gossip);
    runtime.unlock();
    return token;
}

fn queueRequest(runtime: *Runtime) !incoming.Token {
    const table = &runtime.incoming.?;
    const token = try table.reserve(.blocks_by_root_v2, 32);
    try table.allocate(token, &(.{7} ** 32));
    const cell = table.get(token).?;
    cell.native = true;
    table.refresh(cell);
    runtime.lock();
    runtime.recomputeLocked(.serving);
    runtime.unlock();
    return token;
}

fn publishPeer(runtime: *Runtime) void {
    runtime.lock();
    defer runtime.unlock();
    runtime.lane.?.publish(&.{.{ .closed = undefined }}, 1);
    runtime.recomputeLocked(.peers);
}

/// Ends a served stream the host was handed, as its close completion and release would.
fn retireServed(table: *incoming.Table, token: incoming.Token) void {
    const cell = table.get(token).?;
    cell.closed_awaited = false;
    cell.native = false;
    table.retire(token);
}

fn retireQueued(runtime: *Runtime) void {
    for (runtime.incoming.?.cells, 0..) |*cell, i| if (cell.state != .free) {
        cell.native = false;
        runtime.incoming.?.retire(.{ .index = @intCast(i), .generation = cell.generation });
    };
}

const Fixture = struct {
    runtime: Runtime,
    lane: projection.Lane = .{},

    /// A runtime with a lane, two serving cells and a small gossip table. `notified` makes its notifications
    /// reach the counting test notifier.
    fn init(self: *Fixture, notified: bool, serving: usize) !void {
        self.* = .{ .runtime = .{ .env = undefined, .env_alive = notified } };
        self.runtime.payload_budget.limit = 64 << 20;
        self.runtime.lane = &self.lane;
        self.runtime.incoming = try incoming.Table.init(std.testing.allocator, serving, &self.runtime.payload_budget);
        const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
        self.runtime.gossip = try g.Table.init(std.testing.allocator, .{ .limits = limits });
    }
    fn deinit(self: *Fixture) void {
        retireQueued(&self.runtime);
        self.runtime.incoming.?.deinit();
        self.runtime.gossip.?.close();
        self.runtime.gossip.?.deinit();
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
    // Every pinned item is back where it was, completed commands included, and the rows stay queued.
    for (completed) |token| try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    try std.testing.expectEqual(@as(u8, 2), fixture.lane.len);
    for (requests) |token| {
        const cell = runtime.incoming.?.get(token).?;
        try std.testing.expect(cell.state == .queued and !cell.copying and cell.native and cell.input.len == 32);
    }
    const table = &runtime.gossip.?;
    try std.testing.expectEqual(State.needs_check, table.get(checked).?.state);
    for ([_]g.Token{ column, exit }) |token| try std.testing.expectEqual(State.queued, table.get(token).?.state);
    try std.testing.expectEqual(@as(usize, 0), table.diag.executing);
    try std.testing.expectEqual(@as(usize, 0), table.diag.copying);
    try std.testing.expect(!runtime.readiness.armed);
    try std.testing.expectEqual(@as(usize, 4), runtime.readiness.payload.len);

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
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
    for (requests) |token| retireServed(&runtime.incoming.?, token);
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
        try std.testing.expectEqual(State.delivered, runtime.gossip.?.get(exit).?.state);
        try std.testing.expect(runtime.readiness.armed);
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
    try std.testing.expectEqual(@as(usize, 0), runtime.gossip.?.diag.copying);
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

test "control-only exchanges settle in batches immediately while queued payload keeps its place for the timer" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    publishPeer(runtime);
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    for (0..commands.capacity - 1) |_| _ = try completeCommand(runtime, .getIdentity);
    var host: Host = .{ .runtime = runtime };
    var batches: usize = 0;
    var demand = control;
    demand.settle = 8;
    for (0..8) |_| {
        const result = try host.turn(&.{}, demand);
        batches += 1;
        try std.testing.expect(result.outcome.disabled and result.peers == 0 and result.gossip == null);
        try std.testing.expectEqual(runtime.table.occupied > 0, result.outcome.more);
        if (!result.outcome.more) break;
    }
    try std.testing.expectEqual(@as(usize, 4), batches);
    try std.testing.expectEqual(@as(u8, 1), fixture.lane.len);
    try std.testing.expect(!runtime.readiness.armed);
    const result = try host.turn(&.{}, deployed);
    try std.testing.expect(result.peers == 1 and result.gossip != null and runtime.readiness.armed);
    runtime.gossip.?.retire(exit);
}

test "the first arrival into an idle source without capacity notifies once and parks until capacity returns" {
    var fixture: Fixture = undefined;
    try fixture.init(true, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var host: Host = .{ .runtime = runtime };
    var demand = deployed;
    demand.capacity = .{ .serving = 0, .ordinary = false };
    try std.testing.expect(!(try host.turn(&.{}, demand)).outcome.more);
    try std.testing.expect(runtime.readiness.armed);
    const before = tsfn.notifications.load(.acquire);
    const request = try queueRequest(runtime);
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    const parked = try host.turn(&.{}, demand);
    try std.testing.expect(parked.outcome.parked_serving and parked.outcome.parked_ordinary and !parked.outcome.more);
    try std.testing.expect(parked.serving_count == 0 and parked.gossip == null and runtime.readiness.armed);
    // An executable urgent admission beside parked ordinary work queues the gossip row and notifies once.
    const column = try admit(runtime, .data_column_sidecar, null, "data");
    try std.testing.expectEqual(before + 2, tsfn.notifications.load(.acquire));
    const urgent = try host.turn(&.{}, demand);
    try std.testing.expectEqualSlices(g.Token, &.{column}, urgent.gossip.?.tokens[0..urgent.gossip.?.len]);
    try std.testing.expect(urgent.outcome.parked_ordinary);
    // Returning capacity delivers the parked work.
    demand.capacity = .{ .serving = 1, .ordinary = true };
    const delivered = try host.turn(&.{}, demand);
    try std.testing.expectEqualSlices(incoming.Token, &.{request}, delivered.serving[0..delivered.serving_count]);
    try std.testing.expectEqualSlices(g.Token, &.{exit}, delivered.gossip.?.tokens[0..delivered.gossip.?.len]);
    try std.testing.expect(!delivered.outcome.parked_serving and !delivered.outcome.parked_ordinary);
    try std.testing.expectEqual(before + 2, tsfn.notifications.load(.acquire));
    retireServed(&runtime.incoming.?, request);
    for ([_]g.Token{ exit, column }) |token| runtime.gossip.?.retire(token);
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
        demand.capacity = null;
        try std.testing.expectEqual(@as(usize, exchange.serving_max), result.serving_count);
        try std.testing.expectEqual(i < 3, result.outcome.more);
        try std.testing.expect(!result.outcome.parked_serving and !result.outcome.disabled);
        for (result.serving[0..result.serving_count]) |token| retireServed(&runtime.incoming.?, token);
    }
    try std.testing.expectEqual(@as(u32, 0), runtime.capacity.serving);
}

test "publications before phase B, during phase C and after phase D each reach an exchange" {
    var fixture: Fixture = undefined;
    try fixture.init(true, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var host: Host = .{ .runtime = runtime };
    const before = tsfn.notifications.load(.acquire);
    // Before phase B: armed, so the arrival notifies.
    publishPeer(runtime);
    try std.testing.expectEqual(before + 1, tsfn.notifications.load(.acquire));
    // During phase C the row is pinned, so the arrival waits for the unpin, which keeps it queued.
    host.during = publishPeer;
    const racing = try host.turn(&.{}, deployed);
    try std.testing.expect(racing.peers == 1 and racing.outcome.more and !runtime.readiness.armed);
    try std.testing.expectEqual(@as(u8, 1), fixture.lane.len);
    host.during = null;
    try std.testing.expect(!(try host.turn(&.{}, deployed)).outcome.more and runtime.readiness.armed);
    // After phase D armed, the next arrival notifies; a full queue still leaves its undequeued notification.
    tsfn.status = napi_queue_full;
    publishPeer(runtime);
    tsfn.status = 0;
    try std.testing.expect(!runtime.readiness.armed and runtime.notify_live and !runtime.stop);
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
    runtime.stop = true;
    var host: Host = .{ .runtime = runtime };
    const stopped = try host.turn(&.{}, deployed);
    try std.testing.expect(stopped.serving_count == 0 and stopped.checks.len == 0);
    try std.testing.expect(stopped.gossip == null);
    try std.testing.expectEqual(State.queued, runtime.gossip.?.get(exit).?.state);
    try std.testing.expectEqual(r.Place.none, runtime.readiness.place(.serving));
    try std.testing.expectEqual(r.Place.none, runtime.readiness.place(.checks));
    try std.testing.expectEqual(r.Place.none, runtime.readiness.place(.gossip));
    try std.testing.expectEqual(State.needs_check, runtime.gossip.?.get(checked).?.state);
    // Quiescence cancels the command, whose completion holds the close back: its exchange still delivers the peer
    // event but claims no gossip. The close then arrives alone.
    runtime.lock();
    runtime.quiescent = true;
    runtime.cancelCommandsLocked();
    runtime.recomputeLocked(.completions);
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
    runtime.wake = try network_wake.Wake.init();
    defer runtime.wake.?.deinit();
    var readable = [_]std.c.pollfd{.{ .fd = runtime.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 }};
    const checked = try admit(runtime, .beacon_attestation, @splat(3), "data");
    var host: Host = .{ .runtime = runtime };
    const checks = try host.turn(&.{}, deployed);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, checks.checks.tokens[0..checks.checks.len]);
    try runtime.wake.?.drain();
    const answered = try host.turn(&.{.{ .classify = .{ .token = checked, .available = true } }}, deployed);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, answered.gossip.?.tokens[0..answered.gossip.?.len]);
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&readable, 1, 0));
    try runtime.wake.?.drain();
    // An obligation-only batch wakes the owner for the verdict it leaves.
    const verdict = try host.turn(&.{.{ .verdict = .{ .token = checked, .verdict = .accept } }}, control);
    try std.testing.expect(!verdict.outcome.more);
    try std.testing.expectEqual(State.verdict_pending, runtime.gossip.?.get(checked).?.state);
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&readable, 1, 0));
    try runtime.wake.?.drain();
    runtime.gossip.?.retire(checked);
}

test "a 128-column burst reaches the host within two exchanges under saturated ordinary gossip and serving" {
    var runtime: Runtime = .{ .env = undefined, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 64 << 20;
    runtime.incoming = try incoming.Table.init(std.testing.allocator, incoming.capacity_max, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    var limits: limits_mod.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    limits[@intFromEnum(Kind.data_column_sidecar)] = .{ .items = 256, .bytes = 4 << 20 };
    limits[@intFromEnum(Kind.voluntary_exit)] = .{ .items = 1024, .bytes = 1 << 20 };
    runtime.gossip = try g.Table.init(std.testing.allocator, .{ .limits = limits, .execution = limits });
    defer runtime.gossip.?.deinit();
    const table = &runtime.gossip.?;
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
        try std.testing.expect(delivered.outcome.more);
        try std.testing.expectEqual(@as(usize, exchange.serving_max), delivered.serving_count);
        // The host takes each delivery, and both kinds of traffic refill to saturation.
        for (delivered.serving[0..delivered.serving_count]) |token| {
            retireServed(&runtime.incoming.?, token);
            _ = try queueRequest(&runtime);
        }
        demand.capacity = .{ .serving = 32, .ordinary = true };
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
    const table = &runtime.gossip.?;
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
    runtime.recomputeLocked(.completions);
    runtime.unlock();
    try std.testing.expectEqual(readiness.Place.control, runtime.readiness.place(.completions));

    // A failed build keeps them for the next exchange.
    host.fail = .acknowledged;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expectEqual(@as(usize, 2), table.diag.acknowledging);
    host.fail = null;
    const acknowledged = try host.turn(&.{}, control);
    try std.testing.expectEqual(@as(usize, 2), acknowledged.acknowledged_count);
    for (acknowledged.acknowledged[0..2], tokens) |got, token| try std.testing.expect(std.meta.eql(got, token));
    try std.testing.expect(!acknowledged.outcome.more);
    try std.testing.expectEqual(@as(usize, 0), table.diag.acknowledging);
    for (tokens) |token| try std.testing.expect(table.get(token) == null);
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&.{}, control)).acknowledged_count);
}

/// A publication the owner completed at the lowest free cell, as execution leaves it.
fn completePublication(runtime: *Runtime) !publications.Token {
    const token = try runtime.reservePublication(.beacon_block, 0);
    runtime.lock();
    defer runtime.unlock();
    runtime.publications.?.transition(runtime.publications.?.get(token).?, .terminal);
    runtime.recomputeLocked(.completions);
    return token;
}

test "publication completions arrive at most `settle` per exchange whatever the demand, fairly under refill" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.publications = try publications.Table.init(std.testing.allocator, 4, &runtime.payload_budget);
    defer runtime.publications.?.deinit();
    const table = &runtime.publications.?;
    const low = try completePublication(runtime);
    // Two cells stay admitted but unfinished, so only the lowest and the highest complete.
    const unfinished = [_]publications.Token{ try runtime.reservePublication(.beacon_block, 0), try runtime.reservePublication(.beacon_block, 0) };
    const high = try completePublication(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    var demand = control;
    demand.settle = 1;
    var delivered: [4]publications.Token = undefined;
    for (&delivered, 0..) |*token, pass| {
        // The lowest cell completes again whenever it was delivered, with the next generation.
        if (pass > 0 and table.get(.{ .index = 0, .generation = table.cells[0].generation }) == null) _ = try completePublication(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, 1), result.publication_count);
        try std.testing.expect(result.outcome.more == (table.anyTerminal()));
        token.* = result.publications[0];
        try std.testing.expect(table.get(token.*) == null);
    }
    // The highest cell comes second although the lowest refilled, and the reused cell carries a fresh generation.
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
    runtime.publications = try publications.Table.init(std.testing.allocator, 4, &runtime.payload_budget);
    defer runtime.publications.?.deinit();
    const tokens = [_]publications.Token{ try completePublication(runtime), try completePublication(runtime) };
    var host: Host = .{ .runtime = runtime, .fail = .completions };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    for (tokens) |token| try std.testing.expectEqual(publications.State.terminal, runtime.publications.?.get(token).?.state);
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    host.fail = null;
    const result = try host.turn(&.{}, control);
    try std.testing.expectEqualSlices(publications.Token, &tokens, result.publications[0..result.publication_count]);
    try std.testing.expect(!result.outcome.more and runtime.publications.?.diag.occupied == 0);
    // Retiring the last admitted publication lets the event loop go; the restored exchange did not.
    try std.testing.expectEqual(@as(usize, 1), host.idled);
}

/// A command the owner completed at the lowest free cell, as execution leaves it.
fn completeCommand(runtime: *Runtime, command: commands.Command) !commands.Token {
    const token = try runtime.reserveCommand(command);
    runtime.lock();
    defer runtime.unlock();
    runtime.table.transition(runtime.table.get(token), .terminal);
    runtime.recomputeLocked(.completions);
    return token;
}

test "command completions arrive at most `settle` per exchange, fairly under refill, and retire their typed stores" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    var stores = try network_storage.Stores.create(std.testing.allocator, 4);
    defer stores.destroy();
    runtime.stores = stores;
    defer runtime.stores = null;
    const low = try completeCommand(runtime, .getPeers);
    const unfinished = [_]commands.Token{ try runtime.reserveCommand(.getIdentity), try runtime.reserveCommand(.getIdentity) };
    const high = try completeCommand(runtime, .getDirectPeers);
    try std.testing.expectEqual(low.index + 3, high.index);
    var host: Host = .{ .runtime = runtime };
    var demand = control;
    demand.settle = 1;
    var delivered: [4]commands.Token = undefined;
    for (&delivered, 0..) |*token, pass| {
        // The lowest cell completes again whenever it was delivered, taking the freed snapshot store.
        if (pass > 0 and runtime.table.cells[low.index].state == .free) _ = try completeCommand(runtime, .getPeers);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, 1), result.command_count);
        token.* = result.commands[0];
        try std.testing.expectEqual(commands.State.free, runtime.table.cells[token.index].state);
    }
    try std.testing.expectEqualSlices(commands.Token, &.{ low, high, .{ .index = low.index, .generation = low.generation + 1 }, .{ .index = low.index, .generation = low.generation + 2 } }, &delivered);
    // Delivery freed each snapshot store, so both remain available.
    try std.testing.expect(!runtime.table.stores[1][0] and !runtime.table.stores[1][1]);
    try std.testing.expectEqual(@as(usize, 0), host.idled);
    for (unfinished) |token| runtime.abortCommand(token);
}

/// A request admitted at the lowest free cell, holding the runtime as `requestStart` does.
fn admitRequest(runtime: *Runtime) !outgoing.Token {
    const table = &runtime.requests.?;
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
    const cell = runtime.requests.?.get(token).?;
    move(cell);
    runtime.requests.?.releasePayload(cell);
    runtime.requests.?.refresh(cell);
    runtime.recomputeLocked(.completions);
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
    const cell = runtime.requests.?.get(token).?;
    cell.native = null;
    cell.chunk = null;
    cell.delivered = false;
    runtime.requests.?.retire(token);
    runtime.release();
}

/// A request whose terminal outcome awaits its pending pull, at the lowest free cell.
fn completeRequest(runtime: *Runtime) !outgoing.Token {
    const token = try admitRequest(runtime);
    ownerMoves(runtime, token, pulledDone);
    return token;
}

test "request completions arrive at most `settle` per exchange, fairly under refill" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.payload_budget.limit = 1 << 30;
    runtime.requests = try outgoing.Table.init(std.testing.allocator, 4, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    const table = &runtime.requests.?;
    const low = try completeRequest(runtime);
    // Two requests stay admitted with no pull, so only the lowest and the highest complete.
    const unpulled = [_]outgoing.Token{ try admitRequest(runtime), try admitRequest(runtime) };
    const high = try completeRequest(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    var demand = control;
    demand.settle = 1;
    var delivered: [4]outgoing.Token = undefined;
    for (&delivered, 0..) |*token, pass| {
        // The lowest cell completes again whenever it was delivered, with the next generation.
        if (pass > 0 and table.cells[0].state == .free) _ = try completeRequest(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, 1), result.request_count);
        try std.testing.expectEqual(outgoing.Terminal.done, result.requests[0].value.terminal);
        token.* = result.requests[0].token;
        try std.testing.expect(table.get(token.*) == null);
    }
    // The highest cell comes second although the lowest refilled, and the reused cell carries a fresh generation.
    try std.testing.expectEqualSlices(outgoing.Token, &.{ low, high, .{ .index = 0, .generation = 2 }, .{ .index = 0, .generation = 3 } }, &delivered);
    // Once no pull awaits a completion, unpulled requests let the event loop go: after the third and the fourth.
    try std.testing.expectEqual(@as(usize, 2), host.idled);
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
    runtime.payload_budget.limit = 1 << 30;
    runtime.requests = try outgoing.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    const table = &runtime.requests.?;
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
    try std.testing.expect(!result.outcome.more);
    retireStreaming(runtime, streaming);
}

test "an outcome the owner records while its chunk is copied survives the commit and waits for the next pull" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.payload_budget.limit = 1 << 30;
    runtime.requests = try outgoing.Table.init(std.testing.allocator, 1, &runtime.payload_budget);
    defer runtime.requests.?.deinit();
    const table = &runtime.requests.?;
    const token = try admitRequest(runtime);
    ownerMoves(runtime, token, pulledChunk);
    const Owner = struct {
        /// The stream's end, captured as the owner does while the chunk is pinned.
        fn ends(target: *Runtime) void {
            target.lock();
            defer target.unlock();
            const cell = &target.requests.?.cells[0];
            cell.native = null;
            cell.terminal = .done;
            cell.state = .terminal;
            target.requests.?.releasePayload(cell);
            target.requests.?.refresh(cell);
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
    const table = &runtime.incoming.?;
    const cell = table.get(token).?;
    table.releaseInput(cell);
    cell.exposed = true;
    cell.closed_awaited = true;
    cell.state = .serving;
    table.refresh(cell);
    runtime.recomputeLocked(.serving);
    return token;
}

/// Moves a handed stream to where the owner leaves it, and readiness with it.
fn streamMoves(runtime: *Runtime, token: incoming.Token, comptime move: fn (*incoming.Cell) void) void {
    runtime.lock();
    defer runtime.unlock();
    const table = &runtime.incoming.?;
    const cell = table.get(token).?;
    move(cell);
    table.releasePayload(cell);
    table.refresh(cell);
    runtime.recomputeLocked(.completions);
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

test "incoming completions arrive at most `settle` per exchange, fairly under refill" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 4);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const table = &runtime.incoming.?;
    const low = try endedStream(runtime);
    // Two streams still run, so only the lowest and the highest complete.
    const running = [_]incoming.Token{ try exposeStream(runtime), try exposeStream(runtime) };
    const high = try endedStream(runtime);
    try std.testing.expectEqual(@as(u8, 3), high.index);
    var host: Host = .{ .runtime = runtime };
    var demand = control;
    demand.settle = 1;
    var delivered: [4]incoming.Token = undefined;
    for (&delivered, 0..) |*token, pass| {
        // The lowest cell ends again whenever it was delivered, with the next generation.
        if (pass > 0 and table.cells[0].state == .free) _ = try endedStream(runtime);
        const result = try host.turn(&.{}, demand);
        try std.testing.expectEqual(@as(usize, 1), result.incoming_count);
        try std.testing.expect(result.incoming[0].closed and result.incoming[0].ack == null and result.incoming[0].permission == null);
        token.* = result.incoming[0].token;
        try std.testing.expect(table.get(token.*) == null);
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
    const table = &runtime.incoming.?;
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
    const table = &runtime.incoming.?;
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
            const cell = &target.incoming.?.cells[0];
            streamEnds(cell);
            target.incoming.?.releasePayload(cell);
            target.incoming.?.refresh(cell);
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
    runtime.stop = true;
    runtime.failLocked(error.NetworkWakeFailed);
    runtime.quiescent = true;
    runtime.refreshLocked();
    runtime.unlock();
    var host: Host = .{ .runtime = runtime };
    // The owner quiesced, but a completion is still due: it comes first, alone.
    const completion = try host.turn(&.{}, control);
    try std.testing.expect(completion.command_count == 1 and completion.closed == null and completion.outcome.more);
    // JavaScript stops while the close result is built: nothing is delivered, and the next exchange takes it again.
    host.fail = .closed;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expect(!runtime.close_delivered);
    try std.testing.expectEqual(readiness.Place.control, runtime.readiness.place(.completions));
    host.fail = null;
    const closed = try host.turn(&.{}, control);
    try std.testing.expectEqual(exchange.Closed{ .reason = .failed, .failure = error.NetworkWakeFailed }, closed.closed.?);
    try std.testing.expect(runtime.close_delivered and !closed.outcome.more);
    try std.testing.expectEqual(null, (try host.turn(&.{}, control)).closed);
    // A stopped finish after the commit loses the result with the environment; the close stays delivered.
    runtime.close_delivered = false;
    host.fail_finish = true;
    try std.testing.expectError(error.PendingException, host.turn(&.{}, control));
    try std.testing.expect(runtime.close_delivered);
    try std.testing.expectEqual(null, host.site);
}

test "the close result arrives alone although peer events wait under a peer demand, and takes none with it" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    for (0..5) |_| publishPeer(runtime);
    runtime.lock();
    runtime.stop = true;
    runtime.quiescent = true;
    runtime.refreshLocked();
    runtime.unlock();
    try std.testing.expectEqual(readiness.Place.payload, runtime.readiness.place(.peers));
    var host: Host = .{ .runtime = runtime };
    const closed = try host.turn(&.{}, deployed);
    try std.testing.expectEqual(exchange.Closed{ .reason = .requested, .failure = null }, closed.closed.?);
    try std.testing.expectEqual(@as(usize, 0), closed.peers);
    try std.testing.expect(!closed.outcome.more and !closed.outcome.disabled);
    // Delivered, the close ends the peer events too: no exchange takes them.
    try std.testing.expectEqual(readiness.Place.none, runtime.readiness.place(.peers));
    try std.testing.expectEqual(@as(usize, 0), (try host.turn(&.{}, deployed)).peers);
    try std.testing.expectEqual(@as(u8, 5), fixture.lane.len);
}
