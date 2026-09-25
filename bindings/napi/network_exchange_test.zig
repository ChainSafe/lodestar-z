const std = @import("std");
const n = @import("network");
const exchange = @import("network_exchange.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const commands = @import("network_commands.zig");
const tsfn = @import("network_runtime_test.zig");
const Runtime = r.Runtime;
const Kind = n.gossip_processor.limits_mod.Kind;
const limits_mod = n.gossip_processor.limits_mod;
const State = n.gossip_processor.State;

const Part = enum { peers, serving, checks, gossip };

/// Builds a summary instead of JS values, fails at one part or while finishing when asked, and records a
/// contract failure instead of terminating. `during` runs where the build runs, as owner work racing phase C.
const Host = struct {
    runtime: *Runtime,
    clock: u64 = 1,
    fail: ?Part = null,
    fail_finish: bool = false,
    failure: exchange.Failure = .stopped,
    builds: usize = 0,
    discarded: usize = 0,
    kept_alive: usize = 0,
    fatals: usize = 0,
    /// Terminate on a contract failure, as the N-API host's fatal error does.
    aborts: bool = false,
    during: ?*const fn (*Runtime) void = null,

    pub const Result = struct {
        peers: usize = 0,
        serving: [exchange.serving_max]incoming.Token = undefined,
        serving_count: usize = 0,
        checks: g.Batch = .{},
        gossip: ?g.Batch = null,
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
        for (0..selection.serving_count) |i| {
            selection.closed[i] = undefined;
            selection.closed_count = i + 1;
            if (self.failing(.serving)) return self.failure_error();
        }
        if (self.failing(.checks) and selection.checks.len > 0) return self.failure_error();
        if (self.failing(.gossip) and selection.gossip != null) return self.failure_error();
        return .{ .peers = selection.peer_count, .serving = selection.serving, .serving_count = selection.serving_count, .checks = selection.checks, .gossip = selection.gossip };
    }
    pub fn finish(self: *Host, output: Result, outcome: exchange.Outcome) !Result {
        if (self.fail_finish) return self.failure_error();
        var result = output;
        result.outcome = outcome;
        return result;
    }
    pub fn discard(self: *Host, selection: *const exchange.Selection) void {
        self.discarded += selection.closed_count;
    }
    pub fn keepAlive(self: *Host) void {
        self.kept_alive += 1;
    }
    pub fn classify(self: *Host, _: anyerror) exchange.Failure {
        return self.failure;
    }
    pub fn fatal(self: *Host, err: anyerror) anyerror {
        if (self.aborts) std.process.abort();
        self.fatals += 1;
        return err;
    }

    /// Settles as the N-API host does, retiring terminal commands at once, then runs phases B to D.
    fn turn(self: *Host, actions: []const exchange.Action, demand: exchange.Demand) !Result {
        for (0..demand.settle) |_| {
            self.runtime.lock();
            defer self.runtime.unlock();
            const i = self.runtime.table.nextTerminal(0) orelse break;
            self.runtime.table.retire(.{ .index = @intCast(i), .generation = self.runtime.table.cells[i].generation });
        }
        return exchange.run(self.runtime, actions, &demand, self.clock, self);
    }
};

const deployed: exchange.Demand = .{ .settle = 32, .peers = 32, .checks = 64, .serving = 8, .messages = 64, .bytes = 8 * 1024 * 1024, .claim_ordinary = true, .capacity = .{ .serving = 32, .ordinary = true } };
const control: exchange.Demand = .{ .settle = 32, .peers = 0, .checks = 0, .serving = 0, .messages = 0, .bytes = 0, .claim_ordinary = false, .capacity = null };

fn admit(runtime: *Runtime, kind: Kind, root: ?[32]u8, payload: []const u8) !g.Token {
    const table = &runtime.gossip.?;
    const token = try table.reserveKind(kind, payload.len);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = 100;
    cell.metadata = .{ .slot = 1, .root = root, .await_block = root != null };
    @memset(&cell.topic, 0);
    table.install(token, payload);
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

/// Ends a served stream the host was handed, as its close settlement and release would.
fn retireServed(table: *incoming.Table, token: incoming.Token) void {
    const cell = table.get(token).?;
    cell.closed = null;
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
        self.* = .{ .runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .env_alive = notified } };
        self.runtime.payload_budget.limit = 64 << 20;
        self.runtime.lane = &self.lane;
        self.runtime.incoming = try incoming.Table.init(std.testing.allocator, serving, &self.runtime.payload_budget);
        const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
        self.runtime.gossip = try g.Table.init(std.testing.allocator, .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits });
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
    for (0..2) |_| runtime.table.transition(runtime.table.get(try runtime.table.reserve(.getIdentity)), .terminal);

    var host: Host = .{ .runtime = runtime, .fail = part };
    try std.testing.expectError(error.PendingException, host.turn(&.{}, deployed));
    try std.testing.expectEqual(@as(usize, 0), host.fatals);
    // Settled promises stay settled; every pinned item is back where it was, and the rows stay queued.
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
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
    try std.testing.expectEqual(@as(usize, switch (part) {
        .peers => 0,
        .serving => 1,
        .checks, .gossip => 2,
    }), host.discarded);
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
    for (requests) |token| retireServed(&runtime.incoming.?, token);
}

test "a stopped environment during the build at any payload part restores the pins and never replays settlement" {
    inline for (@typeInfo(Part).@"enum".fields) |field| try stopAt(@field(Part, field.name));
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
        try std.testing.expectEqual(@as(usize, @intFromBool(failure == .contract)), host.fatals);
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
    try std.testing.expectEqual(@as(usize, 1), host.fatals);
    try std.testing.expectEqual(@as(usize, 0), runtime.gossip.?.diag.copying);
}

test "a contract failure terminates the process without a retry (child process)" {
    const pid = std.c.fork();
    try std.testing.expect(pid >= 0);
    if (pid == 0) {
        var fixture: Fixture = undefined;
        fixture.init(false, 2) catch std.c._exit(2);
        _ = admit(&fixture.runtime, .voluntary_exit, null, "data") catch std.c._exit(2);
        var host: Host = .{ .runtime = &fixture.runtime, .fail = .gossip, .failure = .contract, .aborts = true };
        _ = host.turn(&.{}, deployed) catch {};
        std.c._exit(3);
    }
    var status: c_int = 0;
    try std.testing.expectEqual(pid, std.c.waitpid(pid, &status, 0));
    const code: u32 = @bitCast(status);
    try std.testing.expect(std.c.W.IFSIGNALED(code));
    try std.testing.expectEqual(std.c.SIG.ABRT, std.c.W.TERMSIG(code));
}

test "control-only exchanges settle in batches immediately while queued payload keeps its place for the timer" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    publishPeer(runtime);
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    for (0..commands.capacity) |_| runtime.table.transition(runtime.table.get(try runtime.table.reserve(.getIdentity)), .terminal);
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

test "a stop ends checks and serving starts, and quiescence ends claims" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    const request = try queueRequest(runtime);
    const checked = try admit(runtime, .beacon_attestation, @splat(3), "data");
    const exit = try admit(runtime, .voluntary_exit, null, "data");
    runtime.stop = true;
    var host: Host = .{ .runtime = runtime };
    const stopped = try host.turn(&.{}, deployed);
    try std.testing.expect(stopped.serving_count == 0 and stopped.checks.len == 0);
    try std.testing.expectEqualSlices(g.Token, &.{exit}, stopped.gossip.?.tokens[0..stopped.gossip.?.len]);
    try std.testing.expectEqual(r.Place.none, runtime.readiness.place(.serving));
    try std.testing.expectEqual(r.Place.none, runtime.readiness.place(.checks));
    try std.testing.expectEqual(State.needs_check, runtime.gossip.?.get(checked).?.state);
    runtime.quiescent = true;
    publishPeer(runtime);
    const quiescent = try host.turn(&.{}, deployed);
    try std.testing.expect(quiescent.peers == 1 and quiescent.gossip == null);
    _ = request;
}

test "actions apply before selection, so a check classified in an exchange is claimed by it, and wake the owner once" {
    var fixture: Fixture = undefined;
    try fixture.init(false, 2);
    defer fixture.deinit();
    const runtime = &fixture.runtime;
    runtime.wake = try @import("network_wake.zig").Wake.init();
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
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 64 << 20;
    runtime.incoming = try incoming.Table.init(std.testing.allocator, incoming.capacity_max, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    var limits: limits_mod.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    limits[@intFromEnum(Kind.data_column_sidecar)] = .{ .items = 256, .bytes = 4 << 20 };
    limits[@intFromEnum(Kind.voluntary_exit)] = .{ .items = 1024, .bytes = 1 << 20 };
    runtime.gossip = try g.Table.init(std.testing.allocator, .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits, .execution = limits });
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
