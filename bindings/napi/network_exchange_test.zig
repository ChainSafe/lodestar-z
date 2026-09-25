const std = @import("std");
const n = @import("network");
const exchange = @import("network_exchange.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const commands = @import("network_commands.zig");
const Runtime = r.Runtime;
const Kind = n.gossip_processor.limits_mod.Kind;
const limits_mod = n.gossip_processor.limits_mod;
const State = n.gossip_processor.State;

const Part = enum { peers, serving, checks, gossip };

/// Builds a summary instead of JS values and fails at one part when asked. Settlement retires
/// terminal commands at once, as the N-API host's does after settling each promise.
const Host = struct {
    runtime: *Runtime,
    clock: u64 = 1,
    fail: ?Part = null,
    discarded: usize = 0,
    kept_alive: usize = 0,

    pub const Output = struct {
        settled: usize,
        peers: usize,
        serving: [exchange.serving_max]incoming.Token,
        serving_count: usize,
        checks: g.Batch,
        gossip: ?g.Batch,
        more: bool,
    };

    pub fn settle(self: *Host, limit: usize) !exchange.Settled {
        var result: exchange.Settled = .{};
        const runtime = self.runtime;
        for (0..commands.capacity) |_| {
            runtime.lock();
            defer runtime.unlock();
            const i = runtime.table.nextTerminal(0) orelse break;
            if (result.count == limit) {
                result.more = true;
                break;
            }
            runtime.table.retire(.{ .index = @intCast(i), .generation = runtime.table.cells[i].generation });
            result.count += 1;
        }
        return result;
    }
    pub fn now(self: *Host) !u64 {
        return self.clock;
    }
    fn failing(self: *const Host, part: Part) bool {
        return if (self.fail) |value| value == part else false;
    }
    pub fn build(self: *Host, selection: *exchange.Selection, settled: usize) !Output {
        if (self.failing(.peers) and selection.peer_count > 0) return error.GenericFailure;
        for (0..selection.serving_count) |i| {
            selection.closed[i] = undefined;
            selection.closed_count = i + 1;
            if (self.failing(.serving)) return error.GenericFailure;
        }
        if (self.failing(.checks) and selection.checks.len > 0) return error.GenericFailure;
        if (self.failing(.gossip) and selection.gossip != null) return error.GenericFailure;
        return .{ .settled = settled, .peers = selection.peer_count, .serving = selection.serving, .serving_count = selection.serving_count, .checks = selection.checks, .gossip = selection.gossip, .more = selection.more };
    }
    pub fn discard(self: *Host, selection: *const exchange.Selection) void {
        self.discarded += selection.closed_count;
    }
    pub fn keepAlive(self: *Host) void {
        self.kept_alive += 1;
    }
};

const deployed: exchange.Demand = .{ .settle = 32, .peers = 32, .serving = 8, .gossip = .{ .items = 64, .bytes = 8 * 1024 * 1024, .ordinary = true, .ready = true } };

fn admit(table: *g.Table, kind: Kind, root: ?[32]u8, payload: []const u8) !g.Token {
    const token = try table.reserveKind(kind, payload.len);
    const cell = table.get(token).?;
    cell.id = @splat(1);
    cell.deadline = 100;
    cell.metadata = .{ .slot = 1, .root = root, .await_block = root != null };
    @memset(&cell.topic, 0);
    table.install(token, payload);
    return token;
}

fn queueRequest(table: *incoming.Table) !incoming.Token {
    const token = try table.reserve(.blocks_by_root_v2, 32);
    try table.allocate(token, &(.{7} ** 32));
    const cell = table.get(token).?;
    cell.native = true;
    table.refresh(cell);
    return token;
}

/// Ends a served stream the host was handed, as its close settlement and release would.
fn retireServed(table: *incoming.Table, token: incoming.Token) void {
    const cell = table.get(token).?;
    cell.closed = null;
    cell.native = false;
    table.retire(token);
}

fn failAt(part: Part) !void {
    // A live notifier lets the commit keep the loop alive; a dead environment keeps pings local.
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .env_alive = false };
    runtime.payload_budget.limit = 1 << 20;
    var lane: projection.Lane = .{};
    runtime.lane = &lane;
    lane.publish(&.{ .{ .closed = undefined }, .{ .closed = undefined } }, 1);
    runtime.incoming = try incoming.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    const requests = [_]incoming.Token{ try queueRequest(&runtime.incoming.?), try queueRequest(&runtime.incoming.?) };
    const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    runtime.gossip = try g.Table.init(std.testing.allocator, .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits });
    defer runtime.gossip.?.deinit();
    const table = &runtime.gossip.?;
    const checked = try admit(table, .beacon_attestation, @splat(3), "data");
    const column = try admit(table, .data_column_sidecar, null, "data");
    const exit = try admit(table, .voluntary_exit, null, "data");
    for (0..2) |_| runtime.table.transition(runtime.table.get(try runtime.table.reserve(.getIdentity)), .terminal);

    var host: Host = .{ .runtime = &runtime, .fail = part };
    try std.testing.expectError(error.GenericFailure, exchange.run(&runtime, &deployed, &host));
    runtime.lock();
    exchange.failLocked(&runtime);
    runtime.unlock();
    // Settled promises stay settled; every pinned item is back where it was.
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
    try std.testing.expectEqual(@as(u8, 2), lane.len);
    for (requests) |token| {
        const cell = runtime.incoming.?.get(token).?;
        try std.testing.expect(cell.state == .queued and !cell.copying and cell.native and cell.input.len == 32);
    }
    try std.testing.expectEqual(State.needs_check, table.get(checked).?.state);
    for ([_]g.Token{ column, exit }) |token| try std.testing.expectEqual(State.queued, table.get(token).?.state);
    try std.testing.expect(table.ordinary_enabled);
    try std.testing.expectEqual(@as(usize, 0), table.diag.executing);
    try std.testing.expectEqual(@as(usize, 0), table.diag.copying);
    try std.testing.expectEqual(@as(usize, switch (part) {
        .peers => 0,
        .serving => 1,
        .checks, .gossip => 2,
    }), host.discarded);
    try std.testing.expect(!runtime.notification_pending and runtime.work_rearm);

    // The next exchange delivers the same items and settles nothing again.
    host.fail = null;
    const delivered = try exchange.run(&runtime, &deployed, &host);
    try std.testing.expectEqual(@as(usize, 0), delivered.settled);
    try std.testing.expectEqual(@as(usize, 2), delivered.peers);
    try std.testing.expectEqual(@as(u8, 0), lane.len);
    try std.testing.expectEqualSlices(incoming.Token, &requests, delivered.serving[0..delivered.serving_count]);
    try std.testing.expectEqual(@as(usize, 1), host.kept_alive);
    try std.testing.expectEqualSlices(g.Token, &.{checked}, delivered.checks.tokens[0..delivered.checks.len]);
    try std.testing.expectEqualSlices(g.Token, &.{ column, exit }, delivered.gossip.?.tokens[0..delivered.gossip.?.len]);
    try std.testing.expect(delivered.more);
    for (requests) |token| retireServed(&runtime.incoming.?, token);
    table.close();
}

test "a build failure at any payload part restores it for the next exchange and never replays settled promises" {
    inline for (@typeInfo(Part).@"enum".fields) |field| try failAt(@field(Part, field.name));
}

test "exchanges pin only the payload the host asks for and end the drain when nothing is left" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 1 << 20;
    var lane: projection.Lane = .{};
    runtime.lane = &lane;
    runtime.incoming = try incoming.Table.init(std.testing.allocator, 2, &runtime.payload_budget);
    defer runtime.incoming.?.deinit();
    const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    runtime.gossip = try g.Table.init(std.testing.allocator, .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits });
    defer runtime.gossip.?.deinit();
    const table = &runtime.gossip.?;
    var host: Host = .{ .runtime = &runtime };
    const idle: exchange.Demand = .{ .settle = 32, .peers = 0, .serving = 0, .gossip = null };

    runtime.notification_pending = true;
    try std.testing.expect(!(try exchange.run(&runtime, &deployed, &host)).more);
    try std.testing.expect(!runtime.notification_pending);

    // A host that takes no payload leaves it queued and still ends its drain.
    lane.publish(&.{.{ .closed = undefined }}, 1);
    const request = try queueRequest(&runtime.incoming.?);
    _ = try admit(table, .voluntary_exit, null, "data");
    runtime.notification_pending = true;
    const settled = try exchange.run(&runtime, &idle, &host);
    try std.testing.expect(settled.peers == 0 and settled.serving_count == 0 and settled.gossip == null and !settled.more);
    try std.testing.expect(!runtime.notification_pending);
    try std.testing.expectEqual(@as(u8, 1), lane.len);
    try std.testing.expectEqual(incoming.State.queued, runtime.incoming.?.get(request).?.state);

    // Stopping ends serving starts and checks; claims end once the owner quiesces.
    runtime.stop = true;
    const checked = try admit(table, .beacon_attestation, @splat(3), "data");
    const stopped = try exchange.run(&runtime, &deployed, &host);
    try std.testing.expect(stopped.peers == 1 and stopped.serving_count == 0 and stopped.checks.len == 0);
    try std.testing.expectEqual(@as(usize, 1), stopped.gossip.?.len);
    try std.testing.expectEqual(State.needs_check, table.get(checked).?.state);
    runtime.quiescent = true;
    lane.publish(&.{.{ .closed = undefined }}, 2);
    const quiescent = try exchange.run(&runtime, &deployed, &host);
    try std.testing.expect(quiescent.peers == 1 and quiescent.gossip == null);
    runtime.incoming.?.get(request).?.native = false;
    runtime.incoming.?.retire(request);
    table.close();
}

test "claims follow the host's lane rule for urgent work, ordinary work and the ordinary gate" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 }, .notify_live = false, .env_alive = false };
    runtime.payload_budget.limit = 1 << 20;
    const limits: limits_mod.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    runtime.gossip = try g.Table.init(std.testing.allocator, .{ .capacity = limits_mod.items(&limits), .bytes = limits_mod.bytes(&limits), .limits = limits });
    defer runtime.gossip.?.deinit();
    const table = &runtime.gossip.?;
    const Wanted = struct { ordinary: bool, ready: bool };
    const wants = [_]Wanted{ .{ .ordinary = false, .ready = false }, .{ .ordinary = false, .ready = true }, .{ .ordinary = true, .ready = true } };
    for ([_]bool{ false, true }) |urgent| for ([_]bool{ false, true }) |ordinary| for ([_]bool{ false, true }) |gate| for (wants) |want| {
        const column: ?g.Token = if (urgent) try admit(table, .data_column_sidecar, null, "data") else null;
        const exit: ?g.Token = if (ordinary) try admit(table, .voluntary_exit, null, "data") else null;
        table.ordinary_enabled = gate;
        const demand: exchange.Demand = .{ .settle = 32, .peers = 0, .serving = 0, .gossip = .{ .items = 64, .bytes = 4096, .ordinary = want.ordinary, .ready = want.ready } };
        var selection: exchange.Selection = .{};
        runtime.lock();
        exchange.selectLocked(&runtime, &demand, 1, &selection);
        runtime.unlock();
        // The lane-driven rule the host ran before the exchange.
        const lanes = urgent or ordinary or !gate;
        const claimed = lanes and (urgent or (want.ordinary and (ordinary or !gate)) or (!want.ready and gate and ordinary));
        const after = if (claimed) want.ordinary else gate;
        const held = lanes and want.ready and !want.ordinary and (ordinary or !after);
        try std.testing.expectEqual(claimed, selection.gossip != null);
        try std.testing.expectEqual(after, table.ordinary_enabled);
        try std.testing.expectEqual(selection.gossip_more or held, selection.more);
        if (selection.gossip) |batch| try std.testing.expectEqual(@as(usize, @intFromBool(urgent)) + @intFromBool(ordinary and want.ordinary), batch.len);
        runtime.lock();
        exchange.restoreLocked(&runtime, &selection);
        runtime.unlock();
        try std.testing.expectEqual(gate, table.ordinary_enabled);
        for ([_]?g.Token{ column, exit }) |token| if (token) |value| table.retire(value);
    };
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
    for (0..incoming.capacity_max) |_| _ = try queueRequest(&runtime.incoming.?);
    for (0..512) |_| _ = try admit(table, .voluntary_exit, null, "exit");
    const column: [16 * 1024]u8 = @splat(5);
    for (0..128) |_| _ = try admit(table, .data_column_sidecar, null, &column);

    var host: Host = .{ .runtime = &runtime };
    var columns: usize = 0;
    var turns: usize = 0;
    for (0..16) |_| {
        if (columns == 128) break;
        const delivered = try exchange.run(&runtime, &deployed, &host);
        turns += 1;
        try std.testing.expect(delivered.more);
        try std.testing.expectEqual(@as(usize, exchange.serving_max), delivered.serving_count);
        // The host takes each delivery, and both kinds of traffic refill to saturation.
        for (delivered.serving[0..delivered.serving_count]) |token| {
            retireServed(&runtime.incoming.?, token);
            _ = try queueRequest(&runtime.incoming.?);
        }
        const batch = delivered.gossip.?;
        try std.testing.expectEqual(@as(usize, g.batch_max), batch.len);
        for (batch.tokens[0..batch.len]) |token| {
            const kind = table.get(token).?.kind;
            columns += @intFromBool(kind == .data_column_sidecar);
            try std.testing.expect(table.report(token, .accept, host.clock));
            table.retire(token);
            if (kind == .voluntary_exit) _ = try admit(table, .voluntary_exit, null, "exit");
        }
    }
    std.debug.print("exchange column_burst columns={d} turns={d}\n", .{ columns, turns });
    try std.testing.expectEqual(@as(usize, 128), columns);
    try std.testing.expectEqual(@as(usize, 2), turns);
    for (runtime.incoming.?.cells, 0..) |*cell, i| if (cell.state != .free) {
        cell.native = false;
        runtime.incoming.?.retire(.{ .index = @intCast(i), .generation = cell.generation });
    };
    table.close();
}
