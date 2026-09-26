//! One host exchange. Phase A decodes the actions and demand, and throws with nothing applied. Phase 0 settles
//! legacy results. Phase B, under the mutex, disarms, applies the actions, takes the capacities and pins the rows it
//! serves. Phase C builds the result; no user code runs from here on. Phase D, under the mutex, commits (or restores
//! the pins when JavaScript stopped), unpins, wakes the owner once and arms when nothing is queued.
const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const readiness = @import("network_readiness.zig");
const Runtime = r.Runtime;
const Row = readiness.Row;
const none = n.index_list.none;

const bytes = @import("network_js.zig").bytes;

/// Actions one exchange applies; a longer batch is refused before any is applied.
pub const action_max = 256;
pub const peers_max = 64;
pub const serving_max = 8;
const settle_max = @import("network_publications.zig").capacity_max;

/// One exchange's quotas, where zero disables a service, and the host's standing capacities, null to keep them.
pub const Demand = struct {
    settle: usize,
    peers: usize,
    checks: usize,
    serving: usize,
    messages: usize,
    bytes: usize,
    claim_ordinary: bool,
    capacity: ?r.Capacity,

    pub fn parse(value: Value) !Demand {
        _ = try object(value);
        const capacity = try cfg.get(value, "capacity");
        const demand: Demand = .{
            .settle = @intCast(try cfg.integer(try cfg.get(value, "settleCells"), settle_max)),
            .peers = @intCast(try cfg.integer(try cfg.get(value, "peers"), peers_max)),
            .checks = @intCast(try cfg.integer(try cfg.get(value, "checks"), g.batch_max)),
            .serving = @intCast(try cfg.integer(try cfg.get(value, "servingStarts"), serving_max)),
            .messages = @intCast(try cfg.integer(try cfg.get(value, "messages"), g.batch_max)),
            .bytes = @intCast(try cfg.integer(try cfg.get(value, "bytes"), g.batch_bytes)),
            .claim_ordinary = try cfg.boolean(try cfg.get(value, "claimOrdinary")),
            .capacity = if (try capacity.typeof() == .null) null else .{
                .serving = @intCast(try cfg.integer(try cfg.get(try object(capacity), "serving"), incoming.capacity_max)),
                .ordinary = try cfg.boolean(try cfg.get(capacity, "ordinary")),
            },
        };
        if (demand.settle == 0) return error.InvalidNetworkInteger;
        return demand;
    }
};

fn object(value: Value) !Value {
    if (try value.typeof() != .object or try value.isArray()) return error.InvalidNetworkConfig;
    return value;
}

/// A host obligation or request, applied in O(1) under the mutex. A verdict's `waited_ns` is how long before this
/// exchange's call the host's validation settled, for the verdicts the host times.
pub const Action = union(enum) {
    verdict: struct { token: g.Token, verdict: n.gossipsub.Verdict, waited_ns: ?u64 = null },
    classify: struct { token: g.Token, available: bool },
    block: [32]u8,
    recheck,
    drop_queued,
    report_peer: struct { identity: n.PeerId, action: n.peers.types.PeerAction, count: u8 },
};
const ActionType = enum { verdict, classify, block, recheck, dropQueued, reportPeer };

pub fn parseActions(value: Value, into: *[action_max]Action) !usize {
    if (!try value.isArray()) return error.InvalidNetworkActions;
    const count = try value.getArrayLength();
    if (count > action_max) return error.InvalidNetworkActions;
    for (into[0..count], 0..) |*action, i| action.* = try parseAction(try value.getElement(@intCast(i)));
    return count;
}

fn parseAction(value: Value) !Action {
    _ = object(value) catch return error.InvalidNetworkAction;
    return switch (try name(ActionType, try cfg.get(value, "type"), error.InvalidNetworkAction)) {
        .verdict => .{ .verdict = .{
            .token = try handle(try cfg.get(value, "handle")),
            .verdict = try name(n.gossipsub.Verdict, try cfg.get(value, "verdict"), error.InvalidGossipVerdict),
            .waited_ns = try waited(try cfg.get(value, "waitedMs")),
        } },
        .classify => .{ .classify = .{ .token = try handle(try cfg.get(value, "handle")), .available = try cfg.boolean(try cfg.get(value, "available")) } },
        .block => .{ .block = try cfg.fixed(32, try cfg.get(value, "root")) },
        .recheck => .recheck,
        .dropQueued => .drop_queued,
        .reportPeer => .{ .report_peer = .{
            .identity = try cfg.peerIdFrom(try cfg.get(value, "peerId")),
            .action = try name(n.peers.types.PeerAction, try cfg.get(value, "action"), error.InvalidNetworkAction),
            .count = try reportCount(try cfg.get(value, "count")),
        } },
    };
}

fn name(comptime T: type, value: Value, invalid: anyerror) !T {
    var text: [16]u8 = undefined;
    const len = app.text(value, &text) catch return invalid;
    return std.meta.stringToEnum(T, text[0..len]) orelse invalid;
}

fn handle(value: Value) !g.Token {
    if (try value.typeof() != .object) return error.InvalidGossipHandle;
    const index = try cfg.integer(try cfg.get(value, "index"), n.gossip_processor.limits_mod.capacity_max - 1);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    if (generation == 0) return error.InvalidGossipHandle;
    return .{ .index = @intCast(index), .generation = generation };
}

/// A verdict's optional wait, capped at a day so the host's clock cannot overflow it.
fn waited(value: Value) !?u64 {
    if (try value.typeof() == .undefined) return null;
    const ms = cfg.number(value) catch return error.InvalidNetworkAction;
    if (ms < 0) return error.InvalidNetworkAction;
    return @intFromFloat(@min(ms, std.time.ms_per_day) * std.time.ns_per_ms);
}

fn reportCount(value: Value) !u8 {
    const result = try cfg.integer(value, @import("network_peer_reports.zig").report_max);
    if (result == 0) return error.InvalidNetworkInteger;
    return @intCast(result);
}

const CheckView = struct { root: [32]u8, slot: u64, identity: n.PeerId, topic: [g.topic_max]u8, topic_len: u16 };

/// What one exchange pinned. Pinned cells stay in place: the owner never retires a copying cell.
pub const Selection = struct {
    pinned: [readiness.row_count]Row = undefined,
    pinned_count: usize = 0,
    peers: [peers_max]projection.Entry = undefined,
    peer_count: usize = 0,
    serving: [serving_max]incoming.Token = undefined,
    serving_count: usize = 0,
    /// Each serving start's closed promise; the build creates the first `closed_count`.
    closed: [serving_max]napi.Deferred = undefined,
    closed_count: usize = 0,
    checks: g.Batch = .{},
    views: [g.batch_max]CheckView = undefined,
    gossip: ?g.Batch = null,
    /// The owner has work from this exchange.
    wake: bool = false,
    /// When the exchange call entered, and when it applied and claimed, after settlement and the runtime mutex.
    entered_ns: u64 = 0,
    claimed_ns: u64 = 0,

    pub fn delivers(self: *const Selection) bool {
        return self.peer_count > 0 or self.serving_count > 0 or self.checks.len > 0 or self.gossip != null;
    }
};

/// The result's scheduling fields, read in phase D.
pub const Outcome = packed struct(u4) {
    /// A fresh exchange with the same enablement would make progress.
    more: bool = false,
    /// Payload waits for a service this exchange disabled.
    disabled: bool = false,
    parked_serving: bool = false,
    parked_ordinary: bool = false,
};

/// How a failed build or finish ends: JavaScript that cannot run shuts the runtime down locally, and anything else
/// breaks the bridge contract and terminates the process. No allocation of ours can fail there
/// (bindings/test/network-allocation.test.ts).
pub const Failure = enum { stopped, contract };

fn enabled(runtime: *Runtime, demand: *const Demand, row: Row) bool {
    return switch (row) {
        .legacy => true,
        .peers => demand.peers > 0,
        .checks => demand.checks > 0,
        .serving => demand.serving > 0,
        .gossip => demand.messages > 0 and (demand.claim_ordinary or runtime.gossip.?.readiness().urgent),
    };
}

fn applyLocked(runtime: *Runtime, actions: []const Action, now: u64, entered_ns: u64) void {
    if (runtime.stop or runtime.quiescent) return;
    for (actions) |action| switch (action) {
        .report_peer => |report| runtime.reports.addCount(&report.identity, report.action, report.count),
        else => if (runtime.gossip) |*table| switch (action) {
            .verdict => |verdict| {
                if (verdict.waited_ns) |ns| table.timeVerdict(verdict.token, ns, entered_ns);
                _ = table.report(verdict.token, verdict.verdict, now);
            },
            .classify => |check| _ = table.classify(check.token, check.available),
            .block => |root| table.notifyBlock(root),
            .recheck => table.recheck(),
            .drop_queued => table.dropQueued(),
            .report_peer => unreachable,
        },
    };
}

fn selectLocked(runtime: *Runtime, demand: *const Demand, now: u64, selection: *Selection) void {
    const ready = &runtime.readiness;
    var next = ready.payload.head;
    for (0..readiness.row_count) |_| {
        if (next == none) break;
        const row: Row = @enumFromInt(next);
        next = ready.rows[next].link.next;
        if (!enabled(runtime, demand, row)) continue;
        ready.pin(row);
        selection.pinned[selection.pinned_count] = row;
        selection.pinned_count += 1;
        switch (row) {
            .legacy => unreachable,
            .peers => selection.peer_count = runtime.lane.?.peek(selection.peers[0..demand.peers]),
            .serving => selectServing(runtime, demand, selection),
            .checks => {
                const table = &runtime.gossip.?;
                selection.checks = table.claimChecks(now, demand.checks);
                for (selection.checks.tokens[0..selection.checks.len], selection.views[0..selection.checks.len]) |token, *view| {
                    const cell = table.get(token).?;
                    view.* = .{ .root = cell.metadata.root.?, .slot = cell.metadata.slot.?, .identity = cell.identity, .topic = cell.topic, .topic_len = cell.topic_len };
                }
            },
            .gossip => {
                const claim = runtime.gossip.?.claimDemand(now, .{ .items = demand.messages, .bytes = demand.bytes, .ordinary = demand.claim_ordinary and runtime.capacity.ordinary });
                if (claim.len > 0) selection.gossip = claim;
            },
        }
    }
}

fn selectServing(runtime: *Runtime, demand: *const Demand, selection: *Selection) void {
    const table = &runtime.incoming.?;
    const limit = @min(demand.serving, runtime.capacity.serving);
    for (0..incoming.capacity_max) |_| {
        if (selection.serving_count == limit) break;
        const token = table.oldest() orelse break;
        const cell = table.get(token).?;
        cell.copying = true;
        cell.state = .copying;
        table.refresh(cell);
        selection.serving[selection.serving_count] = token;
        selection.serving_count += 1;
    }
}

/// Returns whether serving starts now hold promises that keep the event loop alive.
fn commitLocked(runtime: *Runtime, selection: *Selection) bool {
    if (selection.peer_count > 0) {
        runtime.bridge.deliver(.peer_event, selection.peer_count);
        runtime.lane.?.commit(selection.peer_count);
        // Committed events free lane room the owner publishes into.
        selection.wake = true;
    }
    if (selection.serving_count > 0) {
        const table = &runtime.incoming.?;
        for (selection.serving[0..selection.serving_count], selection.closed[0..selection.serving_count]) |token, deferred| {
            const cell = table.get(token).?;
            cell.closed = deferred;
            cell.copying = false;
            cell.exposed = true;
            table.diag.requestsTaken +|= 1;
            table.releaseInput(cell);
            cell.state = if (cell.native) .serving else .terminal;
            table.releasePayload(cell);
            table.refresh(cell);
        }
        runtime.bridge.deliver(.serving_start, selection.serving_count);
        runtime.capacity.serving -|= @intCast(selection.serving_count);
        selection.wake = true;
    }
    runtime.bridge.deliver(.dependency_check, selection.checks.len);
    if (selection.gossip) |*batch| {
        runtime.bridge.deliver(.gossip_message, batch.len);
        runtime.gossip.?.finish(batch, true);
    }
    if (runtime.quiescent) if (runtime.gossip) |*table| table.trim();
    return selection.serving_count > 0 and runtime.notify_live;
}

/// Returns every pinned item to where it was, so teardown reclaims it.
fn restoreLocked(runtime: *Runtime, selection: *const Selection) void {
    if (selection.serving_count > 0) {
        const table = &runtime.incoming.?;
        for (selection.serving[0..selection.serving_count]) |token| {
            const cell = table.get(token).?;
            cell.copying = false;
            if (cell.native) {
                cell.state = .queued;
                table.refresh(cell);
                continue;
            }
            // The stream ended while pinned; finish the retirement its end left to the pin.
            cell.state = .terminal;
            table.releasePayload(cell);
            table.refresh(cell);
            if (cell.serving_retained) cell.release_requested = true else table.retire(token);
        }
    }
    if (selection.checks.len > 0) runtime.gossip.?.retryChecks(&selection.checks);
    if (selection.gossip) |*batch| runtime.gossip.?.finish(batch, false);
    if (runtime.quiescent) if (runtime.gossip) |*table| table.trim();
}

/// Unpins, wakes the owner once and arms when nothing is queued.
fn endLocked(runtime: *Runtime, demand: *const Demand, selection: *const Selection) Outcome {
    const ready = &runtime.readiness;
    for (selection.pinned[0..selection.pinned_count]) |row| ready.unpin(row, runtime.wantLocked(row));
    if (selection.wake) runtime.signalLocked();
    runtime.refreshLocked();
    var outcome: Outcome = .{
        .more = ready.control.len > 0,
        .parked_serving = ready.place(.serving) == .parked,
        .parked_ordinary = ready.place(.gossip) == .parked,
    };
    var next = ready.payload.head;
    for (0..readiness.row_count) |_| {
        if (next == none) break;
        if (enabled(runtime, demand, @enumFromInt(next))) outcome.more = true else outcome.disabled = true;
        next = ready.rows[next].link.next;
    }
    if (ready.arm()) runtime.bridge.boundary();
    return outcome;
}

fn gossipMarks(runtime: *Runtime) struct { bool, ?u64 } {
    const table = if (runtime.gossip) |*table| table else return .{ false, null };
    return .{ table.pending(), table.deadline() };
}

/// Runs phases B to D for a call that entered at `entered_ns`. `host` builds and finishes the result, discards what
/// a failed build created, classifies a failure and keeps the event loop alive for serving starts.
pub fn run(runtime: *Runtime, actions: []const Action, demand: *const Demand, now: u64, entered_ns: u64, host: anytype) !@TypeOf(host.*).Result {
    var selection: Selection = .{ .wake = actions.len > 0, .entered_ns = entered_ns };
    runtime.lock();
    selection.claimed_ns = r.bridge.now();
    if (runtime.gossip) |*table| table.stages.tick(selection.claimed_ns);
    runtime.readiness.armed = false;
    const marks = gossipMarks(runtime);
    applyLocked(runtime, actions, now, entered_ns);
    if (demand.capacity) |capacity| runtime.capacity = capacity;
    runtime.refreshLocked();
    selectLocked(runtime, demand, now, &selection);
    // Ignored claims leave verdicts to apply, and a classification can move the owner's deadline.
    if (!std.meta.eql(marks, gossipMarks(runtime))) selection.wake = true;
    runtime.unlock();
    const output = host.build(&selection) catch |err| {
        const failure = host.classify(err);
        host.discard(&selection);
        runtime.lock();
        restoreLocked(runtime, &selection);
        _ = endLocked(runtime, demand, &selection);
        runtime.unlock();
        return fail(host, failure, err);
    };
    runtime.lock();
    const keep_alive = commitLocked(runtime, &selection);
    const outcome = endLocked(runtime, demand, &selection);
    runtime.unlock();
    if (keep_alive) host.keepAlive();
    return host.finish(output, outcome) catch |err| return fail(host, host.classify(err), err);
}

/// A stopped environment returns the error, for the caller's local shutdown; a contract failure terminates.
fn fail(host: anytype, failure: Failure, err: anyerror) anyerror {
    return switch (failure) {
        .stopped => err,
        .contract => host.fatal(err),
    };
}

/// Results created once, one per combination of the scheduling fields, so an exchange that delivers nothing
/// allocates nothing.
pub const Results = struct {
    idle: [16]?napi.Ref = @splat(null),

    pub fn prepare(self: *Results, env: napi.Env) !void {
        const empty = try env.createArrayWithLength(0);
        try empty.objectFreeze();
        for (&self.idle, 0..) |*slot, i| {
            const result = try env.createObject();
            inline for (.{ "peers", "serving", "checks" }) |field| try result.setNamedProperty(field, empty);
            try result.setNamedProperty("gossip", try env.getNull());
            try result.setNamedProperty("failure", try env.getNull());
            try schedule(env, result, @bitCast(@as(u4, @intCast(i))));
            try (try result.getNamedProperty("parked")).objectFreeze();
            try result.objectFreeze();
            slot.* = try napi.Ref.create(env.env, result, 1);
        }
    }

    pub fn dispose(self: *Results) void {
        for (&self.idle) |*slot| {
            if (slot.*) |ref| ref.delete() catch unreachable;
            slot.* = null;
        }
    }
};

fn schedule(env: napi.Env, result: Value, outcome: Outcome) !void {
    try result.setNamedProperty("more", try env.getBoolean(outcome.more));
    try result.setNamedProperty("disabledWaiting", try env.getBoolean(outcome.disabled));
    const parked = try env.createObject();
    try parked.setNamedProperty("serving", try env.getBoolean(outcome.parked_serving));
    try parked.setNamedProperty("ordinary", try env.getBoolean(outcome.parked_ordinary));
    try result.setNamedProperty("parked", parked);
}

/// Builds a fresh result for a selection that delivers something. Creates the serving starts' closed promises,
/// which the caller discards if a later step fails.
pub fn build(env: napi.Env, runtime: *Runtime, selection: *Selection) !Value {
    const result = try env.createObject();
    const peers = try env.createArrayWithLength(selection.peer_count);
    for (selection.peers[0..selection.peer_count], 0..) |*entry, i| try peers.setElement(@intCast(i), try projection.observation(env, entry));
    try result.setNamedProperty("peers", peers);
    const serving = try env.createArrayWithLength(selection.serving_count);
    for (selection.serving[0..selection.serving_count], 0..) |token, i| {
        selection.closed[i] = try env.createPromise();
        selection.closed_count = i + 1;
        const cell = &runtime.incoming.?.cells[token.index];
        try serving.setElement(@intCast(i), try @import("network_incoming_js.zig").descriptorValue(runtime, token, cell, selection.closed[i]));
    }
    try result.setNamedProperty("serving", serving);
    const checks = try env.createArrayWithLength(selection.checks.len);
    for (selection.checks.tokens[0..selection.checks.len], selection.views[0..selection.checks.len], 0..) |token, *view, i| {
        const check = try env.createObject();
        const reference = try env.createObject();
        try reference.setNamedProperty("index", try env.createUint32(token.index));
        try reference.setNamedProperty("generation", try env.createBigintUint64(token.generation));
        try check.setNamedProperty("handle", reference);
        try check.setNamedProperty("root", try bytes(env, &view.root));
        try check.setNamedProperty("slot", try env.createBigintUint64(view.slot));
        try check.setNamedProperty("peerId", try @import("network_js.zig").peerIdValue(env, &view.identity));
        try check.setNamedProperty("topic", try env.createStringUtf8(view.topic[0..view.topic_len]));
        try checks.setElement(@intCast(i), check);
    }
    try result.setNamedProperty("checks", checks);
    try result.setNamedProperty("gossip", if (selection.gossip) |*batch| try jobs(env, runtime, selection, batch) else try env.getNull());
    try result.setNamedProperty("failure", try env.getNull());
    return result;
}

/// Sets a fresh result's scheduling fields, or returns the prepared result when nothing was built.
pub fn finish(env: napi.Env, runtime: *Runtime, output: ?Value, outcome: Outcome) !Value {
    const result = output orelse return runtime.results.idle[@as(u4, @bitCast(outcome))].?.getValue();
    try schedule(env, result, outcome);
    return result;
}

fn jobs(env: napi.Env, runtime: *Runtime, selection: *const Selection, batch: *const g.Batch) !Value {
    const table = &runtime.gossip.?;
    const messages = try env.createArrayWithLength(batch.len);
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        try messages.setElement(@intCast(i), try @import("network_gossip_js.zig").descriptor(runtime, token, &table.cells[token.index]));
    }
    const result = try env.createObject();
    try result.setNamedProperty("messages", messages);
    const list = try env.createArrayWithLength(batch.job_count);
    for (batch.jobs[0..batch.job_count], 0..) |job, i| {
        const value = try env.createObject();
        try value.setNamedProperty("kind", try env.createStringUtf8(@tagName(job.kind)));
        try value.setNamedProperty("start", try env.createUint32(@intCast(job.start)));
        try value.setNamedProperty("length", try env.createUint32(@intCast(job.len)));
        try value.setNamedProperty("grouped", try env.getBoolean(job.grouped));
        try value.setNamedProperty("urgent", try env.getBoolean(n.gossip_processor.limits_mod.urgent(job.kind)));
        try list.setElement(@intCast(i), value);
    }
    try result.setNamedProperty("jobs", list);
    const offset: f64 = @floatFromInt(selection.claimed_ns -| selection.entered_ns);
    try result.setNamedProperty("claimOffsetMs", try env.createDouble(offset / std.time.ns_per_ms));
    return result;
}

test {
    _ = @import("network_exchange_test.zig");
}
