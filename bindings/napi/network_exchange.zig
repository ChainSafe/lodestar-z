//! One host drain turn. Legacy settlement runs first and commits per promise. The payload the host
//! asked for is then pinned under one mutex hold, built into a complete result without the mutex,
//! and committed as a whole, or restored so the next exchange delivers it again.
const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const Runtime = r.Runtime;

const put = @import("network_js.zig").put;
const element = @import("network_js.zig").element;
const bytes = @import("network_js.zig").bytes;

pub const peers_max = 64;
/// Serving starts per exchange. An exchange that delivers all of them asks for another.
pub const serving_max = 8;
const settle_max = @import("network_publications.zig").capacity_max;

/// The payload one exchange may deliver, read in full before any state changes.
pub const Demand = struct {
    /// Completions settled per native table.
    settle: usize,
    peers: usize,
    serving: usize,
    /// Dependency checks and one job batch, or null to leave gossip queued.
    gossip: ?Gossip,

    pub const Gossip = struct {
        items: usize,
        bytes: usize,
        /// The ordinary gate a claim sets: the host takes ordinary jobs now. Implies `ready`.
        ordinary: bool,
        /// The host executor can take work, whatever its held jobs and time budget.
        ready: bool,
    };

    pub fn parse(value: Value) !Demand {
        try cfg.completeObject(value, &.{ "settle", "peers", "serving", "gossip" });
        var demand: Demand = .{
            .settle = @intCast(try cfg.integer(try cfg.get(value, "settle"), settle_max)),
            .peers = @intCast(try cfg.integer(try cfg.get(value, "peers"), peers_max)),
            .serving = @intCast(try cfg.integer(try cfg.get(value, "serving"), serving_max)),
            .gossip = null,
        };
        if (demand.settle == 0) return error.InvalidNetworkInteger;
        const gossip = try cfg.get(value, "gossip");
        if (try gossip.typeof() == .null) return demand;
        try cfg.completeObject(gossip, &.{ "items", "bytes", "ordinary", "ready" });
        demand.gossip = .{
            .items = @intCast(try cfg.integer(try cfg.get(gossip, "items"), g.batch_max)),
            .bytes = @intCast(try cfg.integer(try cfg.get(gossip, "bytes"), g.batch_bytes)),
            .ordinary = try cfg.boolean(try cfg.get(gossip, "ordinary")),
            .ready = try cfg.boolean(try cfg.get(gossip, "ready")),
        };
        if (demand.gossip.?.ordinary and !demand.gossip.?.ready) return error.InvalidNetworkConfig;
        return demand;
    }
};

pub const Settled = struct { count: usize = 0, more: bool = false };

const CheckView = struct { root: [32]u8, slot: u64, identity: n.PeerId, topic: [g.topic_max]u8, topic_len: u16 };

/// Payload one exchange pinned. Pinned cells stay in place: the owner never retires a copying cell.
pub const Selection = struct {
    peers: [peers_max]projection.Entry = undefined,
    peer_count: usize = 0,
    /// The host asked for peers, so the commit consumes the lane's head.
    peers_taken: bool = false,
    peers_more: bool = false,
    serving: [serving_max]incoming.Token = undefined,
    serving_count: usize = 0,
    /// Each serving start's closed promise; the build creates the first `closed_count`.
    closed: [serving_max]napi.Deferred = undefined,
    closed_count: usize = 0,
    serving_queued: bool = false,
    checks: g.Batch = .{},
    views: [g.batch_max]CheckView = undefined,
    gossip: ?g.Batch = null,
    /// The ordinary gate before the claim set it.
    gate: bool = true,
    /// Claimable gossip remained after the claim.
    gossip_more: bool = false,
    /// Monotonic milliseconds when the build ended, for the maintenance the commit runs.
    finished: u64 = 0,
    /// Native holds work for another exchange, or the drain keeps the notification latch.
    more: bool = false,
};

/// The host's claim rule: urgent work whenever present; ordinary work, or reopening the gate, only
/// when the host takes ordinary jobs; and closing the gate while the executor cannot run them.
fn claimWanted(work: g.Table.HostWork, gate: bool, wanted: *const Demand.Gossip) bool {
    if (work.urgent) return true;
    if (wanted.ordinary and (work.ordinary or !gate)) return true;
    return !wanted.ready and gate and work.ordinary;
}

/// Pins the payload `demand` asks for. The caller holds the runtime mutex.
pub fn selectLocked(runtime: *Runtime, demand: *const Demand, now: u64, selection: *Selection) void {
    if (demand.peers > 0) if (runtime.lane) |lane| {
        selection.peers_taken = true;
        selection.peer_count = lane.peek(selection.peers[0..demand.peers]);
        selection.peers_more = lane.len > selection.peer_count;
    };
    if (!runtime.stop and !runtime.quiescent) if (runtime.incoming) |*table| {
        for (0..demand.serving) |_| {
            const token = table.oldest() orelse break;
            const cell = table.get(token).?;
            cell.copying = true;
            cell.state = .copying;
            table.refresh(cell);
            selection.serving[selection.serving_count] = token;
            selection.serving_count += 1;
        }
        selection.serving_queued = table.oldest() != null;
    };
    var held = false;
    if (demand.gossip) |*wanted| if (!runtime.quiescent) if (runtime.gossip) |*table| {
        // Read before this exchange changes the table, as the host's lanes were at a turn's start.
        const work = table.hostWork();
        if (work.checks and !runtime.stop) {
            selection.checks = table.claimChecks(now);
            for (selection.checks.tokens[0..selection.checks.len], selection.views[0..selection.checks.len]) |token, *view| {
                const cell = table.get(token).?;
                view.* = .{ .root = cell.metadata.root.?, .slot = cell.metadata.slot.?, .identity = cell.identity, .topic = cell.topic, .topic_len = cell.topic_len };
            }
        }
        selection.gate = table.ordinary_enabled;
        if (claimWanted(work, selection.gate, wanted)) {
            const previous = .{ table.pending(), table.deadline() };
            selection.gossip = table.claimDemand(now, .{ .items = wanted.items, .bytes = wanted.bytes, .ordinary = wanted.ordinary });
            // The owner's wait reads these; a change wakes it to recompute.
            if (!std.meta.eql(previous, .{ table.pending(), table.deadline() })) runtime.signalLocked();
            selection.gossip_more = table.hasWork();
        }
        // Ordinary work the host holds back while it could execute needs another exchange.
        held = wanted.ready and !wanted.ordinary and (work.ordinary or !table.ordinary_enabled);
    };
    // Classified checks can make work claimable, which the next exchange claims.
    selection.more = selection.peers_more or selection.serving_count == serving_max or selection.checks.len > 0 or selection.gossip_more or held;
}

/// Hands the pinned payload to the host, which holds its complete result. Returns whether serving
/// starts now hold promises that keep the event loop alive. The caller holds the runtime mutex.
pub fn commitLocked(runtime: *Runtime, selection: *const Selection) bool {
    if (selection.peers_taken) if (runtime.lane) |lane| {
        runtime.bridge.deliver(.peer_event, selection.peer_count);
        lane.commit(selection.peer_count);
        // Events published during the copy were not reported, so the owner notifies again.
        const rearm = !selection.peers_more and lane.len > 0 and !runtime.quiescent;
        if (rearm) runtime.work_rearm = true;
        // Committed events free lane room the owner publishes into.
        if (!runtime.quiescent and (selection.peer_count > 0 or rearm)) runtime.signalLocked();
    };
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
        runtime.signalLocked();
    }
    runtime.bridge.deliver(.dependency_check, selection.checks.len);
    if (selection.gossip) |*batch| {
        const table = &runtime.gossip.?;
        runtime.bridge.deliver(.gossip_message, batch.len);
        table.maintain(selection.finished, table.slot);
        table.finish(batch, true);
        if (runtime.quiescent) table.trim() else if (!selection.gossip_more and table.hasWork()) {
            runtime.work_rearm = true;
            runtime.signalLocked();
        }
    }
    return selection.serving_count > 0 and runtime.notify_live;
}

/// Returns every pinned item to where it was, so the next exchange delivers it again. The caller
/// holds the runtime mutex.
pub fn restoreLocked(runtime: *Runtime, selection: *const Selection) void {
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
        runtime.signalLocked();
    }
    if (selection.checks.len > 0) {
        runtime.gossip.?.retryChecks(&selection.checks);
        runtime.work_rearm = true;
        runtime.signalLocked();
    }
    if (selection.gossip) |*batch| {
        const table = &runtime.gossip.?;
        table.finish(batch, false);
        table.ordinary_enabled = selection.gate;
        if (runtime.quiescent) table.trim() else if (table.hasWork()) {
            runtime.work_rearm = true;
            runtime.signalLocked();
        }
    }
}

/// Ends a drain whose exchange failed: releases the notification latch, or notifies again while
/// legacy results remain, and has the owner notify again for payload the host did not take.
pub fn failLocked(runtime: *Runtime) void {
    const more = runtime.endDrainLocked();
    runtime.work_rearm = true;
    runtime.signalLocked();
    if (!more) return;
    runtime.notification_pending = false;
    runtime.pingLocked();
}

/// Runs one exchange for a parsed demand. `host` settles legacy results, reads the clock, builds
/// the result from a selection, discards what a failed build created, and keeps the event loop
/// alive for serving starts.
pub fn run(runtime: *Runtime, demand: *const Demand, host: anytype) !@TypeOf(host.*).Output {
    const legacy = try host.settle(demand.settle);
    const now = if (demand.gossip != null) try host.now() else 0;
    var selection: Selection = .{};
    runtime.lock();
    selectLocked(runtime, demand, now, &selection);
    selection.more = selection.more or legacy.more;
    // Owner work after this check pings again, so releasing the latch here loses none.
    if (!selection.more) selection.more = runtime.endDrainLocked();
    runtime.unlock();
    const output = host.build(&selection, legacy.count) catch |err| return abandon(runtime, &selection, host, err);
    if (selection.gossip != null) selection.finished = host.now() catch |err| return abandon(runtime, &selection, host, err);
    runtime.lock();
    const keep_alive = commitLocked(runtime, &selection);
    runtime.unlock();
    if (keep_alive) host.keepAlive();
    return output;
}

fn abandon(runtime: *Runtime, selection: *const Selection, host: anytype, err: anyerror) anyerror {
    host.discard(selection);
    runtime.lock();
    restoreLocked(runtime, selection);
    runtime.unlock();
    return err;
}

/// Builds the complete result for a selection. Creates the serving starts' closed promises, which
/// the caller discards if any later step fails.
pub fn build(env: napi.Env, runtime: *Runtime, selection: *Selection, settled: usize) !Value {
    const object = try env.createObject();
    try put(object, "settled", try env.createUint32(@intCast(settled)));
    const peers = try env.createArrayWithLength(selection.peer_count);
    for (selection.peers[0..selection.peer_count], 0..) |*entry, i| try element(peers, i, try projection.observation(env, entry));
    try put(object, "peers", peers);
    const serving = try env.createArrayWithLength(selection.serving_count);
    for (selection.serving[0..selection.serving_count], 0..) |token, i| {
        selection.closed[i] = try env.createPromise();
        selection.closed_count = i + 1;
        const cell = &runtime.incoming.?.cells[token.index];
        try element(serving, i, try @import("network_incoming_js.zig").descriptorValue(runtime, token, cell, selection.closed[i]));
    }
    try put(object, "serving", serving);
    try put(object, "servingQueued", try env.getBoolean(selection.serving_queued));
    const checks = try env.createArrayWithLength(selection.checks.len);
    for (selection.checks.tokens[0..selection.checks.len], selection.views[0..selection.checks.len], 0..) |token, *view, i| {
        const check = try env.createObject();
        const handle = try env.createObject();
        try put(handle, "index", try env.createUint32(token.index));
        try put(handle, "generation", try env.createBigintUint64(token.generation));
        try put(check, "handle", handle);
        try put(check, "root", try bytes(env, &view.root));
        try put(check, "slot", try env.createBigintUint64(view.slot));
        try put(check, "peerId", try @import("network_js.zig").peerIdValue(env, &view.identity));
        try put(check, "topic", try env.createStringUtf8(view.topic[0..view.topic_len]));
        try element(checks, i, check);
    }
    try put(object, "checks", checks);
    try put(object, "gossip", if (selection.gossip) |*batch| try jobs(env, runtime, batch) else try env.getNull());
    try put(object, "more", try env.getBoolean(selection.more));
    // Own, so the binding records a start it could not hand over without reaching inherited accessors.
    try put(object, "failure", try env.getNull());
    return object;
}

fn jobs(env: napi.Env, runtime: *Runtime, batch: *const g.Batch) !Value {
    const table = &runtime.gossip.?;
    const messages = try env.createArrayWithLength(batch.len);
    for (batch.tokens[0..batch.len], 0..) |token, i| {
        try element(messages, i, try @import("network_gossip_js.zig").descriptor(runtime, token, &table.cells[token.index]));
    }
    const object = try env.createObject();
    try put(object, "messages", messages);
    const list = try env.createArrayWithLength(batch.job_count);
    for (batch.jobs[0..batch.job_count], 0..) |job, i| {
        const value = try env.createObject();
        try put(value, "kind", try env.createStringUtf8(@tagName(job.kind)));
        try put(value, "start", try env.createUint32(@intCast(job.start)));
        try put(value, "length", try env.createUint32(@intCast(job.len)));
        try put(value, "grouped", try env.getBoolean(job.grouped));
        try put(value, "urgent", try env.getBoolean(n.gossip_processor.limits_mod.urgent(job.kind)));
        try element(list, i, value);
    }
    try put(object, "jobs", list);
    return object;
}

test {
    _ = @import("network_exchange_test.zig");
}
