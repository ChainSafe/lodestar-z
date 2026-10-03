//! One host exchange. The JS adapter decodes actions and demand before entering this module. Phase B, under the
//! mutex, disarms, applies the actions, takes the capacities and pins the completions and rows it serves, or takes the
//! close result once the owner quiesced and nothing else is due. Phase C joins the owner for a close and builds the
//! result; no user code runs from here on. Phase D, under the mutex, commits (or restores the pins when JavaScript
//! stopped), unpins, wakes the owner once and arms when nothing is queued.
const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const readiness = @import("network_readiness.zig");
const publications = @import("network_publications.zig");
const commands = @import("network_commands.zig");
const requests = @import("network_requests.zig");
const fatal = @import("network_fatal.zig");
const Runtime = r.Runtime;
const Row = readiness.Row;
const none = n.index_list.none;

/// Actions one exchange applies; a longer batch is refused before any is applied.
pub const action_max = 256;
pub const peers_max = 64;
pub const serving_max = 8;
/// Owner dispositions one exchange acknowledges; more set `more`.
pub const acknowledged_max = action_max;

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
};

/// A host obligation or request, applied in O(1) under the mutex.
pub const Action = union(enum) {
    verdict: struct { token: g.Token, verdict: n.gossipsub.Gossipsub.Verdict },
    classify: struct { token: g.Token, available: bool },
    block: [32]u8,
    recheck,
    drop_queued,
    report_peer: struct { identity: n.PeerId, action: n.peers.types.PeerAction, count: u8 },
};
const CheckView = struct { root: [32]u8, slot: u64, identity: n.PeerId, topic: [g.topic_max]u8, topic_len: u16 };

/// What one exchange pinned. Pinned cells stay in place: the owner never retires a copying cell.
pub const Selection = struct {
    pinned: [readiness.row_count]Row = undefined,
    pinned_count: usize = 0,
    peers: [peers_max]projection.Entry = undefined,
    peer_count: usize = 0,
    serving: [serving_max]incoming.Token = undefined,
    serving_count: usize = 0,
    checks: g.Batch = .{},
    views: [g.batch_max]CheckView = undefined,
    gossip: ?g.Batch = null,
    /// Owner dispositions of delivered messages, taken whatever the demand. Their cells stay acknowledging until
    /// the commit frees them.
    acknowledged: [acknowledged_max]g.Token = undefined,
    acknowledged_count: usize = 0,
    /// Completed publications, taken whatever the demand up to its settle quota per family. Their cells stay copying
    /// until the commit retires them.
    publications: [publications.capacity_max]publications.Token = undefined,
    publication_count: usize = 0,
    /// Completed commands, taken likewise.
    commands: [commands.capacity]commands.Token = undefined,
    command_count: usize = 0,
    /// Due requests, taken likewise: each a chunk for its pending pull or its terminal outcome.
    requests: [requests.capacity_max]requests.Completion = undefined,
    request_count: usize = 0,
    /// The requests the commit retired, each holding a runtime reference until then.
    requests_retired: usize = 0,
    /// Due incoming streams, taken likewise: each its acknowledgement, close and permission outcome.
    incoming: [incoming.capacity_max]incoming.Completion = undefined,
    incoming_count: usize = 0,
    /// The close result, taken alone once the owner quiesced and no completion is due, which the commit delivers.
    closed: ?Closed = null,
    /// The owner has work from this exchange.
    wake: bool = false,

    pub fn delivers(self: *const Selection) bool {
        return self.closed != null or self.peer_count > 0 or self.serving_count > 0 or self.checks.len > 0 or self.gossip != null or self.acknowledged_count > 0 or self.publication_count > 0 or self.command_count > 0 or self.request_count > 0 or self.incoming_count > 0;
    }
};

/// Why the network closed: requested, or the first failure, which names its error.
pub const Closed = struct { reason: r.Reason, failure: ?anyerror };

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
/// breaks the bridge contract and terminates the process. No allocation of ours can fail there.
pub const Failure = enum { stopped, contract };

fn enabled(runtime: *Runtime, demand: *const Demand, row: Row) bool {
    return switch (row) {
        .completions => true,
        .peers => demand.peers > 0,
        .checks => demand.checks > 0,
        .serving => demand.serving > 0,
        .gossip => demand.messages > 0 and (demand.claim_ordinary or runtime.gossip.?.readiness().urgent),
    };
}

fn applyLocked(runtime: *Runtime, actions: []const Action, now: u64) void {
    if (runtime.stop or runtime.quiescent) return;
    for (actions) |action| switch (action) {
        .report_peer => |report| runtime.reports.addCount(&report.identity, report.action, report.count),
        else => if (runtime.gossip) |*table| switch (action) {
            .verdict => |verdict| _ = table.report(verdict.token, verdict.verdict, now),
            .classify => |check| _ = table.classify(check.token, check.available),
            .block => |root| table.notifyBlock(root),
            .recheck => table.recheck(),
            .drop_queued => table.dropQueued(),
            .report_peer => unreachable,
        },
    };
}

fn selectLocked(runtime: *Runtime, demand: *const Demand, now: u64, selection: *Selection) void {
    // Owner quiescence is final, so every completion it left is due now; the close follows the last one.
    if (runtime.quiescent and !runtime.close_delivered and !runtime.settleableLocked())
        selection.closed = .{ .reason = runtime.reason, .failure = if (runtime.reason == .failed) runtime.terminal_error.? else null };
    if (runtime.gossip) |*table| selection.acknowledged_count = table.acknowledgements(&selection.acknowledged);
    selectPublications(runtime, demand.settle, selection);
    selectCommands(runtime, demand.settle, selection);
    selectRequests(runtime, demand.settle, selection);
    selectIncoming(runtime, demand.settle, selection);
    // The close ends delivery: no payload handler runs in its exchange, and none waits for a later one.
    if (selection.closed != null) return;
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
            .completions => unreachable,
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

/// Pins up to `limit` completed publications, resuming past the last one delivered so refilled lower cells cannot
/// starve higher ones.
fn selectPublications(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.publications) |*table| table else return;
    for (0..limit) |_| {
        const i = table.nextTerminal(table.settle_cursor) orelse table.nextTerminal(0) orelse break;
        table.settle_cursor = i + 1;
        const cell = &table.cells[i];
        table.transition(cell, .copying);
        selection.publications[selection.publication_count] = .{ .index = @intCast(i), .generation = cell.generation };
        selection.publication_count += 1;
    }
}

/// Pins up to `limit` completed commands, resuming past the last one delivered.
fn selectCommands(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = &runtime.table;
    for (0..@min(limit, commands.capacity)) |_| {
        const i = table.nextTerminal(table.settle_cursor) orelse table.nextTerminal(0) orelse break;
        table.settle_cursor = i + 1;
        table.transition(&table.cells[i], .copying);
        selection.commands[selection.command_count] = .{ .index = @intCast(i), .generation = table.cells[i].generation };
        selection.command_count += 1;
    }
}

/// Pins up to `limit` due requests, resuming past the last one delivered.
fn selectRequests(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.requests) |*table| table else return;
    for (0..@min(limit, requests.capacity_max)) |_| {
        const i = table.nextDue(table.settle_cursor, runtime.stop, runtime.quiescent) orelse table.nextDue(0, runtime.stop, runtime.quiescent) orelse break;
        table.settle_cursor = i + 1;
        selection.requests[selection.request_count] = table.pin(i, runtime.stop);
        selection.request_count += 1;
    }
}

/// Pins up to `limit` due incoming streams, resuming past the last one delivered.
fn selectIncoming(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.incoming) |*table| table else return;
    for (0..@min(limit, incoming.capacity_max)) |_| {
        const i = table.nextDue(table.settle_cursor) orelse table.nextDue(0) orelse break;
        table.settle_cursor = i + 1;
        selection.incoming[selection.incoming_count] = table.pin(i);
        selection.incoming_count += 1;
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

/// Returns whether serving starts now await closes that keep the event loop alive.
fn commitLocked(runtime: *Runtime, selection: *Selection) bool {
    if (selection.peer_count > 0) {
        runtime.bridge.deliver(.peer_event, selection.peer_count);
        runtime.lane.?.commit(selection.peer_count);
        // Committed events free lane room the owner publishes into.
        selection.wake = true;
    }
    if (selection.serving_count > 0) {
        const table = &runtime.incoming.?;
        for (selection.serving[0..selection.serving_count]) |token| {
            const cell = table.get(token).?;
            cell.closed_awaited = true;
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
    if (selection.publication_count > 0) {
        const table = &runtime.publications.?;
        for (selection.publications[0..selection.publication_count]) |token| table.retire(token);
        runtime.bridge.deliver(.completion, selection.publication_count);
        runtime.retireRequestStorageLocked();
    }
    if (selection.command_count > 0) {
        for (selection.commands[0..selection.command_count]) |token| runtime.table.retire(token);
        runtime.bridge.deliver(.completion, selection.command_count);
        runtime.retireStoresLocked();
    }
    if (selection.request_count > 0) {
        const table = &runtime.requests.?;
        for (selection.requests[0..selection.request_count]) |completion| selection.requests_retired += @intFromBool(table.commit(completion));
        runtime.bridge.deliver(.completion, selection.request_count);
        runtime.retireRequestStorageLocked();
    }
    if (selection.incoming_count > 0) {
        const table = &runtime.incoming.?;
        // A released slot the host no longer awaits goes back to the owner.
        for (selection.incoming[0..selection.incoming_count]) |completion| if (table.commit(completion)) {
            selection.wake = true;
        };
        runtime.bridge.deliver(.completion, selection.incoming_count);
        runtime.retireRequestStorageLocked();
    }
    runtime.bridge.deliver(.dependency_check, selection.checks.len);
    // Close may have freed these cells meanwhile; a freed token is ignored. Not counted as delivered items.
    if (runtime.gossip) |*table| for (selection.acknowledged[0..selection.acknowledged_count]) |token| table.acknowledge(token);
    if (selection.gossip) |*batch| {
        runtime.bridge.deliver(.gossip_message, batch.len);
        runtime.gossip.?.finish(batch, true);
    }
    if (runtime.quiescent) if (runtime.gossip) |*table| table.trim();
    if (selection.closed != null) runtime.close_delivered = true;
    return selection.serving_count > 0 and runtime.notify_live;
}

/// Returns every pinned item to where it was, so teardown reclaims it.
fn restoreLocked(runtime: *Runtime, selection: *const Selection) void {
    if (selection.publication_count > 0) {
        const table = &runtime.publications.?;
        for (selection.publications[0..selection.publication_count]) |token| table.transition(table.get(token).?, .terminal);
    }
    for (selection.commands[0..selection.command_count]) |token| runtime.table.transition(runtime.table.get(token), .terminal);
    for (selection.requests[0..selection.request_count]) |completion| runtime.requests.?.restore(completion);
    for (selection.incoming[0..selection.incoming_count]) |completion| runtime.incoming.?.restore(completion);
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
            if (cell.serving != null) cell.release_requested = true else table.retire(token);
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
    _ = ready.arm();
    return outcome;
}

fn gossipMarks(runtime: *Runtime) struct { bool, ?u64 } {
    const table = if (runtime.gossip) |*table| table else return .{ false, null };
    return .{ table.pending(true), table.deadline() };
}

/// Runs phases B to D. `host` builds and finishes the result, classifies a failure, terminates at a fatal site, keeps
/// the event loop alive for serving starts and lets it go once the last delivered completion left the runtime idle.
pub fn run(runtime: *Runtime, actions: []const Action, demand: *const Demand, now: u64, host: anytype) !@TypeOf(host.*).Result {
    var selection: Selection = .{ .wake = actions.len > 0 };
    runtime.lock();
    runtime.readiness.armed = false;
    const marks = gossipMarks(runtime);
    applyLocked(runtime, actions, now);
    if (demand.capacity) |capacity| runtime.capacity = capacity;
    runtime.refreshLocked();
    selectLocked(runtime, demand, now, &selection);
    // Ignored claims leave verdicts to apply, and a classification can move the owner's deadline.
    if (!std.meta.eql(marks, gossipMarks(runtime))) selection.wake = true;
    runtime.unlock();
    // The owner quiesced and releases nothing more, so its thread ends without the mutex.
    if (selection.closed != null) runtime.join();
    const output = host.build(&selection) catch |err| {
        const failure = host.classify(err);
        runtime.lock();
        restoreLocked(runtime, &selection);
        _ = endLocked(runtime, demand, &selection);
        runtime.unlock();
        return fail(host, failure, .exchange_build, err);
    };
    runtime.lock();
    const keep_alive = commitLocked(runtime, &selection);
    // Settlement found the runtime busy while these operations were still admitted or pulled.
    const idle = selection.publication_count + selection.command_count + selection.request_count + selection.incoming_count > 0 and runtime.idleLocked();
    const outcome = endLocked(runtime, demand, &selection);
    runtime.unlock();
    // Each admitted operation held the runtime until its final completion was delivered.
    for (0..selection.publication_count + selection.command_count + selection.requests_retired) |_| runtime.release();
    // Delivered, the close leaves environment cleanup nothing to do.
    if (selection.closed != null) runtime.removeHook();
    if (keep_alive) host.keepAlive();
    if (idle) host.idle();
    return host.finish(output, outcome) catch |err| return fail(host, host.classify(err), .exchange_finish, err);
}

/// A stopped environment returns the error, for the caller's local shutdown; a contract failure terminates at `site`.
fn fail(host: anytype, failure: Failure, site: fatal.Site, err: anyerror) anyerror {
    return switch (failure) {
        .stopped => err,
        .contract => host.terminate(site, err),
    };
}

test {
    _ = @import("network_exchange_test.zig");
}
