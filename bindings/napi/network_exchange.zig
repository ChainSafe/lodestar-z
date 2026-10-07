//! One host exchange. The JS adapter decodes actions and demand before entering this module. Phase B, under the
//! mutex, disarms, applies the actions, takes the capacities and pins the completions and payloads it serves, or takes the
//! close result once the owner quiesced and nothing else is due. Phase C joins the owner for a close and builds the
//! result; no user code runs from here on. Phase D, under the mutex, commits (or restores the pins when JavaScript
//! stopped), wakes the owner once and arms when no deliverable work remains.
const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const publications = @import("network_publications.zig");
const commands = @import("network_commands.zig");
const requests = @import("network_requests.zig");
const fatal = @import("network_fatal.zig");
const Runtime = r.Runtime;

/// Actions one exchange applies; a longer batch is refused before any is applied.
pub const action_max = 256;
pub const peers_max = 32;
pub const serving_max = 8;
/// Owner dispositions one exchange acknowledges; more require another exchange.
pub const acknowledged_max = action_max;

pub const completion_max = 32;
pub const bytes_max = 8 * 1024 * 1024;

pub const Demand = union(enum) {
    control,
    delivery: struct {
        capacity: r.Capacity,
        serving_starts: u8,
        claim_non_urgent_gossip: bool,
    },
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
    /// Completed publications, taken whatever the demand up to the completion limit per family. Their cells stay copying
    /// until the commit retires them.
    publications: [completion_max]publications.Token = undefined,
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
pub const Outcome = struct { needs_another_exchange: bool = false };

/// How a failed build or finish ends: JavaScript that cannot run shuts the runtime down locally, and anything else
/// breaks the bridge contract and terminates the process. No allocation of ours can fail there.
pub const Failure = enum { stopped, contract };

fn applyLocked(runtime: *Runtime, actions: []const Action, now: u64) void {
    if (runtime.bridge.stop or runtime.bridge.quiescent) return;
    for (actions) |action| switch (action) {
        .report_peer => |report| runtime.bridge.reports.addCount(&report.identity, report.action, report.count),
        else => if (runtime.bridge.gossip) |*table| switch (action) {
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
    if (runtime.bridge.quiescent and !runtime.bridge.close_delivered and !runtime.completionsReadyLocked())
        selection.closed = .{ .reason = runtime.bridge.reason, .failure = if (runtime.bridge.reason == .failed) runtime.bridge.terminal_error.? else null };
    if (runtime.bridge.gossip) |*table| selection.acknowledged_count = table.acknowledgements(&selection.acknowledged);
    selectPublications(runtime, completion_max, selection);
    selectCommands(runtime, completion_max, selection);
    selectRequests(runtime, completion_max, selection);
    selectIncoming(runtime, completion_max, selection);
    // The close ends delivery: no payload handler runs in its exchange, and none waits for a later one.
    if (selection.closed != null) return;
    const delivery = switch (demand.*) {
        .control => return,
        .delivery => |value| value,
    };
    if (runtime.deliverableLocked(.peers)) selection.peer_count = runtime.bridge.peer_updates.?.peek(&selection.peers);
    if (runtime.deliverableLocked(.serving)) selectServing(runtime, delivery.serving_starts, selection);
    if (runtime.deliverableLocked(.checks)) {
        const table = &runtime.bridge.gossip.?;
        selection.checks = table.claimChecks(now, g.batch_max);
        for (selection.checks.tokens[0..selection.checks.len], selection.views[0..selection.checks.len]) |token, *view| {
            const cell = table.get(token).?;
            view.* = .{ .root = cell.metadata.root.?, .slot = cell.metadata.slot.?, .identity = cell.identity, .topic = cell.topic, .topic_len = cell.topic_len };
        }
    }
    if (runtime.deliverableLocked(.gossip)) {
        const claim = runtime.bridge.gossip.?.claimDemand(now, .{
            .items = g.batch_max,
            .bytes = bytes_max,
            .ordinary = delivery.claim_non_urgent_gossip and delivery.capacity.gossip_validation == .ready,
        });
        if (claim.len > 0) selection.gossip = claim;
    }
}

/// Pins up to `limit` completed publications, resuming past the last one delivered so refilled lower cells cannot
/// starve higher ones.
fn selectPublications(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.bridge.publications) |*table| table else return;
    for (0..limit) |_| {
        const i = table.nextTerminal(table.completion_cursor) orelse table.nextTerminal(0) orelse break;
        table.completion_cursor = i + 1;
        const cell = &table.cells[i];
        table.transition(cell, .copying);
        selection.publications[selection.publication_count] = .{ .index = @intCast(i), .generation = cell.generation };
        selection.publication_count += 1;
    }
}

/// Pins up to `limit` completed commands, resuming past the last one delivered.
fn selectCommands(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = &runtime.bridge.commands;
    for (0..@min(limit, commands.capacity)) |_| {
        const i = table.nextTerminal(table.completion_cursor) orelse table.nextTerminal(0) orelse break;
        table.completion_cursor = i + 1;
        table.transition(&table.cells[i], .copying);
        selection.commands[selection.command_count] = .{ .index = @intCast(i), .generation = table.cells[i].generation };
        selection.command_count += 1;
    }
}

/// Pins up to `limit` due requests, resuming past the last one delivered.
fn selectRequests(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.bridge.requests) |*table| table else return;
    for (0..@min(limit, requests.capacity_max)) |_| {
        const i = table.nextDue(table.completion_cursor, runtime.bridge.stop, runtime.bridge.quiescent) orelse table.nextDue(0, runtime.bridge.stop, runtime.bridge.quiescent) orelse break;
        table.completion_cursor = i + 1;
        selection.requests[selection.request_count] = table.pin(i, runtime.bridge.stop);
        selection.request_count += 1;
    }
}

/// Pins up to `limit` due incoming streams, resuming past the last one delivered.
fn selectIncoming(runtime: *Runtime, limit: usize, selection: *Selection) void {
    const table = if (runtime.bridge.incoming) |*table| table else return;
    for (0..@min(limit, incoming.capacity_max)) |_| {
        const i = table.nextDue(table.completion_cursor) orelse table.nextDue(0) orelse break;
        table.completion_cursor = i + 1;
        selection.incoming[selection.incoming_count] = table.pin(i);
        selection.incoming_count += 1;
    }
}

fn selectServing(runtime: *Runtime, serving_starts: u8, selection: *Selection) void {
    const table = &runtime.bridge.incoming.?;
    const limit = @min(serving_starts, runtime.bridge.capacity.?.incoming_request_slots);
    for (0..incoming.capacity_max) |_| {
        if (selection.serving_count == limit) break;
        const token = table.pinStart() orelse break;
        selection.serving[selection.serving_count] = token;
        selection.serving_count += 1;
    }
}

/// Returns whether serving starts now await closes that keep the event loop alive.
fn commitLocked(runtime: *Runtime, selection: *Selection) bool {
    if (selection.peer_count > 0) {
        runtime.bridge.peer_updates.?.commit(selection.peer_count);
        // Committed events free lane room the owner publishes into.
        selection.wake = true;
    }
    if (selection.serving_count > 0) {
        const table = &runtime.bridge.incoming.?;
        for (selection.serving[0..selection.serving_count]) |token| table.commitStart(token);
        runtime.bridge.capacity.?.incoming_request_slots -|= @intCast(selection.serving_count);
        selection.wake = true;
    }
    if (selection.publication_count > 0) {
        const table = &runtime.bridge.publications.?;
        for (selection.publications[0..selection.publication_count]) |token| table.retire(token);
        runtime.retireRequestStorageLocked();
    }
    if (selection.command_count > 0) {
        for (selection.commands[0..selection.command_count]) |token| runtime.bridge.commands.retire(token);
        runtime.retireStoresLocked();
    }
    if (selection.request_count > 0) {
        const table = &runtime.bridge.requests.?;
        for (selection.requests[0..selection.request_count]) |completion| selection.requests_retired += @intFromBool(table.commit(completion));
        runtime.retireRequestStorageLocked();
    }
    if (selection.incoming_count > 0) {
        const table = &runtime.bridge.incoming.?;
        // A released slot the host no longer awaits goes back to the owner.
        for (selection.incoming[0..selection.incoming_count]) |completion| if (table.commit(completion)) {
            selection.wake = true;
        };
        runtime.retireRequestStorageLocked();
    }
    // Close may have freed these cells meanwhile; a freed token is ignored. Not counted as delivered items.
    if (runtime.bridge.gossip) |*table| for (selection.acknowledged[0..selection.acknowledged_count]) |token| table.acknowledge(token);
    if (selection.gossip) |*batch| {
        runtime.bridge.gossip.?.finish(batch, true);
    }
    if (runtime.bridge.quiescent) if (runtime.bridge.gossip) |*table| table.trim();
    if (selection.closed != null) runtime.bridge.close_delivered = true;
    return selection.serving_count > 0 and runtime.bridge.notify_live;
}

/// Returns every pinned item to where it was, so teardown reclaims it.
fn restoreLocked(runtime: *Runtime, selection: *const Selection) void {
    if (selection.publication_count > 0) {
        const table = &runtime.bridge.publications.?;
        for (selection.publications[0..selection.publication_count]) |token| table.transition(table.get(token).?, .terminal);
    }
    for (selection.commands[0..selection.command_count]) |token| runtime.bridge.commands.transition(runtime.bridge.commands.get(token), .terminal);
    for (selection.requests[0..selection.request_count]) |completion| runtime.bridge.requests.?.restore(completion);
    for (selection.incoming[0..selection.incoming_count]) |completion| runtime.bridge.incoming.?.restore(completion);
    if (selection.serving_count > 0) {
        const table = &runtime.bridge.incoming.?;
        for (selection.serving[0..selection.serving_count]) |token| table.restoreStart(token);
    }
    if (selection.checks.len > 0) runtime.bridge.gossip.?.retryChecks(&selection.checks);
    if (selection.gossip) |*batch| runtime.bridge.gossip.?.finish(batch, false);
    if (runtime.bridge.quiescent) if (runtime.bridge.gossip) |*table| table.trim();
}

/// Check and arm under the mutex so publication cannot race rearming.
fn endLocked(runtime: *Runtime, selection: *const Selection) Outcome {
    if (selection.wake) runtime.wakeOwnerLocked();
    const pending = runtime.hasDeliveryLocked();
    runtime.bridge.notification_armed = !pending;
    return .{ .needs_another_exchange = pending };
}

fn gossipMarks(runtime: *Runtime) struct { bool, ?u64 } {
    const table = if (runtime.bridge.gossip) |*table| table else return .{ false, null };
    return .{ table.pending(true), table.deadline() };
}

/// Runs phases B to D. `host` builds and finishes the result, classifies a failure, terminates at a fatal site, keeps
/// the event loop alive for serving starts and lets it go once the last delivered completion left the runtime idle.
pub fn run(runtime: *Runtime, actions: []const Action, demand: *const Demand, now: u64, host: anytype) !@TypeOf(host.*).Result {
    var selection: Selection = .{ .wake = actions.len > 0 };
    runtime.lock();
    runtime.bridge.notification_armed = false;
    const marks = gossipMarks(runtime);
    applyLocked(runtime, actions, now);
    runtime.bridge.capacity = switch (demand.*) {
        .control => null,
        .delivery => |delivery| delivery.capacity,
    };
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
        _ = endLocked(runtime, &selection);
        runtime.unlock();
        return fail(host, failure, .exchange_build, err);
    };
    runtime.lock();
    const keep_alive = commitLocked(runtime, &selection);
    // Settlement found the runtime busy while these operations were still admitted or pulled.
    const idle = selection.publication_count + selection.command_count + selection.request_count + selection.incoming_count > 0 and runtime.idleLocked();
    const outcome = endLocked(runtime, &selection);
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
