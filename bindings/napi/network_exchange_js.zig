const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const cfg = @import("network_config.zig");
const app = @import("network_application_config.zig");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const g = @import("network_gossip.zig");
const incoming = @import("network_incoming.zig");
const projection = @import("network_peer_projection.zig");
const publications = @import("network_publications.zig");
const fatal = @import("network_fatal.zig");
const exchange_mod = @import("network_exchange.zig");
const Demand = exchange_mod.Demand;
const Action = exchange_mod.Action;
const Selection = exchange_mod.Selection;
const Outcome = exchange_mod.Outcome;
const Closed = exchange_mod.Closed;
const action_max = exchange_mod.action_max;
const peers_max = exchange_mod.peers_max;
const serving_max = exchange_mod.serving_max;
const settle_max = publications.capacity_max;
const bytes = @import("network_js.zig").bytes;

pub fn parseDemand(value: Value) !Demand {
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

fn object(value: Value) !Value {
    if (try value.typeof() != .object or try value.isArray()) return error.InvalidNetworkConfig;
    return value;
}

const ActionType = enum { verdict, classify, block, recheck, dropQueued, reportPeer };

pub fn parseActions(value: Value, into: *[action_max]Action) !usize {
    if (!try value.isArray()) return error.InvalidNetworkActions;
    const count = try value.getArrayLength();
    if (count > action_max) return error.InvalidNetworkActions;
    for (into[0..count], 0..) |*action, i| action.* = try parseAction(try value.getElement(@intCast(i)));
    return count;
}

pub fn parseAction(value: Value) !Action {
    _ = object(value) catch return error.InvalidNetworkAction;
    return switch (try name(ActionType, try cfg.get(value, "type"), error.InvalidNetworkAction)) {
        .verdict => .{ .verdict = .{
            .token = try handle(try cfg.get(value, "handle")),
            .verdict = try name(n.gossipsub.Gossipsub.Verdict, try cfg.get(value, "verdict"), error.InvalidGossipVerdict),
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
    const index = try cfg.integer(try cfg.get(value, "index"), n.gossip_processor.limits.capacity_max - 1);
    const generation = try cfg.bigint(try cfg.get(value, "generation"));
    if (generation == 0) return error.InvalidGossipHandle;
    return .{ .index = @intCast(index), .generation = generation };
}

fn reportCount(value: Value) !u8 {
    const result = try cfg.integer(value, @import("network_peer_reports.zig").report_max);
    if (result == 0) return error.InvalidNetworkInteger;
    return @intCast(result);
}

/// The N-API side of an exchange: the result's JS values.
pub const Host = struct {
    env: napi.Env,
    runtime: *Runtime,

    pub const Result = Value;

    /// A fresh result, or null when there is nothing to deliver and a prepared one serves.
    pub fn build(self: *Host, selection: *exchange_mod.Selection) !?Value {
        if (!selection.delivers()) return null;
        return try buildResult(self.env, self.runtime, selection);
    }
    pub fn finish(self: *Host, output: ?Value, outcome: exchange_mod.Outcome) !Value {
        return finishResult(self.env, self.runtime, output, outcome);
    }
    pub fn keepAlive(self: *Host) void {
        self.runtime.notify.ref(self.env) catch {};
    }
    pub fn idle(self: *Host) void {
        self.runtime.notify.unref(self.env) catch {};
    }
    /// An exception that clears means the bridge broke its contract. One that will not clear means JavaScript cannot
    /// run, as does a pending-exception status with none pending, which N-API returns for cannot_run_js to this
    /// module version.
    pub fn classify(self: *Host, err: anyerror) exchange_mod.Failure {
        if (err == error.Closing or err == error.CannotRunJS) return .stopped;
        const pending = self.env.isExceptionPending() catch return .stopped;
        if (!pending) return if (err == error.PendingException) .stopped else .contract;
        _ = self.env.getAndClearLastException() catch return .stopped;
        return .contract;
    }
    pub fn terminate(self: *Host, site: fatal.Site, err: anyerror) noreturn {
        fatal.terminate(self.env, site, @errorName(err));
    }
};

/// Results created once, one per combination of the scheduling fields, so an exchange that delivers nothing
/// allocates nothing.
pub const Results = struct {
    idle: [16]?napi.Ref = @splat(null),

    pub fn prepare(self: *Results, env: napi.Env) !void {
        const empty = try env.createArrayWithLength(0);
        try empty.objectFreeze();
        for (&self.idle, 0..) |*slot, i| {
            const result = try env.createObject();
            inline for (.{ "peers", "serving", "checks", "acknowledged", "completions" }) |field| try result.setNamedProperty(field, empty);
            try result.setNamedProperty("gossip", try env.getNull());
            try result.setNamedProperty("failure", try env.getNull());
            try result.setNamedProperty("closed", try env.getNull());
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

/// Builds a fresh result for a selection that delivers something.
fn buildResult(env: napi.Env, runtime: *Runtime, selection: *Selection) !Value {
    const result = try env.createObject();
    const peers = try env.createArrayWithLength(selection.peer_count);
    for (selection.peers[0..selection.peer_count], 0..) |*entry, i| try peers.setElement(@intCast(i), try projection.observation(env, entry));
    try result.setNamedProperty("peers", peers);
    const serving = try env.createArrayWithLength(selection.serving_count);
    for (selection.serving[0..selection.serving_count], 0..) |token, i| {
        const cell = &runtime.incoming.?.cells[token.index];
        try serving.setElement(@intCast(i), try @import("network_incoming_js.zig").descriptorValue(runtime, token, cell));
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
    try result.setNamedProperty("gossip", if (selection.gossip) |*batch| try jobs(env, runtime, batch) else try env.getNull());
    const acknowledged = try env.createArrayWithLength(selection.acknowledged_count);
    for (selection.acknowledged[0..selection.acknowledged_count], 0..) |token, i| {
        const reference = try env.createObject();
        try reference.setNamedProperty("index", try env.createUint32(token.index));
        try reference.setNamedProperty("generation", try env.createBigintUint64(token.generation));
        try acknowledged.setElement(@intCast(i), reference);
    }
    try result.setNamedProperty("acknowledged", acknowledged);
    const completions = try env.createArrayWithLength(@intCast(selection.publication_count + selection.command_count + selection.request_count + selection.incoming_count));
    for (selection.publications[0..selection.publication_count], 0..) |token, i| {
        try completions.setElement(@intCast(i), try @import("network_publication_js.zig").completion(env, token, runtime.publications.?.get(token).?));
    }
    for (selection.commands[0..selection.command_count], selection.publication_count..) |token, i| {
        try completions.setElement(@intCast(i), try @import("network_command_js.zig").completion(env, runtime, token));
    }
    for (selection.requests[0..selection.request_count], selection.publication_count + selection.command_count..) |completion, i| {
        try completions.setElement(@intCast(i), try @import("network_request_js.zig").completion(env, runtime, completion));
    }
    for (selection.incoming[0..selection.incoming_count], selection.publication_count + selection.command_count + selection.request_count..) |completion, i| {
        try completions.setElement(@intCast(i), try @import("network_incoming_js.zig").completion(env, completion));
    }
    try result.setNamedProperty("completions", completions);
    try result.setNamedProperty("failure", try env.getNull());
    try result.setNamedProperty("closed", if (selection.closed) |closed| try closedValue(env, closed) else try env.getNull());
    return result;
}

/// `{reason: "requested"}`, or `{reason: "failed", error}` with the first failure's code.
fn closedValue(env: napi.Env, closed: Closed) !Value {
    const value = try env.createObject();
    try value.setNamedProperty("reason", try env.createStringUtf8(@tagName(closed.reason)));
    if (closed.failure) |err| try value.setNamedProperty("error", try @import("network_js.zig").settled(env, @import("network_js.zig").errorValue(env, @errorName(err))));
    return value;
}

/// Sets a fresh result's scheduling fields, or returns the prepared result when nothing was built.
fn finishResult(env: napi.Env, runtime: *Runtime, output: ?Value, outcome: Outcome) !Value {
    const result = output orelse return runtime.results.idle[@as(u4, @bitCast(outcome))].?.getValue();
    try schedule(env, result, outcome);
    return result;
}

fn jobs(env: napi.Env, runtime: *Runtime, batch: *const g.Batch) !Value {
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
        try value.setNamedProperty("urgent", try env.getBoolean(n.gossip_processor.limits.urgent(job.kind)));
        try list.setElement(@intCast(i), value);
    }
    try result.setNamedProperty("jobs", list);
    return result;
}
