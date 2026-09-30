//! One demand-driven walk and DiscV5 liveness probes share a borrowed Transport. Keep the
//! Transport at a stable address, serialize entry, and cancel before its teardown.
const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");
const types = @import("types.zig");

pub const Error = d.Transport.Error || d.Maintenance.Error || d.Lookup.Error || adapter.Error || std.mem.Allocator.Error || error{ Stopped, InvalidOptions, InvalidDemand, InvalidBootstrap, TooManyBootstraps };
pub const queries_max = 128;
pub const Rejection = enum { missing_eth2, incompatible_fork, invalid_enr, no_quic, endpoint_family, endpoint_scope, demand, output_capacity };
pub const rejection_count = @typeInfo(Rejection).@"enum".fields.len;
pub const datagram_rejection_count = @typeInfo(d.types.RejectReason).@"enum".fields.len;
/// Foreground lookups started, and candidates handed to peer selection, which also marks a
/// lookup that found nothing.
pub const Counters = struct {
    lookups_started: u64 = 0,
    candidates_published: u64 = 0,
};
pub const Options = struct {
    quic_mode: d.types.Mode = .dual,
    query_interval_ms: u64 = 1_000,
    local_retry_ms: u64 = 1_000,
    maintenance: d.Maintenance.Config = .{},
    observations: [2]d.AddressVotes.Policy = .{ .{}, .{} },
};
pub const Demand = struct {
    general: bool = false,
    attnets: [8]u8 = @splat(0),
    syncnets: u8 = 0,
    custody: bool = false,
    expires_ms: u64 = std.math.maxInt(u64),

    fn active(self: *const Demand, now_ms: u64) bool {
        return now_ms < self.expires_ms and (self.general or self.custody or self.syncnets != 0 or !std.mem.allEqual(u8, &self.attnets, 0));
    }
    fn matches(self: *const Demand, candidate: *const adapter.Candidate, context: *const types.ForkContext) bool {
        if (self.general or (self.custody and (candidate.custody_group_count != null or context.custody_requirement > 0))) return true;
        if (candidate.syncnets) |bits| if (bits & self.syncnets != 0) return true;
        if (candidate.attnets) |bits| {
            for (bits, self.attnets) |actual, wanted| if (actual & wanted != 0) return true;
        }
        return false;
    }
};
pub const Result = struct {
    learned: [2]?d.types.Address = .{ null, null },
    candidates: usize = 0,
    started: u8 = 0,
    expired: u16 = 0,
    rejected: u16 = 0,
    dropped: u16 = 0,
    unowned: u16 = 0,
    /// Datagrams dequeued from the sockets, admitted or not. One step dequeues at most one.
    datagrams: u16 = 0,
    failure: ?Error = null,
    failure_stage: d.Transport.FailureStage = .coordinator,

    /// Sums the progress of consecutive steps. The latest learned address of each family and
    /// the first failure are kept.
    pub fn add(self: *Result, next: *const Result) void {
        for (&self.learned, next.learned) |*kept, learned| {
            if (learned) |address| kept.* = address;
        }
        self.candidates +|= next.candidates;
        self.started +|= next.started;
        self.expired +|= next.expired;
        self.rejected +|= next.rejected;
        self.dropped +|= next.dropped;
        self.unowned +|= next.unowned;
        self.datagrams +|= next.datagrams;
        if (self.failure == null and next.failure != null) {
            self.failure = next.failure;
            self.failure_stage = next.failure_stage;
        }
    }
};
const Storage = struct {
    observations: d.AddressVotes,
    candidates: d.Lookup.Candidates,
    expiries: [d.CallTable.capacity_max]d.CallTable.Expired,
};

pub const Discovery = struct {
    allocator: std.mem.Allocator,
    transport: *d.Transport,
    storage: *Storage,
    maintenance: d.Maintenance,
    lookup: ?d.Lookup = null,
    context: types.ForkContext,
    options: Options,
    demand: Demand = .{},
    query_due_ms: u64,
    refill_due_ms: u64 = 0,
    resource_retry_ms: u64 = 0,
    lookup_finishes: [@typeInfo(d.Lookup.FinishReason).@"enum".fields.len]u64 = @splat(0),
    stopped: bool = false,
    counters: Counters = .{},
    rejections: [rejection_count]u64 = @splat(0),
    datagram_rejections: [datagram_rejection_count]u64 = @splat(0),
    lookup_started_ms: u64 = 0,
    lookup_published: u64 = 0,
    empty_lookups: u3 = 0,

    pub fn init(allocator: std.mem.Allocator, transport: *d.Transport, context: *const types.ForkContext, bootstrap: []const d.identity.enr.Record, now_ms: u64, options: Options) Error!Discovery {
        try context.validate();
        if (options.query_interval_ms == 0 or options.query_interval_ms > 86_400_000 or options.local_retry_ms == 0 or options.local_retry_ms > 86_400_000) return error.InvalidOptions;
        if (bootstrap.len > d.types.bootstrap_max) return error.TooManyBootstraps;
        var records: [d.types.bootstrap_max]d.identity.enr.Record = undefined;
        for (bootstrap, records[0..bootstrap.len]) |*record, *copy| {
            copy.* = try d.identity.enr.Record.init(record.slice());
            if (copy.endpoint() == null) return error.InvalidBootstrap;
        }
        var maintenance: d.Maintenance = undefined;
        try maintenance.init(now_ms, options.maintenance, transport.sockets.mode());
        const storage = try allocator.create(Storage);
        errdefer allocator.destroy(storage);
        storage.observations.init(options.observations);
        maintenance.observations = &storage.observations;

        for (records[0..bootstrap.len]) |*record| {
            const address = record.endpointFor(transport.sockets.mode()) orelse continue;
            const peer: d.types.Endpoint = .{ .node_id = record.node_id, .address = address };
            _ = transport.engine.routing.addKnown(&peer, record) catch |err| switch (err) {
                error.AddressLimit, error.SelfEntry => continue,
                else => unreachable,
            };
        }
        return .{ .allocator = allocator, .transport = transport, .storage = storage, .maintenance = maintenance, .context = context.*, .options = options, .query_due_ms = now_ms };
    }

    pub fn deinit(self: *Discovery) void {
        self.cancel();
        self.allocator.destroy(self.storage);
        self.* = undefined;
    }

    pub fn request(self: *Discovery, demand: Demand, now_ms: u64) Error!void {
        if (self.stopped) return error.Stopped;
        if (demand.syncnets & 0xf0 != 0 or demand.expires_ms < now_ms) return error.InvalidDemand;
        self.demand = demand;
        self.expireForeground(now_ms);
    }

    pub fn updateFork(self: *Discovery, context: *const types.ForkContext) Error!void {
        if (self.stopped) return error.Stopped;
        try context.validate();
        if (!std.mem.eql(u8, &self.context.digest, &context.digest)) self.cancelForeground();
        self.context = context.*;
    }

    pub fn nextWakeup(self: *const Discovery, now_ms: u64) ?u64 {
        if (self.stopped) return null;
        var next = self.transport.engine.nextDeadlineMs() orelse std.math.maxInt(u64);
        if (self.maintenance.nextDeadlineMs(&self.transport.engine)) |deadline| next = @min(next, @max(deadline, self.resource_retry_ms));
        if (self.lookup) |*lookup| {
            if (lookup.waitingCount() < d.Lookup.parallelism) next = @min(next, @max(self.refill_due_ms, self.resource_retry_ms));
        } else if (self.demand.active(now_ms)) next = @min(next, @max(self.query_due_ms, self.resource_retry_ms));
        if (self.demand.active(now_ms)) next = @min(next, self.demand.expires_ms);
        return @max(now_ms, next);
    }

    /// Runs one Transport step, then consumes all borrowed progress before exposing a local fault.
    /// The caller's monotonic time must use the same domain as the Transport's host I/O clock.
    pub fn step(self: *Discovery, io: std.Io, now_ms: u64, wake_ms: u64, out: []adapter.Candidate) Error!Result {
        return self.stepWithReadiness(io, now_ms, wake_ms, null, out);
    }

    pub fn stepReady(self: *Discovery, io: std.Io, now_ms: u64, ready: *[2]bool, out: []adapter.Candidate) Error!Result {
        return self.stepWithReadiness(io, now_ms, now_ms, ready, out);
    }

    fn stepWithReadiness(self: *Discovery, io: std.Io, now_ms: u64, wake_ms: u64, ready: ?*[2]bool, out: []adapter.Candidate) Error!Result {
        if (self.stopped) return error.Stopped;
        var result = Result{};
        self.refill(io, now_ms, &result) catch |err| {
            result.failure = err;
            self.resource_retry_ms = now_ms +| self.options.local_retry_ms;
        };
        const progress = if (ready) |eligible|
            try self.transport.stepReady(io, &self.storage.expiries, eligible)
        else
            try self.transport.stepUntil(io, &self.storage.expiries, @min(wake_ms, self.nextWakeup(now_ms).?));
        var consumed = self.consume(&progress, self.storage.expiries[0..progress.calls_expired], out);
        if (progress.event == .request and progress.event.request.message == .talk_request) {
            const incoming = progress.event.request;
            const response: d.wire.message.Message = .{ .talk_response = .{
                .request_id = incoming.message.talk_request.request_id,
                .response = &.{},
            } };
            self.transport.sendResponse(io, incoming.peer, &response) catch |err| {
                if (err != error.DestinationUnreachable and consumed.failure == null) {
                    consumed.failure = err;
                    consumed.failure_stage = .process;
                }
            };
        }
        return .{ .learned = consumed.learned, .candidates = consumed.candidates, .started = result.started, .expired = consumed.expired, .rejected = consumed.rejected, .dropped = consumed.dropped, .unowned = consumed.unowned, .datagrams = consumed.datagrams, .failure = result.failure orelse consumed.failure, .failure_stage = if (result.failure != null) .coordinator else consumed.failure_stage };
    }

    /// Supports hosts that drive the borrowed Transport themselves. Consume every result exactly
    /// once before another Transport step, including results containing failure. The host answers
    /// TALK requests itself; step supplies the unsupported-protocol response. No slice escapes.
    pub fn consume(self: *Discovery, progress: *const d.Transport.StepResult, expiries: []const d.CallTable.Expired, out: []adapter.Candidate) Result {
        std.debug.assert(expiries.len == progress.calls_expired and expiries.len <= d.CallTable.capacity_max);
        var result = Result{ .datagrams = @intFromBool(progress.datagram != .timeout), .failure = progress.failure, .failure_stage = progress.failure_stage };
        if (self.stopped) return result;
        switch (progress.datagram) {
            .timeout, .accepted => {},
            .rejected => |reason| self.datagram_rejections[@intFromEnum(reason)] +|= 1,
        }
        for (expiries) |expired| {
            if (self.lookupForCall(expired.handle)) |lookup| {
                lookup.onFailure(&self.transport.engine, expired.handle) catch unreachable;
                result.expired += 1;
            } else if (self.maintenance.onFailure(&self.transport.engine, expired.handle, progress.now_ms, .expired)) {
                result.expired += 1;
            } else result.unowned += 1;
        }
        if (progress.event == .response) {
            const response = &progress.event.response;
            if (response.matched.response == .pong) {
                if (self.storage.observations.observe(&response.peer, &response.matched.response.pong, progress.now_ms)) |address| {
                    result.learned[if (address == .ip4) @as(usize, 0) else 1] = address;
                }
            }
        }
        self.consumeEvent(progress, out, &result);
        if (self.lookup) |*lookup| if (lookup.isFinished()) {
            self.lookup_finishes[@intFromEnum(lookup.finishReason().?)] +|= 1;
            std.log.scoped(.network_discovery).debug("lookup_completed reason={s} queried={d} candidates={d} published={d} elapsed_ms={d}", .{ @tagName(lookup.finishReason().?), lookup.queries_started, lookup.candidateCount(), self.counters.candidates_published -| self.lookup_published, progress.now_ms -| self.lookup_started_ms });
            self.lookup = null;
            self.empty_lookups = if (self.counters.candidates_published == self.lookup_published) @min(self.empty_lookups +| 1, 6) else 0;
            const delay = self.options.query_interval_ms *| (@as(u64, 1) << self.empty_lookups);
            self.query_due_ms = progress.now_ms +| delay;
        };
        return result;
    }

    pub fn cancel(self: *Discovery) void {
        if (self.stopped) return;
        self.cancelForeground();
        self.maintenance.cancel(&self.transport.engine);
        self.demand = .{};
        self.stopped = true;
    }

    fn refill(self: *Discovery, io: std.Io, now_ms: u64, result: *Result) Error!void {
        self.expireForeground(now_ms);
        if (now_ms < self.resource_retry_ms) return;
        if (self.lookup == null and self.demand.active(now_ms) and now_ms >= self.query_due_ms) {
            self.query_due_ms = now_ms +| self.options.query_interval_ms;
            var target: d.types.NodeId = undefined;
            try std.Io.randomSecure(io, &target);
            var seeds: [d.Lookup.result_max]d.RoutingTable.Entry = undefined;
            const closest = self.transport.engine.closestNodes(&target, &seeds);
            var lookup: d.Lookup = undefined;
            try lookup.init(&self.storage.candidates, self.transport.engine.localRecord().node_id, target, closest, self.transport.sockets.mode());
            lookup.filter = .{ .context = &self.context, .matches = matchesNetwork };
            lookup.query_limit = queries_max;
            self.lookup = lookup;
            self.lookup_started_ms = now_ms;
            self.lookup_published = self.counters.candidates_published;
            self.counters.lookups_started +|= 1;
            std.log.scoped(.network_discovery).debug("lookup_started target={x} seeds={d}", .{ target, closest.len });
        }
        if (self.maintenance.nextDeadlineMs(&self.transport.engine)) |deadline| if (now_ms >= deadline) {
            try self.start(io, now_ms, true, result);
        };
        if (self.lookup == null or now_ms < self.refill_due_ms) return;
        self.refill_due_ms = now_ms +| self.options.local_retry_ms;
        for (0..d.Lookup.parallelism) |_| {
            const before = result.started;
            try self.start(io, now_ms, false, result);
            if (before == result.started) break;
        }
    }

    fn expireForeground(self: *Discovery, now_ms: u64) void {
        if (!self.demand.active(now_ms)) self.cancelForeground();
    }

    fn cancelForeground(self: *Discovery) void {
        if (self.lookup) |*lookup| lookup.cancel(&self.transport.engine);
        self.lookup = null;
    }

    fn start(self: *Discovery, io: std.Io, now_ms: u64, background: bool, result: *Result) Error!void {
        const started = (if (background) d.lookup_io.startMaintenance(self.transport, io, &self.maintenance, now_ms) else d.lookup_io.startLookup(self.transport, io, &self.lookup.?, now_ms)) catch |err| switch (err) {
            error.TableFull, error.PeerBusy => return,
            else => return err,
        };
        if (started.started) result.started += 1;
        // lookup_io released the refused call and reported a local failure to its owner, so the
        // refusal fails only its destination and the step goes on.
        if (started.failure) |err| if (err != error.DestinationUnreachable) return err;
    }

    fn lookupForCall(self: *Discovery, handle: d.CallTable.Handle) ?*d.Lookup {
        const lookup = if (self.lookup) |*active| active else return null;
        return if (lookup.ownsCall(handle)) lookup else null;
    }

    fn consumeEvent(self: *Discovery, progress: *const d.Transport.StepResult, out: []adapter.Candidate, result: *Result) void {
        const handle = switch (progress.event) {
            .response => |response| response.matched.handle,
            .failed => |failed| failed.handle,
            else => return,
        };
        if (self.lookupForCall(handle)) |lookup| {
            switch (progress.event) {
                .response => |*response| {
                    const known = lookup.knownRecord(handle).?.*;
                    lookup.onResponse(&self.transport.engine, response, progress.now_ms) catch |err| {
                        lookup.onFailure(&self.transport.engine, handle) catch unreachable;
                        result.failure = result.failure orelse err;
                        return;
                    };
                    if (response.matched.terminal) self.publishResponse(response, &known, progress.now_ms, out, result);
                    self.publishReferrals(response, progress.now_ms, out, result);
                },
                .failed => lookup.onFailure(&self.transport.engine, handle) catch unreachable,
                else => unreachable,
            }
            self.refill_due_ms = progress.now_ms;
            return;
        }
        const known: ?d.identity.enr.Record = if (self.maintenance.knownRecord(handle)) |record| record.* else null;
        const consumed = self.maintenance.onEvent(&self.transport.engine, &progress.event, progress.now_ms) catch |err| {
            _ = self.maintenance.onFailure(&self.transport.engine, handle, progress.now_ms, .local);
            result.failure = result.failure orelse err;
            return;
        };
        if (!consumed) {
            result.unowned += 1;
            return;
        }
        if (progress.event == .response) {
            const response = &progress.event.response;
            if (response.matched.terminal) if (known) |*record| self.publishResponse(response, record, progress.now_ms, out, result);
            self.publishReferrals(response, progress.now_ms, out, result);
        }
    }

    fn publishReferrals(self: *Discovery, response: *const d.Engine.AuthenticatedResponse, now_ms: u64, out: []adapter.Candidate, result: *Result) void {
        std.debug.assert(response.node_records.len <= d.types.findnode_result_max);
        for (response.node_records) |*record| {
            if (std.mem.eql(u8, &record.node_id, &response.peer.node_id) or
                std.mem.eql(u8, &record.node_id, &self.transport.engine.localRecord().node_id)) continue;
            self.publish(record, response.peer.address, now_ms, out, result);
        }
    }

    fn publishResponse(self: *Discovery, response: *const d.Engine.AuthenticatedResponse, known: *const d.identity.enr.Record, now_ms: u64, out: []adapter.Candidate, result: *Result) void {
        std.debug.assert(response.matched.terminal);
        std.debug.assert(std.mem.eql(u8, &known.node_id, &response.peer.node_id));
        var record = known.*;
        if (response.record) |*updated| if (updated.sequence > record.sequence and std.mem.eql(u8, &updated.node_id, &response.peer.node_id)) {
            record = updated.*;
        };
        std.debug.assert(response.node_records.len <= d.types.findnode_result_max);
        for (response.node_records) |*updated| {
            if (updated.sequence > record.sequence and std.mem.eql(u8, &updated.node_id, &response.peer.node_id)) record = updated.*;
        }
        self.publish(&record, response.peer.address, now_ms, out, result);
    }

    fn rejected(self: *Discovery, reason: Rejection, result: *Result) void {
        self.rejections[@intFromEnum(reason)] +|= 1;
        result.rejected +|= 1;
    }

    fn publish(self: *Discovery, record: *const d.identity.enr.Record, source: d.types.Address, now_ms: u64, out: []adapter.Candidate, result: *Result) void {
        if (!self.demand.active(now_ms)) return;
        var candidate = adapter.decode(record, &self.context) catch |err| {
            self.rejected(switch (err) {
                error.MissingEth2 => .missing_eth2,
                error.IncompatibleFork => .incompatible_fork,
                else => .invalid_enr,
            }, result);
            return;
        };
        if (candidate.address_count == 0) {
            self.rejected(.no_quic, result);
            return;
        }
        var count: u8 = 0;
        var supported: u8 = 0;
        for (candidate.addresses[0..candidate.address_count]) |address| {
            if (!self.options.quic_mode.supports(address)) continue;
            supported += 1;
            if (!relayAllowed(source, address)) continue;
            candidate.addresses[count] = address;
            count += 1;
        }
        candidate.address_count = count;
        @memset(candidate.addresses[count..], .unspecified);
        if (count == 0) {
            self.rejected(if (supported == 0) .endpoint_family else .endpoint_scope, result);
            return;
        }
        if (!self.demand.matches(&candidate, &self.context)) {
            self.rejected(.demand, result);
            return;
        }
        if (result.candidates == out.len) {
            result.dropped += 1;
            self.rejections[@intFromEnum(Rejection.output_capacity)] +|= 1;
            return;
        }
        out[result.candidates] = candidate;
        result.candidates += 1;
        self.counters.candidates_published +|= 1;
    }
};

fn matchesNetwork(context_opaque: *const anyopaque, record: *const d.identity.enr.Record) bool {
    const context: *const types.ForkContext = @ptrCast(@alignCast(context_opaque));
    const eth2 = (record.fieldBytes("eth2") catch return false) orelse return false;
    if (eth2.len != 16 or !std.mem.eql(u8, eth2[0..4], &context.digest)) return false;
    return (record.fieldBytes("quic") catch return false) != null or (record.fieldBytes("quic6") catch return false) != null;
}

pub fn relayAllowed(source: d.types.Address, candidate: types.Address) bool {
    if (candidate.port() < d.Lookup.discovered_port_min) return false;
    const address: d.types.Address = switch (candidate) {
        .ip4 => |value| .{ .ip4 = .{ .octets = value.octets, .port = value.port } },
        .ip6 => |value| blk: {
            if (value.octets[0] == 0xfe and value.octets[1] & 0xc0 == 0x80) return false;
            break :blk .{ .ip6 = .{ .octets = value.octets, .port = value.port } };
        },
    };
    return d.RoutingTable.relayAllowed(source, address);
}

test {
    _ = @import("discovery_test.zig");
}
