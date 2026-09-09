//! One foreground walk and canonical DiscV5 maintenance share a borrowed Driver. Keep the
//! Driver, Engine and UDP at stable addresses, serialize entry, and cancel before their teardown.
const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");
const types = @import("types.zig");

pub const Error = d.Driver.Error || d.Maintenance.Error || adapter.Error || std.mem.Allocator.Error || error{ Stopped, InvalidOptions, InvalidDemand };
pub const queries_max = 128;
pub const Rejection = enum { missing_eth2, incompatible_fork, invalid_enr, no_quic, endpoint_scope, demand, output_capacity };
pub const rejection_count = @typeInfo(Rejection).@"enum".fields.len;
pub const Counters = struct {
    lookups_started: u64 = 0,
    lookups_completed: u64 = 0,
    queries_started: u64 = 0,
    authenticated_candidates: u64 = 0,
    authenticated_not_retained: u64 = 0,
    candidates_published: u64 = 0,
    query_timeouts: u64 = 0,
    query_failures: u64 = 0,
    maintenance_failures: u64 = 0,
    receive_failures: u64 = 0,
    processing_failures: u64 = 0,
    coordinator_failures: u64 = 0,
};
pub const LookupTime = @import("../metrics_histogram.zig").Histogram(&.{ 1000, 5000, 10000, 30000, 60000, 120000 });
pub const Options = struct {
    query_interval_ms: u64 = 1_000,
    local_retry_ms: u64 = 1_000,
    maintenance: d.Maintenance.Config = .{},
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
    fn matches(self: *const Demand, candidate: *const adapter.Candidate) bool {
        if (self.general or (self.custody and candidate.custody_group_count != null)) return true;
        if (candidate.syncnets) |bits| if (bits & self.syncnets != 0) return true;
        if (candidate.attnets) |bits| {
            for (bits, self.attnets) |actual, wanted| if (actual & wanted != 0) return true;
        }
        return false;
    }
};
pub const Result = struct {
    candidates: usize = 0,
    started: u8 = 0,
    expired: u16 = 0,
    rejected: u16 = 0,
    dropped: u16 = 0,
    unowned: u16 = 0,
    failure: ?Error = null,
    failure_stage: d.Driver.FailureStage = .coordinator,
};
pub const MemoryPlan = struct {
    inline_bytes: usize,
    allocated_bytes: usize,
    lookup_candidates: usize,
    expiry_slots: usize,
    bootstrap_slots: usize,
    result_records: usize,
};
const Storage = struct {
    foreground: d.Lookup.Candidates,
    background: d.Lookup.Candidates,
    bootstrap: [d.Maintenance.bootstrap_max]d.identity.enr.Record,
    expiries: [d.CallTable.capacity_max]d.CallTable.Expired,
    records: [d.Lookup.result_max]d.Lookup.Confirmed,
};

pub const Discovery = struct {
    allocator: std.mem.Allocator,
    driver: *d.Driver,
    storage: *Storage,
    maintenance: d.Maintenance,
    lookup: d.Lookup = undefined,
    lookup_active: bool = false,
    context: types.ForkContext,
    options: Options,
    demand: Demand = .{},
    query_due_ms: u64,
    refill_due_ms: u64 = 0,
    resource_retry_ms: u64 = 0,
    lookup_time: LookupTime = .{},
    lookup_finishes: [@typeInfo(d.Lookup.FinishReason).@"enum".fields.len]u64 = @splat(0),
    last_candidate_ms: ?u64 = null,
    stopped: bool = false,
    counters: Counters = .{},
    rejections: [rejection_count]u64 = @splat(0),
    lookup_started_ms: u64 = 0,
    lookup_published: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, driver: *d.Driver, context: *const types.ForkContext, bootstrap: []const d.identity.enr.Record, now_ms: u64, options: Options) Error!Discovery {
        try context.validate();
        if (options.query_interval_ms == 0 or options.query_interval_ms > 86_400_000 or options.local_retry_ms == 0 or options.local_retry_ms > 86_400_000) return error.InvalidOptions;
        if (bootstrap.len > d.Maintenance.bootstrap_max) return error.TooManyBootstraps;
        const storage = try allocator.create(Storage);
        errdefer allocator.destroy(storage);

        for (bootstrap, 0..) |*record, index| storage.bootstrap[index] = try d.identity.enr.Record.init(record.slice());
        var maintenance: d.Maintenance = undefined;
        try maintenance.init(&storage.background, storage.bootstrap[0..bootstrap.len], now_ms, options.maintenance);
        return .{ .allocator = allocator, .driver = driver, .storage = storage, .maintenance = maintenance, .context = context.*, .options = options, .query_due_ms = now_ms };
    }

    pub fn deinit(self: *Discovery) void {
        self.cancel();
        self.allocator.destroy(self.storage);
        self.* = undefined;
    }

    pub fn memoryPlan(_: *const Discovery) MemoryPlan {
        return .{ .inline_bytes = @sizeOf(Discovery), .allocated_bytes = @sizeOf(Storage), .lookup_candidates = 2 * d.Lookup.candidate_capacity, .expiry_slots = d.CallTable.capacity_max, .bootstrap_slots = d.Maintenance.bootstrap_max, .result_records = d.Lookup.result_max };
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
        if (!std.mem.eql(u8, &self.context.digest, &context.digest) and self.lookup_active) {
            self.lookup.cancel(self.driver.core);
            self.lookup_active = false;
        }
        self.context = context.*;
    }

    pub fn nextWakeup(self: *const Discovery, now_ms: u64) ?u64 {
        if (self.stopped) return null;
        var next = self.driver.core.nextDeadlineMs() orelse std.math.maxInt(u64);
        if (self.maintenance.nextDeadlineMs()) |deadline| next = @min(next, @max(deadline, self.resource_retry_ms));
        if (self.lookup_active and self.lookup.waitingCount() < d.Lookup.parallelism) next = @min(next, @max(self.refill_due_ms, self.resource_retry_ms));
        if (!self.lookup_active and self.demand.active(now_ms)) next = @min(next, @max(self.query_due_ms, self.resource_retry_ms));
        if (self.demand.active(now_ms)) next = @min(next, self.demand.expires_ms);
        return @max(now_ms, next);
    }

    /// Runs one Driver step, then consumes all borrowed progress before exposing a local fault.
    /// The caller's monotonic time must use the same domain as the Driver's host I/O clock.
    pub fn step(self: *Discovery, io: std.Io, now_ms: u64, wake_ms: u64, out: []adapter.Candidate) Error!Result {
        if (self.stopped) return error.Stopped;
        var result = Result{};
        self.refill(io, now_ms, &result) catch |err| {
            result.failure = err;
            self.counters.coordinator_failures +|= 1;
            self.resource_retry_ms = now_ms +| self.options.local_retry_ms;
        };
        const progress = try self.driver.stepUntil(io, &self.storage.expiries, @min(wake_ms, self.nextWakeup(now_ms).?));
        const consumed = self.consume(&progress, self.storage.expiries[0..progress.calls_expired], out);
        return .{ .candidates = consumed.candidates, .started = result.started, .expired = consumed.expired, .rejected = consumed.rejected, .dropped = consumed.dropped, .unowned = consumed.unowned, .failure = result.failure orelse consumed.failure, .failure_stage = if (result.failure != null) .coordinator else consumed.failure_stage };
    }

    /// Supports hosts that drive the borrowed Driver themselves. Consume every result exactly
    /// once before another Driver step, including results containing failure. No slice escapes.
    pub fn consume(self: *Discovery, progress: *const d.Driver.StepResult, expiries: []const d.CallTable.Expired, out: []adapter.Candidate) Result {
        std.debug.assert(expiries.len == progress.calls_expired and expiries.len <= d.CallTable.capacity_max);
        var result = Result{ .failure = progress.failure, .failure_stage = progress.failure_stage };
        if (self.stopped) return result;
        if (progress.failure != null) switch (progress.failure_stage) {
            .maintenance => self.counters.maintenance_failures +|= 1,
            .receive => self.counters.receive_failures +|= 1,
            .process => self.counters.processing_failures +|= 1,
            .clock, .coordinator => self.counters.coordinator_failures +|= 1,
        };
        for (expiries) |expired| {
            self.counters.query_timeouts +|= 1;
            if (self.lookup_active and self.lookup.ownsCall(expired.handle)) {
                self.lookup.onFailure(self.driver.core, expired.handle) catch unreachable;
                result.expired += 1;
            } else if (self.maintenance.onFailure(self.driver.core, expired.handle, progress.now_ms, .expired)) {
                result.expired += 1;
            } else result.unowned += 1;
        }
        self.consumeEvent(progress, out, &result);
        if (self.lookup_active and self.lookup.isFinished()) {
            const confirmed_records = self.lookup.confirmedResults(&self.storage.records);
            self.counters.lookups_completed +|= 1;
            self.lookup_time.observe(progress.now_ms -| self.lookup_started_ms);
            self.lookup_finishes[@intFromEnum(self.lookup.finishReason().?)] +|= 1;
            std.log.scoped(.network_discovery).debug("lookup_completed reason={s} confirmed={d} queried={d} candidates={d} published={d} elapsed_ms={d}", .{ @tagName(self.lookup.finishReason().?), confirmed_records.len, self.lookup.queries_started, self.lookup.candidateCount(), self.counters.candidates_published -| self.lookup_published, progress.now_ms -| self.lookup_started_ms });
            self.lookup_active = false;
            self.query_due_ms = progress.now_ms +| self.options.query_interval_ms;
        }
        return result;
    }

    pub fn cancel(self: *Discovery) void {
        if (self.stopped) return;
        if (self.lookup_active) self.lookup.cancel(self.driver.core);
        self.maintenance.cancel(self.driver.core);
        self.lookup_active = false;
        self.demand = .{};
        self.stopped = true;
    }

    fn refill(self: *Discovery, io: std.Io, now_ms: u64, result: *Result) Error!void {
        self.expireForeground(now_ms);
        if (now_ms < self.resource_retry_ms) return;
        if (!self.lookup_active and self.demand.active(now_ms) and now_ms >= self.query_due_ms) {
            self.query_due_ms = now_ms +| self.options.query_interval_ms;
            var target: d.types.NodeId = undefined;
            try std.Io.randomSecure(io, &target);
            var seeds: [d.Lookup.result_max]d.RoutingTable.Entry = undefined;
            const closest = self.driver.core.closestNodes(&target, &seeds);
            try self.lookup.init(&self.storage.foreground, self.driver.core.localRecord().node_id, target, closest);
            self.lookup.filter = .{ .context = &self.context, .matches = matchesNetwork };
            self.lookup.query_limit = queries_max;
            self.lookup_started_ms = now_ms;
            self.lookup_published = self.counters.candidates_published;
            self.counters.lookups_started +|= 1;
            std.log.scoped(.network_discovery).debug("lookup_started target={x} seeds={d}", .{ target, closest.len });
            self.lookup_active = true;
        }
        if (self.maintenance.nextDeadlineMs()) |deadline| if (now_ms >= deadline) {
            try self.start(io, now_ms, true, result);
        };
        if (!self.lookup_active or now_ms < self.refill_due_ms) return;
        self.refill_due_ms = now_ms +| self.options.local_retry_ms;
        for (0..d.Lookup.parallelism) |_| {
            const before = result.started;
            try self.start(io, now_ms, false, result);
            if (before == result.started) break;
        }
    }

    fn expireForeground(self: *Discovery, now_ms: u64) void {
        if (!self.lookup_active or self.demand.active(now_ms)) return;
        self.lookup.cancel(self.driver.core);
        self.lookup_active = false;
    }

    fn start(self: *Discovery, io: std.Io, now_ms: u64, background: bool, result: *Result) Error!void {
        var entropy: d.Engine.StartEntropy = undefined;
        try std.Io.randomSecure(io, std.mem.asBytes(&entropy));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const id = try d.Driver.requestId(io);
        var packet: [d.wire.constants.packet_size_max]u8 = undefined;
        const started = (if (background) self.maintenance.startNext(self.driver.core, &packet, id, now_ms, &entropy) else self.lookup.startNext(self.driver.core, &packet, id, now_ms, &entropy)) catch |err| switch (err) {
            error.TableFull, error.PeerBusy => return,
            else => return err,
        } orelse return;
        result.started += 1;
        self.counters.queries_started +|= 1;
        self.driver.transmit(io, started.peer.address, packet[0..started.call.packet_length]) catch |err| {
            if (background) {
                std.debug.assert(self.maintenance.onFailure(self.driver.core, started.call.handle, now_ms, .local));
            } else self.lookup.onFailure(self.driver.core, started.call.handle) catch unreachable;
            return err;
        };
    }

    fn consumeEvent(self: *Discovery, progress: *const d.Driver.StepResult, out: []adapter.Candidate, result: *Result) void {
        const handle = switch (progress.event) {
            .response => |response| response.matched.handle,
            .failed => |failed| failed.handle,
            else => return,
        };
        if (progress.event == .failed) self.counters.query_failures +|= 1;
        if (self.lookup_active and self.lookup.ownsCall(handle)) {
            switch (progress.event) {
                .response => |*response| {
                    const known = self.lookup.knownRecord(handle).?.*;
                    self.lookup.onResponse(self.driver.core, response, progress.now_ms) catch |err| {
                        self.lookup.onFailure(self.driver.core, handle) catch unreachable;
                        result.failure = result.failure orelse err;
                        return;
                    };
                    if (response.matched.terminal) self.publishResponse(response, &known, progress.now_ms, out, result);
                },
                .failed => self.lookup.onFailure(self.driver.core, handle) catch unreachable,
                else => unreachable,
            }
            self.refill_due_ms = progress.now_ms;
            return;
        }
        const known: ?d.identity.enr.Record = if (self.maintenance.knownRecord(handle)) |record| record.* else null;
        const consumed = self.maintenance.onEvent(self.driver.core, &progress.event, progress.now_ms) catch |err| {
            _ = self.maintenance.onFailure(self.driver.core, handle, progress.now_ms, .local);
            result.failure = result.failure orelse err;
            return;
        };
        if (!consumed) {
            result.unowned += 1;
            return;
        }
        if (progress.event == .response) {
            const response = &progress.event.response;
            if (!response.matched.terminal) return;
            if (known) |*record| self.publishResponse(response, record, progress.now_ms, out, result);
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
        self.counters.authenticated_candidates +|= 1;
        const retained = self.driver.core.peerRecord(&response.peer.node_id);
        if (retained == null or retained.?.last_verified_ms != now_ms or !std.meta.eql(retained.?.peer, response.peer)) self.counters.authenticated_not_retained +|= 1;
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
        for (candidate.addresses[0..candidate.address_count]) |address| {
            if (!relayAllowed(source, address)) continue;
            candidate.addresses[count] = address;
            count += 1;
        }
        candidate.address_count = count;
        @memset(candidate.addresses[count..], .unspecified);
        if (count == 0) {
            self.rejected(.endpoint_scope, result);
            return;
        }
        if (!self.demand.matches(&candidate)) {
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
        self.last_candidate_ms = now_ms;
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
