const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const request_policy = @import("request_policy.zig");
const admission_mod = @import("admission.zig");
const limiter_mod = @import("limiter.zig");
const protocol_mod = @import("protocol.zig");
const config = @import("config");
const engine_mod = @import("../quic/engine.zig");
const limits = @import("../quic/limits.zig");
const negotiate = @import("../negotiate.zig");
const Client = @import("client.zig").Client;
const Server = @import("server.zig").Server;
const Lifecycle = @import("lifecycle.zig").Lifecycle;
const RequestIO = @import("request_io.zig").RequestIO;
const routing = @import("../router.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const Protocol = protocol_mod.Protocol;
const Now = types.Now;

pub const read_buffer_length: usize = 16 * 1024;
pub const reads_per_pump_max: u32 = 8;
pub const over_limit_queue_max: usize = 8;
pub const scratch_length: usize = codec.frame_scratch_max;
/// Two maintenance and two gossip streams remain outside the application allowance.
pub const outbound_stream_headroom: u8 = 4;

pub fn validateForkTable(table: []const ForkEntry) error{InvalidOptions}!void {
    if (table.len > 64) return error.InvalidOptions;
    for (table, 0..) |entry, i| {
        for (table[0..i]) |old| {
            if (std.mem.eql(u8, &old.digest, &entry.digest)) return error.InvalidOptions;
        }
    }
}

pub const ForkEntry = struct {
    digest: [constants.context_bytes_length]u8,
    fork: config.ForkSeq,
};

pub const AdmissionOptions = struct {
    policy: request_policy.Config,
    limits: admission_mod.Options,

    pub fn defaults(configuration: *const request_policy.Config, identities: u16, inbound_max: u16) error{InvalidPolicy}!AdmissionOptions {
        const policy = try request_policy.Policy.init(configuration);
        var quotas: admission_mod.Options = undefined;
        quotas.identities = identities;
        for (0..config.ForkSeq.count) |i| {
            quotas.peer[i] = policy.defaultQuotas(@enumFromInt(i));
            quotas.global[i] = limiter_mod.defaultQuotas();
            for (0..Protocol.count) |j| {
                const which: Protocol = @enumFromInt(j);
                if (which.isControl()) quotas.global[i][j].tokens = @max(quotas.peer[i][j].tokens, inbound_max);
            }
        }
        return .{ .policy = configuration.*, .limits = quotas };
    }
};

const Admission = struct {
    policy: request_policy.Policy,
    limiter: admission_mod.Limiter,
};

pub const Options = struct {
    peers: u16 = limits.connections_max_default,
    outbound_max: u16 = constants.outbound_max_default,
    inbound_max: u16 = constants.inbound_max_default,
    outbound_control_reserved: u16 = 0,
    inbound_control_reserved: u16 = 0,
    /// Zero preserves raw admission without an aggregate application limit.
    outbound_per_peer_max: u8 = 0,
    inbound_per_peer_max: u8 = constants.inbound_per_peer_max_default,
    /// Zero disables the cap; retained application owners count until canonical recycling.
    inbound_application_per_peer_max: u8 = 0,
    /// Inbound wire progress; outbound requests use their absolute phase deadlines.
    progress_timeout_ms: u64 = constants.progress_timeout_ms_default,
    forks: []const ForkEntry,
    request_fork: config.ForkSeq = .phase0,
    admission: ?AdmissionOptions = null,
    quotas: ?limiter_mod.Quotas = null,
    /// Defaults reserve one inbound-capacity control wave; bulk quotas stay per protocol.
    global_quotas: ?limiter_mod.Quotas = null,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    work_per_pump_max: u16 = 32,
};

const Settings = struct {
    peers: u16,
    outbound_control_reserved: u16,
    inbound_control_reserved: u16,
    outbound_per_peer_max: u8,
    inbound_per_peer_max: u8,
    inbound_application_per_peer_max: u8,
    progress_timeout_ms: u64,
    host_timeout_ms: u64,
    quota_timeout_ms: u64,
    work_per_pump_max: u16,
};

pub const AbsoluteTimeouts = struct {
    negotiation_ms: u64 = 5_000,
    request_ms: u64 = 5_000,
    response_ms: u64 = 10_000,
};

pub const RequestPhase = enum { negotiation, request, response };

pub const RequestOptions = struct {
    expected_chunks: ?u32 = null,
    absolute_timeouts: AbsoluteTimeouts = .{},
};

pub const RequestHandle = struct {
    index: u16,
    generation: u32,
    direction: types.Direction,
};

pub const Failure = union(enum) {
    timeout,
    host_timeout,
    quota_timeout,
    cancelled,
    negotiation_rejected,
    negotiation_failed: negotiate.Failure,
    invalid_response: (codec.Error || error{InvalidResponseContext}),
    invalid_request: codec.Error,
    too_many_chunks,
    unknown_context: [constants.context_bytes_length]u8,
    peer_error: struct { code: u8, message_len: u16 },
    connection_closed,
    stream_closed,
    transport,
};

pub const Event = union(enum) {
    chunk: struct { request: RequestHandle, bytes: []const u8, fork: ?config.ForkSeq },
    done: struct { request: RequestHandle, chunks: u32 },
    failed: struct { request: RequestHandle, reason: Failure, phase: ?RequestPhase = null },
    request: struct { request: RequestHandle, peer: Handle, protocol: Protocol, bytes: []const u8 },
    chunk_sent: struct { request: RequestHandle, chunks: u32 },
    served: struct { request: RequestHandle, chunks: u32 },
    over_limit: struct { peer: Handle, protocol: Protocol },
};

pub const Outputs = struct { application: []Event = &.{}, control: []Event = &.{} };
pub const OutputCounts = struct { application: usize, control: usize };
pub const Capacities = struct { application: usize = 0, control: usize = 0 };

pub const InitError = limiter_mod.InitError || error{InvalidPolicy};

pub const RequestError = error{
    ProtocolDisabled,
    InvalidRequest,
    InvalidRequestOptions,
    InvalidCapacity,
    SlotsExhausted,
    TooManyRequests,
    SinkTooSmall,
    RequestTooLarge,
    RequestTooSmall,
    NegotiationTableFull,
    StaleHandle,
    Transport,
};

pub const AcceptError = error{
    InvalidCapacity,
    StaleHandle,
    InvalidHandoff,
    SlotsExhausted,
    PeerSlotsExhausted,
    UnknownProtocol,
};

pub const RespondError = error{
    InvalidError,
    InvalidContext,
    StaleHandle,
    Busy,
    UnknownFork,
    ChunkTooLarge,
    ChunkTooSmall,
    TooManyChunks,
};

pub const Counters = struct {
    inspected: u64 = 0,
    admitted: u64 = 0,
    charged_work: u128 = 0,
    malformed: u64 = 0,
    peer_refusals: u64 = 0,
    aggregate_refusals: u64 = 0,
    identity_capacity_refusals: u64 = 0,
    requests_sent: u64 = 0,
    requests_served: u64 = 0,
    chunks_received: u64 = 0,
    chunks_sent: u64 = 0,
    withheld_chunks: u64 = 0,
    withheld_ms_total: u64 = 0,
    failures: u64 = 0,
    timeouts: u64 = 0,
    over_limit: u64 = 0,
    over_limit_dropped: u64 = 0,
    goodbyes_recovered_on_close: u64 = 0,
    goodbyes_incomplete_on_close: u64 = 0,
};

pub const metrics = @import("metrics.zig");
pub const ProtocolCounters = metrics.ProtocolCounters;

const OverLimit = struct {
    peer: Handle,
    protocol: Protocol,
};

pub const MemoryPlan = struct {
    facade_bytes: usize,
    slot_bytes: usize,
    io_bytes: usize,
    limiter_bytes: usize,
    admission_bytes: usize = 0,
    request_sink_bytes: usize = 0,
    total_bytes: usize,
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    options: Settings,
    outbound: []Client,
    inbound: []Server,
    arena: []u8,
    request_sinks: []u8,
    limiter: limiter_mod.Limiter,
    admission: ?Admission,
    request_fork: config.ForkSeq,
    over_limit: [over_limit_queue_max]OverLimit = undefined,
    over_limit_head: u8 = 0,
    over_limit_len: u8 = 0,
    last_now_ms: u64 = 0,
    counters: Counters = .{},
    protocol_counters: [Protocol.count]ProtocolCounters = @splat(.{}),
    outgoing_error_reasons: [metrics.error_reason_count]u64 = @splat(0),
    forks: [64]ForkEntry = undefined,
    fork_count: u8 = 0,
    work_cursor: usize = 0,
    application_event_cursor: usize = 0,
    control_event_cursor: usize = 0,
    scan_remaining: usize = 0,

    pub const Resources = struct {
        outbound_capacity: usize = 0,
        inbound_capacity: usize = 0,
        outbound_control_reserved: usize = 0,
        inbound_control_reserved: usize = 0,
        outbound_occupied: usize = 0,
        inbound_occupied: usize = 0,
        pending_events: usize = 0,
        pending_terminals: usize = 0,
        held_chunks: usize = 0,
        withheld_chunks: usize = 0,
        oldest_withheld_age_ms: ?u64 = null,
        over_limit_backlog: usize = 0,
    };

    pub fn resourceSnapshot(self: *const ReqResp) Resources {
        var result: Resources = .{
            .outbound_capacity = self.outbound.len,
            .inbound_capacity = self.inbound.len,
            .outbound_control_reserved = self.options.outbound_control_reserved,
            .inbound_control_reserved = self.options.inbound_control_reserved,
            .over_limit_backlog = self.over_limit_len,
        };
        for (self.outbound) |*slot| {
            if (slot.lifecycle.occupied()) result.outbound_occupied += 1;
            if (slot.lifecycle.pendingEvent() != null) result.pending_events += 1;
            if (slot.lifecycle.terminalEvent() != null) result.pending_terminals += 1;
            if (slot.lifecycle.notification == .borrowed_chunk) result.held_chunks += 1;
        }
        for (self.inbound) |*slot| {
            if (slot.lifecycle.occupied()) result.inbound_occupied += 1;
            if (slot.lifecycle.pendingEvent() != null) result.pending_events += 1;
            if (slot.lifecycle.terminalEvent() != null) result.pending_terminals += 1;
            if (slot.lifecycle.running()) if (slot.withheld_since_ms) |since| {
                result.withheld_chunks += 1;
                result.oldest_withheld_age_ms = @max(result.oldest_withheld_age_ms orelse 0, self.last_now_ms -| since);
            };
        }
        return result;
    }

    pub fn validateOptions(options: Options) InitError!struct { peer: limiter_mod.Quotas, global: limiter_mod.Quotas } {
        if (options.admission) |*admission| {
            _ = try request_policy.Policy.init(&admission.policy);
            try admission_mod.Limiter.validate(&admission.limits);
        }
        if (options.outbound_max == 0 or options.outbound_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.inbound_max == 0 or options.inbound_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.outbound_control_reserved > options.outbound_max or
            options.inbound_control_reserved > options.inbound_max) return error.InvalidOptions;
        const application_max = options.outbound_max - options.outbound_control_reserved;
        if (options.outbound_per_peer_max > limits.peer_streams_bidi - outbound_stream_headroom or
            options.outbound_per_peer_max > application_max) return error.InvalidOptions;
        if (options.inbound_per_peer_max == 0 or options.peers == 0) return error.InvalidOptions;
        if (options.inbound_application_per_peer_max > options.inbound_per_peer_max or
            options.inbound_application_per_peer_max > options.inbound_max - options.inbound_control_reserved)
            return error.InvalidOptions;
        if (options.peers > constants.slots_ceiling) return error.InvalidOptions;
        if (options.progress_timeout_ms == 0 or options.host_timeout_ms == 0 or
            options.quota_timeout_ms == 0 or options.work_per_pump_max == 0 or
            options.work_per_pump_max > 2 * constants.slots_ceiling) return error.InvalidOptions;
        const peer_quotas = options.quotas orelse limiter_mod.defaultQuotas();
        var global_quotas = options.global_quotas orelse peer_quotas;
        if (options.global_quotas == null) {
            const controls = [_]Protocol{
                .status_v1,   .status_v2,   .ping_v1,    .metadata_v1,
                .metadata_v2, .metadata_v3, .goodbye_v1,
            };
            for (controls) |which| {
                const quota = &global_quotas[@intFromEnum(which)];
                quota.tokens = @max(quota.tokens, options.inbound_max);
            }
        }
        try limiter_mod.Limiter.validate(peer_quotas);
        try limiter_mod.Limiter.validate(global_quotas);
        try validateForkTable(options.forks);

        return .{ .peer = peer_quotas, .global = global_quotas };
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!ReqResp {
        const quotas = try validateOptions(options);
        var admission: ?Admission = if (options.admission) |*value| .{
            .policy = try request_policy.Policy.init(&value.policy),
            .limiter = try admission_mod.Limiter.init(allocator, value.limits),
        } else null;
        errdefer if (admission) |*owner| owner.limiter.deinit(allocator);

        const outbound = try allocator.alloc(Client, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(outbound, .{});
        const inbound = try allocator.alloc(Server, options.inbound_max);
        errdefer allocator.free(inbound);
        @memset(inbound, .{});

        const request_sink_bytes = @as(usize, options.inbound_max - options.inbound_control_reserved) * protocol_mod.requestMaxAll() +
            @as(usize, options.inbound_control_reserved) * protocol_mod.requestMaxControl();
        const request_sinks = try allocator.alloc(u8, request_sink_bytes);
        errdefer allocator.free(request_sinks);

        const total = @as(usize, options.outbound_max) + options.inbound_max;
        const arena = try allocator.alloc(u8, total * (scratch_length + read_buffer_length));
        errdefer allocator.free(arena);
        var cursor: usize = 0;
        for (outbound) |*slot| cursor = assignBuffers(&slot.lifecycle.io, arena, cursor);
        for (inbound) |*slot| cursor = assignBuffers(&slot.lifecycle.io, arena, cursor);
        assert(cursor == arena.len);

        var buckets = try limiter_mod.Limiter.init(
            allocator,
            options.peers,
            quotas.peer,
            quotas.global,
        );
        errdefer buckets.deinit(allocator);

        var result: ReqResp = .{
            .allocator = allocator,
            .options = .{
                .peers = options.peers,
                .outbound_control_reserved = options.outbound_control_reserved,
                .inbound_control_reserved = options.inbound_control_reserved,
                .outbound_per_peer_max = options.outbound_per_peer_max,
                .inbound_per_peer_max = options.inbound_per_peer_max,
                .inbound_application_per_peer_max = options.inbound_application_per_peer_max,
                .progress_timeout_ms = options.progress_timeout_ms,
                .host_timeout_ms = options.host_timeout_ms,
                .quota_timeout_ms = options.quota_timeout_ms,
                .work_per_pump_max = options.work_per_pump_max,
            },
            .outbound = outbound,
            .inbound = inbound,
            .arena = arena,
            .request_sinks = request_sinks,
            .limiter = buckets,
            .admission = admission,
            .request_fork = options.request_fork,
            .fork_count = @intCast(options.forks.len),
        };
        @memcpy(result.forks[0..options.forks.len], options.forks);
        return result;
    }

    /// Call shutdown first, or destroy the attached transport and Router before deinit.
    pub fn deinit(self: *ReqResp) void {
        if (self.admission) |*owner| owner.limiter.deinit(self.allocator);
        self.limiter.deinit(self.allocator);
        self.allocator.free(self.request_sinks);
        self.allocator.free(self.arena);
        self.allocator.free(self.inbound);
        self.allocator.free(self.outbound);
        self.* = undefined;
    }

    pub fn setRequestFork(self: *ReqResp, fork: config.ForkSeq) void {
        self.request_fork = fork;
    }

    pub fn active(self: *const ReqResp) struct { outbound: u16, inbound: u16 } {
        var out: u16 = 0;
        for (self.outbound) |*slot| {
            if (slot.lifecycle.active()) out += 1;
        }
        var in: u16 = 0;
        for (self.inbound) |*slot| {
            if (slot.lifecycle.active()) in += 1;
        }
        assert(out <= self.outbound.len);
        assert(in <= self.inbound.len);
        return .{ .outbound = out, .inbound = in };
    }

    /// Request bytes stay immutable and the sink exclusive through terminal delivery.
    /// Chunk slices remain stable until consume or terminal delivery.
    pub fn request(
        self: *ReqResp,
        engine: *Engine,
        router: *routing.Router,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        request_options: RequestOptions,
        now: Now,
    ) RequestError!RequestHandle {
        if (!router.capabilities().request.contains(.{ .reqresp = which })) return error.ProtocolDisabled;
        return Client.request(
            self,
            engine,
            router,
            conn,
            which,
            request_ssz,
            sink,
            request_options,
            now,
        );
    }

    pub fn negotiated(self: *ReqResp, outcome: routing.Outcome, now: Now) bool {
        return Client.negotiated(self, outcome, now);
    }

    /// Borrows request bytes from the owned inbound slot through served/failed delivery.
    pub fn accept(
        self: *ReqResp,
        engine: *Engine,
        stream: StreamHandle,
        ready: routing.Selection,
        now: Now,
    ) AcceptError!RequestHandle {
        return Server.accept(self, engine, stream, ready, now);
    }

    /// Response bytes stay immutable through chunk_sent or terminal delivery.
    pub fn respond(
        self: *ReqResp,
        handle: RequestHandle,
        ssz: []const u8,
        context: ?ForkEntry,
        now: Now,
    ) RespondError!void {
        return Server.respond(self, handle, ssz, context, now);
    }

    /// Copies the message; the caller may release it immediately.
    pub fn respondError(
        self: *ReqResp,
        handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) RespondError!void {
        return Server.respondError(self, handle, code, message, now);
    }

    pub fn finish(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        return Server.finish(self, handle, now);
    }

    pub fn consume(self: *ReqResp, handle: RequestHandle) bool {
        return Client.consume(self, handle);
    }

    /// The returned bytes remain valid until the pump after terminal delivery.
    pub fn errorMessage(self: *const ReqResp, handle: RequestHandle) []const u8 {
        const lifecycle: *const Lifecycle = switch (handle.direction) {
            .outbound => if (handle.index < self.outbound.len) &self.outbound[handle.index].lifecycle else return &.{},
            .inbound => if (handle.index < self.inbound.len) &self.inbound[handle.index].lifecycle else return &.{},
        };
        if (lifecycle.generation != handle.generation or !lifecycle.occupied()) return &.{};
        assert(lifecycle.error_len <= codec.error_message_max);
        return lifecycle.error_message[0..lifecycle.error_len];
    }

    /// Forward each full-generation handle drained from Driver activity before querying wakeups.
    pub fn connectionActivity(self: *ReqResp, conn: Handle) void {
        for (self.outbound) |*slot| {
            if (slot.lifecycle.running() and std.meta.eql(slot.lifecycle.conn, conn)) {
                slot.lifecycle.needs_service = true;
            }
        }
        for (self.inbound) |*slot| {
            if (slot.lifecycle.running() and std.meta.eql(slot.lifecycle.conn, conn)) {
                slot.lifecycle.needs_service = true;
            }
        }
    }

    /// Read retained Goodbye bytes before the close event cancels streams and releases their sinks.
    pub fn closingGoodbye(self: *ReqResp, engine: *Engine, conn: Handle, now: Now) ?u64 {
        assert(now.mono_ms >= self.last_now_ms);
        self.last_now_ms = now.mono_ms;
        for (self.inbound, 0..) |*slot, index| {
            if (!slot.lifecycle.running() or slot.lifecycle.protocol != .goodbye_v1 or !std.meta.eql(slot.lifecycle.conn, conn)) continue;
            if (slot.state != .receiving_request and (slot.lifecycle.pendingEvent() == null or slot.lifecycle.pendingEvent().? != .request)) continue;
            if (slot.state == .receiving_request and slot.lifecycle.pendingEvent() == null) Server.readRequest(self, engine, slot, @intCast(index), now);
            if (slot.lifecycle.pendingEvent()) |event| if (event == .request) {
                assert(event.request.bytes.len == 8);
                self.counters.goodbyes_recovered_on_close +|= 1;
                slot.lifecycle.notification = .none;
                slot.state = .serving;
                return std.mem.readInt(u64, event.request.bytes[0..8], .little);
            };
            self.counters.goodbyes_incomplete_on_close +|= 1;
            std.log.scoped(.network_reqresp_errors).debug("goodbye_incomplete_on_close request={d}:{d} connection={d}:{d} stream={d} buffered_bytes={d} decoded_bytes={d} decoder_phase={s} fin={any} detail={s}", .{ index, slot.lifecycle.generation, conn.index, conn.generation, slot.lifecycle.stream.id, slot.lifecycle.io.buffered_end - slot.lifecycle.io.buffered_start, if (slot.lifecycle.io.decoding) slot.lifecycle.io.decoder.written else 0, if (slot.lifecycle.io.decoding) @tagName(slot.lifecycle.io.decoder.phase) else "cleared", slot.lifecycle.io.fin_seen, slot.lifecycle.io.failure_detail });
        }
        return null;
    }

    pub fn connectionClosed(self: *ReqResp, conn: Handle) void {
        for (self.outbound, 0..) |*slot, position| {
            if (!slot.lifecycle.active() or !std.meta.eql(slot.lifecycle.conn, conn)) continue;
            slot.lifecycle.fail(self, @intCast(position), .connection_closed, .{ .outbound = slot.phase }, null);
        }
        for (self.inbound, 0..) |*slot, position| {
            if (!slot.lifecycle.active() or !std.meta.eql(slot.lifecycle.conn, conn)) continue;
            slot.lifecycle.fail(self, @intCast(position), .connection_closed, .{ .inbound = slot.state }, null);
        }
    }

    /// Includes reqresp-owned storage. Caller response sinks and Router storage are separate.
    pub fn memoryPlan(self: *const ReqResp) MemoryPlan {
        const slot_bytes = self.outbound.len * @sizeOf(Client) + self.inbound.len * @sizeOf(Server);
        const limiter_bytes = self.limiter.buckets.len * @sizeOf(limiter_mod.Bucket) +
            self.limiter.generations.len * @sizeOf(?u32);
        const admission_bytes = if (self.admission) |*owner| owner.limiter.memoryPlan().allocated_bytes else 0;
        return .{
            .facade_bytes = @sizeOf(ReqResp),
            .slot_bytes = slot_bytes,
            .io_bytes = self.arena.len,
            .limiter_bytes = limiter_bytes,
            .admission_bytes = admission_bytes,
            .request_sink_bytes = self.request_sinks.len,
            .total_bytes = @sizeOf(ReqResp) + slot_bytes + self.arena.len + limiter_bytes + admission_bytes + self.request_sinks.len,
        };
    }

    /// Monotonic milliseconds; zero capacity suppresses event-only wakeups.
    /// Router negotiation and transport deadlines remain separate.
    pub fn nextWakeup(self: *ReqResp, now: Now, capacities: Capacities) ?u64 {
        for (0..self.over_limit_len) |offset| {
            const item = self.over_limit[(self.over_limit_head + offset) % over_limit_queue_max];
            const capacity = if (item.protocol.isControl())
                capacities.control
            else
                capacities.application;
            if (capacity > 0) return now.mono_ms;
        }
        var due: ?u64 = null;
        for (self.outbound) |*slot| {
            const capacity = if (slot.lifecycle.protocol.isControl())
                capacities.control
            else
                capacities.application;
            if (slot.lifecycle.wakeup(capacity)) return now.mono_ms;
            if (slot.deadline()) |deadline| due = earlier(due, deadline);
        }
        for (self.inbound) |*slot| {
            const capacity = if (slot.lifecycle.protocol.isControl())
                capacities.control
            else
                capacities.application;
            if (slot.lifecycle.wakeup(capacity)) return now.mono_ms;
            if (slot.deadline(self)) |deadline| due = earlier(due, deadline);
            if (slot.lifecycle.running() and slot.state == .withheld) {
                if (self.limiter.nextToken(slot.lifecycle.conn, slot.lifecycle.protocol, now.mono_ms)) |eligible| {
                    due = earlier(due, eligible);
                } else return now.mono_ms;
            }
        }
        return if (due) |deadline| @max(deadline, now.mono_ms) else null;
    }

    fn earlier(current: ?u64, next: u64) u64 {
        return if (current) |value| @min(value, next) else next;
    }

    /// Validate every raw admission against the attached transport capacity.
    pub fn attach(self: *const ReqResp, engine: *const Engine) error{InvalidCapacity}!void {
        if (engine.limits.connections_max > self.options.peers) return error.InvalidCapacity;
    }

    pub fn inboundSink(self: *ReqResp, index: u16) []u8 {
        assert(index < self.inbound.len);
        const reserved = self.options.inbound_control_reserved;
        const control_size = protocol_mod.requestMaxControl();
        const bulk_size = protocol_mod.requestMaxAll();
        const offset = if (index < reserved) @as(usize, index) * control_size else @as(usize, reserved) * control_size + @as(usize, index - reserved) * bulk_size;
        const size = if (index < reserved) control_size else bulk_size;
        return self.request_sinks[offset..][0..size];
    }

    pub fn availableInboundFor(self: *ReqResp, which: Protocol) ?u16 {
        const start: usize = if (which.isControl()) 0 else self.options.inbound_control_reserved;
        for (self.inbound[start..], start..) |*slot, index| {
            if (slot.lifecycle.available()) return @intCast(index);
        }
        return null;
    }

    pub fn availableOutboundFor(self: *ReqResp, which: Protocol) ?u16 {
        const reserved = self.options.outbound_control_reserved;
        if (!which.isControl() and reserved > 0) {
            var ordinary: usize = 0;
            for (self.outbound) |*slot| {
                if (slot.lifecycle.occupied() and !slot.lifecycle.protocol.isControl()) ordinary += 1;
            }
            if (ordinary >= self.outbound.len - reserved) return null;
        }
        for (self.outbound, 0..) |*slot, index| {
            if (slot.lifecycle.available()) return @intCast(index);
        }
        return null;
    }

    /// Latches one terminal result. Call cleanupPending before the next Router pump.
    pub fn cancel(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction == .outbound) {
            const slot = self.outboundSlot(handle) orelse return false;
            if (slot.lifecycle.terminalEvent() != null) return false;
            slot.lifecycle.fail(self, handle.index, .cancelled, .{ .outbound = slot.phase }, null);
        } else {
            const slot = self.inboundSlot(handle) orelse return false;
            if (slot.lifecycle.terminalEvent() != null) return false;
            slot.lifecycle.fail(self, handle.index, .cancelled, .{ .inbound = slot.state }, null);
        }
        return true;
    }

    pub fn cleanupPending(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        self.cleanup(engine, router, false);
    }

    pub fn cancelApplications(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound, 0..) |*slot, index| if (slot.lifecycle.active() and !slot.lifecycle.protocol.isControl()) {
            _ = self.cancel(slot.lifecycle.handle(@intCast(index)));
        };
        for (self.inbound, 0..) |*slot, index| if (slot.lifecycle.active() and !slot.lifecycle.protocol.isControl()) {
            _ = self.cancel(slot.lifecycle.handle(@intCast(index)));
        };
        self.cleanupPending(engine, router);
    }

    pub fn shutdown(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound, 0..) |*slot, index| if (slot.lifecycle.active()) {
            _ = self.cancel(slot.lifecycle.handle(@intCast(index)));
        };
        for (self.inbound, 0..) |*slot, index| if (slot.lifecycle.active()) {
            _ = self.cancel(slot.lifecycle.handle(@intCast(index)));
        };
        self.cleanup(engine, router, false);
    }

    pub fn pump(self: *ReqResp, engine: *Engine, router: *routing.Router, now: Now, outputs: Outputs) OutputCounts {
        self.advance(engine, router, now);
        return .{
            .application = self.drain(now, outputs.application, false, &self.application_event_cursor),
            .control = self.drain(now, outputs.control, true, &self.control_event_cursor),
        };
    }

    fn advance(self: *ReqResp, engine: *Engine, router: *routing.Router, now: Now) void {
        assert(now.mono_ms >= self.last_now_ms or self.last_now_ms == 0);
        self.last_now_ms = now.mono_ms;
        self.cleanup(engine, router, true);
        const total = self.outbound.len + self.inbound.len;
        if (self.scan_remaining == 0) self.scan_remaining = total;
        const steps = @min(self.scan_remaining, self.options.work_per_pump_max);
        self.scan_remaining -= steps;
        for (0..steps) |_| {
            const position = self.work_cursor;
            self.work_cursor = (position + 1) % total;
            if (position < self.outbound.len) {
                const slot = &self.outbound[position];
                slot.lifecycle.needs_service = false;
                if (slot.lifecycle.active()) slot.advance(self, engine, @intCast(position), now);
            } else {
                const index = position - self.outbound.len;
                const slot = &self.inbound[index];
                slot.lifecycle.needs_service = false;
                if (slot.lifecycle.active()) slot.advance(self, engine, @intCast(index), now);
            }
        }
        // Cleanup also covers terminal transitions made during this turn.
        self.cleanup(engine, router, false);
    }

    fn drain(self: *ReqResp, now: Now, events: []Event, control: bool, cursor: *usize) usize {
        const total = self.outbound.len + self.inbound.len;
        var count: usize = 0;
        for (0..total + 1) |_| {
            if (count == events.len) break;
            const position = cursor.*;
            cursor.* = (position + 1) % (total + 1);
            const event = if (position < self.outbound.len)
                self.outbound[position].lifecycle.deliver(control)
            else if (position < total)
                self.inbound[position - self.outbound.len].deliver(control, now)
            else
                self.takeOverLimit(control);
            if (event) |ready| {
                events[count] = ready;
                count += 1;
            }
        }
        return count;
    }

    fn takeOverLimit(self: *ReqResp, control: bool) ?Event {
        for (0..self.over_limit_len) |offset| {
            const index = (self.over_limit_head + offset) % over_limit_queue_max;
            const item = self.over_limit[index];
            if (item.protocol.isControl() != control) continue;
            if (offset == 0) {
                self.over_limit_head = @intCast((self.over_limit_head + 1) % over_limit_queue_max);
            } else {
                for (offset..self.over_limit_len - 1) |next| {
                    self.over_limit[(self.over_limit_head + next) % over_limit_queue_max] =
                        self.over_limit[(self.over_limit_head + next + 1) % over_limit_queue_max];
                }
            }
            self.over_limit_len -= 1;
            return .{ .over_limit = .{ .peer = item.peer, .protocol = item.protocol } };
        }
        return null;
    }

    fn cleanup(self: *ReqResp, engine: *Engine, router: *routing.Router, recycle: bool) void {
        for (self.outbound) |*slot| slot.lifecycle.cleanup(engine, router, recycle);
        for (self.inbound) |*slot| slot.lifecycle.cleanup(engine, router, recycle);
    }

    pub fn servingSlot(self: *ReqResp, handle: RequestHandle) RespondError!*Server {
        if (handle.direction != .inbound) return error.StaleHandle;
        const slot = self.inboundSlot(handle) orelse return error.StaleHandle;
        if (!slot.lifecycle.running() or slot.lifecycle.waitingHost() or slot.state != .serving) return error.Busy;
        return slot;
    }

    pub fn outboundSlot(self: *ReqResp, handle: RequestHandle) ?*Client {
        const slots = self.outbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.lifecycle.generation != handle.generation or !slot.lifecycle.active()) return null;
        return slot;
    }
    pub fn inboundSlot(self: *ReqResp, handle: RequestHandle) ?*Server {
        const slots = self.inbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.lifecycle.generation != handle.generation or !slot.lifecycle.active()) return null;
        return slot;
    }

    pub fn outboundCount(self: *const ReqResp, conn: Handle, which: Protocol) u8 {
        var count: u8 = 0;
        for (self.outbound) |*slot| {
            if (!slot.lifecycle.active() or slot.lifecycle.protocol != which) continue;
            if (!std.meta.eql(slot.lifecycle.conn, conn)) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn outboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.outbound) |*slot| {
            if (!slot.lifecycle.occupied() or slot.lifecycle.protocol.isControl()) continue;
            if (std.meta.eql(slot.lifecycle.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.inbound) |*slot| {
            if (!slot.lifecycle.occupied() or slot.lifecycle.protocol.isControl()) continue;
            if (std.meta.eql(slot.lifecycle.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundCount(self: *const ReqResp, conn: Handle, which: ?Protocol) u8 {
        var count: u8 = 0;
        for (self.inbound) |*slot| {
            if (!slot.lifecycle.active() or !std.meta.eql(slot.lifecycle.conn, conn)) continue;
            if (which) |wanted| if (slot.lifecycle.protocol != wanted) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn pushOverLimit(self: *ReqResp, item: OverLimit) void {
        std.log.scoped(.network_reqresp_errors).debug("request_rate_limited connection={d}:{d} method={s}", .{ item.peer.index, item.peer.generation, @tagName(item.protocol) });
        self.counters.over_limit += 1;
        if (self.over_limit_len == over_limit_queue_max) {
            self.counters.over_limit_dropped += 1;
            return;
        }
        const tail = (self.over_limit_head + self.over_limit_len) % over_limit_queue_max;
        self.over_limit[tail] = item;
        self.over_limit_len += 1;
    }

    pub fn forkFor(
        self: *const ReqResp,
        digest: [constants.context_bytes_length]u8,
    ) ?config.ForkSeq {
        for (self.forks[0..self.fork_count]) |entry| {
            if (std.mem.eql(u8, &entry.digest, &digest)) return entry.fork;
        }
        return null;
    }
};

fn assignBuffers(io: *RequestIO, arena: []u8, cursor: usize) usize {
    io.scratch = arena[cursor..][0..scratch_length];
    io.read_buffer = arena[cursor + scratch_length ..][0..read_buffer_length];
    return cursor + scratch_length + read_buffer_length;
}

comptime {
    assert(read_buffer_length >= 1024);
    assert(scratch_length >= codec.frame_scratch_max);
    assert(@sizeOf(Client) <= 2 * 1024);
    assert(@sizeOf(Server) <= 2 * 1024);
}

test "reqresp typed reserved sinks keep full control waves and exclude bulk" {
    var requests = try ReqResp.init(std.testing.allocator, .{ .forks = &.{}, .inbound_max = 4, .inbound_control_reserved = 2, .inbound_per_peer_max = 4 });
    defer requests.deinit();
    try std.testing.expectEqual(2 * protocol_mod.requestMaxAll() + 2 * protocol_mod.requestMaxControl(), requests.request_sinks.len);
    try std.testing.expectEqual(@as(?u16, 2), requests.availableInboundFor(.blocks_by_range_v2));
    for (0..4) |i| {
        const index = requests.availableInboundFor(.ping_v1).?;
        try std.testing.expectEqual(@as(u16, @intCast(i)), index);
        requests.inbound[index].lifecycle.completion = .active;
        requests.inbound[index].lifecycle.protocol = .ping_v1;
    }
    try std.testing.expectEqual(@as(?u16, null), requests.availableInboundFor(.ping_v1));
    requests.inbound[0].lifecycle.completion = .free;
    try std.testing.expectEqual(@as(?u16, null), requests.availableInboundFor(.blocks_by_range_v2));
    try std.testing.expectEqual(@as(?u16, 0), requests.availableInboundFor(.ping_v1));
}
