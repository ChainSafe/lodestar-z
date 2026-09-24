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
const RequestState = @import("request_state.zig").RequestState;
const RequestIO = @import("request_io.zig").RequestIO;
const routing = @import("../router.zig");
const types = @import("../types.zig");
const receive_plan = @import("receive_plan.zig");
const serving_pool = @import("serving_pool.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const Protocol = protocol_mod.Protocol;
const Now = types.Now;

pub const read_buffer_length: usize = 16 * 1024;
pub const reads_per_pump_max: u32 = 8;
pub const scratch_length: usize = codec.frame_scratch_max;
pub const control_scratch_length: usize = codec.frameLengthMax(@max(protocol_mod.payloadMaxControl(), codec.error_message_max));
pub const control_read_buffer_length: usize = negotiate.inbox_capacity;
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

    pub fn defaults(configuration: *const request_policy.Config, identities: u16, control_peers: u16, application_max: u16) error{InvalidPolicy}!AdmissionOptions {
        if (control_peers == 0 or control_peers > identities) return error.InvalidPolicy;
        const policy = try request_policy.Policy.init(configuration);
        var quotas: admission_mod.Options = undefined;
        quotas.identities = identities;
        quotas.starts = .{ .tokens = Protocol.count * constants.MAX_CONCURRENT_REQUESTS, .period_ms = constants.progress_timeout_ms_default };
        for (0..config.ForkSeq.count) |i| {
            quotas.peer[i] = policy.defaultQuotas(@enumFromInt(i));
            quotas.global[i] = quotas.peer[i];
            for (0..Protocol.count) |j| {
                const which: Protocol = @enumFromInt(j);
                if (which.isControl()) {
                    quotas.global[i][j].tokens *= control_peers;
                } else {
                    quotas.global[i][j].tokens *= @max(1, @as(u32, application_max) / (2 * constants.MAX_CONCURRENT_REQUESTS));
                }
            }
        }
        return .{ .policy = configuration.*, .limits = quotas };
    }
};

const Admission = struct {
    limiter: admission_mod.Limiter,
};

pub const Options = struct {
    peers: u16 = limits.connections_max_default,
    outbound_max: u16 = constants.outbound_max_default,
    /// Shared execution slots, including the control reserve.
    inbound_max: u16 = constants.inbound_max_default,
    /// Two concurrent sync batches can each request blocks and sidecars.
    serving_per_peer_max: u8 = 2 * constants.MAX_CONCURRENT_REQUESTS,
    /// Nonzero partitions outbound slots between control and application requests.
    outbound_control_reserved: u16 = 0,
    inbound_control_reserved: u16 = 0,
    /// Zero preserves raw admission without an aggregate application limit.
    outbound_per_peer_max: u8 = 0,
    inbound_per_peer_max: u8 = constants.inbound_per_peer_max_default,
    /// Concurrent application receivers per connection; zero disables the cap.
    inbound_application_per_peer_max: u8 = 0,
    /// Complete inbound request transfer and each response chunk within this duration.
    progress_timeout_ms: u64 = constants.progress_timeout_ms_default,
    forks: []const ForkEntry,
    request_fork: config.ForkSeq = .phase0,
    admission: AdmissionOptions,
    quotas: ?limiter_mod.Quotas = null,
    /// Control quotas scale to the control peer reservation; application quotas scale to serving capacity.
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

pub const RequestOptions = struct {
    expected_chunks: ?u32 = null,
    absolute_timeouts: AbsoluteTimeouts = .{},
};

pub const RequestPhase = @import("events.zig").RequestPhase;
pub const RequestHandle = @import("events.zig").RequestHandle;
pub const Failure = @import("events.zig").Failure;
pub const Event = @import("events.zig").Event;

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
    TooManyRequests,
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
    error_responses_sent: u64 = 0,
    chunks_received: u64 = 0,
    chunks_sent: u64 = 0,
    withheld_chunks: u64 = 0,
    withheld_ms_total: u64 = 0,
    failures: u64 = 0,
    timeouts: u64 = 0,
    goodbyes_recovered_on_close: u64 = 0,
    goodbyes_incomplete_on_close: u64 = 0,
};

pub const metrics = @import("metrics.zig");
pub const ProtocolCounters = metrics.ProtocolCounters;

pub const MemoryPlan = struct {
    facade_bytes: usize,
    slot_bytes: usize,
    io_bytes: usize,
    limiter_bytes: usize,
    admission_bytes: usize = 0,
    request_sink_bytes: usize = 0,
    serving_bytes: usize = 0,
    scheduler_bytes: usize = 0,
    total_bytes: usize,
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    options: Settings,
    outbound: []Client,
    inbound: []Server,
    arena: []u8,
    request_sinks: []u8,
    receive_plan: receive_plan.Plan,
    serving: serving_pool.Pool,
    peer_cursors: []PeerCursor,
    admission_cursor: [2]u16 = @splat(0),
    admission_class: u1 = 0,
    limiter: limiter_mod.Limiter,
    policy: request_policy.Policy,
    admission: Admission,
    request_fork: config.ForkSeq,
    last_now_ms: u64 = 0,
    counters: Counters = .{},
    protocol_counters: [Protocol.count]ProtocolCounters = @splat(.{}),
    outgoing_error_reasons: [metrics.error_reason_count]u64 = @splat(0),
    forks: [64]ForkEntry = undefined,
    fork_count: u8 = 0,
    work_cursor: usize = 0,
    application_event_cursor: usize = 0,
    control_event_cursor: usize = 0,

    pub const Resources = struct {
        outbound_capacity: usize = 0,
        inbound_capacity: usize = 0,
        outbound_control_reserved: usize = 0,
        inbound_control_reserved: usize = 0,
        outbound_occupied: usize = 0,
        inbound_occupied: usize = 0,
        inbound_phases: [metrics.inbound_phase_count]usize = @splat(0),
        pending_events: usize = 0,
        pending_terminals: usize = 0,
        held_chunks: usize = 0,
        withheld_chunks: usize = 0,
        oldest_withheld_age_ms: ?u64 = null,
        serving_capacity: usize = 0,
        serving_occupied: usize = 0,
        retiring: usize = 0,
    };

    pub fn resourceSnapshot(self: *const ReqResp) Resources {
        var result: Resources = .{
            .outbound_capacity = self.outbound.len,
            .inbound_capacity = self.inbound.len,
            .outbound_control_reserved = self.options.outbound_control_reserved,
            .inbound_control_reserved = self.options.inbound_control_reserved,
            .serving_capacity = self.serving.entries.len,
        };
        for (self.serving.entries) |entry| {
            result.serving_occupied += @intFromBool(entry.request != null);
            result.retiring += @intFromBool(entry.retiring);
        }
        for (self.outbound) |*slot| {
            if (slot.request.occupied()) result.outbound_occupied += 1;
            if (slot.request.pendingEvent() != null) result.pending_events += 1;
            if (slot.request.terminalEvent() != null) result.pending_terminals += 1;
            if (slot.request.notification == .borrowed_chunk) result.held_chunks += 1;
        }
        for (self.inbound) |*slot| {
            if (slot.occupancy()) |phase| {
                result.inbound_occupied += 1;
                result.inbound_phases[@intFromEnum(phase)] += 1;
            }
            if (slot.request.pendingEvent() != null) result.pending_events += 1;
            if (slot.request.terminalEvent() != null) result.pending_terminals += 1;
            if (slot.request.running()) if (slot.withheld_since_ms) |since| {
                result.withheld_chunks += 1;
                result.oldest_withheld_age_ms = @max(result.oldest_withheld_age_ms orelse 0, self.last_now_ms -| since);
            };
        }
        return result;
    }

    pub fn recordAdmissionRefusal(self: *ReqResp, stream: StreamHandle, which: Protocol, reason: metrics.AdmissionRefusal, cost: u128) void {
        const reason_index = @intFromEnum(reason);
        const counts = &self.protocol_counters[@intFromEnum(which)];
        counts.admission_refusals[reason_index] +|= 1;
        switch (reason) {
            .peer_capacity => {},
            .protocol_concurrency, .peer_quota, .global_quota, .identity_capacity, .request_starts => counts.rate_limited +|= 1,
        }
        std.log.scoped(.network_reqresp_errors).debug("request_admission_refused connection={d}:{d} stream={d} method={s} reason={s} cost={d}", .{ stream.conn.index, stream.conn.generation, stream.id, @tagName(which), @tagName(reason), cost });
    }

    pub fn requestBounds(self: *const ReqResp, which: Protocol) protocol_mod.Info {
        return self.policy.requestBounds(which, self.request_fork);
    }

    pub fn responseBounds(self: *const ReqResp, which: Protocol, fork: config.ForkSeq) error{InvalidResponseContext}!codec.Bounds {
        var result = try which.responseBounds(fork);
        result.protocol_max = result.max;
        result.max = @min(result.max, self.policy.config.max_payload_size);
        if (result.min > result.max) return error.InvalidResponseContext;
        return result;
    }

    pub fn inspectRequest(self: *const ReqResp, which: Protocol, bytes: []const u8, fork: config.ForkSeq) request_policy.InspectError!request_policy.Inspection {
        return self.policy.inspect(which, bytes, fork);
    }

    pub fn validateOptions(options: Options) InitError!struct { peer: limiter_mod.Quotas, global: limiter_mod.Quotas } {
        _ = try request_policy.Policy.init(&options.admission.policy);
        try admission_mod.Limiter.validate(&options.admission.limits);
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
        if (options.inbound_per_peer_max == 0 or options.peers == 0 or options.serving_per_peer_max == 0) return error.InvalidOptions;
        if (options.inbound_application_per_peer_max > options.inbound_per_peer_max) return error.InvalidOptions;
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
                quota.tokens = std.math.mul(u32, quota.tokens, if (options.inbound_control_reserved > 0) options.inbound_control_reserved else options.peers) catch return error.InvalidQuota;
            }
            for (std.enums.values(Protocol)) |which| {
                if (!which.isControl()) global_quotas[@intFromEnum(which)].tokens = std.math.mul(u32, peer_quotas[@intFromEnum(which)].tokens, @max(1, (options.inbound_max - options.inbound_control_reserved) / options.serving_per_peer_max)) catch return error.InvalidQuota;
            }
        }
        try limiter_mod.Limiter.validate(peer_quotas);
        try limiter_mod.Limiter.validate(global_quotas);
        try validateForkTable(options.forks);

        return .{ .peer = peer_quotas, .global = global_quotas };
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!ReqResp {
        const quotas = try validateOptions(options);
        const policy = try request_policy.Policy.init(&options.admission.policy);
        var admission: Admission = .{ .limiter = try admission_mod.Limiter.init(allocator, options.admission.limits) };
        errdefer admission.limiter.deinit(allocator);

        const outbound = try allocator.alloc(Client, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(outbound, .{});
        const receive = receive_plan.Plan.init(&policy);
        const inbound = try allocator.alloc(Server, @as(usize, options.peers) * receive_plan.slots_per_peer);
        errdefer allocator.free(inbound);
        @memset(inbound, .{});

        const request_sinks = try allocator.alloc(u8, @as(usize, options.peers) * receive.sink_bytes);
        errdefer allocator.free(request_sinks);

        const outbound_bytes = @as(usize, options.outbound_max - options.outbound_control_reserved) * (scratch_length + read_buffer_length) +
            @as(usize, options.outbound_control_reserved) * (control_scratch_length + control_read_buffer_length);
        const inbound_bytes = @as(usize, options.peers) * receive.io_bytes;
        const arena = try allocator.alloc(u8, outbound_bytes + inbound_bytes);
        errdefer allocator.free(arena);
        var cursor: usize = 0;
        for (outbound, 0..) |*slot, index| cursor = assignBuffers(&slot.request.io, arena, cursor, index < options.outbound_control_reserved);
        for (inbound, 0..) |*slot, index| {
            const buffers = receive.buffers(index, request_sinks, arena[outbound_bytes..]);
            slot.receive = buffers;
            cursor += buffers.scratch.len + buffers.read.len;
        }
        assert(cursor == arena.len);

        var serving = try serving_pool.Pool.init(allocator, options.inbound_max, options.inbound_control_reserved, options.serving_per_peer_max);
        errdefer serving.deinit(allocator);
        const peer_cursors = try allocator.alloc(PeerCursor, options.peers);
        errdefer allocator.free(peer_cursors);
        @memset(peer_cursors, .{});

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
            .receive_plan = receive,
            .serving = serving,
            .peer_cursors = peer_cursors,
            .limiter = buckets,
            .policy = policy,
            .admission = admission,
            .request_fork = options.request_fork,
            .fork_count = @intCast(options.forks.len),
        };
        @memcpy(result.forks[0..options.forks.len], options.forks);
        return result;
    }

    /// Call shutdown first, or destroy the attached transport and Router before deinit.
    pub fn deinit(self: *ReqResp) void {
        self.admission.limiter.deinit(self.allocator);
        self.limiter.deinit(self.allocator);
        self.serving.deinit(self.allocator);
        self.allocator.free(self.peer_cursors);
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
            if (slot.request.active()) out += 1;
        }
        var in: u16 = 0;
        for (self.inbound) |*slot| {
            if (slot.request.active()) in += 1;
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
        return Client.start(
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

    /// Hold execution capacity until asynchronous host work actually retires.
    pub fn retainServing(self: *ReqResp, handle: RequestHandle) bool {
        return self.serving.retain(handle);
    }

    pub fn releaseServing(self: *ReqResp, handle: RequestHandle) bool {
        return self.serving.release(handle);
    }

    /// Reserve one response turn before the host produces its next chunk.
    pub fn reserveResponse(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        if (handle.direction != .inbound) return false;
        const slot = self.inboundSlot(handle) orelse return false;
        return slot.reserveResponse(self, now);
    }

    /// Supply fresh owner time so host-held chunks cannot become remote timeout evidence.
    pub fn consume(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        return Client.consume(self, handle, now);
    }

    /// The returned bytes remain valid until the pump after terminal delivery.
    pub fn errorMessage(self: *const ReqResp, handle: RequestHandle) []const u8 {
        const record: *const RequestState = switch (handle.direction) {
            .outbound => if (handle.index < self.outbound.len) &self.outbound[handle.index].request else return &.{},
            .inbound => if (handle.index < self.inbound.len) &self.inbound[handle.index].request else return &.{},
        };
        if (record.generation != handle.generation or !record.occupied()) return &.{};
        assert(record.error_len <= codec.error_message_max);
        return record.error_message[0..record.error_len];
    }

    /// Forward each full-generation handle drained from transport activity before querying wakeups.
    pub fn connectionActivity(self: *ReqResp, conn: Handle) void {
        for (self.outbound) |*slot| {
            if (slot.request.running() and std.meta.eql(slot.request.conn, conn)) {
                slot.request.needs_service = true;
            }
        }
        for (self.inbound) |*slot| {
            if (slot.request.running() and std.meta.eql(slot.request.conn, conn)) {
                slot.request.needs_service = true;
            }
        }
    }

    /// Read retained Goodbye bytes before the close event cancels streams and releases their sinks.
    pub fn closingGoodbye(self: *ReqResp, engine: *Engine, conn: Handle, now: Now) ?u64 {
        assert(now.mono_ms >= self.last_now_ms);
        self.last_now_ms = now.mono_ms;
        for (self.inbound, 0..) |*slot, index| {
            if (!slot.request.running() or slot.request.protocol != .goodbye_v1 or !std.meta.eql(slot.request.conn, conn)) continue;
            if (slot.state != .receiving_request and slot.state != .ready and (slot.request.pendingEvent() == null or slot.request.pendingEvent().? != .request)) continue;
            if (slot.state == .receiving_request and slot.request.pendingEvent() == null) Server.readRequest(self, engine, slot, @intCast(index), now);
            if (slot.request.running() and slot.state == .ready) {
                const bytes = slot.request.io.decoder.payload();
                assert(bytes.len == @import("consensus_types").phase0.Goodbye.fixed_size);
                self.counters.goodbyes_recovered_on_close +|= 1;
                slot.state = .serving;
                return std.mem.readInt(u64, bytes[0..8], .little);
            }
            if (slot.request.pendingEvent()) |event| if (event == .request) {
                assert(event.request.bytes.len == 8);
                self.counters.goodbyes_recovered_on_close +|= 1;
                slot.request.notification = .none;
                slot.state = .serving;
                return std.mem.readInt(u64, event.request.bytes[0..8], .little);
            };
            self.counters.goodbyes_incomplete_on_close +|= 1;
            std.log.scoped(.network_reqresp_errors).debug("goodbye_incomplete_on_close request={d}:{d} connection={d}:{d} stream={d} buffered_bytes={d} decoded_bytes={d} decoder_phase={s} fin={any} detail={s}", .{ index, slot.request.generation, conn.index, conn.generation, slot.request.stream.id, slot.request.io.buffered_end - slot.request.io.buffered_start, if (slot.request.io.decoding) slot.request.io.decoder.written else 0, if (slot.request.io.decoding) @tagName(slot.request.io.decoder.phase) else "cleared", slot.request.io.fin_seen, slot.request.failure_detail });
        }
        return null;
    }

    pub fn connectionClosed(self: *ReqResp, conn: Handle) void {
        for (self.outbound, 0..) |*slot, position| {
            if (!slot.request.active() or !std.meta.eql(slot.request.conn, conn)) continue;
            slot.fail(self, @intCast(position), .connection_closed, null);
        }
        for (self.inbound, 0..) |*slot, position| {
            if (!slot.request.active() or !std.meta.eql(slot.request.conn, conn)) continue;
            slot.fail(self, @intCast(position), .connection_closed, null);
        }
    }

    pub fn streamReset(self: *ReqResp, stream: StreamHandle) void {
        for (self.inbound, 0..) |*slot, index| {
            if (!slot.request.running() or !std.meta.eql(slot.request.stream, stream)) continue;
            if (slot.state == .writing_chunk or slot.state == .finishing) return;
            slot.fail(self, @intCast(index), .stream_closed, null);
            return;
        }
    }

    pub const PeerFault = struct {
        identity: *const @import("../wire/peer_id.zig").PeerId,
        kind: RequestState.PeerFault,
    };

    /// Read each delivered terminal once, before the next pump recycles its slot.
    pub fn peerFault(self: *const ReqResp, event: Event) ?PeerFault {
        const handle = switch (event) {
            .failed => |e| e.request,
            .served => |e| e.request,
            else => return null,
        };
        if (handle.direction == .inbound) {
            if (handle.index >= self.inbound.len) return null;
            const slot = &self.inbound[handle.index];
            if (slot.request.generation != handle.generation or slot.request.completion != .reported) return null;
            return .{ .identity = &slot.identity, .kind = slot.request.peer_fault orelse return null };
        }
        if (handle.index >= self.outbound.len) return null;
        const slot = &self.outbound[handle.index];
        if (slot.request.generation != handle.generation or slot.request.completion != .reported) return null;
        return .{ .identity = &slot.identity, .kind = slot.request.peer_fault orelse return null };
    }

    /// Includes reqresp-owned storage. Caller response sinks and Router storage are separate.
    pub fn memoryPlan(self: *const ReqResp) MemoryPlan {
        const slot_bytes = self.outbound.len * @sizeOf(Client) + self.inbound.len * @sizeOf(Server);
        const limiter_bytes = self.limiter.buckets.len * @sizeOf(limiter_mod.Bucket) +
            self.limiter.generations.len * @sizeOf(?u32);
        const admission_bytes = self.admission.limiter.memoryPlan().allocated_bytes;
        return .{
            .facade_bytes = @sizeOf(ReqResp),
            .slot_bytes = slot_bytes,
            .io_bytes = self.arena.len,
            .limiter_bytes = limiter_bytes,
            .admission_bytes = admission_bytes,
            .request_sink_bytes = self.request_sinks.len,
            .serving_bytes = self.serving.memoryBytes(),
            .scheduler_bytes = self.peer_cursors.len * @sizeOf(PeerCursor),
            .total_bytes = @sizeOf(ReqResp) + slot_bytes + self.arena.len + limiter_bytes + admission_bytes + self.request_sinks.len + self.serving.memoryBytes() + self.peer_cursors.len * @sizeOf(PeerCursor),
        };
    }

    /// Monotonic milliseconds; zero capacity suppresses event-only wakeups.
    /// Router negotiation and transport deadlines remain separate.
    pub fn nextWakeup(self: *ReqResp, now: Now, capacities: Capacities) ?u64 {
        var due: ?u64 = null;
        for (self.outbound) |*slot| {
            const capacity = if (slot.request.protocol.isControl())
                capacities.control
            else
                capacities.application;
            if (slot.request.wakeup(capacity)) return now.mono_ms;
            if (slot.deadline()) |deadline| due = earlier(due, deadline);
        }
        for (self.inbound) |*slot| {
            const capacity = if (slot.request.protocol.isControl())
                capacities.control
            else
                capacities.application;
            if (slot.request.wakeup(capacity)) return now.mono_ms;
            if (slot.deadline(self)) |deadline| due = earlier(due, deadline);
            if (slot.request.running() and slot.state == .ready and
                self.serving.available(&slot.identity, slot.request.protocol.isControl()) != null)
                due = earlier(due, slot.eligible_ms);
            if (slot.request.running() and (slot.state == .withheld or slot.state == .waiting_capacity)) {
                if (self.limiter.nextToken(slot.request.conn, slot.request.protocol, now.mono_ms)) |eligible| {
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
        return self.inbound[index].receive.sink;
    }

    pub fn availableInbound(self: *ReqResp, peer: Handle, which: Protocol) ?u16 {
        const first = receive_plan.Plan.first(peer.index, which);
        for (self.inbound[first..][0..constants.MAX_CONCURRENT_REQUESTS], first..) |*slot, index| {
            if (slot.request.available()) return @intCast(index);
        }
        return null;
    }

    pub fn availableOutboundFor(self: *ReqResp, which: Protocol) ?u16 {
        const reserved = self.options.outbound_control_reserved;
        const start: usize = if (which.isControl()) 0 else reserved;
        const end: usize = if (which.isControl() and reserved > 0) reserved else self.outbound.len;
        for (self.outbound[start..end], start..) |*slot, index| {
            if (slot.request.available()) return @intCast(index);
        }
        return null;
    }

    pub const CompletionInfo = struct {
        phase_name: []const u8,
        rejection: ?@import("server.zig").Rejection = null,
        result_code: u8 = constants.result_success,
    };

    pub fn complete(owner: *ReqResp, record: *RequestState, index: u16, event: Event, info: CompletionInfo) void {
        if (!record.terminate(event)) return;
        const counts = &owner.protocol_counters[@intFromEnum(record.protocol)];
        const duration_ms = owner.last_now_ms -| record.started_ms;
        if (info.rejection != null) {
            owner.counters.malformed +|= 1;
        }
        if (event == .served) owner.counters.requests_served +|= 1;
        if (event == .served and info.result_code != constants.result_success) {
            owner.counters.error_responses_sent +|= 1;
            std.log.scoped(.network_reqresp_errors).debug("request_error_response request={d}:{d} connection={d}:{d} method={s} code={d} detail={s} chunks={d} elapsed_ms={d}", .{ index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), info.result_code, if (info.rejection) |err| @errorName(err) else "", record.chunks, duration_ms });
        } else if (event != .failed) std.log.scoped(.network_reqresp).debug("request_completed direction={s} request={d}:{d} connection={d}:{d} method={s} chunks={d} elapsed_ms={d}", .{ @tagName(record.direction), index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), record.chunks, duration_ms });
        if (record.direction == .outbound) counts.outgoing_time.observe(duration_ms) else counts.incoming_time.observe(duration_ms);
        if (event == .failed) owner.recordFailure(record, index, event, info);
    }

    fn recordFailure(owner: *ReqResp, record: *const RequestState, index: u16, event: Event, info: CompletionInfo) void {
        const reason = event.failed.reason;
        if (reason == .timeout) owner.counters.timeouts +|= 1;
        const counts = &owner.protocol_counters[@intFromEnum(record.protocol)];
        const duration_ms = owner.last_now_ms -| record.started_ms;
        const request_detail = info.rejection;
        if (reason == .cancelled) {
            if (record.direction == .outbound) counts.outgoing_cancelled +|= 1 else counts.incoming_cancelled +|= 1;
            std.log.scoped(.network_reqresp).debug("request_cancelled direction={s} request={d}:{d} connection={d}:{d} method={s} request_detail={s} chunks={d} elapsed_ms={d}", .{ @tagName(record.direction), index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), if (request_detail) |err| @errorName(err) else "", record.chunks, duration_ms });
        } else {
            const detail: []const u8 = switch (reason) {
                .invalid_response => |err| @errorName(err),
                .invalid_request => |err| @errorName(err),
                .negotiation_failed => |failure| @tagName(failure),
                else => record.failure_detail,
            };
            const peer_code: u16 = if (reason == .peer_error) reason.peer_error.code else 0;
            std.log.scoped(.network_reqresp_errors).debug("request_failed direction={s} request={d}:{d} connection={d}:{d} method={s} phase={s} reason={s} detail={s} request_detail={s} peer_code={d} chunks={d} elapsed_ms={d}", .{ @tagName(record.direction), index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), info.phase_name, @tagName(reason), detail, if (request_detail) |err| @errorName(err) else "", peer_code, record.chunks, duration_ms });
            owner.counters.failures += 1;
            if (record.direction == .outbound) {
                counts.outgoing_errors +|= 1;
                owner.outgoing_error_reasons[@intFromEnum(metrics.ErrorReason.fromFailure(reason, event.failed.phase.?))] +|= 1;
            } else counts.incoming_errors +|= 1;
        }
    }

    /// Latches one terminal result. Call cleanupPending before the next Router pump.
    pub fn cancel(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction == .outbound) {
            const slot = self.outboundSlot(handle) orelse return false;
            if (slot.request.terminalEvent() != null) return false;
            slot.fail(self, handle.index, .cancelled, null);
        } else {
            const slot = self.inboundSlot(handle) orelse return false;
            if (slot.request.terminalEvent() != null) return false;
            slot.fail(self, handle.index, .cancelled, null);
        }
        return true;
    }

    pub fn cleanupPending(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound) |*slot| slot.request.closePending(engine, router);
        for (self.inbound) |*slot| slot.request.closePending(engine, router);
    }

    pub fn cancelApplications(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound, 0..) |*slot, index| if (slot.request.active() and !slot.request.protocol.isControl()) {
            _ = self.cancel(slot.request.handle(@intCast(index)));
        };
        for (self.inbound, 0..) |*slot, index| if (slot.request.active() and !slot.request.protocol.isControl()) {
            _ = self.cancel(slot.request.handle(@intCast(index)));
        };
        self.cleanupPending(engine, router);
    }

    pub fn shutdown(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound, 0..) |*slot, index| if (slot.request.active()) {
            _ = self.cancel(slot.request.handle(@intCast(index)));
        };
        for (self.inbound, 0..) |*slot, index| if (slot.request.active()) {
            _ = self.cancel(slot.request.handle(@intCast(index)));
        };
        self.cleanupPending(engine, router);
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
        self.cleanupPending(engine, router);
        self.recycleDelivered();
        const total = self.outbound.len + self.options.peers;
        var serviced: usize = 0;
        // Empty capacity must not add owner turns between chunks of a runnable stream.
        for (0..total) |_| {
            if (serviced == self.options.work_per_pump_max) break;
            const position = self.work_cursor;
            self.work_cursor = (position + 1) % total;
            if (position < self.outbound.len) {
                const slot = &self.outbound[position];
                if (!slot.request.running()) continue;
                if (!slot.request.needs_service and slot.deadline().? > now.mono_ms) continue;
                slot.request.needs_service = false;
                slot.advance(self, engine, @intCast(position), now);
                serviced += 1;
            } else {
                const peer = position - self.outbound.len;
                const first = peer * receive_plan.slots_per_peer;
                const start = self.peer_cursors[peer].receive;
                for (0..receive_plan.slots_per_peer) |offset| {
                    const local = (start + offset) % receive_plan.slots_per_peer;
                    const index = first + local;
                    const slot = &self.inbound[index];
                    if (!self.inboundRunnable(slot, now)) continue;
                    self.peer_cursors[peer].receive = @intCast((local + 1) % receive_plan.slots_per_peer);
                    slot.request.needs_service = false;
                    slot.advance(self, engine, @intCast(index), now);
                    serviced += 1;
                    break;
                }
            }
        }
        self.promoteReady(now);
        // Cleanup also covers terminal transitions made during this turn.
        self.cleanupPending(engine, router);
    }

    fn inboundRunnable(self: *ReqResp, slot: *const Server, now: Now) bool {
        if (!slot.request.running()) return false;
        if (slot.request.needs_service or slot.deadline(self).? <= now.mono_ms) return true;
        if (slot.state == .withheld) {
            const eligible = self.limiter.nextToken(slot.request.conn, slot.request.protocol, now.mono_ms) orelse return true;
            return eligible <= now.mono_ms;
        }
        return false;
    }

    fn promoteReady(self: *ReqResp, now: Now) void {
        const start = self.admission_cursor;
        const first_class = self.admission_class;
        var promoted: usize = 0;
        for (0..self.options.peers) |offset| {
            for (0..2) |class_offset| {
                const class: u1 = @intCast((@as(usize, first_class) + class_offset) % 2);
                const peer: u16 = @intCast((start[class] + offset) % self.options.peers);
                const first = @as(usize, peer) * receive_plan.slots_per_peer;
                const end = first + receive_plan.slots_per_peer;
                const local_start = self.peer_cursors[peer].admission[class];
                for (0..end - first) |local_offset| {
                    const local = (local_start + local_offset) % (end - first);
                    const index = first + local;
                    const slot = &self.inbound[index];
                    if (!slot.request.running() or slot.request.conn.index != peer or slot.state != .ready or @intFromBool(slot.request.protocol.isControl()) != class) continue;
                    const paid = slot.admission_paid;
                    const admitted = slot.promote(self, @intCast(index), now);
                    if (admitted or slot.admission_paid > paid) {
                        promoted += 1;
                        self.peer_cursors[peer].admission[class] = @intCast((local + 1) % (end - first));
                        self.admission_cursor[class] = (peer + 1) % self.options.peers;
                        self.admission_class = 1 - class;
                        break;
                    }
                }
                if (promoted == self.options.work_per_pump_max) return;
            }
        }
    }

    fn drain(self: *ReqResp, now: Now, events: []Event, control: bool, cursor: *usize) usize {
        const total = self.outbound.len + self.inbound.len;
        var count: usize = 0;
        for (0..total) |_| {
            if (count == events.len) break;
            const position = cursor.*;
            cursor.* = (position + 1) % total;
            const event = if (position < self.outbound.len)
                self.outbound[position].request.deliver(control)
            else
                self.inbound[position - self.outbound.len].deliver(control, now);
            if (event) |ready| {
                events[count] = ready;
                count += 1;
            }
        }
        return count;
    }

    fn recycleDelivered(self: *ReqResp) void {
        for (self.outbound) |*slot| slot.request.recycleDelivered();
        for (self.inbound) |*slot| {
            if (slot.request.completion == .reported) {
                if (slot.execution) |index| self.serving.retire(index);
                slot.execution = null;
            }
            slot.request.recycleDelivered();
        }
    }

    pub fn servingSlot(self: *ReqResp, handle: RequestHandle) RespondError!*Server {
        if (handle.direction != .inbound) return error.StaleHandle;
        const slot = self.inboundSlot(handle) orelse return error.StaleHandle;
        if (!slot.request.running() or slot.request.waitingHost() or slot.state != .serving) return error.Busy;
        return slot;
    }

    pub fn outboundSlot(self: *ReqResp, handle: RequestHandle) ?*Client {
        const slots = self.outbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.request.generation != handle.generation or !slot.request.active()) return null;
        return slot;
    }
    pub fn inboundSlot(self: *ReqResp, handle: RequestHandle) ?*Server {
        const slots = self.inbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.request.generation != handle.generation or !slot.request.active()) return null;
        return slot;
    }

    pub fn outboundCount(self: *const ReqResp, conn: Handle, which: Protocol) u8 {
        var count: u8 = 0;
        for (self.outbound) |*slot| {
            if (!slot.request.active() or slot.request.protocol != which) continue;
            if (!std.meta.eql(slot.request.conn, conn)) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn outboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.outbound) |*slot| {
            if (!slot.request.occupied() or slot.request.protocol.isControl()) continue;
            if (std.meta.eql(slot.request.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.inbound) |*slot| {
            if (!slot.request.occupied() or slot.request.protocol.isControl()) continue;
            if (std.meta.eql(slot.request.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundCount(self: *const ReqResp, conn: Handle, which: ?Protocol) u8 {
        var count: u8 = 0;
        for (self.inbound) |*slot| {
            if (!slot.request.active() or !std.meta.eql(slot.request.conn, conn)) continue;
            if (which) |wanted| if (!slot.request.running() or slot.request.protocol != wanted) continue;
            count +|= 1;
        }
        return count;
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

const PeerCursor = struct { receive: u8 = 0, admission: [2]u16 = @splat(0) };

fn assignBuffers(io: *RequestIO, arena: []u8, cursor: usize, control: bool) usize {
    const scratch = if (control) control_scratch_length else scratch_length;
    const read_buffer = if (control) control_read_buffer_length else read_buffer_length;
    io.scratch = arena[cursor..][0..scratch];
    io.read_buffer = arena[cursor + scratch ..][0..read_buffer];
    return cursor + scratch + read_buffer;
}

comptime {
    assert(read_buffer_length >= 1024);
    assert(scratch_length >= codec.frame_scratch_max);
    assert(control_scratch_length < scratch_length);
    assert(control_read_buffer_length >= negotiate.inbox_capacity);
    assert(@sizeOf(Client) <= 2 * 1024);
    assert(@sizeOf(Server) <= 2 * 1024);
}

test {
    _ = @import("reqresp_admission_lifecycle_test.zig");
    _ = @import("reqresp_active_protocols_test.zig");
    _ = @import("reqresp_attribution_test.zig");
    _ = @import("reqresp_control_capacity_test.zig");
    _ = @import("reqresp_control_partition_test.zig");
    _ = @import("reqresp_failures_test.zig");
    _ = @import("reqresp_half_close_test.zig");
    _ = @import("reqresp_service_test.zig");
    _ = @import("reqresp_terminal_test.zig");
    _ = @import("reqresp_test.zig");
}
