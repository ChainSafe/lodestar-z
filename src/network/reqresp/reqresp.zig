const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const request_policy = @import("request_policy.zig");
const admission_mod = @import("admission.zig");
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
const index_list = @import("../index_list.zig");
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;

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

pub const InitError = admission_mod.InitError || error{InvalidPolicy};

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

pub const metrics = @import("metrics.zig");
pub const ProtocolCounters = metrics.ProtocolCounters;

pub const MemoryPlan = struct {
    facade_bytes: usize,
    slot_bytes: usize,
    io_bytes: usize,
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
    /// Per connection index: the admission lists' links and the `.ready` inbound slots per class.
    peer_cursors: []PeerCursor,
    /// Indexed by slot id: outbound slots are `[0, outbound.len)`, and inbound slot `i` is
    /// `outbound.len + i`, which belongs to connection index `i / slots_per_peer`.
    links: []SlotLinks,
    /// Running slots whose next advance can progress without a new stream event.
    ready: index_list.List = .{},
    /// Slots with a stream close still to issue.
    closing: index_list.List = .{},
    /// Slots with a pending notification or an undelivered terminal, per class
    /// (application, control).
    deliver: [2]index_list.List = .{ .{}, .{} },
    /// Slots whose terminal was delivered; recycled by the next pump.
    reported: index_list.List = .{},
    /// Running slots keyed on their deadline, or on their admission eligibility while waiting
    /// for their start or tokens.
    deadlines: DeadlineHeap,
    /// Per class, the connections with a `.ready` inbound slot.
    admission_ready: [2]index_list.List = .{ .{}, .{} },
    /// A `.ready` slot is due an admission attempt: it just became ready, its token wait ended,
    /// or serving capacity was released.
    admission_pending: bool = false,
    /// Per connection index, its occupied outbound slots.
    outbound_by_connection: []index_list.List,
    /// Slots taken from a list or the heap by pump. An idle owner visits none.
    visits: u64 = 0,
    policy: request_policy.Policy,
    admission: Admission,
    request_fork: config.ForkSeq,
    last_now_ms: u64 = 0,
    protocol_counters: [Protocol.count]ProtocolCounters = @splat(.{}),
    outgoing_error_reasons: [metrics.error_reason_count]u64 = @splat(0),
    forks: [64]ForkEntry = undefined,
    fork_count: u8 = 0,

    /// Occupied request slots and their undelivered events, inbound slots by phase, and serving
    /// resources held or retiring.
    pub const Resources = struct {
        outbound_occupied: usize = 0,
        inbound_phases: [metrics.inbound_phase_count]usize = @splat(0),
        pending_events: usize = 0,
        pending_terminals: usize = 0,
        serving_capacity: usize = 0,
        serving_occupied: usize = 0,
        retiring: usize = 0,
    };

    pub fn resourceSnapshot(self: *const ReqResp) Resources {
        var result: Resources = .{ .serving_capacity = self.serving.entries.len };
        for (self.serving.entries) |entry| {
            result.serving_occupied += @intFromBool(entry.request != null);
            result.retiring += @intFromBool(entry.retiring);
        }
        for (self.outbound) |*slot| {
            if (slot.request.occupied()) result.outbound_occupied += 1;
            if (slot.request.pendingEvent() != null) result.pending_events += 1;
            if (slot.request.terminalEvent() != null) result.pending_terminals += 1;
        }
        for (self.inbound) |*slot| {
            if (slot.occupancy()) |phase| result.inbound_phases[@intFromEnum(phase)] += 1;
            if (slot.request.pendingEvent() != null) result.pending_events += 1;
            if (slot.request.terminalEvent() != null) result.pending_terminals += 1;
        }
        return result;
    }

    pub fn recordAdmissionRefusal(self: *ReqResp, stream: StreamHandle, which: Protocol, reason: metrics.AdmissionRefusal, cost: u128) void {
        const reason_index = @intFromEnum(reason);
        const counts = &self.protocol_counters[@intFromEnum(which)];
        counts.admission_refusals[reason_index] +|= 1;
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

    pub fn validateOptions(options: Options) InitError!void {
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
        try validateForkTable(options.forks);
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!ReqResp {
        try validateOptions(options);
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
        const links = try allocator.alloc(SlotLinks, outbound.len + inbound.len);
        errdefer allocator.free(links);
        @memset(links, .{});
        var deadlines = try DeadlineHeap.init(allocator, @intCast(links.len));
        errdefer deadlines.deinit(allocator);
        const outbound_by_connection = try allocator.alloc(index_list.List, options.peers);
        errdefer allocator.free(outbound_by_connection);
        @memset(outbound_by_connection, .{});

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
            .links = links,
            .deadlines = deadlines,
            .outbound_by_connection = outbound_by_connection,
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
        self.serving.deinit(self.allocator);
        self.allocator.free(self.outbound_by_connection);
        self.deadlines.deinit(self.allocator);
        self.allocator.free(self.links);
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
        const handle = try Client.start(
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
        self.settle(handle.index);
        return handle;
    }

    /// Hands a negotiated stream to the outbound slot waiting for it. Returns false when none is.
    pub fn negotiated(self: *ReqResp, engine: *Engine, outcome: routing.Outcome, now: Now) bool {
        const index = Client.negotiated(self, engine, outcome, now) orelse return false;
        self.settle(index);
        return true;
    }

    /// Borrows request bytes from the owned inbound slot through served/failed delivery.
    pub fn accept(
        self: *ReqResp,
        engine: *Engine,
        stream: StreamHandle,
        ready: routing.Selection,
        now: Now,
    ) AcceptError!RequestHandle {
        const handle = try Server.accept(self, engine, stream, ready, now);
        self.settle(self.inboundId(handle.index));
        return handle;
    }

    /// Response bytes stay immutable through chunk_sent or terminal delivery.
    pub fn respond(
        self: *ReqResp,
        handle: RequestHandle,
        ssz: []const u8,
        context: ?ForkEntry,
        now: Now,
    ) RespondError!void {
        try Server.respond(self, handle, ssz, context, now);
        self.markReady(.inbound, handle.index);
        self.settle(self.inboundId(handle.index));
    }

    /// Copies the message; the caller may release it immediately.
    pub fn respondError(
        self: *ReqResp,
        handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) RespondError!void {
        try Server.respondError(self, handle, code, message, now);
        self.markReady(.inbound, handle.index);
        self.settle(self.inboundId(handle.index));
    }

    pub fn finish(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        if (!Server.finish(self, handle, now)) return false;
        self.settle(self.inboundId(handle.index));
        return true;
    }

    /// Hold execution capacity until asynchronous host work actually retires.
    pub fn retainServing(self: *ReqResp, handle: RequestHandle) bool {
        return self.serving.retain(handle);
    }

    /// A release may free serving capacity for a `.ready` slot.
    pub fn releaseServing(self: *ReqResp, handle: RequestHandle) bool {
        if (!self.serving.release(handle)) return false;
        self.admission_pending = true;
        return true;
    }

    /// Reserve one response turn before the host produces its next chunk.
    pub fn reserveResponse(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction != .inbound) return false;
        const slot = self.inboundSlot(handle) orelse return false;
        return slot.reserveResponse();
    }

    /// Supply fresh owner time so host-held chunks cannot become remote timeout evidence.
    pub fn consume(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        if (!Client.consume(self, handle, now)) return false;
        self.settle(handle.index);
        return true;
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

    /// Read retained Goodbye bytes before the close event cancels streams and releases their sinks.
    pub fn closingGoodbye(self: *ReqResp, engine: *Engine, conn: Handle, now: Now) ?u64 {
        assert(now.mono_ms >= self.last_now_ms);
        self.last_now_ms = now.mono_ms;
        if (conn.index >= self.options.peers) return null;
        const first = receive_plan.Plan.first(conn.index, .goodbye_v1);
        for (first..first + constants.MAX_CONCURRENT_REQUESTS) |position| {
            const index: u16 = @intCast(position);
            const slot = &self.inbound[index];
            if (!slot.request.running() or slot.request.protocol != .goodbye_v1 or !std.meta.eql(slot.request.conn, conn)) continue;
            defer self.settle(self.inboundId(index));
            if (slot.state != .receiving_request and slot.state != .ready and (slot.request.pendingEvent() == null or slot.request.pendingEvent().? != .request)) continue;
            if (slot.state == .receiving_request and slot.request.pendingEvent() == null) Server.readRequest(self, engine, slot, index, now);
            if (slot.request.running() and slot.state == .ready) {
                const bytes = slot.request.io.decoder.payload();
                assert(bytes.len == @import("consensus_types").phase0.Goodbye.fixed_size);
                slot.state = .serving;
                return std.mem.readInt(u64, bytes[0..8], .little);
            }
            if (slot.request.pendingEvent()) |event| if (event == .request) {
                assert(event.request.bytes.len == 8);
                slot.request.notification = .none;
                slot.state = .serving;
                return std.mem.readInt(u64, event.request.bytes[0..8], .little);
            };
            std.log.scoped(.network_reqresp_errors).debug("goodbye_incomplete_on_close request={d}:{d} connection={d}:{d} stream={d} buffered_bytes={d} decoded_bytes={d} decoder_phase={s} fin={any} detail={s}", .{ index, slot.request.generation, conn.index, conn.generation, slot.request.stream.id, slot.request.io.buffered_end - slot.request.io.buffered_start, if (slot.request.io.decoding) slot.request.io.decoder.written else 0, if (slot.request.io.decoding) @tagName(slot.request.io.decoder.phase) else "cleared", slot.request.io.fin_seen, slot.request.failure_detail });
        }
        return null;
    }

    /// Fails the connection's slots: its outbound list and its inbound block of the receive plan.
    pub fn connectionClosed(self: *ReqResp, conn: Handle) void {
        if (conn.index >= self.options.peers) return;
        const list = &self.outbound_by_connection[conn.index];
        var cursor = list.head;
        for (0..self.outbound.len) |_| {
            if (cursor == index_list.none) break;
            const index: u16 = @intCast(cursor);
            cursor = self.outbound[index].conn_link.next;
            const slot = &self.outbound[index];
            if (!slot.request.active() or !std.meta.eql(slot.request.conn, conn)) continue;
            slot.fail(self, index, .connection_closed, null);
            self.settle(index);
        }
        const first = receive_plan.Plan.first(conn.index, @enumFromInt(0));
        for (first..first + receive_plan.slots_per_peer) |position| {
            const index: u16 = @intCast(position);
            const slot = &self.inbound[index];
            if (!slot.request.active() or !std.meta.eql(slot.request.conn, conn)) continue;
            slot.fail(self, index, .connection_closed, null);
            self.settle(self.inboundId(index));
        }
    }

    /// A routed stream event. An event for a stream the slot no longer holds is dropped.
    pub fn streamReady(self: *ReqResp, route: types.Route, stream: StreamHandle) void {
        const id = self.routedSlot(route, stream) orelse return;
        self.markId(id);
    }

    /// A routed stream close. A reset fails an inbound slot that is not writing its response;
    /// any other close is observed by the slot's next stream call.
    pub fn streamClosed(self: *ReqResp, route: types.Route, stream: StreamHandle, reset_code: ?u64) void {
        const id = self.routedSlot(route, stream) orelse return;
        if (reset_code != null and route.owner == .reqresp_inbound) {
            const index: u16 = @intCast(route.row);
            const slot = &self.inbound[index];
            if (slot.state != .writing_chunk and slot.state != .finishing) {
                slot.fail(self, index, .stream_closed, null);
                self.settle(id);
                return;
            }
        }
        self.markId(id);
    }

    fn routedSlot(self: *const ReqResp, route: types.Route, stream: StreamHandle) ?u32 {
        const id: u32 = switch (route.owner) {
            .reqresp_outbound => if (route.row < self.outbound.len) route.row else return null,
            .reqresp_inbound => if (route.row < self.inbound.len) self.inboundId(@intCast(route.row)) else return null,
            else => return null,
        };
        const record = self.recordOf(id);
        if (!record.running() or !std.meta.eql(record.stream, stream)) return null;
        return id;
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
        const admission_bytes = self.admission.limiter.memoryPlan().allocated_bytes;
        return .{
            .facade_bytes = @sizeOf(ReqResp),
            .slot_bytes = slot_bytes,
            .io_bytes = self.arena.len,
            .admission_bytes = admission_bytes,
            .request_sink_bytes = self.request_sinks.len,
            .serving_bytes = self.serving.memoryBytes(),
            .scheduler_bytes = self.schedulerBytes(),
            .total_bytes = @sizeOf(ReqResp) + slot_bytes + self.arena.len + admission_bytes + self.request_sinks.len + self.serving.memoryBytes() + self.schedulerBytes(),
        };
    }

    fn schedulerBytes(self: *const ReqResp) usize {
        return self.peer_cursors.len * @sizeOf(PeerCursor) + self.links.len * @sizeOf(SlotLinks) +
            self.deadlines.entries.len * (@sizeOf(DeadlineHeap.Entry) + @sizeOf(u32)) + self.outbound_by_connection.len * @sizeOf(index_list.List);
    }

    /// Monotonic milliseconds; zero capacity suppresses event-only wakeups. Reads list lengths and
    /// the heap top only. Router negotiation and transport deadlines remain separate.
    pub fn nextWakeup(self: *const ReqResp, now: Now, capacities: Capacities) ?u64 {
        if (self.ready.len > 0 or self.closing.len > 0 or self.reported.len > 0) return now.mono_ms;
        if (capacities.application > 0 and self.deliver[0].len > 0) return now.mono_ms;
        if (capacities.control > 0 and self.deliver[1].len > 0) return now.mono_ms;
        if (self.admission_pending and self.admission_ready[0].len + self.admission_ready[1].len > 0) return now.mono_ms;
        const top = self.deadlines.peek() orelse return null;
        return @max(top.deadline, now.mono_ms);
    }

    /// Validate every raw admission against the attached transport capacity.
    pub fn attach(self: *const ReqResp, engine: *const Engine) error{InvalidCapacity}!void {
        if (engine.limits.connections_max > self.options.peers) return error.InvalidCapacity;
    }

    pub fn inboundSink(self: *ReqResp, index: u16) []u8 {
        assert(index < self.inbound.len);
        return self.inbound[index].receive.sink;
    }

    fn inboundId(self: *const ReqResp, index: u16) u32 {
        assert(index < self.inbound.len);
        return @intCast(self.outbound.len + index);
    }

    pub fn markReady(self: *ReqResp, direction: types.Direction, index: u16) void {
        self.markId(switch (direction) {
            .outbound => index,
            .inbound => self.inboundId(index),
        });
    }

    fn markId(self: *ReqResp, id: u32) void {
        assert(self.recordOf(id).running());
        _ = self.ready.insert(self.links, "ready", id);
    }

    fn recordOf(self: *const ReqResp, id: u32) *RequestState {
        if (id < self.outbound.len) return &self.outbound[id].request;
        return &self.inbound[id - self.outbound.len].request;
    }

    fn eventList(self: *ReqResp, which: EventList) *index_list.List {
        return switch (which) {
            .none => unreachable,
            .application => &self.deliver[0],
            .control => &self.deliver[1],
            .reported => &self.reported,
        };
    }

    fn wantedEvent(record: *const RequestState) EventList {
        if (record.completion == .reported) return .reported;
        if (!record.deliverable()) return .none;
        return if (record.protocol.isControl()) .control else .application;
    }

    fn deadlineOf(self: *const ReqResp, id: u32) ?u64 {
        if (id < self.outbound.len) return self.outbound[id].deadline();
        const slot = &self.inbound[id - self.outbound.len];
        const due = slot.deadline(self) orelse return null;
        if (slot.state == .ready and (slot.admission_wait == .start or slot.admission_wait == .tokens)) return @min(due, slot.eligible_ms);
        return due;
    }

    /// Brings the slot's scheduling in line with its state after a change made by its own module.
    pub fn settleSlot(self: *ReqResp, direction: types.Direction, index: u16) void {
        self.settle(switch (direction) {
            .outbound => index,
            .inbound => self.inboundId(index),
        });
    }

    /// Brings the slot's closing, delivery and admission memberships and its heap key in line
    /// with its state. Every change to a slot outside `advance` ends here.
    fn settle(self: *ReqResp, id: u32) void {
        const links = &self.links[id];
        const record = self.recordOf(id);
        const closing = record.close_code != null;
        if (closing and !links.close.linked) self.closing.append(self.links, "close", id);
        if (!closing and links.close.linked) self.closing.remove(self.links, "close", id);
        const wanted = wantedEvent(record);
        if (wanted != links.event_list) {
            if (links.event_list != .none) self.eventList(links.event_list).remove(self.links, "event", id);
            if (wanted != .none) self.eventList(wanted).append(self.links, "event", id);
            links.event_list = wanted;
        }
        if (!record.running() and links.ready.linked) self.ready.remove(self.links, "ready", id);
        if (self.deadlineOf(id)) |key| self.deadlines.set(id, key) else self.deadlines.clear(id);
        if (id >= self.outbound.len) self.settleAdmission(@intCast(id - self.outbound.len));
    }

    fn settleAdmission(self: *ReqResp, index: u16) void {
        const slot = &self.inbound[index];
        const peer = index / receive_plan.slots_per_peer;
        const bit = @as(u64, 1) << @intCast(index % receive_plan.slots_per_peer);
        const class: u1 = @intFromBool(slot.request.protocol.isControl());
        const cursor = &self.peer_cursors[peer];
        const waiting = slot.request.running() and slot.state == .ready;
        if (waiting and cursor.ready_mask[class] & bit == 0 and slot.admission_wait == .none) self.admission_pending = true;
        if (waiting) cursor.ready_mask[class] |= bit else cursor.ready_mask[class] &= ~bit;
        switch (class) {
            inline else => |which| {
                const field = PeerCursor.link_fields[which];
                const linked = @field(cursor, field).linked;
                if (cursor.ready_mask[which] != 0 and !linked) self.admission_ready[which].append(self.peer_cursors, field, peer);
                if (cursor.ready_mask[which] == 0 and linked) self.admission_ready[which].remove(self.peer_cursors, field, peer);
            },
        }
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
        if (event == .served and info.result_code != constants.result_success) {
            std.log.scoped(.network_reqresp_errors).debug("request_error_response request={d}:{d} connection={d}:{d} method={s} code={d} detail={s} chunks={d} elapsed_ms={d}", .{ index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), info.result_code, if (info.rejection) |err| @errorName(err) else "", record.chunks, duration_ms });
        } else if (event != .failed) std.log.scoped(.network_reqresp).debug("request_completed direction={s} request={d}:{d} connection={d}:{d} method={s} chunks={d} elapsed_ms={d}", .{ @tagName(record.direction), index, record.generation, record.conn.index, record.conn.generation, @tagName(record.protocol), record.chunks, duration_ms });
        if (record.direction == .outbound) counts.outgoing_time.observe(duration_ms) else counts.incoming_time.observe(duration_ms);
        if (event == .failed) owner.recordFailure(record, index, event, info);
    }

    fn recordFailure(owner: *ReqResp, record: *const RequestState, index: u16, event: Event, info: CompletionInfo) void {
        const reason = event.failed.reason;
        const counts = &owner.protocol_counters[@intFromEnum(record.protocol)];
        const duration_ms = owner.last_now_ms -| record.started_ms;
        const request_detail = info.rejection;
        if (reason == .cancelled) {
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
            self.settle(handle.index);
        } else {
            const slot = self.inboundSlot(handle) orelse return false;
            if (slot.request.terminalEvent() != null) return false;
            slot.fail(self, handle.index, .cancelled, null);
            self.settle(self.inboundId(handle.index));
        }
        return true;
    }

    /// Issues the stream closes of the slots on `closing`.
    pub fn cleanupPending(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        var closed: usize = 0;
        while (self.closing.pop(self.links, "close")) |id| : (closed += 1) {
            assert(closed < self.links.len);
            self.visits +|= 1;
            self.recordOf(id).closePending(engine, router);
            self.settle(id);
        }
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
        const exhausted = self.advance(engine, router, now);
        const counts: OutputCounts = .{
            .application = self.drain(now, outputs.application, false),
            .control = self.drain(now, outputs.control, true),
        };
        if (@import("builtin").is_test) self.checkInvariants(engine, now, exhausted);
        return counts;
    }

    /// Closes, recycles, then services the due keys and the ready slots up to
    /// `work_per_pump_max`, then admits `.ready` slots. Returns whether the budget ran out.
    /// A due key goes first, so runnable slots cannot hold a deadline past its time; servicing
    /// one retires its slot or moves its key into the future. A slot re-marked while serviced
    /// waits for the next pump, behind the slots marked before it.
    fn advance(self: *ReqResp, engine: *Engine, router: *routing.Router, now: Now) bool {
        assert(now.mono_ms >= self.last_now_ms or self.last_now_ms == 0);
        self.last_now_ms = now.mono_ms;
        self.cleanupPending(engine, router);
        self.recycleDelivered();
        // The slots marked before this pump that are still on `ready`.
        var marked = self.ready.len;
        const keyed: usize = self.deadlines.len;
        var serviced: usize = 0;
        // A due key comes back at most once more, when its start or token wait ended before its
        // deadline.
        for (0..marked + 2 * keyed + 1) |_| {
            if (serviced == self.options.work_per_pump_max) break;
            const due = self.deadlines.popDue(now.mono_ms);
            const id: u32 = due orelse ready: {
                if (marked == 0) break;
                marked -= 1;
                break :ready self.ready.pop(self.links, "ready").?;
            };
            self.visits +|= 1;
            if (due != null and id >= self.outbound.len) {
                const slot = &self.inbound[id - self.outbound.len];
                if (slot.request.running() and slot.state == .ready and now.mono_ms < slot.deadline(self).?) {
                    // Only its start or token wait ended.
                    slot.admission_wait = .none;
                    self.admission_pending = true;
                    self.settle(id);
                    continue;
                }
            }
            if (self.links[id].ready.linked) {
                // A serviced slot's key lies in the future, so a due slot was not serviced
                // earlier in this pump and is on `ready` from a mark made before it.
                assert(marked > 0);
                marked -= 1;
                self.ready.remove(self.links, "ready", id);
            }
            if (id < self.outbound.len) {
                self.outbound[id].advance(self, engine, @intCast(id), now);
            } else self.inbound[id - self.outbound.len].advance(self, engine, @intCast(id - self.outbound.len), now);
            serviced += 1;
            self.settle(id);
        }
        const exhausted = serviced == self.options.work_per_pump_max;
        self.promoteReady(now);
        // Cleanup also covers terminal transitions made during this turn.
        self.cleanupPending(engine, router);
        return exhausted;
    }

    /// One admission attempt per connection per class, control first. A connection that was
    /// admitted moves to the tail; one that was not keeps its place ahead of it.
    fn promoteReady(self: *ReqResp, now: Now) void {
        if (!self.admission_pending) return;
        self.admission_pending = false;
        var promoted: usize = 0;
        inline for (.{ 1, 0 }) |class| {
            const field = PeerCursor.link_fields[class];
            const list = &self.admission_ready[class];
            var next = list.head;
            // Each visited connection is behind every unvisited one once moved, so each
            // connection on the list is visited once.
            for (0..list.len) |_| {
                if (next == index_list.none) break;
                if (promoted == self.options.work_per_pump_max) {
                    self.admission_pending = true;
                    return;
                }
                const peer: u16 = @intCast(next);
                const cursor = &self.peer_cursors[peer];
                next = @field(cursor, field).next;
                if (self.promotePeer(peer, class, now)) {
                    promoted += 1;
                    // The connection's other `.ready` slots wait for the next round.
                    if (cursor.ready_mask[class] != 0) {
                        self.admission_pending = true;
                        list.remove(self.peer_cursors, field, peer);
                        list.append(self.peer_cursors, field, peer);
                    }
                }
            }
        }
    }

    /// Tries the connection's `.ready` slots of the class in turn until one is admitted, is
    /// charged its start or pays toward its cost.
    fn promotePeer(self: *ReqResp, peer: u16, comptime class: u1, now: Now) bool {
        const cursor = &self.peer_cursors[peer];
        const first = @as(usize, peer) * receive_plan.slots_per_peer;
        const start = cursor.admission[class];
        for (0..receive_plan.slots_per_peer) |offset| {
            const local: u8 = @intCast((start + offset) % receive_plan.slots_per_peer);
            if (cursor.ready_mask[class] & (@as(u64, 1) << @intCast(local)) == 0) continue;
            const index: u16 = @intCast(first + local);
            const slot = &self.inbound[index];
            self.visits +|= 1;
            const paid = slot.admission_paid;
            const start_pending = slot.start_pending;
            const admitted = slot.promote(self, index, now);
            self.settle(self.inboundId(index));
            if (admitted or slot.admission_paid > paid or start_pending != slot.start_pending) {
                cursor.admission[class] = @intCast((local + 1) % receive_plan.slots_per_peer);
                return true;
            }
        }
        return false;
    }

    /// Delivers at most one event per queued slot, in queue order.
    fn drain(self: *ReqResp, now: Now, events: []Event, control: bool) usize {
        const class: EventList = if (control) .control else .application;
        const list = self.eventList(class);
        const queued = list.len;
        var count: usize = 0;
        for (0..queued) |_| {
            if (count == events.len) break;
            const id = list.pop(self.links, "event").?;
            self.links[id].event_list = .none;
            self.visits +|= 1;
            if (id < self.outbound.len) {
                events[count] = self.outbound[id].request.deliver(control).?;
            } else {
                const slot = &self.inbound[id - self.outbound.len];
                events[count] = slot.deliver(control, now).?;
                if (slot.request.running() and slot.state == .finishing) self.markId(id);
            }
            count += 1;
            self.settle(id);
        }
        return count;
    }

    fn recycleDelivered(self: *ReqResp) void {
        var recycled: usize = 0;
        while (self.reported.pop(self.links, "event")) |id| : (recycled += 1) {
            assert(recycled < self.links.len);
            self.links[id].event_list = .none;
            self.visits +|= 1;
            if (id < self.outbound.len) {
                const slot = &self.outbound[id];
                slot.request.recycleDelivered();
                self.outbound_by_connection[slot.request.conn.index].remove(self.outbound, "conn_link", id);
            } else {
                const slot = &self.inbound[id - self.outbound.len];
                if (slot.execution) |index| {
                    self.serving.retire(index);
                    self.admission_pending = true;
                }
                slot.execution = null;
                slot.request.recycleDelivered();
            }
            self.settle(id);
        }
    }

    /// Test builds check, after every pump, that the lists, the heap and the admission masks
    /// match the slot states, that no slot with stream work is off `ready`, that a pump with
    /// budget to spare left no due key, and that each live stream a slot holds routes to it and
    /// back.
    fn checkInvariants(self: *const ReqResp, engine: *const Engine, now: Now, exhausted: bool) void {
        var lengths: struct { ready: usize = 0, closing: usize = 0, events: [4]usize = @splat(0) } = .{};
        for (self.links, 0..) |*links, position| {
            const id: u32 = @intCast(position);
            const record = self.recordOf(id);
            lengths.ready += @intFromBool(links.ready.linked);
            lengths.closing += @intFromBool(links.close.linked);
            lengths.events[@intFromEnum(links.event_list)] += 1;
            assert(links.close.linked == (record.close_code != null));
            assert(links.event_list == wantedEvent(record));
            assert(!links.ready.linked or record.running());
            if (!record.running()) {
                assert(self.deadlines.get(id) == null);
            } else if (!links.ready.linked) assert(self.deadlines.get(id).? == self.deadlineOf(id).?);
            const direction: types.Direction = if (id < self.outbound.len) .outbound else .inbound;
            const index: u16 = @intCast(if (direction == .outbound) id else id - self.outbound.len);
            // Admission, which runs after servicing, alone keys a slot due now: a token wait
            // that ends within this millisecond.
            if (!exhausted) if (self.deadlines.get(id)) |key| if (key <= now.mono_ms) {
                assert(direction == .inbound);
                const slot = &self.inbound[index];
                assert(slot.state == .ready and slot.admission_wait == .tokens and slot.eligible_ms == now.mono_ms);
            };
            if (direction == .inbound) {
                const slot = &self.inbound[index];
                const bit = @as(u64, 1) << @intCast(index % receive_plan.slots_per_peer);
                const class: u1 = @intFromBool(record.protocol.isControl());
                const waiting = record.running() and slot.state == .ready;
                const cursor = &self.peer_cursors[index / receive_plan.slots_per_peer];
                assert((cursor.ready_mask[class] & bit != 0) == waiting);
                if (waiting) assert(PeerCursor.linked(self.peer_cursors, class, index / receive_plan.slots_per_peer));
                if (waiting and slot.admission_wait == .none) assert(self.admission_pending);
            }
            if (!record.active() or record.stream_owner != .protocol) continue;
            const bound = engine.route(record.stream) orelse continue;
            assert(bound.owner == (if (direction == .outbound) types.StreamOwner.reqresp_outbound else .reqresp_inbound) and bound.row == index);
            if (!record.running() or links.ready.linked) continue;
            const waits = engine.streamWaits(record.stream) orelse continue;
            switch (direction) {
                .outbound => {
                    const slot = &self.outbound[index];
                    if (record.waitingHost()) continue;
                    switch (slot.phase) {
                        .negotiation => {},
                        .request => if (record.io.writing or !record.io.outbox.idle()) assert(waits.write_waiting),
                        .response => assertDrained(record, waits),
                    }
                },
                .inbound => {
                    const slot = &self.inbound[index];
                    if (record.waitingHost() or slot.state == .serving) continue;
                    switch (slot.state) {
                        .ready, .serving => {},
                        .receiving_request => assertDrained(record, waits),
                        .writing_chunk, .finishing => assert(waits.write_waiting),
                    }
                },
            }
        }
        assert(lengths.ready == self.ready.len and lengths.closing == self.closing.len);
        assert(lengths.events[@intFromEnum(EventList.application)] == self.deliver[0].len);
        assert(lengths.events[@intFromEnum(EventList.control)] == self.deliver[1].len);
        assert(lengths.events[@intFromEnum(EventList.reported)] == self.reported.len);
        for (engine.registry.slots, 0..) |*connection, conn_index| {
            // A closing connection keeps its streams until retired, and closes nothing more.
            if (connection.state != .established or connection.pending_close != null or connection.close_reason != null) continue;
            for (&connection.table.entries, 0..) |*entry, entry_index| {
                if (!entry.claimed or entry.closed_pending) continue;
                const direction: types.Direction = switch (entry.route.owner) {
                    .reqresp_outbound => .outbound,
                    .reqresp_inbound => .inbound,
                    else => continue,
                };
                const record: *const RequestState = if (direction == .outbound) &self.outbound[entry.route.row].request else &self.inbound[entry.route.row].request;
                assert(record.active() and record.stream_owner == .protocol);
                assert(std.meta.eql(record.stream, StreamHandle{ .conn = .{ .index = @intCast(conn_index), .generation = connection.generation }, .id = entry.id, .slot = @intCast(entry_index) }));
            }
        }
    }

    /// A reading slot off `ready` has consumed its buffered input and read its last delivered
    /// readable edge to Done.
    fn assertDrained(record: *const RequestState, waits: Engine.StreamWaits) void {
        assert(record.io.buffered_start == record.io.buffered_end and !record.io.fin_seen);
        assert(!waits.read_open);
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
        var cursor = if (conn.index < self.options.peers) self.outbound_by_connection[conn.index].head else index_list.none;
        for (0..self.outbound.len) |_| {
            if (cursor == index_list.none) break;
            const slot = &self.outbound[cursor];
            cursor = slot.conn_link.next;
            if (!slot.request.active() or slot.request.protocol != which) continue;
            if (!std.meta.eql(slot.request.conn, conn)) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn outboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        var cursor = if (conn.index < self.options.peers) self.outbound_by_connection[conn.index].head else index_list.none;
        for (0..self.outbound.len) |_| {
            if (cursor == index_list.none) break;
            const slot = &self.outbound[cursor];
            cursor = slot.conn_link.next;
            if (!slot.request.occupied() or slot.request.protocol.isControl()) continue;
            if (std.meta.eql(slot.request.conn, conn)) count += 1;
        }
        return count;
    }

    /// The connection's block of the receive plan.
    fn inboundOf(self: *const ReqResp, conn: Handle) []const Server {
        if (conn.index >= self.options.peers) return &.{};
        return self.inbound[receive_plan.Plan.first(conn.index, @enumFromInt(0))..][0..receive_plan.slots_per_peer];
    }

    pub fn inboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.inboundOf(conn)) |*slot| {
            if (!slot.request.occupied() or slot.request.protocol.isControl()) continue;
            if (std.meta.eql(slot.request.conn, conn)) count += 1;
        }
        return count;
    }

    /// Whether a running request of the class on the connection is still owed its start.
    pub fn startsPending(self: *const ReqResp, conn: Handle, control: bool) bool {
        for (self.inboundOf(conn)) |*slot| {
            if (!slot.start_pending or !slot.request.running() or slot.request.protocol.isControl() != control) continue;
            if (std.meta.eql(slot.request.conn, conn)) return true;
        }
        return false;
    }

    /// Whether another `.ready` request of the slot's class on its connection has waited longer
    /// for its start, by accept time and then slot order. Starts go to the longest waiter, so a
    /// waiter's start comes within one refill per request ahead of it.
    pub fn startQueued(self: *const ReqResp, index: u16) bool {
        const slot = &self.inbound[index];
        const peer = index / receive_plan.slots_per_peer;
        const first = @as(usize, peer) * receive_plan.slots_per_peer;
        var mask = self.peer_cursors[peer].ready_mask[@intFromBool(slot.request.protocol.isControl())];
        for (0..receive_plan.slots_per_peer) |_| {
            if (mask == 0) break;
            const other = first + @ctz(mask);
            mask &= mask - 1;
            const waiter = &self.inbound[other];
            if (other == index or !waiter.start_pending) continue;
            if (waiter.request.started_ms < slot.request.started_ms) return true;
            if (waiter.request.started_ms == slot.request.started_ms and other < index) return true;
        }
        return false;
    }

    pub fn inboundCount(self: *const ReqResp, conn: Handle, which: ?Protocol) u8 {
        var count: u8 = 0;
        for (self.inboundOf(conn)) |*slot| {
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

/// Per connection index: where the next admission attempt starts, the `.ready` inbound slots and
/// the admission list links, per class (application, control).
const PeerCursor = struct {
    admission: [2]u8 = @splat(0),
    ready_mask: [2]u64 = @splat(0),
    application_link: index_list.Link = .{},
    control_link: index_list.Link = .{},

    const link_fields = [2][]const u8{ "application_link", "control_link" };

    fn linked(rows: []const PeerCursor, class: u1, peer: u32) bool {
        return if (class == 0) rows[peer].application_link.linked else rows[peer].control_link.linked;
    }
};

const EventList = enum(u2) { none, application, control, reported };

const SlotLinks = struct {
    ready: index_list.Link = .{},
    close: index_list.Link = .{},
    /// On `deliver[class]` or `reported`, as `event_list` names.
    event: index_list.Link = .{},
    event_list: EventList = .none,
};

comptime {
    assert(receive_plan.slots_per_peer <= 64);
}

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
    _ = @import("reqresp_request_start_test.zig");
    _ = @import("reqresp_service_test.zig");
    _ = @import("reqresp_terminal_test.zig");
    _ = @import("reqresp_test.zig");
}
