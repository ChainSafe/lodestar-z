const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const limiter_mod = @import("limiter.zig");
const protocol_mod = @import("protocol.zig");
const config = @import("config");
const engine_mod = @import("../quic/engine.zig");
const limits = @import("../quic/limits.zig");
const negotiate = @import("../negotiate.zig");
const Client = @import("client.zig").Client;
const Server = @import("server.zig").Server;
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

pub const ForkEntry = struct {
    digest: [constants.context_bytes_length]u8,
    fork: config.ForkSeq,
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
    progress_timeout_ms: u64 = constants.progress_timeout_ms_default,
    forks: []const ForkEntry,
    quotas: ?limiter_mod.Quotas = null,
    /// Defaults reserve one inbound-capacity control wave; bulk quotas stay per protocol.
    global_quotas: ?limiter_mod.Quotas = null,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    work_per_pump_max: u16 = 32,
};

pub const RequestOptions = struct {
    expected_chunks: ?u32 = null,
    progress_timeout_ms: ?u64 = null,
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
    invalid_response: codec.Error,
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
    failed: struct { request: RequestHandle, reason: Failure },
    request: struct { request: RequestHandle, peer: Handle, protocol: Protocol, bytes: []const u8 },
    chunk_sent: struct { request: RequestHandle, chunks: u32 },
    served: struct { request: RequestHandle, chunks: u32 },
    over_limit: struct { peer: Handle, protocol: Protocol },
};

pub const PartitionedCounts = struct { application: usize, control: usize };

pub const InitError = limiter_mod.InitError;

pub const RequestError = error{
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
    SinkTooSmall,
    UnknownProtocol,
};

pub const RespondError = error{
    InvalidError,
    StaleHandle,
    Busy,
    UnknownFork,
    ChunkTooLarge,
    ChunkTooSmall,
    TooManyChunks,
};

pub const Counters = struct {
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
};

const OverLimit = struct {
    peer: Handle,
    protocol: Protocol,
};

pub const MemoryPlan = struct {
    facade_bytes: usize,
    slot_bytes: usize,
    io_bytes: usize,
    limiter_bytes: usize,
    request_sink_bytes: usize = 0,
    total_bytes: usize,
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    options: Options,
    outbound: []Client,
    inbound: []Server,
    arena: []u8,
    limiter: limiter_mod.Limiter,
    over_limit: [over_limit_queue_max]OverLimit = undefined,
    over_limit_head: u8 = 0,
    over_limit_len: u8 = 0,
    last_now_ms: u64 = 0,
    counters: Counters = .{},
    forks: [64]ForkEntry = undefined,
    fork_count: u8 = 0,
    work_cursor: usize = 0,
    event_cursor: usize = 0,
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
            if (slot.state != .free) result.outbound_occupied += 1;
            if (slot.pending_event != null) result.pending_events += 1;
            if (slot.terminal != null) result.pending_terminals += 1;
            if (slot.chunk_held) result.held_chunks += 1;
        }
        for (self.inbound) |*slot| {
            if (slot.state != .free) result.inbound_occupied += 1;
            if (slot.pending_event != null) result.pending_events += 1;
            if (slot.terminal != null) result.pending_terminals += 1;
            if (slot.withheld_since_ms) |since| {
                result.withheld_chunks += 1;
                result.oldest_withheld_age_ms = @max(result.oldest_withheld_age_ms orelse 0, self.last_now_ms -| since);
            }
        }
        return result;
    }

    pub fn validateOptions(options: Options) InitError!struct { peer: limiter_mod.Quotas, global: limiter_mod.Quotas } {
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
        if (options.forks.len > 64) return error.InvalidOptions;

        return .{ .peer = peer_quotas, .global = global_quotas };
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!ReqResp {
        const quotas = try validateOptions(options);

        const outbound = try allocator.alloc(Client, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(outbound, .{});
        const inbound = try allocator.alloc(Server, options.inbound_max);
        errdefer allocator.free(inbound);
        @memset(inbound, .{});

        const total = @as(usize, options.outbound_max) + options.inbound_max;
        const arena = try allocator.alloc(u8, total * (scratch_length + read_buffer_length));
        errdefer allocator.free(arena);
        var cursor: usize = 0;
        for (outbound) |*slot| cursor = assignBuffers(slot, arena, cursor);
        for (inbound) |*slot| cursor = assignBuffers(slot, arena, cursor);
        assert(cursor == arena.len);

        var buckets = try limiter_mod.Limiter.initWithGlobal(
            allocator,
            options.peers,
            quotas.peer,
            quotas.global,
        );
        errdefer buckets.deinit(allocator);

        var resolved_options = options;
        resolved_options.forks = &.{};
        resolved_options.quotas = quotas.peer;
        resolved_options.global_quotas = quotas.global;
        var result: ReqResp = .{
            .allocator = allocator,
            .options = resolved_options,
            .outbound = outbound,
            .inbound = inbound,
            .arena = arena,
            .limiter = buckets,
            .fork_count = @intCast(options.forks.len),
        };
        @memcpy(result.forks[0..options.forks.len], options.forks);
        return result;
    }

    /// Call shutdown first, or destroy the attached transport and Router before deinit.
    pub fn deinit(self: *ReqResp) void {
        self.limiter.deinit(self.allocator);
        self.allocator.free(self.arena);
        self.allocator.free(self.inbound);
        self.allocator.free(self.outbound);
        self.* = undefined;
    }

    pub fn active(self: *const ReqResp) struct { outbound: u16, inbound: u16 } {
        var out: u16 = 0;
        for (self.outbound) |*slot| {
            if (slot.active()) out += 1;
        }
        var in: u16 = 0;
        for (self.inbound) |*slot| {
            if (slot.active()) in += 1;
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

    /// The request sink stays exclusive through served/failed delivery.
    pub fn accept(
        self: *ReqResp,
        engine: *Engine,
        stream: StreamHandle,
        ready: routing.Selection,
        request_sink: []u8,
        now: Now,
    ) AcceptError!RequestHandle {
        return Server.accept(self, engine, stream, ready, request_sink, now);
    }

    /// Response bytes stay immutable through chunk_sent or terminal delivery.
    pub fn respond(
        self: *ReqResp,
        handle: RequestHandle,
        ssz: []const u8,
        fork: ?config.ForkSeq,
        now: Now,
    ) RespondError!void {
        return Server.respond(self, handle, ssz, fork, now);
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

    pub fn consume(self: *ReqResp, handle: RequestHandle, now: Now) bool {
        return Client.consume(self, handle, now);
    }

    /// The returned bytes remain valid until the pump after terminal delivery.
    pub fn errorMessage(self: *const ReqResp, handle: RequestHandle) []const u8 {
        return if (handle.direction == .outbound)
            messageFor(self.outbound, handle)
        else
            messageFor(self.inbound, handle);
    }

    fn messageFor(slots: anytype, handle: RequestHandle) []const u8 {
        if (handle.index >= slots.len) return &.{};
        const slot = &slots[handle.index];
        if (slot.generation != handle.generation or slot.state == .free) return &.{};
        assert(slot.error_len <= codec.error_message_max);
        return slot.error_message[0..slot.error_len];
    }

    /// Forward each full-generation handle drained from Driver activity before querying wakeups.
    pub fn connectionActivity(self: *ReqResp, conn: Handle) void {
        for (self.outbound) |*slot| {
            if (slot.active() and slot.terminal == null and std.meta.eql(slot.conn, conn)) {
                slot.needs_service = true;
            }
        }
        for (self.inbound) |*slot| {
            if (slot.active() and slot.terminal == null and std.meta.eql(slot.conn, conn)) {
                slot.needs_service = true;
            }
        }
    }

    pub fn connectionClosed(self: *ReqResp, conn: Handle) void {
        for (self.outbound, 0..) |*slot, position| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            self.fail(slot, @intCast(position), .connection_closed, null);
        }
        for (self.inbound, 0..) |*slot, position| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            self.fail(slot, @intCast(position), .connection_closed, null);
        }
    }

    /// Includes reqresp-owned storage. Caller response sinks and Router storage are separate.
    pub fn memoryPlan(self: *const ReqResp) MemoryPlan {
        const slot_bytes = self.outbound.len * @sizeOf(Client) + self.inbound.len * @sizeOf(Server);
        const limiter_bytes = self.limiter.buckets.len * @sizeOf(limiter_mod.Bucket) +
            self.limiter.generations.len * @sizeOf(?u32);
        return .{
            .facade_bytes = @sizeOf(ReqResp),
            .slot_bytes = slot_bytes,
            .io_bytes = self.arena.len,
            .limiter_bytes = limiter_bytes,
            .total_bytes = @sizeOf(ReqResp) + slot_bytes + self.arena.len + limiter_bytes,
        };
    }

    /// Monotonic milliseconds; zero capacity suppresses event-only wakeups.
    /// Router negotiation and transport deadlines remain separate.
    pub fn nextWakeup(self: *ReqResp, now: Now, event_capacity: usize) ?u64 {
        return self.nextWakeupPartitioned(now, event_capacity, event_capacity);
    }

    pub fn nextWakeupPartitioned(
        self: *ReqResp,
        now: Now,
        application_capacity: usize,
        control_capacity: usize,
    ) ?u64 {
        if (self.scan_remaining > 0) return now.mono_ms;
        for (0..self.over_limit_len) |offset| {
            const item = self.over_limit[(self.over_limit_head + offset) % over_limit_queue_max];
            const capacity = if (item.protocol.isControl())
                control_capacity
            else
                application_capacity;
            if (capacity > 0) return now.mono_ms;
        }
        var due: ?u64 = null;
        for (self.outbound) |*slot| {
            const capacity = if (slot.protocol.isControl())
                control_capacity
            else
                application_capacity;
            if (slot.needs_service or slot.close_pending or slot.state == .reported or
                (capacity > 0 and (slot.pending_event != null or slot.terminal != null)))
            {
                return now.mono_ms;
            }
            if (slot.deadline(self)) |deadline| due = earlier(due, deadline);
        }
        for (self.inbound) |*slot| {
            const capacity = if (slot.protocol.isControl())
                control_capacity
            else
                application_capacity;
            if (slot.needs_service or slot.close_pending or slot.state == .reported or
                (capacity > 0 and (slot.pending_event != null or slot.terminal != null)))
            {
                return now.mono_ms;
            }
            if (slot.deadline(self)) |deadline| due = earlier(due, deadline);
            if (slot.state == .withheld) {
                if (self.limiter.nextToken(slot.conn, slot.protocol, now.mono_ms)) |eligible| {
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

    pub fn availableInbound(self: *ReqResp) ?u16 {
        return self.claim(self.inbound);
    }

    pub fn availableInboundFor(self: *ReqResp, which: Protocol) ?u16 {
        const start: usize = if (which.isControl()) 0 else self.options.inbound_control_reserved;
        const offset = self.claim(self.inbound[start..]) orelse return null;
        return @intCast(start + offset);
    }

    pub fn availableOutboundFor(self: *ReqResp, which: Protocol) ?u16 {
        return self.claimProtocol(self.outbound, which, self.options.outbound_control_reserved);
    }

    fn claimProtocol(self: *ReqResp, slots: anytype, which: Protocol, reserved: u16) ?u16 {
        if (!which.isControl() and reserved > 0) {
            var ordinary: usize = 0;
            for (slots) |*slot| {
                if (slot.state != .free and !slot.protocol.isControl()) ordinary += 1;
            }
            if (ordinary >= slots.len - reserved) return null;
        }
        return self.claim(slots);
    }

    /// Latches one terminal result. Call cleanupPending before the next Router pump.
    pub fn cancel(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction == .outbound) {
            const slot = self.outboundSlot(handle) orelse return false;
            if (slot.terminal != null) return false;
            self.fail(slot, handle.index, .cancelled, null);
        } else {
            const slot = self.inboundSlot(handle) orelse return false;
            if (slot.terminal != null) return false;
            self.fail(slot, handle.index, .cancelled, null);
        }
        return true;
    }

    pub fn cleanupPending(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        self.cleanup(engine, router, self.outbound, false);
        self.cleanup(engine, router, self.inbound, false);
    }

    pub fn shutdown(self: *ReqResp, engine: *Engine, router: *routing.Router) void {
        for (self.outbound, 0..) |*slot, index| if (slot.active()) {
            _ = self.cancel(slot.handle(@intCast(index)));
        };
        for (self.inbound, 0..) |*slot, index| if (slot.active()) {
            _ = self.cancel(slot.handle(@intCast(index)));
        };
        self.cleanup(engine, router, self.outbound, false);
        self.cleanup(engine, router, self.inbound, false);
    }

    pub fn pump(
        self: *ReqResp,
        engine: *Engine,
        router: *routing.Router,
        now: Now,
        events: []Event,
    ) usize {
        self.advance(engine, router, now);
        return self.drain(now, events, null, &self.event_cursor);
    }

    pub fn pumpPartitioned(
        self: *ReqResp,
        engine: *Engine,
        router: *routing.Router,
        now: Now,
        application: []Event,
        control: []Event,
    ) PartitionedCounts {
        self.advance(engine, router, now);
        return .{
            .application = self.drain(now, application, false, &self.application_event_cursor),
            .control = self.drain(now, control, true, &self.control_event_cursor),
        };
    }

    fn advance(self: *ReqResp, engine: *Engine, router: *routing.Router, now: Now) void {
        assert(now.mono_ms >= self.last_now_ms or self.last_now_ms == 0);
        self.last_now_ms = now.mono_ms;
        self.cleanup(engine, router, self.outbound, true);
        self.cleanup(engine, router, self.inbound, true);
        const total = self.outbound.len + self.inbound.len;
        if (self.scan_remaining == 0) self.scan_remaining = total;
        const steps = @min(self.scan_remaining, self.options.work_per_pump_max);
        self.scan_remaining -= steps;
        for (0..steps) |_| {
            const position = self.work_cursor;
            self.work_cursor = (position + 1) % total;
            if (position < self.outbound.len) {
                const slot = &self.outbound[position];
                slot.needs_service = false;
                if (slot.active()) slot.advance(self, engine, @intCast(position), now);
            } else {
                const index = position - self.outbound.len;
                const slot = &self.inbound[index];
                slot.needs_service = false;
                if (slot.active()) slot.advance(self, engine, @intCast(index), now);
            }
        }
        // Cleanup also covers terminal transitions made during this turn.
        self.cleanup(engine, router, self.outbound, false);
        self.cleanup(engine, router, self.inbound, false);
    }

    fn drain(self: *ReqResp, now: Now, events: []Event, control: ?bool, cursor: *usize) usize {
        const total = self.outbound.len + self.inbound.len;
        var count: usize = 0;
        for (0..total + 1) |_| {
            if (count == events.len) break;
            const position = cursor.*;
            cursor.* = (position + 1) % (total + 1);
            const event = if (position < self.outbound.len)
                deliverMatching(&self.outbound[position], now, control)
            else if (position < total)
                deliverMatching(&self.inbound[position - self.outbound.len], now, control)
            else
                self.takeOverLimit(control);
            if (event) |ready| {
                events[count] = ready;
                count += 1;
            }
        }
        return count;
    }

    fn deliverMatching(slot: anytype, now: Now, control: ?bool) ?Event {
        if (control) |wanted| if (slot.protocol.isControl() != wanted) return null;
        return deliver(slot, now);
    }

    fn takeOverLimit(self: *ReqResp, control: ?bool) ?Event {
        for (0..self.over_limit_len) |offset| {
            const index = (self.over_limit_head + offset) % over_limit_queue_max;
            const item = self.over_limit[index];
            if (control) |wanted| if (item.protocol.isControl() != wanted) continue;
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

    fn cleanup(
        self: *ReqResp,
        engine: *Engine,
        router: *routing.Router,
        slots: anytype,
        recycle: bool,
    ) void {
        _ = self;
        for (slots) |*slot| {
            if (slot.close_pending) {
                if (comptime @TypeOf(slot.*) == Client) {
                    if (slot.negotiation_owned) {
                        router.cancel(engine, slot.stream);
                        slot.negotiation_owned = false;
                    } else engine.closeStream(slot.stream, slot.close_code);
                } else engine.closeStream(slot.stream, slot.close_code);
                slot.close_pending = false;
            }
            if (recycle and slot.state == .reported) {
                slot.state = .free;
                slot.io.sink = &.{};
                slot.terminal = null;
            }
        }
    }

    fn deliver(slot: anytype, now: Now) ?Event {
        if (slot.pending_event) |event| {
            slot.pending_event = null;
            slot.delivered(event, now);
            return event;
        }
        if (slot.terminal) |event| {
            if (slot.state == .reported) return null;
            slot.state = .reported;
            return event;
        }
        return null;
    }

    pub fn complete(
        self: *ReqResp,
        slot: anytype,
        index: u16,
        event: Event,
        engine: ?*Engine,
    ) void {
        _ = self;
        _ = index;
        if (slot.terminal != null) return;
        slot.terminal = event;
        slot.state = .terminal;
        slot.clear();
        slot.close_pending = true;
        if (engine) |live| {
            live.closeStream(slot.stream, slot.close_code);
            slot.close_pending = false;
        }
    }

    pub fn fail(self: *ReqResp, slot: anytype, index: u16, reason: Failure, engine: ?*Engine) void {
        if (slot.terminal != null) return;
        self.counters.failures += 1;
        slot.close_code = switch (reason) {
            .timeout => constants.app_error_timeout,
            .invalid_response,
            .too_many_chunks,
            .unknown_context,
            => constants.app_error_invalid_response,
            else => types.app_error_normal,
        };
        self.complete(
            slot,
            index,
            .{ .failed = .{ .request = slot.handle(index), .reason = reason } },
            engine,
        );
    }

    pub fn failStream(
        self: *ReqResp,
        slot: anytype,
        index: u16,
        err: engine_mod.StreamError,
        engine: *Engine,
    ) void {
        const reason: Failure = switch (err) {
            error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
            else => .transport,
        };
        self.fail(slot, index, reason, engine);
    }

    pub fn servingSlot(self: *ReqResp, handle: RequestHandle) RespondError!*Server {
        if (handle.direction != .inbound) return error.StaleHandle;
        const slot = self.inboundSlot(handle) orelse return error.StaleHandle;
        if (slot.state != .serving) return error.Busy;
        return slot;
    }

    pub fn outboundSlot(self: *ReqResp, handle: RequestHandle) ?*Client {
        const slots = self.outbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.generation != handle.generation or !slot.active()) return null;
        return slot;
    }
    pub fn inboundSlot(self: *ReqResp, handle: RequestHandle) ?*Server {
        const slots = self.inbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.generation != handle.generation or !slot.active()) return null;
        return slot;
    }

    pub fn claim(self: *ReqResp, slots: anytype) ?u16 {
        _ = self;
        for (slots, 0..) |*slot, position| {
            if (slot.state == .free and slot.generation < std.math.maxInt(u32)) return @intCast(
                position,
            );
        }
        return null;
    }

    pub fn outboundCount(self: *const ReqResp, conn: Handle, which: Protocol) u8 {
        var count: u8 = 0;
        for (self.outbound) |*slot| {
            if (!slot.active() or slot.protocol != which) continue;
            if (!std.meta.eql(slot.conn, conn)) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn outboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.outbound) |*slot| {
            if (slot.state == .free or slot.protocol.isControl()) continue;
            if (std.meta.eql(slot.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundApplicationCount(self: *const ReqResp, conn: Handle) u16 {
        var count: u16 = 0;
        for (self.inbound) |*slot| {
            if (slot.state == .free or slot.protocol.isControl()) continue;
            if (std.meta.eql(slot.conn, conn)) count += 1;
        }
        return count;
    }

    pub fn inboundCount(self: *const ReqResp, conn: Handle, which: ?Protocol) u8 {
        var count: u8 = 0;
        for (self.inbound) |*slot| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            if (which) |wanted| if (slot.protocol != wanted) continue;
            count +|= 1;
        }
        return count;
    }

    pub fn pushOverLimit(self: *ReqResp, item: OverLimit) void {
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

    pub fn digestFor(
        self: *const ReqResp,
        fork: config.ForkSeq,
    ) ?[constants.context_bytes_length]u8 {
        for (self.forks[0..self.fork_count]) |entry| {
            if (entry.fork == fork) return entry.digest;
        }
        return null;
    }
};

fn assignBuffers(slot: anytype, arena: []u8, cursor: usize) usize {
    slot.io.scratch = arena[cursor..][0..scratch_length];
    slot.io.read_buffer = arena[cursor + scratch_length ..][0..read_buffer_length];
    return cursor + scratch_length + read_buffer_length;
}

comptime {
    assert(read_buffer_length >= 1024);
    assert(scratch_length >= codec.frame_scratch_max);
    assert(@sizeOf(Client) <= 2 * 1024);
    assert(@sizeOf(Server) <= 2 * 1024);
}
