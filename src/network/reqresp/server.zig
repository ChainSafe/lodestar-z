const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const reqresp = @import("reqresp.zig");
const engine_mod = @import("../quic/engine.zig");
const types = @import("../types.zig");
const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const StreamHandle = engine_mod.StreamHandle;
const protocol = @import("protocol.zig");
const Now = types.Now;
const routing = @import("../router.zig");
const AcceptError = reqresp.AcceptError;
const RespondError = reqresp.RespondError;

const ReqResp = reqresp.ReqResp;
const RequestHandle = reqresp.RequestHandle;
const Event = reqresp.Event;
const Failure = reqresp.Failure;
const reads_per_pump_max = reqresp.reads_per_pump_max;

pub const State = enum { receiving_request, ready, serving, waiting_capacity, writing_chunk, withheld, finishing };
pub const Rejection = codec.Error || @import("request_policy.zig").InspectError;

pub const Server = struct {
    request: @import("request_state.zig").RequestState = .{ .direction = .inbound },
    progress_ms: u64 = 0,
    pending_context: ?[constants.context_bytes_length]u8 = null,
    pending_result: u8 = constants.result_success,
    close_after_write: bool = false,
    withheld_since_ms: ?u64 = null,
    state: State = .receiving_request,
    request_fork: @import("config").ForkSeq = .phase0,
    rejection: ?Rejection = null,
    receive: @import("receive_plan.zig").Buffers = .{ .sink = &.{}, .scratch = &.{}, .read = &.{} },
    identity: @import("../wire/peer_id.zig").PeerId = undefined,
    execution: ?u16 = null,
    charged_cost: u128 = 1,
    admission_paid: u128 = 0,
    eligible_ms: u64 = 0,
    response_reserved: bool = false,

    pub fn complete(self: *Server, owner: *ReqResp, index: u16, event: Event, engine: ?*Engine) void {
        owner.complete(&self.request, index, event, .{ .phase_name = @tagName(self.state), .rejection = self.rejection, .result_code = self.pending_result });
        if (engine) |live| self.request.closeProtocol(live);
    }

    pub fn fail(self: *Server, owner: *ReqResp, index: u16, reason: Failure, engine: ?*Engine) void {
        self.complete(owner, index, .{ .failed = .{ .request = self.request.handle(index), .reason = reason, .phase = null } }, engine);
    }

    fn failStream(self: *Server, owner: *ReqResp, index: u16, err: engine_mod.StreamError, engine: *Engine) void {
        self.request.failure_detail = @errorName(err);
        self.fail(owner, index, switch (err) {
            error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
            else => .transport,
        }, engine);
    }

    pub fn deliver(self: *Server, control: bool, now: Now) ?Event {
        const request = &self.request;
        const event = request.deliver(control) orelse return null;
        if (request.running() and self.state == .finishing) {
            self.progress_ms = now.mono_ms;
            request.needs_service = true;
        }
        return event;
    }

    fn waitingHost(self: *const Server) bool {
        return self.request.waitingHost() or self.state == .serving;
    }

    pub fn occupancy(self: *const Server) ?reqresp.metrics.InboundPhase {
        if (!self.request.occupied()) return null;
        if (!self.request.running()) return .terminal;
        if (self.waitingHost()) return .waiting_host;
        return switch (self.state) {
            .receiving_request => .receiving_request,
            .ready => .ready,
            .withheld, .waiting_capacity => .withheld,
            .writing_chunk, .finishing => .writing_response,
            .serving => unreachable,
        };
    }

    pub fn deadline(self: *const Server, ctx: *const ReqResp) ?u64 {
        const request = &self.request;
        if (!request.running()) return null;
        if (self.state == .receiving_request) return request.started_ms +| ctx.options.progress_timeout_ms;
        if (self.state == .ready) return self.progress_ms +| ctx.options.quota_timeout_ms;
        const duration = if (self.waitingHost())
            ctx.options.host_timeout_ms
        else if (self.state == .withheld or self.state == .waiting_capacity)
            ctx.options.quota_timeout_ms
        else
            ctx.options.progress_timeout_ms;
        return self.progress_ms +| duration;
    }

    pub fn advance(self: *Server, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        const request = &self.request;
        if (!request.running()) return;
        if (self.deadline(ctx)) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (self.waitingHost())
                .host_timeout
            else if (self.state == .withheld or self.state == .waiting_capacity or self.state == .ready)
                .quota_timeout
            else
                .timeout;
            self.fail(ctx, index, reason, engine);
            return;
        };
        if (self.state == .ready or self.state == .serving or self.state == .waiting_capacity or self.state == .withheld) {
            _ = engine.streamCapacity(request.stream) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => {
                    self.failStream(ctx, index, err, engine);
                    return;
                },
            };
        }
        if (request.waitingHost()) return;
        switch (self.state) {
            .serving, .ready, .waiting_capacity => {},
            .receiving_request => readRequest(ctx, engine, self, index, now),
            .withheld => {
                if (!ctx.limiter.matches(request.conn)) {
                    self.fail(ctx, index, .connection_closed, engine);
                    return;
                }
                retryWithheld(ctx, self, now);
            },
            .writing_chunk => writeChunk(ctx, engine, self, index, now),
            .finishing => finishStream(ctx, engine, self, index, now),
        }
    }

    pub fn readRequest(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
        const request = &slot.request;
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            const input = request.io.read(engine, request.stream) catch |err| {
                slot.failStream(owner, index, err, engine);
                return;
            };
            if (input.reset) {
                slot.fail(owner, index, .stream_closed, engine);
                return;
            }
            if (input.progressed) slot.progress_ms = now.mono_ms;
            if (input.bytes.len == 0 and !input.fin) return;
            if (input.bytes.len > 0) {
                if (!request.io.decoding or request.io.decoder.isDone()) {
                    Server.rejectRequest(owner, slot, error.TooManyBytes, now);
                    return;
                }
                _ = request.io.feed(input.bytes) catch |err| {
                    Server.rejectRequest(owner, slot, err, now);
                    return;
                };
                if (request.io.buffered_start < request.io.buffered_end) {
                    Server.rejectRequest(owner, slot, error.TooManyBytes, now);
                    return;
                }
            }
            // Goodbye only closes this authenticated peer's connection. Handle its complete
            // bounded frame before FIN, which can race the peer's connection shutdown.
            if (input.fin or (request.protocol == .goodbye_v1 and request.io.decoding and request.io.decoder.isDone())) {
                request.io.fin_seen = input.fin;
                const finished = !request.io.decoding or request.io.decoder.isDone();
                if (!finished) {
                    Server.rejectRequest(owner, slot, error.Truncated, now);
                    return;
                }
                const payload: []const u8 = if (request.io.decoding)
                    request.io.decoder.payload()
                else
                    &.{};
                if (owner.admission != null) owner.counters.inspected +|= 1;
                const inspected = owner.inspectRequest(request.protocol, payload, slot.request_fork) catch |err| {
                    if (err == error.PolicyRequired) {
                        reject(owner, slot, constants.result_resource_unavailable, "request policy unavailable", now);
                    } else {
                        if (owner.admission != null) _ = takeAdmission(owner, engine, slot, 1, now);
                        Server.rejectRequest(owner, slot, err, now);
                    }
                    return;
                };
                request.chunks_max = inspected.chunks_max;
                slot.charged_cost = inspected.charged_cost;
                slot.progress_ms = now.mono_ms;
                slot.eligible_ms = now.mono_ms;
                slot.state = .ready;
                return;
            }
        }
        request.needs_service = true;
    }

    pub fn promote(self: *Server, owner: *ReqResp, index: u16, now: Now) bool {
        const request = &self.request;
        if (!request.running() or self.state != .ready or now.mono_ms < self.eligible_ms) return false;
        const execution = owner.serving.available(&self.identity, request.protocol.isControl()) orelse return false;
        if (owner.admission) |*admission| {
            const cost = admission.limiter.requestCost(request.protocol, self.charged_cost, self.request_fork);
            if (self.admission_paid < cost) {
                const granted = admission.limiter.grant(&self.identity, request.protocol, cost - self.admission_paid, self.request_fork, now.mono_ms);
                self.admission_paid += granted;
                owner.counters.charged_work +|= granted;
                if (self.admission_paid < cost) {
                    self.eligible_ms = admission.limiter.eligibleAt(&self.identity, request.protocol, 1, self.request_fork, now.mono_ms).?;
                    return false;
                }
            }
            owner.counters.admitted +|= 1;
        }
        const payload: []const u8 = if (request.io.decoding) request.io.decoder.payload() else &.{};
        request.io.decoding = false;
        request.io.scratch = owner.serving.acquire(execution, request.handle(index), &self.identity, request.protocol.isControl());
        self.execution = execution;
        self.state = .serving;
        self.progress_ms = now.mono_ms;
        request.queue(.{ .request = .{
            .request = request.handle(index),
            .peer = request.conn,
            .protocol = request.protocol,
            .bytes = payload,
        } });
        return true;
    }

    fn rejectRequest(owner: *ReqResp, slot: *Server, reason: Rejection, now: Now) void {
        assert(slot.rejection == null);
        slot.rejection = reason;
        reject(owner, slot, constants.result_invalid_request, "invalid request", now);
    }

    fn takeAdmission(owner: *ReqResp, engine: *Engine, slot: *Server, cost: u128, now: Now) bool {
        const request = &slot.request;
        const identity = engine.peerId(request.conn) orelse return false;
        const decision = owner.admission.?.limiter.take(&identity, request.protocol, cost, slot.request_fork, now.mono_ms);
        switch (decision) {
            .allowed => {
                owner.counters.charged_work +|= cost;
                return true;
            },
            .peer_quota => owner.counters.peer_refusals +|= 1,
            .global_quota => owner.counters.aggregate_refusals +|= 1,
            .identity_capacity => owner.counters.identity_capacity_refusals +|= 1,
        }
        owner.recordAdmissionRefusal(request.stream, request.protocol, switch (decision) {
            .allowed => unreachable,
            .peer_quota => .peer_quota,
            .global_quota => .global_quota,
            .identity_capacity => .identity_capacity,
        }, cost);
        return false;
    }

    fn reject(owner: *ReqResp, slot: *Server, code: u8, message: []const u8, now: Now) void {
        const request = &slot.request;
        assert(message.len <= request.error_message.len);
        @memcpy(request.error_message[0..message.len], message);
        request.error_len = @intCast(message.len);
        request.io.decoding = false;
        slot.state = .serving;
        Server.queueChunk(
            owner,
            slot,
            code,
            null,
            request.error_message[0..message.len],
            true,
            now,
        );
    }

    fn queueChunk(
        owner: *ReqResp,
        slot: *Server,
        result: u8,
        context: ?[constants.context_bytes_length]u8,
        ssz: []const u8,
        close_after: bool,
        now: Now,
    ) void {
        const request = &slot.request;
        assert(slot.state == .serving);
        assert(request.io.outbox.idle());
        request.io.payload = ssz;
        slot.pending_context = context;
        slot.pending_result = result;
        slot.close_after_write = close_after;
        slot.progress_ms = now.mono_ms;
        if (slot.response_reserved or owner.limiter.take(request.conn, request.protocol, 1, now.mono_ms)) {
            slot.response_reserved = false;
            Server.beginWrite(slot);
        } else {
            slot.state = .withheld;
            slot.withheld_since_ms = now.mono_ms;
            owner.counters.withheld_chunks += 1;
        }
    }

    fn beginWrite(slot: *Server) void {
        const request = &slot.request;
        request.needs_service = true;
        request.io.writer = codec.ChunkWriter.initChunk(
            slot.pending_result,
            slot.pending_context,
            request.io.payload,
        );
        request.io.writing = true;
        slot.state = .writing_chunk;
    }

    fn retryWithheld(owner: *ReqResp, slot: *Server, now: Now) void {
        const request = &slot.request;
        assert(slot.state == .withheld);
        if (!owner.limiter.take(request.conn, request.protocol, 1, now.mono_ms)) return;
        const since = slot.withheld_since_ms orelse now.mono_ms;
        owner.counters.withheld_ms_total += now.mono_ms -| since;
        slot.withheld_since_ms = null;
        slot.progress_ms = now.mono_ms;
        Server.beginWrite(slot);
    }

    fn writeChunk(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
        const request = &slot.request;
        const flushed = request.io.flush(engine, request.stream, false) catch |err| {
            request.failure_detail = @errorName(err);
            const reason: Failure = switch (err) {
                error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
                else => .transport,
            };
            slot.fail(owner, index, reason, engine);
            return;
        };
        if (!flushed.done) {
            if (request.io.outbox.idle()) request.needs_service = true;
            return;
        }
        if (slot.pending_result == constants.result_success) {
            request.chunks += 1;
            owner.counters.chunks_sent += 1;
        }
        request.io.payload = &.{};
        request.io.writer = undefined;
        if (slot.close_after_write) {
            request.io.outbox.queue("", true);
            slot.state = .finishing;
            request.needs_service = true;
            slot.progress_ms = now.mono_ms;
            return;
        }
        slot.state = .serving;
        slot.progress_ms = now.mono_ms;
        request.queue(.{ .chunk_sent = .{
            .request = request.handle(index),
            .chunks = request.chunks,
        } });
    }

    fn finishStream(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Server,
        index: u16,
        now: Now,
    ) void {
        const request = &slot.request;
        assert(slot.state == .finishing);
        const flushed = request.io.outbox.pump(engine, request.stream) catch |err| stopped: {
            if (err != error.StreamStopped or request.chunks == 0 or request.io.outbox.offset != request.io.outbox.bytes.len) {
                slot.failStream(owner, index, err, engine);
                return;
            }
            owner.protocol_counters[@intFromEnum(request.protocol)].response_finish_stops +|= 1;
            std.log.scoped(.network_reqresp).debug("response_finish_stopped request={d}:{d} connection={d}:{d} stream={d} method={s} chunks={d}", .{ index, request.generation, request.conn.index, request.conn.generation, request.stream.id, @tagName(request.protocol), request.chunks });
            request.io.outbox = .{};
            break :stopped true;
        };
        if (!flushed) return;
        slot.progress_ms = now.mono_ms;
        slot.complete(
            owner,
            index,
            .{ .served = .{ .request = request.handle(index), .chunks = request.chunks } },
            null,
        );
    }

    pub fn accept(
        owner: *ReqResp,
        engine: *Engine,
        stream: StreamHandle,
        ready: routing.Selection,
        now: Now,
    ) AcceptError!RequestHandle {
        try owner.attach(engine);
        if (stream.conn.index >= owner.options.peers) return error.InvalidCapacity;
        const identity = engine.peerId(stream.conn) orelse return error.StaleHandle;
        if (ready.leftover.len > reqresp.read_buffer_length) return error.InvalidHandoff;
        const which = switch (ready.protocol) {
            .reqresp => |which| which,
            else => return error.UnknownProtocol,
        };
        const bounds = owner.requestBounds(which);
        if (owner.admission) |*admission| {
            const decision = admission.limiter.start(&identity, which.isControl(), now.mono_ms);
            if (decision != .allowed) {
                if (decision == .identity_capacity) owner.counters.identity_capacity_refusals +|= 1 else owner.counters.peer_refusals +|= 1;
                owner.recordAdmissionRefusal(stream, which, if (decision == .identity_capacity) .identity_capacity else .request_starts, 1);
                return error.TooManyRequests;
            }
        }
        if (owner.inboundCount(stream.conn, null) >= owner.options.inbound_per_peer_max) {
            owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
            return error.PeerSlotsExhausted;
        }
        const available = owner.availableInbound(stream.conn, which);
        if (available == null and owner.receive_plan == null) {
            owner.recordAdmissionRefusal(stream, which, .server_capacity, 0);
            return error.SlotsExhausted;
        }
        if (!which.isControl() and owner.options.inbound_application_per_peer_max > 0 and
            owner.inboundApplicationCount(stream.conn) >= owner.options.inbound_application_per_peer_max)
        {
            owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
            return error.PeerSlotsExhausted;
        }
        if (owner.inboundCount(stream.conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            owner.recordAdmissionRefusal(stream, which, .protocol_concurrency, 0);
            return error.TooManyRequests;
        }
        const index = available orelse {
            owner.recordAdmissionRefusal(stream, which, if (owner.receive_plan != null) .peer_capacity else .server_capacity, 0);
            return error.SlotsExhausted;
        };
        const slot = &owner.inbound[index];
        if (ready.leftover.len > slot.receive.read.len) return error.InvalidHandoff;
        const request_sink = owner.inboundSink(index);
        assert(request_sink.len >= bounds.request_max);
        slot.* = .{
            .receive = slot.receive,
            .identity = identity,
            .request_fork = owner.request_fork,
            .progress_ms = now.mono_ms,
            .request = .{
                .completion = .active,
                .direction = .inbound,
                .generation = slot.request.generation + 1,
                .conn = stream.conn,
                .stream = stream,
                .protocol = which,
                .started_ms = now.mono_ms,
                .io = .{
                    .sink = request_sink,
                    .scratch = slot.receive.scratch,
                    .read_buffer = slot.receive.read,
                    .buffered_end = ready.leftover.len,
                    .fin_seen = ready.fin,
                },
            },
        };
        assert(ready.leftover.len <= slot.request.io.read_buffer.len);
        @memcpy(slot.request.io.read_buffer[0..ready.leftover.len], ready.leftover);
        if (bounds.request_max > 0) {
            slot.request.io.decoder = codec.Decoder.initRequest(
                .{ .min = bounds.request_min, .max = bounds.request_max },
                request_sink,
                slot.request.io.scratch,
            );
            slot.request.io.decoding = true;
        }
        owner.limiter.bind(stream.conn, now.mono_ms);
        owner.protocol_counters[@intFromEnum(which)].incoming +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=inbound request={d}:{d} connection={d}:{d} stream={d} method={s}", .{ index, slot.request.generation, stream.conn.index, stream.conn.generation, stream.id, @tagName(which) });
        slot.request.needs_service = true;
        assert(slot.request.active());
        return slot.request.handle(index);
    }

    pub fn respond(
        owner: *ReqResp,
        request_handle: RequestHandle,
        ssz: []const u8,
        context: ?reqresp.ForkEntry,
        now: Now,
    ) RespondError!void {
        const slot = try owner.servingSlot(request_handle);
        const request = &slot.request;
        const bounds = owner.requestBounds(request.protocol);
        if (request.chunks >= request.chunks_max) return error.TooManyChunks;
        var response = codec.Bounds{ .min = bounds.response_min, .max = bounds.response_max };
        var digest: ?[constants.context_bytes_length]u8 = null;
        if (bounds.context_bytes) {
            const selected = context orelse return error.UnknownFork;
            const known = owner.forkFor(selected.digest) orelse return error.UnknownFork;
            if (known != selected.fork) return error.UnknownFork;
            response = owner.responseBounds(request.protocol, known) catch return error.InvalidContext;
            digest = selected.digest;
        }
        if (!bounds.context_bytes and context != null) return error.InvalidContext;
        if (ssz.len > response.max) return error.ChunkTooLarge;
        if (ssz.len < response.min) return error.ChunkTooSmall;
        Server.queueChunk(owner, slot, constants.result_success, digest, ssz, false, now);
    }

    pub fn reserveResponse(self: *Server, owner: *ReqResp, now: Now) bool {
        const request = &self.request;
        if (!request.running() or request.waitingHost() or (self.state != .serving and self.state != .waiting_capacity)) return false;
        if (self.response_reserved) return true;
        if (owner.limiter.take(request.conn, request.protocol, 1, now.mono_ms)) {
            self.response_reserved = true;
            self.state = .serving;
            self.progress_ms = now.mono_ms;
            if (self.withheld_since_ms) |since| owner.counters.withheld_ms_total +|= now.mono_ms -| since;
            self.withheld_since_ms = null;
            return true;
        }
        if (self.state != .waiting_capacity) {
            self.state = .waiting_capacity;
            self.progress_ms = now.mono_ms;
            self.withheld_since_ms = now.mono_ms;
            owner.counters.withheld_chunks +|= 1;
        }
        return false;
    }

    pub fn respondError(
        owner: *ReqResp,
        request_handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) RespondError!void {
        if (!constants.isErrorResult(code) or message.len > codec.error_message_max) {
            return error.InvalidError;
        }
        const slot = try owner.servingSlot(request_handle);
        const request = &slot.request;
        @memcpy(request.error_message[0..message.len], message);
        request.error_len = @intCast(message.len);
        Server.queueChunk(owner, slot, code, null, request.error_message[0..message.len], true, now);
    }

    pub fn finish(owner: *ReqResp, request_handle: RequestHandle, now: Now) bool {
        if (request_handle.direction != .inbound) return false;
        const slot = owner.inboundSlot(request_handle) orelse return false;
        const request = &slot.request;
        if (!request.running()) return false;
        if (request.pendingEvent()) |event| if (event == .request) return false;
        switch (slot.state) {
            .serving => {
                if (!request.io.outbox.idle()) return false;
                request.io.outbox.queue("", true);
                request.needs_service = true;
                slot.state = .finishing;
                slot.progress_ms = now.mono_ms;
            },
            .writing_chunk, .withheld => {
                if (slot.close_after_write) return false;
                slot.close_after_write = true;
            },
            else => return false,
        }
        return true;
    }
};
