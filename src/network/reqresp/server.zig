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

pub const State = enum { receiving_request, ready, serving, writing_chunk, finishing };
pub const Rejection = codec.Error || @import("request_policy.zig").InspectError;

pub const Server = struct {
    request: @import("request_state.zig").RequestState = .{ .direction = .inbound },
    progress_ms: u64 = 0,
    pending_context: ?[constants.context_bytes_length]u8 = null,
    pending_result: u8 = constants.result_success,
    close_after_write: bool = false,
    state: State = .receiving_request,
    request_fork: @import("config").ForkSeq = .phase0,
    rejection: ?Rejection = null,
    receive: @import("receive_plan.zig").Buffers = .{ .sink = &.{}, .scratch = &.{}, .read = &.{} },
    identity: @import("../wire/peer_id.zig").PeerId = undefined,
    execution: ?u16 = null,
    charged_cost: u128 = 1,
    admission_paid: u128 = 0,
    eligible_ms: u64 = 0,
    /// Why a `.ready` slot was not admitted at its last attempt. `none` means it is due one.
    admission_wait: enum { none, tokens, serving } = .none,

    pub fn complete(self: *Server, owner: *ReqResp, index: u16, event: Event, engine: ?*Engine) void {
        owner.complete(&self.request, index, event, .{ .phase_name = @tagName(self.state), .rejection = self.rejection, .result_code = self.pending_result });
        if (engine) |live| self.request.closeProtocol(live);
        owner.settleSlot(.inbound, index);
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

    /// A finishing slot resumes its FIN once the host has taken its last event.
    pub fn deliver(self: *Server, control: bool, now: Now) ?Event {
        const request = &self.request;
        const event = request.deliver(control) orelse return null;
        if (request.running() and self.state == .finishing) self.progress_ms = now.mono_ms;
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
            else if (self.state == .ready)
                .quota_timeout
            else
                .timeout;
            if (reason == .timeout and self.state == .receiving_request and !request.protocol.isControl() and
                !request.io.unread(engine, request.stream))
                request.peer_fault = .non_completion;
            self.fail(ctx, index, reason, engine);
            return;
        };
        // A peer stop surfaces here while the host holds the slot. With an event still queued
        // for the host, its next call on the slot observes the stop instead.
        if (self.state == .ready or (self.state == .serving and !request.waitingHost())) {
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
            .serving, .ready => {},
            .receiving_request => readRequest(ctx, engine, self, index, now),
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
                    request.peer_fault = .protocol;
                    Server.rejectRequest(owner, slot, index, error.TooManyBytes, now);
                    return;
                }
                _ = request.io.feed(input.bytes) catch |err| {
                    if (request.io.decoder.protocolFault(err)) request.peer_fault = .protocol;
                    Server.rejectRequest(owner, slot, index, err, now);
                    return;
                };
                if (request.io.buffered_start < request.io.buffered_end) {
                    request.peer_fault = .protocol;
                    Server.rejectRequest(owner, slot, index, error.TooManyBytes, now);
                    return;
                }
            }
            // Goodbye only closes this authenticated peer's connection. Handle its complete
            // bounded frame before FIN, which can race the peer's connection shutdown.
            if (input.fin or (request.protocol == .goodbye_v1 and request.io.decoding and request.io.decoder.isDone())) {
                request.io.fin_seen = input.fin;
                const finished = !request.io.decoding or request.io.decoder.isDone();
                if (!finished) {
                    request.peer_fault = .protocol;
                    Server.rejectRequest(owner, slot, index, error.Truncated, now);
                    return;
                }
                const payload: []const u8 = if (request.io.decoding)
                    request.io.decoder.payload()
                else
                    &.{};
                const inspected = owner.inspectRequest(request.protocol, payload, slot.request_fork) catch |err| {
                    if (err == error.MalformedSsz or err == error.InvalidRequest) request.peer_fault = .protocol;
                    _ = takeAdmission(owner, engine, slot, 1, now);
                    Server.rejectRequest(owner, slot, index, err, now);
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
        owner.markReady(.inbound, index);
    }

    pub fn promote(self: *Server, owner: *ReqResp, index: u16, now: Now) bool {
        const request = &self.request;
        if (!request.running() or self.state != .ready or now.mono_ms < self.eligible_ms) return false;
        const execution = owner.serving.available(&self.identity, request.protocol.isControl()) orelse {
            self.admission_wait = .serving;
            return false;
        };
        const admission = &owner.admission;
        const cost = admission.limiter.requestCost(request.protocol, self.charged_cost, self.request_fork);
        if (self.admission_paid < cost) {
            const granted = admission.limiter.grant(&self.identity, request.protocol, cost - self.admission_paid, self.request_fork, now.mono_ms);
            self.admission_paid += granted;
            if (self.admission_paid < cost) {
                self.eligible_ms = admission.limiter.eligibleAt(&self.identity, request.protocol, 1, self.request_fork, now.mono_ms).?;
                self.admission_wait = .tokens;
                return false;
            }
        }
        self.admission_wait = .none;
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

    fn rejectRequest(owner: *ReqResp, slot: *Server, index: u16, reason: Rejection, now: Now) void {
        assert(slot.rejection == null);
        slot.rejection = reason;
        reject(slot, constants.result_invalid_request, "invalid request", now);
        owner.markReady(.inbound, index);
    }

    fn takeAdmission(owner: *ReqResp, engine: *Engine, slot: *Server, cost: u128, now: Now) bool {
        const request = &slot.request;
        const identity = engine.peerId(request.conn) orelse return false;
        const decision = owner.admission.limiter.take(&identity, request.protocol, cost, slot.request_fork, now.mono_ms);
        if (decision == .allowed) return true;
        owner.recordAdmissionRefusal(request.stream, request.protocol, switch (decision) {
            .allowed => unreachable,
            .peer_quota => .peer_quota,
            .global_quota => .global_quota,
            .identity_capacity => .identity_capacity,
        }, cost);
        return false;
    }

    fn reject(slot: *Server, code: u8, message: []const u8, now: Now) void {
        const request = &slot.request;
        assert(message.len <= request.error_message.len);
        @memcpy(request.error_message[0..message.len], message);
        request.error_len = @intCast(message.len);
        request.io.decoding = false;
        slot.state = .serving;
        Server.queueChunk(
            slot,
            code,
            null,
            request.error_message[0..message.len],
            true,
            now,
        );
    }

    fn queueChunk(
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
        Server.beginWrite(slot);
    }

    /// The caller marks the slot ready.
    fn beginWrite(slot: *Server) void {
        const request = &slot.request;
        request.io.writer = codec.ChunkWriter.initChunk(
            slot.pending_result,
            slot.pending_context,
            request.io.payload,
        );
        request.io.writing = true;
        slot.state = .writing_chunk;
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
            if (flushed.runnable) owner.markReady(.inbound, index);
            return;
        }
        if (slot.pending_result == constants.result_success) {
            request.chunks += 1;
        }
        request.io.payload = &.{};
        request.io.writer = undefined;
        if (slot.close_after_write) {
            request.io.outbox.queue("", true);
            slot.state = .finishing;
            owner.markReady(.inbound, index);
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
            // An error chunk ends the response, so a peer can stop the stream once it has read one.
            const answered = request.chunks > 0 or slot.pending_result != constants.result_success;
            if (err != error.StreamStopped or !answered or request.io.outbox.offset != request.io.outbox.bytes.len) {
                slot.failStream(owner, index, err, engine);
                return;
            }
            std.log.scoped(.network_reqresp).debug("response_finish_stopped request={d}:{d} connection={d}:{d} stream={d} method={s} chunks={d}", .{ index, request.generation, request.conn.index, request.conn.generation, request.stream.id, @tagName(request.protocol), request.chunks });
            request.io.outbox = .{};
            break :stopped .done;
        };
        if (flushed != .done) {
            if (flushed == .yielded) owner.markReady(.inbound, index);
            return;
        }
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
        const decision = owner.admission.limiter.start(&identity, which.isControl(), now.mono_ms);
        if (decision != .allowed) {
            owner.recordAdmissionRefusal(stream, which, if (decision == .identity_capacity) .identity_capacity else .request_starts, 1);
            return error.TooManyRequests;
        }
        if (owner.inboundCount(stream.conn, null) >= owner.options.inbound_per_peer_max) {
            owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
            return error.PeerSlotsExhausted;
        }
        const available = owner.availableInbound(stream.conn, which);
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
            owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
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
                .{ .min = bounds.request_min, .max = bounds.request_max, .protocol_max = which.info().request_max },
                request_sink,
                slot.request.io.scratch,
            );
            slot.request.io.decoding = true;
        }
        owner.protocol_counters[@intFromEnum(which)].incoming +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=inbound request={d}:{d} connection={d}:{d} stream={d} method={s}", .{ index, slot.request.generation, stream.conn.index, stream.conn.generation, stream.id, @tagName(which) });
        // A stream that is already gone fails on the slot's first read.
        engine.bindStream(stream, .{ .owner = .reqresp_inbound, .row = index }) catch {};
        owner.markReady(.inbound, index);
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
        Server.queueChunk(slot, constants.result_success, digest, ssz, false, now);
    }

    pub fn reserveResponse(self: *Server) bool {
        const request = &self.request;
        if (!request.running() or request.waitingHost() or self.state != .serving) return false;
        return true;
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
        Server.queueChunk(slot, code, null, request.error_message[0..message.len], true, now);
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
                owner.markReady(.inbound, request_handle.index);
                slot.state = .finishing;
                slot.progress_ms = now.mono_ms;
            },
            .writing_chunk => {
                if (slot.close_after_write) return false;
                slot.close_after_write = true;
            },
            else => return false,
        }
        return true;
    }
};
