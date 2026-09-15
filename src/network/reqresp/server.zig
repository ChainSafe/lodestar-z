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

pub const State = enum { receiving_request, serving, writing_chunk, withheld, finishing };

pub const Server = struct {
    lifecycle: @import("lifecycle.zig").Lifecycle = .{ .direction = .inbound },
    progress_ms: u64 = 0,
    pending_context: ?[constants.context_bytes_length]u8 = null,
    pending_result: u8 = constants.result_success,
    close_after_write: bool = false,
    withheld_since_ms: ?u64 = null,
    state: State = .receiving_request,
    request_fork: @import("config").ForkSeq = .phase0,

    pub fn deliver(self: *Server, control: bool, now: Now) ?Event {
        const lifecycle = &self.lifecycle;
        const event = lifecycle.deliver(control) orelse return null;
        if (lifecycle.running() and self.state == .finishing) {
            self.progress_ms = now.mono_ms;
            lifecycle.needs_service = true;
        }
        return event;
    }

    fn waitingHost(self: *const Server) bool {
        return self.lifecycle.waitingHost() or self.state == .serving;
    }

    pub fn deadline(self: *const Server, ctx: *const ReqResp) ?u64 {
        const lifecycle = &self.lifecycle;
        if (!lifecycle.running()) return null;
        const duration = if (self.waitingHost())
            ctx.options.host_timeout_ms
        else if (self.state == .withheld)
            ctx.options.quota_timeout_ms
        else
            ctx.options.progress_timeout_ms;
        return self.progress_ms +| duration;
    }

    pub fn advance(self: *Server, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        const lifecycle = &self.lifecycle;
        if (!lifecycle.running()) return;
        if (self.deadline(ctx)) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (self.waitingHost())
                .host_timeout
            else if (self.state == .withheld)
                .quota_timeout
            else
                .timeout;
            if (reason == .timeout) ctx.counters.timeouts += 1;
            lifecycle.fail(ctx, index, reason, .{ .inbound = self.state }, engine);
            return;
        };
        if (lifecycle.waitingHost()) return;
        switch (self.state) {
            .serving => {},
            .receiving_request => readRequest(ctx, engine, self, index, now),
            .withheld => {
                if (!ctx.limiter.matches(lifecycle.conn)) {
                    lifecycle.fail(ctx, index, .connection_closed, .{ .inbound = self.state }, engine);
                    return;
                }
                retryWithheld(ctx, self, now);
            },
            .writing_chunk => writeChunk(ctx, engine, self, index, now),
            .finishing => finishStream(ctx, engine, self, index, now),
        }
    }

    pub fn readRequest(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
        const lifecycle = &slot.lifecycle;
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            const input = lifecycle.io.read(engine, lifecycle.stream) catch |err| {
                lifecycle.failStream(owner, index, err, .{ .inbound = slot.state }, engine);
                return;
            };
            if (input.reset) {
                lifecycle.fail(owner, index, .stream_closed, .{ .inbound = slot.state }, engine);
                return;
            }
            if (input.progressed) slot.progress_ms = now.mono_ms;
            if (input.bytes.len == 0 and !input.fin) return;
            if (input.bytes.len > 0) {
                if (!lifecycle.io.decoding or lifecycle.io.decoder.isDone()) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
                _ = lifecycle.io.feed(input.bytes) catch {
                    Server.rejectRequest(owner, slot, now);
                    return;
                };
                if (lifecycle.io.buffered_start < lifecycle.io.buffered_end) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
            }
            // Goodbye only closes this authenticated peer's connection. Handle its complete
            // bounded frame before FIN, which can race the peer's connection shutdown.
            if (input.fin or (lifecycle.protocol == .goodbye_v1 and lifecycle.io.decoding and lifecycle.io.decoder.isDone())) {
                lifecycle.io.fin_seen = input.fin;
                const finished = !lifecycle.io.decoding or lifecycle.io.decoder.isDone();
                if (!finished) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
                const payload: []const u8 = if (lifecycle.io.decoding)
                    lifecycle.io.decoder.payload()
                else
                    &.{};
                if (owner.admission) |*admission| {
                    owner.counters.inspected +|= 1;
                    const inspected = admission.policy.inspect(lifecycle.protocol, payload, slot.request_fork) catch {
                        owner.counters.malformed +|= 1;
                        _ = takeAdmission(owner, engine, slot, 1, now);
                        Server.rejectRequest(owner, slot, now);
                        return;
                    };
                    lifecycle.chunks_max = inspected.chunks_max;
                    if (!takeAdmission(owner, engine, slot, inspected.charged_cost, now)) {
                        reject(owner, slot, constants.result_server_error, "rate limited", now);
                        return;
                    }
                    owner.counters.admitted +|= 1;
                } else {
                    lifecycle.chunks_max = protocol.requestChunkLimit(lifecycle.protocol, payload) catch {
                        Server.rejectRequest(owner, slot, now);
                        return;
                    };
                }
                lifecycle.queue(.{ .request = .{
                    .request = lifecycle.handle(index),
                    .peer = lifecycle.conn,
                    .protocol = lifecycle.protocol,
                    .bytes = payload,
                } });
                slot.state = .serving;
                return;
            }
        }
        lifecycle.needs_service = true;
    }

    fn rejectRequest(owner: *ReqResp, slot: *Server, now: Now) void {
        reject(owner, slot, constants.result_invalid_request, "invalid request", now);
    }

    fn takeAdmission(owner: *ReqResp, engine: *Engine, slot: *Server, cost: u128, now: Now) bool {
        const lifecycle = &slot.lifecycle;
        const identity = engine.peerId(lifecycle.conn) orelse return false;
        const decision = owner.admission.?.limiter.take(&identity, lifecycle.protocol, cost, slot.request_fork, now.mono_ms);
        switch (decision) {
            .allowed => {
                owner.counters.charged_work +|= cost;
                return true;
            },
            .peer_quota => owner.counters.peer_refusals +|= 1,
            .global_quota => owner.counters.aggregate_refusals +|= 1,
            .identity_capacity => owner.counters.identity_capacity_refusals +|= 1,
        }
        owner.protocol_counters[@intFromEnum(lifecycle.protocol)].rate_limited +|= 1;
        std.log.scoped(.network_reqresp_errors).debug("request_admission_refused connection={d}:{d} method={s} reason={s} cost={d}", .{ lifecycle.conn.index, lifecycle.conn.generation, @tagName(lifecycle.protocol), @tagName(decision), cost });
        return false;
    }

    fn reject(owner: *ReqResp, slot: *Server, code: u8, message: []const u8, now: Now) void {
        const lifecycle = &slot.lifecycle;
        assert(message.len <= lifecycle.error_message.len);
        @memcpy(lifecycle.error_message[0..message.len], message);
        lifecycle.error_len = @intCast(message.len);
        lifecycle.io.decoding = false;
        slot.state = .serving;
        Server.queueChunk(
            owner,
            slot,
            code,
            null,
            lifecycle.error_message[0..message.len],
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
        const lifecycle = &slot.lifecycle;
        assert(slot.state == .serving);
        assert(lifecycle.io.outbox.idle());
        lifecycle.io.payload = ssz;
        slot.pending_context = context;
        slot.pending_result = result;
        slot.close_after_write = close_after;
        slot.progress_ms = now.mono_ms;
        if (owner.limiter.take(lifecycle.conn, lifecycle.protocol, 1, now.mono_ms)) {
            Server.beginWrite(slot);
        } else {
            slot.state = .withheld;
            slot.withheld_since_ms = now.mono_ms;
            owner.counters.withheld_chunks += 1;
        }
    }

    fn beginWrite(slot: *Server) void {
        const lifecycle = &slot.lifecycle;
        lifecycle.needs_service = true;
        lifecycle.io.writer = codec.ChunkWriter.initChunk(
            slot.pending_result,
            slot.pending_context,
            lifecycle.io.payload,
        );
        lifecycle.io.writing = true;
        slot.state = .writing_chunk;
    }

    fn retryWithheld(owner: *ReqResp, slot: *Server, now: Now) void {
        const lifecycle = &slot.lifecycle;
        assert(slot.state == .withheld);
        if (!owner.limiter.take(lifecycle.conn, lifecycle.protocol, 1, now.mono_ms)) return;
        const since = slot.withheld_since_ms orelse now.mono_ms;
        owner.counters.withheld_ms_total += now.mono_ms -| since;
        slot.withheld_since_ms = null;
        slot.progress_ms = now.mono_ms;
        Server.beginWrite(slot);
    }

    fn writeChunk(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
        const lifecycle = &slot.lifecycle;
        const flushed = lifecycle.io.flush(engine, lifecycle.stream, false) catch |err| {
            lifecycle.io.failure_detail = @errorName(err);
            const reason: Failure = switch (err) {
                error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
                else => .transport,
            };
            lifecycle.fail(owner, index, reason, .{ .inbound = slot.state }, engine);
            return;
        };
        if (flushed.progressed) slot.progress_ms = now.mono_ms;
        if (!flushed.done) {
            if (lifecycle.io.outbox.idle()) lifecycle.needs_service = true;
            return;
        }
        if (slot.pending_result == constants.result_success) {
            lifecycle.chunks += 1;
            owner.counters.chunks_sent += 1;
        }
        lifecycle.io.payload = &.{};
        lifecycle.io.writer = undefined;
        if (slot.close_after_write) {
            lifecycle.io.outbox.queue("", true);
            slot.state = .finishing;
            lifecycle.needs_service = true;
            slot.progress_ms = now.mono_ms;
            return;
        }
        slot.state = .serving;
        slot.progress_ms = now.mono_ms;
        lifecycle.queue(.{ .chunk_sent = .{
            .request = lifecycle.handle(index),
            .chunks = lifecycle.chunks,
        } });
    }

    fn finishStream(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Server,
        index: u16,
        now: Now,
    ) void {
        const lifecycle = &slot.lifecycle;
        assert(slot.state == .finishing);
        const flushed = lifecycle.io.outbox.pump(engine, lifecycle.stream) catch |err| stopped: {
            if (err != error.StreamStopped or lifecycle.chunks == 0 or lifecycle.io.outbox.offset != lifecycle.io.outbox.bytes.len) {
                lifecycle.failStream(owner, index, err, .{ .inbound = slot.state }, engine);
                return;
            }
            owner.protocol_counters[@intFromEnum(lifecycle.protocol)].response_finish_stops +|= 1;
            std.log.scoped(.network_reqresp).debug("response_finish_stopped request={d}:{d} connection={d}:{d} stream={d} method={s} chunks={d}", .{ index, lifecycle.generation, lifecycle.conn.index, lifecycle.conn.generation, lifecycle.stream.id, @tagName(lifecycle.protocol), lifecycle.chunks });
            lifecycle.io.outbox = .{};
            break :stopped true;
        };
        if (!flushed) return;
        slot.progress_ms = now.mono_ms;
        owner.counters.requests_served += 1;
        lifecycle.complete(
            owner,
            index,
            .{ .served = .{ .request = lifecycle.handle(index), .chunks = lifecycle.chunks } },
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
        if (engine.peerId(stream.conn) == null) return error.StaleHandle;
        if (ready.leftover.len > reqresp.read_buffer_length) return error.InvalidHandoff;
        const which = switch (ready.protocol) {
            .reqresp => |which| which,
            else => return error.UnknownProtocol,
        };
        const bounds = which.info();
        if (owner.inboundCount(stream.conn, null) >= owner.options.inbound_per_peer_max) {
            return error.PeerSlotsExhausted;
        }
        const index = owner.availableInboundFor(which) orelse return error.SlotsExhausted;
        const slot = &owner.inbound[index];
        const request_sink = owner.inboundSink(index);
        assert(request_sink.len >= bounds.request_max);
        if (!which.isControl() and owner.options.inbound_application_per_peer_max > 0 and
            owner.inboundApplicationCount(stream.conn) >= owner.options.inbound_application_per_peer_max)
            return error.PeerSlotsExhausted;
        if (owner.inboundCount(stream.conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            owner.pushOverLimit(.{ .peer = stream.conn, .protocol = which });
        }
        slot.* = .{
            .request_fork = owner.request_fork,
            .progress_ms = now.mono_ms,
            .lifecycle = .{
                .completion = .active,
                .direction = .inbound,
                .generation = slot.lifecycle.generation + 1,
                .conn = stream.conn,
                .stream = stream,
                .protocol = which,
                .started_ms = now.mono_ms,
                .io = .{
                    .sink = request_sink,
                    .scratch = slot.lifecycle.io.scratch,
                    .read_buffer = slot.lifecycle.io.read_buffer,
                    .buffered_end = ready.leftover.len,
                    .fin_seen = ready.fin,
                },
            },
        };
        assert(ready.leftover.len <= slot.lifecycle.io.read_buffer.len);
        @memcpy(slot.lifecycle.io.read_buffer[0..ready.leftover.len], ready.leftover);
        if (bounds.request_max > 0) {
            slot.lifecycle.io.decoder = codec.Decoder.initRequest(
                .{ .min = bounds.request_min, .max = bounds.request_max },
                request_sink,
                slot.lifecycle.io.scratch,
            );
            slot.lifecycle.io.decoding = true;
        }
        owner.limiter.bind(stream.conn, now.mono_ms);
        owner.protocol_counters[@intFromEnum(which)].incoming +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=inbound request={d}:{d} connection={d}:{d} stream={d} method={s}", .{ index, slot.lifecycle.generation, stream.conn.index, stream.conn.generation, stream.id, @tagName(which) });
        slot.lifecycle.needs_service = true;
        assert(slot.lifecycle.active());
        return slot.lifecycle.handle(index);
    }

    pub fn respond(
        owner: *ReqResp,
        request_handle: RequestHandle,
        ssz: []const u8,
        context: ?reqresp.ForkEntry,
        now: Now,
    ) RespondError!void {
        const slot = try owner.servingSlot(request_handle);
        const lifecycle = &slot.lifecycle;
        const bounds = lifecycle.protocol.info();
        if (lifecycle.chunks >= lifecycle.chunks_max) return error.TooManyChunks;
        var response = codec.Bounds{ .min = bounds.response_min, .max = bounds.response_max };
        var digest: ?[constants.context_bytes_length]u8 = null;
        if (bounds.context_bytes) {
            const selected = context orelse return error.UnknownFork;
            const known = owner.forkFor(selected.digest) orelse return error.UnknownFork;
            if (known != selected.fork) return error.UnknownFork;
            response = lifecycle.protocol.responseBounds(known) catch return error.InvalidContext;
            digest = selected.digest;
        }
        if (!bounds.context_bytes and context != null) return error.InvalidContext;
        if (ssz.len > response.max) return error.ChunkTooLarge;
        if (ssz.len < response.min) return error.ChunkTooSmall;
        Server.queueChunk(owner, slot, constants.result_success, digest, ssz, false, now);
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
        const lifecycle = &slot.lifecycle;
        @memcpy(lifecycle.error_message[0..message.len], message);
        lifecycle.error_len = @intCast(message.len);
        Server.queueChunk(owner, slot, code, null, lifecycle.error_message[0..message.len], true, now);
    }

    pub fn finish(owner: *ReqResp, request_handle: RequestHandle, now: Now) bool {
        if (request_handle.direction != .inbound) return false;
        const slot = owner.inboundSlot(request_handle) orelse return false;
        const lifecycle = &slot.lifecycle;
        if (!lifecycle.running()) return false;
        if (lifecycle.pendingEvent()) |event| if (event == .request) return false;
        switch (slot.state) {
            .serving => {
                if (!lifecycle.io.outbox.idle()) return false;
                lifecycle.io.outbox.queue("", true);
                lifecycle.needs_service = true;
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
