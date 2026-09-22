const std = @import("std");
const config = @import("config");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const reqresp = @import("reqresp.zig");
const RequestIO = @import("request_io.zig").RequestIO;
const engine_mod = @import("../quic/engine.zig");
const types = @import("../types.zig");
const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const protocol = @import("protocol.zig");
const Protocol = protocol.Protocol;
const Now = types.Now;
const routing = @import("../router.zig");
const RequestOptions = reqresp.RequestOptions;
const RequestError = reqresp.RequestError;

const ReqResp = reqresp.ReqResp;
const RequestHandle = reqresp.RequestHandle;
const Event = reqresp.Event;
const Failure = reqresp.Failure;
const reads_per_pump_max = reqresp.reads_per_pump_max;

pub const Client = struct {
    request: @import("request_state.zig").RequestState = .{},
    phase: reqresp.RequestPhase = .negotiation,
    absolute_timeouts: reqresp.AbsoluteTimeouts = .{},
    phase_deadline_ms: u64 = 0,

    pub fn complete(self: *Client, owner: *ReqResp, index: u16, event: Event, engine: ?*Engine) void {
        owner.complete(&self.request, index, event, .{ .phase_name = @tagName(self.phase) });
        if (engine) |live| self.request.closeProtocol(live);
    }

    pub fn fail(self: *Client, owner: *ReqResp, index: u16, reason: Failure, engine: ?*Engine) void {
        self.complete(owner, index, .{ .failed = .{ .request = self.request.handle(index), .reason = reason, .phase = self.phase } }, engine);
    }

    fn failStream(self: *Client, owner: *ReqResp, index: u16, err: engine_mod.StreamError, engine: *Engine) void {
        self.request.failure_detail = @errorName(err);
        self.fail(owner, index, switch (err) {
            error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
            else => .transport,
        }, engine);
    }

    pub fn deadline(self: *const Client) ?u64 {
        return if (self.request.running()) self.phase_deadline_ms else null;
    }

    pub fn advance(self: *Client, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        const request = &self.request;
        if (!request.running()) return;
        if (self.deadline()) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (request.waitingHost())
                .host_timeout
            else
                .timeout;
            self.fail(ctx, index, reason, engine);
            return;
        };
        if (request.waitingHost()) return;
        switch (self.phase) {
            .negotiation => {},
            .request => sendRequest(ctx, engine, self, index, now),
            .response => readResponse(ctx, engine, self, index),
        }
    }

    fn sendRequest(owner: *ReqResp, engine: *Engine, slot: *Client, index: u16, now: Now) void {
        const request = &slot.request;
        const flushed = request.io.flush(engine, request.stream, true) catch |err| stopped: {
            if (err == error.StreamStopped or (err == error.UnknownStream and request.io.fin_seen)) {
                // STOP_SENDING closes only the request direction; the peer can still send a response.
                // quiche may already have retired that stream if its response FIN was read by the router.
                request.io.writing = false;
                request.io.outbox = .{};
                owner.protocol_counters[@intFromEnum(request.protocol)].request_write_stops +|= 1;
                std.log.scoped(.network_reqresp).debug("request_write_stopped request={d}:{d} connection={d}:{d} method={s} detail={s} response_fin={any} awaiting_response=true", .{ index, request.generation, request.conn.index, request.conn.generation, @tagName(request.protocol), @errorName(err), request.io.fin_seen });
                break :stopped RequestIO.Flush{ .done = true };
            }
            request.failure_detail = @errorName(err);
            slot.fail(owner, index, switch (err) {
                error.StaleHandle, error.UnknownStream => .stream_closed,
                else => .transport,
            }, engine);
            return;
        };
        if (!flushed.done) {
            request.needs_service = flushed.runnable;
            return;
        }
        request.io.payload = &.{};
        request.io.writer = undefined;
        slot.phase = .response;
        slot.phase_deadline_ms = now.mono_ms +| slot.absolute_timeouts.response_ms;
        slot.resetResponseDecoder(owner);
        // Native response bytes may already be readable after this turn consumed activity.
        request.needs_service = true;
    }

    fn readResponse(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
    ) void {
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
            if (input.bytes.len == 0 and !input.fin) return;
            if (input.bytes.len > 0) {
                const done = request.io.feed(input.bytes) catch |err| {
                    slot.fail(owner, index, .{ .invalid_response = err }, engine);
                    return;
                };
                if (request.io.decoder.awaitingContext()) {
                    const digest = request.io.decoder.context().?;
                    const fork = owner.forkFor(digest) orelse {
                        slot.fail(owner, index, .{ .unknown_context = digest }, engine);
                        return;
                    };
                    const bounds = owner.responseBounds(request.protocol, fork) catch |err| {
                        slot.fail(owner, index, .{ .invalid_response = err }, engine);
                        return;
                    };
                    request.io.decoder.setContextBounds(bounds) catch |err| {
                        slot.fail(owner, index, .{ .invalid_response = err }, engine);
                        return;
                    };
                }
                if (done) {
                    Client.completeChunk(owner, engine, slot, index);
                    return;
                }
            }
            if (request.io.fin_seen and request.io.buffered_start == request.io.buffered_end) {
                if (request.io.decoder.phase == .result) {
                    slot.complete(
                        owner,
                        index,
                        .{ .done = .{ .request = request.handle(index), .chunks = request.chunks } },
                        engine,
                    );
                } else {
                    slot.fail(owner, index, .{ .invalid_response = error.Truncated }, engine);
                }
                return;
            }
        }
        request.needs_service = true;
    }

    fn completeChunk(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
    ) void {
        const request = &slot.request;
        assert(request.io.decoder.isDone());
        const payload = request.io.decoder.payload();
        if (request.io.decoder.isError()) {
            const message_len: u16 = @intCast(@min(payload.len, codec.error_message_max));
            @memcpy(request.error_message[0..message_len], payload[0..message_len]);
            request.error_len = message_len;
            const code = request.io.decoder.result();
            const reason = Failure{ .peer_error = .{ .code = code, .message_len = message_len } };
            slot.fail(owner, index, reason, engine);
            return;
        }
        if (request.chunks >= request.chunks_max) {
            slot.fail(owner, index, .too_many_chunks, engine);
            return;
        }
        var fork: ?config.ForkSeq = null;
        if (request.io.decoder.context()) |digest| {
            fork = owner.forkFor(digest) orelse {
                slot.fail(owner, index, .{ .unknown_context = digest }, engine);
                return;
            };
        }
        request.chunks += 1;
        owner.counters.chunks_received += 1;
        request.queue(.{ .chunk = .{
            .request = request.handle(index),
            .bytes = payload,
            .fork = fork,
        } });
    }

    fn resetResponseDecoder(slot: *Client, owner: *const ReqResp) void {
        const request = &slot.request;
        const bounds = owner.requestBounds(request.protocol);
        const response = codec.Bounds{ .min = if (bounds.context_bytes) 0 else bounds.response_min, .max = bounds.response_max };
        request.io.decoder = if (bounds.context_bytes)
            codec.Decoder.initResponseWithContext(response, request.io.sink, request.io.scratch)
        else
            codec.Decoder.initResponse(response, false, request.io.sink, request.io.scratch);
        request.io.decoding = true;
    }

    pub fn start(
        owner: *ReqResp,
        engine: *Engine,
        router: *routing.Router,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        request_options: RequestOptions,
        now: Now,
    ) RequestError!RequestHandle {
        const bounds = owner.requestBounds(which);
        try owner.attach(engine);
        if (conn.index >= owner.options.peers) return error.InvalidCapacity;
        inline for (.{ "negotiation_ms", "request_ms", "response_ms" }) |field| {
            const duration = @field(request_options.absolute_timeouts, field);
            if (duration == 0 or duration > 60_000) return error.InvalidRequestOptions;
        }
        if (request_ssz.len > bounds.request_max) return error.RequestTooLarge;
        if (request_ssz.len < bounds.request_min) return error.RequestTooSmall;
        const request_ceiling = (owner.inspectRequest(which, request_ssz, owner.request_fork) catch return error.InvalidRequest).chunks_max;
        const chunks_max = request_options.expected_chunks orelse request_ceiling;
        if (chunks_max > request_ceiling) return error.InvalidRequestOptions;
        if (sink.len < bounds.response_max) return error.SinkTooSmall;
        if (owner.outboundCount(conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            return error.TooManyRequests;
        }
        if (!which.isControl() and owner.options.outbound_per_peer_max > 0 and
            owner.outboundApplicationCount(conn) >= owner.options.outbound_per_peer_max)
            return error.TooManyRequests;
        const index = owner.availableOutboundFor(which) orelse return error.SlotsExhausted;
        const slot = &owner.outbound[index];
        const stream = router.beginReqRespTimed(engine, conn, which, now, request_options.absolute_timeouts.negotiation_ms) catch |err| {
            return switch (err) {
                error.NegotiationTableFull => error.NegotiationTableFull,
                error.ProtocolDisabled => error.ProtocolDisabled,
                error.StaleHandle => error.StaleHandle,
                else => error.Transport,
            };
        };
        slot.* = .{
            .absolute_timeouts = request_options.absolute_timeouts,
            .phase_deadline_ms = now.mono_ms +| request_options.absolute_timeouts.negotiation_ms,
            .request = .{
                .completion = .active,
                .stream_owner = .router,
                .generation = slot.request.generation + 1,
                .conn = conn,
                .stream = stream,
                .protocol = which,
                .started_ms = now.mono_ms,
                .io = .{ .payload = request_ssz, .sink = sink, .scratch = slot.request.io.scratch, .read_buffer = slot.request.io.read_buffer },
                .chunks_max = chunks_max,
            },
        };
        owner.counters.requests_sent += 1;
        owner.protocol_counters[@intFromEnum(which)].outgoing +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=outbound request={d}:{d} connection={d}:{d} stream={d} method={s} bytes={d} max_chunks={d}", .{ index, slot.request.generation, conn.index, conn.generation, stream.id, @tagName(which), request_ssz.len, chunks_max });
        assert(slot.request.active());
        return slot.request.handle(index);
    }

    pub fn negotiated(owner: *ReqResp, outcome: routing.Outcome, now: Now) bool {
        for (owner.outbound, 0..) |*slot, position| {
            const request = &slot.request;
            if (!request.running() or slot.phase != .negotiation) continue;
            if (!std.meta.eql(request.stream, outcome.stream)) continue;
            const index: u16 = @intCast(position);
            request.stream_owner = .protocol;
            switch (outcome.result) {
                .ready => |ready| {
                    if (ready.protocol != .reqresp or ready.protocol.reqresp != request.protocol or
                        ready.leftover.len > request.io.read_buffer.len)
                    {
                        slot.fail(owner, index, .transport, null);
                        return true;
                    }
                    assert(ready.leftover.len <= request.io.read_buffer.len);
                    @memcpy(request.io.read_buffer[0..ready.leftover.len], ready.leftover);
                    request.io.buffered_start = 0;
                    request.io.buffered_end = ready.leftover.len;
                    request.io.fin_seen = ready.fin;
                    slot.phase = .request;
                    slot.phase_deadline_ms = now.mono_ms +| slot.absolute_timeouts.request_ms;
                    request.needs_service = true;
                    request.io.writer = codec.ChunkWriter.initRequest(request.io.payload);
                    request.io.writing = request.protocol.info().request_max > 0;
                    if (!request.io.writing) request.io.outbox.queue("", true);
                },
                .rejected => slot.fail(owner, index, .negotiation_rejected, null),
                .failed => |failure| {
                    slot.fail(owner, index, if (failure == .timeout) .timeout else .{ .negotiation_failed = failure }, null);
                },
            }
            return true;
        }
        return false;
    }

    pub fn consume(owner: *ReqResp, request_handle: RequestHandle) bool {
        if (request_handle.direction != .outbound) return false;
        const slot = owner.outboundSlot(request_handle) orelse return false;
        const request = &slot.request;
        if (!request.consume()) return false;
        if (!request.running()) return true;
        assert(slot.phase == .response);
        if (request.chunks >= request.chunks_max) {
            const done = Event{ .done = .{ .request = request_handle, .chunks = request.chunks } };
            slot.complete(owner, request_handle.index, done, null);
            return true;
        }
        request.needs_service = true;
        slot.resetResponseDecoder(owner);
        return true;
    }
};
