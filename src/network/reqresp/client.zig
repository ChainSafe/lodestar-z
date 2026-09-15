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
    lifecycle: @import("lifecycle.zig").Lifecycle = .{},
    phase: reqresp.RequestPhase = .negotiation,
    absolute_timeouts: reqresp.AbsoluteTimeouts = .{},
    phase_deadline_ms: u64 = 0,

    pub fn deadline(self: *const Client) ?u64 {
        return if (self.lifecycle.running()) self.phase_deadline_ms else null;
    }

    pub fn advance(self: *Client, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        const lifecycle = &self.lifecycle;
        if (!lifecycle.running()) return;
        if (self.deadline()) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (lifecycle.waitingHost())
                .host_timeout
            else
                .timeout;
            if (reason == .timeout) ctx.counters.timeouts += 1;
            lifecycle.fail(ctx, index, reason, .{ .outbound = self.phase }, engine);
            return;
        };
        if (lifecycle.waitingHost()) return;
        switch (self.phase) {
            .negotiation => {},
            .request => sendRequest(ctx, engine, self, index, now),
            .response => readResponse(ctx, engine, self, index),
        }
    }

    fn sendRequest(owner: *ReqResp, engine: *Engine, slot: *Client, index: u16, now: Now) void {
        const lifecycle = &slot.lifecycle;
        const flushed = lifecycle.io.flush(engine, lifecycle.stream, true) catch |err| stopped: {
            if (err == error.StreamStopped or (err == error.UnknownStream and lifecycle.io.fin_seen)) {
                // STOP_SENDING closes only the request direction; the peer can still send a response.
                // quiche may already have retired that stream if its response FIN was read by the router.
                lifecycle.io.writing = false;
                lifecycle.io.outbox = .{};
                owner.protocol_counters[@intFromEnum(lifecycle.protocol)].request_write_stops +|= 1;
                std.log.scoped(.network_reqresp).debug("request_write_stopped request={d}:{d} connection={d}:{d} method={s} detail={s} response_fin={any} awaiting_response=true", .{ index, lifecycle.generation, lifecycle.conn.index, lifecycle.conn.generation, @tagName(lifecycle.protocol), @errorName(err), lifecycle.io.fin_seen });
                break :stopped RequestIO.Flush{ .done = true, .progressed = false };
            }
            lifecycle.io.failure_detail = @errorName(err);
            lifecycle.fail(owner, index, switch (err) {
                error.StaleHandle, error.UnknownStream => .stream_closed,
                else => .transport,
            }, .{ .outbound = slot.phase }, engine);
            return;
        };
        if (!flushed.done) {
            if (lifecycle.io.outbox.idle()) lifecycle.needs_service = true;
            return;
        }
        lifecycle.io.payload = &.{};
        lifecycle.io.writer = undefined;
        slot.phase = .response;
        slot.phase_deadline_ms = now.mono_ms +| slot.absolute_timeouts.response_ms;
        slot.resetResponseDecoder();
        // Native response bytes may already be readable after this turn consumed activity.
        lifecycle.needs_service = true;
    }

    fn readResponse(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
    ) void {
        const lifecycle = &slot.lifecycle;
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            const input = lifecycle.io.read(engine, lifecycle.stream) catch |err| {
                lifecycle.failStream(owner, index, err, .{ .outbound = slot.phase }, engine);
                return;
            };
            if (input.reset) {
                lifecycle.fail(owner, index, .stream_closed, .{ .outbound = slot.phase }, engine);
                return;
            }
            if (input.bytes.len == 0 and !input.fin) return;
            if (input.bytes.len > 0) {
                const done = lifecycle.io.feed(input.bytes) catch |err| {
                    lifecycle.fail(owner, index, .{ .invalid_response = err }, .{ .outbound = slot.phase }, engine);
                    return;
                };
                if (lifecycle.io.decoder.awaitingContext()) {
                    const digest = lifecycle.io.decoder.context().?;
                    const fork = owner.forkFor(digest) orelse {
                        lifecycle.fail(owner, index, .{ .unknown_context = digest }, .{ .outbound = slot.phase }, engine);
                        return;
                    };
                    const bounds = lifecycle.protocol.responseBounds(fork) catch |err| {
                        lifecycle.fail(owner, index, .{ .invalid_response = err }, .{ .outbound = slot.phase }, engine);
                        return;
                    };
                    lifecycle.io.decoder.setContextBounds(bounds) catch |err| {
                        lifecycle.fail(owner, index, .{ .invalid_response = err }, .{ .outbound = slot.phase }, engine);
                        return;
                    };
                }
                if (done) {
                    Client.completeChunk(owner, engine, slot, index);
                    return;
                }
            }
            if (lifecycle.io.fin_seen and lifecycle.io.buffered_start == lifecycle.io.buffered_end) {
                if (lifecycle.io.decoder.phase == .result) {
                    lifecycle.complete(
                        owner,
                        index,
                        .{ .done = .{ .request = lifecycle.handle(index), .chunks = lifecycle.chunks } },
                        engine,
                    );
                } else {
                    lifecycle.fail(owner, index, .{ .invalid_response = error.Truncated }, .{ .outbound = slot.phase }, engine);
                }
                return;
            }
        }
        lifecycle.needs_service = true;
    }

    fn completeChunk(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
    ) void {
        const lifecycle = &slot.lifecycle;
        assert(lifecycle.io.decoder.isDone());
        const payload = lifecycle.io.decoder.payload();
        if (lifecycle.io.decoder.isError()) {
            const message_len: u16 = @intCast(@min(payload.len, codec.error_message_max));
            @memcpy(lifecycle.error_message[0..message_len], payload[0..message_len]);
            lifecycle.error_len = message_len;
            const code = lifecycle.io.decoder.result();
            const reason = Failure{ .peer_error = .{ .code = code, .message_len = message_len } };
            lifecycle.fail(owner, index, reason, .{ .outbound = slot.phase }, engine);
            return;
        }
        if (lifecycle.chunks >= lifecycle.chunks_max) {
            lifecycle.fail(owner, index, .too_many_chunks, .{ .outbound = slot.phase }, engine);
            return;
        }
        var fork: ?config.ForkSeq = null;
        if (lifecycle.io.decoder.context()) |digest| {
            fork = owner.forkFor(digest) orelse {
                lifecycle.fail(owner, index, .{ .unknown_context = digest }, .{ .outbound = slot.phase }, engine);
                return;
            };
        }
        lifecycle.chunks += 1;
        owner.counters.chunks_received += 1;
        lifecycle.queue(.{ .chunk = .{
            .request = lifecycle.handle(index),
            .bytes = payload,
            .fork = fork,
        } });
    }

    fn resetResponseDecoder(slot: *Client) void {
        const lifecycle = &slot.lifecycle;
        const bounds = lifecycle.protocol.info();
        const response = codec.Bounds{ .min = bounds.response_min, .max = bounds.response_max };
        lifecycle.io.decoder = if (bounds.context_bytes)
            codec.Decoder.initResponseWithContext(response, lifecycle.io.sink, lifecycle.io.scratch)
        else
            codec.Decoder.initResponse(response, false, lifecycle.io.sink, lifecycle.io.scratch);
        lifecycle.io.decoding = true;
    }

    pub fn request(
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
        const bounds = which.info();
        try owner.attach(engine);
        if (conn.index >= owner.options.peers) return error.InvalidCapacity;
        inline for (.{ "negotiation_ms", "request_ms", "response_ms" }) |field| {
            const duration = @field(request_options.absolute_timeouts, field);
            if (duration == 0 or duration > 60_000) return error.InvalidRequestOptions;
        }
        if (request_ssz.len > bounds.request_max) return error.RequestTooLarge;
        if (request_ssz.len < bounds.request_min) return error.RequestTooSmall;
        const request_ceiling = if (owner.admission) |*admission|
            (admission.policy.inspect(which, request_ssz, owner.request_fork) catch return error.InvalidRequest).chunks_max
        else
            try protocol.requestChunkLimit(which, request_ssz);
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
            .lifecycle = .{
                .completion = .active,
                .stream_owner = .router,
                .generation = slot.lifecycle.generation + 1,
                .conn = conn,
                .stream = stream,
                .protocol = which,
                .started_ms = now.mono_ms,
                .io = .{ .payload = request_ssz, .sink = sink, .scratch = slot.lifecycle.io.scratch, .read_buffer = slot.lifecycle.io.read_buffer },
                .chunks_max = chunks_max,
            },
        };
        owner.counters.requests_sent += 1;
        owner.protocol_counters[@intFromEnum(which)].outgoing +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=outbound request={d}:{d} connection={d}:{d} stream={d} method={s} bytes={d} max_chunks={d}", .{ index, slot.lifecycle.generation, conn.index, conn.generation, stream.id, @tagName(which), request_ssz.len, chunks_max });
        assert(slot.lifecycle.active());
        return slot.lifecycle.handle(index);
    }

    pub fn negotiated(owner: *ReqResp, outcome: routing.Outcome, now: Now) bool {
        for (owner.outbound, 0..) |*slot, position| {
            const lifecycle = &slot.lifecycle;
            if (!lifecycle.running() or slot.phase != .negotiation) continue;
            if (!std.meta.eql(lifecycle.stream, outcome.stream)) continue;
            const index: u16 = @intCast(position);
            lifecycle.stream_owner = .protocol;
            switch (outcome.result) {
                .ready => |ready| {
                    if (ready.protocol != .reqresp or ready.protocol.reqresp != lifecycle.protocol or
                        ready.leftover.len > lifecycle.io.read_buffer.len)
                    {
                        lifecycle.fail(owner, index, .transport, .{ .outbound = slot.phase }, null);
                        return true;
                    }
                    assert(ready.leftover.len <= lifecycle.io.read_buffer.len);
                    @memcpy(lifecycle.io.read_buffer[0..ready.leftover.len], ready.leftover);
                    lifecycle.io.buffered_start = 0;
                    lifecycle.io.buffered_end = ready.leftover.len;
                    lifecycle.io.fin_seen = ready.fin;
                    slot.phase = .request;
                    slot.phase_deadline_ms = now.mono_ms +| slot.absolute_timeouts.request_ms;
                    lifecycle.needs_service = true;
                    lifecycle.io.writer = codec.ChunkWriter.initRequest(lifecycle.io.payload);
                    lifecycle.io.writing = lifecycle.protocol.info().request_max > 0;
                    if (!lifecycle.io.writing) lifecycle.io.outbox.queue("", true);
                },
                .rejected => lifecycle.fail(owner, index, .negotiation_rejected, .{ .outbound = slot.phase }, null),
                .failed => |failure| {
                    lifecycle.fail(owner, index, if (failure == .timeout) .timeout else .{ .negotiation_failed = failure }, .{ .outbound = slot.phase }, null);
                },
            }
            return true;
        }
        return false;
    }

    pub fn consume(owner: *ReqResp, request_handle: RequestHandle) bool {
        if (request_handle.direction != .outbound) return false;
        const slot = owner.outboundSlot(request_handle) orelse return false;
        const lifecycle = &slot.lifecycle;
        if (!lifecycle.consume()) return false;
        if (!lifecycle.running()) return true;
        assert(slot.phase == .response);
        if (lifecycle.chunks >= lifecycle.chunks_max) {
            const done = Event{ .done = .{ .request = request_handle, .chunks = lifecycle.chunks } };
            lifecycle.complete(owner, request_handle.index, done, null);
            return true;
        }
        lifecycle.needs_service = true;
        slot.resetResponseDecoder();
        return true;
    }
};
