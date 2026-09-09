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
const StreamHandle = engine_mod.StreamHandle;
const protocol = @import("protocol.zig");
const Protocol = protocol.Protocol;
const Now = types.Now;
const routing = @import("../router.zig");
const RequestOptions = reqresp.RequestOptions;
const RequestError = reqresp.RequestError;
const AcceptError = reqresp.AcceptError;
const RespondError = reqresp.RespondError;

const ReqResp = reqresp.ReqResp;
const RequestHandle = reqresp.RequestHandle;
const Event = reqresp.Event;
const Failure = reqresp.Failure;
const reads_per_pump_max = reqresp.reads_per_pump_max;

pub const State = enum {
    free,
    negotiating,
    sending_request,
    awaiting,
    reading,
    chunk_ready,
    terminal,
    reported,
};

pub const Client = struct {
    request_ssz: []const u8 = &.{},
    chunks_max: u32 = 1,
    chunk_held: bool = false,
    negotiation_owned: bool = true,
    state: State = .free,
    generation: u32 = 0,
    conn: Handle = undefined,
    stream: StreamHandle = undefined,
    protocol: Protocol = .status_v1,
    progress_ms: u64 = 0,
    started_ms: u64 = 0,
    needs_service: bool = false,
    timeout_ms: u64 = 0,
    absolute_timeouts: ?reqresp.AbsoluteTimeouts = null,
    phase_deadline_ms: u64 = 0,
    chunks: u32 = 0,
    io: RequestIO = .{},
    error_message: [codec.error_message_max]u8 = undefined,
    error_len: u16 = 0,
    pending_event: ?Event = null,
    terminal: ?Event = null,
    after_event: State = .free,
    close_pending: bool = false,
    close_code: u64 = types.app_error_normal,

    pub fn delivered(self: *Client, event: Event, now: Now) void {
        _ = now;
        if (event == .chunk) self.chunk_held = true;
        if (self.terminal == null) self.state = self.after_event;
    }

    pub fn clear(self: *Client) void {
        self.io.clear();
        self.needs_service = false;
        self.request_ssz = &.{};
    }

    pub fn requestPhase(self: *const Client) reqresp.RequestPhase {
        return switch (self.state) {
            .negotiating => .negotiation,
            .sending_request => .request,
            .awaiting, .reading, .chunk_ready => .response,
            .free, .terminal, .reported => unreachable,
        };
    }

    pub fn deadline(self: *const Client, ctx: *const ReqResp) ?u64 {
        if (!self.active() or self.terminal != null) return null;
        if (self.absolute_timeouts != null) return self.phase_deadline_ms;
        if (self.state == .negotiating) return null;
        const duration = if (self.pending_event != null or self.state == .chunk_ready)
            ctx.options.host_timeout_ms
        else
            self.timeout_ms;
        return self.progress_ms +| duration;
    }

    pub fn advance(self: *Client, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        if (self.terminal != null) return;
        if (self.deadline(ctx)) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (self.pending_event != null or self.state == .chunk_ready)
                .host_timeout
            else
                .timeout;
            if (reason == .timeout) ctx.counters.timeouts += 1;
            ctx.fail(self, index, reason, engine);
            return;
        };
        if (self.pending_event != null) return;
        switch (self.state) {
            .negotiating, .chunk_ready, .terminal => {},
            .sending_request => sendRequest(ctx, engine, self, index, now),
            .awaiting, .reading => readResponse(ctx, engine, self, index, now),
            .free, .reported => unreachable,
        }
    }

    pub fn active(self: *const Client) bool {
        return self.state != .free and self.state != .reported;
    }

    pub fn handle(self: *const Client, index: u16) RequestHandle {
        return .{ .index = index, .generation = self.generation, .direction = .outbound };
    }

    pub fn sendRequest(owner: *ReqResp, engine: *Engine, slot: *Client, index: u16, now: Now) void {
        const flushed = slot.io.flush(engine, slot.stream, true) catch |err| stopped: {
            if (err == error.StreamStopped or (err == error.UnknownStream and slot.io.fin_seen)) {
                // STOP_SENDING closes only the request direction; the peer can still send a response.
                // quiche may already have retired that stream if its response FIN was read by the router.
                slot.io.writing = false;
                slot.io.outbox = .{};
                owner.protocol_counters[@intFromEnum(slot.protocol)].request_write_stops +|= 1;
                std.log.scoped(.network_reqresp).debug("request_write_stopped request={d}:{d} connection={d}:{d} method={s} detail={s} response_fin={any} awaiting_response=true", .{ index, slot.generation, slot.conn.index, slot.conn.generation, @tagName(slot.protocol), @errorName(err), slot.io.fin_seen });
                break :stopped RequestIO.Flush{ .done = true, .progressed = false };
            }
            slot.io.failure_detail = @errorName(err);
            owner.fail(slot, index, switch (err) {
                error.StaleHandle, error.UnknownStream => .stream_closed,
                else => .transport,
            }, engine);
            return;
        };
        if (flushed.progressed) slot.progress_ms = now.mono_ms;
        if (!flushed.done) {
            if (slot.io.outbox.idle()) slot.needs_service = true;
            return;
        }
        slot.request_ssz = &.{};
        slot.io.writer = undefined;
        slot.state = .awaiting;
        if (slot.absolute_timeouts) |policy| slot.phase_deadline_ms = now.mono_ms +| policy.response_ms;
        slot.progress_ms = now.mono_ms;
        Client.resetResponseDecoder(owner, slot);
        // Native response bytes may already be readable after this turn consumed activity.
        slot.needs_service = true;
    }

    pub fn readResponse(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
        now: Now,
    ) void {
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            const input = slot.io.read(engine, slot.stream) catch |err| {
                owner.failStream(slot, index, err, engine);
                return;
            };
            if (input.reset) {
                owner.fail(slot, index, .stream_closed, engine);
                return;
            }
            if (input.progressed) slot.progress_ms = now.mono_ms;
            if (input.bytes.len == 0 and !input.fin) return;
            if (input.bytes.len > 0) {
                const done = slot.io.feed(input.bytes) catch |err| {
                    owner.fail(slot, index, .{ .invalid_response = err }, engine);
                    return;
                };
                if (slot.io.decoder.awaitingContext()) {
                    const digest = slot.io.decoder.context().?;
                    const fork = owner.forkFor(digest) orelse {
                        owner.fail(slot, index, .{ .unknown_context = digest }, engine);
                        return;
                    };
                    const bounds = slot.protocol.responseBounds(fork) catch |err| {
                        owner.fail(slot, index, .{ .invalid_response = err }, engine);
                        return;
                    };
                    slot.io.decoder.setContextBounds(bounds) catch |err| {
                        owner.fail(slot, index, .{ .invalid_response = err }, engine);
                        return;
                    };
                }
                if (done) {
                    Client.completeChunk(owner, engine, slot, index, now);
                    return;
                }
            }
            if (slot.io.fin_seen and slot.io.buffered_start == slot.io.buffered_end) {
                if (slot.io.decoder.phase == .result) {
                    owner.complete(
                        slot,
                        index,
                        .{ .done = .{ .request = slot.handle(index), .chunks = slot.chunks } },
                        engine,
                    );
                } else {
                    owner.fail(slot, index, .{ .invalid_response = error.Truncated }, engine);
                }
                return;
            }
        }
        slot.needs_service = true;
    }

    pub fn completeChunk(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Client,
        index: u16,
        now: Now,
    ) void {
        assert(slot.io.decoder.isDone());
        const payload = slot.io.decoder.payload();
        if (slot.io.decoder.isError()) {
            const message_len: u16 = @intCast(@min(payload.len, codec.error_message_max));
            @memcpy(slot.error_message[0..message_len], payload[0..message_len]);
            slot.error_len = message_len;
            const code = slot.io.decoder.result();
            const reason = Failure{ .peer_error = .{ .code = code, .message_len = message_len } };
            owner.fail(slot, index, reason, engine);
            return;
        }
        if (slot.chunks >= slot.chunks_max) {
            owner.fail(slot, index, .too_many_chunks, engine);
            return;
        }
        var fork: ?config.ForkSeq = null;
        if (slot.io.decoder.context()) |digest| {
            fork = owner.forkFor(digest) orelse {
                owner.fail(slot, index, .{ .unknown_context = digest }, engine);
                return;
            };
        }
        slot.chunks += 1;
        slot.progress_ms = now.mono_ms;
        owner.counters.chunks_received += 1;
        slot.pending_event = .{ .chunk = .{
            .request = slot.handle(index),
            .bytes = payload,
            .fork = fork,
        } };
        slot.after_event = .chunk_ready;
    }

    pub fn resetResponseDecoder(owner: *ReqResp, slot: *Client) void {
        _ = owner;
        const bounds = slot.protocol.info();
        const response = codec.Bounds{ .min = bounds.response_min, .max = bounds.response_max };
        slot.io.decoder = if (bounds.context_bytes)
            codec.Decoder.initResponseWithContext(response, slot.io.sink, slot.io.scratch)
        else
            codec.Decoder.initResponse(response, false, slot.io.sink, slot.io.scratch);
        slot.io.decoding = true;
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
        if (request_options.progress_timeout_ms == 0) return error.InvalidRequestOptions;
        if (request_options.absolute_timeouts) |policy| {
            if (request_options.progress_timeout_ms != null) return error.InvalidRequestOptions;
            inline for (.{ "negotiation_ms", "request_ms", "response_ms" }) |field| {
                const duration = @field(policy, field);
                if (duration == 0 or duration > 60_000) return error.InvalidRequestOptions;
            }
        }
        if (request_ssz.len > bounds.request_max) return error.RequestTooLarge;
        if (request_ssz.len < bounds.request_min) return error.RequestTooSmall;
        const request_ceiling = if (owner.policy) |*policy|
            (policy.inspect(which, request_ssz, owner.request_fork) catch return error.InvalidRequest).chunks_max
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
        const opened = if (request_options.absolute_timeouts) |policy|
            router.beginReqRespTimed(engine, conn, which, now, policy.negotiation_ms)
        else
            router.beginOutbound(engine, conn, .{ .reqresp = which }, now);
        const stream = opened catch |err| {
            owner.outbound[index].state = .free;
            return switch (err) {
                error.NegotiationTableFull => error.NegotiationTableFull,
                error.ProtocolDisabled => error.ProtocolDisabled,
                error.StaleHandle => error.StaleHandle,
                else => error.Transport,
            };
        };
        slot.* = .{
            .state = .negotiating,
            .absolute_timeouts = request_options.absolute_timeouts,
            .phase_deadline_ms = if (request_options.absolute_timeouts) |policy| now.mono_ms +| policy.negotiation_ms else 0,
            .generation = slot.generation + 1,
            .conn = conn,
            .stream = stream,
            .protocol = which,
            .progress_ms = now.mono_ms,
            .started_ms = now.mono_ms,
            .timeout_ms = request_options.progress_timeout_ms orelse
                owner.options.progress_timeout_ms,
            .io = .{ .sink = sink, .scratch = slot.io.scratch, .read_buffer = slot.io.read_buffer },
            .request_ssz = request_ssz,
            .chunks_max = chunks_max,
        };
        owner.counters.requests_sent += 1;
        owner.protocol_counters[@intFromEnum(which)].outgoing +|= 1;
        std.log.scoped(.network_reqresp).debug("request_started direction=outbound request={d}:{d} connection={d}:{d} stream={d} method={s} bytes={d} max_chunks={d}", .{ index, slot.generation, conn.index, conn.generation, stream.id, @tagName(which), request_ssz.len, chunks_max });
        assert(slot.active());
        return slot.handle(index);
    }

    pub fn negotiated(owner: *ReqResp, outcome: routing.Outcome, now: Now) bool {
        for (owner.outbound, 0..) |*slot, position| {
            if (slot.state != .negotiating) continue;
            if (!std.meta.eql(slot.stream, outcome.stream)) continue;
            const index: u16 = @intCast(position);
            slot.negotiation_owned = false;
            switch (outcome.result) {
                .ready => |ready| {
                    if (ready.protocol != .reqresp or ready.protocol.reqresp != slot.protocol or
                        ready.leftover.len > slot.io.read_buffer.len)
                    {
                        owner.fail(slot, index, .transport, null);
                        return true;
                    }
                    assert(ready.leftover.len <= slot.io.read_buffer.len);
                    @memcpy(slot.io.read_buffer[0..ready.leftover.len], ready.leftover);
                    slot.io.buffered_start = 0;
                    slot.io.buffered_end = ready.leftover.len;
                    slot.io.fin_seen = ready.fin;
                    slot.state = .sending_request;
                    if (slot.absolute_timeouts) |policy| slot.phase_deadline_ms = now.mono_ms +| policy.request_ms;
                    slot.needs_service = true;
                    slot.progress_ms = now.mono_ms;
                    slot.io.writer = codec.ChunkWriter.initRequest(slot.request_ssz);
                    slot.io.writing = slot.protocol.info().request_max > 0;
                    if (!slot.io.writing) slot.io.outbox.queue("", true);
                },
                .rejected => owner.fail(slot, index, .negotiation_rejected, null),
                .failed => |failure| {
                    owner.fail(slot, index, if (failure == .timeout and slot.absolute_timeouts != null) .timeout else .{ .negotiation_failed = failure }, null);
                },
            }
            return true;
        }
        return false;
    }

    pub fn consume(owner: *ReqResp, request_handle: RequestHandle, now: Now) bool {
        if (request_handle.direction != .outbound) return false;
        const slot = owner.outboundSlot(request_handle) orelse return false;
        if (!slot.chunk_held) return false;
        slot.chunk_held = false;
        if (slot.terminal != null) return true;
        assert(slot.state == .chunk_ready);
        if (slot.chunks >= slot.chunks_max) {
            const done = Event{ .done = .{ .request = request_handle, .chunks = slot.chunks } };
            slot.close_pending = true;
            owner.complete(slot, request_handle.index, done, null);
            return true;
        }
        slot.state = .reading;
        slot.needs_service = true;
        slot.progress_ms = now.mono_ms;
        Client.resetResponseDecoder(owner, slot);
        return true;
    }
};
