const std = @import("std");
const config = @import("config");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const ReqResp = @import("ReqResp.zig");
const RequestIO = @import("RequestIO.zig");
const Engine = @import("../quic/Engine.zig");
const types = @import("../types.zig");
const assert = std.debug.assert;
const protocol = @import("protocol.zig");
const Protocol = protocol.Protocol;
const Now = types.Now;
const Router = @import("../router.zig").Router;
const RequestOptions = ReqResp.RequestOptions;
const RequestState = @import("RequestState.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const index_list = @import("../index_list.zig");

const Event = ReqResp.Event;
const Failure = ReqResp.Failure;
const reads_per_pump_max = RequestIO.reads_per_pump_max;

const Client = @This();

request: RequestState = .{},
phase: ReqResp.RequestPhase = .negotiation,
timeouts: ReqResp.RequestOptions.Timeouts = .{},
phase_deadline_ms: u64 = 0,
identity: PeerId = undefined,
protocol_chunks_max: u32 = 1,
host_hold_started_ms: ?u64 = null,
host_held_ms: u64 = 0,
/// On the owner's list for this slot's connection index while occupied.
conn_link: index_list.Link = .{},

pub fn complete(self: *Client, owner: *ReqResp, index: u16, event: Event, now: Now) void {
    owner.complete(&self.request, index, event, .{ .phase_name = @tagName(self.phase) }, now);
}

pub fn fail(self: *Client, owner: *ReqResp, index: u16, reason: Failure, now: Now) void {
    self.complete(owner, index, .{ .failed = .{ .request = self.request.handle(index), .reason = reason, .phase = self.phase } }, now);
}

fn failStream(self: *Client, owner: *ReqResp, index: u16, err: Engine.StreamError, now: Now) void {
    self.request.failure_detail = @errorName(err);
    self.fail(owner, index, switch (err) {
        error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
        else => .transport,
    }, now);
}

pub fn deadline(self: *const Client) ?u64 {
    return if (self.request.running()) self.phase_deadline_ms else null;
}

pub fn advance(self: *Client, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
    const request = &self.request;
    if (!request.running()) return;
    if (self.deadline()) |due| if (now.millis() >= due) {
        const reason: Failure = if (request.waitingHost())
            .host_timeout
        else
            .timeout;
        if (reason == .timeout and self.phase == .response and !request.protocol.isControl() and
            self.host_held_ms == 0 and !request.io.unread(engine, request.stream))
            request.peer_fault = .non_completion;
        self.fail(ctx, index, reason, now);
        return;
    };
    if (request.waitingHost()) return;
    switch (self.phase) {
        .negotiation => {},
        .request => sendRequest(ctx, engine, self, index, now),
        .response => readResponse(ctx, engine, self, index, now),
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
            std.log.scoped(.network_reqresp).debug("request_write_stopped request={d}:{d} connection={d}:{d} method={s} detail={s} response_fin={any} awaiting_response=true", .{ index, request.generation, request.conn.index, request.conn.generation, @tagName(request.protocol), @errorName(err), request.io.fin_seen });
            break :stopped .done;
        }
        request.failure_detail = @errorName(err);
        slot.fail(owner, index, switch (err) {
            error.StaleHandle, error.UnknownStream => .stream_closed,
            else => .transport,
        }, now);
        return;
    };
    if (flushed != .done) {
        if (flushed == .yielded) owner.markReady(.outbound, index);
        return;
    }
    request.io.payload = &.{};
    request.io.writer = undefined;
    slot.phase = .response;
    slot.phase_deadline_ms = now.deadlineMilliseconds(slot.timeouts.response);
    slot.resetResponseDecoder(owner);
    // Response bytes may have arrived while the request was still being written.
    owner.markReady(.outbound, index);
}

fn readResponse(
    owner: *ReqResp,
    engine: *Engine,
    slot: *Client,
    index: u16,
    now: Now,
) void {
    const request = &slot.request;
    var reads: u32 = 0;
    while (reads < reads_per_pump_max) : (reads += 1) {
        const input = request.io.read(engine, request.stream) catch |err| {
            slot.failStream(owner, index, err, now);
            return;
        };
        if (input.reset) {
            slot.fail(owner, index, .stream_closed, now);
            return;
        }
        if (input.bytes.len == 0 and !input.fin) return;
        if (input.bytes.len > 0) {
            const done = request.io.feed(input.bytes) catch |err| {
                if (request.io.decoder.protocolFault(err)) request.peer_fault = .protocol;
                slot.fail(owner, index, .{ .invalid_response = err }, now);
                return;
            };
            if (request.io.decoder.awaitingContext()) {
                const digest = request.io.decoder.context().?;
                const fork = owner.forkFor(digest) orelse {
                    request.peer_fault = .protocol;
                    slot.fail(owner, index, .{ .unknown_context = digest }, now);
                    return;
                };
                _ = request.protocol.responseBounds(fork) catch |err| {
                    request.peer_fault = .protocol;
                    slot.fail(owner, index, .{ .invalid_response = err }, now);
                    return;
                };
                const bounds = owner.responseBounds(request.protocol, fork) catch |err| {
                    slot.fail(owner, index, .{ .invalid_response = err }, now);
                    return;
                };
                request.io.decoder.setContextBounds(bounds) catch |err| {
                    slot.fail(owner, index, .{ .invalid_response = err }, now);
                    return;
                };
            }
            if (done) {
                Client.completeChunk(owner, slot, index, now);
                return;
            }
        }
        if (request.io.fin_seen and request.io.buffered_start == request.io.buffered_end) {
            if (request.io.decoder.phase == .result) {
                if (request.chunks == 0 and request.chunks_max > 0 and request.protocol.requiresResponse()) {
                    slot.fail(owner, index, .empty_response, now);
                } else {
                    slot.complete(owner, index, .{ .done = .{ .request = request.handle(index), .chunks = request.chunks } }, now);
                }
            } else {
                request.peer_fault = .protocol;
                slot.fail(owner, index, .{ .invalid_response = error.Truncated }, now);
            }
            return;
        }
    }
    owner.markReady(.outbound, index);
}

fn completeChunk(
    owner: *ReqResp,
    slot: *Client,
    index: u16,
    now: Now,
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
        slot.fail(owner, index, reason, now);
        return;
    }
    if (request.chunks >= request.chunks_max) {
        if (request.chunks >= slot.protocol_chunks_max) request.peer_fault = .protocol;
        slot.fail(owner, index, .too_many_chunks, now);
        return;
    }
    var fork: ?config.ForkSeq = null;
    if (request.io.decoder.context()) |digest| {
        fork = owner.forkFor(digest) orelse {
            request.peer_fault = .protocol;
            slot.fail(owner, index, .{ .unknown_context = digest }, now);
            return;
        };
    }
    request.chunks += 1;
    slot.host_hold_started_ms = now.millis();
    request.queue(.{ .chunk = .{
        .request = request.handle(index),
        .bytes = payload,
        .fork = fork,
    } });
}

fn resetResponseDecoder(slot: *Client, owner: *const ReqResp) void {
    const request = &slot.request;
    const bounds = owner.requestBounds(request.protocol);
    const response = codec.Bounds{ .min = if (bounds.context_bytes) 0 else bounds.response_min, .max = bounds.response_max, .protocol_max = request.protocol.info().response_max };
    request.io.decoder = if (bounds.context_bytes)
        codec.Decoder.initResponseWithContext(response, request.io.sink, request.io.scratch)
    else
        codec.Decoder.initResponse(response, false, request.io.sink, request.io.scratch);
    request.io.decoding = true;
}

pub const Start = struct {
    identity: PeerId,
    stream: Engine.StreamHandle,
    protocol: Protocol,
    request_ssz: []const u8,
    sink: []u8,
    timeouts: RequestOptions.Timeouts,
    protocol_chunks_max: u32,
    chunks_max: u32,
};

pub fn start(self: *Client, input: *const Start, now: Now) void {
    assert(self.request.available());
    assert(!self.conn_link.linked);
    self.* = .{
        .identity = input.identity,
        .protocol_chunks_max = input.protocol_chunks_max,
        .timeouts = input.timeouts,
        .phase_deadline_ms = now.deadlineMilliseconds(input.timeouts.negotiation),
        .request = .{
            .completion = .running,
            .stream_owner = .router,
            .generation = self.request.generation + 1,
            .conn = input.stream.conn,
            .stream = input.stream,
            .protocol = input.protocol,
            .started_ms = now.millis(),
            .io = .{ .payload = input.request_ssz, .sink = input.sink, .scratch = self.request.io.scratch, .read_buffer = self.request.io.read_buffer },
            .chunks_max = input.chunks_max,
        },
    };
}

pub fn negotiated(slot: *Client, owner: *ReqResp, engine: *Engine, index: u16, outcome: Router.Outcome, now: Now) void {
    const request = &slot.request;
    assert(request.running() and slot.phase == .negotiation);
    assert(std.meta.eql(request.stream, outcome.stream));
    request.stream_owner = .protocol;
    switch (outcome.result) {
        .ready => |ready| {
            if (ready.protocol != .reqresp or ready.protocol.reqresp != request.protocol or
                ready.leftover.len > request.io.read_buffer.len)
            {
                slot.fail(owner, index, .transport, now);
                return;
            }
            // A stream that is already gone fails on the slot's first write.
            engine.bindStream(outcome.stream, .{ .owner = .reqresp_outbound, .row = index }) catch {};
            assert(ready.leftover.len <= request.io.read_buffer.len);
            @memcpy(request.io.read_buffer[0..ready.leftover.len], ready.leftover);
            request.io.buffered_start = 0;
            request.io.buffered_end = ready.leftover.len;
            request.io.fin_seen = ready.fin;
            slot.phase = .request;
            slot.phase_deadline_ms = now.deadlineMilliseconds(slot.timeouts.request);
            request.io.writer = codec.ChunkWriter.initRequest(request.io.payload);
            request.io.writing = request.protocol.info().request_max > 0;
            if (!request.io.writing) request.io.outbox.queue("", true);
        },
        .rejected => slot.fail(owner, index, .negotiation_rejected, now),
        .failed => |failure| {
            if (failure == .malformed) request.peer_fault = .protocol;
            slot.fail(owner, index, if (failure == .timeout) .timeout else .{ .negotiation_failed = failure }, now);
        },
    }
}

pub fn consume(slot: *Client, owner: *ReqResp, index: u16, now: Now) bool {
    const request = &slot.request;
    if (!request.consume()) return false;
    if (slot.host_hold_started_ms) |since| {
        assert(now.millis() >= since);
        slot.host_held_ms +|= now.millis() - since;
        slot.host_hold_started_ms = null;
    }
    if (!request.running()) return true;
    assert(slot.phase == .response);
    if (request.chunks >= request.chunks_max) {
        const done = Event{ .done = .{ .request = request.handle(index), .chunks = request.chunks } };
        slot.complete(owner, index, done, now);
        return true;
    }
    slot.resetResponseDecoder(owner);
    return true;
}
