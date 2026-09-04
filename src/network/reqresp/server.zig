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
const Protocol = @import("protocol.zig").Protocol;
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
    receiving_request,
    serving,
    writing_chunk,
    chunk_sent,
    withheld,
    finishing,
    terminal,
    reported,
};

pub const Server = struct {
    pending_ssz: []const u8 = &.{},
    pending_context: ?[constants.context_bytes_length]u8 = null,
    pending_result: u8 = constants.result_success,
    close_after_write: bool = false,
    withheld_since_ms: ?u64 = null,
    state: State = .free,
    generation: u32 = 0,
    conn: Handle = undefined,
    stream: StreamHandle = undefined,
    protocol: Protocol = .status_v1,
    progress_ms: u64 = 0,
    timeout_ms: u64 = 0,
    chunks: u32 = 0,
    io: RequestIO = .{},
    error_message: [codec.error_message_max]u8 = undefined,
    error_len: u16 = 0,
    pending_event: ?Event = null,
    terminal: ?Event = null,
    after_event: State = .free,
    close_pending: bool = false,
    close_code: u64 = types.app_error_normal,

    pub fn clear(self: *Server) void {
        self.io.clear();
        self.pending_ssz = &.{};
        self.pending_context = null;
        self.withheld_since_ms = null;
        if (self.pending_event) |event| if (event == .request) {
            self.pending_event = null;
        };
    }

    fn waitingHost(self: *const Server) bool {
        return self.pending_event != null or self.state == .serving or self.state == .chunk_sent;
    }

    pub fn deadline(self: *const Server, ctx: *const ReqResp) ?u64 {
        if (!self.active() or self.terminal != null) return null;
        const duration = if (self.waitingHost())
            ctx.options.host_timeout_ms
        else if (self.state == .withheld)
            ctx.options.quota_timeout_ms
        else
            self.timeout_ms;
        return self.progress_ms +| duration;
    }

    pub fn advance(self: *Server, ctx: *ReqResp, engine: *Engine, index: u16, now: Now) void {
        if (self.terminal != null) return;
        if (self.deadline(ctx)) |due| if (now.mono_ms >= due) {
            const reason: Failure = if (self.waitingHost())
                .host_timeout
            else if (self.state == .withheld)
                .quota_timeout
            else
                .timeout;
            if (reason == .timeout) ctx.counters.timeouts += 1;
            ctx.fail(self, index, reason, engine);
            return;
        };
        if (self.pending_event != null) return;
        switch (self.state) {
            .serving, .chunk_sent, .terminal => {},
            .receiving_request => readRequest(ctx, engine, self, index, now),
            .withheld => {
                if (!ctx.limiter.matches(self.conn)) {
                    ctx.fail(self, index, .connection_closed, engine);
                    return;
                }
                retryWithheld(ctx, self, now);
            },
            .writing_chunk => writeChunk(ctx, engine, self, index, now),
            .finishing => finishStream(ctx, engine, self, index, now),
            .free, .reported => unreachable,
        }
    }

    pub fn active(self: *const Server) bool {
        return self.state != .free and self.state != .reported;
    }

    pub fn handle(self: *const Server, index: u16) RequestHandle {
        return .{ .index = index, .generation = self.generation, .direction = .inbound };
    }

    pub fn readRequest(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
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
                if (!slot.io.decoding or slot.io.decoder.isDone()) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
                _ = slot.io.feed(input.bytes) catch {
                    Server.rejectRequest(owner, slot, now);
                    return;
                };
                if (slot.io.buffered_start < slot.io.buffered_end) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
            }
            if (input.fin) {
                slot.io.fin_seen = true;
                const finished = !slot.io.decoding or slot.io.decoder.isDone();
                if (!finished) {
                    Server.rejectRequest(owner, slot, now);
                    return;
                }
                const payload: []const u8 = if (slot.io.decoding)
                    slot.io.decoder.payload()
                else
                    &.{};
                slot.pending_event = .{ .request = .{
                    .request = slot.handle(index),
                    .peer = slot.conn,
                    .protocol = slot.protocol,
                    .bytes = payload,
                } };
                slot.after_event = .serving;
                return;
            }
        }
        owner.deferred_work = true;
    }

    pub fn rejectRequest(owner: *ReqResp, slot: *Server, now: Now) void {
        const message = "invalid request";
        @memcpy(slot.error_message[0..message.len], message);
        slot.error_len = message.len;
        slot.io.decoding = false;
        slot.state = .serving;
        Server.queueChunk(
            owner,
            slot,
            constants.result_invalid_request,
            null,
            slot.error_message[0..message.len],
            true,
            now,
        );
    }

    pub fn queueChunk(
        owner: *ReqResp,
        slot: *Server,
        result: u8,
        context: ?[constants.context_bytes_length]u8,
        ssz: []const u8,
        close_after: bool,
        now: Now,
    ) void {
        assert(slot.state == .serving);
        assert(slot.io.outbox.idle());
        slot.pending_ssz = ssz;
        slot.pending_context = context;
        slot.pending_result = result;
        slot.close_after_write = close_after;
        slot.progress_ms = now.mono_ms;
        if (owner.limiter.take(slot.conn, slot.protocol, 1, now.mono_ms)) {
            Server.beginWrite(owner, slot);
        } else {
            slot.state = .withheld;
            slot.withheld_since_ms = now.mono_ms;
            owner.counters.withheld_chunks += 1;
        }
    }

    pub fn beginWrite(owner: *ReqResp, slot: *Server) void {
        owner.deferred_work = true;
        slot.io.writer = codec.ChunkWriter.initChunk(
            slot.pending_result,
            slot.pending_context,
            slot.pending_ssz,
        );
        slot.io.writing = true;
        slot.state = .writing_chunk;
    }

    pub fn retryWithheld(owner: *ReqResp, slot: *Server, now: Now) void {
        assert(slot.state == .withheld);
        if (!owner.limiter.take(slot.conn, slot.protocol, 1, now.mono_ms)) return;
        const since = slot.withheld_since_ms orelse now.mono_ms;
        owner.counters.withheld_ms_total += now.mono_ms -| since;
        slot.withheld_since_ms = null;
        slot.progress_ms = now.mono_ms;
        Server.beginWrite(owner, slot);
    }

    pub fn writeChunk(owner: *ReqResp, engine: *Engine, slot: *Server, index: u16, now: Now) void {
        const flushed = slot.io.flush(engine, slot.stream, false) catch |err| {
            const reason: Failure = switch (err) {
                error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
                else => .transport,
            };
            owner.fail(slot, index, reason, engine);
            return;
        };
        if (flushed.progressed) slot.progress_ms = now.mono_ms;
        if (!flushed.done) {
            if (slot.io.outbox.idle()) owner.deferred_work = true;
            return;
        }
        if (slot.pending_result == constants.result_success) {
            slot.chunks += 1;
            owner.counters.chunks_sent += 1;
        }
        slot.pending_ssz = &.{};
        slot.io.writer = undefined;
        if (slot.close_after_write) {
            slot.io.outbox.queue("", true);
            slot.state = .finishing;
            owner.deferred_work = true;
            slot.progress_ms = now.mono_ms;
            return;
        }
        slot.pending_ssz = &.{};
        slot.io.writer = undefined;
        slot.state = .chunk_sent;
        slot.progress_ms = now.mono_ms;
        slot.pending_event = .{ .chunk_sent = .{
            .request = slot.handle(index),
            .chunks = slot.chunks,
        } };
        slot.after_event = .serving;
    }

    pub fn finishStream(
        owner: *ReqResp,
        engine: *Engine,
        slot: *Server,
        index: u16,
        now: Now,
    ) void {
        assert(slot.state == .finishing);
        const flushed = slot.io.outbox.pump(engine, slot.stream) catch |err| {
            owner.failStream(slot, index, err, engine);
            return;
        };
        if (!flushed) return;
        slot.progress_ms = now.mono_ms;
        owner.counters.requests_served += 1;
        owner.complete(
            slot,
            index,
            .{ .served = .{ .request = slot.handle(index), .chunks = slot.chunks } },
            null,
        );
    }

    pub fn accept(
        owner: *ReqResp,
        engine: *Engine,
        stream: StreamHandle,
        ready: routing.Selection,
        request_sink: []u8,
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
        if (request_sink.len < bounds.request_max) return error.SinkTooSmall;
        if (owner.inboundCount(stream.conn, null) >= owner.options.inbound_per_peer_max) {
            return error.PeerSlotsExhausted;
        }
        const index = owner.claim(owner.inbound) orelse return error.SlotsExhausted;
        const slot = &owner.inbound[index];
        if (owner.inboundCount(stream.conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            owner.pushOverLimit(.{ .peer = stream.conn, .protocol = which });
        }
        slot.* = .{
            .state = .receiving_request,
            .generation = slot.generation + 1,
            .conn = stream.conn,
            .stream = stream,
            .protocol = which,
            .progress_ms = now.mono_ms,
            .timeout_ms = owner.options.progress_timeout_ms,
            .io = .{
                .sink = request_sink,
                .scratch = slot.io.scratch,
                .read_buffer = slot.io.read_buffer,
                .buffered_end = ready.leftover.len,
                .fin_seen = ready.fin,
            },
        };
        assert(ready.leftover.len <= slot.io.read_buffer.len);
        @memcpy(slot.io.read_buffer[0..ready.leftover.len], ready.leftover);
        if (bounds.request_max > 0) {
            slot.io.decoder = codec.Decoder.initRequest(
                .{ .min = bounds.request_min, .max = bounds.request_max },
                request_sink,
                slot.io.scratch,
            );
            slot.io.decoding = true;
        }
        owner.limiter.bind(stream.conn, now.mono_ms);
        owner.deferred_work = true;
        assert(slot.active());
        return slot.handle(index);
    }

    pub fn respond(
        owner: *ReqResp,
        request_handle: RequestHandle,
        ssz: []const u8,
        fork: ?config.ForkSeq,
        now: Now,
    ) RespondError!void {
        const slot = try owner.servingSlot(request_handle);
        const bounds = slot.protocol.info();
        if (slot.chunks >= bounds.chunks_max) return error.TooManyChunks;
        if (ssz.len > bounds.response_max) return error.ChunkTooLarge;
        if (ssz.len < bounds.response_min) return error.ChunkTooSmall;
        var context: ?[constants.context_bytes_length]u8 = null;
        if (bounds.context_bytes) {
            const which = fork orelse return error.UnknownFork;
            context = owner.digestFor(which) orelse return error.UnknownFork;
        }
        Server.queueChunk(owner, slot, constants.result_success, context, ssz, false, now);
    }

    pub fn respondError(
        owner: *ReqResp,
        request_handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) RespondError!void {
        if (code == constants.result_success or message.len > codec.error_message_max) {
            return error.InvalidError;
        }
        const slot = try owner.servingSlot(request_handle);
        @memcpy(slot.error_message[0..message.len], message);
        slot.error_len = @intCast(message.len);
        Server.queueChunk(owner, slot, code, null, slot.error_message[0..message.len], true, now);
    }

    pub fn finish(owner: *ReqResp, request_handle: RequestHandle, now: Now) bool {
        if (request_handle.direction != .inbound) return false;
        const slot = owner.inboundSlot(request_handle) orelse return false;
        switch (slot.state) {
            .serving, .chunk_sent => {
                if (!slot.io.outbox.idle()) return false;
                slot.io.outbox.queue("", true);
                owner.deferred_work = true;
                if (slot.pending_event != null) {
                    slot.after_event = .finishing;
                } else {
                    slot.state = .finishing;
                }
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
