const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const limiter_mod = @import("limiter.zig");
const protocol_mod = @import("protocol.zig");
const config = @import("config");
const engine_mod = @import("../quic/engine.zig");
const limits = @import("../quic/limits.zig");
const negotiate = @import("../negotiate.zig");
const stream_io = @import("../stream_io.zig");
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

pub const ForkEntry = struct {
    digest: [constants.context_bytes_length]u8,
    fork: config.ForkSeq,
};

pub const Options = struct {
    peers: u16 = limits.connections_max_default,
    outbound_max: u16 = constants.outbound_max_default,
    inbound_max: u16 = constants.inbound_max_default,
    inbound_per_peer_max: u8 = constants.inbound_per_peer_max_default,
    progress_timeout_ms: u64 = constants.progress_timeout_ms_default,
    forks: []const ForkEntry,
    quotas: ?limiter_mod.Quotas = null,
};

pub const RequestOptions = struct {
    progress_timeout_ms: ?u64 = null,
};

pub const RequestHandle = struct {
    index: u16,
    generation: u32,
    direction: types.Direction,
};

pub const Failure = union(enum) {
    timeout,
    negotiation_rejected,
    negotiation_failed: negotiate.Failure,
    invalid_response: codec.Error,
    invalid_request: codec.Error,
    too_many_chunks,
    unknown_context: [constants.context_bytes_length]u8,
    peer_error: struct { code: u8, message_len: u8 },
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

pub const InitError = error{InvalidOptions} || std.mem.Allocator.Error;

pub const RequestError = error{
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
    SlotsExhausted,
    PeerSlotsExhausted,
    SinkTooSmall,
    UnknownProtocol,
};

pub const RespondError = error{
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

const State = enum {
    free,
    negotiating,
    sending_request,
    awaiting,
    reading,
    chunk_ready,
    receiving_request,
    serving,
    writing_chunk,
    withheld,
    finishing,
    reported,
};

const Slot = struct {
    state: State = .free,
    generation: u32 = 0,
    direction: types.Direction = .outbound,
    conn: Handle = undefined,
    stream: StreamHandle = undefined,
    protocol: Protocol = .status_v1,
    started_ms: u64 = 0,
    progress_ms: u64 = 0,
    timeout_ms: u64 = 0,
    chunks: u32 = 0,
    sink: []u8 = &.{},
    scratch: []u8 = &.{},
    read_buffer: []u8 = &.{},
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    fin_seen: bool = false,
    decoder: codec.Decoder = undefined,
    decoding: bool = false,
    writer: codec.ChunkWriter = undefined,
    writing: bool = false,
    outbox: stream_io.Outbox = .{},
    request_ssz: []const u8 = &.{},
    pending_ssz: []const u8 = &.{},
    pending_context: ?[constants.context_bytes_length]u8 = null,
    pending_result: u8 = constants.result_success,
    close_after_write: bool = false,
    withheld_since_ms: ?u64 = null,
    error_message: [codec.error_message_max]u8 = undefined,
    error_len: u8 = 0,
    pending_event: ?Event = null,
    after_event: State = .free,

    fn handle(self: *const Slot, index: u16) RequestHandle {
        return .{ .index = index, .generation = self.generation, .direction = self.direction };
    }

    fn active(self: *const Slot) bool {
        return self.state != .free and self.state != .reported;
    }

    fn awaitingPeer(self: *const Slot) bool {
        return switch (self.state) {
            .sending_request, .awaiting, .reading => true,
            .receiving_request, .serving, .writing_chunk, .finishing => true,
            else => false,
        };
    }
};

const OverLimit = struct {
    peer: Handle,
    protocol: Protocol,
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    options: Options,
    outbound: []Slot,
    inbound: []Slot,
    arena: []u8,
    limiter: limiter_mod.Limiter,
    over_limit: [over_limit_queue_max]OverLimit = undefined,
    over_limit_head: u8 = 0,
    over_limit_len: u8 = 0,
    last_now_ms: u64 = 0,
    counters: Counters = .{},

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!ReqResp {
        if (options.outbound_max == 0 or options.outbound_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.inbound_max == 0 or options.inbound_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.inbound_per_peer_max == 0 or options.peers == 0) return error.InvalidOptions;
        if (options.progress_timeout_ms == 0) return error.InvalidOptions;
        if (options.forks.len > 64) return error.InvalidOptions;

        const outbound = try allocator.alloc(Slot, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(outbound, .{});
        const inbound = try allocator.alloc(Slot, options.inbound_max);
        errdefer allocator.free(inbound);
        @memset(inbound, .{});

        const total = @as(usize, options.outbound_max) + options.inbound_max;
        const arena = try allocator.alloc(u8, total * (scratch_length + read_buffer_length));
        errdefer allocator.free(arena);
        var cursor: usize = 0;
        for (outbound) |*slot| cursor = assignBuffers(slot, arena, cursor);
        for (inbound) |*slot| cursor = assignBuffers(slot, arena, cursor);
        assert(cursor == arena.len);

        var buckets = try limiter_mod.Limiter.init(allocator, options.peers, options.quotas);
        errdefer buckets.deinit(allocator);

        return .{
            .allocator = allocator,
            .options = options,
            .outbound = outbound,
            .inbound = inbound,
            .arena = arena,
            .limiter = buckets,
        };
    }

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

    pub fn request(
        self: *ReqResp,
        engine: *Engine,
        negotiator: *negotiate.Negotiator,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        request_options: RequestOptions,
        now: Now,
    ) RequestError!RequestHandle {
        const bounds = which.info();
        if (request_ssz.len > bounds.request_max) return error.RequestTooLarge;
        if (request_ssz.len < bounds.request_min) return error.RequestTooSmall;
        if (sink.len < bounds.response_max) return error.SinkTooSmall;
        if (self.outboundCount(conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            return error.TooManyRequests;
        }
        const index = self.claim(self.outbound) orelse return error.SlotsExhausted;
        const slot = &self.outbound[index];
        const stream = negotiator.beginOutbound(engine, conn, which.id(), now) catch |err| {
            self.outbound[index].state = .free;
            return switch (err) {
                error.NegotiationTableFull => error.NegotiationTableFull,
                error.StaleHandle => error.StaleHandle,
                else => error.Transport,
            };
        };
        slot.* = .{
            .state = .negotiating,
            .generation = slot.generation +% 1,
            .direction = .outbound,
            .conn = conn,
            .stream = stream,
            .protocol = which,
            .started_ms = now.mono_ms,
            .progress_ms = now.mono_ms,
            .timeout_ms = request_options.progress_timeout_ms orelse
                self.options.progress_timeout_ms,
            .sink = sink,
            .scratch = slot.scratch,
            .read_buffer = slot.read_buffer,
            .request_ssz = request_ssz,
        };
        self.counters.requests_sent += 1;
        assert(slot.active());
        return slot.handle(index);
    }

    pub fn negotiated(self: *ReqResp, outcome: negotiate.Outcome) bool {
        for (self.outbound, 0..) |*slot, position| {
            if (slot.state != .negotiating) continue;
            if (!std.meta.eql(slot.stream, outcome.stream)) continue;
            const index: u16 = @intCast(position);
            switch (outcome.result) {
                .ready => |ready| {
                    assert(ready.leftover.len <= slot.read_buffer.len);
                    @memcpy(slot.read_buffer[0..ready.leftover.len], ready.leftover);
                    slot.buffered_start = 0;
                    slot.buffered_end = ready.leftover.len;
                    slot.fin_seen = ready.fin;
                    slot.state = .sending_request;
                    slot.progress_ms = self.last_now_ms;
                    slot.writer = codec.ChunkWriter.initRequest(slot.request_ssz);
                    slot.writing = slot.protocol.info().request_max > 0;
                    if (!slot.writing) slot.outbox.queue("", true);
                },
                .rejected => self.fail(slot, index, .negotiation_rejected, null),
                .failed => |failure| {
                    self.fail(slot, index, .{ .negotiation_failed = failure }, null);
                },
            }
            return true;
        }
        return false;
    }

    pub fn accept(
        self: *ReqResp,
        stream: StreamHandle,
        ready: negotiate.Ready,
        request_sink: []u8,
        now: Now,
    ) AcceptError!RequestHandle {
        if (ready.protocol_index >= Protocol.count) return error.UnknownProtocol;
        const which: Protocol = @enumFromInt(ready.protocol_index);
        const bounds = which.info();
        if (request_sink.len < bounds.request_max) return error.SinkTooSmall;
        if (self.inboundCount(stream.conn, null) >= self.options.inbound_per_peer_max) {
            return error.PeerSlotsExhausted;
        }
        const index = self.claim(self.inbound) orelse return error.SlotsExhausted;
        const slot = &self.inbound[index];
        if (self.inboundCount(stream.conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
            self.pushOverLimit(.{ .peer = stream.conn, .protocol = which });
        }
        slot.* = .{
            .state = .receiving_request,
            .generation = slot.generation +% 1,
            .direction = .inbound,
            .conn = stream.conn,
            .stream = stream,
            .protocol = which,
            .started_ms = now.mono_ms,
            .progress_ms = now.mono_ms,
            .timeout_ms = self.options.progress_timeout_ms,
            .sink = request_sink,
            .scratch = slot.scratch,
            .read_buffer = slot.read_buffer,
            .buffered_end = ready.leftover.len,
            .fin_seen = ready.fin,
        };
        assert(ready.leftover.len <= slot.read_buffer.len);
        @memcpy(slot.read_buffer[0..ready.leftover.len], ready.leftover);
        if (bounds.request_max > 0) {
            slot.decoder = codec.Decoder.initRequest(
                .{ .min = bounds.request_min, .max = bounds.request_max },
                request_sink,
                slot.scratch,
            );
            slot.decoding = true;
        }
        assert(slot.active());
        return slot.handle(index);
    }

    pub fn respond(
        self: *ReqResp,
        handle: RequestHandle,
        ssz: []const u8,
        fork: ?config.ForkSeq,
        now: Now,
    ) RespondError!void {
        const slot = try self.servingSlot(handle);
        const bounds = slot.protocol.info();
        if (slot.chunks >= bounds.chunks_max) return error.TooManyChunks;
        if (ssz.len > bounds.response_max) return error.ChunkTooLarge;
        if (ssz.len < bounds.response_min) return error.ChunkTooSmall;
        var context: ?[constants.context_bytes_length]u8 = null;
        if (bounds.context_bytes) {
            const which = fork orelse return error.UnknownFork;
            context = self.digestFor(which) orelse return error.UnknownFork;
        }
        self.queueChunk(slot, constants.result_success, context, ssz, false, now);
    }

    pub fn respondError(
        self: *ReqResp,
        handle: RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) RespondError!void {
        assert(code != constants.result_success);
        assert(message.len <= codec.error_message_max);
        const slot = try self.servingSlot(handle);
        @memcpy(slot.error_message[0..message.len], message);
        slot.error_len = @intCast(message.len);
        self.queueChunk(slot, code, null, slot.error_message[0..message.len], true, now);
    }

    pub fn finish(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction != .inbound) return false;
        const slot = self.slotFor(handle) orelse return false;
        switch (slot.state) {
            .serving => {
                assert(slot.outbox.idle());
                slot.outbox.queue("", true);
                slot.state = .finishing;
                slot.progress_ms = self.last_now_ms;
            },
            .writing_chunk, .withheld => {
                if (slot.close_after_write) return false;
                slot.close_after_write = true;
            },
            else => return false,
        }
        return true;
    }

    pub fn consume(self: *ReqResp, handle: RequestHandle) bool {
        if (handle.direction != .outbound) return false;
        const slot = self.slotFor(handle) orelse return false;
        if (slot.state != .chunk_ready) return false;
        const bounds = slot.protocol.info();
        if (slot.chunks >= bounds.chunks_max) {
            const done = Event{ .done = .{ .request = handle, .chunks = slot.chunks } };
            self.complete(slot, handle.index, done, null);
            return true;
        }
        slot.state = .reading;
        slot.progress_ms = self.last_now_ms;
        self.resetResponseDecoder(slot);
        return true;
    }

    pub fn errorMessage(self: *const ReqResp, handle: RequestHandle) []const u8 {
        const slots = if (handle.direction == .outbound) self.outbound else self.inbound;
        if (handle.index >= slots.len) return &.{};
        const slot = &slots[handle.index];
        if (slot.generation != handle.generation or slot.state == .free) return &.{};
        assert(slot.error_len <= codec.error_message_max);
        return slot.error_message[0..slot.error_len];
    }

    pub fn connectionClosed(self: *ReqResp, conn: Handle) void {
        for (self.outbound, 0..) |*slot, position| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            if (slot.pending_event != null) continue;
            self.fail(slot, @intCast(position), .connection_closed, null);
        }
        for (self.inbound, 0..) |*slot, position| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            if (slot.pending_event != null) continue;
            self.fail(slot, @intCast(position), .connection_closed, null);
        }
    }

    pub fn pump(self: *ReqResp, engine: *Engine, now: Now, events: []Event) usize {
        assert(now.mono_ms >= self.last_now_ms or self.last_now_ms == 0);
        self.last_now_ms = now.mono_ms;
        var count: usize = 0;
        while (self.over_limit_len > 0 and count < events.len) {
            const item = self.over_limit[self.over_limit_head];
            self.over_limit_head = @intCast((self.over_limit_head + 1) % over_limit_queue_max);
            self.over_limit_len -= 1;
            events[count] = .{ .over_limit = .{ .peer = item.peer, .protocol = item.protocol } };
            count += 1;
        }
        count = self.pumpSlots(engine, self.outbound, now, events, count);
        count = self.pumpSlots(engine, self.inbound, now, events, count);
        assert(count <= events.len);
        return count;
    }

    fn pumpSlots(
        self: *ReqResp,
        engine: *Engine,
        slots: []Slot,
        now: Now,
        events: []Event,
        start: usize,
    ) usize {
        var count = start;
        for (slots, 0..) |*slot, position| {
            const index: u16 = @intCast(position);
            if (slot.state == .reported) {
                slot.state = .free;
                continue;
            }
            if (!slot.active()) continue;
            if (slot.pending_event == null) self.advance(engine, slot, index, now);
            if (slot.pending_event) |event| {
                if (count == events.len) continue;
                events[count] = event;
                count += 1;
                slot.pending_event = null;
                slot.state = slot.after_event;
            }
        }
        assert(count <= events.len);
        return count;
    }

    fn advance(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        assert(slot.active());
        assert(slot.pending_event == null);
        if (slot.awaitingPeer() and now.mono_ms -| slot.progress_ms >= slot.timeout_ms) {
            self.counters.timeouts += 1;
            self.fail(slot, index, .timeout, engine);
            return;
        }
        switch (slot.state) {
            .negotiating, .chunk_ready => {},
            .sending_request => self.sendRequest(engine, slot, index, now),
            .awaiting, .reading => self.readResponse(engine, slot, index, now),
            .receiving_request => self.readRequest(engine, slot, index, now),
            .serving => {},
            .withheld => self.retryWithheld(slot, now),
            .writing_chunk => self.writeChunk(engine, slot, index, now),
            .finishing => self.finishStream(engine, slot, index, now),
            .free, .reported => unreachable,
        }
    }

    fn sendRequest(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        if (slot.writing and slot.outbox.idle()) {
            const piece = slot.writer.next(slot.scratch) catch {
                self.fail(slot, index, .transport, engine);
                return;
            };
            slot.outbox.queue(piece, slot.writer.done());
            if (slot.writer.done()) slot.writing = false;
        }
        const flushed = slot.outbox.pump(engine, slot.stream) catch |err| {
            self.failStream(slot, index, err, engine);
            return;
        };
        if (!slot.outbox.idle() or slot.writing) {
            slot.progress_ms = now.mono_ms;
            return;
        }
        assert(flushed);
        slot.state = .awaiting;
        slot.progress_ms = now.mono_ms;
        self.resetResponseDecoder(slot);
    }

    fn readResponse(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            if (slot.buffered_start == slot.buffered_end and !slot.fin_seen) {
                const read = engine.read(slot.stream, slot.read_buffer) catch |err| {
                    self.failStream(slot, index, err, engine);
                    return;
                };
                if (read.reset_code != null) {
                    self.fail(slot, index, .stream_closed, engine);
                    return;
                }
                if (read.len == 0 and !read.fin) return;
                slot.buffered_start = 0;
                slot.buffered_end = read.len;
                if (read.fin) slot.fin_seen = true;
                slot.progress_ms = now.mono_ms;
            }
            const pending = slot.read_buffer[slot.buffered_start..slot.buffered_end];
            if (pending.len > 0) {
                const progress = slot.decoder.feed(pending) catch |err| {
                    self.fail(slot, index, .{ .invalid_response = err }, engine);
                    return;
                };
                slot.buffered_start += progress.consumed;
                if (progress.done) {
                    self.completeChunk(engine, slot, index, now);
                    return;
                }
            }
            if (slot.fin_seen and slot.buffered_start == slot.buffered_end) {
                if (slot.decoder.phase == .result) {
                    self.complete(
                        slot,
                        index,
                        .{ .done = .{ .request = slot.handle(index), .chunks = slot.chunks } },
                        engine,
                    );
                } else {
                    self.fail(slot, index, .{ .invalid_response = error.Truncated }, engine);
                }
                return;
            }
        }
    }

    fn completeChunk(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        assert(slot.decoder.isDone());
        const payload = slot.decoder.payload();
        if (slot.decoder.isError()) {
            const message_len: u8 = @intCast(@min(payload.len, codec.error_message_max));
            @memcpy(slot.error_message[0..message_len], payload[0..message_len]);
            slot.error_len = message_len;
            const code = slot.decoder.result();
            const reason = Failure{ .peer_error = .{ .code = code, .message_len = message_len } };
            self.fail(slot, index, reason, engine);
            return;
        }
        const bounds = slot.protocol.info();
        if (slot.chunks >= bounds.chunks_max) {
            self.fail(slot, index, .too_many_chunks, engine);
            return;
        }
        var fork: ?config.ForkSeq = null;
        if (slot.decoder.context()) |digest| {
            fork = self.forkFor(digest) orelse {
                self.fail(slot, index, .{ .unknown_context = digest }, engine);
                return;
            };
        }
        slot.chunks += 1;
        slot.progress_ms = now.mono_ms;
        self.counters.chunks_received += 1;
        slot.pending_event = .{ .chunk = .{
            .request = slot.handle(index),
            .bytes = payload,
            .fork = fork,
        } };
        slot.after_event = .chunk_ready;
    }

    fn readRequest(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        var reads: u32 = 0;
        while (reads < reads_per_pump_max) : (reads += 1) {
            var bytes: []const u8 = slot.read_buffer[slot.buffered_start..slot.buffered_end];
            var fin = slot.fin_seen;
            if (bytes.len == 0 and !fin) {
                const read = engine.read(slot.stream, slot.read_buffer) catch |err| {
                    self.failStream(slot, index, err, engine);
                    return;
                };
                if (read.reset_code != null) {
                    self.fail(slot, index, .stream_closed, engine);
                    return;
                }
                if (read.len == 0 and !read.fin) return;
                bytes = slot.read_buffer[0..read.len];
                fin = read.fin;
            }
            slot.buffered_start = 0;
            slot.buffered_end = 0;
            slot.progress_ms = now.mono_ms;
            if (bytes.len > 0) {
                if (!slot.decoding or slot.decoder.isDone()) {
                    self.rejectRequest(slot, now);
                    return;
                }
                const progress = slot.decoder.feed(bytes) catch {
                    self.rejectRequest(slot, now);
                    return;
                };
                if (progress.consumed < bytes.len) {
                    self.rejectRequest(slot, now);
                    return;
                }
            }
            if (fin) {
                slot.fin_seen = true;
                const finished = !slot.decoding or slot.decoder.isDone();
                if (!finished) {
                    self.rejectRequest(slot, now);
                    return;
                }
                const payload: []const u8 = if (slot.decoding) slot.decoder.payload() else &.{};
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
    }

    fn rejectRequest(self: *ReqResp, slot: *Slot, now: Now) void {
        self.counters.failures += 1;
        const message = "invalid request";
        @memcpy(slot.error_message[0..message.len], message);
        slot.error_len = message.len;
        slot.decoding = false;
        slot.state = .serving;
        self.queueChunk(
            slot,
            constants.result_invalid_request,
            null,
            slot.error_message[0..message.len],
            true,
            now,
        );
    }

    fn queueChunk(
        self: *ReqResp,
        slot: *Slot,
        result: u8,
        context: ?[constants.context_bytes_length]u8,
        ssz: []const u8,
        close_after: bool,
        now: Now,
    ) void {
        assert(slot.state == .serving);
        assert(slot.outbox.idle());
        slot.pending_ssz = ssz;
        slot.pending_context = context;
        slot.pending_result = result;
        slot.close_after_write = close_after;
        slot.progress_ms = now.mono_ms;
        if (self.limiter.take(slot.conn.index, slot.protocol, 1, now.mono_ms)) {
            self.beginWrite(slot);
        } else {
            slot.state = .withheld;
            slot.withheld_since_ms = now.mono_ms;
            self.counters.withheld_chunks += 1;
        }
    }

    fn beginWrite(self: *ReqResp, slot: *Slot) void {
        _ = self;
        slot.writer = codec.ChunkWriter.initChunk(
            slot.pending_result,
            slot.pending_context,
            slot.pending_ssz,
        );
        slot.writing = true;
        slot.state = .writing_chunk;
    }

    fn retryWithheld(self: *ReqResp, slot: *Slot, now: Now) void {
        assert(slot.state == .withheld);
        if (!self.limiter.take(slot.conn.index, slot.protocol, 1, now.mono_ms)) return;
        const since = slot.withheld_since_ms orelse now.mono_ms;
        self.counters.withheld_ms_total += now.mono_ms -| since;
        slot.withheld_since_ms = null;
        slot.progress_ms = now.mono_ms;
        self.beginWrite(slot);
    }

    fn writeChunk(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        if (slot.writing and slot.outbox.idle()) {
            const piece = slot.writer.next(slot.scratch) catch {
                self.fail(slot, index, .transport, engine);
                return;
            };
            const last = slot.writer.done();
            slot.outbox.queue(piece, last and slot.close_after_write);
            if (last) slot.writing = false;
        }
        const before = slot.outbox.offset;
        _ = slot.outbox.pump(engine, slot.stream) catch |err| {
            self.failStream(slot, index, err, engine);
            return;
        };
        if (slot.outbox.offset != before) slot.progress_ms = now.mono_ms;
        if (slot.writing or !slot.outbox.idle()) return;
        if (slot.pending_result == constants.result_success) {
            slot.chunks += 1;
            self.counters.chunks_sent += 1;
        }
        if (slot.close_after_write) {
            self.counters.requests_served += 1;
            self.complete(
                slot,
                index,
                .{ .served = .{ .request = slot.handle(index), .chunks = slot.chunks } },
                null,
            );
            return;
        }
        slot.progress_ms = now.mono_ms;
        slot.pending_event = .{ .chunk_sent = .{
            .request = slot.handle(index),
            .chunks = slot.chunks,
        } };
        slot.after_event = .serving;
    }

    fn finishStream(self: *ReqResp, engine: *Engine, slot: *Slot, index: u16, now: Now) void {
        assert(slot.state == .finishing);
        const flushed = slot.outbox.pump(engine, slot.stream) catch |err| {
            self.failStream(slot, index, err, engine);
            return;
        };
        if (!flushed) return;
        slot.progress_ms = now.mono_ms;
        self.counters.requests_served += 1;
        self.complete(
            slot,
            index,
            .{ .served = .{ .request = slot.handle(index), .chunks = slot.chunks } },
            null,
        );
    }

    fn complete(self: *ReqResp, slot: *Slot, index: u16, event: Event, engine: ?*Engine) void {
        _ = index;
        _ = self;
        if (engine) |live| live.closeStream(slot.stream, types.app_error_normal);
        slot.pending_event = event;
        slot.after_event = .reported;
    }

    fn fail(self: *ReqResp, slot: *Slot, index: u16, reason: Failure, engine: ?*Engine) void {
        self.counters.failures += 1;
        if (engine) |live| {
            const code: u64 = switch (reason) {
                .timeout => constants.app_error_timeout,
                .invalid_response,
                .too_many_chunks,
                .unknown_context,
                => constants.app_error_invalid_response,
                else => types.app_error_normal,
            };
            live.closeStream(slot.stream, code);
        }
        slot.pending_event = .{ .failed = .{ .request = slot.handle(index), .reason = reason } };
        slot.after_event = .reported;
    }

    fn failStream(
        self: *ReqResp,
        slot: *Slot,
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

    fn resetResponseDecoder(self: *ReqResp, slot: *Slot) void {
        _ = self;
        const bounds = slot.protocol.info();
        slot.decoder = codec.Decoder.initResponse(
            .{ .min = bounds.response_min, .max = bounds.response_max },
            bounds.context_bytes,
            slot.sink,
            slot.scratch,
        );
        slot.decoding = true;
    }

    fn servingSlot(self: *ReqResp, handle: RequestHandle) RespondError!*Slot {
        if (handle.direction != .inbound) return error.StaleHandle;
        const slot = self.slotFor(handle) orelse return error.StaleHandle;
        if (slot.state != .serving) return error.Busy;
        return slot;
    }

    fn slotFor(self: *ReqResp, handle: RequestHandle) ?*Slot {
        const slots = if (handle.direction == .outbound) self.outbound else self.inbound;
        if (handle.index >= slots.len) return null;
        const slot = &slots[handle.index];
        if (slot.generation != handle.generation or !slot.active()) return null;
        return slot;
    }

    fn claim(self: *ReqResp, slots: []Slot) ?u16 {
        _ = self;
        for (slots, 0..) |*slot, position| {
            if (slot.state == .free) return @intCast(position);
        }
        return null;
    }

    fn outboundCount(self: *const ReqResp, conn: Handle, which: Protocol) u8 {
        var count: u8 = 0;
        for (self.outbound) |*slot| {
            if (!slot.active() or slot.protocol != which) continue;
            if (!std.meta.eql(slot.conn, conn)) continue;
            count +|= 1;
        }
        return count;
    }

    fn inboundCount(self: *const ReqResp, conn: Handle, which: ?Protocol) u8 {
        var count: u8 = 0;
        for (self.inbound) |*slot| {
            if (!slot.active() or !std.meta.eql(slot.conn, conn)) continue;
            if (which) |wanted| if (slot.protocol != wanted) continue;
            count +|= 1;
        }
        return count;
    }

    fn pushOverLimit(self: *ReqResp, item: OverLimit) void {
        self.counters.over_limit += 1;
        if (self.over_limit_len == over_limit_queue_max) {
            self.counters.over_limit_dropped += 1;
            return;
        }
        const tail = (self.over_limit_head + self.over_limit_len) % over_limit_queue_max;
        self.over_limit[tail] = item;
        self.over_limit_len += 1;
    }

    fn forkFor(self: *const ReqResp, digest: [constants.context_bytes_length]u8) ?config.ForkSeq {
        for (self.options.forks) |entry| {
            if (std.mem.eql(u8, &entry.digest, &digest)) return entry.fork;
        }
        return null;
    }

    fn digestFor(self: *const ReqResp, fork: config.ForkSeq) ?[constants.context_bytes_length]u8 {
        for (self.options.forks) |entry| {
            if (entry.fork == fork) return entry.digest;
        }
        return null;
    }
};

fn assignBuffers(slot: *Slot, arena: []u8, cursor: usize) usize {
    slot.scratch = arena[cursor..][0..scratch_length];
    slot.read_buffer = arena[cursor + scratch_length ..][0..read_buffer_length];
    return cursor + scratch_length + read_buffer_length;
}

comptime {
    assert(read_buffer_length >= 1024);
    assert(scratch_length >= codec.frame_scratch_max);
    assert(@sizeOf(Slot) <= 2 * 1024);
}
