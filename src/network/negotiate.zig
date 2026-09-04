const std = @import("std");
const engine_mod = @import("quic/engine.zig");
const multistream = @import("wire/multistream.zig");
const stream_io = @import("stream_io.zig");
const types = @import("types.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const StreamError = engine_mod.StreamError;

pub const negotiations_max_default: u16 = 256;
pub const negotiations_max_ceiling: u16 = 4_096;
pub const negotiate_timeout_ms: u64 = 10_000;
pub const inbox_capacity: usize = 2 * multistream.message_length_max;
pub const outbox_capacity: usize = multistream.listener_write_max;

pub const Error = error{ NegotiationTableFull, InvalidLimits } || multistream.Error ||
    StreamError || std.mem.Allocator.Error;

pub const Failure = enum { timeout, malformed, stream_closed, transport, overflow, exhausted };

pub const Ready = struct {
    protocol_index: u8,
    leftover: []const u8,
    fin: bool,
};

pub const Outcome = struct {
    stream: StreamHandle,
    direction: types.Direction = .inbound,
    protocol_id: []const u8 = "",
    result: Result,

    pub const Result = union(enum) {
        ready: Ready,
        rejected,
        failed: Failure,
    };
};

const State = enum { free, negotiating, pending, reported };
const candidates_max = @import("wire/constants.zig").multistream_proposals_max;

const Role = union(enum) {
    dialer: multistream.Dialer,
    listener: multistream.Listener,
};

const Entry = struct {
    state: State = .free,
    stream: StreamHandle = undefined,
    started_ms: u64 = 0,
    role: Role = undefined,
    selected: ?u8 = null,
    candidates: [candidates_max][]const u8 = undefined,
    candidates_len: u8 = 0,
    candidate: u8 = 0,
    pending_result: Outcome.Result = undefined,
    fin_seen: bool = false,
    outbox: stream_io.Outbox = .{},
    out_buffer: [outbox_capacity]u8 = undefined,
    inbox: stream_io.Inbox(inbox_capacity) = .{},
};

pub const Negotiator = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    timeout_ms: u64 = negotiate_timeout_ms,

    pub fn init(allocator: std.mem.Allocator, negotiations_max: u16) Error!Negotiator {
        if (negotiations_max == 0 or negotiations_max > negotiations_max_ceiling) {
            return error.InvalidLimits;
        }
        const entries = try allocator.alloc(Entry, negotiations_max);
        @memset(entries, .{});
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *Negotiator) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn active(self: *const Negotiator) usize {
        var count: usize = 0;
        for (self.entries) |*entry| {
            if (entry.state == .negotiating) count += 1;
        }
        assert(count <= self.entries.len);
        return count;
    }

    pub fn beginOutbound(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocol: []const u8,
        now: types.Now,
    ) Error!StreamHandle {
        return self.beginOutboundCandidates(engine, conn, &.{protocol}, now);
    }

    /// Copies the bounded offer list; protocol strings must outlive negotiation.
    pub fn beginOutboundCandidates(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocols: []const []const u8,
        now: types.Now,
    ) Error!StreamHandle {
        if (protocols.len == 0 or protocols.len > candidates_max) return error.InvalidLimits;
        for (protocols) |protocol| _ = try multistream.Dialer.init(protocol);
        const entry = self.claim() orelse return error.NegotiationTableFull;
        assert(entry.state == .free);
        const dialer = try multistream.Dialer.init(protocols[0]);
        @memcpy(entry.candidates[0..protocols.len], protocols);
        entry.candidates_len = @intCast(protocols.len);
        entry.candidate = 0;
        const hello = try dialer.initialWrite(&entry.out_buffer);
        const stream = try engine.openStream(conn);
        entry.stream = stream;
        entry.started_ms = now.mono_ms;
        entry.role = .{ .dialer = dialer };
        entry.selected = null;
        entry.fin_seen = false;
        entry.inbox = .{};
        entry.outbox = .{};
        entry.outbox.queue(hello, false);
        entry.state = .negotiating;
        assert(entry.outbox.bytes.len == hello.len);
        return stream;
    }

    pub fn acceptInbound(
        self: *Negotiator,
        stream: StreamHandle,
        supported: []const []const u8,
        now: types.Now,
    ) Error!void {
        assert(supported.len > 0);
        const entry = self.claim() orelse return error.NegotiationTableFull;
        assert(entry.state == .free);
        entry.stream = stream;
        entry.started_ms = now.mono_ms;
        entry.role = .{ .listener = multistream.Listener.init(supported) };
        entry.selected = null;
        entry.fin_seen = false;
        entry.inbox = .{};
        entry.outbox = .{};
        entry.state = .negotiating;
    }

    pub fn pump(
        self: *Negotiator,
        engine: *Engine,
        now: types.Now,
        outcomes: []Outcome,
    ) usize {
        var count: usize = 0;
        for (self.entries) |*entry| {
            if (entry.state == .reported) {
                entry.state = .free;
                continue;
            }
            if (entry.state == .negotiating) {
                if (self.advance(engine, entry, now)) |outcome| {
                    entry.pending_result = outcome.result;
                    entry.state = .pending;
                }
            }
            if (entry.state != .pending or count == outcomes.len) continue;
            outcomes[count] = .{
                .stream = entry.stream,
                .direction = direction(entry),
                .protocol_id = switch (entry.role) {
                    .dialer => |dialer| dialer.protocol,
                    .listener => |listener| if (entry.selected) |index| listener.supported[index] else "",
                },
                .result = entry.pending_result,
            };
            count += 1;
            entry.state = .reported;
        }
        assert(count <= outcomes.len);
        return count;
    }

    pub fn connectionClosed(self: *Negotiator, engine: *Engine, conn: Handle) void {
        for (self.entries) |*entry| {
            if (entry.state != .negotiating and entry.state != .pending) continue;
            if (!std.meta.eql(entry.stream.conn, conn)) continue;
            entry.pending_result = fail(engine, entry, .stream_closed).result;
            entry.state = .pending;
        }
    }

    pub fn streamClosed(self: *Negotiator, engine: *Engine, stream: StreamHandle) void {
        for (self.entries) |*entry| {
            if (entry.state != .negotiating and entry.state != .pending) continue;
            if (!std.meta.eql(entry.stream, stream)) continue;
            entry.pending_result = fail(engine, entry, .stream_closed).result;
            entry.state = .pending;
        }
    }

    pub fn cancel(self: *Negotiator, engine: *Engine, stream: StreamHandle) void {
        for (self.entries) |*entry| {
            if (entry.state == .free or !std.meta.eql(entry.stream, stream)) continue;
            entry.state = .free;
        }
        engine.closeStream(stream, types.app_error_negotiation_failed);
    }

    fn claim(self: *Negotiator) ?*Entry {
        for (self.entries) |*entry| {
            if (entry.state == .free) return entry;
        }
        return null;
    }

    fn advance(self: *Negotiator, engine: *Engine, entry: *Entry, now: types.Now) ?Outcome {
        assert(entry.state == .negotiating);
        const waited_ms = now.mono_ms -| entry.started_ms;
        if (waited_ms >= self.timeout_ms) return fail(engine, entry, .timeout);
        const flushed = entry.outbox.pump(engine, entry.stream) catch |err|
            return failStream(engine, entry, err);
        if (!flushed) return null;
        if (entry.selected) |index| return ready(entry, index);
        if (entry.inbox.free() == 0) return fail(engine, entry, .overflow);
        const read = entry.inbox.fill(engine, entry.stream) catch |err|
            return failStream(engine, entry, err);
        if (entry.inbox.len == 0 and !read.fin) return null;
        if (read.fin) entry.fin_seen = true;
        switch (entry.role) {
            .dialer => |*dialer| {
                const outcome = dialer.feed(entry.inbox.slice()) catch
                    return fail(engine, entry, .malformed);
                entry.inbox.drop(outcome.consumed);
                switch (outcome.status) {
                    .accepted => return ready(entry, entry.candidate),
                    .rejected => {
                        if (!entry.fin_seen and entry.candidate + 1 < entry.candidates_len) {
                            return proposeNext(engine, entry, dialer);
                        }
                        engine.closeStream(entry.stream, types.app_error_negotiation_failed);
                        return .{ .stream = entry.stream, .result = .rejected };
                    },
                    .pending => {},
                }
            },
            .listener => |*listener| {
                const outcome = listener.feed(entry.inbox.slice(), &entry.out_buffer) catch
                    return fail(engine, entry, .malformed);
                entry.inbox.drop(outcome.consumed);
                if (outcome.write.len > 0) entry.outbox.queue(outcome.write, false);
                switch (outcome.status) {
                    .selected => |index| {
                        assert(index < std.math.maxInt(u8));
                        entry.selected = @intCast(index);
                        const replied = entry.outbox.pump(engine, entry.stream) catch |err|
                            return failStream(engine, entry, err);
                        return if (replied) ready(entry, entry.selected.?) else null;
                    },
                    .failed => return fail(engine, entry, .exhausted),
                    .pending => {},
                }
            },
        }
        if (read.fin) return fail(engine, entry, .stream_closed);
        return null;
    }
};

fn proposeNext(engine: *Engine, entry: *Entry, dialer: *multistream.Dialer) ?Outcome {
    assert(entry.candidate + 1 < entry.candidates_len);
    entry.candidate += 1;
    dialer.* = .{
        .protocol = entry.candidates[entry.candidate],
        .header_seen = true,
    };
    const proposal = multistream.encodeMessage(dialer.protocol, &entry.out_buffer) catch
        return fail(engine, entry, .malformed);
    entry.outbox.queue(proposal, false);
    return null;
}

fn direction(entry: *const Entry) types.Direction {
    return switch (entry.role) {
        .dialer => .outbound,
        .listener => .inbound,
    };
}

fn ready(entry: *const Entry, index: u8) Outcome {
    assert(entry.outbox.idle());
    return .{ .stream = entry.stream, .result = .{ .ready = .{
        .protocol_index = index,
        .leftover = entry.inbox.slice(),
        .fin = entry.fin_seen,
    } } };
}

fn fail(engine: *Engine, entry: *const Entry, failure: Failure) Outcome {
    engine.closeStream(entry.stream, types.app_error_negotiation_failed);
    return .{ .stream = entry.stream, .result = .{ .failed = failure } };
}

fn failStream(engine: *Engine, entry: *const Entry, err: StreamError) Outcome {
    const failure: Failure = switch (err) {
        error.StaleHandle, error.UnknownStream, error.StreamStopped => .stream_closed,
        else => .transport,
    };
    return fail(engine, entry, failure);
}

comptime {
    assert(@sizeOf(Entry) <= 1_536);
    assert(negotiations_max_default <= negotiations_max_ceiling);
    assert(2 * multistream.message_length_max <= outbox_capacity);
}
