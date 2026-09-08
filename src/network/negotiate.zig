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
/// Bounds descriptor copies below the Listener u8 index limit.
pub const supported_max: usize = 64;
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
    control: bool = false,
    stream: StreamHandle = undefined,
    started_ms: u64 = 0,
    timeout_ms: u64 = negotiate_timeout_ms,
    role: Role = undefined,
    selected: ?u8 = null,
    needs_service: bool = false,
    candidates: [candidates_max][]const u8 = undefined,
    supported: [supported_max][]const u8 = undefined,
    candidates_len: u8 = 0,
    candidate: u8 = 0,
    pending_result: Outcome.Result = undefined,
    fin_seen: bool = false,
    outbox: stream_io.Outbox = .{},
    out_buffer: [outbox_capacity]u8 = undefined,
    inbox: stream_io.Inbox(inbox_capacity) = .{},
};

pub const Options = struct {
    negotiations_max: u16 = negotiations_max_default,
    outbound_control_reserved: u16 = 0,
};

pub const Negotiator = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    timeout_ms: u64 = negotiate_timeout_ms,
    outbound_control_reserved: u16 = 0,

    pub fn init(allocator: std.mem.Allocator, negotiations_max: u16) Error!Negotiator {
        return initWithOptions(allocator, .{ .negotiations_max = negotiations_max });
    }

    pub fn validateOptions(options: Options) Error!void {
        const negotiations_max = options.negotiations_max;
        if (options.outbound_control_reserved > negotiations_max) return error.InvalidLimits;
        if (negotiations_max == 0 or negotiations_max > negotiations_max_ceiling) {
            return error.InvalidLimits;
        }
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, options: Options) Error!Negotiator {
        try validateOptions(options);
        const negotiations_max = options.negotiations_max;
        const entries = try allocator.alloc(Entry, negotiations_max);
        @memset(entries, .{});
        return .{
            .allocator = allocator,
            .entries = entries,
            .outbound_control_reserved = options.outbound_control_reserved,
        };
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

    pub fn beginOutboundControl(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocol: @import("reqresp/protocol.zig").Protocol,
        now: types.Now,
    ) Error!StreamHandle {
        if (!protocol.isControl()) return error.InvalidLimits;
        return self.beginCandidates(engine, conn, &.{protocol.id()}, now, true, self.timeout_ms);
    }

    pub fn beginOutboundTimed(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocol: @import("reqresp/protocol.zig").Protocol,
        now: types.Now,
        timeout_ms: u64,
    ) Error!StreamHandle {
        return self.beginCandidates(engine, conn, &.{protocol.id()}, now, protocol.isControl(), timeout_ms);
    }

    /// Copies the bounded offer list; protocol strings must outlive negotiation.
    pub fn beginOutboundCandidates(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocols: []const []const u8,
        now: types.Now,
    ) Error!StreamHandle {
        return self.beginCandidates(engine, conn, protocols, now, false, self.timeout_ms);
    }

    fn beginCandidates(
        self: *Negotiator,
        engine: *Engine,
        conn: Handle,
        protocols: []const []const u8,
        now: types.Now,
        control: bool,
        timeout_ms: u64,
    ) Error!StreamHandle {
        if (timeout_ms == 0) return error.InvalidLimits;
        if (protocols.len == 0 or protocols.len > candidates_max) return error.InvalidLimits;
        for (protocols) |protocol| _ = try multistream.Dialer.init(protocol);
        const entry = self.claim(control) orelse return error.NegotiationTableFull;
        assert(entry.state == .free);
        const dialer = try multistream.Dialer.init(protocols[0]);
        @memcpy(entry.candidates[0..protocols.len], protocols);
        entry.candidates_len = @intCast(protocols.len);
        entry.candidate = 0;
        const hello = try dialer.initialWrite(&entry.out_buffer);
        const stream = try engine.openStream(conn);
        entry.control = control;
        entry.stream = stream;
        entry.started_ms = now.mono_ms;
        entry.timeout_ms = timeout_ms;
        entry.role = .{ .dialer = dialer };
        entry.selected = null;
        entry.fin_seen = false;
        entry.inbox = .{};
        entry.outbox = .{};
        entry.outbox.queue(hello, false);
        entry.state = .negotiating;
        entry.needs_service = true;
        assert(entry.outbox.bytes.len == hello.len);
        return stream;
    }

    /// Copies descriptors into stable storage; ID strings must be immutable and outlive negotiation.
    pub fn acceptInbound(
        self: *Negotiator,
        stream: StreamHandle,
        supported: []const []const u8,
        now: types.Now,
    ) Error!void {
        if (supported.len == 0 or supported.len > supported_max) return error.InvalidLimits;
        const entry = self.claim(false) orelse return error.NegotiationTableFull;
        assert(entry.state == .free);
        entry.stream = stream;
        entry.started_ms = now.mono_ms;
        entry.timeout_ms = self.timeout_ms;
        entry.control = false;
        @memcpy(entry.supported[0..supported.len], supported);
        entry.role = .{ .listener = multistream.Listener.init(entry.supported[0..supported.len]) };
        entry.selected = null;
        entry.fin_seen = false;
        entry.inbox = .{};
        entry.outbox = .{};
        entry.state = .negotiating;
        entry.needs_service = true;
    }

    /// Output pressure alone is ready only when the host supplies outcome capacity.
    pub fn nextWakeup(self: *const Negotiator, now: types.Now, outcome_capacity: usize) ?u64 {
        var deadline: ?u64 = null;
        for (self.entries) |*entry| switch (entry.state) {
            .free => {},
            .reported => return now.mono_ms,
            .pending => if (outcome_capacity > 0) {
                return now.mono_ms;
            },
            .negotiating => {
                if (entry.needs_service) return now.mono_ms;
                const due = @max(now.mono_ms, entry.started_ms +| entry.timeout_ms);
                deadline = if (deadline) |prior| @min(prior, due) else due;
            },
        };
        return deadline;
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
                entry.needs_service = false;
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

    pub fn shutdown(self: *Negotiator, engine: *Engine) void {
        for (self.entries) |*entry| {
            if (entry.state == .free) continue;
            engine.closeStream(entry.stream, types.app_error_negotiation_failed);
            entry.state = .free;
        }
    }

    fn claim(self: *Negotiator, control: bool) ?*Entry {
        if (!control and self.outbound_control_reserved > 0) {
            var ordinary: usize = 0;
            for (self.entries) |*entry| {
                if (entry.state != .free and !entry.control) ordinary += 1;
            }
            if (ordinary >= self.entries.len - self.outbound_control_reserved) return null;
        }
        for (self.entries) |*entry| {
            if (entry.state == .free) return entry;
        }
        return null;
    }

    fn advance(_: *Negotiator, engine: *Engine, entry: *Entry, now: types.Now) ?Outcome {
        assert(entry.state == .negotiating);
        const waited_ms = now.mono_ms -| entry.started_ms;
        if (waited_ms >= entry.timeout_ms) return fail(engine, entry, .timeout);
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
                if (outcome.write.len > 0) {
                    entry.outbox.queue(outcome.write, false);
                    entry.needs_service = true;
                }
                switch (outcome.status) {
                    .selected => |index| {
                        assert(index < std.math.maxInt(u8));
                        entry.selected = @intCast(index);
                        entry.needs_service = false;
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
    entry.needs_service = true;
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
    assert(@sizeOf(Entry) <= 2_560);
    assert(supported_max < std.math.maxInt(u8));
    assert(negotiations_max_default <= negotiations_max_ceiling);
    assert(2 * multistream.message_length_max <= outbox_capacity);
}

test "negotiation timed entry owns exact expiry below and above the default" {
    const support = @import("test_support.zig");
    for ([_]u64{ 50, 20_000 }) |duration| {
        var pair: support.Pair = .{};
        try pair.init(.{}, .{});
        defer pair.deinit();
        const handles = try support.connectPair(&pair);
        var negotiator = try Negotiator.init(std.testing.allocator, 2);
        defer negotiator.deinit();
        const stream = try negotiator.beginOutboundTimed(&pair.client, handles.client, .ping_v1, pair.now, duration);
        const due = pair.now.mono_ms + duration;
        var outcomes: [1]Outcome = undefined;
        try std.testing.expectEqual(@as(usize, 0), negotiator.pump(&pair.client, pair.now, &outcomes));
        try std.testing.expectEqual(@as(?u64, due), negotiator.nextWakeup(pair.now, 1));
        pair.now.mono_ms = due - 1;
        try std.testing.expectEqual(@as(usize, 0), negotiator.pump(&pair.client, pair.now, &outcomes));
        pair.now.mono_ms = due;
        try std.testing.expectEqual(@as(usize, 1), negotiator.pump(&pair.client, pair.now, &outcomes));
        try std.testing.expectEqual(stream, outcomes[0].stream);
        try std.testing.expectEqual(.timeout, outcomes[0].result.failed);
    }
}
