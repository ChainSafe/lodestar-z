const std = @import("std");
const builtin = @import("builtin");
const constants = @import("constants.zig");
const Engine = @import("quic/Engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const peer_id = @import("wire/peer_id.zig");
const tls = @import("tls/context.zig");
const types = @import("types.zig");
const Sockets = @import("udp").Sockets;

const assert = std.debug.assert;

pub const Options = struct {
    host: *const keys.KeyPair,
    bind: Sockets.Bindings,
    limits: Engine.Limits = .{},
    work_limits: WorkLimits = .{},
    /// Null keeps the system's default socket buffer sizes.
    socket_buffers: ?Sockets.Buffers = null,
};

pub const InitError = tls.Error || Engine.Error || std.Io.net.IpAddress.BindError ||
    std.Io.RandomSecureError || error{ClockOutOfRange};

pub const send_burst_max: u16 = 256;

pub const WorkLimits = struct {
    /// Datagrams sent per turn.
    send_per_step_max: u16 = send_burst_max,
    receive_per_step_max: u16 = constants.receive_batch_max,
    /// Datagrams sent per dirty-connection visit.
    burst_per_connection: u16 = constants.send_batch_max,

    pub fn validate(self: WorkLimits) error{InvalidLimits}!void {
        if (self.send_per_step_max == 0 or self.send_per_step_max > send_burst_max) return error.InvalidLimits;
        if (self.receive_per_step_max == 0 or self.receive_per_step_max > constants.receive_batch_max) return error.InvalidLimits;
        if (self.burst_per_connection == 0 or self.burst_per_connection > self.send_per_step_max) return error.InvalidLimits;
    }
};

/// One sendmmsg batch. quiche writes each datagram straight into `buffers`, and datagrams of
/// different connections share a batch.
pub const SendBatch = struct {
    buffers: [constants.send_batch_max][constants.datagram_size_max]u8 = undefined,
    outgoing: [constants.send_batch_max]Sockets.Outgoing = undefined,
    release_times: [constants.send_batch_max]u64 = undefined,
    scratch: Sockets.BatchScratch = undefined,
    owners: [constants.send_batch_max]types.Handle = undefined,
};

/// Configured QUIC windows and the send batch, excluding native overhead.
pub const MemoryPlan = struct {
    engine: Engine.MemoryPlan,
    ready_batch_datagrams: u8 = constants.send_batch_max,
    ready_batch_storage_bytes: u64 = @sizeOf(SendBatch),
};

pub const StepError = Sockets.DatagramError || error{ClockOutOfRange};
pub const DialError = Sockets.SendError || Engine.DialError || error{ ClockOutOfRange, DestinationUnreachable, MissingPeerId };

/// Options of the standalone `step`, which also waits for the socket. NetworkCore polls its
/// sockets itself and drives the phases directly.
pub const StepOptions = struct {
    wait_max_ms: u32 = constants.poll_interval_ms,
};

const Received = union(enum) {
    datagram: Sockets.Datagram,
    dropped,
    timeout,
};

pub const StepResult = struct {
    now: Engine.Now,
    datagrams_received: u32 = 0,
    datagrams_accepted: u32 = 0,
    datagrams_dropped: u32 = 0,
    version_negotiations: u32 = 0,
    datagrams_sent: u32 = 0,
    send_calls: u32 = 0,
    receive_errors: u32 = 0,
    send_failures: u32 = 0,
    events: usize = 0,
    events_pending: bool = false,
    /// A flush stopped at a burst or turn budget, so connections still have output.
    backlog: bool = false,
};

pub const ProgressResult = struct {
    progress: StepResult,
    failure: ?StepError = null,
};

pub const Counters = struct {
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    received_datagrams: u64 = 0,
    sent_datagrams: u64 = 0,
};

pub const Transport = struct {
    engine: Engine = undefined,
    sockets: Sockets = .{},
    counters: Counters = .{},
    send_drops: Sockets.SendDrops = .{},
    work_limits: WorkLimits = .{},
    batch: SendBatch = .{},
    batch_len: u8 = 0,
    receive_buffer: [constants.datagram_size_max]u8 = undefined,

    /// The I/O provider must honor std.Io.randomSecure's external entropy contract.
    pub fn init(
        target: *Transport,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) InitError!void {
        try options.work_limits.validate();
        if (options.socket_buffers) |request| if (!request.valid()) return error.InvalidLimits;
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed_bytes);
        try std.Io.randomSecure(io, &seed_bytes);
        const now = try currentTime(io);
        var context = try tls.Context.init(options.host, now.unix_s, serial);
        var context_owned = true;
        errdefer if (context_owned) context.deinit();
        target.sockets = try Sockets.bind(io, options.bind);
        errdefer target.sockets.close(io);
        if (options.socket_buffers) |request| @import("configuration.zig").requestBuffers(&target.sockets, io, request, .network_quic);
        target.engine = try Engine.init(allocator, .{
            .tls = context,
            .limits = options.limits,
            .local = target.sockets.localAddresses(),
            .seed = &seed_bytes,
        });
        context_owned = false;
        target.work_limits = options.work_limits;
        target.batch_len = 0;
        target.counters = .{};
        target.send_drops = .{};
        assert(target.engine.registry.slots.len == options.limits.connections_max);
    }

    pub fn deinit(self: *Transport, io: std.Io) void {
        self.engine.deinit();
        self.sockets.close(io);
        self.* = undefined;
    }

    pub fn peerId(self: *const Transport) peer_id.PeerId {
        assert(self.engine.registry.slots.len > 0);
        return self.engine.tls.local_peer_id;
    }

    pub fn localAddress(self: *const Transport) types.Address {
        assert(self.engine.registry.slots.len > 0);
        return self.sockets.localAddress();
    }

    pub fn localMultiaddr(self: *const Transport) multiaddr.Multiaddr {
        assert(self.engine.registry.slots.len > 0);
        return .{ .address = self.sockets.localAddress(), .peer = self.engine.tls.local_peer_id };
    }

    pub fn memoryPlan(self: *const Transport) MemoryPlan {
        return .{ .engine = self.engine.memoryPlan() };
    }

    pub fn dial(
        self: *Transport,
        io: std.Io,
        target: *const multiaddr.Multiaddr,
    ) DialError!Engine.Handle {
        const expected = target.peer orelse return error.MissingPeerId;
        return self.dialPeer(io, target.address, expected);
    }

    /// Earliest engine timer key in monotonic nanoseconds. O(1).
    pub fn nextDeadlineNs(self: *const Transport) ?u64 {
        return self.engine.nextDeadlineNs();
    }

    /// Produces the first flight before returning. Local pressure drops it for QUIC loss recovery;
    /// other send failures are dial errors.
    pub fn dialPeer(
        self: *Transport,
        io: std.Io,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!Engine.Handle {
        const now = try currentTime(io);
        const handle = self.engine.dial(&peer, expected, now) catch |err| switch (err) {
            error.AddressFamilyUnsupported => return error.DestinationUnreachable,
            else => return err,
        };
        assert(self.batch_len == 0);
        var result = StepResult{ .now = now };
        var remaining: u32 = self.work_limits.send_per_step_max;
        assert(remaining > 0);
        const drained = self.burst(io, handle.index, handle, now, &remaining, &result) catch |err| {
            self.engine.sent(handle.index, keyClock(io, now), false);
            _ = self.engine.abandon(handle);
            return err;
        };
        const failure = self.submit(io, &result);
        self.engine.sent(handle.index, keyClock(io, now), drained);
        if (failure) |err| {
            _ = self.engine.abandon(handle);
            return mapSendError(err);
        }
        return handle;
    }

    /// Standalone turn for programs that own only a Transport: waits up to `wait_max_ms` for a
    /// datagram when nothing is due, then receives, expires timers, collects events and flushes.
    /// Publishes completed work on failure. A failure to read the initial clock leaves the turn
    /// and pending events untouched.
    pub fn step(
        self: *Transport,
        io: std.Io,
        events: []Engine.Event,
        options: StepOptions,
    ) ProgressResult {
        var result = StepResult{ .now = currentTime(io) catch |err| return .{
            .progress = .{ .now = .{ .mono_ms = 0, .unix_s = 0 } },
            .failure = err,
        } };
        self.engine.releaseReported();
        const wait_ms = self.idleWaitMs(result.now, options.wait_max_ms);
        var failure: ?StepError = if (self.receiveBatch(io, &result, wait_ms, @splat(true))) |_| null else |err| err;
        // The wait may have slept; timers use a fresh clock when one can be read.
        if (currentTime(io)) |fresh| {
            if (fresh.mono_ms >= result.now.mono_ms) result.now = fresh;
        } else |err| failure = failure orelse err;
        self.expire(result.now);
        self.engine.collect(result.now);
        if (failure == null or failure.? != error.Canceled) self.flush(io, result.now, &result) catch |err| {
            failure = err;
        };
        // Events from this turn's sends, such as a close reached by sending CONNECTION_CLOSE, are
        // published with the rest.
        result.events = self.engine.pollEvents(events);
        result.events_pending = self.engine.eventsPending();
        return .{ .progress = result, .failure = failure };
    }

    /// Non-blocking drain of the QUIC sockets into the engine, up to the receive budget. Reads
    /// only the families `ready` marks, indexed like the sockets, alternating while both hold
    /// datagrams. A family found empty is not read again this turn; a later arrival keeps its
    /// socket readable for the owner's next poll.
    pub fn receive(self: *Transport, io: std.Io, result: *StepResult, ready: [2]bool) StepError!void {
        return self.receiveBatch(io, result, 0, ready);
    }

    pub fn expire(self: *Transport, now: Engine.Now) void {
        self.engine.expire(now);
    }

    /// Gathers stream readiness for the connections touched this turn and drains their events.
    pub fn collect(self: *Transport, now: Engine.Now, events: []Engine.Event) usize {
        self.engine.collect(now);
        return self.engine.pollEvents(events);
    }

    /// Drains the dirty connections in bursts of burst_per_connection datagrams until each
    /// reports Done or the turn's send budget runs out. A connection its burst did not finish
    /// moves to the dirty tail, so busy connections share the budget round-robin. A failed
    /// datagram fails only its own connection; the rest of its batch is resubmitted. Temporary
    /// local pressure instead drops the unsent suffix for QUIC loss recovery.
    /// Cancellation stops production and submission, retains completed progress, and leaves
    /// connection recovery state intact. It never identifies a failed destination.
    pub fn flush(self: *Transport, io: std.Io, now: Engine.Now, result: *StepResult) std.Io.Cancelable!void {
        assert(self.batch_len == 0);
        var remaining: u32 = self.work_limits.send_per_step_max;
        assert(remaining > 0);
        // The latest clock read that keyed a timer.
        var keyed = now;
        defer {
            result.backlog = self.engine.backlog();
            self.engine.finishFlush(keyed);
        }
        // Each visit either drains its connection or sends at least one datagram.
        const visits_max = self.engine.dirtyCount() + remaining;
        for (0..visits_max) |_| {
            if (remaining == 0) break;
            const index = self.engine.nextDirty() orelse break;
            const owner = self.engine.sendOwner(index) orelse {
                self.engine.sent(index, keyed, true);
                continue;
            };
            const drained = self.burst(io, index, owner, now, &remaining, result) catch |err| {
                keyed = keyClock(io, keyed);
                self.engine.sent(index, keyed, false);
                return err;
            };
            keyed = keyClock(io, keyed);
            self.engine.sent(index, keyed, drained);
        }
        if (self.submit(io, result)) |err| if (err == error.Canceled) return error.Canceled;
    }

    /// quiche reports the time left on its timer from its own clock read, so a timer key built on
    /// a clock read earlier in the turn lands early by the time the turn has run since. A clock
    /// supplied without nanoseconds is not the one quiche reads and is kept.
    fn keyClock(io: std.Io, after: Engine.Now) Engine.Now {
        const previous = after.mono_ns orelse return after;
        const read = std.math.cast(u64, std.Io.Clock.awake.now(io).nanoseconds) orelse return after;
        if (read <= previous) return after;
        return .{ .mono_ms = read / std.time.ns_per_ms, .mono_ns = read, .unix_s = after.unix_s };
    }

    /// Sends up to burst_per_connection datagrams of one connection into the shared batch.
    /// Returns whether quiche reported nothing left to send.
    fn burst(self: *Transport, io: std.Io, index: u16, owner: types.Handle, now: Engine.Now, remaining: *u32, result: *StepResult) std.Io.Cancelable!bool {
        var count: u16 = 0;
        while (count < self.work_limits.burst_per_connection and remaining.* > 0) : (count += 1) {
            if (self.batch_len == constants.send_batch_max) {
                if (self.submit(io, result)) |err| if (err == error.Canceled) return error.Canceled;
            }
            const at = self.batch_len;
            const sent = self.engine.sendOne(index, now, &self.batch.buffers[at]) orelse return true;
            assert(sent.bytes.len <= constants.datagram_size_max);
            self.batch.outgoing[at] = .{ .to = sent.to, .bytes = sent.bytes };
            self.batch.release_times[at] = sent.transmit_at_ns;
            self.batch.owners[at] = owner;
            self.batch_len += 1;
            remaining.* -= 1;
        }
        return false;
    }

    /// Returns cancellation immediately, or the first destination failure after failing its owner. QUIC already accounts
    /// for produced packets as sent: local pressure drops their bytes without rolling back packet
    /// state or closing connections, so loss timers can retransmit the frames.
    fn submit(self: *Transport, io: std.Io, result: *StepResult) ?Sockets.SendError {
        const count = self.batch_len;
        if (count == 0) return null;
        defer self.batch_len = 0;
        if (builtin.mode == .Debug) assertReleased(io, self.batch.release_times[0..count]);
        var first: ?Sockets.SendError = null;
        var begin: usize = 0;
        while (begin < count) {
            result.send_calls += 1;
            const outcome = self.sockets.sendMany(io, self.batch.outgoing[begin..count], constants.datagram_size_max, &self.batch.scratch);
            for (self.batch.outgoing[begin..][0..outcome.sent]) |sent| {
                self.counters.sent_bytes +|= sent.bytes.len;
                self.counters.sent_datagrams +|= 1;
            }
            assert(begin + outcome.sent <= count);
            result.datagrams_sent += @intCast(outcome.sent);
            begin += outcome.sent;
            const err = outcome.failure orelse break;
            if (Sockets.SendDrops.Reason.fromError(err)) |reason| {
                for (self.batch.outgoing[begin..count]) |unsent| self.send_drops.add(reason, unsent.bytes.len);
                break;
            }
            if (err == error.Canceled) return error.Canceled;
            first = first orelse err;
            const owner = self.batch.owners[begin];
            if (self.engine.sendOwner(owner.index)) |current| if (std.meta.eql(current, owner)) {
                self.engine.failSend(owner.index);
                result.send_failures += 1;
            };
            begin += 1;
        }
        return first;
    }

    fn idleWaitMs(self: *const Transport, now: Engine.Now, wait_max_ms: u32) u32 {
        if (wait_max_ms == 0 or self.engine.backlog() or self.engine.eventsPending()) return 0;
        const deadline = self.engine.nextDeadlineNs() orelse return wait_max_ms;
        const remaining = deadline -| now.nanos();
        const ceiling = remaining / std.time.ns_per_ms + @intFromBool(remaining % std.time.ns_per_ms != 0);
        return @intCast(@min(wait_max_ms, ceiling));
    }

    fn receiveBatch(self: *Transport, io: std.Io, result: *StepResult, first_wait_ms: u32, ready: [2]bool) StepError!void {
        var eligible = ready;
        var count: u32 = 0;
        while (count < self.work_limits.receive_per_step_max) : (count += 1) {
            const wait_ms: u32 = if (count == 0) first_wait_ms else 0;
            const admitted = switch (try self.receiveDatagram(io, result, wait_ms, &eligible)) {
                .timeout => break,
                .dropped => continue,
                .datagram => |datagram| datagram,
            };
            result.datagrams_received += 1;
            // Version negotiation and retry replies use the idle batch buffer.
            const outcome = self.engine.receive(admitted.bytes, &admitted.from, result.now, &self.batch.buffers[0]);
            switch (outcome) {
                .accepted => result.datagrams_accepted += 1,
                .version_negotiation, .retry => |bytes| {
                    self.sendReply(io, admitted.from, bytes) catch |err| {
                        if (err == error.Canceled) return error.Canceled;
                    };
                    if (outcome == .version_negotiation) result.version_negotiations += 1;
                },
                .dropped => result.datagrams_dropped += 1,
            }
        }
    }

    fn receiveDatagram(
        self: *Transport,
        io: std.Io,
        result: *StepResult,
        wait_ms: u32,
        ready: *[2]bool,
    ) StepError!Received {
        const received: Sockets.DatagramError!?Sockets.Datagram = if (wait_ms == 0)
            self.sockets.receiveReadyDatagram(io, &self.receive_buffer, ready)
        else if (self.sockets.receiveDatagram(io, &self.receive_buffer, receiveTimeout(wait_ms))) |packet| packet else |err| err;
        const datagram = received catch |err| switch (err) {
            error.Timeout => return .timeout,
            error.DatagramTooLarge,
            error.PortUnreachable,
            error.ConnectionResetByPeer,
            error.NetworkDown,
            error.SystemResources,
            => {
                if (err == error.DatagramTooLarge) self.counters.received_datagrams +|= 1;
                result.receive_errors += 1;
                return .dropped;
            },
            else => return err,
        };
        const packet = datagram orelse return .timeout;
        self.counters.received_datagrams +|= 1;
        self.counters.received_bytes +|= packet.bytes.len;
        return .{ .datagram = packet };
    }
    fn sendReply(self: *Transport, io: std.Io, destination: types.Address, bytes: []const u8) Sockets.SendError!void {
        self.sockets.sendTo(io, destination, bytes, constants.datagram_size_max) catch |err| {
            if (Sockets.SendDrops.Reason.fromError(err)) |reason| self.send_drops.add(reason, bytes.len);
            return err;
        };
        self.counters.sent_bytes +|= bytes.len;
        self.counters.sent_datagrams +|= 1;
    }
};

/// quiche 0.28 under CUBIC releases every datagram at its send time. A controller that paces
/// would need held datagrams, which this transport does not keep.
fn assertReleased(io: std.Io, release_times: []const u64) void {
    const now = currentTime(io) catch return;
    for (release_times) |release_time| assert(release_time <= now.nanos());
}

fn receiveTimeout(wait_ms: u32) std.Io.Timeout {
    return .{ .duration = .{
        .raw = .fromMilliseconds(wait_ms),
        .clock = .awake,
    } };
}

fn mapSendError(err: Sockets.SendError) DialError {
    return switch (err) {
        error.AccessDenied,
        error.AddressFamilyUnsupported,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.DestinationRefused,
        error.HostUnreachable,
        error.NetworkUnreachable,
        => error.DestinationUnreachable,
        else => err,
    };
}

pub fn currentTime(io: std.Io) error{ClockOutOfRange}!Engine.Now {
    const mono = std.Io.Clock.awake.now(io).nanoseconds;
    const wall = std.Io.Clock.real.now(io).toSeconds();
    if (mono < 0 or mono > std.math.maxInt(u64) or wall < 0) return error.ClockOutOfRange;
    return .{ .mono_ms = @intCast(@divTrunc(mono, std.time.ns_per_ms)), .mono_ns = @intCast(mono), .unix_s = wall };
}

comptime {
    assert(@sizeOf(Transport) <= 32 * 1_024);
    assert(send_burst_max % constants.send_batch_max == 0);
}

test "transport zero wait remains an actual nonblocking timeout" {
    try std.testing.expectEqual(@as(i96, 0), receiveTimeout(0).duration.raw.nanoseconds);
    try std.testing.expectEqual(@as(i96, 5 * std.time.ns_per_ms), receiveTimeout(5).duration.raw.nanoseconds);
}

test {
    _ = @import("transport_io_test.zig");
    _ = @import("transport_test.zig");
}
