const std = @import("std");
const builtin = @import("builtin");
const constants = @import("constants.zig");
const schedule = @import("quic/schedule.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const peer_id = @import("wire/peer_id.zig");
const tls = @import("tls/context.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;

pub const Options = struct {
    host: *const keys.KeyPair,
    bind: udp_mod.Bindings,
    limits: engine_mod.Limits = .{},
    work_limits: WorkLimits = .{},
    keylog_path: ?[]const u8 = null,
};

pub const InitError = tls.Error || engine_mod.Error || std.Io.net.IpAddress.BindError ||
    std.Io.RandomSecureError || std.Io.File.OpenError || std.Io.File.StatError ||
    error{ClockOutOfRange};

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
    sent: [constants.send_batch_max]types.Sent = undefined,
    owners: [constants.send_batch_max]types.Handle = undefined,
};

/// Configured QUIC windows and the send batch, excluding native overhead.
pub const MemoryPlan = struct {
    engine: engine_mod.MemoryPlan,
    ready_batch_datagrams: u8 = constants.send_batch_max,
    ready_batch_storage_bytes: u64 = @sizeOf(SendBatch),
};

const IoError = udp_mod.ReceiveTimeoutError || error{ClockOutOfRange};

pub const StepError = IoError || error{KeylogWriteFailed};
pub const DialError = udp_mod.SendError || engine_mod.DialError || error{ ClockOutOfRange, DestinationUnreachable, MissingPeerId };

/// Options of the standalone `step`, which also waits for the socket. NetworkCore polls its
/// sockets itself and drives the phases directly.
pub const StepOptions = struct {
    wait_max_ms: u32 = constants.poll_interval_ms,
};

const Received = union(enum) {
    datagram: udp_mod.Datagram,
    dropped,
    timeout,
};

pub const StepResult = struct {
    now: engine_mod.Now,
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

pub const Transport = struct {
    engine: engine_mod.Engine = undefined,
    udp: udp_mod.Udp = undefined,
    work_limits: WorkLimits = .{},
    batch: SendBatch = .{},
    batch_len: u8 = 0,
    receive_buffer: [constants.datagram_size_max]u8 = undefined,
    keylog: ?std.Io.File = null,
    keylog_offset: u64 = 0,

    /// The I/O provider must honor std.Io.randomSecure's external entropy contract.
    pub fn init(
        target: *Transport,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) InitError!void {
        try options.work_limits.validate();
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed_bytes);
        try std.Io.randomSecure(io, &seed_bytes);
        const now = try currentTime(io);
        target.keylog = null;
        target.keylog_offset = 0;
        if (options.keylog_path) |path| {
            const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .permissions = @enumFromInt(0o600) });
            errdefer file.close(io);
            target.keylog_offset = (try file.stat(io)).size;
            target.keylog = file;
        }
        errdefer if (target.keylog) |file| file.close(io);
        var context = try tls.Context.init(options.host, now.unix_s, serial);
        var context_owned = true;
        errdefer if (context_owned) context.deinit();
        target.udp = try udp_mod.Udp.bind(io, options.bind);
        errdefer target.udp.close(io);
        var engine_limits = options.limits;
        engine_limits.keylog = options.keylog_path != null;
        target.engine = try engine_mod.Engine.init(allocator, .{
            .tls = context,
            .limits = engine_limits,
            .local = target.udp.localAddresses(),
            .seed = &seed_bytes,
        });
        context_owned = false;
        target.work_limits = options.work_limits;
        target.batch_len = 0;
        assert(target.engine.registry.slots.len == options.limits.connections_max);
        assert(target.keylog != null or options.keylog_path == null);
    }

    pub fn deinit(self: *Transport, io: std.Io) void {
        self.engine.deinit();
        self.udp.close(io);
        if (self.keylog) |file| file.close(io);
        self.* = undefined;
    }

    pub fn peerId(self: *const Transport) peer_id.PeerId {
        assert(self.engine.registry.slots.len > 0);
        return self.engine.tls.local_peer_id;
    }

    pub fn localAddress(self: *const Transport) types.Address {
        assert(self.engine.registry.slots.len > 0);
        return self.udp.localAddress();
    }

    pub fn localMultiaddr(self: *const Transport) multiaddr.Multiaddr {
        assert(self.engine.registry.slots.len > 0);
        return .{ .address = self.udp.localAddress(), .peer = self.engine.tls.local_peer_id };
    }

    pub fn memoryPlan(self: *const Transport) MemoryPlan {
        return .{ .engine = self.engine.memoryPlan() };
    }

    pub fn dial(
        self: *Transport,
        io: std.Io,
        target: *const multiaddr.Multiaddr,
    ) DialError!engine_mod.Handle {
        const expected = target.peer orelse return error.MissingPeerId;
        return self.dialPeer(io, target.address, expected);
    }

    /// Earliest engine timer key in monotonic nanoseconds. O(1).
    pub fn nextDeadlineNs(self: *const Transport) ?u64 {
        return self.engine.nextDeadlineNs();
    }

    /// Sends the first flight before returning, so a local send failure is a dial error.
    pub fn dialPeer(
        self: *Transport,
        io: std.Io,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        const now = try currentTime(io);
        const handle = self.engine.dial(&peer, expected, now) catch |err| switch (err) {
            error.AddressFamilyUnsupported => return error.DestinationUnreachable,
            else => return err,
        };
        assert(self.batch_len == 0);
        var result = StepResult{ .now = now };
        var turn = schedule.Turn.init(self.work_limits.send_per_step_max);
        const drained = self.burst(io, handle.index, handle, now, &turn, &result);
        const failure = self.submit(io, &result);
        self.engine.sent(handle.index, now, drained);
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
        events: []engine_mod.Event,
        options: StepOptions,
    ) ProgressResult {
        var result = StepResult{ .now = currentTime(io) catch |err| return .{
            .progress = .{ .now = .{ .mono_ms = 0, .unix_s = 0 } },
            .failure = err,
        } };
        self.engine.releaseReported();
        const wait_ms = self.idleWaitMs(result.now, options.wait_max_ms);
        var failure: ?StepError = if (self.receiveBatch(io, &result, wait_ms)) |_| null else |err| err;
        // The wait may have slept; timers use a fresh clock when one can be read.
        if (currentTime(io)) |fresh| {
            if (fresh.mono_ms >= result.now.mono_ms) result.now = fresh;
        } else |err| failure = failure orelse err;
        self.expire(result.now);
        self.engine.collect(result.now);
        self.flush(io, result.now, &result);
        // Events from this turn's sends, such as a close reached by sending CONNECTION_CLOSE, are
        // published with the rest.
        result.events = self.engine.pollEvents(events);
        result.events_pending = self.engine.eventsPending();
        if (failure) |err| return .{ .progress = result, .failure = err };
        self.drainKeylog(io) catch |err| return .{ .progress = result, .failure = err };
        return .{ .progress = result };
    }

    /// Non-blocking drain of the QUIC socket into the engine, up to the receive budget.
    pub fn receive(self: *Transport, io: std.Io, result: *StepResult) IoError!void {
        return self.receiveBatch(io, result, 0);
    }

    pub fn expire(self: *Transport, now: engine_mod.Now) void {
        self.engine.expire(now);
    }

    /// Gathers stream readiness for the connections touched this turn and drains their events.
    pub fn collect(self: *Transport, now: engine_mod.Now, events: []engine_mod.Event) usize {
        self.engine.collect(now);
        return self.engine.pollEvents(events);
    }

    /// Drains the dirty connections in bursts of burst_per_connection datagrams until each
    /// reports Done or the turn's send budget runs out. A connection its burst did not finish
    /// moves to the dirty tail, so busy connections share the budget round-robin. A failed
    /// datagram fails only its own connection; the rest of its batch is resubmitted.
    pub fn flush(self: *Transport, io: std.Io, now: engine_mod.Now, result: *StepResult) void {
        assert(self.batch_len == 0);
        var turn = schedule.Turn.init(self.work_limits.send_per_step_max);
        // Each visit either drains its connection or sends at least one datagram.
        const visits_max = self.engine.dirtyCount() + turn.send_max;
        for (0..visits_max) |_| {
            if (!turn.canSend()) break;
            const index = self.engine.nextDirty() orelse break;
            const owner = self.engine.sendOwner(index) orelse {
                self.engine.sent(index, now, true);
                continue;
            };
            const drained = self.burst(io, index, owner, now, &turn, result);
            self.engine.sent(index, now, drained);
        }
        _ = self.submit(io, result);
        result.backlog = self.engine.backlog();
        self.engine.finishFlush(now);
    }

    /// Sends up to burst_per_connection datagrams of one connection into the shared batch.
    /// Returns whether quiche reported nothing left to send.
    fn burst(self: *Transport, io: std.Io, index: u16, owner: types.Handle, now: engine_mod.Now, turn: *schedule.Turn, result: *StepResult) bool {
        var count: u16 = 0;
        while (count < self.work_limits.burst_per_connection and turn.canSend()) : (count += 1) {
            if (self.batch_len == constants.send_batch_max) _ = self.submit(io, result);
            const at = self.batch_len;
            const sent = self.engine.sendOne(index, now, &self.batch.buffers[at]) orelse return true;
            self.batch.sent[at] = sent;
            self.batch.owners[at] = owner;
            self.batch_len += 1;
            turn.recordSend();
        }
        return false;
    }

    /// Returns the first send failure, after failing the connection that owned the datagram.
    fn submit(self: *Transport, io: std.Io, result: *StepResult) ?udp_mod.SendError {
        const count = self.batch_len;
        if (count == 0) return null;
        defer self.batch_len = 0;
        if (builtin.mode == .Debug) assertReleased(io, self.batch.sent[0..count]);
        var first: ?udp_mod.SendError = null;
        var begin: usize = 0;
        while (begin < count) {
            result.send_calls += 1;
            const outcome = self.udp.sendMany(io, self.batch.sent[begin..count]);
            assert(begin + outcome.sent <= count);
            result.datagrams_sent += @intCast(outcome.sent);
            begin += outcome.sent;
            const err = outcome.failure orelse break;
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

    fn idleWaitMs(self: *const Transport, now: engine_mod.Now, wait_max_ms: u32) u32 {
        if (wait_max_ms == 0 or self.engine.backlog() or self.engine.eventsPending()) return 0;
        const deadline = self.engine.nextDeadlineNs() orelse return wait_max_ms;
        const remaining = deadline -| now.nanos();
        const ceiling = remaining / std.time.ns_per_ms + @intFromBool(remaining % std.time.ns_per_ms != 0);
        return @intCast(@min(wait_max_ms, ceiling));
    }

    fn receiveBatch(self: *Transport, io: std.Io, result: *StepResult, first_wait_ms: u32) IoError!void {
        var count: u32 = 0;
        while (count < self.work_limits.receive_per_step_max) : (count += 1) {
            const wait_ms: u32 = if (count == 0) first_wait_ms else 0;
            const admitted = switch (try self.receiveDatagram(io, result, wait_ms)) {
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
                    self.udp.send(io, &admitted.from, bytes) catch {};
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
    ) IoError!Received {
        const datagram = self.udp.receiveTimeout(io, &self.receive_buffer, receiveTimeout(wait_ms)) catch |err| switch (err) {
            error.Timeout => return .timeout,
            error.DatagramTooLarge,
            error.PortUnreachable,
            error.ConnectionResetByPeer,
            error.NetworkDown,
            error.SystemResources,
            => {
                result.receive_errors += 1;
                return .dropped;
            },
            else => return err,
        };
        return .{ .datagram = datagram };
    }

    fn drainKeylog(self: *Transport, io: std.Io) error{KeylogWriteFailed}!void {
        const file = self.keylog orelse return;
        var lines: [tls.keylog_capacity]u8 = undefined;
        for (self.engine.activeIndices()) |index| {
            const length = self.engine.takeKeylog(index, &lines);
            if (length == 0) continue;
            file.writePositionalAll(io, lines[0..length], self.keylog_offset) catch {
                file.close(io);
                self.keylog = null;
                return error.KeylogWriteFailed;
            };
            self.keylog_offset += length;
        }
    }
};

/// quiche 0.28 under CUBIC releases every datagram at its send time. A controller that paces
/// would need held datagrams, which this transport does not keep.
fn assertReleased(io: std.Io, batch: []const types.Sent) void {
    const now = currentTime(io) catch return;
    for (batch) |sent| assert(sent.transmit_at_ns <= now.nanos());
}

fn receiveTimeout(wait_ms: u32) std.Io.Timeout {
    return .{ .duration = .{
        .raw = .fromMilliseconds(wait_ms),
        .clock = .awake,
    } };
}

fn mapSendError(err: udp_mod.SendError) DialError {
    return switch (err) {
        error.AccessDenied,
        error.AddressFamilyUnsupported,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        => error.DestinationUnreachable,
        else => err,
    };
}

pub fn currentTime(io: std.Io) error{ClockOutOfRange}!engine_mod.Now {
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
