const std = @import("std");
const constants = @import("constants.zig");
const engine_mod = @import("quic/engine.zig");
const limits = @import("quic/limits.zig");
const peer_id = @import("wire/peer_id.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Udp = udp_mod.Udp;

pub const StepError = udp_mod.ReceiveTimeoutError || udp_mod.SendError ||
    std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
};

pub const DialError = StepError || engine_mod.DialError;

pub const StepOptions = struct {
    wait_max_ms: u32 = constants.poll_interval_ms,
};

const drain_rounds_max: u32 = @divExact(limits.send_burst_max, constants.send_batch_max);

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
    activity: usize = 0,
    activity_pending: bool = false,
};

pub const Drained = struct {
    sent: u32 = 0,
    calls: u32 = 0,
    failure: ?StepError = null,
};

pub const Driver = struct {
    pool: engine_mod.EntropyPool = .{},
    batch: engine_mod.SendBatch = .{},
    output: [constants.datagram_size_max]u8 = undefined,

    pub fn init() Driver {
        return .{};
    }

    pub fn nextTimeoutMs(self: *const Driver, engine: *Engine, now: engine_mod.Now) ?u64 {
        _ = self;
        const view = engine.driverView();
        assert(view.slotCount() > 0);
        const next = view.nextTimeoutMs(now);
        if (view.activeIndices().len == 0) assert(next == null);
        return next;
    }

    pub fn dial(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        const now = try currentTime(io);
        const handle = try engine.dial(&peer, expected, now, try entropy(io));
        assert(handle.index < engine.driverView().slotCount());
        if (self.drain(io, engine, udp, handle.index, now).failure) |err| {
            engine.driverView().failSend(handle.index);
            assert(engine.abandon(handle));
            return err;
        }
        return handle;
    }

    pub fn step(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: StepOptions,
    ) StepError!StepResult {
        var result = StepResult{ .now = try currentTime(io) };
        var batch: u32 = 0;
        while (batch < constants.receive_batch_max) : (batch += 1) {
            if (!self.pool.fresh) self.pool.fill(try entropy(io));
            const wait_ms: ?u32 = if (batch == 0) options.wait_max_ms else null;
            const received = try self.receiveDatagram(io, engine, udp, &result, wait_ms);
            const admitted = switch (received) {
                .timeout => break,
                .dropped => continue,
                .datagram => |datagram| datagram,
            };
            result.datagrams_received += 1;
            defer udp.release(admitted.handle) catch unreachable;
            switch (engine.driverView().receive(
                admitted.bytes,
                &admitted.from,
                result.now,
                &self.pool,
                &self.output,
            )) {
                .accepted => result.datagrams_accepted += 1,
                .version_negotiation => |bytes| {
                    send(io, udp, &admitted.from, bytes) catch {};
                    result.version_negotiations += 1;
                },
                .dropped => result.datagrams_dropped += 1,
            }
        }
        result.now = try currentTime(io);
        const view = engine.driverView();
        view.tick(result.now);
        for (view.activeIndices()) |index| {
            const drained = self.drain(io, engine, udp, index, result.now);
            result.datagrams_sent += drained.sent;
            result.send_calls += drained.calls;
            if (drained.failure != null) {
                result.send_failures += 1;
                view.failSend(index);
            }
        }
        view.releaseReported();
        result.events = engine.pollEvents(events);
        result.events_pending = engine.eventsPending();
        result.activity = view.takeActivity(activity);
        result.activity_pending = view.activityPending();
        assert(result.events <= events.len);
        assert(result.activity <= activity.len);
        return result;
    }

    fn receiveDatagram(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        result: *StepResult,
        wait_ms: ?u32,
    ) StepError!Received {
        _ = self;
        const view = engine.driverView();
        const timeout = receiveTimeout(wait_ms, view.nextTimeoutMs(result.now));
        const datagram = udp.receiveTimeout(io, timeout) catch |err| switch (err) {
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

    fn drain(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        index: u16,
        now: engine_mod.Now,
    ) Drained {
        const view = engine.driverView();
        var result = Drained{};
        var rounds: u32 = 0;
        while (rounds < drain_rounds_max) : (rounds += 1) {
            const count = view.sendBatch(index, now, &self.batch);
            if (count == 0) break;
            sendMany(io, udp, self.batch.sent[0..count]) catch |err| {
                result.failure = err;
                return result;
            };
            result.sent += count;
            result.calls += 1;
            if (count < constants.send_batch_max) break;
        }
        assert(result.sent <= limits.send_burst_max);
        assert(result.calls <= drain_rounds_max);
        return result;
    }
};

fn receiveTimeout(wait_ms: ?u32, earliest_ms: ?u64) std.Io.Timeout {
    return if (wait_ms) |bound| blk: {
        var wait: u64 = bound;
        if (earliest_ms) |earliest| wait = @min(wait, earliest);
        break :blk .{ .duration = .{
            .raw = .fromMilliseconds(@intCast(wait)),
            .clock = .awake,
        } };
    } else .{ .duration = .{ .raw = .zero, .clock = .awake } };
}

fn sendMany(io: std.Io, udp: *const Udp, batch: []const types.Sent) StepError!void {
    return udp.sendMany(io, batch) catch |err| mapSendError(err);
}

fn send(
    io: std.Io,
    udp: *const Udp,
    destination: *const types.Address,
    bytes: []const u8,
) StepError!void {
    return udp.send(io, destination, bytes) catch |err| mapSendError(err);
}

fn mapSendError(err: udp_mod.SendError) StepError {
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
    const mono = std.Io.Clock.awake.now(io).toMilliseconds();
    const wall = std.Io.Clock.real.now(io).toSeconds();
    if (mono < 0 or wall < 0) return error.ClockOutOfRange;
    return .{ .mono_ms = @intCast(mono), .unix_s = wall };
}

fn entropy(io: std.Io) std.Io.RandomSecureError![limits.local_cid_length]u8 {
    var bytes: [limits.local_cid_length]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    return bytes;
}

comptime {
    assert(drain_rounds_max > 0);
    assert(@sizeOf(Driver) <= 32 * 1_024);
}

test "driver zero wait remains an actual nonblocking timeout" {
    const timeout = receiveTimeout(0, null);
    try std.testing.expectEqual(@as(i96, 0), timeout.duration.raw.nanoseconds);
    try std.testing.expectEqual(@as(i96, 0), receiveTimeout(5, 0).duration.raw.nanoseconds);
}
