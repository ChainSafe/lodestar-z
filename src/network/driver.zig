const std = @import("std");
const constants = @import("constants.zig");
const engine_mod = @import("quic/engine.zig");
const limits = @import("quic/limits.zig");
const peer_id = @import("wire/peer_id.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;

pub const StepError = udp_mod.ReceiveTimeoutError || udp_mod.SendError ||
    std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
    InvalidPollInterval,
};

pub const DialError = StepError || engine_mod.DialError;

pub const Config = struct {
    poll_interval_ms: u32 = constants.poll_interval_ms,
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
    receive_errors: u32 = 0,
    send_failures: u32 = 0,
    first_failure: ?struct { conn: engine_mod.Handle, err: StepError } = null,
    events: usize = 0,
    events_pending: bool = false,
};

pub const Drained = struct {
    sent: u32 = 0,
    failure: ?StepError = null,
};

pub const Driver = struct {
    engine: *engine_mod.Engine,
    udp: *udp_mod.Udp,
    config: Config,
    pool: engine_mod.EntropyPool = .{},
    output: [constants.datagram_size_max]u8 = undefined,

    pub fn init(engine: *engine_mod.Engine, udp: *udp_mod.Udp) Driver {
        return .{ .engine = engine, .udp = udp, .config = .{} };
    }

    pub fn initWithConfig(
        engine: *engine_mod.Engine,
        udp: *udp_mod.Udp,
        config: Config,
    ) StepError!Driver {
        if (config.poll_interval_ms == 0) return error.InvalidPollInterval;
        return .{ .engine = engine, .udp = udp, .config = config };
    }

    pub fn dial(
        self: *Driver,
        io: std.Io,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        const now = try currentTime(io);
        const local = self.udp.localAddress();
        const handle = try self.engine.dial(&local, &peer, expected, now, try entropy(io));
        assert(handle.index < self.engine.driverView().slotCount());
        if (self.drain(io, handle.index, now).failure) |err| {
            _ = self.engine.abandon(handle);
            return err;
        }
        return handle;
    }

    pub fn step(self: *Driver, io: std.Io, events: []engine_mod.Event) StepError!StepResult {
        var result = StepResult{ .now = try currentTime(io) };
        var batch: u32 = 0;
        while (batch < constants.receive_batch_max) : (batch += 1) {
            if (!self.pool.fresh) self.pool.fill(try entropy(io));
            const received = try self.receiveDatagram(io, &result, batch == 0);
            const admitted = switch (received) {
                .timeout => break,
                .dropped => continue,
                .datagram => |datagram| datagram,
            };
            result.datagrams_received += 1;
            defer self.udp.release(admitted.handle) catch unreachable;
            const local = self.udp.localAddress();
            switch (self.engine.driverView().receive(
                admitted.bytes,
                &admitted.from,
                &local,
                result.now,
                &self.pool,
                &self.output,
            )) {
                .accepted => result.datagrams_accepted += 1,
                .version_negotiation => |bytes| {
                    self.send(io, &admitted.from, bytes) catch {};
                    result.version_negotiations += 1;
                },
                .dropped => result.datagrams_dropped += 1,
            }
        }
        result.now = try currentTime(io);
        const view = self.engine.driverView();
        view.tick(result.now);
        for (view.activeIndices()) |index| {
            const drained = self.drain(io, index, result.now);
            result.datagrams_sent += drained.sent;
            if (drained.failure) |err| {
                result.send_failures += 1;
                if (result.first_failure == null) {
                    result.first_failure = .{ .conn = view.handleAt(index).?, .err = err };
                }
            }
        }
        result.events = self.engine.pollEvents(events);
        result.events_pending = self.engine.eventsPending();
        assert(result.events <= events.len);
        return result;
    }

    fn receiveDatagram(
        self: *Driver,
        io: std.Io,
        result: *StepResult,
        wait: bool,
    ) StepError!Received {
        const view = self.engine.driverView();
        const timeout: std.Io.Timeout = if (wait) blk: {
            var wait_ms: u64 = self.config.poll_interval_ms;
            if (view.nextTimeoutMs()) |earliest| wait_ms = @min(wait_ms, earliest);
            break :blk .{ .duration = .{
                .raw = .fromMilliseconds(@intCast(@max(wait_ms, 1))),
                .clock = .awake,
            } };
        } else .{ .duration = .{ .raw = .zero, .clock = .awake } };
        const datagram = self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
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

    fn drain(self: *Driver, io: std.Io, index: u16, now: engine_mod.Now) Drained {
        const view = self.engine.driverView();
        const peer = view.peerAddressAt(index) orelse return .{};
        var result = Drained{};
        while (result.sent < limits.send_burst_max) {
            const datagram = view.send(index, now, &self.output) orelse break;
            self.send(io, &peer, datagram) catch |err| {
                result.failure = err;
                return result;
            };
            result.sent += 1;
        }
        assert(result.sent <= limits.send_burst_max);
        return result;
    }

    fn send(
        self: *const Driver,
        io: std.Io,
        destination: *const types.Address,
        bytes: []const u8,
    ) StepError!void {
        return self.udp.send(io, destination, bytes) catch |err| switch (err) {
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
};

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
    assert(@sizeOf(Driver) <= 4 * 1_024);
}
