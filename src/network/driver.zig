const std = @import("std");
const constants = @import("constants.zig");
const engine_mod = @import("quic/engine.zig");
const peer_id = @import("identity/peer_id.zig");
const runtime = @import("runtime.zig");
const types = @import("types.zig");

pub const Error = engine_mod.Error || runtime.ReceiveTimeoutError || runtime.ReleaseError ||
    runtime.SendError || std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
    InvalidPollInterval,
};

pub const Config = struct {
    poll_interval_ms: u32 = constants.poll_interval_ms,
};

pub const DatagramResult = enum { timeout, accepted, version_negotiation, dropped };

pub const StepResult = struct {
    now: engine_mod.Now,
    datagram: DatagramResult = .timeout,
    datagrams_received: u32 = 0,
    datagrams_sent: u32 = 0,
    receive_errors: u32 = 0,
    send_failures: u32 = 0,
    first_failure: ?struct { conn: engine_mod.Handle, err: Error } = null,
    events: usize = 0,
    events_pending: bool = false,
};

pub const Drained = struct {
    sent: u32 = 0,
    failure: ?Error = null,
};

pub const Driver = struct {
    engine: *engine_mod.Engine,
    udp: *runtime.Udp,
    config: Config,
    pool: engine_mod.EntropyPool = .{},
    output: [constants.datagram_size_max]u8 = undefined,

    pub fn init(engine: *engine_mod.Engine, udp: *runtime.Udp) Driver {
        return .{ .engine = engine, .udp = udp, .config = .{} };
    }

    pub fn initWithConfig(engine: *engine_mod.Engine, udp: *runtime.Udp, config: Config) Error!Driver {
        if (config.poll_interval_ms == 0) return error.InvalidPollInterval;
        return .{ .engine = engine, .udp = udp, .config = config };
    }

    pub fn dial(self: *Driver, io: std.Io, peer: types.Address, expected: peer_id.PeerId) Error!engine_mod.Handle {
        const now = try currentTime(io);
        const handle = try self.engine.dial(self.udp.localAddress(), peer, expected, now, try entropy(io));
        if (self.drain(io, handle.index, now).failure) |err| {
            _ = self.engine.abandon(handle);
            return err;
        }
        return handle;
    }

    pub fn step(self: *Driver, io: std.Io, events: []engine_mod.Event) Error!StepResult {
        var result = StepResult{ .now = try currentTime(io) };
        var batch: u32 = 0;
        while (batch < constants.receive_batch_max) : (batch += 1) {
            if (!self.pool.fresh) self.pool.fill(try entropy(io));
            const admitted = (try self.receiveDatagram(io, &result, batch == 0)) orelse break;
            result.datagrams_received += 1;
            defer self.udp.release(admitted.handle) catch unreachable;
            const outcome = self.engine.receive(
                admitted.bytes,
                admitted.from,
                self.udp.localAddress(),
                result.now,
                &self.pool,
                &self.output,
            );
            result.datagram = switch (outcome) {
                .accepted => .accepted,
                .version_negotiation => |bytes| blk: {
                    self.send(io, admitted.from, bytes) catch {};
                    break :blk .version_negotiation;
                },
                .dropped => .dropped,
            };
        }
        result.now = try currentTime(io);
        self.engine.tick(result.now);
        var indices: [constants.connections_max_ceiling]u16 = undefined;
        const active = self.engine.activeIndices(&indices);
        for (indices[0..active]) |index| {
            const drained = self.drain(io, index, result.now);
            result.datagrams_sent += drained.sent;
            if (drained.failure) |err| {
                result.send_failures += 1;
                if (result.first_failure == null) {
                    result.first_failure = .{ .conn = self.engine.handle(index).?, .err = err };
                }
            }
        }
        result.events = self.engine.pollEvents(events);
        result.events_pending = self.engine.eventsPending();
        return result;
    }

    fn receiveDatagram(self: *Driver, io: std.Io, result: *StepResult, wait: bool) Error!?runtime.Datagram {
        const timeout: std.Io.Timeout = if (wait) blk: {
            var wait_ms: u64 = self.config.poll_interval_ms;
            if (self.engine.nextTimeoutMs()) |earliest| wait_ms = @min(wait_ms, earliest);
            break :blk .{ .duration = .{
                .raw = .fromMilliseconds(@intCast(@max(wait_ms, 1))),
                .clock = .awake,
            } };
        } else .{ .duration = .{ .raw = .zero, .clock = .awake } };
        return self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => null,
            error.DatagramTooLarge,
            error.PortUnreachable,
            error.ConnectionResetByPeer,
            error.NetworkDown,
            error.SystemResources,
            => blk: {
                result.receive_errors += 1;
                break :blk null;
            },
            else => err,
        };
    }

    fn drain(self: *Driver, io: std.Io, index: u16, now: engine_mod.Now) Drained {
        const peer = self.engine.peerAddress(index) orelse return .{};
        var result = Drained{};
        while (result.sent < constants.send_burst_max) {
            const datagram = self.engine.send(index, now, &self.output) catch |err| {
                result.failure = err;
                return result;
            } orelse break;
            self.send(io, peer, datagram) catch |err| {
                result.failure = err;
                return result;
            };
            result.sent += 1;
        }
        return result;
    }

    fn send(self: *const Driver, io: std.Io, destination: types.Address, bytes: []const u8) Error!void {
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

pub fn currentTime(io: std.Io) Error!engine_mod.Now {
    const mono = std.Io.Clock.awake.now(io).toMilliseconds();
    const wall = std.Io.Clock.real.now(io).toSeconds();
    if (mono < 0 or wall < 0) return error.ClockOutOfRange;
    return .{ .mono_ms = @intCast(mono), .unix_s = wall };
}

fn entropy(io: std.Io) std.Io.RandomSecureError![constants.local_cid_length]u8 {
    var bytes: [constants.local_cid_length]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    return bytes;
}

comptime {
    std.debug.assert(@sizeOf(Driver) <= 4 * 1_024);
}
