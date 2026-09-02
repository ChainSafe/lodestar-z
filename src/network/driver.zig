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
    datagrams_sent: u32 = 0,
    receive_errors: u32 = 0,
    send_failures: u32 = 0,
    events: usize = 0,
};

pub const Drained = struct {
    sent: u32 = 0,
    failure: ?Error = null,
};

pub const Driver = struct {
    engine: *engine_mod.Engine,
    udp: *runtime.Udp,
    config: Config,
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
            self.engine.close(handle, 0);
            return err;
        }
        return handle;
    }

    pub fn step(self: *Driver, io: std.Io, events: []engine_mod.Event) Error!StepResult {
        var result = StepResult{ .now = try currentTime(io) };
        if (try self.receiveDatagram(io, &result)) |admitted| {
            defer self.udp.release(admitted.handle) catch unreachable;
            const outcome = self.engine.receive(
                admitted.bytes,
                admitted.from,
                self.udp.localAddress(),
                result.now,
                try entropy(io),
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
        var index: u16 = 0;
        while (index < self.engine.slotCount()) : (index += 1) {
            const drained = self.drain(io, index, result.now);
            result.datagrams_sent += drained.sent;
            if (drained.failure != null) result.send_failures += 1;
        }
        result.events = self.engine.pollEvents(events);
        return result;
    }

    fn receiveDatagram(self: *Driver, io: std.Io, result: *StepResult) Error!?runtime.Datagram {
        var wait_ms: u64 = self.config.poll_interval_ms;
        if (self.engine.nextTimeoutMs()) |timeout| wait_ms = @min(wait_ms, timeout);
        const timeout = std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(@intCast(@max(wait_ms, 1))),
            .clock = .awake,
        } };
        return self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => null,
            error.DatagramTooLarge,
            error.PortUnreachable,
            error.ConnectionResetByPeer,
            error.NetworkDown,
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
