const std = @import("std");
const calls = @import("calls.zig");
const engine = @import("engine.zig");
const protocol = @import("protocol.zig");
const runtime = @import("runtime.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = engine.Error || runtime.ReceiveTimeoutError || runtime.ReleaseError ||
    runtime.SendError || std.Io.RandomSecureError || error{
    ClockOutOfRange,
    InvalidPollInterval,
    MissingExpiryStorage,
};

pub const Config = struct {
    poll_interval_ms: u32 = 100,
};

pub const StepResult = struct {
    event: engine.Event = .none,
    calls_expired: usize = 0,
    maintenance_expired: usize = 0,
    challenges_expired: usize = 0,
    sessions_expired: usize = 0,
    standard_responses: u8 = 0,
    maintenance_started: bool = false,
};

pub const Driver = struct {
    const Self = @This();

    core: *engine.Engine,
    udp: *runtime.Udp,
    config: Config,
    scratch: engine.Scratch = .{},
    response: engine.StandardResponse = undefined,
    output: [constants.packet_size_max]u8 = undefined,

    pub fn init(core: *engine.Engine, udp: *runtime.Udp) Self {
        return .{ .core = core, .udp = udp, .config = .{} };
    }

    pub fn initWithConfig(
        core: *engine.Engine,
        udp: *runtime.Udp,
        config: Config,
    ) Error!Self {
        if (config.poll_interval_ms == 0) return error.InvalidPollInterval;
        return .{ .core = core, .udp = udp, .config = config };
    }

    /// The returned event borrows driver scratch and remains valid until the next step.
    pub fn step(
        self: *Self,
        io: std.Io,
        expired_calls: []calls.Expired,
    ) Error!StepResult {
        if (expired_calls.len == 0) return error.MissingExpiryStorage;
        var result = StepResult{};

        var now_ms = try monotonicMilliseconds(io);
        self.tick(now_ms, expired_calls, &result);
        result.maintenance_started = try self.startMaintenance(io, now_ms);

        const timeout = std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(self.config.poll_interval_ms),
            .clock = .awake,
        } };
        const datagram = self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => {
                now_ms = try monotonicMilliseconds(io);
                self.tick(now_ms, expired_calls, &result);
                if (!result.maintenance_started) {
                    result.maintenance_started = try self.startMaintenance(io, now_ms);
                }
                return result;
            },
            else => return err,
        };
        defer self.udp.release(datagram.handle) catch unreachable;

        now_ms = try monotonicMilliseconds(io);
        self.tick(now_ms, expired_calls, &result);
        var entropy = try receiveEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const outcome = try self.core.receive(
            &self.output,
            datagram.bytes,
            datagram.from,
            .{ .now_ms = now_ms, .known_record = null, .entropy = entropy },
            &self.scratch,
        );
        if (outcome.packet_length > 0) {
            try self.udp.send(io, datagram.from, self.output[0..outcome.packet_length]);
        }
        result.event = try self.handleEvent(io, outcome.event, now_ms, &result);
        if (!result.maintenance_started) {
            result.maintenance_started = try self.startMaintenance(io, now_ms);
        }
        return result;
    }

    fn tick(
        self: *Self,
        now_ms: u64,
        expired_calls: []calls.Expired,
        result: *StepResult,
    ) void {
        const available = expired_calls[result.calls_expired..];
        const expired = self.core.tick(now_ms, available);
        result.calls_expired += expired.calls;
        result.maintenance_expired += expired.maintenance_calls;
        result.challenges_expired += expired.challenges;
        result.sessions_expired += expired.sessions;
    }

    fn handleEvent(
        self: *Self,
        io: std.Io,
        event: engine.Event,
        now_ms: u64,
        result: *StepResult,
    ) Error!engine.Event {
        const request = switch (event) {
            .request => |request| request,
            else => return event,
        };
        switch (request.message) {
            .talk_request => return event,
            .ping, .find_node => {},
            else => unreachable,
        }
        try self.core.prepareStandardResponse(&request, &self.response);
        while (result.standard_responses < protocol.findnode_response_packets_max) {
            var entropy = try startEntropy(io);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
            const packet_length = try self.core.sendNextStandardResponse(
                &self.output,
                &self.response,
                now_ms,
                entropy,
            ) orelse break;
            try self.udp.send(io, request.peer.address, self.output[0..packet_length]);
            result.standard_responses += 1;
        }
        std.debug.assert(self.response.complete());
        return .none;
    }

    fn startMaintenance(self: *Self, io: std.Io, now_ms: u64) Error!bool {
        if (!self.core.hasPendingRevalidation()) return false;
        var request_id_bytes: [8]u8 = undefined;
        try std.Io.randomSecure(io, &request_id_bytes);
        const request_id = message.RequestId.init(&request_id_bytes) catch unreachable;
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const started = self.core.startRevalidation(
            &self.output,
            request_id,
            now_ms,
            entropy,
        ) catch |err| switch (err) {
            calls.Error.PeerBusy, calls.Error.TableFull => return false,
            else => return err,
        } orelse return false;
        self.udp.send(
            io,
            started.peer.address,
            self.output[0..started.call.packet_length],
        ) catch |err| {
            const cancelled = self.core.cancelCall(started.call.handle);
            std.debug.assert(cancelled);
            return err;
        };
        return true;
    }
};

fn monotonicMilliseconds(io: std.Io) Error!u64 {
    const value = std.Io.Clock.awake.now(io).toMilliseconds();
    if (value < 0) return error.ClockOutOfRange;
    return @intCast(value);
}

fn startEntropy(io: std.Io) std.Io.RandomSecureError!engine.StartEntropy {
    var entropy: engine.StartEntropy = undefined;
    try std.Io.randomSecure(io, std.mem.asBytes(&entropy));
    return entropy;
}

fn receiveEntropy(io: std.Io) std.Io.RandomSecureError!engine.ReceiveEntropy {
    var entropy: engine.ReceiveEntropy = undefined;
    try std.Io.randomSecure(io, std.mem.asBytes(&entropy));
    return entropy;
}

comptime {
    std.debug.assert(@sizeOf(Driver) <= 32 * 1_024);
}
