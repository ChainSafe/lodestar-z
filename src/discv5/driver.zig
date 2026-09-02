const std = @import("std");
const calls = @import("calls.zig");
const engine = @import("engine.zig");
const enr = @import("identity/enr.zig");
const lookup_mod = @import("lookup.zig");
const protocol = @import("protocol.zig");
const runtime = @import("runtime.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = engine.Error || runtime.ReceiveTimeoutError || runtime.ReleaseError ||
    runtime.SendError || std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
    InvalidPollInterval,
    MissingExpiryStorage,
};

pub const LookupError = Error || lookup_mod.Error;

pub const Config = struct {
    poll_interval_ms: u32 = 100,
};

pub const DatagramResult = union(enum) {
    timeout,
    accepted,
    rejected: types.RejectReason,
};

pub const StepResult = struct {
    now_ms: u64 = 0,
    event: engine.Event = .none,
    datagram: DatagramResult = .timeout,
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

    pub fn startCall(
        self: *Self,
        io: std.Io,
        peer: types.Endpoint,
        record: *const enr.Record,
        request: *const message.Message,
    ) Error!calls.Handle {
        const now_ms = try monotonicMilliseconds(io);
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const started = try self.core.startCall(
            &self.output,
            peer,
            record,
            request,
            now_ms,
            entropy,
        );
        self.send(io, peer.address, self.output[0..started.packet_length]) catch |err| {
            const cancelled = self.core.cancelCall(started.handle);
            std.debug.assert(cancelled);
            return err;
        };
        return started.handle;
    }

    pub fn sendResponse(
        self: *Self,
        io: std.Io,
        peer: types.Endpoint,
        response: *const message.Message,
    ) Error!void {
        const now_ms = try monotonicMilliseconds(io);
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const packet_length = try self.core.sendResponse(
            &self.output,
            peer,
            response,
            now_ms,
            entropy,
        );
        try self.send(io, peer.address, self.output[0..packet_length]);
    }

    pub fn startLookupCall(
        self: *Self,
        io: std.Io,
        operation: *lookup_mod.Lookup,
    ) LookupError!bool {
        const now_ms = try monotonicMilliseconds(io);
        const request_id = try randomRequestId(io);
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const started = try operation.startNext(
            self.core,
            &self.output,
            request_id,
            now_ms,
            entropy,
        ) orelse return false;
        self.send(
            io,
            started.peer.address,
            self.output[0..started.call.packet_length],
        ) catch |err| {
            operation.onFailure(self.core, started.call.handle) catch unreachable;
            return err;
        };
        return true;
    }

    /// The returned event borrows driver scratch and remains valid until the next step.
    pub fn step(
        self: *Self,
        io: std.Io,
        expired_calls: []calls.Expired,
    ) Error!StepResult {
        if (expired_calls.len == 0) return error.MissingExpiryStorage;
        var result = StepResult{};
        try self.advance(io, expired_calls, &result);
        try self.maintain(io, &result);

        const datagram = try self.receiveDatagram(io);
        defer if (datagram) |admitted| self.udp.release(admitted.handle) catch unreachable;
        try self.advance(io, expired_calls, &result);
        if (datagram) |admitted| try self.processDatagram(io, admitted, &result);
        try self.maintain(io, &result);
        return result;
    }

    fn advance(
        self: *Self,
        io: std.Io,
        expired_calls: []calls.Expired,
        result: *StepResult,
    ) Error!void {
        result.now_ms = try monotonicMilliseconds(io);
        const available = expired_calls[result.calls_expired..];
        const expired = self.core.tick(result.now_ms, available);
        result.calls_expired += expired.calls;
        result.maintenance_expired += expired.maintenance_calls;
        result.challenges_expired += expired.challenges;
        result.sessions_expired += expired.sessions;
    }

    fn maintain(self: *Self, io: std.Io, result: *StepResult) Error!void {
        if (result.maintenance_started) return;
        result.maintenance_started = try self.startMaintenance(io, result.now_ms);
    }

    fn receiveDatagram(self: *Self, io: std.Io) Error!?runtime.Datagram {
        const timeout = std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(self.config.poll_interval_ms),
            .clock = .awake,
        } };
        return self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => null,
            else => err,
        };
    }

    fn processDatagram(
        self: *Self,
        io: std.Io,
        datagram: runtime.Datagram,
        result: *StepResult,
    ) Error!void {
        var entropy = try receiveEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const accepted = switch (try self.core.receive(
            &self.output,
            datagram.bytes,
            datagram.from,
            .{ .now_ms = result.now_ms, .entropy = entropy },
            &self.scratch,
        )) {
            .accepted => |accepted| accepted,
            .rejected => |reason| {
                result.datagram = .{ .rejected = reason };
                return;
            },
        };
        result.datagram = .accepted;
        if (accepted.packet_length > 0) {
            try self.send(io, datagram.from, self.output[0..accepted.packet_length]);
        }
        result.event = try self.handleEvent(io, accepted.event, result);
    }

    fn handleEvent(
        self: *Self,
        io: std.Io,
        event: engine.Event,
        result: *StepResult,
    ) Error!engine.Event {
        const request = switch (event) {
            .request => |request| request,
            else => return event,
        };
        switch (request.message) {
            .talk_request => return event,
            .ping, .find_node => {},
        }
        try self.core.prepareStandardResponse(&request, &self.response);
        while (result.standard_responses < protocol.findnode_response_packets_max) {
            var entropy = try startEntropy(io);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
            const packet_length = try self.core.sendNextStandardResponse(
                &self.output,
                &self.response,
                result.now_ms,
                entropy,
            ) orelse break;
            try self.send(io, request.peer.address, self.output[0..packet_length]);
            result.standard_responses += 1;
        }
        std.debug.assert(self.response.complete());
        return .none;
    }

    fn startMaintenance(self: *Self, io: std.Io, now_ms: u64) Error!bool {
        if (!self.core.hasPendingRevalidation()) return false;
        const request_id = try randomRequestId(io);
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
        self.send(
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

    fn send(
        self: *const Self,
        io: std.Io,
        destination: types.Address,
        bytes: []const u8,
    ) Error!void {
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

pub fn monotonicMilliseconds(io: std.Io) Error!u64 {
    const value = std.Io.Clock.awake.now(io).toMilliseconds();
    if (value < 0) return error.ClockOutOfRange;
    return @intCast(value);
}

fn randomRequestId(io: std.Io) std.Io.RandomSecureError!message.RequestId {
    var bytes: [8]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    return message.RequestId.init(&bytes) catch unreachable;
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
