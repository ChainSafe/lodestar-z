const std = @import("std");
const CallTable = @import("CallTable.zig");
const Engine = @import("Engine.zig");
const ResponsePlan = @import("ResponsePlan.zig");
const enr = @import("identity/enr.zig");
const Udp = @import("Udp.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = Engine.Error || Udp.ReceiveTimeoutError || Udp.ReleaseError ||
    Udp.SendError || std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
    InvalidPollInterval,
    MissingExpiryStorage,
};

pub const Config = struct {
    poll_interval_ms: u32 = 100,
};

pub const DatagramResult = union(enum) {
    timeout,
    accepted,
    rejected: types.RejectReason,
};

pub const Progress = struct {
    maintenance_expired: usize = 0,
    challenges_expired: usize = 0,
    sessions_expired: usize = 0,
    standard_responses: u8 = 0,
    maintenance_started: bool = false,
};

pub const StepResult = struct {
    now_ms: u64 = 0,
    event: Engine.Event = .none,
    datagram: DatagramResult = .timeout,
    calls_expired: usize = 0,
    progress: Progress = .{},
};

/// Clock reading and fresh entropy for one outbound packet.
pub const SendContext = struct {
    now_ms: u64,
    entropy: Engine.StartEntropy,
};

const Driver = @This();

core: *Engine,
udp: *Udp,
config: Config,
scratch: Engine.Scratch = .{},
response: ResponsePlan = .{},
output: [constants.packet_size_max]u8 = undefined,

pub fn init(core: *Engine, adapter: *Udp) Driver {
    return .{ .core = core, .udp = adapter, .config = .{} };
}

pub fn initWithConfig(
    core: *Engine,
    adapter: *Udp,
    config: Config,
) Error!Driver {
    if (config.poll_interval_ms == 0) return error.InvalidPollInterval;
    return .{ .core = core, .udp = adapter, .config = config };
}

pub fn startCall(
    self: *Driver,
    io: std.Io,
    peer: types.Endpoint,
    record: *const enr.Record,
    request: *const message.Message,
) Error!CallTable.Handle {
    var context = try sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    const started = try self.core.startCall(
        &self.output,
        peer,
        record,
        request,
        context.now_ms,
        &context.entropy,
    );
    self.transmit(io, peer.address, self.output[0..started.packet_length]) catch |err| {
        const cancelled = self.core.cancelCall(started.handle);
        std.debug.assert(cancelled);
        return err;
    };
    return started.handle;
}

pub fn sendResponse(
    self: *Driver,
    io: std.Io,
    peer: types.Endpoint,
    response: *const message.Message,
) Error!void {
    var context = try sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    const packet_length = try self.core.sendResponse(
        &self.output,
        peer,
        response,
        context.now_ms,
        &context.entropy,
    );
    try self.transmit(io, peer.address, self.output[0..packet_length]);
}

/// Failures tied to the destination collapse into `DestinationUnreachable`.
pub fn transmit(
    self: *const Driver,
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

/// The returned event borrows driver scratch and remains valid until the next step.
pub fn step(
    self: *Driver,
    io: std.Io,
    expired_calls: []CallTable.Expired,
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
    self: *Driver,
    io: std.Io,
    expired_calls: []CallTable.Expired,
    result: *StepResult,
) Error!void {
    result.now_ms = try monotonicMilliseconds(io);
    const available = expired_calls[result.calls_expired..];
    const expired = self.core.tick(result.now_ms, available);
    result.calls_expired += expired.calls;
    result.progress.maintenance_expired += expired.maintenance_calls;
    result.progress.challenges_expired += expired.challenges;
    result.progress.sessions_expired += expired.sessions;
}

fn maintain(self: *Driver, io: std.Io, result: *StepResult) Error!void {
    if (result.progress.maintenance_started) return;
    result.progress.maintenance_started = try self.startMaintenance(io, result.now_ms);
}

fn receiveDatagram(self: *Driver, io: std.Io) Error!?Udp.Datagram {
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
    self: *Driver,
    io: std.Io,
    datagram: Udp.Datagram,
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
        try self.transmit(io, datagram.from, self.output[0..accepted.packet_length]);
    }
    result.event = try self.handleEvent(io, accepted.event, result);
}

fn handleEvent(
    self: *Driver,
    io: std.Io,
    event: Engine.Event,
    result: *StepResult,
) Error!Engine.Event {
    const request = switch (event) {
        .request => |request| request,
        else => return event,
    };
    switch (request.message) {
        .talk_request => return event,
        .ping, .find_node => {},
    }
    try self.core.prepareStandardResponse(&request, &self.response);
    while (result.progress.standard_responses < types.findnode_response_packets_max) {
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const packet_length = try self.core.sendNextStandardResponse(
            &self.output,
            &self.response,
            result.now_ms,
            &entropy,
        ) orelse break;
        try self.transmit(io, request.peer.address, self.output[0..packet_length]);
        result.progress.standard_responses += 1;
    }
    std.debug.assert(self.response.complete());
    return .none;
}

fn startMaintenance(self: *Driver, io: std.Io, now_ms: u64) Error!bool {
    if (!self.core.hasPendingRevalidation()) return false;
    const request_id = try requestId(io);
    var entropy = try startEntropy(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
    const started = self.core.startRevalidation(
        &self.output,
        request_id,
        now_ms,
        &entropy,
    ) catch |err| switch (err) {
        CallTable.Error.PeerBusy, CallTable.Error.TableFull => return false,
        else => return err,
    } orelse return false;
    self.transmit(
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

pub fn monotonicMilliseconds(io: std.Io) Error!u64 {
    const value = std.Io.Clock.awake.now(io).toMilliseconds();
    if (value < 0) return error.ClockOutOfRange;
    return @intCast(value);
}

pub fn sendContext(io: std.Io) Error!SendContext {
    return .{ .now_ms = try monotonicMilliseconds(io), .entropy = try startEntropy(io) };
}

pub fn requestId(io: std.Io) std.Io.RandomSecureError!message.RequestId {
    var bytes: [8]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    return message.RequestId.init(&bytes) catch unreachable;
}

fn startEntropy(io: std.Io) std.Io.RandomSecureError!Engine.StartEntropy {
    var entropy: Engine.StartEntropy = undefined;
    try std.Io.randomSecure(io, std.mem.asBytes(&entropy));
    return entropy;
}

fn receiveEntropy(io: std.Io) std.Io.RandomSecureError!Engine.ReceiveEntropy {
    var entropy: Engine.ReceiveEntropy = undefined;
    try std.Io.randomSecure(io, std.mem.asBytes(&entropy));
    return entropy;
}

comptime {
    std.debug.assert(@sizeOf(Driver) <= 32 * 1_024);
}
