//! The Transport is the synchronous host loop. Each step handles at most one datagram, sends
//! without a queue, and does expiry work on every poll, so progress never depends on inbound
//! traffic.

const std = @import("std");
const CallTable = @import("CallTable.zig");
const Engine = @import("Engine.zig");
const ResponsePlan = @import("ResponsePlan.zig");
const enr = @import("identity/enr.zig");
const sockets_mod = @import("udp");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = Engine.Error || sockets_mod.DatagramError ||
    sockets_mod.SendError || std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
    InvalidPollInterval,
    MissingExpiryStorage,
};

pub const Config = struct {
    poll_interval_ms: u32 = 100,
};
pub const FailureStage = enum { coordinator, clock, receive, process };

pub const DatagramResult = union(enum) {
    timeout,
    accepted,
    rejected: types.RejectReason,
};

/// These counters exist for observability. Nothing in `step` depends on them.
pub const Progress = struct {
    challenges_expired: usize = 0,
    sessions_expired: usize = 0,
    standard_responses: u8 = 0,
};

pub const StepResult = struct {
    now_ms: u64 = 0,
    event: Engine.Event = .none,
    datagram: DatagramResult = .timeout,
    calls_expired: usize = 0,
    progress: Progress = .{},
    failure: ?Error = null,
    failure_stage: FailureStage = .coordinator,
};

/// A clock reading and fresh entropy for one outbound packet.
pub const SendContext = struct {
    now_ms: u64,
    entropy: Engine.StartEntropy,
};

const Transport = @This();

engine: Engine,
sockets: sockets_mod.Sockets,
config: Config,
scratch: Engine.Scratch = .{},
response: ResponsePlan = .{},
output: [constants.packet_size_max]u8 = undefined,
receive_buffer: [constants.packet_size_max]u8 = undefined,

pub const Options = struct {
    engine: Engine.Config = .{},
    poll_interval_ms: u32 = 100,
};

/// Takes ownership of bound sockets on success. Initialize at the final address.
pub fn init(self: *Transport, allocator: std.mem.Allocator, sockets: sockets_mod.Sockets, key: @import("identity/crypto.zig").KeyPair, record: enr.Record, options: Options) !void {
    if (options.poll_interval_ms == 0) return error.InvalidPollInterval;
    self.* = .{ .engine = undefined, .sockets = sockets, .config = .{ .poll_interval_ms = options.poll_interval_ms } };
    try self.engine.initWithConfig(allocator, key, record, options.engine);
}

pub fn deinit(self: *Transport, allocator: std.mem.Allocator, io: std.Io) void {
    self.engine.deinit(allocator);
    self.sockets.close(io);
    self.* = undefined;
}

pub fn localAddress(self: *const Transport) types.Address {
    return types.Address.fromNetwork(self.sockets.primary().address);
}

/// Encodes and sends one request immediately. A failed send cancels the call, so no unsent
/// request lingers.
pub fn startCall(
    self: *Transport,
    io: std.Io,
    peer: types.Endpoint,
    record: *const enr.Record,
    request: *const message.Message,
) Error!CallTable.Handle {
    var context = try sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    const started = try self.engine.startCall(
        &self.output,
        peer,
        record,
        request,
        context.now_ms,
        &context.entropy,
    );
    self.transmit(io, peer.address, self.output[0..started.packet_length]) catch |err| {
        const cancelled = self.engine.cancelCall(started.handle);
        std.debug.assert(cancelled);
        return err;
    };
    return started.handle;
}

pub fn sendResponse(
    self: *Transport,
    io: std.Io,
    peer: types.Endpoint,
    response: *const message.Message,
) Error!void {
    var context = try sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    const packet_length = try self.engine.sendResponse(
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
    self: *const Transport,
    io: std.Io,
    destination: types.Address,
    bytes: []const u8,
) Error!void {
    return self.sockets.sendTo(io, destination, bytes, constants.packet_size_max) catch |err| {
        std.log.scoped(.network_discovery).debug("discovery_send_failed endpoint={any} bytes={d} reason={s}", .{ destination, bytes.len, @errorName(err) });
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
    };
}

/// Runs one poll. It expires state, waits up to the poll interval
/// for one datagram, processes it, and drains any standard response. The returned event
/// borrows transport scratch and stays valid until the next step.
pub fn step(
    self: *Transport,
    io: std.Io,
    expired_calls: []CallTable.Expired,
) Error!StepResult {
    return self.stepUntil(io, expired_calls, std.math.maxInt(u64));
}

/// Preserves events and expiries alongside local faults. The host must consume progress before
/// handling `failure`. `wake_ms` can shorten the wait for host-owned maintenance or shutdown.
pub fn stepUntil(
    self: *Transport,
    io: std.Io,
    expired_calls: []CallTable.Expired,
    wake_ms: u64,
) Error!StepResult {
    if (expired_calls.len == 0) return error.MissingExpiryStorage;
    var result = StepResult{};
    self.runStep(io, expired_calls, wake_ms, &result) catch |err| {
        recordFailure(&result, err, .clock);
    };
    return result;
}

fn runStep(
    self: *Transport,
    io: std.Io,
    expired_calls: []CallTable.Expired,
    wake_ms: u64,
    result: *StepResult,
) Error!void {
    try self.advance(io, expired_calls, result);

    const datagram = self.receiveDatagram(io, wake_ms, result) catch |err| {
        recordFailure(result, err, .receive);
        return;
    };
    try self.advance(io, expired_calls, result);
    if (datagram) |admitted| self.processDatagram(io, admitted, result) catch |err| {
        recordFailure(result, err, .process);
    };
}

fn advance(
    self: *Transport,
    io: std.Io,
    expired_calls: []CallTable.Expired,
    result: *StepResult,
) Error!void {
    result.now_ms = try monotonicMilliseconds(io);
    const available = expired_calls[result.calls_expired..];
    const expired = self.engine.tick(result.now_ms, available);
    result.calls_expired += expired.calls;
    result.progress.challenges_expired += expired.challenges;
    result.progress.sessions_expired += expired.sessions;
}

fn recordFailure(result: *StepResult, err: Error, stage: FailureStage) void {
    if (result.failure != null) return;
    result.failure = err;
    result.failure_stage = stage;
}

fn receiveDatagram(self: *Transport, io: std.Io, wake_ms: u64, result: *StepResult) Error!?sockets_mod.Datagram {
    const deadline_ms = @min(wake_ms, self.engine.nextDeadlineMs() orelse wake_ms);
    const wait_ms = @min(self.config.poll_interval_ms, deadline_ms -| result.now_ms);
    const timeout = std.Io.Timeout{ .duration = .{
        .raw = .fromMilliseconds(wait_ms),
        .clock = .awake,
    } };
    return self.sockets.receiveDatagram(io, &self.receive_buffer, timeout) catch |err| switch (err) {
        error.Timeout => null,
        error.DatagramTooLarge => blk: {
            result.datagram = .{ .rejected = .oversized_datagram };
            break :blk null;
        },
        else => err,
    };
}

fn processDatagram(
    self: *Transport,
    io: std.Io,
    datagram: sockets_mod.Datagram,
    result: *StepResult,
) Error!void {
    if (!self.engine.admitDatagram(&datagram.from, result.now_ms)) {
        result.datagram = .{ .rejected = .admission_limited };
        return;
    }
    var entropy = try receiveEntropy(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
    const accepted = switch (try self.engine.receiveAdmitted(
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
    result.event = accepted.event;
    const packet = self.output[0..accepted.packet_length];
    if (accepted.call) |handle| {
        std.debug.assert(packet.len > 0 and accepted.event == .none);
        // An unsent handshake fails its call now, so the owner records a local failure rather
        // than a remote timeout later. A local fault still fails the step.
        const sent = self.reply(io, datagram.from, packet) catch |err| {
            result.event = self.engine.failCall(handle, error.HandshakeUnsent);
            return err;
        };
        if (!sent) result.event = self.engine.failCall(handle, error.HandshakeUnsent);
        return;
    }
    if (packet.len > 0) _ = try self.reply(io, datagram.from, packet);
    result.event = try self.handleEvent(io, accepted.event, result);
}

fn handleEvent(
    self: *Transport,
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
    try self.engine.prepareStandardResponse(&request, &self.response);
    while (result.progress.standard_responses < types.findnode_response_packets_max) {
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const packet_length = try self.engine.sendNextStandardResponse(
            &self.output,
            &self.response,
            result.now_ms,
            &entropy,
        ) orelse break;
        // The destination refuses the remaining fragments too.
        if (!try self.reply(io, request.peer.address, self.output[0..packet_length])) return .none;
        result.progress.standard_responses += 1;
    }
    std.debug.assert(self.response.complete());
    return .none;
}

/// Sends a packet this step produced and returns false when its destination refuses it. The
/// refusal fails only that destination: a requester retries a dropped reply.
fn reply(self: *const Transport, io: std.Io, destination: types.Address, bytes: []const u8) Error!bool {
    self.transmit(io, destination, bytes) catch |err| switch (err) {
        error.DestinationUnreachable => return false,
        else => return err,
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
    std.debug.assert(@sizeOf(Transport) <= 32 * 1_024);
}

test {
    _ = @import("transport_test.zig");
}
