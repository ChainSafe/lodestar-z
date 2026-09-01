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

pub const Error = lookup_mod.Error || runtime.ReceiveTimeoutError || runtime.ReleaseError ||
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
    lookup_started: u8 = 0,
    lookup_responses: u8 = 0,
    lookup_failures: u8 = 0,
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
        request: *const message.Message,
    ) Error!calls.Handle {
        return self.startCallWithRecord(io, peer, null, request);
    }

    pub fn startCallKnown(
        self: *Self,
        io: std.Io,
        peer: types.Endpoint,
        record: *const enr.Record,
        request: *const message.Message,
    ) Error!calls.Handle {
        return self.startCallWithRecord(io, peer, record, request);
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
        try self.udp.send(io, peer.address, self.output[0..packet_length]);
    }

    /// The returned event borrows driver scratch and remains valid until the next step.
    pub fn step(
        self: *Self,
        io: std.Io,
        expired_calls: []calls.Expired,
    ) Error!StepResult {
        return self.stepWithLookup(io, expired_calls, null);
    }

    /// Consumes only events and expiries owned by this lookup; all others remain returned.
    /// Pass the same operation to every step while it has waiting calls.
    pub fn stepLookup(
        self: *Self,
        io: std.Io,
        operation: *lookup_mod.Lookup,
        expired_calls: []calls.Expired,
    ) Error!StepResult {
        return self.stepWithLookup(io, expired_calls, operation);
    }

    fn stepWithLookup(
        self: *Self,
        io: std.Io,
        expired_calls: []calls.Expired,
        operation: ?*lookup_mod.Lookup,
    ) Error!StepResult {
        if (expired_calls.len == 0) return error.MissingExpiryStorage;
        var result = StepResult{};

        var now_ms = try monotonicMilliseconds(io);
        try self.tick(now_ms, expired_calls, operation, &result);
        if (operation) |active| {
            try self.startLookupCalls(io, active, now_ms, &result);
            if (active.isFinished()) return result;
        }
        result.maintenance_started = try self.startMaintenance(io, now_ms);

        const timeout = std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(self.config.poll_interval_ms),
            .clock = .awake,
        } };
        const datagram = self.udp.receiveTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => {
                now_ms = try monotonicMilliseconds(io);
                try self.tick(now_ms, expired_calls, operation, &result);
                if (operation) |active| {
                    try self.startLookupCalls(io, active, now_ms, &result);
                }
                if (!result.maintenance_started) {
                    result.maintenance_started = try self.startMaintenance(io, now_ms);
                }
                return result;
            },
            else => return err,
        };
        defer self.udp.release(datagram.handle) catch unreachable;

        now_ms = try monotonicMilliseconds(io);
        try self.tick(now_ms, expired_calls, operation, &result);
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
        const event = try self.handleEvent(io, outcome.event, now_ms, &result);
        result.event = if (operation) |active|
            try self.handleLookupEvent(active, event, now_ms, &result)
        else
            event;
        if (operation) |active| {
            try self.startLookupCalls(io, active, now_ms, &result);
        }
        if (!result.maintenance_started) {
            result.maintenance_started = try self.startMaintenance(io, now_ms);
        }
        return result;
    }

    fn tick(
        self: *Self,
        now_ms: u64,
        expired_calls: []calls.Expired,
        operation: ?*lookup_mod.Lookup,
        result: *StepResult,
    ) Error!void {
        const available = expired_calls[result.calls_expired..];
        const expired = self.core.tick(now_ms, available);
        var retained: usize = 0;
        for (available[0..expired.calls]) |item| {
            if (operation) |active| {
                if (active.ownsCall(item.handle)) {
                    try active.onFailure(self.core, item.handle);
                    result.lookup_failures += 1;
                    continue;
                }
            }
            available[retained] = item;
            retained += 1;
        }
        result.calls_expired += retained;
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

    fn handleLookupEvent(
        self: *Self,
        operation: *lookup_mod.Lookup,
        event: engine.Event,
        now_ms: u64,
        result: *StepResult,
    ) Error!engine.Event {
        const response = switch (event) {
            .response => |response| response,
            else => return event,
        };
        if (!operation.ownsCall(response.matched.handle)) return event;
        try operation.onResponse(self.core, &response, now_ms);
        result.lookup_responses += 1;
        return .none;
    }

    fn startLookupCalls(
        self: *Self,
        io: std.Io,
        operation: *lookup_mod.Lookup,
        now_ms: u64,
        result: *StepResult,
    ) Error!void {
        for (0..lookup_mod.parallelism) |_| {
            if (operation.isFinished() or
                operation.waitingCount() == lookup_mod.parallelism) return;
            const request_id = try randomRequestId(io);
            var entropy = try startEntropy(io);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
            const started = operation.startNext(
                self.core,
                &self.output,
                request_id,
                now_ms,
                entropy,
            ) catch |err| switch (err) {
                calls.Error.PeerBusy, calls.Error.TableFull => return,
                else => return err,
            } orelse return;
            self.udp.send(
                io,
                started.peer.address,
                self.output[0..started.call.packet_length],
            ) catch |err| {
                operation.onFailure(self.core, started.call.handle) catch unreachable;
                return err;
            };
            result.lookup_started += 1;
        }
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

    fn startCallWithRecord(
        self: *Self,
        io: std.Io,
        peer: types.Endpoint,
        record: ?*const enr.Record,
        request: *const message.Message,
    ) Error!calls.Handle {
        const now_ms = try monotonicMilliseconds(io);
        var entropy = try startEntropy(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
        const started = if (record) |known|
            try self.core.startCallKnown(
                &self.output,
                peer,
                known,
                request,
                now_ms,
                entropy,
            )
        else
            try self.core.startCall(
                &self.output,
                peer,
                request,
                now_ms,
                entropy,
            );
        self.udp.send(
            io,
            peer.address,
            self.output[0..started.packet_length],
        ) catch |err| {
            const cancelled = self.core.cancelCall(started.handle);
            std.debug.assert(cancelled);
            return err;
        };
        return started.handle;
    }
};

fn monotonicMilliseconds(io: std.Io) Error!u64 {
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
