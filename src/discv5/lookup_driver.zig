const std = @import("std");
const CallTable = @import("CallTable.zig");
const Driver = @import("Driver.zig");
const Lookup = @import("Lookup.zig");
const constants = @import("wire/constants.zig");

pub const operations_max: usize = CallTable.capacity_max / Lookup.parallelism;

pub const Error = Driver.Error || Lookup.Error || error{TooManyLookups};

pub const Progress = struct {
    started: u16 = 0,
    responses: u16 = 0,
    failures: u16 = 0,
};

pub const StepResult = struct {
    driver: Driver.StepResult = .{},
    /// Index into `operations` of the lookup that consumed `Driver.event`, if any.
    consumed: ?u16 = null,
    progress: Progress = .{},
};

/// Borrows `operations` for this call only. Pass every lookup that still has waiting CallTable.
pub fn step(
    transport: *Driver,
    io: std.Io,
    operations: []const *Lookup,
    expired_calls: []CallTable.Expired,
) Error!StepResult {
    if (expired_calls.len == 0) return error.MissingExpiryStorage;
    if (operations.len > operations_max) return error.TooManyLookups;
    var result = StepResult{};
    try refill(transport, io, operations, &result);
    result.driver = try transport.step(io, expired_calls);
    try consumeExpiries(transport, operations, expired_calls, &result);
    try consumeEvent(transport, operations, &result);
    try refill(transport, io, operations, &result);
    return result;
}

fn refill(
    transport: *Driver,
    io: std.Io,
    operations: []const *Lookup,
    result: *StepResult,
) Error!void {
    for (0..Lookup.parallelism) |_| {
        var progressed = false;
        for (operations) |operation| {
            if (operation.isFinished() or operation.waitingCount() == Lookup.parallelism) continue;
            const started = startCall(transport, io, operation) catch |err| switch (err) {
                CallTable.Error.PeerBusy, CallTable.Error.TableFull => continue,
                error.DestinationUnreachable => {
                    result.progress.failures += 1;
                    progressed = true;
                    continue;
                },
                else => return err,
            };
            if (!started) continue;
            result.progress.started += 1;
            progressed = true;
        }
        if (!progressed) return;
    }
}

fn startCall(transport: *Driver, io: std.Io, operation: *Lookup) Error!bool {
    var context = try Driver.sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    const request_id = try Driver.requestId(io);
    var out: [constants.packet_size_max]u8 = undefined;
    const started = try operation.startNext(
        transport.core,
        &out,
        request_id,
        context.now_ms,
        &context.entropy,
    ) orelse return false;
    transport.transmit(io, started.peer.address, out[0..started.call.packet_length]) catch |err| {
        operation.onFailure(transport.core, started.call.handle) catch unreachable;
        return err;
    };
    return true;
}

fn consumeExpiries(
    transport: *Driver,
    operations: []const *Lookup,
    expired_calls: []CallTable.Expired,
    result: *StepResult,
) Lookup.Error!void {
    var retained: usize = 0;
    for (expired_calls[0..result.driver.calls_expired]) |item| {
        if (owner(operations, item.handle)) |index| {
            try operations[index].onFailure(transport.core, item.handle);
            result.progress.failures += 1;
            continue;
        }
        expired_calls[retained] = item;
        retained += 1;
    }
    result.driver.calls_expired = retained;
}

fn consumeEvent(
    transport: *Driver,
    operations: []const *Lookup,
    result: *StepResult,
) Lookup.Error!void {
    const response = switch (result.driver.event) {
        .response => |response| response,
        else => return,
    };
    const index = owner(operations, response.matched.handle) orelse return;
    try operations[index].onResponse(transport.core, &response, result.driver.now_ms);
    result.consumed = @intCast(index);
    result.progress.responses += 1;
}

fn owner(operations: []const *Lookup, handle: CallTable.Handle) ?usize {
    for (operations, 0..) |operation, index| {
        if (operation.ownsCall(handle)) return index;
    }
    return null;
}

comptime {
    std.debug.assert(operations_max == 85);
    std.debug.assert(operations_max * Lookup.parallelism * 2 <= std.math.maxInt(u16));
    std.debug.assert(@sizeOf(StepResult) <= @sizeOf(Driver.StepResult) + 16);
}
