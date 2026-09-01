const std = @import("std");
const calls = @import("calls.zig");
const driver = @import("driver.zig");
const lookup = @import("lookup.zig");

pub const operations_max: usize = calls.capacity_max / lookup.parallelism;

pub const Error = driver.LookupError || error{TooManyLookups};

pub const StepResult = struct {
    driver: driver.StepResult = .{},
    started: u16 = 0,
    responses: u16 = 0,
    failures: u16 = 0,
    /// Index into `operations` of the lookup that consumed `driver.event`, if any.
    consumed: ?u16 = null,
};

/// Borrows `operations` for this call only. Pass every lookup that still has waiting calls.
pub fn step(
    transport: *driver.Driver,
    io: std.Io,
    operations: []const *lookup.Lookup,
    expired_calls: []calls.Expired,
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
    transport: *driver.Driver,
    io: std.Io,
    operations: []const *lookup.Lookup,
    result: *StepResult,
) Error!void {
    for (0..lookup.parallelism) |_| {
        var progressed = false;
        for (operations) |operation| {
            if (operation.isFinished() or operation.waitingCount() == lookup.parallelism) continue;
            const started = transport.startLookupCall(io, operation) catch |err| switch (err) {
                calls.Error.PeerBusy, calls.Error.TableFull => continue,
                error.DestinationUnreachable => {
                    result.failures += 1;
                    progressed = true;
                    continue;
                },
                else => return err,
            };
            if (!started) continue;
            result.started += 1;
            progressed = true;
        }
        if (!progressed) return;
    }
}

fn consumeExpiries(
    transport: *driver.Driver,
    operations: []const *lookup.Lookup,
    expired_calls: []calls.Expired,
    result: *StepResult,
) lookup.Error!void {
    var retained: usize = 0;
    for (expired_calls[0..result.driver.calls_expired]) |item| {
        if (owner(operations, item.handle)) |index| {
            try operations[index].onFailure(transport.core, item.handle);
            result.failures += 1;
            continue;
        }
        expired_calls[retained] = item;
        retained += 1;
    }
    result.driver.calls_expired = retained;
}

fn consumeEvent(
    transport: *driver.Driver,
    operations: []const *lookup.Lookup,
    result: *StepResult,
) lookup.Error!void {
    const response = switch (result.driver.event) {
        .response => |response| response,
        else => return,
    };
    const index = owner(operations, response.matched.handle) orelse return;
    try operations[index].onResponse(transport.core, &response, result.driver.now_ms);
    result.consumed = @intCast(index);
    result.responses += 1;
}

fn owner(operations: []const *lookup.Lookup, handle: calls.Handle) ?usize {
    for (operations, 0..) |operation, index| {
        if (operation.ownsCall(handle)) return index;
    }
    return null;
}

comptime {
    std.debug.assert(operations_max == 85);
    std.debug.assert(operations_max * lookup.parallelism * 2 <= std.math.maxInt(u16));
    std.debug.assert(@sizeOf(StepResult) <= @sizeOf(driver.StepResult) + 16);
}
