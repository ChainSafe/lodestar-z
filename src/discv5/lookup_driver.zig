const std = @import("std");
const calls = @import("calls.zig");
const driver = @import("driver.zig");
const lookup = @import("lookup.zig");

pub const Error = driver.LookupError;

pub const StepResult = struct {
    driver: driver.StepResult = .{},
    started: u8 = 0,
    responses: u8 = 0,
    failures: u8 = 0,
};

/// Borrows the lookup for this call only. Pass the same lookup while it has waiting calls.
pub fn step(
    transport: *driver.Driver,
    io: std.Io,
    operation: *lookup.Lookup,
    expired_calls: []calls.Expired,
) Error!StepResult {
    if (expired_calls.len == 0) return error.MissingExpiryStorage;
    var result = StepResult{};
    try refill(transport, io, operation, &result);
    if (operation.isFinished()) return result;

    result.driver = try transport.step(io, expired_calls);
    try consumeExpiries(transport, operation, expired_calls, &result);
    try consumeEvent(transport, operation, &result);
    try refill(transport, io, operation, &result);
    return result;
}

fn refill(
    transport: *driver.Driver,
    io: std.Io,
    operation: *lookup.Lookup,
    result: *StepResult,
) Error!void {
    for (0..lookup.parallelism) |_| {
        if (operation.isFinished() or operation.waitingCount() == lookup.parallelism) return;
        const started = transport.startLookupCall(io, operation) catch |err| switch (err) {
            calls.Error.PeerBusy, calls.Error.TableFull => return,
            else => return err,
        };
        if (!started) return;
        result.started += 1;
    }
}

fn consumeExpiries(
    transport: *driver.Driver,
    operation: *lookup.Lookup,
    expired_calls: []calls.Expired,
    result: *StepResult,
) lookup.Error!void {
    var retained: usize = 0;
    for (expired_calls[0..result.driver.calls_expired]) |item| {
        if (operation.ownsCall(item.handle)) {
            try operation.onFailure(transport.core, item.handle);
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
    operation: *lookup.Lookup,
    result: *StepResult,
) lookup.Error!void {
    const response = switch (result.driver.event) {
        .response => |response| response,
        else => return,
    };
    if (!operation.ownsCall(response.matched.handle)) return;
    try operation.onResponse(transport.core, &response, result.driver.now_ms);
    result.driver.event = .none;
    result.responses += 1;
}

comptime {
    std.debug.assert(@sizeOf(StepResult) <= @sizeOf(driver.StepResult) + 8);
}
