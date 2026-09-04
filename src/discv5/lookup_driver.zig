//! The lookup driver advances a caller-owned set of lookups through the synchronous driver, one
//! step at a time.

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

pub const Cursor = struct {
    next: usize = 0,
};

pub const StepResult = struct {
    driver: Driver.StepResult = .{},
    /// The index into `operations` of the lookup that consumed `driver.event`, if any.
    consumed: ?u16 = null,
    progress: Progress = .{},
    failure: ?Error = null,
};

/// Borrows `operations` for this call only. Pass every lookup that still has waiting calls and
/// retain the cursor across steps to rotate priority when calls contend for limited capacity.
pub fn step(
    transport: *Driver,
    io: std.Io,
    operations: []const *Lookup,
    cursor: *Cursor,
    expired_calls: []CallTable.Expired,
) Error!StepResult {
    if (expired_calls.len == 0) return error.MissingExpiryStorage;
    if (operations.len > operations_max) return error.TooManyLookups;
    var result = StepResult{};
    const first = if (operations.len == 0) 0 else cursor.next % operations.len;
    cursor.next = if (operations.len == 0) 0 else (first + 1) % operations.len;
    refill(transport, io, operations, first, &result) catch |err| {
        result.failure = err;
    };
    result.driver = transport.step(io, expired_calls) catch |err| {
        result.failure = result.failure orelse err;
        return result;
    };
    consumeExpiries(transport, operations, expired_calls, &result);
    consumeEvent(transport, operations, &result) catch |err| {
        result.failure = result.failure orelse err;
    };
    result.failure = result.failure orelse result.driver.failure;
    if (result.failure == null) {
        refill(transport, io, operations, first, &result) catch |err| {
            result.failure = err;
        };
    }
    return result;
}

fn refill(
    transport: *Driver,
    io: std.Io,
    operations: []const *Lookup,
    first: usize,
    result: *StepResult,
) Error!void {
    for (0..Lookup.parallelism) |_| {
        var progressed = false;
        for (0..operations.len) |offset| {
            const operation = operations[(first + offset) % operations.len];
            if (operation.isFinished() or operation.waitingCount() == Lookup.parallelism) continue;
            const started = startCall(
                transport,
                io,
                operation,
                &result.progress,
            ) catch |err| switch (err) {
                CallTable.Error.PeerBusy, CallTable.Error.TableFull => continue,
                error.DestinationUnreachable => {
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

fn startCall(
    transport: *Driver,
    io: std.Io,
    operation: *Lookup,
    progress: *Progress,
) Error!bool {
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
        progress.failures += 1;
        return err;
    };
    return true;
}

fn consumeExpiries(
    transport: *Driver,
    operations: []const *Lookup,
    expired_calls: []CallTable.Expired,
    result: *StepResult,
) void {
    var retained: usize = 0;
    for (expired_calls[0..result.driver.calls_expired]) |item| {
        if (owner(operations, item.handle)) |index| {
            operations[index].onFailure(transport.core, item.handle) catch unreachable;
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
    switch (result.driver.event) {
        .response => |response| {
            const index = owner(operations, response.matched.handle) orelse return;
            try operations[index].onResponse(transport.core, &response, result.driver.now_ms);
            result.consumed = @intCast(index);
            result.progress.responses += 1;
        },
        .failed => |failed| {
            const index = owner(operations, failed.handle) orelse return;
            try operations[index].onFailure(transport.core, failed.handle);
            result.consumed = @intCast(index);
            result.progress.failures += 1;
        },
        else => return,
    }
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
