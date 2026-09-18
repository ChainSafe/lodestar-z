//! Advances a bounded batch of caller-owned lookups through Transport, one step at a time.

const std = @import("std");
const CallTable = @import("CallTable.zig");
const Transport = @import("Transport.zig");
const Lookup = @import("Lookup.zig");

pub const operations_max: usize = CallTable.capacity_max / Lookup.parallelism;

pub const Error = Transport.Error || Lookup.Error || error{TooManyLookups};

pub const Progress = struct {
    started: u16 = 0,
    responses: u16 = 0,
    failures: u16 = 0,
};

pub const Cursor = struct {
    next: usize = 0,
};

pub const StepResult = struct {
    transport: Transport.StepResult = .{},
    /// The index into `operations` of the lookup that consumed `transport.event`, if any.
    consumed: ?u16 = null,
    progress: Progress = .{},
    failure: ?Error = null,
};

/// Borrows `operations` for this call only. Pass every lookup that still has waiting calls and
/// retain the cursor across steps to rotate priority when calls contend for limited capacity.
pub fn step(
    transport: *Transport,
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
    result.transport = transport.step(io, expired_calls) catch |err| {
        result.failure = result.failure orelse err;
        return result;
    };
    consumeExpiries(transport, operations, expired_calls, &result);
    consumeEvent(transport, operations, &result) catch |err| {
        result.failure = result.failure orelse err;
    };
    result.failure = result.failure orelse result.transport.failure;
    if (result.failure == null) {
        refill(transport, io, operations, first, &result) catch |err| {
            result.failure = err;
        };
    }
    return result;
}

fn refill(
    transport: *Transport,
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
    transport: *Transport,
    io: std.Io,
    operation: *Lookup,
    progress: *Progress,
) Error!bool {
    const result = try @import("lookup_io.zig").startLookup(transport, io, operation, try Transport.monotonicMilliseconds(io));
    if (result.failure) |err| {
        progress.failures += 1;
        return err;
    }
    return result.started;
}

fn consumeExpiries(
    transport: *Transport,
    operations: []const *Lookup,
    expired_calls: []CallTable.Expired,
    result: *StepResult,
) void {
    var retained: usize = 0;
    for (expired_calls[0..result.transport.calls_expired]) |item| {
        if (owner(operations, item.handle)) |index| {
            operations[index].onFailure(&transport.engine, item.handle) catch unreachable;
            result.progress.failures += 1;
            continue;
        }
        expired_calls[retained] = item;
        retained += 1;
    }
    result.transport.calls_expired = retained;
}

fn consumeEvent(
    transport: *Transport,
    operations: []const *Lookup,
    result: *StepResult,
) Lookup.Error!void {
    switch (result.transport.event) {
        .response => |response| {
            const index = owner(operations, response.matched.handle) orelse return;
            try operations[index].onResponse(&transport.engine, &response, result.transport.now_ms);
            result.consumed = @intCast(index);
            result.progress.responses += 1;
        },
        .failed => |failed| {
            const index = owner(operations, failed.handle) orelse return;
            try operations[index].onFailure(&transport.engine, failed.handle);
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
    std.debug.assert(@sizeOf(StepResult) <= @sizeOf(Transport.StepResult) + 16);
}

test {
    _ = @import("lookup_batch_test.zig");
}
