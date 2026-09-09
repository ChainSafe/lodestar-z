const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

const validator_monitor = @import("./validator_monitor.zig");

/// JS: metrics.init() → void
pub fn init() !void {
    if (initialized) return;
    try state_transition.metrics.init(allocator, js.io(), .{});
    initialized = true;
}

/// JS: metrics.registerLocalValidator(index) → void
///
/// Adds a validator index to the process-wide validator monitor so that
/// metrics are recorded for it on every epoch transition.
pub fn registerLocalValidator(index: js.Number) !void {
    const value = try index.toI64();
    if (value < 0) return error.InvalidValidatorIndex;
    try validator_monitor.get().registerLocalValidator(@intCast(value));
}

/// JS: metrics.unregisterLocalValidator(index) → void
///
/// Prunes a validator index from the process-wide validator monitor.
pub fn unregisterLocalValidator(index: js.Number) !void {
    const value = try index.toI64();
    if (value < 0) return error.InvalidValidatorIndex;
    validator_monitor.get().unregisterLocalValidator(@intCast(value));
}

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try state_transition.metrics.write(&aw.writer);
    return js.String.from(aw.written());
}

/// JS: metrics.scrapeStateTransitionMetrics() → string
pub fn scrapeStateTransitionMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try state_transition.metrics.writeStateTransition(&aw.writer);
    return js.String.from(aw.written());
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.deinit();
    validator_monitor.deinit();
    initialized = false;
}
