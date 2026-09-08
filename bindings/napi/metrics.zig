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

/// JS: metrics.init() → void
pub fn init() !void {
    if (initialized) return;
    try state_transition.metrics.init(allocator, js.io(), .{});
    initialized = true;
}

/// JS: metrics.observeStateHashTreeRoot(source, seconds) → void
pub fn observeStateHashTreeRoot(source: js.String, seconds: js.Number) !void {
    if (!initialized) return error.MetricsNotInitialized;

    var source_buffer: [32]u8 = undefined;
    const source_name = try source.toSlice(&source_buffer);
    const source_value = std.meta.stringToEnum(
        state_transition.metrics.StateHashTreeRootSource,
        source_name,
    ) orelse return error.InvalidStateHashTreeRootSource;
    const seconds_value = try seconds.toF64();
    if (!std.math.isFinite(seconds_value) or
        seconds_value < 0 or
        seconds_value > state_transition.metrics.state_hash_tree_root_duration_seconds_max)
    {
        return error.InvalidMetricDuration;
    }

    try state_transition.metrics.observeStateHashTreeRoot(source_value, seconds_value);
}

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try state_transition.metrics.write(&aw.writer);
    return js.String.from(aw.written());
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    initialized = false;
}
