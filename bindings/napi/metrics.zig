const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

threadlocal var historical: ?bool = null;

/// JS: metrics.init({historical?: boolean}) → void
pub fn init(options: ?js.Value) !void {
    var use_historical_prefix = false;
    if (options) |value| {
        const raw = value.toValue();
        if (try raw.hasNamedProperty("historical")) {
            use_historical_prefix = try (try raw.getNamedProperty("historical")).getValueBool();
        }
    }
    if (historical) |previous| {
        if (previous != use_historical_prefix) return error.MetricsAlreadyInitialized;
        return;
    }
    if (use_historical_prefix) {
        try state_transition.metrics.init(allocator, js.io(), .{ .prefix = "lodestar_historical_state_" });
    } else {
        try state_transition.metrics.init(allocator, js.io(), .{});
    }
    historical = use_historical_prefix;
}

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try state_transition.metrics.write(&aw.writer);
    return js.String.from(aw.written());
}

pub fn deinit() void {
    if (historical == null) return;
    state_transition.metrics.state_transition.deinit();
    historical = null;
}
