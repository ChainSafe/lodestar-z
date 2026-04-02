const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi").js;
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try state_transition.metrics.write(buf.writer());
    return js.String.from(buf.items);
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    initialized = false;
}
