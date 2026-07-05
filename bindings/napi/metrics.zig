const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const state_transition = @import("state_transition");
const beacon_engine = @import("beacon_engine");
const napi_io = @import("./io.zig");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

/// JS: metrics.init() → void
pub fn init() !void {
    if (initialized) return;
    try state_transition.metrics.init(allocator, napi_io.get(), .{});
    try beacon_engine.metrics.init(allocator, napi_io.get(), .{});
    initialized = true;
}

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    try state_transition.metrics.write(&aw.writer);
    try beacon_engine.metrics.write(&aw.writer);
    var list = aw.toArrayList();
    defer list.deinit(allocator);
    return js.String.from(list.items);
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    initialized = false;
}
