const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const state_transition = @import("state_transition");
const peer_manager = @import("peer_manager");
const napi_io = @import("./io.zig");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

/// JS: metrics.init()
/// Initializes the metric registries so subsequent recordings are live; until
/// called, all metrics are noop. Safe to call more than once.
pub fn init() !void {
    if (initialized) return;
    const io = napi_io.get();
    try state_transition.metrics.init(allocator, io, .{});
    errdefer state_transition.metrics.state_transition.deinit();
    try peer_manager.metrics.init(allocator, io, .{});
    initialized = true;
}

/// JS: metrics.scrapeMetrics() → string
pub fn scrapeMetrics() !js.String {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    try state_transition.metrics.write(&aw.writer);
    try peer_manager.metrics.write(&aw.writer);
    var list = aw.toArrayList();
    defer list.deinit(allocator);
    return js.String.from(list.items);
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    peer_manager.metrics.deinit();
    initialized = false;
}
