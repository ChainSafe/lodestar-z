const std = @import("std");
const builtin = @import("builtin");
const napi = @import("zapi:zapi");
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

pub fn Metrics_scrapeMetrics(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    try state_transition.metrics.write(&aw.writer);
    var list = aw.toArrayList();
    defer list.deinit(allocator);
    return env.createStringUtf8(list.items);
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    initialized = false;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const metrics_obj = try env.createObject();

    try metrics_obj.setNamedProperty("scrapeMetrics", try env.createFunction(
        "scrapeMetrics",
        0,
        Metrics_scrapeMetrics,
        null,
    ));
    try exports.setNamedProperty("metrics", metrics_obj);
}
