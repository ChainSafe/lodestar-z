const std = @import("std");
const builtin = @import("builtin");
const napi = @import("zapi:napi");
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var initialized: bool = false;

pub fn Metrics_init(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    if (!initialized) {
        try state_transition.metrics.init(allocator, .{});
        initialized = true;
    }
    return env.getUndefined();
}

pub fn Metrics_scrapeMetrics(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try state_transition.metrics.write(buf.writer());
    try buf.append(0);
    return env.createStringUtf8(buf.items[0 .. buf.items.len - 1]);
}

pub fn deinit() void {
    if (!initialized) return;
    state_transition.metrics.state_transition.deinit();
    initialized = false;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const metrics_obj = try env.createObject();
    try metrics_obj.setNamedProperty("init", try env.createFunction(
        "init",
        0,
        Metrics_init,
        null,
    ));
    try metrics_obj.setNamedProperty("scrapeMetrics", try env.createFunction(
        "scrapeMetrics",
        0,
        Metrics_scrapeMetrics,
        null,
    ));
    try exports.setNamedProperty("metrics", metrics_obj);
}
