const std = @import("std");
const napi = @import("zapi:zapi").napi;
const n = @import("network");
const r = @import("network_runtime.zig");

pub const Export = struct {
    buffer: []u8 = &.{},
    length: usize = 0,
    failure: ?n.metrics.registry.Error = null,

    pub fn init(capacity: usize) !Export {
        return .{ .buffer = try r.allocator.alloc(u8, capacity) };
    }
    pub fn deinit(self: *Export) void {
        r.allocator.free(self.buffer);
        self.* = .{};
    }
    pub fn allocatedBytes(self: *const Export) usize {
        return self.buffer.len;
    }
    /// The owner renders on demand or at shutdown; rendering and readers hold the runtime mutex.
    pub fn render(self: *Export, context: *const n.metrics.Context) n.metrics.registry.Error!void {
        var writer = std.Io.Writer.fixed(self.buffer);
        n.metrics.write(context, &writer) catch |err| {
            self.failure = err;
            return err;
        };
        self.length = writer.buffered().len;
        self.failure = null;
    }

    /// The caller holds the runtime mutex. Log delivery continues after the network owner stops.
    pub fn text(self: *Export, logs: *const n.logging.Stats, reports_dropped: u64, xray: ?*n.xray.Probe) n.metrics.registry.Error![]const u8 {
        if (self.failure) |err| return err;
        var writer = std.Io.Writer.fixed(self.buffer);
        writer.end = self.length;
        var encoder: n.metrics.registry.Encoder = .{ .writer = &writer };
        try logs.write(&encoder);
        const reports = try encoder.family(.{
            .name = "lodestar_peers_report_peer_dropped_total",
            .kind = .counter,
            .help = "Peer reports dropped because the binding's pending report table was full",
        });
        try reports.sample(.{}, reports_dropped);
        if (xray) |probe| try probe.writeMetrics(&encoder);
        return writer.buffered();
    }
};

/// Copy under the mutex, then construct the JavaScript value after releasing it.
pub fn value(runtime: *r.Runtime) !napi.Value {
    const copy = blk: {
        runtime.lock();
        defer runtime.unlock();
        const logs = runtime.logs.snapshot();
        const borrowed = runtime.metrics.text(&logs, runtime.bridge.reports.dropped, runtime.xray) catch |err| return switch (err) {
            error.WriteFailed, error.MetricCapacity => error.NetworkMetricsCapacity,
            error.DuplicateMetric => error.NetworkMetricsSchema,
        };
        break :blk try r.allocator.dupe(u8, borrowed);
    };
    defer r.allocator.free(copy);
    return runtime.env.createStringUtf8(copy);
}
