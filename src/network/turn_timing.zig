const std = @import("std");
const timing = @import("metrics/timing.zig");

pub const Phase = enum { receive, transport, host, protocols, maintenance, send };
const phase_count = std.meta.fields(Phase).len;
const window_ns = 50 * std.time.ns_per_ms;

pub const TurnTiming = struct {
    enabled: bool = false,
    window_start: ?u64 = null,
    start: u64 = 0,
    previous: u64 = 0,
    elapsed: [phase_count]u64 = @splat(0),
    turns: u64 = 0,
    max_turn_ns: u64 = 0,
    received: u64 = 0,
    sent: u64 = 0,

    pub fn begin(self: *TurnTiming, now_ns: u64) void {
        if (!self.enabled) return;
        if (self.window_start == null) self.window_start = now_ns;
        self.start = now_ns;
        self.previous = now_ns;
    }

    pub fn mark(self: *TurnTiming, io: std.Io, phase: Phase) void {
        if (self.enabled) self.markAt(timing.now(io), phase);
    }

    fn markAt(self: *TurnTiming, now_ns: u64, phase: Phase) void {
        self.elapsed[@intFromEnum(phase)] +|= now_ns -| self.previous;
        self.previous = now_ns;
    }

    pub fn finish(self: *TurnTiming, now_ns: u64, received: u32, sent: u32) void {
        if (!self.enabled) return;
        self.turns +|= 1;
        self.max_turn_ns = @max(self.max_turn_ns, now_ns -| self.start);
        self.received +|= received;
        self.sent +|= sent;
        const elapsed_ns = now_ns -| self.window_start.?;
        if (elapsed_ns < window_ns) return;
        std.log.scoped(.network_core).info("turn_window elapsed_ns={d} turns={d} max_turn_ns={d} receive_ns={d} transport_ns={d} host_ns={d} protocols_ns={d} maintenance_ns={d} send_ns={d} received={d} sent={d}", .{
            elapsed_ns,      self.turns,      self.max_turn_ns,
            self.elapsed[0], self.elapsed[1], self.elapsed[2],
            self.elapsed[3], self.elapsed[4], self.elapsed[5],
            self.received,   self.sent,
        });
        self.* = .{ .enabled = true, .window_start = now_ns };
    }
};

test "turn timing excludes idle time and bounds each reporting window" {
    var trace: TurnTiming = .{ .enabled = true };
    trace.begin(0);
    trace.markAt(10, .receive);
    trace.markAt(30, .host);
    trace.finish(30, 2, 0);
    trace.begin(100);
    trace.markAt(115, .receive);
    trace.markAt(125, .protocols);
    trace.finish(125, 3, 1);
    try std.testing.expectEqual(@as(u64, 25), trace.elapsed[0]);
    try std.testing.expectEqual(@as(u64, 20), trace.elapsed[2]);
    try std.testing.expectEqual(@as(u64, 10), trace.elapsed[3]);
    try std.testing.expectEqual(@as(u64, 30), trace.max_turn_ns);
    try std.testing.expectEqual(@as(u64, 2), trace.turns);
    trace.begin(window_ns);
    trace.finish(window_ns + 1, 0, 0);
    try std.testing.expectEqual(@as(u64, 0), trace.turns);
    try std.testing.expectEqual(@as(?u64, window_ns + 1), trace.window_start);
}
