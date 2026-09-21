const std = @import("std");
const histogram = @import("histogram.zig");

pub const Duration = histogram.Histogram(u64, &.{ 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 700_000_000, 1_000_000_000, 3_000_000_000 }, .{ .unit = .nanoseconds });

pub fn now(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .awake).nanoseconds));
}

pub const Gossip = struct {
    cycles: Duration = .{},
    setup: Duration = .{},
    topics: Duration = .{},
    lateness: Duration = .{},
    started_ns: ?u64 = null,
    completed_unix_s: i64 = 0,

    pub fn completed(self: *Gossip, end_ns: u64, unix_s: i64) void {
        if (self.started_ns) |start| self.cycles.observe(end_ns -| start);
        self.started_ns = null;
        self.completed_unix_s = unix_s;
    }
};

test {
    _ = @import("timing_test.zig");
}
