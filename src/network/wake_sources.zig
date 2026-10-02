const std = @import("std");
const Schedule = @import("schedule.zig").Schedule;

/// Owner-loop wakeup sources.
pub const Source = enum {
    transport_backlog,
    transport_events,
    transport_timer,
    gossip,
    reqresp,
    identify,
    negotiation,
    control,
    dial,
    peer_policy,
    peer_events,
    discovery,
    host,
};
pub const source_count = std.meta.fields(Source).len;

/// Scheduling state by source, retained separately for owner wakeup metrics.
pub const Wakeups = struct {
    sources: [source_count]Schedule = @splat(.{}),

    pub fn note(self: *Wakeups, source: Source, value: Schedule) void {
        const slot = &self.sources[@intFromEnum(source)];
        slot.* = slot.merge(value);
    }

    pub fn schedule(self: *const Wakeups) Schedule {
        var result: Schedule = .{};
        for (self.sources) |source| result = result.merge(source);
        return result;
    }
};
