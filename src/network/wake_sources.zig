const std = @import("std");

/// Owner-loop wakeup sources. Each name is a `source` label value of
/// lodestar_native_network_due_now_turns_total.
pub const Source = enum {
    transport_backlog,
    transport_host_work,
    transport_activity,
    transport_events,
    transport_closing,
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

/// The earliest monotonic deadline of each source for one owner turn.
pub const Wakeups = struct {
    due: [source_count]?u64 = @splat(null),

    pub fn note(self: *Wakeups, source: Source, deadline: ?u64) void {
        const value = deadline orelse return;
        const slot = &self.due[@intFromEnum(source)];
        slot.* = @min(slot.* orelse value, value);
    }

    pub fn earliest(self: *const Wakeups) ?u64 {
        var result: ?u64 = null;
        for (self.due) |deadline| {
            const value = deadline orelse continue;
            result = @min(result orelse value, value);
        }
        return result;
    }
};
