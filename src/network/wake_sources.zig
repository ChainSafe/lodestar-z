const Schedule = @import("schedule.zig").Schedule;

/// Discovery may run alone when no other owner has work due.
pub const Wakeups = struct {
    discovery: Schedule = .{},
    other: Schedule = .{},

    pub fn schedule(self: Wakeups) Schedule {
        return self.discovery.merge(self.other);
    }
};
