/// Work the owner can run without another external event, and its next monotonic timer.
/// Pending work blocked on I/O or output capacity is not runnable. An empty schedule says
/// nothing about whether the owner is closed or still holds borrowed storage.
pub const Schedule = struct {
    runnable: bool = false,
    deadline_ms: ?u64 = null,

    pub fn merge(self: Schedule, other: Schedule) Schedule {
        return .{
            .runnable = self.runnable or other.runnable,
            .deadline_ms = if (self.deadline_ms) |a|
                if (other.deadline_ms) |b| @min(a, b) else a
            else
                other.deadline_ms,
        };
    }

    pub fn due(self: Schedule, now_ms: u64) bool {
        return self.runnable or if (self.deadline_ms) |deadline| deadline <= now_ms else false;
    }

    pub fn nextWakeup(self: Schedule, now_ms: u64) ?u64 {
        if (self.runnable) return now_ms;
        return if (self.deadline_ms) |deadline| @max(now_ms, deadline) else null;
    }

    pub fn waitMs(self: Schedule, now_ms: u64, maximum_ms: u32) u32 {
        if (self.runnable) return 0;
        const deadline = self.deadline_ms orelse return maximum_ms;
        return @intCast(@min(deadline -| now_ms, maximum_ms));
    }
};

test {
    _ = @import("schedule_test.zig");
}
