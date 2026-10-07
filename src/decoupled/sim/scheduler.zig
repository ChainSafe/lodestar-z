//! A bounded queue of pending deliveries. Pops are by the `Delivery.before`
//! order, so one event list always replays to one sequence of states. The
//! queue is a few megabytes; allocate it on the heap.

const std = @import("std");
const assert = std.debug.assert;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("../limits.zig");
const types = @import("../types.zig");
const event = @import("event.zig");

const Delivery = event.Delivery;

pub const Scheduler = struct {
    pending: BoundedArray(Delivery, limits.max_pending),
    next_seq: u32,

    pub fn init(self: *Scheduler) void {
        self.pending = .{};
        self.next_seq = 0;
        assert(self.pending.empty());
        assert(self.next_seq == 0);
    }

    pub fn len(self: *const Scheduler) u32 {
        assert(self.pending.count <= limits.max_pending);
        return self.pending.count;
    }

    pub fn push(self: *Scheduler, time: types.Time, phase: event.Phase, node: u32, payload: *const event.Payload) void {
        assert(!self.pending.full());
        assert(time < limits.max_time);
        self.pending.push(.{
            .time = time,
            .phase = phase,
            .node = node,
            .seq = self.next_seq,
            .payload = payload.*,
        });
        self.next_seq += 1;
    }

    fn minIndex(self: *const Scheduler) u32 {
        assert(self.pending.count > 0);
        var best: u32 = 0;
        for (self.pending.constSlice(), 0..) |*candidate, i| {
            if (candidate.before(&self.pending.buffer[best])) best = @intCast(i);
        }
        assert(best < self.pending.count);
        return best;
    }

    /// Pops the earliest delivery if it is at (`time`, `phase`). Asserts that
    /// nothing earlier was left behind.
    pub fn popAt(self: *Scheduler, time: types.Time, phase: event.Phase) ?Delivery {
        if (self.pending.count == 0) return null;
        const index = self.minIndex();
        const head = &self.pending.buffer[index];
        assert(head.time > time or (head.time == time and @intFromEnum(head.phase) >= @intFromEnum(phase)));
        if (head.time != time) return null;
        if (head.phase != phase) return null;
        const delivery = head.*;
        const last = self.pending.count - 1;
        self.pending.buffer[index] = self.pending.buffer[last];
        self.pending.count = last;
        assert(self.pending.count == last);
        return delivery;
    }
};

test {
    _ = @import("scheduler_test.zig");
}
