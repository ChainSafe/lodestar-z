const std = @import("std");

pub const Mutex = struct {
    raw: std.atomic.Mutex = .unlocked,

    pub fn lock(self: *Mutex) void {
        var spins: usize = 0;
        while (!self.raw.tryLock()) {
            if (spins < 64) {
                spins += 1;
                std.atomic.spinLoopHint();
            } else {
                std.Thread.yield() catch {};
            }
        }
    }

    pub fn unlock(self: *Mutex) void {
        self.raw.unlock();
    }
};
