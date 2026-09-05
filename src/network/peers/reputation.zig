const t = @import("types.zig");
pub const ban_cooldown_ms: u64 = 30 * 60 * 1000;
pub const half_life_ms: u64 = 10 * 60 * 1000;
pub const State = struct {
    score: f64 = 0,
    decay_at_ms: u64 = 0,
    ban_until_ms: u64 = 0,
    goodbye_until_ms: u64 = 0,

    pub fn decay(self: *State, now_ms: u64) void {
        const start = @max(self.decay_at_ms, self.ban_until_ms);
        if (now_ms <= start) return;
        const elapsed = now_ms - start;
        if (elapsed >= 64 * half_life_ms) {
            self.score = 0;
        } else {
            self.score *= @exp2(-@as(f64, @floatFromInt(elapsed)) / half_life_ms);
            if (self.score > -0.001) self.score = 0;
        }
        self.decay_at_ms = now_ms;
    }

    pub fn apply(self: *State, action: t.PeerAction, now_ms: u64) t.ReputationDecision {
        self.decay(now_ms);
        const weight: f64 = switch (action) {
            .fatal => -100,
            .low_tolerance => -10,
            .mid_tolerance => -5,
            .high_tolerance => -1,
        };
        self.score = @max(-100, self.score + weight);
        self.decay_at_ms = @max(self.decay_at_ms, now_ms);
        if (self.score <= -50) {
            self.ban_until_ms = @max(self.ban_until_ms, now_ms +| ban_cooldown_ms);
            return .ban;
        }
        return if (self.score <= -20) .disconnect else .none;
    }

    pub fn banned(self: *const State, now_ms: u64) bool {
        return now_ms < self.ban_until_ms or self.score <= -50;
    }

    pub fn retained(self: *const State, now_ms: u64) bool {
        return self.score < 0 or self.banned(now_ms) or now_ms < self.goodbye_until_ms;
    }

    pub fn nextDeadline(self: *const State, now_ms: u64) ?u64 {
        var current = self.*;
        current.decay(now_ms);
        var deadline: ?u64 = if (now_ms < current.goodbye_until_ms)
            current.goodbye_until_ms
        else
            null;
        if (now_ms < current.ban_until_ms) {
            deadline = @min(deadline orelse current.ban_until_ms, current.ban_until_ms);
        } else if (current.score < 0) {
            const threshold: f64 = if (current.score <= -50) 50 else 0.001;
            const periods = @log2(-current.score / threshold);
            const remaining: u64 = @intFromFloat(@max(0, periods * half_life_ms));
            const next = now_ms +| remaining +| 1;
            deadline = @min(deadline orelse next, next);
        }
        return deadline;
    }

    pub fn remoteGoodbye(self: *State, now_ms: u64, duration_ms: u64) void {
        self.goodbye_until_ms = @max(self.goodbye_until_ms, now_ms +| duration_ms);
    }
};
