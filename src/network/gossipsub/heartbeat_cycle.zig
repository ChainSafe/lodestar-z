const std = @import("std");
const constants = @import("constants.zig");
const Sessions = @import("sessions.zig").Sessions;
const PeerScore = @import("score.zig").PeerScore;

pub const Score = struct { generation: u64 = 0, value: f64 = 0 };
pub const Scores = [constants.peers_cap]Score;

pub const Cycle = struct {
    scores: Scores = @splat(.{}),
    cursor: usize = 0,
    phase: union(enum) { idle, active: usize } = .idle,
    epoch: u64 = 0,
    opportunistic: bool = false,

    pub fn takeSnapshot(self: *Cycle, sessions: *const Sessions, scores: *PeerScore, now: u64) void {
        for (sessions.rows, 0..) |*peer, i| {
            self.scores[i] = if (peer.active) .{ .generation = peer.generation, .value = scores.score(peer.logical.index, now) } else .{};
        }
    }

    pub fn begin(self: *Cycle, sessions: *const Sessions, scores: *PeerScore, now: u64, opportunistic: bool) void {
        std.debug.assert(self.phase == .idle and self.epoch < std.math.maxInt(u64));
        self.epoch += 1;
        self.takeSnapshot(sessions, scores, now);
        self.phase = .{ .active = constants.topics_cap };
        self.opportunistic = opportunistic;
    }

    pub fn isActive(self: *const Cycle) bool {
        return self.phase == .active;
    }

    pub fn complete(self: *Cycle) ?u64 {
        if (self.phase == .idle or self.phase.active != 0) return null;
        self.phase = .idle;
        return self.epoch;
    }

    pub fn next(self: *Cycle) ?u16 {
        if (self.phase == .idle or self.phase.active == 0) return null;
        const index = self.cursor;
        self.cursor = (index + 1) % constants.topics_cap;
        self.phase.active -= 1;
        return @intCast(index);
    }
};
