const std = @import("std");
const constants = @import("constants.zig");
const State = @import("state.zig").State;
const PeerScore = @import("score.zig").PeerScore;

pub const Score = struct { generation: u64 = 0, value: f64 = 0 };
pub const Scores = [constants.peers_cap]Score;

pub const Cycle = struct {
    scores: Scores = @splat(.{}),
    cursor: usize = 0,
    remaining: usize = 0,
    opportunistic: bool = false,

    pub fn takeSnapshot(self: *Cycle, state: *const State, scores: *PeerScore, now: u64) void {
        for (state.peers, 0..) |*peer, i| {
            self.scores[i] = if (peer.active) .{ .generation = peer.generation, .value = scores.score(peer.logical.index, now) } else .{};
        }
    }

    pub fn begin(self: *Cycle, state: *const State, scores: *PeerScore, now: u64, opportunistic: bool) void {
        std.debug.assert(self.remaining == 0);
        self.takeSnapshot(state, scores, now);
        self.remaining = constants.topics_cap;
        self.opportunistic = opportunistic;
    }

    pub fn next(self: *Cycle) ?u16 {
        if (self.remaining == 0) return null;
        const index = self.cursor;
        self.cursor = (index + 1) % constants.topics_cap;
        self.remaining -= 1;
        return @intCast(index);
    }
};
