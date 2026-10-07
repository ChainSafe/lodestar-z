//! One delivery of one object at one honest node (`Generic/Run.lean`). Ticks
//! are not queued: the runner ticks every node at every public time.
//!
//! `before_tick` is an object that arrived strictly inside the previous
//! interval; the store stamps it with the earlier public time. `after_tick`
//! is an object that arrived exactly at the public time, after the tick.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../types.zig");

pub const Phase = enum(u8) {
    before_tick = 0,
    after_tick = 1,
};

pub const Payload = union(enum) {
    block: types.Block,
    vote: types.GoldfishVote,
};

pub const Delivery = struct {
    time: types.Time,
    phase: Phase,
    node: u32,
    seq: u32,
    payload: Payload,

    /// Processing order: time, phase, node, then arrival sequence.
    pub fn before(a: *const Delivery, b: *const Delivery) bool {
        if (a.time != b.time) return a.time < b.time;
        if (a.phase != b.phase) return @intFromEnum(a.phase) < @intFromEnum(b.phase);
        if (a.node != b.node) return a.node < b.node;
        assert(a.seq != b.seq or a == b);
        return a.seq < b.seq;
    }
};

test "deliveries order by time, phase, node, seq" {
    const vote: types.GoldfishVote = .{ .val_index = 0, .slot = 1, .head = types.genesis_root };
    const a: Delivery = .{ .time = 4, .phase = .after_tick, .node = 9, .seq = 0, .payload = .{ .vote = vote } };
    const b: Delivery = .{ .time = 5, .phase = .before_tick, .node = 0, .seq = 1, .payload = .{ .vote = vote } };
    const c: Delivery = .{ .time = 5, .phase = .before_tick, .node = 0, .seq = 2, .payload = .{ .vote = vote } };
    try std.testing.expect(a.before(&b));
    try std.testing.expect(b.before(&c));
    try std.testing.expect(!c.before(&b));
}
