//! Per-kind timing of each message's way through the processor, to attribute its wait before the host starts it and
//! the wait of its verdict. Receipt is gossipsub admission (`admitted_ms`, the origin of the host's job wait). A message
//! is ready when it first queues past its dependency check, and claimed when an exchange selects it. Ready to claimed
//! splits into `ready_credit_blocked`, the time the kind's execution credits refused the kind's next ready item while
//! this one was ready (no item of a kind is claimed past a refused one), and `ready_other_wait`, the rest; neither alone
//! proves a cause when credit pressure and host delay overlap. Claim to verdict application covers the host holding
//! its credit. For verdicts the host times, the host's validation settlement to the call of the exchange carrying the
//! verdict and to its application; application to the owner report that hands an accepted message to gossip delivery.
//! Add means of intervals only over comparable populations, never quantiles. With the host's stages, which start at
//! the claim and end at the verdict's exchange call, the means add up to within the host's time from its exchange
//! timestamp to native's call entry (about 12 us median). Times are monotonic nanoseconds of the clock `tick` last
//! advanced, which callers read after taking the runtime mutex.
const std = @import("std");
const limits_mod = @import("../gossip_limits.zig");
const histogram = @import("../metrics/histogram.zig");
const Kind = limits_mod.Kind;
const kind_count = limits_mod.kind_count;

pub const Interval = enum { receipt_to_ready, ready_credit_blocked, ready_other_wait, claimed_to_applied, completed_to_exchange, completed_to_applied, applied_to_forwarded };
pub const interval_count = @typeInfo(Interval).@"enum".fields.len;
/// Why a claim left a kind's next ready item: the kind's execution items or bytes, the claim's item, work or byte
/// bound, an ordinary kind the claim excluded, or none of these (a group whose members all expired).
pub const Stop = enum { item_credit, byte_credit, claim_bound, ordinary_gate, other };
pub const stop_count = @typeInfo(Stop).@"enum".fields.len;
pub const Duration = histogram.Histogram(u64, &.{ 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 20_000_000, 50_000_000, 100_000_000, 200_000_000, 500_000_000, 1_000_000_000, 2_000_000_000, 5_000_000_000 }, .{ .unit = .nanoseconds });

pub const Stages = struct {
    now_ns: u64 = 0,
    intervals: [kind_count][interval_count]Duration = @splat(@splat(.{})),
    stops: [kind_count][stop_count]u64 = @splat(@splat(0)),
    /// Time each kind's next ready item waited on execution credits, closed waits only, and the open wait's start.
    blocked_ns: [kind_count]u64 = @splat(0),
    blocked_since: [kind_count]?u64 = @splat(null),
    /// Executing items and bytes integrated over time up to `integrated_ns`, in item and byte nanoseconds.
    item_ns: [kind_count]u128 = @splat(0),
    byte_ns: [kind_count]u128 = @splat(0),
    integrated_ns: [kind_count]u64 = @splat(0),

    /// Advances the clock; an earlier reading, taken before a mutex another caller held, keeps the later one.
    pub fn tick(self: *Stages, now_ns: u64) void {
        self.now_ns = @max(self.now_ns, now_ns);
    }

    pub fn observe(self: *Stages, kind: Kind, interval: Interval, ns: u64) void {
        self.intervals[@intFromEnum(kind)][@intFromEnum(interval)].observe(ns);
    }

    pub fn stop(self: *Stages, kind: Kind, reason: Stop) void {
        self.stops[@intFromEnum(kind)][@intFromEnum(reason)] +|= 1;
    }

    /// Records whether execution credits refuse the kind's next ready item, from now on.
    pub fn credit(self: *Stages, kind: Kind, refused: bool) void {
        const k = @intFromEnum(kind);
        if (self.blocked_since[k]) |since| {
            if (refused) return;
            self.blocked_ns[k] +|= self.now_ns -| since;
            self.blocked_since[k] = null;
        } else if (refused) self.blocked_since[k] = self.now_ns;
    }

    /// Time the kind's next ready item has waited on execution credits, up to now.
    pub fn blocked(self: *const Stages, kind: Kind) u64 {
        const k = @intFromEnum(kind);
        const open = if (self.blocked_since[k]) |since| self.now_ns -| since else 0;
        return self.blocked_ns[k] +| open;
    }

    /// Accumulates the kind's credits in use since the last change; call it before they change.
    pub fn integrate(self: *Stages, kind: Kind, items: usize, bytes: usize) void {
        const k = @intFromEnum(kind);
        const elapsed = self.now_ns -| self.integrated_ns[k];
        self.item_ns[k] +|= @as(u128, items) * elapsed;
        self.byte_ns[k] +|= @as(u128, bytes) * elapsed;
        self.integrated_ns[k] = self.now_ns;
    }
};
