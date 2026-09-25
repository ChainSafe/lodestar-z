//! The wall-clock position within the current slot, as basis points of the slot duration. Phases
//! carry no fork's duty times; callers map them to duties from the chain config.
const std = @import("std");
const Now = @import("types.zig").Now;

pub const bps_per_slot = 10_000;
/// Equal metric buckets of the slot phase, each labeled by the first basis point it covers.
pub const phase_buckets = 16;
const bucket_bps = bps_per_slot / phase_buckets;
pub const bucket_labels = blk: {
    var labels: [phase_buckets][]const u8 = undefined;
    for (&labels, 0..) |*label, i| label.* = std.fmt.comptimePrint("{d:0>4}", .{i * bucket_bps});
    break :blk labels;
};

pub const SlotClock = struct {
    genesis_unix_ms: u64,
    slot_duration_ms: u64,
    /// Wall minus monotonic time at the latest clock read, so a monotonic time from any caller
    /// maps to wall time.
    wall_offset_ms: ?i64 = null,

    pub fn validate(self: *const SlotClock) error{InvalidOptions}!void {
        if (self.slot_duration_ms == 0 or self.slot_duration_ms > 3_600_000 or self.genesis_unix_ms > std.math.maxInt(i64)) return error.InvalidOptions;
    }

    pub fn observe(self: *SlotClock, now: Now) void {
        const wall = now.unix_ms orelse return;
        self.wall_offset_ms = @as(i64, @intCast(wall)) - @as(i64, @intCast(now.mono_ms));
    }

    /// The phase at monotonic time `mono_ms`: 0 at the slot's start, at most 9,999. Null before
    /// the first wall clock read or before genesis.
    pub fn phaseBps(self: *const SlotClock, mono_ms: u64) ?u16 {
        const wall = @as(i64, @intCast(mono_ms)) + (self.wall_offset_ms orelse return null);
        if (wall < @as(i64, @intCast(self.genesis_unix_ms))) return null;
        const into = (@as(u64, @intCast(wall)) - self.genesis_unix_ms) % self.slot_duration_ms;
        return @intCast(into * bps_per_slot / self.slot_duration_ms);
    }

    pub fn bucket(bps: u16) usize {
        std.debug.assert(bps < bps_per_slot);
        return bps / bucket_bps;
    }

    /// Adds to each phase bucket the milliseconds of `[from_ms, to_ms)` in monotonic time that
    /// fell in it. Returns false, adding nothing, when the interval has no known phase.
    pub fn split(self: *const SlotClock, from_ms: u64, to_ms: u64, out: *[phase_buckets]u64) bool {
        std.debug.assert(from_ms <= to_ms);
        const offset = self.wall_offset_ms orelse return false;
        const from = @as(i64, @intCast(from_ms)) + offset - @as(i64, @intCast(self.genesis_unix_ms));
        if (from < 0) return false;
        const slot = self.slot_duration_ms;
        var at: u64 = @intCast(from);
        const end = at + (to_ms - from_ms);
        const whole = (end - at) / slot;
        if (whole > 0) for (out, 0..) |*total, index| {
            total.* += whole * (bucketStart(slot, index + 1) - bucketStart(slot, index));
        };
        at += whole * slot;
        for (0..phase_buckets + 1) |_| {
            if (at == end) break;
            const into = at % slot;
            const index: usize = @intCast(into * phase_buckets / slot);
            const step = @min(end - at, bucketStart(slot, index + 1) - into);
            out[index] += step;
            at += step;
        }
        std.debug.assert(at == end);
        return true;
    }

    /// The first millisecond of the slot in bucket `index`, whose phase is `index * bucket_bps`.
    fn bucketStart(slot: u64, index: usize) u64 {
        return (index * slot + phase_buckets - 1) / phase_buckets;
    }
};

test "slot phase follows wall time from genesis in basis points of the slot" {
    const genesis = 1_742_213_400_000;
    var clock: SlotClock = .{ .genesis_unix_ms = genesis, .slot_duration_ms = 12_000 };
    try clock.validate();
    try std.testing.expectEqual(@as(?u16, null), clock.phaseBps(0));
    // Monotonic 1,000 ms is 3 s into slot 10.
    clock.observe(.{ .mono_ms = 1_000, .unix_s = 0, .unix_ms = genesis + 10 * 12_000 + 3_000 });
    try std.testing.expectEqual(@as(?u16, 2_500), clock.phaseBps(1_000));
    try std.testing.expectEqual(@as(?u16, 9_999), clock.phaseBps(1_000 + 8_999));
    try std.testing.expectEqual(@as(?u16, 0), clock.phaseBps(1_000 + 9_000));
    // A read without wall time keeps the last offset.
    clock.observe(.{ .mono_ms = 5, .unix_s = 0 });
    try std.testing.expectEqual(@as(?u16, 2_500), clock.phaseBps(1_000));
    try std.testing.expectEqual(@as(usize, 4), SlotClock.bucket(2_500));
    try std.testing.expectEqual(@as(usize, phase_buckets - 1), SlotClock.bucket(9_999));
    try std.testing.expectEqualStrings("0000", bucket_labels[0]);
    try std.testing.expectEqualStrings("2500", bucket_labels[4]);
    try std.testing.expectEqualStrings("9375", bucket_labels[phase_buckets - 1]);
    var early: SlotClock = .{ .genesis_unix_ms = genesis, .slot_duration_ms = 12_000 };
    early.observe(.{ .mono_ms = 1_000, .unix_s = 0, .unix_ms = genesis - 1 });
    try std.testing.expectEqual(@as(?u16, null), early.phaseBps(1_000));
    try std.testing.expectEqual(@as(?u16, 0), early.phaseBps(1_001));
    // An interval splits across the buckets it crosses, whole slots included.
    var spans: [phase_buckets]u64 = @splat(0);
    try std.testing.expect(clock.split(1_000, 1_000 + 12_000 + 1_500, &spans));
    for (spans, 0..) |span, index| try std.testing.expectEqual(@as(u64, if (index == 4 or index == 5) 1_500 else 750), span);
    try std.testing.expect(!early.split(0, 1_000, &spans));
    clock.slot_duration_ms = 0;
    try std.testing.expectError(error.InvalidOptions, clock.validate());
}
