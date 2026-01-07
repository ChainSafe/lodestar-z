const std = @import("std");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ChainConfig = @import("./ChainConfig.zig");
const Epoch = types.primitive.Epoch.Type;
const Slot = types.primitive.Slot.Type;
const Version = types.primitive.Version.Type;

/// Ordered consensus fork identifiers used throughout the client.
///
/// The numeric values define the canonical chronological ordering of forks.
// Implementors note: when adding a new fork, append it to preserve ordering and update any
// tests that enumerate names.
pub const ForkSeq = enum(u8) {
    phase0 = 0,
    altair = 1,
    bellatrix = 2,
    capella = 3,
    deneb = 4,
    electra = 5,
    fulu = 6,

    /// Total number of fork variants.
    pub const count: u8 = @intCast(@typeInfo(ForkSeq).@"enum".fields.len);

    /// Returns the canonical tag name for this fork (e.g. `"capella"`).
    pub fn name(self: ForkSeq) [:0]const u8 {
        return @tagName(self);
    }

    /// Parses a fork name into a `ForkSeq`.
    ///
    /// If `fork_name` does not match any known fork tag name exactly, this returns
    /// `.phase0` as a safe default.
    pub fn fromName(fork_name: []const u8) ForkSeq {
        const values = comptime std.enums.values(ForkSeq);
        inline for (values) |fork_seq| {
            if (std.mem.eql(u8, fork_seq.name(), fork_name)) {
                return fork_seq;
            }
        }

        return ForkSeq.phase0;
    }

    /// Returns `true` if `self` is strictly earlier than `other` in fork order.
    pub inline fn lt(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) < @intFromEnum(other);
    }

    /// Returns `true` if `self` is earlier than or equal to `other` in fork order.
    pub inline fn lte(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }

    /// Returns `true` if `self` is strictly later than `other` in fork order.
    pub inline fn gt(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) > @intFromEnum(other);
    }

    /// Returns `true` if `self` is later than or equal to `other` in fork order.
    pub inline fn gte(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
    }
};

test "fork - ForkSeq.name" {
    try std.testing.expectEqualSlices(u8, "phase0", ForkSeq.phase0.name());
    try std.testing.expectEqualSlices(u8, "altair", ForkSeq.altair.name());
    try std.testing.expectEqualSlices(u8, "bellatrix", ForkSeq.bellatrix.name());
    try std.testing.expectEqualSlices(u8, "capella", ForkSeq.capella.name());
    try std.testing.expectEqualSlices(u8, "deneb", ForkSeq.deneb.name());
    try std.testing.expectEqualSlices(u8, "electra", ForkSeq.electra.name());
    try std.testing.expectEqualSlices(u8, "fulu", ForkSeq.fulu.name());
}

test "fork - ForkSeq.fromName" {
    try std.testing.expectEqual(ForkSeq.phase0, ForkSeq.fromName("phase0"));
    try std.testing.expectEqual(ForkSeq.altair, ForkSeq.fromName("altair"));
    try std.testing.expectEqual(ForkSeq.bellatrix, ForkSeq.fromName("bellatrix"));
    try std.testing.expectEqual(ForkSeq.capella, ForkSeq.fromName("capella"));
    try std.testing.expectEqual(ForkSeq.deneb, ForkSeq.fromName("deneb"));
    try std.testing.expectEqual(ForkSeq.electra, ForkSeq.fromName("electra"));
    try std.testing.expectEqual(ForkSeq.fulu, ForkSeq.fromName("fulu"));
}
