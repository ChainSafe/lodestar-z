const std = @import("std");
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const Version = types.primitive.Version.Type;

pub const TOTAL_FORKS = 7;

pub const ForkSeq = enum(u8) {
    phase0 = 0,
    altair = 1,
    bellatrix = 2,
    capella = 3,
    deneb = 4,
    electra = 5,
    fulu = 6,

    pub fn forkName(self: ForkSeq) []const u8 {
        return @tagName(self);
    }

    pub inline fn lt(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) < @intFromEnum(other);
    }

    pub inline fn lte(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }

    pub inline fn gt(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) > @intFromEnum(other);
    }

    pub inline fn gte(self: ForkSeq, other: ForkSeq) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
    }

    pub fn isPostAltair(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0 => false,
            else => true,
        };
    }

    pub fn isPostBellatrix(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0, .altair => false,
            else => true,
        };
    }

    pub fn isPostCapella(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0, .altair, .bellatrix => false,
            else => true,
        };
    }

    pub fn isPostDeneb(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0, .altair, .bellatrix, .capella => false,
            else => true,
        };
    }

    pub fn isPostElectra(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => false,
            else => true,
        };
    }

    pub fn isPostFulu(self: ForkSeq) bool {
        return switch (self) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => false,
            else => true,
        };
    }
};

pub fn forkSeqByForkName(fork_name: []const u8) ForkSeq {
    const values = comptime std.enums.values(ForkSeq);
    inline for (values) |fork_seq| {
        if (std.mem.eql(u8, fork_seq.forkName(), fork_name)) {
            return fork_seq;
        }
    }

    return ForkSeq.phase0;
}

pub const ForkInfo = struct {
    fork_seq: ForkSeq,
    epoch: Epoch,
    version: Version,
    prev_version: Version,
    prev_fork_seq: ForkSeq,
};

test "fork - forkName" {
    try std.testing.expectEqualSlices(u8, "phase0", ForkSeq.phase0.forkName());
    try std.testing.expectEqualSlices(u8, "altair", ForkSeq.altair.forkName());
    try std.testing.expectEqualSlices(u8, "bellatrix", ForkSeq.bellatrix.forkName());
    try std.testing.expectEqualSlices(u8, "capella", ForkSeq.capella.forkName());
    try std.testing.expectEqualSlices(u8, "deneb", ForkSeq.deneb.forkName());
    try std.testing.expectEqualSlices(u8, "electra", ForkSeq.electra.forkName());
    try std.testing.expectEqualSlices(u8, "fulu", ForkSeq.fulu.forkName());
}

test "fork - forkSeqByForkName" {
    try std.testing.expect(ForkSeq.phase0 == forkSeqByForkName("phase0"));
    try std.testing.expect(ForkSeq.altair == forkSeqByForkName("altair"));
    try std.testing.expect(ForkSeq.bellatrix == forkSeqByForkName("bellatrix"));
    try std.testing.expect(ForkSeq.capella == forkSeqByForkName("capella"));
    try std.testing.expect(ForkSeq.deneb == forkSeqByForkName("deneb"));
    try std.testing.expect(ForkSeq.electra == forkSeqByForkName("electra"));
    try std.testing.expect(ForkSeq.fulu == forkSeqByForkName("fulu"));
}
