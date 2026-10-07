//! Proposer and committee assignment for a run. The paper takes both as
//! inputs (PROTOCOL.md A.1); the election is not modeled. `honest` marks
//! which validators run an honest node.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const types = @import("types.zig");

const Slot = types.Slot;
const ValidatorIndex = types.ValidatorIndex;

pub const Schedule = struct {
    validator_count: u32,
    honest: [limits.max_validators]bool,
    proposer: [limits.max_slots]ValidatorIndex,
    committee: [limits.max_slots][limits.max_validators]bool,

    /// Every validator honest, validator 0 proposes every slot, no committees.
    pub fn blank(validator_count: u32) Schedule {
        assert(validator_count > 0);
        assert(validator_count <= limits.max_validators);
        var schedule: Schedule = .{
            .validator_count = validator_count,
            .honest = [_]bool{false} ** limits.max_validators,
            .proposer = [_]ValidatorIndex{0} ** limits.max_slots,
            .committee = undefined,
        };
        for (0..validator_count) |v| schedule.honest[v] = true;
        for (&schedule.committee) |*row| @memset(row, false);
        return schedule;
    }

    pub fn isHonest(self: *const Schedule, v: ValidatorIndex) bool {
        assert(v < self.validator_count);
        return self.honest[v];
    }

    pub fn inCommittee(self: *const Schedule, s: Slot, v: ValidatorIndex) bool {
        assert(s < limits.max_slots);
        assert(v < self.validator_count);
        return self.committee[s][v];
    }

    pub fn committeeSize(self: *const Schedule, s: Slot) u32 {
        assert(s < limits.max_slots);
        var size: u32 = 0;
        for (0..self.validator_count) |v| {
            if (self.committee[s][v]) size += 1;
        }
        assert(size <= limits.max_committee);
        return size;
    }

    pub fn honestCommitteeCount(self: *const Schedule, s: Slot) u32 {
        assert(s < limits.max_slots);
        var count: u32 = 0;
        for (0..self.validator_count) |v| {
            if (self.committee[s][v] and self.honest[v]) count += 1;
        }
        assert(count <= self.committeeSize(s));
        return count;
    }

    /// `HonestCommittees` for one slot: a strict honest majority by count.
    pub fn honestMajority(self: *const Schedule, s: Slot) bool {
        return 2 * self.honestCommitteeCount(s) > self.committeeSize(s);
    }

    pub fn honestCount(self: *const Schedule) u32 {
        var count: u32 = 0;
        for (0..self.validator_count) |v| {
            if (self.honest[v]) count += 1;
        }
        assert(count <= self.validator_count);
        return count;
    }
};

test "honest majority counts members, not weight" {
    var schedule = Schedule.blank(4);
    schedule.committee[1][0] = true;
    schedule.committee[1][1] = true;
    schedule.committee[1][2] = true;
    schedule.honest[2] = false;
    try std.testing.expectEqual(@as(u32, 3), schedule.committeeSize(1));
    try std.testing.expect(schedule.honestMajority(1));
    schedule.honest[1] = false;
    try std.testing.expect(!schedule.honestMajority(1));
    try std.testing.expectEqual(@as(u32, 2), schedule.honestCount());
}
