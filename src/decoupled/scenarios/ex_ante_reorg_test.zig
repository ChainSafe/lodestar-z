//! Tests for `ex_ante_reorg.zig`. Each test runs a handful of seeds; a
//! release-mode sweep over many seeds is a separate executable.

const std = @import("std");
const testing = std.testing;
const scenario = @import("ex_ante_reorg.zig");

const seeds: u64 = 24;

test "vote expiry defeats the ex-ante reorg" {
    var seed: u64 = 0;
    while (seed < seeds) : (seed += 1) {
        const result = try scenario.run(testing.allocator, .{ .seed = seed, .rule = .goldfish });
        try testing.expectEqual(scenario.Outcome.honest, result.outcome);
    }
}

test "under LMD-GHOST the released votes reorg the honest chain" {
    var seed: u64 = 0;
    while (seed < seeds) : (seed += 1) {
        const result = try scenario.run(testing.allocator, .{ .seed = seed, .rule = .lmd_ghost });
        try testing.expectEqual(scenario.Outcome.private, result.outcome);
    }
}

test "one seed replays to one digest" {
    const first = try scenario.run(testing.allocator, .{ .seed = 7, .rule = .goldfish });
    const second = try scenario.run(testing.allocator, .{ .seed = 7, .rule = .goldfish });
    try testing.expect(std.mem.eql(u8, &first.digest, &second.digest));
    try testing.expectEqual(first.first_attack_slot, second.first_attack_slot);
    const other = try scenario.run(testing.allocator, .{ .seed = 8, .rule = .goldfish });
    try testing.expect(!std.mem.eql(u8, &first.digest, &other.digest));
}
