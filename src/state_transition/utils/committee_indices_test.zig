const std = @import("std");
const committee_indices = @import("committee_indices.zig");
const ComputeShuffledIndex = @import("swap_or_not_shuffle").ComputeShuffledIndex;
const computeProposerIndex = committee_indices.computeProposerIndex;
const computeSyncCommitteeIndices = committee_indices.computeSyncCommitteeIndices;
const ByteCount = committee_indices.ByteCount;

test "ComputeShuffledIndex" {
    const allocator = std.testing.allocator;
    const seed = [_]u8{1} ** 32;
    const index_count = 1000;
    // SHUFFLE_ROUND_COUNT is 90 in ethereum mainnet
    const rounds = 90;

    var instance = try ComputeShuffledIndex.init(allocator, seed[0..], index_count, rounds);
    defer instance.deinit();

    const expected = [_]u32{ 789, 161, 541, 509, 498, 445, 270, 2, 505, 621, 947, 550, 338, 814, 285, 597, 169, 819, 644, 638, 751, 514, 750, 523, 303, 231, 391, 982, 409, 396, 641, 837 };

    for (0..index_count) |i| {
        if (i < 32) {
            const shuffled_index = try instance.get(@intCast(i));
            try std.testing.expectEqual(expected[i], shuffled_index);
        }
    }
}

test "compute_proposer_index" {
    const allocator = std.testing.allocator;
    const seed = [_]u8{1} ** 32;
    const index_count = 1000;
    // SHUFFLE_ROUND_COUNT is 90 in ethereum mainnet
    const rounds = 90;
    var active_indices = [_]u64{0} ** index_count;
    for (0..index_count) |i| {
        active_indices[i] = @intCast(i);
    }
    var effective_balance_increments = [_]u16{0} ** index_count;
    for (0..index_count) |i| {
        effective_balance_increments[i] = @intCast(32 + 32 * (i % 64));
    }
    // phase0
    const MAX_EFFECTIVE_BALANCE: u64 = 32000000000;
    const EFFECTIVE_BALANCE_INCREMENT: u32 = 1000000000;
    const phase0_index = try computeProposerIndex(
        allocator,
        seed[0..],
        active_indices[0..],
        effective_balance_increments[0..],
        ByteCount.One,
        MAX_EFFECTIVE_BALANCE,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds,
    );
    try std.testing.expectEqual(789, phase0_index);

    // electra
    const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2048000000000;
    const electra_index = try computeProposerIndex(
        allocator,
        seed[0..],
        active_indices[0..],
        effective_balance_increments[0..],
        ByteCount.Two,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds,
    );
    try std.testing.expectEqual(161, electra_index);
}

test "compute_sync_committee_indices" {
    const allocator = std.testing.allocator;
    const seed = [_]u8{ 74, 7, 102, 54, 84, 136, 68, 56, 19, 191, 186, 58, 72, 53, 151, 49, 220, 123, 42, 116, 59, 7, 73, 162, 110, 145, 93, 199, 163, 66, 85, 34 };
    const vc = 1000;
    // SHUFFLE_ROUND_COUNT is 90 in ethereum mainnet
    const rounds = 90;
    var active_indices = [_]u64{0} ** vc;
    for (0..vc) |i| {
        active_indices[i] = @intCast(i);
    }
    var effective_balance_increments = [_]u16{0} ** vc;
    for (0..vc) |i| {
        effective_balance_increments[i] = @intCast(32 + 32 * (i % 64));
    }

    // only get first 32 indices to make it easier to test
    var out = [_]u64{0} ** 32;

    // phase0
    const MAX_EFFECTIVE_BALANCE: u64 = 32000000000;
    const EFFECTIVE_BALANCE_INCREMENT: u32 = 1000000000;
    try computeSyncCommitteeIndices(
        allocator,
        seed[0..],
        active_indices[0..],
        effective_balance_increments[0..],
        ByteCount.One,
        MAX_EFFECTIVE_BALANCE,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds,
        out[0..],
    );
    const expected_phase0 = [_]u64{ 293, 726, 771, 677, 530, 475, 322, 66, 521, 106, 774, 23, 508, 410, 526, 44, 213, 948, 248, 903, 85, 853, 171, 679, 309, 791, 851, 817, 609, 119, 128, 983 };
    try std.testing.expectEqualSlices(u64, expected_phase0[0..], out[0..]);

    // electra
    const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2048000000000;
    try computeSyncCommitteeIndices(
        allocator,
        seed[0..],
        active_indices[0..],
        effective_balance_increments[0..],
        ByteCount.Two,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds,
        out[0..],
    );
    const expected_electra = [_]u64{ 726, 475, 521, 23, 508, 410, 213, 948, 248, 85, 171, 309, 791, 817, 119, 126, 651, 416, 273, 471, 739, 290, 588, 840, 665, 945, 496, 158, 757, 616, 226, 766 };
    try std.testing.expectEqualSlices(u64, expected_electra[0..], out[0..]);
}

test "proposer sampling matches cached committee sampling after active list wraps" {
    const active_indices = [_]u64{ 7, 2, 11 };
    const cases = [_]struct {
        byte_count: ByteCount,
        seed_byte: u8,
        balance: u16,
        max_balance: u64,
        expected: [2]u64,
    }{
        .{ .byte_count = .One, .seed_byte = 1, .balance = 32, .max_balance = 32, .expected = .{ 2, 2 } },
        // First acceptance is at i=163 and i=174, after many wraps and hash refreshes.
        .{ .byte_count = .One, .seed_byte = 1, .balance = 1, .max_balance = 32, .expected = .{ 7, 7 } },
        .{ .byte_count = .One, .seed_byte = 1, .balance = 0, .max_balance = 32, .expected = .{ 2, 2 } },
        .{ .byte_count = .Two, .seed_byte = 1, .balance = 2048, .max_balance = 2048, .expected = .{ 2, 2 } },
        // First acceptance is at i=81 and i=231. A zero balance accepts random_value=0.
        .{ .byte_count = .Two, .seed_byte = 1, .balance = 32, .max_balance = 2048, .expected = .{ 2, 2 } },
        .{ .byte_count = .Two, .seed_byte = 104, .balance = 0, .max_balance = 2048, .expected = .{ 11, 7 } },
    };
    for (cases) |case| {
        const seed = [_]u8{case.seed_byte} ** 32;
        var increments = [_]u16{0} ** 12;
        for (active_indices) |index| increments[index] = case.balance;
        for ([_]u32{ 10, 90 }, 0..) |rounds, round_index| {
            for ([_]usize{ 1, active_indices.len }) |count| {
                const proposer = try computeProposerIndex(
                    std.testing.allocator,
                    &seed,
                    active_indices[0..count],
                    &increments,
                    case.byte_count,
                    case.max_balance,
                    1,
                    rounds,
                );
                const expected = if (count == 1) active_indices[0] else case.expected[round_index];
                try std.testing.expectEqual(expected, proposer);
                var cached = [_]u64{0};
                try computeSyncCommitteeIndices(
                    std.testing.allocator,
                    &seed,
                    active_indices[0..count],
                    &increments,
                    case.byte_count,
                    case.max_balance,
                    1,
                    rounds,
                    &cached,
                );
                try std.testing.expectEqual(proposer, cached[0]);
            }
        }
    }
}

test "proposer sampling preserves active order and validator-indexed balances" {
    const active_indices = [_]u64{ 7, 2, 11 };
    const seed = [_]u8{1} ** 32;
    for ([_]ByteCount{ .One, .Two }) |byte_count| {
        const max_balance: u16 = if (byte_count == .One) 32 else 2048;
        var increments = [_]u16{0} ** 12;
        increments[2] = 1;
        increments[11] = max_balance;
        for ([_]u32{ 10, 90 }) |rounds| {
            const proposer = try computeProposerIndex(
                std.testing.allocator,
                &seed,
                &active_indices,
                &increments,
                byte_count,
                max_balance,
                1,
                rounds,
            );
            // The first two candidates, validator 2 then validator 7, are rejected.
            try std.testing.expectEqual(@as(u64, 11), proposer);
        }
    }
}
