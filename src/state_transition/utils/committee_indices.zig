const std = @import("std");
const builtin = @import("builtin");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;
const swap_or_not_shuffle = @import("swap_or_not_shuffle");

const ACTIVE_INDICES_LENGTH_MAX: usize = std.math.maxInt(u32);
// The active-index bound keeps shuffled positions in u32; validator indices remain u64.
const ComputeShuffledIndex = swap_or_not_shuffle.ComputeShuffledIndex;
// Extra source-hash recomputation can outweigh cache savings with software SHA.
const ProposerShuffledIndex = if (builtin.zig_backend != .stage2_c and switch (builtin.cpu.arch) {
    .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }),
    .aarch64 => builtin.cpu.has(.aarch64, .sha2),
    else => false,
}) swap_or_not_shuffle.ComputeShuffledIndexSingleSource else ComputeShuffledIndex;

pub fn computeProposerIndex(
    allocator: Allocator,
    seed: *const [32]u8,
    active_indices: []const u64,
    effective_balance_increments: []u16,
    rand_byte_count: ByteCount,
    max_effective_balance: u64,
    effective_balance_increment: u32,
    rounds: u32,
) !u64 {
    var out = [_]u64{0};
    try getCommitteeIndices(
        ProposerShuffledIndex,
        allocator,
        seed,
        active_indices,
        effective_balance_increments,
        rand_byte_count,
        max_effective_balance,
        effective_balance_increment,
        rounds,
        out[0..],
    );
    return out[0];
}

pub fn computeSyncCommitteeIndices(
    allocator: Allocator,
    seed: *const [32]u8,
    active_indices: []const u64,
    effective_balance_increments: []u16,
    rand_byte_count: ByteCount,
    max_effective_balance_electra: u64,
    effective_balance_increment: u32,
    rounds: u32,
    out: []u64,
) !void {
    try getCommitteeIndices(
        ComputeShuffledIndex,
        allocator,
        seed,
        active_indices,
        effective_balance_increments,
        rand_byte_count,
        max_effective_balance_electra,
        effective_balance_increment,
        rounds,
        out,
    );
}

pub const ByteCount = enum(u8) {
    One = 1,
    Two = 2,
};

/// the same to Rust implementation with "out" param to simplify memory allocation
/// T should be u32 for Bun or ValidatorIndex for zig consumer
fn getCommitteeIndices(
    comptime ShuffledIndex: type,
    allocator: Allocator,
    seed: *const [32]u8,
    active_indices: []const u64,
    effective_balance_increments: []const u16,
    rand_byte_count: ByteCount,
    max_effective_balance: u64,
    effective_balance_increment: u32,
    rounds: u32,
    out: []u64,
) !void {
    const max_random_value: u32 = switch (rand_byte_count) {
        .One => 0xff,
        .Two => 0xffff,
    };
    const max_effective_balance_increment: u64 = max_effective_balance / effective_balance_increment;

    if (active_indices.len == 0) {
        return error.InvalidIndexCount;
    }
    if (rounds == 0) {
        return error.InvalidRounds;
    }
    if (active_indices.len > ACTIVE_INDICES_LENGTH_MAX) {
        return error.InvalidIndexCount;
    }

    var compute_shuffled_index = try ShuffledIndex.init(
        allocator,
        seed,
        @intCast(active_indices.len),
        rounds,
    );
    defer compute_shuffled_index.deinit();

    var shuffled_result = std.AutoHashMap(u64, u64).init(allocator);
    defer shuffled_result.deinit();

    var i: u32 = 0;
    var cached_hash_input = [_]u8{0} ** (32 + 8);
    // seed should have 32 bytes as checked in ComputeShuffledIndex.init
    @memcpy(cached_hash_input[0..32], seed);
    var cached_hash = [_]u8{0} ** 32;
    var next_committee_index: usize = 0;

    while (next_committee_index < out.len) {
        const index: u64 = @intCast(i % active_indices.len);
        const shuffled_index = try shuffled_result.getOrPut(index);
        if (!shuffled_index.found_existing) {
            const _shuffled_index = try compute_shuffled_index.get(@intCast(index));
            shuffled_index.value_ptr.* = _shuffled_index;
        }
        const candidate_index = active_indices[@intCast(shuffled_index.value_ptr.*)];

        const hash_increment: u32 = 32 / @intFromEnum(rand_byte_count);
        if (i % hash_increment == 0) {
            // this is the same to below Rust implementation
            // cached_hash_input[32..36].copy_from_slice(&(i / hash_increment).to_le_bytes());
            std.mem.writeInt(u32, cached_hash_input[32..][0..4], i / hash_increment, .little);

            Sha256.hash(cached_hash_input[0..], cached_hash[0..], .{});
        }

        const random_bytes = cached_hash;
        const random_value: u16 = switch (rand_byte_count) {
            .One => blk: {
                const offset = i % hash_increment;
                break :blk @intCast(random_bytes[offset]);
            },
            .Two => blk: {
                const offset = (i % hash_increment) * 2;
                break :blk std.mem.readInt(u16, random_bytes[offset..][0..2], .little);
            },
        };

        const candidate_effective_balance_increment = effective_balance_increments[@intCast(candidate_index)];
        if (candidate_effective_balance_increment * max_random_value >= max_effective_balance_increment * random_value) {
            out[next_committee_index] = candidate_index;
            next_committee_index += 1;
        }

        i += 1;
    }
}

test {
    _ = @import("committee_indices_test.zig");
}
