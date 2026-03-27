//! Data availability sampling for PeerDAS (Fulu).
//!
//! Nodes verify data availability by randomly sampling columns
//! from peers beyond their custody set. If sampled columns can be
//! retrieved and verified, the node has high confidence that the
//! full data is available across the network.
//!
//! Reference:
//!   consensus-specs/specs/fulu/das-core.md
//!   consensus-specs/specs/fulu/sampling.md

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset_root = @import("preset");

pub const NUMBER_OF_COLUMNS: u64 = preset_root.NUMBER_OF_COLUMNS;

/// Number of random columns to sample per block (spec: SAMPLES_PER_SLOT).
pub const SAMPLES_PER_SLOT: u64 = 8;

/// Root type.
pub const Root = [32]u8;

/// Result of a sampling attempt.
pub const SampleResult = enum {
    /// All sampled columns received and verified — DA confirmed.
    available,
    /// Some sampled columns could not be retrieved — DA not confirmed.
    unavailable,
    /// Sampling requests are still in flight.
    pending,
};

/// Selects random column indices for DA sampling.
///
/// Deterministic given block_root (used as seed), but avoids columns
/// the node already custodies (since those are already verified).
///
/// Returns up to `sample_count` column indices (sorted). Caller owns the slice.
pub fn selectSampleColumns(
    allocator: Allocator,
    block_root: Root,
    custody_columns: []const u64,
    sample_count: u64,
) ![]u64 {
    // Build array of non-custody columns.
    var candidates: [NUMBER_OF_COLUMNS]u64 = undefined;
    var candidate_count: usize = 0;

    for (0..NUMBER_OF_COLUMNS) |i| {
        const col: u64 = @intCast(i);
        var is_custody = false;
        for (custody_columns) |cc| {
            if (cc == col) {
                is_custody = true;
                break;
            }
        }
        if (!is_custody) {
            candidates[candidate_count] = col;
            candidate_count += 1;
        }
    }

    if (candidate_count == 0) {
        return allocator.alloc(u64, 0);
    }

    // Deterministic Fisher-Yates shuffle using block_root as seed.
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&block_root, &seed, .{});

    var idx = candidate_count;
    while (idx > 1) {
        idx -= 1;
        var buf: [32 + 8]u8 = undefined;
        @memcpy(buf[0..32], &seed);
        std.mem.writeInt(u64, buf[32..40], @intCast(idx), .little);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&buf, &hash, .{});
        const rand_val = std.mem.readInt(u64, hash[0..8], .little);
        const j = rand_val % (idx + 1);
        const tmp = candidates[idx];
        candidates[idx] = candidates[j];
        candidates[j] = tmp;
    }

    // Take the first sample_count.
    const take = @min(sample_count, candidate_count);
    const result = try allocator.alloc(u64, take);
    @memcpy(result, candidates[0..take]);

    // Sort for stable output.
    std.sort.pdq(u64, result, {}, std.sort.asc(u64));

    return result;
}

/// DA sampler state machine for a single block.
pub const BlockSampleState = struct {
    block_root: Root,
    /// Columns selected for sampling.
    sample_columns: []const u64,
    /// Which samples have been received and verified.
    received: std.StaticBitSet(NUMBER_OF_COLUMNS),
    /// Current result.
    result: SampleResult,

    pub fn init(block_root: Root, sample_columns: []const u64) BlockSampleState {
        return .{
            .block_root = block_root,
            .sample_columns = sample_columns,
            .received = std.StaticBitSet(NUMBER_OF_COLUMNS).initEmpty(),
            .result = .pending,
        };
    }

    /// Mark a sampled column as received and verified.
    pub fn onSampleReceived(self: *BlockSampleState, column_index: u64) void {
        if (column_index < NUMBER_OF_COLUMNS) {
            self.received.set(column_index);
        }
        self.updateResult();
    }

    /// Mark sampling as failed for a column (no peers had it).
    pub fn onSampleFailed(self: *BlockSampleState, column_index: u64) void {
        _ = column_index;
        self.result = .unavailable;
    }

    fn updateResult(self: *BlockSampleState) void {
        for (self.sample_columns) |col| {
            if (!self.received.isSet(col)) return; // still pending
        }
        self.result = .available;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "selectSampleColumns: deterministic" {
    const allocator = std.testing.allocator;

    const root = [_]u8{0xAA} ** 32;
    const custody = [_]u64{ 10, 20, 30, 40 };

    const samples1 = try selectSampleColumns(allocator, root, &custody, SAMPLES_PER_SLOT);
    defer allocator.free(samples1);

    const samples2 = try selectSampleColumns(allocator, root, &custody, SAMPLES_PER_SLOT);
    defer allocator.free(samples2);

    try std.testing.expectEqualSlices(u64, samples1, samples2);
}

test "selectSampleColumns: avoids custody columns" {
    const allocator = std.testing.allocator;

    const root = [_]u8{0xBB} ** 32;
    const custody = [_]u64{ 0, 1, 2, 3, 4, 5, 6, 7 };

    const samples = try selectSampleColumns(allocator, root, &custody, 16);
    defer allocator.free(samples);

    for (samples) |s| {
        for (custody) |c| {
            try std.testing.expect(s != c);
        }
    }
}

test "selectSampleColumns: correct count" {
    const allocator = std.testing.allocator;

    const root = [_]u8{0xCC} ** 32;
    const custody = [_]u64{0};

    const samples = try selectSampleColumns(allocator, root, &custody, SAMPLES_PER_SLOT);
    defer allocator.free(samples);

    try std.testing.expectEqual(@as(usize, SAMPLES_PER_SLOT), samples.len);
}

test "selectSampleColumns: sorted output" {
    const allocator = std.testing.allocator;

    const root = [_]u8{0xDD} ** 32;
    const custody = [_]u64{};

    const samples = try selectSampleColumns(allocator, root, &custody, 10);
    defer allocator.free(samples);

    for (1..samples.len) |i| {
        try std.testing.expect(samples[i] > samples[i - 1]);
    }
}

test "BlockSampleState: tracks sample completion" {
    const columns = [_]u64{ 10, 20, 30 };
    var state = BlockSampleState.init([_]u8{0xFF} ** 32, &columns);

    try std.testing.expectEqual(SampleResult.pending, state.result);

    state.onSampleReceived(10);
    try std.testing.expectEqual(SampleResult.pending, state.result);

    state.onSampleReceived(20);
    state.onSampleReceived(30);
    try std.testing.expectEqual(SampleResult.available, state.result);
}

test "BlockSampleState: failure propagates" {
    const columns = [_]u64{ 5, 10 };
    var state = BlockSampleState.init([_]u8{0xEE} ** 32, &columns);

    state.onSampleFailed(5);
    try std.testing.expectEqual(SampleResult.unavailable, state.result);
}
