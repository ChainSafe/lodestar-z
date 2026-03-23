const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const ct = @import("consensus_types");
const AnyBeaconState = @import("fork_types").AnyBeaconState;

const Validator = ct.phase0.Validator;
const Validators = ct.phase0.Validators;
const InactivityScores = ct.altair.InactivityScores;

/// Size of a single serialized Validator in SSZ (fixed-size container).
pub const VALIDATOR_BYTES_SIZE: usize = Validator.fixed_size;

/// Size of a single inactivity score (UintNum64 = 8 bytes).
pub const INACTIVITY_SCORE_SIZE: usize = 8;

/// Result of loading a state from bytes using a seed state.
pub const LoadStateResult = struct {
    state: AnyBeaconState,
    modified_validators: []u32,
};

/// Find modified items by binary-search byte comparison.
///
/// Recursively compares two byte arrays representing serialized lists of fixed-size items.
/// Returns the indices of items that differ between seed and new bytes.
/// This is O(n) best case (all equal), O(k * log n) for k modified items.
///
/// Caller owns the returned slice and must free with the same allocator.
pub fn findModifiedItems(
    allocator: Allocator,
    seed_bytes: []const u8,
    new_bytes: []const u8,
    item_size: usize,
) ![]u32 {
    var result: std.ArrayList(u32) = .empty;
    errdefer result.deinit(allocator);

    // Only compare the common range (shorter of the two)
    const seed_count = seed_bytes.len / item_size;
    const new_count = new_bytes.len / item_size;
    const common_count = @min(seed_count, new_count);

    if (common_count > 0) {
        const common_bytes = common_count * item_size;
        try findModifiedItemsRecursive(
            allocator,
            &result,
            seed_bytes[0..common_bytes],
            new_bytes[0..common_bytes],
            item_size,
            0,
        );
    }

    // New items appended beyond seed are all "modified" (new)
    if (new_count > seed_count) {
        try result.ensureUnusedCapacity(allocator, new_count - seed_count);
        for (seed_count..new_count) |i| {
            result.appendAssumeCapacity(@intCast(i));
        }
    }

    return result.toOwnedSlice(allocator);
}

fn findModifiedItemsRecursive(
    allocator: Allocator,
    result: *std.ArrayList(u32),
    seed_bytes: []const u8,
    new_bytes: []const u8,
    item_size: usize,
    offset: u32,
) !void {
    std.debug.assert(seed_bytes.len == new_bytes.len);

    // Fast path: entire range is identical
    if (std.mem.eql(u8, seed_bytes, new_bytes)) {
        return;
    }

    // Base case: single item differs
    if (seed_bytes.len == item_size) {
        try result.append(allocator, offset);
        return;
    }

    // Recurse on halves
    const num_items = seed_bytes.len / item_size;
    const half = num_items / 2;
    const half_bytes = half * item_size;

    try findModifiedItemsRecursive(
        allocator,
        result,
        seed_bytes[0..half_bytes],
        new_bytes[0..half_bytes],
        item_size,
        offset,
    );
    try findModifiedItemsRecursive(
        allocator,
        result,
        seed_bytes[half_bytes..],
        new_bytes[half_bytes..],
        item_size,
        offset + @as(u32, @intCast(half)),
    );
}

/// Load a beacon state from SSZ bytes, sharing unchanged tree nodes with a seed state.
///
/// The approach:
/// 1. Deserialize the new state fully from bytes.
/// 2. For the validators list: clone seed's tree, find modified validators via binary diff,
///    and patch only the changed entries. This shares tree nodes for unchanged validators.
/// 3. Same optimization for inactivity_scores (altair+).
/// 4. Return the new state and indices of modified validators.
pub fn loadState(
    allocator: Allocator,
    pool: *Node.Pool,
    seed_state: *AnyBeaconState,
    fork_seq: ForkSeq,
    state_bytes: []const u8,
    seed_validators_bytes: ?[]const u8,
) !LoadStateResult {
    // 1. Deserialize the full new state
    var new_state = try AnyBeaconState.deserialize(allocator, pool, fork_seq, state_bytes);
    errdefer new_state.deinit();

    // 2. Get the serialized validators byte ranges from state_bytes
    const validators_range = try getValidatorsRange(fork_seq, state_bytes);
    const new_validators_bytes = state_bytes[validators_range[0]..validators_range[1]];

    // Get seed validators bytes — use provided cache or serialize from seed
    var owned_seed_validators_bytes: ?[]u8 = null;
    defer if (owned_seed_validators_bytes) |b| allocator.free(b);

    const actual_seed_validators_bytes: []const u8 = if (seed_validators_bytes) |svb|
        svb
    else blk: {
        var seed_validators = try seed_state.validators();
        const size = try seed_validators.serializedSize();
        const buf = try allocator.alloc(u8, size);
        _ = try seed_validators.serializeIntoBytes(buf);
        owned_seed_validators_bytes = buf;
        break :blk buf;
    };

    // 3. Find modified validators via binary diff
    const modified_validators = try findModifiedItems(
        allocator,
        actual_seed_validators_bytes,
        new_validators_bytes,
        VALIDATOR_BYTES_SIZE,
    );

    // 4. Optimize validators: clone seed's validators tree, then patch modified entries
    try loadValidators(&new_state, seed_state, new_validators_bytes, actual_seed_validators_bytes, modified_validators);

    // 5. Optimize inactivity_scores for altair+ forks
    const seed_fork = seed_state.forkSeq();
    if (fork_seq.gte(.altair) and seed_fork.gte(.altair)) {
        const inactivity_scores_range = try getInactivityScoresRange(fork_seq, state_bytes);
        const new_inactivity_bytes = state_bytes[inactivity_scores_range[0]..inactivity_scores_range[1]];
        try loadInactivityScores(allocator, pool, &new_state, seed_state, new_inactivity_bytes);
    }

    // 6. Commit the new state
    try new_state.commit();

    return .{
        .state = new_state,
        .modified_validators = modified_validators,
    };
}

/// Replace the validators list in new_state with seed's tree, patching only modified validators.
fn loadValidators(
    new_state: *AnyBeaconState,
    seed_state: *AnyBeaconState,
    new_validators_bytes: []const u8,
    seed_validators_bytes: []const u8,
    modified_indices: []const u32,
) !void {
    const seed_validator_count = seed_validators_bytes.len / VALIDATOR_BYTES_SIZE;
    const new_validator_count = new_validators_bytes.len / VALIDATOR_BYTES_SIZE;

    // Clone seed's validators tree
    var seed_validators_view = try seed_state.validators();
    var cloned_validators = try seed_validators_view.clone(.{});
    errdefer cloned_validators.deinit();

    // Patch modified validators in the common range
    for (modified_indices) |idx| {
        if (idx < seed_validator_count) {
            const start = @as(usize, idx) * VALIDATOR_BYTES_SIZE;
            const end = start + VALIDATOR_BYTES_SIZE;
            const validator_bytes = new_validators_bytes[start..end];

            // Deserialize the modified validator and set it in the cloned tree
            var new_validator: Validator.Type = undefined;
            try Validator.deserializeFromBytes(validator_bytes, &new_validator);
            try cloned_validators.setValue(idx, &new_validator);
        }
    }

    // Handle new validators appended beyond seed
    if (new_validator_count > seed_validator_count) {
        for (seed_validator_count..new_validator_count) |i| {
            const start = i * VALIDATOR_BYTES_SIZE;
            const end = start + VALIDATOR_BYTES_SIZE;
            const validator_bytes = new_validators_bytes[start..end];

            var new_validator: Validator.Type = undefined;
            try Validator.deserializeFromBytes(validator_bytes, &new_validator);
            try cloned_validators.pushValue(&new_validator);
        }
    } else if (new_validator_count < seed_validator_count) {
        // Fewer validators in new state — truncate
        const truncated = try cloned_validators.sliceTo(new_validator_count - 1);
        cloned_validators.deinit();
        cloned_validators = truncated;
    }

    // Replace new_state's validators with the optimized cloned tree
    try setValidators(new_state, cloned_validators);
}

/// Replace the inactivity_scores list in new_state with seed's tree, patching only modified scores.
fn loadInactivityScores(
    allocator: Allocator,
    pool: *Node.Pool,
    new_state: *AnyBeaconState,
    seed_state: *AnyBeaconState,
    new_inactivity_bytes: []const u8,
) !void {
    var seed_scores_view = try seed_state.inactivityScores();
    var cloned_scores = try seed_scores_view.clone(.{});
    errdefer cloned_scores.deinit();

    const old_count = try cloned_scores.length();
    const new_count = new_inactivity_bytes.len / INACTIVITY_SCORE_SIZE;
    const min_count = @min(old_count, new_count);

    // Serialize seed's inactivity scores for comparison
    const seed_size = try seed_scores_view.serializedSize();
    const seed_inactivity_bytes = try allocator.alloc(u8, seed_size);
    defer allocator.free(seed_inactivity_bytes);
    _ = try seed_scores_view.serializeIntoBytes(seed_inactivity_bytes);

    // Find modified scores via binary diff
    const common_seed = seed_inactivity_bytes[0 .. min_count * INACTIVITY_SCORE_SIZE];
    const common_new = new_inactivity_bytes[0 .. min_count * INACTIVITY_SCORE_SIZE];
    const modified_scores = try findModifiedItems(
        allocator,
        common_seed,
        common_new,
        INACTIVITY_SCORE_SIZE,
    );
    defer allocator.free(modified_scores);

    // Patch modified scores
    for (modified_scores) |idx| {
        const start = @as(usize, idx) * INACTIVITY_SCORE_SIZE;
        const score = std.mem.readInt(u64, new_inactivity_bytes[start..][0..8], .little);
        try cloned_scores.set(idx, score);
    }

    // Handle new scores appended
    if (new_count > old_count) {
        for (old_count..new_count) |i| {
            const start = i * INACTIVITY_SCORE_SIZE;
            const score = std.mem.readInt(u64, new_inactivity_bytes[start..][0..8], .little);
            try cloned_scores.push(score);
        }
    } else if (new_count < old_count) {
        if (new_count == 0) {
            cloned_scores.deinit();
            cloned_scores = try InactivityScores.TreeView.fromValue(allocator, pool, &InactivityScores.default_value);
        } else {
            const truncated = try cloned_scores.sliceTo(new_count - 1);
            cloned_scores.deinit();
            cloned_scores = truncated;
        }
    }

    // Replace inactivity_scores in new_state
    try setInactivityScores(new_state, cloned_scores);
}

/// Set validators on AnyBeaconState across all forks.
fn setValidators(state: *AnyBeaconState, validators: *Validators.TreeView) !void {
    switch (state.*) {
        inline else => |s| try s.set("validators", validators),
    }
}

/// Set inactivity_scores on AnyBeaconState for altair+ forks.
fn setInactivityScores(state: *AnyBeaconState, scores: *InactivityScores.TreeView) !void {
    switch (state.*) {
        .phase0 => {}, // phase0 has no inactivity_scores
        inline else => |s| try s.set("inactivity_scores", scores),
    }
}

/// Get the byte range [start, end] for the validators field in serialized state bytes.
fn getValidatorsRange(fork_seq: ForkSeq, state_bytes: []const u8) ![2]usize {
    return switch (fork_seq) {
        inline else => |f| {
            const StateType = @import("fork_types").ForkTypes(f).BeaconState;
            const ranges = try StateType.readFieldRanges(state_bytes);
            const idx = comptime StateType.getFieldIndex("validators");
            return ranges[idx];
        },
    };
}

/// Get the byte range [start, end] for the inactivity_scores field in serialized state bytes.
fn getInactivityScoresRange(fork_seq: ForkSeq, state_bytes: []const u8) ![2]usize {
    return switch (fork_seq) {
        .phase0 => error.InvalidAtFork,
        inline else => |f| {
            const StateType = @import("fork_types").ForkTypes(f).BeaconState;
            const ranges = try StateType.readFieldRanges(state_bytes);
            const idx = comptime StateType.getFieldIndex("inactivity_scores");
            return ranges[idx];
        },
    };
}

// =============================================================================
// Tests
// =============================================================================

test "findModifiedItems - all identical returns empty" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    const result = try findModifiedItems(allocator, &data, &data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "findModifiedItems - single item changed" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const seed = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var new_data = seed;
    new_data[5] = 99; // modify second item

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u32, 1), result[0]);
}

test "findModifiedItems - multiple scattered changes" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    // 8 items = 32 bytes
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    var new_data = seed;
    new_data[0] = 255; // item 0
    new_data[12] = 255; // item 3
    new_data[28] = 255; // item 7

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqual(@as(u32, 0), result[0]);
    try std.testing.expectEqual(@as(u32, 3), result[1]);
    try std.testing.expectEqual(@as(u32, 7), result[2]);
}

test "findModifiedItems - new items appended" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const seed = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }; // 2 items
    const new_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }; // 3 items (1 appended)

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u32, 2), result[0]); // new item at index 2
}

test "findModifiedItems - fewer items in new" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const seed = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }; // 3 items
    const new_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }; // 2 items

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "findModifiedItems - validator-sized items" {
    const allocator = std.testing.allocator;
    // Simulate 4 validators, modify one
    const count = 4;
    var seed: [count * VALIDATOR_BYTES_SIZE]u8 = undefined;
    @memset(&seed, 0);
    // Give each validator a distinct pubkey byte
    for (0..count) |i| {
        seed[i * VALIDATOR_BYTES_SIZE] = @intCast(i);
    }
    var new_data = seed;
    // Modify validator 2's effective_balance (offset 80 within validator)
    new_data[2 * VALIDATOR_BYTES_SIZE + 80] = 42;

    const result = try findModifiedItems(allocator, &seed, &new_data, VALIDATOR_BYTES_SIZE);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u32, 2), result[0]);
}

test "findModifiedItems - empty inputs" {
    const allocator = std.testing.allocator;
    const empty: []const u8 = &.{};

    const result = try findModifiedItems(allocator, empty, empty, 4);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "findModifiedItems - all items changed" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const seed = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const new_data = [_]u8{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqual(@as(u32, 0), result[0]);
    try std.testing.expectEqual(@as(u32, 1), result[1]);
    try std.testing.expectEqual(@as(u32, 2), result[2]);
}

test "findModifiedItems - single item" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const seed = [_]u8{ 1, 2, 3, 4 };
    const new_data = [_]u8{ 1, 2, 3, 5 };

    const result = try findModifiedItems(allocator, &seed, &new_data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u32, 0), result[0]);
}

test "findModifiedItems - single item identical" {
    const allocator = std.testing.allocator;
    const item_size: usize = 4;
    const data = [_]u8{ 1, 2, 3, 4 };

    const result = try findModifiedItems(allocator, &data, &data, item_size);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}
