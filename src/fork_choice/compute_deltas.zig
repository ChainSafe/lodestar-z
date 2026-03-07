const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const math = std.math;
const testing = std.testing;

const vote_tracker = @import("vote_tracker.zig");
const Votes = vote_tracker.Votes;
const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

const consensus_types = @import("consensus_types");
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;

pub const VoteIndex = u32;

/// Set of equivocating validator indices.
pub const EquivocatingIndices = std.AutoArrayHashMap(ValidatorIndex, void);

/// Diagnostic counters from a computeDeltas call.
/// Used for monitoring fork choice health (not for correctness).
pub const ComputeDeltasResult = struct {
    deltas: []i64,
    equivocating_validators: u32 = 0,
    old_inactive_validators: u32 = 0,
    new_inactive_validators: u32 = 0,
    unchanged_vote_validators: u32 = 0,
    new_vote_validators: u32 = 0,
};

/// Type alias for the per-node deltas buffer, instantiated by the caller (typically ForkChoice).
pub const DeltasCache = std.ArrayListUnmanaged(i64);

/// Computes per-node weight deltas from vote changes and balance updates.
///
/// For each validator, compares current_index (last applied vote) with
/// next_index (pending vote) and old/new balances. Subtracts old balance
/// from the departing node, adds new balance to the arriving node.
///
/// Equivocating validators have their weight removed and votes zeroed
/// so they are only penalized once across multiple calls.
///
/// Mutates:
///   - `deltas_cache`: resized and zeroed, weight changes per proto-array node
///   - `vote_current_indices`: current_index updated to next_index (commits pending votes)
pub fn computeDeltas(
    allocator: Allocator,
    deltas_cache: *DeltasCache,
    num_proto_nodes: usize,
    vote_current_indices: []VoteIndex,
    vote_next_indices: []const VoteIndex,
    old_balances: []const u16,
    new_balances: []const u16,
    equivocating_indices: EquivocatingIndices,
) !ComputeDeltasResult {
    assert(vote_current_indices.len == vote_next_indices.len);
    assert(num_proto_nodes < NULL_VOTE_INDEX);

    // deltas.length = numProtoNodes; deltas.fill(0)
    try deltas_cache.resize(allocator, num_proto_nodes);
    const deltas = deltas_cache.items;
    @memset(deltas, 0);

    const num_validators = vote_next_indices.len;

    // Sort equivocating indices for pointer advancement in the loop.
    // Heap-allocated like TS's Array.from(equivocatingIndicesSet).sort().
    const sorted_eq = try sortEquivocatingKeys(allocator, equivocating_indices);
    defer allocator.free(sorted_eq);

    var result: ComputeDeltasResult = .{ .deltas = deltas, .equivocating_validators = @intCast(sorted_eq.len) };
    // Pre-fetch the first equivocating validator index for pointer advancement comparison.
    // Use maxInt as sentinel when empty so `v_index == equivocating_validator_index` is always false.
    var equivocating_validator_index: ValidatorIndex = if (sorted_eq.len > 0) sorted_eq[0] else std.math.maxInt(ValidatorIndex);
    var equivocating_index: usize = 0;

    for (0..num_validators) |v_index| {
        const current_index = vote_current_indices[v_index];
        const next_index = vote_next_indices[v_index];

        // Validator has never voted and has no pending vote.
        if (current_index == NULL_VOTE_INDEX and next_index == NULL_VOTE_INDEX) {
            result.old_inactive_validators += 1;
            continue;
        }

        const old_balance: i64 = if (v_index < old_balances.len) old_balances[v_index] else 0;
        const new_balance: i64 = if (old_balances.ptr == new_balances.ptr) old_balance else if (v_index < new_balances.len) new_balances[v_index] else 0;

        // Check if this validator is equivocating (sorted pointer advancement).
        if (v_index == equivocating_validator_index) {
            // Remove weight from current vote. Only process once: after zeroing
            // current_index, subsequent calls skip this validator.
            if (current_index != NULL_VOTE_INDEX) {
                assert(current_index < deltas.len);
                deltas[current_index] = math.sub(i64, deltas[current_index], old_balance) catch return error.DeltaOverflow;
            }
            vote_current_indices[v_index] = NULL_VOTE_INDEX;
            equivocating_index += 1;
            // Advance to next equivocating validator, or set sentinel when all processed.
            // equivocating_index == sorted_eq.len is the normal end condition, not an
            // invariant violation, so a bounds check (not assert) is required here.
            equivocating_validator_index = if (equivocating_index < sorted_eq.len) sorted_eq[equivocating_index] else std.math.maxInt(ValidatorIndex);
            continue;
        }

        if (old_balance == 0 and new_balance == 0) {
            result.new_inactive_validators += 1;
            continue;
        }

        // Vote or balance changed: apply delta.
        if (current_index != next_index or old_balance != new_balance) {
            // Subtract old weight from departing node.
            if (current_index != NULL_VOTE_INDEX) {
                assert(current_index < deltas.len);
                deltas[current_index] = math.sub(i64, deltas[current_index], old_balance) catch return error.DeltaOverflow;
            }
            // Add new weight to arriving node.
            if (next_index != NULL_VOTE_INDEX) {
                assert(next_index < deltas.len);
                deltas[next_index] = math.add(i64, deltas[next_index], new_balance) catch return error.DeltaOverflow;
            }
            // Commit vote.
            vote_current_indices[v_index] = next_index;
            result.new_vote_validators += 1;
        } else {
            result.unchanged_vote_validators += 1;
        }
    }

    return result;
}

/// Copies equivocating keys into a heap buffer and sorts ascending for pointer advancement.
fn sortEquivocatingKeys(allocator: Allocator, indices: EquivocatingIndices) ![]const ValidatorIndex {
    const keys = indices.keys();
    const buf = try allocator.alloc(ValidatorIndex, keys.len);
    @memcpy(buf, keys);
    std.mem.sortUnstable(ValidatorIndex, buf, {}, std.sort.asc(ValidatorIndex));
    return buf;
}

// ── Tests ──

const TestContext = struct {
    dc: DeltasCache = .{},
    votes: Votes = .{},

    fn init(count: usize) !TestContext {
        var ctx: TestContext = .{};
        try ctx.votes.ensureValidatorCount(testing.allocator, @intCast(count));
        return ctx;
    }

    fn deinit(self: *TestContext) void {
        self.votes.deinit(testing.allocator);
        self.dc.deinit(testing.allocator);
    }

    fn run(
        self: *TestContext,
        num_nodes: usize,
        old_bal: []const u16,
        new_bal: []const u16,
        eq: EquivocatingIndices,
    ) !ComputeDeltasResult {
        const f = self.votes.fields();
        return computeDeltas(testing.allocator, &self.dc, num_nodes, f.current_indices, f.next_indices, old_bal, new_bal, eq);
    }

    const empty_eq = EquivocatingIndices.init(testing.allocator);
};

fn expectDeltas(actual: []const i64, expected: []const i64) !void {
    try testing.expectEqualSlices(i64, expected, actual);
}

test "zero hash" {
    const n = 16;
    var ctx = try TestContext.init(n);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 0);

    const result = try ctx.run(n, &([_]u16{0} ** n), &([_]u16{0} ** n), TestContext.empty_eq);
    try expectDeltas(result.deltas, &([_]i64{0} ** n));
    // current_indices should be updated to match next_indices
    try testing.expectEqualSlices(VoteIndex, f.next_indices, f.current_indices);
}

test "all voted the same" {
    const n = 16;
    var ctx = try TestContext.init(n);
    defer ctx.deinit();

    @memset(ctx.votes.fields().next_indices, 0);

    const bal = [_]u16{42} ** n;
    const result = try ctx.run(n, &bal, &bal, TestContext.empty_eq);

    var expected = [_]i64{0} ** n;
    expected[0] = 42 * n;
    try expectDeltas(result.deltas, &expected);
}

test "different votes" {
    const n = 16;
    var ctx = try TestContext.init(n);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    for (0..n) |i| f.next_indices[i] = @intCast(i);

    const bal = [_]u16{42} ** n;
    const result = try ctx.run(n, &bal, &bal, TestContext.empty_eq);
    try expectDeltas(result.deltas, &([_]i64{42} ** n));
}

test "moving votes" {
    const n = 16;
    var ctx = try TestContext.init(n);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 1);

    const bal = [_]u16{42} ** n;
    const result = try ctx.run(n, &bal, &bal, TestContext.empty_eq);

    var expected = [_]i64{0} ** n;
    expected[0] = -42 * n;
    expected[1] = 42 * n;
    try expectDeltas(result.deltas, &expected);
}

test "changing balances" {
    const n = 16;
    var ctx = try TestContext.init(n);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 1);

    const result = try ctx.run(n, &([_]u16{42} ** n), &([_]u16{84} ** n), TestContext.empty_eq);

    var expected = [_]i64{0} ** n;
    expected[0] = -42 * n;
    expected[1] = 84 * n;
    try expectDeltas(result.deltas, &expected);
}

test "validator appears" {
    var ctx = try TestContext.init(2);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 1);

    // Only one validator in old balances, two in new
    const result = try ctx.run(2, &.{42}, &.{ 42, 42 }, TestContext.empty_eq);
    try expectDeltas(result.deltas, &.{ -42, 84 });
    try testing.expectEqualSlices(VoteIndex, f.next_indices, f.current_indices);
}

test "validator disappears" {
    var ctx = try TestContext.init(2);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 1);

    // Two validators in old balances, only one in new
    const result = try ctx.run(2, &.{ 42, 42 }, &.{42}, TestContext.empty_eq);
    try expectDeltas(result.deltas, &.{ -84, 42 });
    try testing.expectEqualSlices(VoteIndex, f.next_indices, f.current_indices);
}

test "not empty equivocation set" {
    var ctx = try TestContext.init(2);
    defer ctx.deinit();

    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, 1);

    const bal: []const u16 = &.{ 31, 32 };
    // 1st validator is part of an attester slashing
    var eq = EquivocatingIndices.init(testing.allocator);
    defer eq.deinit();
    try eq.put(0, {});

    // Should disregard the 1st validator due to attester slashing
    const r1 = try ctx.run(2, bal, bal, eq);
    try expectDeltas(r1.deltas, &.{ -63, 32 });

    // Calling computeDeltas again should not have any effect on the weight
    const r2 = try ctx.run(2, bal, bal, eq);
    try expectDeltas(r2.deltas, &.{ 0, 0 });
}

test "move out of tree" {
    var ctx = try TestContext.init(2);
    defer ctx.deinit();

    // Both validators move from node 0 to NULL (leave the tree).
    const f = ctx.votes.fields();
    @memset(f.current_indices, 0);
    @memset(f.next_indices, NULL_VOTE_INDEX);

    const bal: []const u16 = &.{ 42, 42 };
    const result = try ctx.run(1, bal, bal, TestContext.empty_eq);
    // Both old balances deducted, no new balance added anywhere
    try expectDeltas(result.deltas, &.{-84});
}
