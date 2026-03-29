const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

const vote_tracker = @import("vote_tracker.zig");
const Votes = vote_tracker.Votes;
const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

const consensus_types = @import("consensus_types");
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;

pub const VoteIndex = u32;

/// Set of equivocating validator indices.
pub const EquivocatingIndices = std.AutoArrayHashMapUnmanaged(ValidatorIndex, void);

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
    num_proto_nodes: u32,
    vote_current_indices: []VoteIndex,
    vote_next_indices: []const VoteIndex,
    old_balances: []const u16,
    new_balances: []const u16,
    equivocating_indices: *const EquivocatingIndices,
) !ComputeDeltasResult {
    assert(vote_current_indices.len == vote_next_indices.len);
    assert(num_proto_nodes < NULL_VOTE_INDEX);

    // deltas.length = numProtoNodes; deltas.fill(0)
    try deltas_cache.resize(allocator, @intCast(num_proto_nodes));
    const deltas = deltas_cache.items;
    @memset(deltas, 0);

    const num_validators = vote_next_indices.len;

    // Sort equivocating indices for pointer advancement in the loop.
    const sorted_eq = try sortEquivocatingKeys(allocator, equivocating_indices.*);
    defer allocator.free(sorted_eq);

    var result: ComputeDeltasResult = .{ .deltas = deltas, .equivocating_validators = @intCast(sorted_eq.len) };
    // Pre-fetch the first equivocating validator index for pointer advancement comparison.
    // Use maxInt as sentinel when empty so the equivocating check is always false.
    var equivocating_validator_index: ValidatorIndex = if (sorted_eq.len > 0) sorted_eq[0] else std.math.maxInt(ValidatorIndex);
    var equivocating_index: usize = 0;

    for (0..num_validators) |v_index| {
        const current_index = vote_current_indices[v_index];
        const next_index = vote_next_indices[v_index];

        // Validator has never voted and has no pending vote.
        if (current_index == NULL_VOTE_INDEX) {
            if (next_index == NULL_VOTE_INDEX) {
                result.old_inactive_validators += 1;
                continue;
            }
        }

        const bal = resolveBalances(v_index, old_balances, new_balances);

        // Check if this validator is equivocating (sorted pointer advancement).
        if (@as(ValidatorIndex, @intCast(v_index)) == equivocating_validator_index) {
            // Remove weight from current vote. Only process once: after zeroing
            // current_index, subsequent calls skip this validator.
            subtractOldBalance(deltas, current_index, bal.old);
            vote_current_indices[v_index] = NULL_VOTE_INDEX;
            equivocating_index += 1;
            // Advance to next equivocating validator, or set sentinel when exhausted.
            equivocating_validator_index = if (equivocating_index < sorted_eq.len)
                sorted_eq[equivocating_index]
            else
                std.math.maxInt(ValidatorIndex);
            continue;
        }

        if (bal.old == 0) {
            if (bal.new == 0) {
                result.new_inactive_validators += 1;
                continue;
            }
        }

        // Vote or balance changed: apply delta.
        if (current_index != next_index or bal.old != bal.new) {
            subtractOldBalance(deltas, current_index, bal.old);
            addNewBalance(deltas, next_index, bal.new);
            vote_current_indices[v_index] = next_index;
            result.new_vote_validators += 1;
        } else {
            result.unchanged_vote_validators += 1;
        }
    }

    return result;
}

/// Subtracts a validator's old balance from the node it is departing.
fn subtractOldBalance(deltas: []i64, node_index: VoteIndex, old_balance: i64) void {
    if (node_index != NULL_VOTE_INDEX) {
        assert(node_index < deltas.len);
        assert(deltas[node_index] >= std.math.minInt(i64) + old_balance);
        deltas[node_index] -|= old_balance;
    }
}

/// Adds a validator's new balance to the node it is arriving at.
fn addNewBalance(deltas: []i64, node_index: VoteIndex, new_balance: i64) void {
    if (node_index != NULL_VOTE_INDEX) {
        assert(node_index < deltas.len);
        assert(deltas[node_index] <= std.math.maxInt(i64) - new_balance);
        deltas[node_index] +|= new_balance;
    }
}

/// Resolves old and new effective balance for a validator, handling mismatched slice lengths
/// and the same-pointer optimisation (when old_balances == new_balances).
fn resolveBalances(
    v_index: usize,
    old_balances: []const u16,
    new_balances: []const u16,
) struct { old: i64, new: i64 } {
    const old_balance: i64 = if (v_index < old_balances.len) old_balances[v_index] else 0;
    const new_balance: i64 = if (old_balances.ptr == new_balances.ptr)
        old_balance
    else if (v_index < new_balances.len)
        new_balances[v_index]
    else
        0;
    return .{ .old = old_balance, .new = new_balance };
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
    dc: DeltasCache = .empty,
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
        num_nodes: u32,
        old_bal: []const u16,
        new_bal: []const u16,
        eq: *const EquivocatingIndices,
    ) !ComputeDeltasResult {
        const f = self.votes.fields();
        return computeDeltas(testing.allocator, &self.dc, num_nodes, f.current_indices, f.next_indices, old_bal, new_bal, eq);
    }

    // No deinit needed: init performs no allocation, so there is nothing to free.
    const empty_eq: EquivocatingIndices = .empty;
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

    const result = try ctx.run(n, &([_]u16{0} ** n), &([_]u16{0} ** n), &TestContext.empty_eq);
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
    const result = try ctx.run(n, &bal, &bal, &TestContext.empty_eq);

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
    const result = try ctx.run(n, &bal, &bal, &TestContext.empty_eq);
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
    const result = try ctx.run(n, &bal, &bal, &TestContext.empty_eq);

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

    const result = try ctx.run(n, &([_]u16{42} ** n), &([_]u16{84} ** n), &TestContext.empty_eq);

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
    const result = try ctx.run(2, &.{42}, &.{ 42, 42 }, &TestContext.empty_eq);
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
    const result = try ctx.run(2, &.{ 42, 42 }, &.{42}, &TestContext.empty_eq);
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
    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(testing.allocator);
    try eq.put(testing.allocator, 0, {});

    // Should disregard the 1st validator due to attester slashing
    const r1 = try ctx.run(2, bal, bal, &eq);
    try expectDeltas(r1.deltas, &.{ -63, 32 });

    // Calling computeDeltas again should not have any effect on the weight
    const r2 = try ctx.run(2, bal, bal, &eq);
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
    const result = try ctx.run(1, bal, bal, &TestContext.empty_eq);
    // Both old balances deducted, no new balance added anywhere
    try expectDeltas(result.deltas, &.{-84});
}
