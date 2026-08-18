const std = @import("std");
const types = @import("types.zig");
const constants = @import("constants.zig");

const ForkName = types.ForkName;
const Status = types.Status;
const IrrelevantPeerResult = types.IrrelevantPeerResult;

/// Returns null if peer is relevant, or the reason it's irrelevant.
pub fn assertPeerRelevance(
    fork_name: ForkName,
    remote: Status,
    local: Status,
    current_slot: u64,
) ?IrrelevantPeerResult {
    // 1. The node is on a different network/fork
    if (!std.mem.eql(u8, &local.fork_digest, &remote.fork_digest)) {
        return .{ .incompatible_forks = .{
            .ours = local.fork_digest,
            .theirs = remote.fork_digest,
        } };
    }

    // 2. The remote's head is on a slot that is significantly ahead of what we consider the
    // current slot. This could be because they are using a different genesis time, or that
    // their or our system's clock is incorrect.
    const slot_diff: i64 = @as(i64, @intCast(remote.head_slot)) - @as(i64, @intCast(current_slot));
    if (slot_diff > @as(i64, constants.FUTURE_SLOT_TOLERANCE)) {
        return .{ .different_clocks = .{ .slot_diff = slot_diff } };
    }

    // 3. The remote's finalized epoch is less than or equal to ours, but the block root is
    // different to the one in our chain. Therefore, the node is on a different chain and we
    // should not communicate with them.
    if (remote.finalized_epoch <= local.finalized_epoch and
        !isZeroRoot(remote.finalized_root) and
        !isZeroRoot(local.finalized_root))
    {
        const expected_root: ?[32]u8 = if (remote.finalized_epoch == local.finalized_epoch)
            local.finalized_root
        else
            null;

        if (expected_root) |expected| {
            if (!std.mem.eql(u8, &remote.finalized_root, &expected)) {
                return .{ .different_finalized = .{
                    .expected_root = expected,
                    .remote_root = remote.finalized_root,
                } };
            }
        }
    }

    // 4. Post-fulu peers must announce earliest_available_slot
    if (fork_name.isPostFulu() and remote.earliest_available_slot == null) {
        return .{ .no_earliest_available_slot = {} };
    }

    return null;
}

fn isZeroRoot(root: [32]u8) bool {
    return std.mem.eql(u8, &root, &([_]u8{0} ** 32));
}

// --- Tests ---

const testing = std.testing;

fn makeStatus(
    fork_digest: [4]u8,
    finalized_root: [32]u8,
    finalized_epoch: u64,
    head_slot: u64,
    earliest_available_slot: ?u64,
) Status {
    return .{
        .fork_digest = fork_digest,
        .finalized_root = finalized_root,
        .finalized_epoch = finalized_epoch,
        .head_root = [_]u8{0} ** 32,
        .head_slot = head_slot,
        .earliest_available_slot = earliest_available_slot,
    };
}

test "relevant peer returns null" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 101, null);
    try testing.expect(assertPeerRelevance(.deneb, remote, local, 100) == null);
}

test "incompatible forks" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const remote = makeStatus(.{ 0x11, 0x22, 0x33, 0x44 }, root, 10, 100, null);
    const result = assertPeerRelevance(.deneb, remote, local, 100).?;
    try testing.expect(result == .incompatible_forks);
}

test "different clocks — remote too far ahead" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 102, null);
    const result = assertPeerRelevance(.deneb, remote, local, 100).?;
    try testing.expect(result == .different_clocks);
}

test "different finalized — same epoch different root" {
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, [_]u8{1} ** 32, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, [_]u8{2} ** 32, 10, 100, null);
    const result = assertPeerRelevance(.deneb, remote, local, 100).?;
    try testing.expect(result == .different_finalized);
}

test "different finalized — both zero roots is fine" {
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, [_]u8{0} ** 32, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, [_]u8{0} ** 32, 10, 100, null);
    try testing.expect(assertPeerRelevance(.deneb, remote, local, 100) == null);
}

test "no earliest available slot — post fulu" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, 0);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const result = assertPeerRelevance(.fulu, remote, local, 100).?;
    try testing.expect(result == .no_earliest_available_slot);
}

test "no earliest available slot — pre fulu is fine" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    try testing.expect(assertPeerRelevance(.deneb, remote, local, 100) == null);
}

test "different clocks — exact tolerance is ok" {
    const root = [_]u8{1} ** 32;
    const local = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 100, null);
    const remote = makeStatus(.{ 0xAA, 0xBB, 0xCC, 0xDD }, root, 10, 101, null);
    // head_slot == current_slot + FUTURE_SLOT_TOLERANCE (1) => not > tolerance => relevant
    try testing.expect(assertPeerRelevance(.deneb, remote, local, 100) == null);
}
