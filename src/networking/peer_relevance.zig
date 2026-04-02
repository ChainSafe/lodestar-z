//! Peer relevance assertion: determines whether a peer is on the same chain.
//!
//! After every Status exchange (initial handshake + periodic re-status), we
//! check whether the remote peer's view of the chain is compatible with ours.
//! Incompatible peers are disconnected with Goodbye(IRRELEVANT_NETWORK).
//!
//! Based on Lodestar TS `assertPeerRelevance` and Lighthouse's relevance checks.
//! Key design decision: we do NOT penalize peers whose head is behind ours —
//! they may be syncing, and disconnecting them hurts network stability.
//!
//! Reference:
//! - Lodestar: packages/beacon-node/src/network/peers/utils/assertPeerRelevance.ts
//! - Lighthouse: beacon_node/lighthouse_network/src/peer_manager/mod.rs (is_peer_relevant)

const std = @import("std");
const testing = std.testing;

const ForkSeq = @import("config").ForkSeq;
const status_cache = @import("status_cache.zig");
const CachedStatus = status_cache.CachedStatus;

// ── Constants ────────────────────────────────────────────────────────────────

/// Tolerance for clock skew: remote head_slot may be up to this many slots
/// ahead of our current slot without being considered irrelevant.
/// Value from Lighthouse / Lodestar TS.
const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// The zero root (all zeros) — used to detect uninitialized finalized roots
/// at genesis. We skip finalized root comparison when either side is zero.
const ZERO_ROOT: [32]u8 = [_]u8{0} ** 32;

// ── Irrelevance reasons ──────────────────────────────────────────────────────

/// Reason why a peer was determined to be irrelevant.
pub const IrrelevantPeerCode = enum {
    /// Fork digests don't match — different network or fork.
    incompatible_forks,
    /// Remote's finalized root differs from ours at the same epoch — diverged chain.
    different_finalized,
    /// Remote's head slot is too far in the future — clock skew or different genesis.
    different_clocks,
    /// Post-Fulu peer did not announce earliestAvailableSlot.
    no_earliest_available_slot,
};

/// Detailed irrelevance info for logging.
pub const IrrelevantPeerInfo = union(IrrelevantPeerCode) {
    incompatible_forks: struct {
        ours: [4]u8,
        theirs: [4]u8,
    },
    different_finalized: struct {
        expected_root: [32]u8,
        remote_root: [32]u8,
    },
    different_clocks: struct {
        slot_diff: i64,
    },
    no_earliest_available_slot: void,

    pub fn code(self: IrrelevantPeerInfo) IrrelevantPeerCode {
        return std.meta.activeTag(self);
    }
};

// ── Public API ───────────────────────────────────────────────────────────────

/// Check whether a remote peer's status is compatible with our local chain view.
///
/// Returns `null` if the peer is relevant (compatible), or an `IrrelevantPeerInfo`
/// describing why the peer is irrelevant.
///
/// Arguments:
/// - `remote`: The peer's Status message fields.
/// - `local`: Our cached local Status.
/// - `current_slot`: The current slot from our clock.
///
/// This function is pure (no side effects) and allocation-free.
pub fn assertPeerRelevance(
    remote_fork_digest: [4]u8,
    remote_finalized_root: [32]u8,
    remote_finalized_epoch: u64,
    remote_head_slot: u64,
    remote_earliest_available_slot: ?u64,
    local: CachedStatus,
    local_fork_seq: ForkSeq,
    current_slot: u64,
) ?IrrelevantPeerInfo {
    // 1. Fork digest must match — different digest means different network/fork entirely.
    if (!std.mem.eql(u8, &remote_fork_digest, &local.fork_digest)) {
        return .{ .incompatible_forks = .{
            .ours = local.fork_digest,
            .theirs = remote_fork_digest,
        } };
    }

    // 2. Clock skew check — remote's head is too far in the future.
    //    This catches peers with a different genesis time or a broken clock.
    //    We use saturating arithmetic to handle current_slot near zero.
    if (remote_head_slot > current_slot +| FUTURE_SLOT_TOLERANCE) {
        const slot_diff: i64 = @intCast(remote_head_slot -| current_slot);
        return .{ .different_clocks = .{ .slot_diff = slot_diff } };
    }

    // 3. Finalized checkpoint compatibility.
    //    If the remote's finalized epoch is at or behind ours, and both finalized
    //    roots are non-zero, and the roots disagree at the same epoch → diverged chain.
    //
    //    We only compare when remote.finalized_epoch == local.finalized_epoch because
    //    we can't cheaply look up our historical finalized root at the remote's epoch
    //    without chain state access. This matches Lodestar TS behavior.
    if (remote_finalized_epoch <= local.finalized_epoch) {
        if (!isZeroRoot(remote_finalized_root) and !isZeroRoot(local.finalized_root)) {
            if (remote_finalized_epoch == local.finalized_epoch) {
                if (!std.mem.eql(u8, &remote_finalized_root, &local.finalized_root)) {
                    return .{ .different_finalized = .{
                        .expected_root = local.finalized_root,
                        .remote_root = remote_finalized_root,
                    } };
                }
            }
            // If remote_finalized_epoch < local.finalized_epoch, we can't verify the
            // root without chain state. Per Lodestar TS: "the impact of not doing this
            // check is low". The ENR fork check should be sufficient.
        }
    }

    // Note: We intentionally do NOT check if the remote's finalized epoch is ahead of
    // ours (remote_finalized_epoch > local.finalized_epoch). That just means the remote
    // is ahead — we accept it and may sync from them. Lodestar TS: "Accept request
    // status finalized checkpoint in the future, we do not know if it is a true
    // finalized root."

    // Note: We do NOT check if the remote's head is too far behind. Lodestar TS
    // explicitly avoids this: "It's dangerous to downscore peers that are far behind.
    // This means we'd be more likely to disconnect peers that are attempting to sync,
    // which would affect network stability."

    if (local_fork_seq.gte(.fulu) and remote_earliest_available_slot == null) {
        return .{ .no_earliest_available_slot = {} };
    }

    return null; // Peer is relevant.
}

/// Helper: check if a root is all zeros.
fn isZeroRoot(root: [32]u8) bool {
    return std.mem.eql(u8, &root, &ZERO_ROOT);
}

// ── Tests ────────────────────────────────────────────────────────────────────

const TEST_FORK_DIGEST = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
const TEST_FINALIZED_ROOT = [_]u8{0xAA} ** 32;
const OTHER_FINALIZED_ROOT = [_]u8{0xBB} ** 32;

fn makeLocalStatus(finalized_epoch: u64, head_slot: u64) CachedStatus {
    return .{
        .fork_digest = TEST_FORK_DIGEST,
        .finalized_root = TEST_FINALIZED_ROOT,
        .finalized_epoch = finalized_epoch,
        .head_root = [_]u8{0xCC} ** 32,
        .head_slot = head_slot,
    };
}

test "assertPeerRelevance: compatible peer returns null" {
    const local = makeLocalStatus(10, 320);
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        TEST_FINALIZED_ROOT,
        10,
        315,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: different fork digest → incompatible_forks" {
    const local = makeLocalStatus(10, 320);
    const other_digest = [4]u8{ 0x01, 0x02, 0x03, 0x04 };
    const result = assertPeerRelevance(
        other_digest,
        TEST_FINALIZED_ROOT,
        10,
        315,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result != null);
    try testing.expectEqual(IrrelevantPeerCode.incompatible_forks, result.?.code());
}

test "assertPeerRelevance: head too far in future → different_clocks" {
    const local = makeLocalStatus(10, 320);
    // Remote head at 400, current_slot is 320, tolerance is 1 → 400 > 321.
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        TEST_FINALIZED_ROOT,
        10,
        400,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result != null);
    try testing.expectEqual(IrrelevantPeerCode.different_clocks, result.?.code());
}

test "assertPeerRelevance: head at current_slot + 1 → still relevant" {
    const local = makeLocalStatus(10, 320);
    // Remote head at 321, current_slot is 320, tolerance is 1 → 321 <= 321.
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        TEST_FINALIZED_ROOT,
        10,
        321,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: different finalized root at same epoch → different_finalized" {
    const local = makeLocalStatus(10, 320);
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        OTHER_FINALIZED_ROOT, // Different from local's TEST_FINALIZED_ROOT
        10, // Same epoch
        315,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result != null);
    try testing.expectEqual(IrrelevantPeerCode.different_finalized, result.?.code());
}

test "assertPeerRelevance: different finalized root at earlier epoch → relevant (can't verify)" {
    const local = makeLocalStatus(10, 320);
    // Remote is at epoch 5 (behind us at 10) with a different root — we can't
    // verify because we don't have the historical root at epoch 5 without chain state.
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        OTHER_FINALIZED_ROOT,
        5, // Earlier epoch
        200,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: zero finalized root → skip finalized check" {
    const local = makeLocalStatus(10, 320);
    // Remote has zero finalized root (genesis) — skip comparison.
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        ZERO_ROOT,
        10,
        315,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: local has zero finalized root → skip finalized check" {
    var local = makeLocalStatus(10, 320);
    local.finalized_root = ZERO_ROOT;
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        OTHER_FINALIZED_ROOT,
        10,
        315,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: remote finalized ahead of us → relevant" {
    const local = makeLocalStatus(10, 320);
    // Remote claims finalized_epoch=20 — ahead of our 10.
    // We can't verify but we accept it (may sync from them).
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        OTHER_FINALIZED_ROOT,
        20, // Ahead of us
        321,
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: remote head far behind us → still relevant" {
    const local = makeLocalStatus(10, 320);
    // Remote head at slot 10 — way behind our 320.
    // We intentionally do NOT disconnect them (they're syncing).
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        TEST_FINALIZED_ROOT,
        10,
        10, // Far behind
        null,
        local,
        .phase0,
        320,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: current_slot at zero → handles edge case" {
    const local = makeLocalStatus(0, 0);
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        ZERO_ROOT,
        0,
        1,
        null,
        local,
        .phase0,
        0,
    );
    try testing.expect(result == null);
}

test "assertPeerRelevance: post-Fulu peer without earliestAvailableSlot is irrelevant" {
    const local = makeLocalStatus(10, 320);
    const result = assertPeerRelevance(
        TEST_FORK_DIGEST,
        TEST_FINALIZED_ROOT,
        10,
        315,
        null,
        local,
        .fulu,
        320,
    );
    try testing.expect(result != null);
    try testing.expectEqual(IrrelevantPeerCode.no_earliest_available_slot, result.?.code());
}
