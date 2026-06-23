//! Computes the Merkle witness that proves the current and next sync committee
//! roots are committed to by a beacon state root. Light-client servers serve
//! this witness so that clients can verify sync committee updates without
//! downloading the full beacon state.
//!
//! The witness is a sibling branch from the `sync_committees` subtree up to the
//! state root, ordered by descending gindex. The path through the BeaconState
//! tree differs across forks because the container layout changes: pre-electra
//! the sync committees live at gindices 54/55 (4 siblings), electra and later
//! at gindices 86/87 (5 siblings).
//!
//! Tests are ported from lodestar:
//! packages/beacon-node/test/unit/chain/lightclient/proof.test.ts
const std = @import("std");

const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const hashOne = @import("hashing").hashOne;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const verifyMerkleBranch = @import("./utils/verify_merkle_branch.zig").verifyMerkleBranch;

/// Witness data needed to prove the current and next sync committee roots
/// against the beacon state root. Used by the light-client server.
///
/// Witness branch is sorted by descending gindex.
/// Pre-electra: 4 witness entries. Post-electra: 5 witness entries.
pub const SyncCommitteeWitness = struct {
    witness_buf: [5][32]u8,
    witness_len: u8 = 0,
    current_sync_committee_root: [32]u8,
    next_sync_committee_root: [32]u8,

    pub fn witness(self: *const SyncCommitteeWitness) []const [32]u8 {
        return self.witness_buf[0..self.witness_len];
    }
};

/// Compute the sync-committee witness for the beacon state rooted at `root_node`.
///
/// The walk path depends on which fork the state was produced under because the BeaconState
/// container layout changes across forks — sync committee fields move to different gindices.
pub fn getSyncCommitteesWitness(
    fork: ForkSeq,
    root_node: Node.Id,
    pool: *Node.Pool,
    out: *SyncCommitteeWitness,
) !void {
    std.debug.assert(fork.gte(.altair));
    const n1 = root_node;

    var current: Node.Id = undefined;
    var next: Node.Id = undefined;
    // Layout from electra onward: sync committees sit deeper in the tree.
    if (fork.gte(.electra)) {
        const n2 = try Node.Id.getLeft(n1, pool);
        const n5 = try Node.Id.getRight(n2, pool);
        const n10 = try Node.Id.getLeft(n5, pool);
        const n21 = try Node.Id.getRight(n10, pool);
        const n43 = try Node.Id.getRight(n21, pool);

        current = try Node.Id.getLeft(n43, pool); // n86
        next = try Node.Id.getRight(n43, pool); // n87

        // Siblings on the path to the sync-committee subtree, descending gindex order.
        const w0 = try Node.Id.getLeft(n21, pool); // gindex 42
        const w1 = try Node.Id.getLeft(n10, pool); // gindex 20
        const w2 = try Node.Id.getRight(n5, pool); // gindex 11
        const w3 = try Node.Id.getLeft(n2, pool); // gindex 4
        const w4 = try Node.Id.getRight(n1, pool); // gindex 3

        out.witness_buf = .{
            w0.getRoot(pool).*,
            w1.getRoot(pool).*,
            w2.getRoot(pool).*,
            w3.getRoot(pool).*,
            w4.getRoot(pool).*,
        };
        out.witness_len = 5;
    }
    // Pre-electra layout (altair → deneb): sync committees at gindices 54, 55.
    else {
        const n3 = try Node.Id.getRight(n1, pool); // [1]0110
        const n6 = try Node.Id.getLeft(n3, pool); // 1[0]110
        const n13 = try Node.Id.getRight(n6, pool); // 10[1]10
        const n27 = try Node.Id.getRight(n13, pool); // 101[1]0

        current = try Node.Id.getLeft(n27, pool); // n54 — 1011[0]
        next = try Node.Id.getRight(n27, pool); // n55 — 1011[1]

        const w0 = try Node.Id.getLeft(n13, pool); // gindex 26
        const w1 = try Node.Id.getLeft(n6, pool); // gindex 12
        const w2 = try Node.Id.getRight(n3, pool); // gindex 7
        const w3 = try Node.Id.getLeft(n1, pool); // gindex 2

        out.witness_buf = .{
            w0.getRoot(pool).*,
            w1.getRoot(pool).*,
            w2.getRoot(pool).*,
            w3.getRoot(pool).*,
            std.mem.zeroes([32]u8),
        };
        out.witness_len = 4;
    }

    out.current_sync_committee_root = current.getRoot(pool).*;
    out.next_sync_committee_root = next.getRoot(pool).*;
}

const NUM_WITNESS: u8 = 4;
const NUM_WITNESS_ELECTRA: u8 = 5;

fn fillSyncCommittee(byte: u8) ct.altair.SyncCommittee.Type {
    return .{
        .pubkeys = [_][48]u8{[_]u8{byte} ** 48} ** preset.SYNC_COMMITTEE_SIZE,
        .aggregate_pubkey = [_]u8{byte} ** 48,
    };
}

/// Convert a gindex to (depth, index-at-depth)
fn fromGindex(gindex: usize) struct { depth: usize, index: usize } {
    const depth = std.math.log2_int(usize, gindex);
    const first_index = @as(usize, 1) << @intCast(depth);
    return .{ .depth = depth, .index = gindex - first_index };
}

/// Pack a variable-length witness branch into the fixed [33]Root proof buffer
/// that verifyMerkleBranch expects. Only the first `depth` slots are read by
/// verifyMerkleBranch.
fn packProof(branch: []const [32]u8) [33][32]u8 {
    var proof: [33][32]u8 = .{[_]u8{0} ** 32} ** 33;
    for (branch, 0..) |w, i| proof[i] = w;
    return proof;
}

/// Sets up a sync-committee proof. Only used for tests.
const ProofFixture = struct {
    pool: Node.Pool,
    state: AnyBeaconState,
    state_root: [32]u8,
    root_node: Node.Id,
    current_sync_committee: ct.altair.SyncCommittee.Type,
    next_sync_committee: ct.altair.SyncCommittee.Type,

    fn init(self: *ProofFixture, fork: ForkSeq) !void {
        const allocator = std.testing.allocator;
        self.pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
        errdefer self.pool.deinit();

        self.state = switch (fork) {
            .altair => try AnyBeaconState.fromValue(allocator, &self.pool, .altair, &ct.altair.BeaconState.default_value),
            .electra => try AnyBeaconState.fromValue(allocator, &self.pool, .electra, &ct.electra.BeaconState.default_value),
            else => return error.UnsupportedFork,
        };
        errdefer self.state.deinit();

        self.current_sync_committee = fillSyncCommittee(0xbb);
        self.next_sync_committee = fillSyncCommittee(0xcc);
        try self.state.setCurrentSyncCommittee(&self.current_sync_committee);
        try self.state.setNextSyncCommittee(&self.next_sync_committee);

        try self.state.commit();
        self.state_root = (try self.state.hashTreeRoot()).*;
        self.root_node = switch (self.state) {
            inline else => |view| view.root,
        };
    }

    fn deinit(self: *ProofFixture) void {
        self.state.deinit();
        self.pool.deinit();
    }
};

test "getSyncCommitteesWitness: SyncCommittees proof" {
    const TestCase = struct {
        fork_seq: ForkSeq,
        num_witness: u8,
        sync_committees_gindex: usize,
    };

    const test_cases: [2]TestCase = .{
        .{
            .fork_seq = .altair,
            .num_witness = NUM_WITNESS,
            .sync_committees_gindex = 27,
        },
        .{
            .fork_seq = .electra,
            .num_witness = NUM_WITNESS_ELECTRA,
            .sync_committees_gindex = 43,
        },
    };

    for (test_cases) |tc| {
        var fixture: ProofFixture = undefined;
        try fixture.init(tc.fork_seq);
        defer fixture.deinit();

        var witness_data: SyncCommitteeWitness = undefined;
        try getSyncCommitteesWitness(tc.fork_seq, fixture.root_node, &fixture.pool, &witness_data);

        var sync_committees_leaf: [32]u8 = undefined;
        hashOne(&sync_committees_leaf, &witness_data.current_sync_committee_root, &witness_data.next_sync_committee_root);

        try std.testing.expectEqual(@as(u8, tc.num_witness), witness_data.witness_len);

        const pos = fromGindex(tc.sync_committees_gindex);
        const proof = packProof(witness_data.witness());
        try std.testing.expect(verifyMerkleBranch(sync_committees_leaf, &proof, pos.depth, pos.index, fixture.state_root));
    }
}

test "getSyncCommitteesWitness: currentSyncCommittee proof" {
    const TestCase = struct {
        fork_seq: ForkSeq,
        num_witness: u8,
        current_sync_committee_gindex: usize,
    };

    const test_cases: [2]TestCase = .{
        .{
            .fork_seq = .altair,
            .num_witness = NUM_WITNESS,
            .current_sync_committee_gindex = 54,
        },
        .{
            .fork_seq = .electra,
            .num_witness = NUM_WITNESS_ELECTRA,
            .current_sync_committee_gindex = 86,
        },
    };

    inline for (test_cases) |tc| {
        var fixture: ProofFixture = undefined;
        try fixture.init(tc.fork_seq);
        defer fixture.deinit();

        var witness_data: SyncCommitteeWitness = undefined;
        try getSyncCommitteesWitness(tc.fork_seq, fixture.root_node, &fixture.pool, &witness_data);

        // currentSyncCommitteeBranch = [nextSyncCommitteeRoot, ...witness]
        var branch_buf: [tc.num_witness + 1][32]u8 = undefined;
        branch_buf[0] = witness_data.next_sync_committee_root;
        for (witness_data.witness(), 0..) |w, i| branch_buf[1 + i] = w;

        try std.testing.expectEqual(@as(u8, tc.num_witness), witness_data.witness_len);

        var current_leaf: [32]u8 = undefined;
        try ct.altair.SyncCommittee.hashTreeRoot(&fixture.current_sync_committee, &current_leaf);

        const pos = fromGindex(tc.current_sync_committee_gindex);
        const proof = packProof(&branch_buf);
        try std.testing.expect(verifyMerkleBranch(current_leaf, &proof, pos.depth, pos.index, fixture.state_root));
    }
}

test "getSyncCommitteesWitness: nextSyncCommittee proof" {
    const TestCase = struct {
        fork_seq: ForkSeq,
        num_witness: u8,
        next_sync_committee_gindex: usize,
    };

    const test_cases: [2]TestCase = .{
        .{
            .fork_seq = .altair,
            .num_witness = NUM_WITNESS,
            .next_sync_committee_gindex = 55,
        },
        .{
            .fork_seq = .electra,
            .num_witness = NUM_WITNESS_ELECTRA,
            .next_sync_committee_gindex = 87,
        },
    };

    inline for (test_cases) |tc| {
        var fixture: ProofFixture = undefined;
        try fixture.init(tc.fork_seq);
        defer fixture.deinit();

        var witness_data: SyncCommitteeWitness = undefined;
        try getSyncCommitteesWitness(tc.fork_seq, fixture.root_node, &fixture.pool, &witness_data);

        // nextSyncCommitteeBranch = [currentSyncCommitteeRoot, ...witness]
        var branch_buf: [tc.num_witness + 1][32]u8 = undefined;
        branch_buf[0] = witness_data.current_sync_committee_root;
        for (witness_data.witness(), 0..) |w, i| branch_buf[1 + i] = w;

        try std.testing.expectEqual(@as(u8, tc.num_witness), witness_data.witness_len);

        var next_leaf: [32]u8 = undefined;
        try ct.altair.SyncCommittee.hashTreeRoot(&fixture.next_sync_committee, &next_leaf);

        const pos = fromGindex(tc.next_sync_committee_gindex);
        const proof = packProof(&branch_buf);
        try std.testing.expect(verifyMerkleBranch(next_leaf, &proof, pos.depth, pos.index, fixture.state_root));
    }
}
