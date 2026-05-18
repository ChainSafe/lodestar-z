const std = @import("std");

const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;

/// Witness data needed to prove the current and next sync committee roots
/// against the beacon state root. Used by the light-client server.
///
/// Witness branch is sorted by descending gindex.
/// Pre-electra: 4 witness entries. Post-electra: 5 witness entries.
pub const SyncCommitteeWitness = struct {
    witness_buf: [5][32]u8,
    witness_len: u8,
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
) !SyncCommitteeWitness {
    std.debug.assert(fork.gte(.altair));
    const n1 = root_node;

    // Layout from electra onward: sync committees sit deeper in the tree.
    if (fork.gte(.electra)) {
        const n2 = try Node.Id.getLeft(n1, pool);
        const n5 = try Node.Id.getRight(n2, pool);
        const n10 = try Node.Id.getLeft(n5, pool);
        const n21 = try Node.Id.getRight(n10, pool);
        const n43 = try Node.Id.getRight(n21, pool);

        const current = try Node.Id.getLeft(n43, pool); // n86
        const next = try Node.Id.getRight(n43, pool); // n87

        // Siblings on the path to the sync-committee subtree, descending gindex order.
        const w0 = try Node.Id.getLeft(n21, pool); // gindex 42
        const w1 = try Node.Id.getLeft(n10, pool); // gindex 20
        const w2 = try Node.Id.getRight(n5, pool); // gindex 11
        const w3 = try Node.Id.getLeft(n2, pool); // gindex 4
        const w4 = try Node.Id.getRight(n1, pool); // gindex 3

        return .{
            .witness_buf = .{
                w0.getRoot(pool).*,
                w1.getRoot(pool).*,
                w2.getRoot(pool).*,
                w3.getRoot(pool).*,
                w4.getRoot(pool).*,
            },
            .witness_len = 5,
            .current_sync_committee_root = current.getRoot(pool).*,
            .next_sync_committee_root = next.getRoot(pool).*,
        };
    }
    // Pre-electra layout (altair → deneb): sync committees at gindices 54, 55.
    else {
        const n3 = try Node.Id.getRight(n1, pool); // [1]0110
        const n6 = try Node.Id.getLeft(n3, pool); // 1[0]110
        const n13 = try Node.Id.getRight(n6, pool); // 10[1]10
        const n27 = try Node.Id.getRight(n13, pool); // 101[1]0

        const current = try Node.Id.getLeft(n27, pool); // n54 — 1011[0]
        const next = try Node.Id.getRight(n27, pool); // n55 — 1011[1]

        const w0 = try Node.Id.getLeft(n13, pool); // gindex 26
        const w1 = try Node.Id.getLeft(n6, pool); // gindex 12
        const w2 = try Node.Id.getRight(n3, pool); // gindex 7
        const w3 = try Node.Id.getLeft(n1, pool); // gindex 2

        return .{
            .witness_buf = .{
                w0.getRoot(pool).*,
                w1.getRoot(pool).*,
                w2.getRoot(pool).*,
                w3.getRoot(pool).*,
                std.mem.zeroes([32]u8),
            },
            .witness_len = 4,
            .current_sync_committee_root = current.getRoot(pool).*,
            .next_sync_committee_root = next.getRoot(pool).*,
        };
    }
}
