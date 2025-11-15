const std = @import("std");
const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const preset_mod = @import("preset");
const test_case = @import("../test_case.zig");
const loadSszValue = test_case.loadSszSnappyValue;

const Root = ct.primitive.Root.Type;
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const NodeId = Node.Id;
const Gindex = pmt.Gindex;

pub const Handler = enum {
    single_merkle_proof,

    pub fn suiteName(self: Handler) []const u8 {
        return @tagName(self);
    }
};

const MerkleProof = struct {
    leaf: Root,
    leaf_index: u64,
    branch: []Root,

    pub fn deinit(self: *MerkleProof, allocator: std.mem.Allocator) void {
        allocator.free(self.branch);
    }
};

pub fn TestCase(comptime fork: ForkSeq, comptime handler: Handler) type {
    _ = handler;
    const ForkTypes = @field(ct, fork.forkName());
    const BeaconBlockBody = ForkTypes.BeaconBlockBody;
    const KzgCommitment = ct.primitive.KZGCommitment;

    return struct {
        body: BeaconBlockBody.Type,
        proof: MerkleProof,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);

            try tc.runTest(allocator);
        }

        fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) !Self {
            var body = BeaconBlockBody.default_value;
            errdefer {
                if (comptime @hasDecl(BeaconBlockBody, "deinit")) {
                    BeaconBlockBody.deinit(allocator, &body);
                }
            }
            try loadSszValue(BeaconBlockBody, allocator, dir, "object.ssz_snappy", &body);

            const proof = try loadProof(allocator, dir);
            errdefer proof.deinit(allocator);

            return .{
                .body = body,
                .proof = proof,
            };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            if (comptime @hasDecl(BeaconBlockBody, "deinit")) {
                BeaconBlockBody.deinit(allocator, &self.body);
            }
        }

        fn runTest(self: *Self, allocator: std.mem.Allocator) !void {
            try verifyLeaf(self);
            try verifyBranch(allocator, self);
        }

        fn verifyLeaf(self: *Self) !void {
            // TODO: handle post-Fulu forks where blob_kzg_commitments is a list root, similar to Lodestar merkleProof tests.
            const leaf_gindex_value = preset_mod.KZG_COMMITMENT_GINDEX0;
            const actual_leaf_index: u64 = @intCast(leaf_gindex_value);

            try std.testing.expectEqual(self.proof.leaf_index, actual_leaf_index);

            if (self.body.blob_kzg_commitments.items.len == 0) {
                return error.EmptyBlobKzgCommitments;
            }

            var actual_leaf: Root = undefined;
            try KzgCommitment.hashTreeRoot(&self.body.blob_kzg_commitments.items[0], &actual_leaf);

            try std.testing.expect(std.mem.eql(u8, &self.proof.leaf, &actual_leaf));
        }

        fn verifyBranch(allocator: std.mem.Allocator, self: *Self) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            var pool = try Node.Pool.init(allocator, 2048);
            defer pool.deinit();

            const root_node = try BeaconBlockBody.tree.fromValue(arena_allocator, &pool, &self.body);

            var actual_branch: std.ArrayListUnmanaged(Root) = .empty;
            defer actual_branch.deinit(allocator);

            try buildBranch(&pool, root_node, preset_mod.KZG_COMMITMENT_GINDEX0, allocator, &actual_branch);

            try std.testing.expectEqualSlices(Root, self.proof.branch, actual_branch.items);
        }

        fn buildBranch(
            pool: *Node.Pool,
            root_node: Node.Id,
            leaf_gindex_value: usize,
            allocator: std.mem.Allocator,
            branch_out: *std.ArrayListUnmanaged(Root),
        ) !void {
            // TODO: switch to a persistent_merkle_tree helper if/when one exists (e.g. getSingleProof).
            const leaf_gindex = Gindex.fromUint(@as(Gindex.Uint, @intCast(leaf_gindex_value)));

            var current = leaf_gindex;
            while (@intFromEnum(current) > 1) {
                const sibling = if ((@intFromEnum(current) & 1) == 0)
                    @as(Gindex, @enumFromInt(@intFromEnum(current) + 1))
                else
                    @as(Gindex, @enumFromInt(@intFromEnum(current) - 1));

                const sibling_node = try NodeId.getNode(root_node, pool, sibling);
                const sibling_root = sibling_node.getRoot(pool);
                try branch_out.append(allocator, sibling_root.*);

                current = @as(Gindex, @enumFromInt(@intFromEnum(current) >> 1));
            }
        }

        fn loadProof(allocator: std.mem.Allocator, dir: std.fs.Dir) !MerkleProof {
            var file = try dir.openFile("proof.yaml", .{});
            defer file.close();

            const contents = try file.readToEndAlloc(allocator, 4096);
            defer allocator.free(contents);

            return parseProofYaml(allocator, contents);
        }

        fn parseProofYaml(allocator: std.mem.Allocator, contents: []const u8) !MerkleProof {
            var proof = MerkleProof{
                .leaf = undefined,
                .leaf_index = 0,
                .branch = &.{},
            };

            var branch: std.ArrayListUnmanaged(Root) = .empty;
            errdefer branch.deinit(allocator);

            var leaf_parsed = false;
            var index_parsed = false;

            var iter = std.mem.tokenizeScalar(u8, contents, '\n');
            while (iter.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \r\t");
                if (trimmed.len == 0) continue;

                if (std.mem.startsWith(u8, trimmed, "leaf:")) {
                    const value_slice = std.mem.trim(u8, trimmed["leaf:".len..], " \t");
                    proof.leaf = try parseHexRoot(value_slice);
                    leaf_parsed = true;
                } else if (std.mem.startsWith(u8, trimmed, "leaf_index:")) {
                    const value_slice = std.mem.trim(u8, trimmed["leaf_index:".len..], " \t");
                    proof.leaf_index = try std.fmt.parseInt(u64, value_slice, 10);
                    index_parsed = true;
                } else if (trimmed[0] == '-') {
                    const value_slice = std.mem.trim(u8, trimmed[1..], " '\t");
                    const branch_value = try parseHexRoot(value_slice);
                    try branch.append(allocator, branch_value);
                }
            }

            if (!leaf_parsed or !index_parsed) {
                return error.InvalidProof;
            }

            proof.branch = try branch.toOwnedSlice(allocator);
            return proof;
        }

        fn parseHexRoot(raw_value: []const u8) !Root {
            var value = std.mem.trim(u8, raw_value, " '\t\"");
            if (std.mem.startsWith(u8, value, "0x")) {
                value = value[2..];
            }
            if (value.len != 64) {
                return error.InvalidHexLength;
            }

            var out: Root = undefined;
            _ = try std.fmt.hexToBytes(out[0..], value);
            return out;
        }
    };
}
