const std = @import("std");
const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const preset_mod = @import("preset");
const test_case = @import("../test_case.zig");
const loadSszValue = test_case.loadSszSnappyValue;
const hex = @import("hex");

const pmt = @import("persistent_merkle_tree");
const proof = pmt.proof;
const Node = pmt.Node;
const Gindex = pmt.Gindex;

pub const Handler = enum {
    single_merkle_proof,

    pub fn suiteName(self: Handler) []const u8 {
        return @tagName(self);
    }
};

const MerkleProof = struct {
    leaf: [66]u8,
    leaf_index: u64,
    branch: [][66]u8,

    pub fn deinit(self: *MerkleProof, allocator: std.mem.Allocator) void {
        allocator.free(self.branch);
    }
};

pub fn TestCase(comptime fork: ForkSeq) type {
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

            var proof_data: MerkleProof = undefined;
            try loadProof(allocator, dir, &proof_data);

            return .{
                .body = body,
                .proof = proof_data,
            };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            if (comptime @hasDecl(BeaconBlockBody, "deinit")) {
                BeaconBlockBody.deinit(allocator, &self.body);
            }
        }

        fn runTest(self: *Self, allocator: std.mem.Allocator) !void {
            const actual_leaf_index: u64 = @intCast(preset_mod.KZG_COMMITMENT_GINDEX0);
            var actual_leaf: [32]u8 = undefined;
            try KzgCommitment.hashTreeRoot(&self.body.blob_kzg_commitments.items[0], &actual_leaf);

            var pool = try Node.Pool.init(allocator, 2048);
            defer pool.deinit();

            const root_node = try BeaconBlockBody.tree.fromValue(allocator, &pool, &self.body);
            const gindex = Gindex.fromUint(@as(Gindex.Uint, actual_leaf_index));

            var single_proof = try pmt.proof.createSingleProof(allocator, &pool, root_node, gindex);
            defer single_proof.deinit(allocator);

            var actual_proof = try buildActualProof(allocator, actual_leaf_index, &actual_leaf, single_proof.witnesses);
            defer actual_proof.deinit(allocator);

            try expectEqualProof(&self.proof, &actual_proof);
        }

        fn buildActualProof(
            allocator: std.mem.Allocator,
            leaf_index: u64,
            leaf_bytes: *const [32]u8,
            witnesses: [][32]u8,
        ) !MerkleProof {
            var branch = try allocator.alloc([66]u8, witnesses.len);
            errdefer allocator.free(branch);

            for (witnesses, 0..) |witness, i| {
                branch[i] = try hex.rootToHex(&witness);
            }

            return .{
                .leaf = try hex.rootToHex(leaf_bytes),
                .leaf_index = leaf_index,
                .branch = branch,
            };
        }

        fn expectEqualProof(
            expected: *const MerkleProof,
            actual: *const MerkleProof,
        ) !void {
            try std.testing.expectEqual(expected.leaf_index, actual.leaf_index);
            try std.testing.expectEqualSlices(u8, expected.leaf[0..66], actual.leaf[0..66]);
            try std.testing.expectEqual(expected.branch.len, actual.branch.len);
            for (expected.branch, 0..) |expected_witness, i| {
                try std.testing.expectEqualSlices(u8, expected_witness[0..66], actual.branch[i][0..66]);
            }
        }

        fn loadProof(allocator: std.mem.Allocator, dir: std.fs.Dir, out: *MerkleProof) !void {
            var file = try dir.openFile("proof.yaml", .{});
            defer file.close();

            const contents = try file.readToEndAlloc(allocator, 4096);
            defer allocator.free(contents);

            out.* = try parseProofYaml(allocator, contents);
        }

        fn parseProofYaml(allocator: std.mem.Allocator, contents: []const u8) !MerkleProof {
            var branch: std.ArrayListUnmanaged([66]u8) = .empty;
            errdefer branch.deinit(allocator);
            var leaf: ?[66]u8 = null;
            var leaf_index: ?u64 = null;

            var iter = std.mem.tokenizeScalar(u8, contents, '\n');
            const quote = "'\"";
            while (iter.next()) |line| {
                if (line.len == 0) continue;

                if (std.mem.startsWith(u8, line, "leaf: ")) {
                    const value_slice = std.mem.trim(u8, line["leaf: ".len..], quote);
                    std.debug.assert(value_slice.len == 66);
                    leaf = value_slice[0..66].*;
                } else if (std.mem.startsWith(u8, line, "leaf_index: ")) {
                    const value_slice = std.mem.trim(u8, line["leaf_index: ".len..], quote);
                    leaf_index = try std.fmt.parseInt(u64, value_slice, 10);
                } else if (std.mem.startsWith(u8, line, "- ")) {
                    const value_slice = std.mem.trim(u8, line[2..], quote);
                    std.debug.assert(value_slice.len == 66);
                    const branch_value = value_slice[0..66].*;
                    try branch.append(allocator, branch_value);
                }
            }

            if (leaf == null or leaf_index == null) {
                return error.InvalidProof;
            }

            const gindex = Gindex.fromUint(@as(Gindex.Uint, leaf_index.?));
            const expected_branch_len: usize = @intCast(gindex.pathLen());
            if (branch.items.len != expected_branch_len) {
                return error.InvalidProof;
            }

            return .{
                .leaf = leaf.?,
                .leaf_index = leaf_index.?,
                .branch = try branch.toOwnedSlice(allocator),
            };
        }
    };
}
