const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("snappy").raw;
const ForkSeq = @import("config").ForkSeq;
const isFixedType = @import("ssz").isFixedType;
const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const BeaconState = state_transition.BeaconState;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const phase0 = types.phase0;
const altair = types.altair;
const bellatrix = types.bellatrix;
const capella = types.capella;
const deneb = types.deneb;
const electra = types.electra;
const fulu = types.fulu;

pub const BlsSetting = enum {
    default,
    required,
    ignored,

    pub fn verify(self: BlsSetting) bool {
        return switch (self) {
            .required => true,
            .default, .ignored => false,
        };
    }
};

pub fn TestCaseUtils(comptime fork: ForkSeq) type {
    const ForkTypes = @field(types, fork.name());
    return struct {
        pub fn getForkPre() ForkSeq {
            return switch (fork) {
                .altair => .phase0,
                .bellatrix => .altair,
                .capella => .bellatrix,
                .deneb => .capella,
                .electra => .deneb,
                .fulu => .electra,
                else => unreachable,
            };
        }

        pub fn loadPreStatePreFork(allocator: Allocator, pool: *Node.Pool, dir: std.fs.Dir, fork_epoch: Epoch) !TestCachedBeaconState {
            const fork_pre = comptime getForkPre();
            const ForkPreTypes = @field(types, fork_pre.name());
            var pre_state = ForkPreTypes.BeaconState.default_value;
            try loadSszSnappyValue(ForkPreTypes.BeaconState, allocator, dir, "pre.ssz_snappy", &pre_state);
            defer ForkPreTypes.BeaconState.deinit(allocator, &pre_state);

            const pre_state_all_forks = try allocator.create(BeaconState);
            errdefer allocator.destroy(pre_state_all_forks);

            pre_state_all_forks.* = @unionInit(
                BeaconState,
                fork_pre.name(),
                try ForkPreTypes.BeaconState.TreeView.fromValue(allocator, pool, &pre_state),
            );
            errdefer pre_state_all_forks.deinit();

            return try TestCachedBeaconState.initFromState(allocator, pre_state_all_forks, fork, fork_epoch);
        }

        pub fn loadPreState(allocator: Allocator, pool: *Node.Pool, dir: std.fs.Dir) !TestCachedBeaconState {
            var pre_state = ForkTypes.BeaconState.default_value;
            try loadSszSnappyValue(ForkTypes.BeaconState, allocator, dir, "pre.ssz_snappy", &pre_state);
            defer ForkTypes.BeaconState.deinit(allocator, &pre_state);

            const pre_state_all_forks = try allocator.create(BeaconState);
            errdefer allocator.destroy(pre_state_all_forks);

            pre_state_all_forks.* = @unionInit(
                BeaconState,
                fork.name(),
                try ForkTypes.BeaconState.TreeView.fromValue(allocator, pool, &pre_state),
            );
            errdefer pre_state_all_forks.deinit();

            var f = try pre_state_all_forks.fork();
            const fork_epoch = try f.get("epoch");
            return try TestCachedBeaconState.initFromState(allocator, pre_state_all_forks, fork, fork_epoch);
        }

        /// consumer should deinit the returned state and destroy the pointer
        pub fn loadPostState(allocator: Allocator, pool: *Node.Pool, dir: std.fs.Dir) !?*BeaconState {
            if (dir.statFile("post.ssz_snappy")) |_| {
                var post_state = ForkTypes.BeaconState.default_value;
                try loadSszSnappyValue(ForkTypes.BeaconState, allocator, dir, "post.ssz_snappy", &post_state);
                defer ForkTypes.BeaconState.deinit(allocator, &post_state);

                const post_state_all_forks = try allocator.create(BeaconState);
                errdefer allocator.destroy(post_state_all_forks);

                post_state_all_forks.* = @unionInit(
                    BeaconState,
                    fork.name(),
                    try ForkTypes.BeaconState.TreeView.fromValue(allocator, pool, &post_state),
                );
                return post_state_all_forks;
            } else |err| {
                if (err == error.FileNotFound) {
                    return null;
                } else {
                    return err;
                }
            }
        }
    };
}

pub fn loadBlsSetting(allocator: std.mem.Allocator, dir: std.fs.Dir) BlsSetting {
    var file = dir.openFile("meta.yaml", .{}) catch return .default;
    defer file.close();

    const contents = file.readToEndAlloc(allocator, 100) catch return .default;
    defer allocator.free(contents);

    if (std.mem.indexOf(u8, contents, "bls_setting: 0") != null) {
        return .default;
    } else if (std.mem.indexOf(u8, contents, "bls_setting: 1") != null) {
        return .required;
    } else if (std.mem.indexOf(u8, contents, "bls_setting: 2") != null) {
        return .ignored;
    } else {
        return .default;
    }
}

/// load SignedBeaconBlock from file using runtime fork
/// consumer should deinit the returned block and destroy the pointer
pub fn loadSignedBeaconBlock(allocator: std.mem.Allocator, fork: ForkSeq, dir: std.fs.Dir, file_name: []const u8) !SignedBeaconBlock {
    return switch (fork) {
        .phase0 => blk: {
            const out = try allocator.create(phase0.SignedBeaconBlock.Type);
            out.* = phase0.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.phase0.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .phase0 = out,
            };
        },
        .altair => blk: {
            const out = try allocator.create(altair.SignedBeaconBlock.Type);
            out.* = altair.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.altair.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .altair = out,
            };
        },
        .bellatrix => blk: {
            const out = try allocator.create(bellatrix.SignedBeaconBlock.Type);
            out.* = bellatrix.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.bellatrix.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .bellatrix = out,
            };
        },
        .capella => blk: {
            const out = try allocator.create(capella.SignedBeaconBlock.Type);
            out.* = capella.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.capella.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .capella = out,
            };
        },
        .deneb => blk: {
            const out = try allocator.create(deneb.SignedBeaconBlock.Type);
            out.* = deneb.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.deneb.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .deneb = out,
            };
        },
        .electra => blk: {
            const out = try allocator.create(electra.SignedBeaconBlock.Type);
            out.* = electra.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.electra.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .electra = out,
            };
        },
        .fulu => blk: {
            const out = try allocator.create(fulu.SignedBeaconBlock.Type);
            out.* = fulu.SignedBeaconBlock.default_value;
            try loadSszSnappyValue(types.fulu.SignedBeaconBlock, allocator, dir, file_name, out);
            break :blk SignedBeaconBlock{
                .fulu = out,
            };
        },
    };
}

/// TODO: move this to SignedBeaconBlock deinit method if this is useful there
pub fn deinitSignedBeaconBlock(signed_block: SignedBeaconBlock, allocator: std.mem.Allocator) void {
    switch (signed_block) {
        .phase0 => |b| {
            phase0.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .altair => |b| {
            altair.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .bellatrix => |b| {
            bellatrix.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .capella => |b| {
            capella.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .deneb => |b| {
            deneb.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .electra => |b| {
            electra.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
        .fulu => |b| {
            fulu.SignedBeaconBlock.deinit(allocator, @constCast(b));
            allocator.destroy(b);
        },
    }
}

pub fn loadSszSnappyValue(comptime ST: type, allocator: std.mem.Allocator, dir: std.fs.Dir, file_name: []const u8, out: *ST.Type) !void {
    var object_file = try dir.openFile(file_name, .{});
    defer object_file.close();

    const value_bytes = try object_file.readToEndAlloc(allocator, 100_000_000);
    defer allocator.free(value_bytes);

    const serialized_buf = try allocator.alloc(u8, try snappy.uncompressedLength(value_bytes));
    defer allocator.free(serialized_buf);
    const serialized_len = try snappy.uncompress(value_bytes, serialized_buf);
    const serialized = serialized_buf[0..serialized_len];

    if (comptime isFixedType(ST)) {
        try ST.deserializeFromBytes(serialized, out);
    } else {
        try ST.deserializeFromBytes(allocator, serialized, out);
    }
}

pub fn expectEqualBeaconStates(expected: *BeaconState, actual: *BeaconState) !void {
    if (expected.forkSeq() != actual.forkSeq()) return error.ForkMismatch;

    if (!std.mem.eql(
        u8,
        try expected.hashTreeRoot(),
        try actual.hashTreeRoot(),
    )) {
        const Debug = struct {
            fn printDiff(comptime StateST: type, expected_state: *BeaconState, actual_state: *BeaconState) !void {
                var expected_view = StateST.TreeView{ .base_view = expected_state.baseView() };
                var actual_view = StateST.TreeView{ .base_view = actual_state.baseView() };

                inline for (StateST.fields) |field| {
                    const expected_field_root = try expected_view.getRoot(field.name);
                    const actual_field_root = try actual_view.getRoot(field.name);
                    if (!std.mem.eql(u8, expected_field_root, actual_field_root)) {
                        std.debug.print(
                            "field: {s}\n  expected_root: {s}\n  actual_root:   {s}\n",
                            .{
                                field.name,
                                std.fmt.fmtSliceHexLower(expected_field_root),
                                std.fmt.fmtSliceHexLower(actual_field_root),
                            },
                        );

                        @setEvalBranchQuota(100000);
                        const FieldST = StateST.getFieldType(field.name);
                        const allocator = std.testing.allocator;
                        {
                            var expected_field_view = try expected_view.get(field.name);
                            if (comptime @hasDecl(FieldST, "TreeView") and @hasDecl(FieldST.TreeView, "length") and @typeInfo(@TypeOf(FieldST.TreeView.length)) == .@"fn") {
                                std.debug.print(
                                    "  expected_value_length: {any}\n",
                                    .{try expected_field_view.length()},
                                );
                            }
                            var expected_field_value: FieldST.Type = undefined;
                            try expected_view.getValue(allocator, field.name, &expected_field_value);
                            defer if (@hasDecl(FieldST, "deinit"))
                                FieldST.deinit(allocator, &expected_field_value);

                            std.debug.print(
                                "  expected_value: {any}\n",
                                .{expected_field_value},
                            );
                        }
                        {
                            var actual_field_view = try actual_view.get(field.name);
                            if (comptime @hasDecl(FieldST, "TreeView") and @hasDecl(FieldST.TreeView, "length") and @typeInfo(@TypeOf(FieldST.TreeView.length)) == .@"fn") {
                                std.debug.print(
                                    "  actual_value_length:   {any}\n",
                                    .{try actual_field_view.length()},
                                );
                            }
                            var actual_field_value: FieldST.Type = undefined;
                            try actual_view.getValue(allocator, field.name, &actual_field_value);
                            defer if (@hasDecl(FieldST, "deinit"))
                                FieldST.deinit(allocator, &actual_field_value);

                            std.debug.print(
                                "  actual_value:   {any}\n",
                                .{actual_field_value},
                            );
                        }
                    }
                }
            }
        };

        switch (expected.forkSeq()) {
            .phase0 => try Debug.printDiff(types.phase0.BeaconState, expected, actual),
            .altair => try Debug.printDiff(types.altair.BeaconState, expected, actual),
            .bellatrix => try Debug.printDiff(types.bellatrix.BeaconState, expected, actual),
            .capella => try Debug.printDiff(types.capella.BeaconState, expected, actual),
            .deneb => try Debug.printDiff(types.deneb.BeaconState, expected, actual),
            .electra => try Debug.printDiff(types.electra.BeaconState, expected, actual),
            .fulu => try Debug.printDiff(types.fulu.BeaconState, expected, actual),
        }
        return error.NotEqual;
    }
}
