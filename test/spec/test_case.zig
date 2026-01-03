const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("snappy").raw;
const ForkSeq = @import("config").ForkSeq;
const isFixedType = @import("ssz").isFixedType;
const state_transition = @import("state_transition");
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;

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
    const ForkTypes = @field(types, fork.forkName());
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

        pub fn loadPreStatePreFork(allocator: Allocator, dir: std.fs.Dir, fork_epoch: Epoch) !TestCachedBeaconStateAllForks {
            const fork_pre = comptime getForkPre();
            const ForkPreTypes = @field(types, fork_pre.forkName());
            const pre_state = try allocator.create(ForkPreTypes.BeaconState.Type);
            var transfered_pre_state: bool = false;
            errdefer {
                if (!transfered_pre_state) {
                    ForkPreTypes.BeaconState.deinit(allocator, pre_state);
                    allocator.destroy(pre_state);
                }
            }
            pre_state.* = ForkPreTypes.BeaconState.default_value;
            try loadSszSnappyValue(ForkPreTypes.BeaconState, allocator, dir, "pre.ssz_snappy", pre_state);
            transfered_pre_state = true;

            var pre_state_all_forks = try BeaconStateAllForks.init(fork_pre, pre_state);
            return try TestCachedBeaconStateAllForks.initFromState(allocator, &pre_state_all_forks, fork, fork_epoch);
        }

        pub fn loadPreState(allocator: Allocator, dir: std.fs.Dir) !TestCachedBeaconStateAllForks {
            const pre_state = try allocator.create(ForkTypes.BeaconState.Type);
            var transfered_pre_state: bool = false;
            errdefer {
                if (!transfered_pre_state) {
                    ForkTypes.BeaconState.deinit(allocator, pre_state);
                    allocator.destroy(pre_state);
                }
            }
            pre_state.* = ForkTypes.BeaconState.default_value;
            try loadSszSnappyValue(ForkTypes.BeaconState, allocator, dir, "pre.ssz_snappy", pre_state);
            transfered_pre_state = true;

            var pre_state_all_forks = try BeaconStateAllForks.init(fork, pre_state);
            return try TestCachedBeaconStateAllForks.initFromState(allocator, &pre_state_all_forks, fork, pre_state_all_forks.fork().epoch);
        }

        /// consumer should deinit the returned state and destroy the pointer
        pub fn loadPostState(allocator: Allocator, dir: std.fs.Dir) !?BeaconStateAllForks {
            if (dir.statFile("post.ssz_snappy")) |_| {
                const post_state = try allocator.create(ForkTypes.BeaconState.Type);
                errdefer {
                    ForkTypes.BeaconState.deinit(allocator, post_state);
                    allocator.destroy(post_state);
                }
                post_state.* = ForkTypes.BeaconState.default_value;
                try loadSszSnappyValue(ForkTypes.BeaconState, allocator, dir, "post.ssz_snappy", post_state);
                return try BeaconStateAllForks.init(fork, post_state);
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

pub fn expectEqualBeaconStates(expected: BeaconStateAllForks, actual: BeaconStateAllForks) !void {
    if (expected.forkSeq() != actual.forkSeq()) return error.ForkMismatch;

    switch (expected.forkSeq()) {
        .phase0 => {
            if (!phase0.BeaconState.equals(expected.phase0, actual.phase0)) return error.NotEqual;
        },
        .altair => {
            if (!altair.BeaconState.equals(expected.altair, actual.altair)) return error.NotEqual;
        },
        .bellatrix => {
            if (!bellatrix.BeaconState.equals(expected.bellatrix, actual.bellatrix)) return error.NotEqual;
        },
        .capella => {
            if (!capella.BeaconState.equals(expected.capella, actual.capella)) return error.NotEqual;
        },
        .deneb => {
            if (!deneb.BeaconState.equals(expected.deneb, actual.deneb)) return error.NotEqual;
        },
        .electra => {
            if (!electra.BeaconState.equals(expected.electra, actual.electra)) {
                // more debug
                if (!phase0.BeaconBlockHeader.equals(&expected.electra.latest_block_header, &actual.electra.latest_block_header)) return error.LatestBlockHeaderNotEqual;
                return error.NotEqual;
            }
        },
        .fulu => {
            if (!fulu.BeaconState.equals(expected.fulu, actual.fulu)) return error.NotEqual;
        },
    }
}
