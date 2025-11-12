const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("snappy");
const ForkSeq = @import("config").ForkSeq;
const isFixedType = @import("ssz").isFixedType;
const state_transition = @import("state_transition");
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;

const ct = @import("consensus_types");
const phase0 = ct.phase0;
const altair = ct.altair;
const bellatrix = ct.bellatrix;
const capella = ct.capella;
const deneb = ct.deneb;
const electra = ct.electra;

pub const BlsSetting = enum {
    default,
    required,
    ignored,

    pub fn verify(self: BlsSetting) bool {
        return switch (self) {
            .default, .required => true,
            .ignored => false,
        };
    }
};

pub fn TestCaseUtils(comptime fork: ForkSeq) type {
    const ForkTypes = @field(ct, fork.forkName());
    return struct {
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
            if (!electra.BeaconState.equals(expected.electra, actual.electra)) return error.NotEqual;
        },
    }
}
