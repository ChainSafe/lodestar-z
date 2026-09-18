//! Tests for `signing_root.zig`.

const std = @import("std");
const types = @import("consensus_types");
const AnyBeaconBlock = @import("fork_types").AnyBeaconBlock;
const computeBlockSigningRoot = @import("signing_root.zig").computeBlockSigningRoot;
const computeSigningRoot = @import("signing_root.zig").computeSigningRoot;

test "computeSigningRoot - sanity" {
    const ssz_type = types.phase0.Checkpoint;
    const ssz_object: types.phase0.Checkpoint.Type = .{
        .epoch = 1,
        .root = [_]u8{0x01} ** 32,
    };

    const domain = [_]u8{0x01} ** 32;
    var out: [32]u8 = undefined;
    try computeSigningRoot(ssz_type, &ssz_object, &domain, &out);
}

test "computeBlockSigningRoot - sanity" {
    const allocator = std.testing.allocator;
    var electra_block = types.electra.BeaconBlock.default_value;
    electra_block.slot = 2025;
    const domain = [_]u8{0x01} ** 32;
    var out: [32]u8 = undefined;

    const beacon_block = AnyBeaconBlock{ .full_electra = &electra_block };
    try computeBlockSigningRoot(allocator, beacon_block, &domain, &out);
}
