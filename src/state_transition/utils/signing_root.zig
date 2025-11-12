const std = @import("std");
const Allocator = std.mem.Allocator;
const Domain = types.primitive.Domain.Type;
const Root = types.primitive.Root.Type;
const types = @import("consensus_types");
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const SignedBeaconBlock = @import("../state_transition.zig").SignedBeaconBlock;
const Block = @import("../state_transition.zig").Block;
const SignedBlock = @import("../types/signed_block.zig").SignedBlock;

const SigningData = types.phase0.SigningData.Type;

/// Return the signing root of an object by calculating the root of the object-domain tree.
pub fn computeSigningRoot(comptime T: type, ssz_object: *const T.Type, domain: Domain, out: *[32]u8) !void {
    var object_root: Root = undefined;
    try T.hashTreeRoot(ssz_object, &object_root);
    const domain_wrapped_object: SigningData = .{
        .object_root = object_root,
        .domain = domain,
    };

    try types.phase0.SigningData.hashTreeRoot(&domain_wrapped_object, out);
}

pub fn computeBlockSigningRoot(allocator: Allocator, block: *const SignedBlock, domain: Domain, out: *[32]u8) !void {
    var object_root: Root = undefined;
    try block.hashTreeRoot(allocator, &object_root);
    const domain_wrapped_object: SigningData = .{
        .object_root = object_root,
        .domain = domain,
    };
    try types.phase0.SigningData.hashTreeRoot(&domain_wrapped_object, out);
}

test "computeSigningRoot - sanity" {
    const ssz_type = types.phase0.Checkpoint;
    const ssz_object: types.phase0.Checkpoint.Type = .{
        .epoch = 1,
        .root = [_]u8{0x01} ** 32,
    };

    const domain = [_]u8{0x01} ** 32;
    var out: [32]u8 = undefined;
    try computeSigningRoot(ssz_type, &ssz_object, domain, &out);
}

test "computeBlockSigningRoot - sanity" {
    const allocator = std.testing.allocator;
    var electra_block = types.electra.BeaconBlock.default_value;
    electra_block.slot = 2025;
    var signed_electra_block = types.electra.SignedBeaconBlock.default_value;
    signed_electra_block.message = electra_block;
    const domain = [_]u8{0x01} ** 32;
    var out: [32]u8 = undefined;

    const signed_beacon_block = SignedBeaconBlock{ .electra = &signed_electra_block };
    const signed_block = SignedBlock{ .regular = &signed_beacon_block };
    try computeBlockSigningRoot(allocator, &signed_block, domain, &out);
}
