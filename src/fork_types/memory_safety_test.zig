const std = @import("std");
const ct = @import("consensus_types");
const AnySignedBeaconBlock = @import("./any_beacon_block.zig").AnySignedBeaconBlock;

test "AnySignedBeaconBlock deserialize should deinit partial block on OOM" {
    const allocator = std.testing.allocator;
    const SignedBeaconBlock = ct.phase0.SignedBeaconBlock;

    var block = SignedBeaconBlock.default_value;
    defer SignedBeaconBlock.deinit(allocator, &block);

    try block.message.body.proposer_slashings.append(
        allocator,
        ct.phase0.ProposerSlashing.default_value,
    );
    try block.message.body.voluntary_exits.append(
        allocator,
        ct.phase0.SignedVoluntaryExit.default_value,
    );

    const bytes = try allocator.alloc(u8, SignedBeaconBlock.serializedSize(&block));
    defer allocator.free(bytes);
    _ = SignedBeaconBlock.serializeIntoBytes(&block, bytes);

    const voluntary_exits_fail_index = 2;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = voluntary_exits_fail_index },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        AnySignedBeaconBlock.deserialize(failing.allocator(), .full, .phase0, bytes),
    );

    // The decoded proposer slashings list must not leak when voluntary exits allocation fails.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
