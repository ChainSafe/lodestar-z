const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconConfig = @import("config").BeaconConfig;
const c = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;

pub fn getExecutionPayloadBidSigningRoot(
    allocator: Allocator,
    config: *const BeaconConfig,
    state_slot: u64,
    bid: *const types.gloas.ExecutionPayloadBid.Type,
) ![32]u8 {
    const domain = try config.getDomain(computeEpochAtSlot(state_slot), c.DOMAIN_BEACON_BUILDER, null);

    var out: [32]u8 = undefined;
    var object_root: [32]u8 = undefined;
    try types.gloas.ExecutionPayloadBid.hashTreeRoot(allocator, bid, &object_root);
    try computeSigningRoot(types.primitive.Root, &object_root, domain, &out);
    return out;
}
