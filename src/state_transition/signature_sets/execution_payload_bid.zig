const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconConfig = @import("config").BeaconConfig;
const c = @import("constants");
const computeSigningRootVariable = @import("../utils/signing_root.zig").computeSigningRootVariable;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;

pub fn getExecutionPayloadBidSigningRoot(
    allocator: Allocator,
    config: *const BeaconConfig,
    state_slot: u64,
    bid: *const types.gloas.ExecutionPayloadBid.Type,
) ![32]u8 {
    const domain = try config.getDomain(computeEpochAtSlot(state_slot), c.DOMAIN_BEACON_BUILDER, null);

    var out: [32]u8 = undefined;
    try computeSigningRootVariable(types.gloas.ExecutionPayloadBid, allocator, bid, domain, &out);
    return out;
}
