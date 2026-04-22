const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const types = @import("consensus_types");
const constants = @import("constants");
const fork_types = @import("fork_types");
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const computeSigningRootAlloc = @import("../utils/signing_root.zig").computeSigningRootAlloc;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const gossip_domains = @import("gossip_domains.zig");

pub fn getSelectionProofSigningRoot(config: *const BeaconConfig, slot: u64, out: *[32]u8) !void {
    const domain = try gossip_domains.getDomainAtSlot(config, slot, constants.DOMAIN_SELECTION_PROOF);
    try computeSigningRoot(types.primitive.Slot, &slot, domain, out);
}

pub fn getAggregateAndProofSigningRoot(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch: types.primitive.Epoch.Type,
    aggregate: *const AnySignedAggregateAndProof,
    out: *[32]u8,
) !void {
    const slot = computeStartSlotAtEpoch(epoch);
    const domain = try gossip_domains.getDomainAtSlot(config, slot, constants.DOMAIN_AGGREGATE_AND_PROOF);
    switch (aggregate.*) {
        .phase0 => |signed_agg| try computeSigningRootAlloc(
            types.phase0.AggregateAndProof,
            allocator,
            &signed_agg.message,
            domain,
            out,
        ),
        .electra => |signed_agg| try computeSigningRootAlloc(
            types.electra.AggregateAndProof,
            allocator,
            &signed_agg.message,
            domain,
            out,
        ),
    }
}

pub fn getSelectionProofSignatureSet(
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    aggregate: *const AnySignedAggregateAndProof,
) !SingleSignatureSet {
    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.InvalidAggregatorIndex;

    var signing_root: [32]u8 = undefined;
    try getSelectionProofSigningRoot(config, aggregate.slot(), &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[aggregator_index],
        .signing_root = signing_root,
        .signature = aggregate.selectionProof(),
    };
}

pub fn getAggregateAndProofSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    aggregate: *const AnySignedAggregateAndProof,
) !SingleSignatureSet {
    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.InvalidAggregatorIndex;

    var signing_root: [32]u8 = undefined;
    try getAggregateAndProofSigningRoot(allocator, config, aggregate.targetEpoch(), aggregate, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[aggregator_index],
        .signing_root = signing_root,
        .signature = aggregate.signature(),
    };
}
