const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const createAggregateSignatureSetFromComponents = @import("../utils/signature_sets.zig").createAggregateSignatureSetFromComponents;
const types = @import("consensus_types");
const constants = @import("constants");
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const gossip_domains = @import("gossip_domains.zig");

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub fn getSyncCommitteeSelectionProofSigningRoot(
    config: *const BeaconConfig,
    selection_data: *const types.altair.SyncAggregatorSelectionData.Type,
    out: *[32]u8,
) !void {
    const domain = try gossip_domains.getDomainAtSlot(
        config,
        selection_data.slot,
        constants.DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    );
    try computeSigningRoot(types.altair.SyncAggregatorSelectionData, selection_data, domain, out);
}

pub fn getContributionAndProofSigningRoot(
    config: *const BeaconConfig,
    contribution_and_proof: *const types.altair.ContributionAndProof.Type,
    out: *[32]u8,
) !void {
    const domain = try gossip_domains.getDomainAtSlot(
        config,
        contribution_and_proof.contribution.slot,
        constants.DOMAIN_CONTRIBUTION_AND_PROOF,
    );
    try computeSigningRoot(types.altair.ContributionAndProof, contribution_and_proof, domain, out);
}

pub fn getSyncContributionSigningRoot(
    config: *const BeaconConfig,
    contribution: *const types.altair.SyncCommitteeContribution.Type,
    out: *[32]u8,
) !void {
    const domain = try gossip_domains.getDomainAtSlot(
        config,
        contribution.slot,
        constants.DOMAIN_SYNC_COMMITTEE,
    );
    try computeSigningRoot(types.primitive.Root, &contribution.beacon_block_root, domain, out);
}

pub fn getSyncCommitteeSelectionProofSignatureSet(
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_contribution: *const types.altair.SignedContributionAndProof.Type,
) !SingleSignatureSet {
    const aggregator_index = signed_contribution.message.aggregator_index;
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.ValidatorNotFound;

    const selection_data = types.altair.SyncAggregatorSelectionData.Type{
        .slot = signed_contribution.message.contribution.slot,
        .subcommittee_index = signed_contribution.message.contribution.subcommittee_index,
    };
    var signing_root: [32]u8 = undefined;
    try getSyncCommitteeSelectionProofSigningRoot(config, &selection_data, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[aggregator_index],
        .signing_root = signing_root,
        .signature = signed_contribution.message.selection_proof,
    };
}

pub fn getContributionAndProofSignatureSet(
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_contribution: *const types.altair.SignedContributionAndProof.Type,
) !SingleSignatureSet {
    const aggregator_index = signed_contribution.message.aggregator_index;
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.ValidatorNotFound;

    var signing_root: [32]u8 = undefined;
    try getContributionAndProofSigningRoot(config, &signed_contribution.message, &signing_root);
    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[aggregator_index],
        .signing_root = signing_root,
        .signature = signed_contribution.signature,
    };
}

pub fn getSyncCommitteeContributionSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    contribution: *const types.altair.SyncCommitteeContribution.Type,
    participant_indices: []const ValidatorIndex,
) !AggregatedSignatureSet {
    const pubkeys = try allocator.alloc(@TypeOf(epoch_cache.index_to_pubkey.items[0]), participant_indices.len);
    errdefer allocator.free(pubkeys);

    for (participant_indices, 0..) |validator_index, i| {
        if (validator_index >= epoch_cache.index_to_pubkey.items.len) return error.ValidatorNotFound;
        pubkeys[i] = epoch_cache.index_to_pubkey.items[validator_index];
    }

    var signing_root: [32]u8 = undefined;
    try getSyncContributionSigningRoot(config, contribution, &signing_root);
    return createAggregateSignatureSetFromComponents(pubkeys, signing_root, contribution.signature);
}
