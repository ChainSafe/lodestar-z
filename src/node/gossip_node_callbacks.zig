//! Gossip callbacks for the GossipHandler vtable.
//!
//! Extracted from beacon_node.zig. Bridges the type-erased *anyopaque
//! callbacks required by GossipHandler back to BeaconNode state.
//!
//! All functions that receive `ptr: *anyopaque` cast it to `*BeaconNode`.
//! The three "ptr-free" vtable functions (getProposerIndex, isKnownBlockRoot,
//! getValidatorCount) are threaded through the GossipHandler's `node` field
//! instead of a module-level global — eliminating the gossip_node hack.

const std = @import("std");
const scoped_log = std.log.scoped(.gossip_node_callbacks);
const config_mod = @import("config");
const types = @import("consensus_types");
const state_transition = @import("state_transition");
const bls_mod = @import("bls");
const chain_mod = @import("chain");
const fork_types = @import("fork_types");
const AnyAttestation = fork_types.AnyAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const preset = @import("preset").preset;
const preset_root = @import("preset");
const constants = @import("constants");
const ssz = @import("ssz");
const processor_mod = @import("processor");
const AggregateWork = processor_mod.work_item.AggregateWork;
const AttestationWork = processor_mod.work_item.AttestationWork;
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
const gossip_handler_mod = @import("gossip_handler.zig");
const UnknownParentBlock = gossip_handler_mod.UnknownParentBlock;
const verifyMerkleBranch = state_transition.verifyMerkleBranch;
const aggregate_signature_sets = state_transition.signature_sets.aggregate_and_proof;
const sync_contribution_signature_sets = state_transition.signature_sets.sync_contribution_and_proof;
const gossip_domains = state_transition.signature_sets.gossip_domains;

// Import BeaconNode lazily to avoid circular dependency.
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const ResolvedAttestationData = struct {
    committee_validator_indices: []const ValidatorIndex,
    signing_root: [32]u8,
    expected_subnet: u8,
};

const OwnedIndexedAttestation = union(enum) {
    phase0: types.phase0.IndexedAttestation.Type,
    electra: types.electra.IndexedAttestation.Type,

    fn asAny(self: *OwnedIndexedAttestation) AnyIndexedAttestation {
        return switch (self.*) {
            .phase0 => |*att| .{ .phase0 = att },
            .electra => |*att| .{ .electra = att },
        };
    }

    fn deinit(self: *OwnedIndexedAttestation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .phase0 => |*att| att.attesting_indices.deinit(allocator),
            .electra => |*att| att.attesting_indices.deinit(allocator),
        }
    }
};

// ---------------------------------------------------------------------------
// Block import callback
// ---------------------------------------------------------------------------

pub fn importBlockFromGossip(ptr: *anyopaque, prepared: chain_mod.PreparedBlockInput) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const result = node.importPreparedBlock(prepared) catch |err| {
        scoped_log.debug("Gossip block import failed: {}", .{err});
        return err;
    };
    switch (result) {
        .ignored, .pending => {},
        .imported => |imported| {
            scoped_log.debug("GOSSIP BLOCK IMPORTED (via handler) slot={d}", .{imported.slot});
        },
    }
}

pub fn queueUnknownBlockFromGossip(ptr: *anyopaque, block: UnknownParentBlock) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var prepared = chain_mod.PreparedBlockInput{
        .block = block.block,
        .source = .gossip,
        .block_root = block.block_root,
        .seen_timestamp_sec = block.seen_timestamp_sec,
    };
    prepared.setPeerId(block.peer_id);
    _ = try node.queueOrphanPreparedBlock(prepared, block.peer_id);
}

pub fn queueUnknownBlockAttestationFromGossip(
    ptr: *anyopaque,
    block_root: [32]u8,
    work: AttestationWork,
    peer_id: ?[]const u8,
) anyerror!bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.queueUnknownBlockAttestation(block_root, work, peer_id);
}

pub fn queueUnknownBlockAggregateFromGossip(
    ptr: *anyopaque,
    block_root: [32]u8,
    work: AggregateWork,
    peer_id: ?[]const u8,
) anyerror!bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.queueUnknownBlockAggregate(block_root, work, peer_id);
}

// ---------------------------------------------------------------------------
// "Ptr-free" vtable callbacks — use the node pointer from GossipHandler.node.
// These are now regular ptr-bearing callbacks matching GossipHandler's node field.
// ---------------------------------------------------------------------------

/// Returns the expected block proposer for `slot` from the head state's epoch cache.
pub fn getForkSeqForSlot(ptr: *anyopaque, slot: u64) config_mod.ForkSeq {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.config.forkSeq(slot);
}

/// Returns the expected block proposer for `slot` from the head state's epoch cache.
pub fn getProposerIndex(ptr: *anyopaque, slot: u64) ?u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.chainQuery().getProposerIndex(slot);
}

/// Returns true if `root` appears in the head tracker's slot→root map or fork choice.
pub fn isKnownBlockRoot(ptr: *anyopaque, root: [32]u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.chainQuery().isKnownBlockRoot(root);
}

/// Returns fork-choice block metadata for `root` when it is known.
pub fn getKnownBlockInfo(ptr: *anyopaque, root: [32]u8) ?chain_mod.gossip_validation.ChainState.KnownBlockInfo {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const block = node.chain.forkChoice().getBlockDefaultStatus(root) orelse return null;
    return .{
        .slot = block.slot,
        .target_root = block.target_root,
    };
}

/// Returns the total validator count.
pub fn getValidatorCount(ptr: *anyopaque) u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.chainQuery().getValidatorCount();
}

pub fn getBlobSidecarSubnetCountForSlot(ptr: *anyopaque, slot: u64) u64 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const fork_seq = node.config.forkSeq(slot);
    return if (fork_seq.gte(.electra))
        node.config.chain.BLOB_SIDECAR_SUBNET_COUNT_ELECTRA
    else
        node.config.chain.BLOB_SIDECAR_SUBNET_COUNT;
}

pub fn computeAttestationSubnet(ptr: *anyopaque, slot: u64, committee_index: u64) ?u8 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return null;
    return cached.epoch_cache.computeSubnetForSlot(slot, @intCast(committee_index)) catch null;
}

fn syncCommitteePositionsForValidator(node: *BeaconNode, slot: u64, validator_index: u64) ?[]const u32 {
    const cached = node.headState() orelse return null;
    const indexed = cached.epoch_cache.getIndexedSyncCommittee(slot) catch return null;
    const positions = indexed.getValidatorIndexMap().get(validator_index) orelse return null;
    return positions.items;
}

fn loadPreStateForGossipHeader(
    node: *BeaconNode,
    parent_root: [32]u8,
    block_slot: u64,
) !*state_transition.CachedBeaconState {
    const parent = node.chain.forkChoice().getBlockDefaultStatus(parent_root) orelse
        return error.ParentUnknown;
    if (parent.slot >= block_slot) return error.NotLaterThanParent;

    const parent_state_root = (try node.chainQuery().stateRootByBlockRoot(parent_root)) orelse
        return error.ParentStateUnavailable;

    return node.chain.queued_regen.getPreState(
        parent_root,
        parent_state_root,
        parent.slot,
        block_slot,
        .fork_choice,
    ) catch |err| switch (err) {
        error.NoPreStateAvailable => error.NoPreStateAvailable,
        else => err,
    };
}

fn verifyExpectedProposer(
    pre_state: *const state_transition.CachedBeaconState,
    slot: u64,
    proposer_index: u64,
) !void {
    const expected_proposer = try pre_state.getBeaconProposer(slot);
    if (expected_proposer != proposer_index) return error.InvalidProposer;
}

fn verifyBlockHeaderProposerSignature(
    node: *BeaconNode,
    pre_state: *const state_transition.CachedBeaconState,
    signed_block_header: *const types.phase0.SignedBeaconBlockHeader.Type,
) !void {
    const proposer_index = signed_block_header.message.proposer_index;
    if (proposer_index >= pre_state.epoch_cache.index_to_pubkey.items.len) {
        return error.InvalidProposer;
    }

    const domain = try node.config.getDomain(
        pre_state.epoch_cache.epoch,
        constants.DOMAIN_BEACON_PROPOSER,
        signed_block_header.message.slot,
    );
    var signing_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.phase0.BeaconBlockHeader,
        &signed_block_header.message,
        domain,
        &signing_root,
    );

    const valid = state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = pre_state.epoch_cache.index_to_pubkey.items[proposer_index],
        .signing_root = signing_root,
        .signature = signed_block_header.signature,
    }) catch return error.InvalidSignature;
    if (!valid) return error.InvalidSignature;
}

fn verifyBlobSidecarInclusionProof(sidecar: *const types.deneb.BlobSidecar.Type) !void {
    var leaf: [32]u8 = undefined;
    try types.primitive.KZGCommitment.hashTreeRoot(&sidecar.kzg_commitment, &leaf);

    var proof: [33][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 33;
    for (sidecar.kzg_commitment_inclusion_proof, 0..) |proof_node, i| {
        proof[i] = proof_node;
    }

    if (!verifyMerkleBranch(
        leaf,
        &proof,
        preset.KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
        preset_root.KZG_COMMITMENT_SUBTREE_INDEX0 + sidecar.index,
        sidecar.signed_block_header.message.body_root,
    )) {
        return error.InvalidInclusionProof;
    }
}

fn verifyDataColumnSidecarInclusionProof(
    allocator: std.mem.Allocator,
    sidecar: *const types.fulu.DataColumnSidecar.Type,
) !void {
    var leaf: [32]u8 = undefined;
    try types.deneb.BlobKzgCommitments.hashTreeRoot(allocator, &sidecar.kzg_commitments, &leaf);

    var proof: [33][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 33;
    for (sidecar.kzg_commitments_inclusion_proof, 0..) |proof_node, i| {
        proof[i] = proof_node;
    }

    if (!verifyMerkleBranch(
        leaf,
        &proof,
        preset.KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
        preset_root.KZG_COMMITMENTS_SUBTREE_INDEX,
        sidecar.signed_block_header.message.body_root,
    )) {
        return error.InvalidInclusionProof;
    }
}

fn syncContributionParticipantIndices(
    allocator: std.mem.Allocator,
    cached: *const state_transition.CachedBeaconState,
    contribution: *const types.altair.SyncCommitteeContribution.Type,
) !std.array_list.AlignedManaged(ValidatorIndex, null) {
    const subcommittee_size: usize = preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT;
    if (contribution.subcommittee_index >= constants.SYNC_COMMITTEE_SUBNET_COUNT) {
        return error.InvalidSubcommitteeIndex;
    }

    const indexed = try cached.epoch_cache.getIndexedSyncCommittee(contribution.slot);
    const validator_indices = indexed.getValidatorIndices();
    const start_index = contribution.subcommittee_index * subcommittee_size;
    if (start_index + subcommittee_size > validator_indices.len) {
        return error.InvalidSubcommitteeIndex;
    }

    const all_validator_indices = @as(
        *const [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex,
        @ptrCast(validator_indices.ptr),
    );
    var subcommittee_validator_indices: [subcommittee_size]ValidatorIndex = undefined;
    @memcpy(
        subcommittee_validator_indices[0..],
        all_validator_indices[start_index..][0..subcommittee_size],
    );

    return contribution.aggregation_bits.intersectValues(
        ValidatorIndex,
        allocator,
        &subcommittee_validator_indices,
    );
}

fn verifySingleValidatorSignature(
    pubkey: bls_mod.PublicKey,
    signing_root: [32]u8,
    signature: types.primitive.BLSSignature.Type,
) !void {
    const valid = state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = pubkey,
        .signing_root = signing_root,
        .signature = signature,
    }) catch return error.InvalidSignature;
    if (!valid) return error.InvalidSignature;
}

fn verifySyncContributionAggregateSignature(
    allocator: std.mem.Allocator,
    config: *const config_mod.BeaconConfig,
    cached: *const state_transition.CachedBeaconState,
    contribution: *const types.altair.SyncCommitteeContribution.Type,
    participant_indices: []const ValidatorIndex,
) !void {
    const sig_set = try sync_contribution_signature_sets.getSyncCommitteeContributionSignatureSet(
        allocator,
        config,
        cached.epoch_cache,
        contribution,
        participant_indices,
    );
    defer allocator.free(sig_set.pubkeys);

    const valid = state_transition.signature_sets.verifyAggregatedSignatureSet(&sig_set) catch return error.InvalidSignature;
    if (!valid) return error.InvalidSignature;
}

pub fn isValidSyncCommitteeSubnet(ptr: *anyopaque, slot: u64, validator_index: u64, subnet: u64) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const positions = syncCommitteePositionsForValidator(node, slot, validator_index) orelse return false;
    const subcommittee_size: u32 = @intCast(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);

    for (positions) |position| {
        if (@as(u64, @intCast(@divFloor(position, subcommittee_size))) == subnet) return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Import callbacks
// ---------------------------------------------------------------------------

fn getSingleAttestingIndexPhase0FromEpochCache(
    epoch_cache: *const state_transition.EpochCache,
    attestation: *const types.phase0.Attestation.Type,
) !types.primitive.ValidatorIndex.Type {
    const committee = try epoch_cache.getBeaconCommittee(attestation.data.slot, attestation.data.index);
    if (attestation.aggregation_bits.bit_len != committee.len) return error.InvalidGossipAttestation;

    const bit_index = attestation.aggregation_bits.getSingleTrueBit() orelse
        return error.InvalidGossipAttestation;
    if (bit_index >= committee.len) return error.InvalidGossipAttestation;

    return committee[bit_index];
}

fn convertSingleAttestationResolved(
    allocator: std.mem.Allocator,
    single: *const types.electra.SingleAttestation.Type,
    validator_committee_index: u32,
    committee_size: u32,
) !types.electra.Attestation.Type {
    const AggregationBits = ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT);
    const CommitteeBits = ssz.BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);

    var aggregation_bits = try AggregationBits.Type.fromBitLen(allocator, committee_size);
    errdefer aggregation_bits.data.deinit(allocator);
    try aggregation_bits.set(allocator, validator_committee_index, true);

    var committee_bits = CommitteeBits.default_value;
    try committee_bits.set(single.committee_index, true);

    var data = single.data;
    data.index = 0;

    return .{
        .aggregation_bits = aggregation_bits,
        .data = data,
        .signature = single.signature,
        .committee_bits = committee_bits,
    };
}

fn dupAttestingIndices(
    allocator: std.mem.Allocator,
    attesting_indices: []const ValidatorIndex,
) !std.ArrayListUnmanaged(ValidatorIndex) {
    var indices = try std.ArrayListUnmanaged(ValidatorIndex).initCapacity(allocator, attesting_indices.len);
    indices.appendSliceAssumeCapacity(attesting_indices);
    return indices;
}

fn buildIndexedAttestationFromSingle(
    allocator: std.mem.Allocator,
    attestation: *const AnyGossipAttestation,
    resolved: *const ResolvedAttestation,
) !OwnedIndexedAttestation {
    var attesting_indices = try dupAttestingIndices(allocator, &.{resolved.validator_index});
    errdefer attesting_indices.deinit(allocator);

    return switch (attestation.*) {
        .phase0 => |att| .{
            .phase0 = .{
                .attesting_indices = attesting_indices,
                .data = att.data,
                .signature = att.signature,
            },
        },
        .electra_single => |single| .{
            .electra = .{
                .attesting_indices = attesting_indices,
                .data = single.data,
                .signature = single.signature,
            },
        },
    };
}

fn buildIndexedAttestationFromAggregate(
    allocator: std.mem.Allocator,
    aggregate: *const AnySignedAggregateAndProof,
    resolved: *const ResolvedAggregate,
) !OwnedIndexedAttestation {
    var attesting_indices = try dupAttestingIndices(allocator, resolved.attesting_indices);
    errdefer attesting_indices.deinit(allocator);

    return switch (aggregate.attestation()) {
        .phase0 => |att| .{
            .phase0 = .{
                .attesting_indices = attesting_indices,
                .data = att.data,
                .signature = att.signature,
            },
        },
        .electra => |att| .{
            .electra = .{
                .attesting_indices = attesting_indices,
                .data = att.data,
                .signature = att.signature,
            },
        },
    };
}

fn getAttestationSigningRootFromEpochCache(
    node: *const BeaconNode,
    _: *const state_transition.EpochCache,
    attestation: *const AnyGossipAttestation,
    out: *[32]u8,
) !void {
    try gossipAttestationDataSigningRoot(node.config, &attestation.data(), out);
}

fn getAttestationSigningRootFromAnyAttestation(
    node: *const BeaconNode,
    _: *const state_transition.EpochCache,
    attestation: *const AnyAttestation,
    out: *[32]u8,
) !void {
    try gossipAttestationDataSigningRoot(node.config, &attestation.data(), out);
}

fn gossipDomainAtSlot(
    config: *const config_mod.BeaconConfig,
    slot: u64,
    domain_type: types.primitive.DomainType.Type,
) !*const [32]u8 {
    return gossip_domains.getDomainAtSlot(config, slot, domain_type);
}

fn gossipAttestationDataSigningRoot(
    config: *const config_mod.BeaconConfig,
    data: *const types.phase0.AttestationData.Type,
    out: *[32]u8,
) !void {
    try state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(config, 0, data, out);
}

fn gossipSelectionProofSigningRoot(
    config: *const config_mod.BeaconConfig,
    slot: u64,
    out: *[32]u8,
) !void {
    try aggregate_signature_sets.getSelectionProofSigningRoot(config, slot, out);
}

fn gossipAggregateAndProofSigningRoot(
    allocator: std.mem.Allocator,
    config: *const config_mod.BeaconConfig,
    aggregate: *const AnySignedAggregateAndProof,
    epoch: types.primitive.Epoch.Type,
    out: *[32]u8,
) !void {
    try aggregate_signature_sets.getAggregateAndProofSigningRoot(allocator, config, epoch, aggregate, out);
}

fn gossipSyncSelectionProofSigningRoot(
    config: *const config_mod.BeaconConfig,
    selection_data: *const types.altair.SyncAggregatorSelectionData.Type,
    out: *[32]u8,
) !void {
    try sync_contribution_signature_sets.getSyncCommitteeSelectionProofSigningRoot(config, selection_data, out);
}

fn gossipContributionAndProofSigningRoot(
    config: *const config_mod.BeaconConfig,
    contribution_and_proof: *const types.altair.ContributionAndProof.Type,
    out: *[32]u8,
) !void {
    try sync_contribution_signature_sets.getContributionAndProofSigningRoot(config, contribution_and_proof, out);
}

fn gossipSyncContributionSigningRoot(
    config: *const config_mod.BeaconConfig,
    contribution: *const types.altair.SyncCommitteeContribution.Type,
    out: *[32]u8,
) !void {
    try sync_contribution_signature_sets.getSyncContributionSigningRoot(config, contribution, out);
}

fn resolveCachedAttestationData(
    node: *BeaconNode,
    slot: u64,
    committee_index: u64,
    attestation_data_root: *const [32]u8,
    comptime AttestationType: type,
    attestation: *const AttestationType,
    signing_root_fn: *const fn (
        node: *const BeaconNode,
        epoch_cache: *const state_transition.EpochCache,
        attestation: *const AttestationType,
        out: *[32]u8,
    ) anyerror!void,
) !ResolvedAttestationData {
    const cached = node.headState() orelse return error.NoHeadState;
    const epoch_cache = cached.epoch_cache;

    if (node.chain.attestation_data_cache.get(slot, committee_index, attestation_data_root.*)) |entry| {
        return .{
            .committee_validator_indices = entry.committee_validator_indices,
            .signing_root = entry.signing_root,
            .expected_subnet = entry.expected_subnet,
        };
    }

    const committee = try epoch_cache.getBeaconCommittee(slot, committee_index);
    const expected_subnet = try epoch_cache.computeSubnetForSlot(slot, committee_index);

    var signing_root: [32]u8 = undefined;
    try signing_root_fn(node, epoch_cache, attestation, &signing_root);

    _ = try node.chain.attestation_data_cache.insert(
        slot,
        committee_index,
        attestation_data_root.*,
        committee,
        signing_root,
        expected_subnet,
    );

    return .{
        .committee_validator_indices = committee,
        .signing_root = signing_root,
        .expected_subnet = expected_subnet,
    };
}

fn resolvePhase0Attester(
    committee: []const types.primitive.ValidatorIndex.Type,
    attestation: *const types.phase0.Attestation.Type,
) !struct { validator_index: u64, validator_committee_index: u32 } {
    if (attestation.aggregation_bits.bit_len != committee.len) return error.InvalidGossipAttestation;

    const bit_index = attestation.aggregation_bits.getSingleTrueBit() orelse
        return error.InvalidGossipAttestation;
    if (bit_index >= committee.len) return error.InvalidGossipAttestation;

    return .{
        .validator_index = committee[bit_index],
        .validator_committee_index = @intCast(bit_index),
    };
}

fn resolveElectraAttester(
    committee: []const types.primitive.ValidatorIndex.Type,
    attestation: *const types.electra.SingleAttestation.Type,
) !u32 {
    for (committee, 0..) |validator_index, validator_committee_index| {
        if (validator_index == attestation.attester_index) {
            return @intCast(validator_committee_index);
        }
    }
    return error.AttesterNotInCommittee;
}

pub fn resolveAttestation(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    attestation_data_root: *const [32]u8,
) anyerror!ResolvedAttestation {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached_data = try resolveCachedAttestationData(
        node,
        attestation.slot(),
        attestation.committeeIndex(),
        attestation_data_root,
        AnyGossipAttestation,
        attestation,
        getAttestationSigningRootFromEpochCache,
    );

    return switch (attestation.*) {
        .phase0 => |phase0_att| blk: {
            const resolved = try resolvePhase0Attester(cached_data.committee_validator_indices, &phase0_att);
            break :blk .{
                .validator_index = resolved.validator_index,
                .validator_committee_index = resolved.validator_committee_index,
                .committee_size = @intCast(cached_data.committee_validator_indices.len),
                .signing_root = cached_data.signing_root,
                .expected_subnet = cached_data.expected_subnet,
                .already_seen = node.chain.seen_attesters.isKnown(phase0_att.data.target.epoch, resolved.validator_index),
            };
        },
        .electra_single => |electra_att| blk: {
            const validator_committee_index = try resolveElectraAttester(cached_data.committee_validator_indices, &electra_att);
            break :blk .{
                .validator_index = electra_att.attester_index,
                .validator_committee_index = validator_committee_index,
                .committee_size = @intCast(cached_data.committee_validator_indices.len),
                .signing_root = cached_data.signing_root,
                .expected_subnet = cached_data.expected_subnet,
                .already_seen = node.chain.seen_attesters.isKnown(electra_att.data.target.epoch, electra_att.attester_index),
            };
        },
    };
}

pub fn importResolvedAttestation(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    attestation_data_root: *const [32]u8,
    resolved: *const ResolvedAttestation,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var indexed = try buildIndexedAttestationFromSingle(node.allocator, attestation, resolved);
    defer indexed.deinit(node.allocator);
    var any_indexed = indexed.asAny();

    switch (attestation.*) {
        .phase0 => |att| {
            try node.chainService().importIndexedAttestation(
                resolved.validator_index,
                .{ .phase0 = att },
                &any_indexed,
                attestation_data_root.*,
            );
        },
        .electra_single => |single| {
            var full_att = try convertSingleAttestationResolved(
                node.allocator,
                &single,
                resolved.validator_committee_index,
                resolved.committee_size,
            );
            defer full_att.aggregation_bits.data.deinit(node.allocator);

            try node.chainService().importIndexedAttestation(
                resolved.validator_index,
                .{ .electra = full_att },
                &any_indexed,
                attestation_data_root.*,
            );
        },
    }
}

pub fn importAttestation(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
) anyerror!void {
    var attestation_data_root: [32]u8 = undefined;
    try types.phase0.AttestationData.hashTreeRoot(&attestation.data(), &attestation_data_root);
    const resolved = try resolveAttestation(ptr, attestation, &attestation_data_root);
    try importResolvedAttestation(ptr, attestation, &attestation_data_root, &resolved);
}

fn getAttestingIndicesForAnyAttestation(
    node: *BeaconNode,
    attestation: AnyAttestation,
) !std.array_list.AlignedManaged(types.primitive.ValidatorIndex.Type, null) {
    const cached = node.headState() orelse return error.NoHeadState;
    return switch (attestation) {
        .phase0 => |att| cached.epoch_cache.getAttestingIndicesPhase0(&att),
        .electra => |att| cached.epoch_cache.getAttestingIndicesElectra(&att),
    };
}

fn getSingleCommitteeAttestingIndices(
    allocator: std.mem.Allocator,
    attestation: *const AnyAttestation,
    committee_validator_indices: []const ValidatorIndex,
) ![]ValidatorIndex {
    return switch (attestation.*) {
        .phase0 => |phase0_att| blk: {
            var attesting_indices = phase0_att.aggregation_bits.intersectValues(
                ValidatorIndex,
                allocator,
                committee_validator_indices,
            ) catch |err| switch (err) {
                error.InvalidSize => return error.InvalidGossipAttestation,
                else => return err,
            };
            break :blk try attesting_indices.toOwnedSlice();
        },
        .electra => |electra_att| blk: {
            if (electra_att.committee_bits.getSingleTrueBit() == null) return error.InvalidGossipAttestation;
            var attesting_indices = electra_att.aggregation_bits.intersectValues(
                ValidatorIndex,
                allocator,
                committee_validator_indices,
            ) catch |err| switch (err) {
                error.InvalidSize => return error.InvalidGossipAttestation,
                else => return err,
            };
            break :blk try attesting_indices.toOwnedSlice();
        },
    };
}

pub fn resolveAggregate(
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    attestation_data_root: *const [32]u8,
) anyerror!ResolvedAggregate {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;
    const epoch_cache = cached.epoch_cache;
    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.InvalidAggregatorIndex;

    const attestation = aggregate.attestation();
    const committee_index = switch (attestation) {
        .phase0 => |phase0_att| phase0_att.data.index,
        .electra => |electra_att| electra_att.committee_bits.getSingleTrueBit() orelse return error.InvalidGossipAttestation,
    };
    const cached_data = try resolveCachedAttestationData(
        node,
        attestation.slot(),
        committee_index,
        attestation_data_root,
        AnyAttestation,
        &attestation,
        getAttestationSigningRootFromAnyAttestation,
    );

    var aggregator_in_committee = false;
    for (cached_data.committee_validator_indices) |validator_index| {
        if (validator_index == aggregator_index) {
            aggregator_in_committee = true;
            break;
        }
    }
    if (!aggregator_in_committee) return error.AggregatorNotInCommittee;

    if (!state_transition.isAggregatorFromCommitteeLength(
        cached_data.committee_validator_indices.len,
        aggregate.selectionProof(),
    )) return error.InvalidSelectionProof;

    const attesting_indices = try getSingleCommitteeAttestingIndices(
        node.allocator,
        &attestation,
        cached_data.committee_validator_indices,
    );
    errdefer node.allocator.free(attesting_indices);
    if (attesting_indices.len == 0) return error.EmptyAggregateAttestation;

    const att_slot = attestation.slot();

    var selection_signing_root: [32]u8 = undefined;
    try gossipSelectionProofSigningRoot(node.config, att_slot, &selection_signing_root);

    var aggregate_signing_root: [32]u8 = undefined;
    try gossipAggregateAndProofSigningRoot(
        node.allocator,
        node.config,
        aggregate,
        attestation.data().target.epoch,
        &aggregate_signing_root,
    );

    return ResolvedAggregate.initOwned(
        attesting_indices,
        cached_data.signing_root,
        selection_signing_root,
        aggregate_signing_root,
    );
}

pub fn importResolvedAggregate(
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    attestation_data_root: *const [32]u8,
    resolved: *const ResolvedAggregate,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var indexed = try buildIndexedAttestationFromAggregate(node.allocator, aggregate, resolved);
    defer indexed.deinit(node.allocator);
    var any_indexed = indexed.asAny();
    try node.chainService().importIndexedAggregate(
        aggregate.attestation(),
        &any_indexed,
        attestation_data_root.*,
    );
}

pub fn importAggregate(ptr: *anyopaque, aggregate: *const AnySignedAggregateAndProof) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var attestation_data_root: [32]u8 = undefined;
    try types.phase0.AttestationData.hashTreeRoot(&aggregate.attestation().data(), &attestation_data_root);
    const resolved = try resolveAggregate(ptr, aggregate, &attestation_data_root);
    defer resolved.deinit(node.allocator);
    try importResolvedAggregate(ptr, aggregate, &attestation_data_root, &resolved);
}

pub fn importVoluntaryExit(ptr: *anyopaque, exit: *const types.phase0.SignedVoluntaryExit.Type) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    try node.chainService().importVoluntaryExit(exit.*);
}

pub fn importProposerSlashing(ptr: *anyopaque, slashing: *const types.phase0.ProposerSlashing.Type) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    try node.chainService().importProposerSlashing(slashing.*);
}

pub fn importAttesterSlashing(ptr: *anyopaque, slashing: *const AnyAttesterSlashing) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    try node.chainService().importAttesterSlashing(slashing);
}

pub fn importBlsChange(ptr: *anyopaque, change: *const types.capella.SignedBLSToExecutionChange.Type) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    try node.chainService().importBlsChange(change.*);
}

pub fn importSyncContribution(ptr: *anyopaque, signed_contribution: *const types.altair.SignedContributionAndProof.Type) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    try node.chainService().importSyncContribution(&signed_contribution.message.contribution);
}

pub fn importSyncCommitteeMessage(ptr: *anyopaque, msg: *const types.altair.SyncCommitteeMessage.Type, subnet: u64) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const positions = syncCommitteePositionsForValidator(node, msg.slot, msg.validator_index) orelse return error.ValidatorNotFound;
    const subcommittee_size: u32 = @intCast(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);
    var imported = false;

    for (positions) |position| {
        if (@as(u64, @intCast(@divFloor(position, subcommittee_size))) != subnet) continue;
        try node.chainService().importSyncCommitteeMessage(
            subnet,
            msg.slot,
            msg.beacon_block_root,
            @intCast(position % subcommittee_size),
            msg.signature,
        );
        imported = true;
    }

    if (!imported) return error.InvalidSubnet;
}

pub fn importBlobSidecar(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));

    var sidecar: types.deneb.BlobSidecar.Type = undefined;
    types.deneb.BlobSidecar.deserializeFromBytes(ssz_bytes, &sidecar) catch |err| {
        scoped_log.debug("BlobSidecar SSZ decode failed: {}", .{err});
        return err;
    };

    var block_root: [32]u8 = undefined;
    types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root) catch |err| {
        scoped_log.debug("BlobSidecar block root hash failed: {}", .{err});
        return err;
    };

    if (try node.ingestBlobSidecar(block_root, sidecar.index, sidecar.signed_block_header.message.slot, ssz_bytes)) |ready| {
        _ = try node.completeReadyIngress(ready, null);
    }
}

pub fn importDataColumnSidecar(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));

    var sidecar = types.fulu.DataColumnSidecar.default_value;
    types.fulu.DataColumnSidecar.deserializeFromBytes(node.allocator, ssz_bytes, &sidecar) catch |err| {
        scoped_log.debug("DataColumnSidecar SSZ decode failed: {}", .{err});
        return err;
    };
    defer types.fulu.DataColumnSidecar.deinit(node.allocator, &sidecar);

    var block_root: [32]u8 = undefined;
    types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root) catch |err| {
        scoped_log.debug("DataColumnSidecar block root hash failed: {}", .{err});
        return err;
    };

    if (try node.ingestDataColumnSidecar(block_root, sidecar.index, sidecar.signed_block_header.message.slot, ssz_bytes)) |ready| {
        _ = try node.completeReadyIngress(ready, null);
    }
}

// ---------------------------------------------------------------------------
// BLS signature verification callbacks
// ---------------------------------------------------------------------------

pub fn verifyBlockSignature(ptr: *anyopaque, any_signed: *const AnySignedBeaconBlock) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    const sig_set = state_transition.signature_sets.proposer.getBlockProposerSignatureSet(
        node.allocator,
        node.config,
        cached.epoch_cache,
        any_signed.*,
    ) catch return false;

    return state_transition.signature_sets.verifySingleSignatureSet(&sig_set) catch false;
}

pub fn verifyVoluntaryExitSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    var signed_exit: types.phase0.SignedVoluntaryExit.Type = undefined;
    types.phase0.SignedVoluntaryExit.deserializeFromBytes(ssz_bytes, &signed_exit) catch return false;

    return state_transition.signature_sets.voluntary_exits.verifyVoluntaryExitSignature(
        node.config,
        cached.epoch_cache,
        &signed_exit,
    ) catch false;
}

pub fn verifyProposerSlashingSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    var slashing: types.phase0.ProposerSlashing.Type = undefined;
    types.phase0.ProposerSlashing.deserializeFromBytes(ssz_bytes, &slashing) catch return false;

    const sig_sets = state_transition.signature_sets.proposer_slashings.getProposerSlashingSignatureSets(
        node.config,
        cached.epoch_cache,
        &slashing,
    ) catch return false;

    const valid1 = state_transition.signature_sets.verifySingleSignatureSet(&sig_sets[0]) catch return false;
    if (!valid1) return false;
    return state_transition.signature_sets.verifySingleSignatureSet(&sig_sets[1]) catch false;
}

pub fn verifyAttesterSlashingSignature(ptr: *anyopaque, slashing: *const AnyAttesterSlashing) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    const sig_set1 = switch (slashing.*) {
        .phase0 => |s| state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
            node.allocator,
            node.config,
            cached.epoch_cache,
            &s.attestation_1.data,
            s.attestation_1.signature,
            s.attestation_1.attesting_indices.items,
        ),
        .electra => |s| state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
            node.allocator,
            node.config,
            cached.epoch_cache,
            &s.attestation_1.data,
            s.attestation_1.signature,
            s.attestation_1.attesting_indices.items,
        ),
    } catch return false;
    defer node.allocator.free(sig_set1.pubkeys);

    const valid1 = state_transition.signature_sets.verifyAggregatedSignatureSet(&sig_set1) catch return false;
    if (!valid1) return false;

    const sig_set2 = switch (slashing.*) {
        .phase0 => |s| state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
            node.allocator,
            node.config,
            cached.epoch_cache,
            &s.attestation_2.data,
            s.attestation_2.signature,
            s.attestation_2.attesting_indices.items,
        ),
        .electra => |s| state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
            node.allocator,
            node.config,
            cached.epoch_cache,
            &s.attestation_2.data,
            s.attestation_2.signature,
            s.attestation_2.attesting_indices.items,
        ),
    } catch return false;
    defer node.allocator.free(sig_set2.pubkeys);

    return state_transition.signature_sets.verifyAggregatedSignatureSet(&sig_set2) catch false;
}

pub fn verifyBlsChangeSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));

    var signed_change: types.capella.SignedBLSToExecutionChange.Type = undefined;
    types.capella.SignedBLSToExecutionChange.deserializeFromBytes(ssz_bytes, &signed_change) catch return false;

    return state_transition.signature_sets.bls_to_execution_change.verifyBlsToExecutionChangeSignature(
        node.config,
        &signed_change,
    ) catch false;
}

pub fn verifyAttestationSignature(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    resolved: *const ResolvedAttestation,
) bool {
    const owned_set = buildResolvedAttestationSignatureSet(ptr, attestation, resolved) catch return false;
    defer {
        var mutable = owned_set;
        mutable.deinit();
    }

    return state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = owned_set.set.pubkey.?,
        .signing_root = owned_set.set.signing_root,
        .signature = owned_set.set.signature,
    }) catch false;
}

pub fn getAttestationSigningRoot(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    out: *[32]u8,
) !void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;

    try state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(
        node.config,
        cached.epoch_cache.epoch,
        &attestation.data(),
        out,
    );
}

pub fn buildAttestationSignatureSetWithSigningRoot(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    signing_root: *const [32]u8,
) !bls_mod.OwnedSignatureSet {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;

    return switch (attestation.*) {
        .phase0 => |att| blk: {
            const validator_index = try getSingleAttestingIndexPhase0FromEpochCache(
                cached.epoch_cache,
                &att,
            );
            if (validator_index >= cached.epoch_cache.index_to_pubkey.items.len) {
                return error.ValidatorIndexOutOfBounds;
            }

            break :blk bls_mod.OwnedSignatureSet.initSingle(
                cached.epoch_cache.index_to_pubkey.items[validator_index],
                signing_root.*,
                att.signature,
            );
        },
        .electra_single => |att| blk: {
            if (att.attester_index >= cached.epoch_cache.index_to_pubkey.items.len) {
                return error.ValidatorIndexOutOfBounds;
            }

            break :blk bls_mod.OwnedSignatureSet.initSingle(
                cached.epoch_cache.index_to_pubkey.items[att.attester_index],
                signing_root.*,
                att.signature,
            );
        },
    };
}

pub fn buildResolvedAttestationSignatureSet(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
    resolved: *const ResolvedAttestation,
) !bls_mod.OwnedSignatureSet {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;
    if (resolved.validator_index >= cached.epoch_cache.index_to_pubkey.items.len) {
        return error.ValidatorIndexOutOfBounds;
    }

    return bls_mod.OwnedSignatureSet.initSingle(
        cached.epoch_cache.index_to_pubkey.items[resolved.validator_index],
        resolved.signing_root,
        attestation.signature(),
    );
}

pub fn buildAttestationSignatureSet(
    allocator: std.mem.Allocator,
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
) !bls_mod.OwnedSignatureSet {
    _ = allocator;

    var signing_root: [32]u8 = undefined;
    try getAttestationSigningRoot(ptr, attestation, &signing_root);
    return buildAttestationSignatureSetWithSigningRoot(ptr, attestation, &signing_root);
}

pub fn buildAggregateSignatureSets(
    allocator: std.mem.Allocator,
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    out: *[3]bls_mod.OwnedSignatureSet,
) !void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var attestation_data_root: [32]u8 = undefined;
    try types.phase0.AttestationData.hashTreeRoot(&aggregate.attestation().data(), &attestation_data_root);
    const resolved = try resolveAggregate(ptr, aggregate, &attestation_data_root);
    defer resolved.deinit(node.allocator);
    try buildResolvedAggregateSignatureSets(allocator, ptr, aggregate, &resolved, out);
}

fn makeResolvedAggregateSignatureSets(
    allocator: std.mem.Allocator,
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    resolved: *const ResolvedAggregate,
) ![3]bls_mod.OwnedSignatureSet {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;
    const epoch_cache = cached.epoch_cache;
    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.InvalidAggregatorIndex;

    const aggregator_pubkey = epoch_cache.index_to_pubkey.items[aggregator_index];
    const pubkeys = try allocator.alloc(bls_mod.PublicKey, resolved.attesting_indices.len);
    errdefer allocator.free(pubkeys);

    for (resolved.attesting_indices, 0..) |validator_index, i| {
        if (validator_index >= epoch_cache.index_to_pubkey.items.len) return error.ValidatorIndexOutOfBounds;
        pubkeys[i] = epoch_cache.index_to_pubkey.items[validator_index];
    }

    return .{
        bls_mod.OwnedSignatureSet.initSingle(
            aggregator_pubkey,
            resolved.selection_signing_root,
            aggregate.selectionProof(),
        ),
        bls_mod.OwnedSignatureSet.initSingle(
            aggregator_pubkey,
            resolved.aggregate_signing_root,
            aggregate.signature(),
        ),
        bls_mod.OwnedSignatureSet.initOwnedAggregate(
            allocator,
            pubkeys,
            resolved.attestation_signing_root,
            aggregate.attestation().signature(),
        ),
    };
}

pub fn buildResolvedAggregateSignatureSets(
    allocator: std.mem.Allocator,
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    resolved: *const ResolvedAggregate,
    out: *[3]bls_mod.OwnedSignatureSet,
) !void {
    out.* = try makeResolvedAggregateSignatureSets(allocator, ptr, aggregate, resolved);
}

pub fn verifyAggregateSignature(
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var attestation_data_root: [32]u8 = undefined;
    types.phase0.AttestationData.hashTreeRoot(&aggregate.attestation().data(), &attestation_data_root) catch return false;
    const resolved = resolveAggregate(ptr, aggregate, &attestation_data_root) catch return false;
    defer resolved.deinit(node.allocator);
    return verifyResolvedAggregateSignature(ptr, aggregate, &resolved);
}

pub fn verifyResolvedAggregateSignature(
    ptr: *anyopaque,
    aggregate: *const AnySignedAggregateAndProof,
    resolved: *const ResolvedAggregate,
) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;
    const epoch_cache = cached.epoch_cache;
    const aggregator_index = aggregate.aggregatorIndex();
    const slot = aggregate.slot();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return false;

    const aggregator_pubkey = epoch_cache.index_to_pubkey.items[aggregator_index];
    const selection_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = resolved.selection_signing_root,
        .signature = aggregate.selectionProof(),
    };
    const selection_valid = state_transition.signature_sets.verifySingleSignatureSet(&selection_sig_set) catch {
        scoped_log.debug("aggregate selection proof verification errored: aggregator={d} slot={d}", .{ aggregator_index, slot });
        return false;
    };
    if (!selection_valid) {
        const pubkey_hex = std.fmt.bytesToHex(&aggregator_pubkey.compress(), .lower);
        const root_hex = std.fmt.bytesToHex(&resolved.selection_signing_root, .lower);
        const sig_hex = std.fmt.bytesToHex(&aggregate.selectionProof(), .lower);
        scoped_log.debug(
            "aggregate selection proof invalid: aggregator={d} slot={d} pubkey=0x{s} root=0x{s} sig=0x{s}",
            .{ aggregator_index, slot, &pubkey_hex, &root_hex, &sig_hex },
        );
        return false;
    }

    const agg_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = resolved.aggregate_signing_root,
        .signature = aggregate.signature(),
    };
    const agg_valid = state_transition.signature_sets.verifySingleSignatureSet(&agg_sig_set) catch {
        scoped_log.debug("aggregate-and-proof wrapper verification errored: aggregator={d} slot={d}", .{ aggregator_index, slot });
        return false;
    };
    if (!agg_valid) {
        scoped_log.debug("aggregate-and-proof wrapper signature invalid: aggregator={d} slot={d}", .{ aggregator_index, slot });
        return false;
    }

    var pubkeys = node.allocator.alloc(bls_mod.PublicKey, resolved.attesting_indices.len) catch return false;
    defer node.allocator.free(pubkeys);
    for (resolved.attesting_indices, 0..) |validator_index, i| {
        if (validator_index >= epoch_cache.index_to_pubkey.items.len) return false;
        pubkeys[i] = epoch_cache.index_to_pubkey.items[validator_index];
    }

    const attestation_valid = state_transition.signature_sets.verifyAggregatedSignatureSet(&.{
        .pubkeys = pubkeys,
        .signing_root = resolved.attestation_signing_root,
        .signature = aggregate.attestation().signature(),
    }) catch {
        scoped_log.debug("aggregate attestation signature verification errored: aggregator={d} slot={d} participants={d}", .{ aggregator_index, slot, resolved.attesting_indices.len });
        return false;
    };
    if (!attestation_valid) {
        scoped_log.debug("aggregate attestation signature invalid: aggregator={d} slot={d} participants={d}", .{ aggregator_index, slot, resolved.attesting_indices.len });
        return false;
    }
    return true;
}

pub fn verifySyncCommitteeSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    var msg: types.altair.SyncCommitteeMessage.Type = undefined;
    types.altair.SyncCommitteeMessage.deserializeFromBytes(ssz_bytes, &msg) catch return false;
    return verifySyncCommitteeMessage(ptr, &msg);
}

pub fn buildSyncCommitteeSignatureSet(
    ptr: *anyopaque,
    msg: *const types.altair.SyncCommitteeMessage.Type,
) !bls_mod.OwnedSignatureSet {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return error.NoHeadState;

    if (msg.validator_index >= cached.epoch_cache.index_to_pubkey.items.len) {
        return error.ValidatorNotFound;
    }

    const slot = msg.slot;
    const domain = try node.config.getDomain(cached.epoch_cache.epoch, constants.DOMAIN_SYNC_COMMITTEE, slot);

    var signing_root: [32]u8 = undefined;
    const computeSigningRoot = state_transition.computeSigningRoot;
    try computeSigningRoot(types.primitive.Root, &msg.beacon_block_root, domain, &signing_root);

    return bls_mod.OwnedSignatureSet.initSingle(
        cached.epoch_cache.index_to_pubkey.items[msg.validator_index],
        signing_root,
        msg.signature,
    );
}

pub fn verifySyncCommitteeMessage(
    ptr: *anyopaque,
    msg: *const types.altair.SyncCommitteeMessage.Type,
) bool {
    const owned_set = buildSyncCommitteeSignatureSet(ptr, msg) catch return false;
    return state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = owned_set.set.pubkey.?,
        .signing_root = owned_set.set.signing_root,
        .signature = owned_set.set.signature,
    }) catch false;
}

pub fn verifySyncContributionSignature(
    ptr: *anyopaque,
    signed_contribution: *const types.altair.SignedContributionAndProof.Type,
) anyerror!u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState().?;

    const contribution_and_proof = &signed_contribution.message;
    const contribution = &contribution_and_proof.contribution;
    const aggregator_index = contribution_and_proof.aggregator_index;

    const positions = syncCommitteePositionsForValidator(node, contribution.slot, aggregator_index) orelse
        return error.ValidatorNotFound;
    const subcommittee_size: u32 = @intCast(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);

    var aggregator_in_subcommittee = false;
    for (positions) |position| {
        if (@divFloor(position, subcommittee_size) == contribution.subcommittee_index) {
            aggregator_in_subcommittee = true;
            break;
        }
    }
    if (!aggregator_in_subcommittee) return error.ValidatorNotInSyncCommittee;

    var participant_indices = try syncContributionParticipantIndices(node.allocator, cached, contribution);
    defer participant_indices.deinit();
    if (participant_indices.items.len == 0) return error.NoParticipant;

    if (!state_transition.isSyncCommitteeAggregator(contribution_and_proof.selection_proof)) {
        return error.InvalidSelectionProof;
    }

    const selection_sig_set = try sync_contribution_signature_sets.getSyncCommitteeSelectionProofSignatureSet(
        node.config,
        cached.epoch_cache,
        signed_contribution,
    );
    const selection_valid = state_transition.signature_sets.verifySingleSignatureSet(&selection_sig_set) catch {
        scoped_log.debug("sync contribution selection proof verification errored: aggregator={d} slot={d} subcommittee={d}", .{ aggregator_index, contribution.slot, contribution.subcommittee_index });
        return error.InvalidSignature;
    };
    if (!selection_valid) {
        const pubkey_hex = std.fmt.bytesToHex(&selection_sig_set.pubkey.compress(), .lower);
        const root_hex = std.fmt.bytesToHex(&selection_sig_set.signing_root, .lower);
        const sig_hex = std.fmt.bytesToHex(&selection_sig_set.signature, .lower);
        scoped_log.debug(
            "sync contribution selection proof invalid: aggregator={d} slot={d} subcommittee={d} pubkey=0x{s} root=0x{s} sig=0x{s}",
            .{ aggregator_index, contribution.slot, contribution.subcommittee_index, &pubkey_hex, &root_hex, &sig_hex },
        );
        return error.InvalidSignature;
    }

    const contribution_and_proof_sig_set = try sync_contribution_signature_sets.getContributionAndProofSignatureSet(
        node.config,
        cached.epoch_cache,
        signed_contribution,
    );
    const contribution_and_proof_valid = state_transition.signature_sets.verifySingleSignatureSet(&contribution_and_proof_sig_set) catch {
        scoped_log.debug("sync contribution wrapper verification errored: aggregator={d} slot={d} subcommittee={d}", .{ aggregator_index, contribution.slot, contribution.subcommittee_index });
        return error.InvalidSignature;
    };
    if (!contribution_and_proof_valid) {
        scoped_log.debug("sync contribution wrapper signature invalid: aggregator={d} slot={d} subcommittee={d}", .{ aggregator_index, contribution.slot, contribution.subcommittee_index });
        return error.InvalidSignature;
    }

    verifySyncContributionAggregateSignature(
        node.allocator,
        node.config,
        cached,
        contribution,
        participant_indices.items,
    ) catch |err| switch (err) {
        error.InvalidSignature => {
            scoped_log.debug("sync contribution aggregate signature invalid: aggregator={d} slot={d} subcommittee={d} participants={d}", .{ aggregator_index, contribution.slot, contribution.subcommittee_index, participant_indices.items.len });
            return err;
        },
        else => return err,
    };

    return @intCast(participant_indices.items.len);
}

pub fn verifyBlobSidecar(
    ptr: *anyopaque,
    sidecar: *const types.deneb.BlobSidecar.Type,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const block_slot = sidecar.signed_block_header.message.slot;
    const max_blobs_per_block = node.config.getMaxBlobsPerBlock(
        state_transition.computeEpochAtSlot(block_slot),
    );
    if (sidecar.index >= max_blobs_per_block) return error.InvalidBlobIndex;

    const pre_state = try loadPreStateForGossipHeader(
        node,
        sidecar.signed_block_header.message.parent_root,
        block_slot,
    );
    try verifyBlockHeaderProposerSignature(node, pre_state, &sidecar.signed_block_header);
    try verifyExpectedProposer(pre_state, block_slot, sidecar.signed_block_header.message.proposer_index);
    try verifyBlobSidecarInclusionProof(sidecar);

    const blob_ptr: *const [chain_mod.blob_kzg_verification.BYTES_PER_BLOB]u8 = @ptrCast(&sidecar.blob);
    node.chainService().verifyBlobSidecar(.{
        .blob = blob_ptr,
        .commitment = sidecar.kzg_commitment,
        .proof = sidecar.kzg_proof,
    }) catch |err| switch (err) {
        error.InvalidKzgProof => return error.InvalidKzgProof,
        else => return err,
    };
}

pub fn verifyDataColumnSidecar(
    ptr: *anyopaque,
    sidecar: *const types.fulu.DataColumnSidecar.Type,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const block_slot = sidecar.signed_block_header.message.slot;

    if (sidecar.index >= preset_root.NUMBER_OF_COLUMNS) return error.InvalidColumnIndex;
    if (sidecar.kzg_commitments.items.len == 0) return error.InvalidCommitmentCount;

    const max_blobs_per_block = node.config.getMaxBlobsPerBlock(
        state_transition.computeEpochAtSlot(block_slot),
    );
    if (sidecar.kzg_commitments.items.len > max_blobs_per_block) {
        return error.InvalidCommitmentCount;
    }
    if (sidecar.column.items.len != sidecar.kzg_commitments.items.len) {
        return error.InvalidColumnCount;
    }
    if (sidecar.kzg_proofs.items.len != sidecar.kzg_commitments.items.len) {
        return error.InvalidProofCount;
    }

    const pre_state = try loadPreStateForGossipHeader(
        node,
        sidecar.signed_block_header.message.parent_root,
        block_slot,
    );
    try verifyExpectedProposer(pre_state, block_slot, sidecar.signed_block_header.message.proposer_index);
    try verifyBlockHeaderProposerSignature(node, pre_state, &sidecar.signed_block_header);
    try verifyDataColumnSidecarInclusionProof(node.allocator, sidecar);

    node.chainService().verifyDataColumnSidecar(
        node.allocator,
        sidecar.index,
        sidecar.kzg_commitments.items,
        sidecar.column.items,
        sidecar.kzg_proofs.items,
    ) catch |err| switch (err) {
        error.InvalidCellKzgProof => return error.InvalidKzgProof,
        error.LengthMismatch => return error.InvalidColumnCount,
        else => return err,
    };
}

test "gossipDomainAtSlot uses the message slot fork rather than state-epoch fallback" {
    var chain = config_mod.minimal.chain_config;
    chain.ALTAIR_FORK_EPOCH = 1;
    chain.BELLATRIX_FORK_EPOCH = 2;
    chain.CAPELLA_FORK_EPOCH = 3;
    chain.DENEB_FORK_EPOCH = 4;
    chain.ELECTRA_FORK_EPOCH = 5;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{0} ** 32;
    const cfg = config_mod.BeaconConfig.init(chain, gvr);
    const message_slot = @as(u64, 0);
    const state_epoch = @as(types.primitive.Epoch.Type, 5);

    const legacy = try cfg.getDomain(state_epoch, constants.DOMAIN_SELECTION_PROOF, message_slot);
    const gossip = try gossipDomainAtSlot(&cfg, message_slot, constants.DOMAIN_SELECTION_PROOF);
    const expected = try cfg.domain_cache.get(cfg.forkSeq(message_slot), constants.DOMAIN_SELECTION_PROOF);

    try std.testing.expectEqual(expected.*, gossip.*);
    try std.testing.expect(!std.mem.eql(u8, legacy, gossip));
}

test "gossip attestation signing root uses target epoch fork" {
    var chain = config_mod.minimal.chain_config;
    chain.ALTAIR_FORK_EPOCH = 1;
    chain.BELLATRIX_FORK_EPOCH = 2;
    chain.CAPELLA_FORK_EPOCH = 3;
    chain.DENEB_FORK_EPOCH = 4;
    chain.ELECTRA_FORK_EPOCH = 5;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{0} ** 32;
    const cfg = config_mod.BeaconConfig.init(chain, gvr);

    var data = types.phase0.AttestationData.default_value;
    data.slot = 0;
    data.target.epoch = 0;

    var gossip_root: [32]u8 = undefined;
    try gossipAttestationDataSigningRoot(&cfg, &data, &gossip_root);

    const slot = state_transition.computeStartSlotAtEpoch(data.target.epoch);
    const expected_domain = try cfg.domain_cache.get(cfg.forkSeq(slot), constants.DOMAIN_BEACON_ATTESTER);
    var expected_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(types.phase0.AttestationData, &data, expected_domain, &expected_root);

    try std.testing.expectEqual(expected_root, gossip_root);
}

test "gossip sync contribution roots use contribution slot fork rather than legacy state epoch helper" {
    var chain = config_mod.minimal.chain_config;
    chain.ALTAIR_FORK_EPOCH = 1;
    chain.BELLATRIX_FORK_EPOCH = 2;
    chain.CAPELLA_FORK_EPOCH = 3;
    chain.DENEB_FORK_EPOCH = 4;
    chain.ELECTRA_FORK_EPOCH = 5;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{0} ** 32;
    const cfg = config_mod.BeaconConfig.init(chain, gvr);

    var signed_contribution = types.altair.SignedContributionAndProof.default_value;
    signed_contribution.message.aggregator_index = 1;
    signed_contribution.message.contribution.slot = preset.SLOTS_PER_EPOCH;
    signed_contribution.message.contribution.subcommittee_index = 0;

    const contribution = &signed_contribution.message.contribution;
    const selection_data = types.altair.SyncAggregatorSelectionData.Type{
        .slot = contribution.slot,
        .subcommittee_index = contribution.subcommittee_index,
    };

    const legacy_selection_domain = try cfg.getDomain(5, constants.DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, contribution.slot);
    var legacy_selection_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.altair.SyncAggregatorSelectionData,
        &selection_data,
        legacy_selection_domain,
        &legacy_selection_root,
    );

    var gossip_selection_root: [32]u8 = undefined;
    try gossipSyncSelectionProofSigningRoot(&cfg, &selection_data, &gossip_selection_root);

    const legacy_contribution_domain = try cfg.getDomain(5, constants.DOMAIN_SYNC_COMMITTEE, contribution.slot);
    var legacy_contribution_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.primitive.Root,
        &contribution.beacon_block_root,
        legacy_contribution_domain,
        &legacy_contribution_root,
    );

    var gossip_contribution_root: [32]u8 = undefined;
    try gossipSyncContributionSigningRoot(&cfg, contribution, &gossip_contribution_root);

    const expected_selection_domain = try cfg.domain_cache.get(cfg.forkSeq(contribution.slot), constants.DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF);
    var expected_selection_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.altair.SyncAggregatorSelectionData,
        &selection_data,
        expected_selection_domain,
        &expected_selection_root,
    );

    const expected_contribution_domain = try cfg.domain_cache.get(cfg.forkSeq(contribution.slot), constants.DOMAIN_SYNC_COMMITTEE);
    var expected_contribution_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.primitive.Root,
        &contribution.beacon_block_root,
        expected_contribution_domain,
        &expected_contribution_root,
    );

    try std.testing.expectEqual(expected_selection_root, gossip_selection_root);
    try std.testing.expectEqual(expected_contribution_root, gossip_contribution_root);
    try std.testing.expect(!std.mem.eql(u8, &legacy_selection_root, &gossip_selection_root));
    try std.testing.expect(!std.mem.eql(u8, &legacy_contribution_root, &gossip_contribution_root));
}

test "gossip selection proof helpers verify Lodestar TS electra vectors" {
    var chain = config_mod.mainnet.chain_config;
    chain.ALTAIR_FORK_EPOCH = 0;
    chain.BELLATRIX_FORK_EPOCH = 0;
    chain.CAPELLA_FORK_EPOCH = 0;
    chain.DENEB_FORK_EPOCH = 0;
    chain.ELECTRA_FORK_EPOCH = 0;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{0} ** 32;
    const cfg = config_mod.BeaconConfig.init(chain, gvr);

    const pubkey_hex = "a8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac";
    const aggregate_root_hex = "fc6679fc11b6c9310dea0fe6b36fe5944c9e5488a73a01acb13fed4fbbb23c1f";
    const aggregate_sig_hex = "a5ebf86b71e5aa9ce85a0fd1725122fef21e31f355c01067e3d99db521a98679fd1c63512d25dded740ac6320d96e68a0fe44f98ee89ff34a36d677f52bf4b8e647980061e12689f03a92a42565840a55ce1c8a278ad8f8a61cb451b0bdbc40f";
    const aggregate_bytes_hex = "6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000006c000000a5ebf86b71e5aa9ce85a0fd1725122fef21e31f355c01067e3d99db521a98679fd1c63512d25dded740ac6320d96e68a0fe44f98ee89ff34a36d677f52bf4b8e647980061e12689f03a92a42565840a55ce1c8a278ad8f8a61cb451b0bdbc40fec0000002100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001";
    const sync_root_hex = "c27315e3be76213ef904a07424a3465940ae94d57e2261889f31af50e2137b8b";
    const sync_sig_hex = "8011cee60caa6576de8caf4fc427b7973b4874acb30537192d4a3c46c95a5c9bd7cd8cb11d0fa31f0e5bd35e5d851d5a024e9b598e0fe4e8ecb8d6a7405b5804d1b573d058a3c2e83686cdaf95cbc633649100efc68811783dbeff323987fdb1";
    const sync_bytes_hex = "0700000000000000210000000000000000000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008011cee60caa6576de8caf4fc427b7973b4874acb30537192d4a3c46c95a5c9bd7cd8cb11d0fa31f0e5bd35e5d851d5a024e9b598e0fe4e8ecb8d6a7405b5804d1b573d058a3c2e83686cdaf95cbc633649100efc68811783dbeff323987fdb1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    var pubkey_bytes: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey_bytes, pubkey_hex);
    const pubkey = try bls_mod.PublicKey.uncompress(&pubkey_bytes);

    var aggregate_root_expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&aggregate_root_expected, aggregate_root_hex);
    var aggregate_sig: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&aggregate_sig, aggregate_sig_hex);

    const aggregate_bytes_len = aggregate_bytes_hex.len / 2;
    const aggregate_storage = try std.testing.allocator.alloc(u8, aggregate_bytes_len);
    defer std.testing.allocator.free(aggregate_storage);
    _ = try std.fmt.hexToBytes(aggregate_storage, aggregate_bytes_hex);

    var signed_aggregate: types.electra.SignedAggregateAndProof.Type = undefined;
    try types.electra.SignedAggregateAndProof.deserializeFromBytes(std.testing.allocator, aggregate_storage, &signed_aggregate);

    var aggregate_root: [32]u8 = undefined;
    try gossipSelectionProofSigningRoot(&cfg, signed_aggregate.message.aggregate.data.slot, &aggregate_root);
    try std.testing.expectEqual(aggregate_root_expected, aggregate_root);
    try std.testing.expect(try state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = pubkey,
        .signing_root = aggregate_root,
        .signature = aggregate_sig,
    }));

    var sync_root_expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sync_root_expected, sync_root_hex);
    var sync_sig: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sync_sig, sync_sig_hex);
    const sync_bytes_len = sync_bytes_hex.len / 2;
    const sync_storage = try std.testing.allocator.alloc(u8, sync_bytes_len);
    defer std.testing.allocator.free(sync_storage);
    _ = try std.fmt.hexToBytes(sync_storage, sync_bytes_hex);

    var signed_contribution: types.altair.SignedContributionAndProof.Type = undefined;
    try types.altair.SignedContributionAndProof.deserializeFromBytes(sync_storage, &signed_contribution);

    const selection_data = types.altair.SyncAggregatorSelectionData.Type{
        .slot = signed_contribution.message.contribution.slot,
        .subcommittee_index = signed_contribution.message.contribution.subcommittee_index,
    };
    var sync_root: [32]u8 = undefined;
    try gossipSyncSelectionProofSigningRoot(&cfg, &selection_data, &sync_root);
    try std.testing.expectEqual(sync_root_expected, sync_root);
    try std.testing.expect(try state_transition.signature_sets.verifySingleSignatureSet(&.{
        .pubkey = pubkey,
        .signing_root = sync_root,
        .signature = sync_sig,
    }));
}

test "gossip selection proof helpers match live kurtosis config roots" {
    var chain = config_mod.mainnet.chain_config;
    chain.GENESIS_FORK_VERSION = .{ 0x10, 0x00, 0x00, 0x38 };
    chain.ALTAIR_FORK_VERSION = .{ 0x20, 0x00, 0x00, 0x38 };
    chain.BELLATRIX_FORK_VERSION = .{ 0x30, 0x00, 0x00, 0x38 };
    chain.CAPELLA_FORK_VERSION = .{ 0x40, 0x00, 0x00, 0x38 };
    chain.DENEB_FORK_VERSION = .{ 0x50, 0x00, 0x00, 0x38 };
    chain.ELECTRA_FORK_VERSION = .{ 0x60, 0x00, 0x00, 0x38 };
    chain.FULU_FORK_VERSION = .{ 0x70, 0x00, 0x00, 0x38 };
    chain.ALTAIR_FORK_EPOCH = 0;
    chain.BELLATRIX_FORK_EPOCH = 0;
    chain.CAPELLA_FORK_EPOCH = 0;
    chain.DENEB_FORK_EPOCH = 0;
    chain.ELECTRA_FORK_EPOCH = 0;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{ 0xd6, 0x1e, 0xa4, 0x84, 0xfe, 0xba, 0xcf, 0xae, 0x52, 0x98, 0xd5, 0x2a, 0x2b, 0x58, 0x1f, 0x3e, 0x30, 0x5a, 0x51, 0xf3, 0x11, 0x2a, 0x92, 0x41, 0xb9, 0x68, 0xdc, 0xcf, 0x01, 0x9f, 0x7b, 0x11 };
    const cfg = config_mod.BeaconConfig.init(chain, gvr);

    const aggregate_root_hex = "0c6a5bee4931d8eb94e79d64e0040c8bff87956a88cb4343060eb9fb37540107";
    const sync_root_hex = "2f2f03bcf43d5bb6b22df78dbf1141b987d0b21b97377d6b710122827b472e81";

    var expected_aggregate_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_aggregate_root, aggregate_root_hex);
    var expected_sync_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_sync_root, sync_root_hex);

    var aggregate_root: [32]u8 = undefined;
    try gossipSelectionProofSigningRoot(&cfg, 11463, &aggregate_root);
    try std.testing.expectEqual(expected_aggregate_root, aggregate_root);

    const selection_data = types.altair.SyncAggregatorSelectionData.Type{
        .slot = 11463,
        .subcommittee_index = 2,
    };
    var sync_root: [32]u8 = undefined;
    try gossipSyncSelectionProofSigningRoot(&cfg, &selection_data, &sync_root);
    try std.testing.expectEqual(expected_sync_root, sync_root);
}

test "gossip selection proof helpers match live kurtosis config roots at higher slot" {
    var chain = config_mod.mainnet.chain_config;
    chain.GENESIS_FORK_VERSION = .{ 0x10, 0x00, 0x00, 0x38 };
    chain.ALTAIR_FORK_VERSION = .{ 0x20, 0x00, 0x00, 0x38 };
    chain.BELLATRIX_FORK_VERSION = .{ 0x30, 0x00, 0x00, 0x38 };
    chain.CAPELLA_FORK_VERSION = .{ 0x40, 0x00, 0x00, 0x38 };
    chain.DENEB_FORK_VERSION = .{ 0x50, 0x00, 0x00, 0x38 };
    chain.ELECTRA_FORK_VERSION = .{ 0x60, 0x00, 0x00, 0x38 };
    chain.FULU_FORK_VERSION = .{ 0x70, 0x00, 0x00, 0x38 };
    chain.ALTAIR_FORK_EPOCH = 0;
    chain.BELLATRIX_FORK_EPOCH = 0;
    chain.CAPELLA_FORK_EPOCH = 0;
    chain.DENEB_FORK_EPOCH = 0;
    chain.ELECTRA_FORK_EPOCH = 0;
    chain.FULU_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);
    chain.GLOAS_FORK_EPOCH = std.math.maxInt(types.primitive.Epoch.Type);

    const gvr = [_]u8{ 0xd6, 0x1e, 0xa4, 0x84, 0xfe, 0xba, 0xcf, 0xae, 0x52, 0x98, 0xd5, 0x2a, 0x2b, 0x58, 0x1f, 0x3e, 0x30, 0x5a, 0x51, 0xf3, 0x11, 0x2a, 0x92, 0x41, 0xb9, 0x68, 0xdc, 0xcf, 0x01, 0x9f, 0x7b, 0x11 };
    const cfg = config_mod.BeaconConfig.init(chain, gvr);

    const aggregate_root_hex = "81254c9a3297cd034d2a0656493882e828a2e7b78fbfa1e0ffd919df4bb43aff";
    const sync0_root_hex = "92d0613d72d93484a115269f301c78d2d2eb3a1264aa46d107cc3c48a7fe963e";
    const sync1_root_hex = "d2311472966a79eaac072c0b68b576afcc3d191b7111225b245a03e69bd5d6a4";
    const sync2_root_hex = "32c70f5edfdabbaf6ec53db00bbd07caf5a9b73606c708128d85574488a773e3";
    const sync3_root_hex = "ce4ea4878fa9b9e7e48ad4de520c1e98ef6a3835b0f9042b7ef340ec2e4cb58f";

    var expected_aggregate_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_aggregate_root, aggregate_root_hex);
    var aggregate_root: [32]u8 = undefined;
    try gossipSelectionProofSigningRoot(&cfg, 11737, &aggregate_root);
    try std.testing.expectEqual(expected_aggregate_root, aggregate_root);

    const expected_sync_hexes = [_][]const u8{ sync0_root_hex, sync1_root_hex, sync2_root_hex, sync3_root_hex };
    for (expected_sync_hexes, 0..) |expected_hex, subcommittee_index| {
        var expected_root: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_root, expected_hex);
        const selection_data = types.altair.SyncAggregatorSelectionData.Type{
            .slot = 11737,
            .subcommittee_index = @intCast(subcommittee_index),
        };
        var actual_root: [32]u8 = undefined;
        try gossipSyncSelectionProofSigningRoot(&cfg, &selection_data, &actual_root);
        try std.testing.expectEqual(expected_root, actual_root);
    }
}
