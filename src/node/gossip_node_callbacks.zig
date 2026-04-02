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
const config_mod = @import("config");
const types = @import("consensus_types");
const state_transition = @import("state_transition");
const bls_mod = @import("bls");
const fork_types = @import("fork_types");
const AnyAttestation = fork_types.AnyAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const preset = @import("preset").preset;
const constants = @import("constants");
const ssz = @import("ssz");

// Import BeaconNode lazily to avoid circular dependency.
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

fn readSignedBeaconBlockSlot(bytes: []const u8) ?u64 {
    if (bytes.len < 4) return null;
    const msg_offset = std.mem.readInt(u32, bytes[0..4], .little);
    if (bytes.len < @as(usize, msg_offset) + 8) return null;
    return std.mem.readInt(u64, bytes[msg_offset..][0..8], .little);
}

// ---------------------------------------------------------------------------
// Block import callback
// ---------------------------------------------------------------------------

pub fn importBlockFromGossip(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const block_slot = readSignedBeaconBlockSlot(block_bytes) orelse node.currentHeadSlot();
    const fork_seq = node.config.forkSeq(block_slot);
    const any_signed = AnySignedBeaconBlock.deserialize(
        node.allocator,
        .full,
        fork_seq,
        block_bytes,
    ) catch |err| {
        std.log.warn("Gossip block import deserialize: {}", .{err});
        return err;
    };

    const accepted = node.chainService().acceptGossipBlock(any_signed, 0) catch |err| {
        any_signed.deinit(node.allocator);
        return err;
    };
    const ready = switch (accepted) {
        .pending_block_data => return,
        .ready => |ready| ready,
    };

    const maybe_result = node.completeReadyIngress(ready, block_bytes) catch |err| {
        std.log.warn("Gossip block import: {}", .{err});
        return err;
    };
    if (maybe_result) |result| {
        std.log.info("GOSSIP BLOCK IMPORTED (via handler) slot={d}", .{result.slot});
    }
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

/// Returns the total validator count.
pub fn getValidatorCount(ptr: *anyopaque) u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return node.chainQuery().getValidatorCount();
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

pub fn importAttestation(
    ptr: *anyopaque,
    attestation: *const AnyGossipAttestation,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    switch (attestation.*) {
        .phase0 => |att| {
            const validator_index = try getSingleAttestingIndexPhase0(node, &att);
            try node.chainService().importAttestation(
                validator_index,
                .{ .phase0 = att },
            );
        },
        .electra_single => |single| {
            var full_att = try convertSingleAttestation(node, &single);
            defer full_att.aggregation_bits.data.deinit(node.allocator);

            try node.chainService().importAttestation(
                single.attester_index,
                .{ .electra = full_att },
            );
        },
    }
}

fn getSingleAttestingIndexPhase0(
    node: *BeaconNode,
    attestation: *const types.phase0.Attestation.Type,
) !types.primitive.ValidatorIndex.Type {
    const cached = node.headState() orelse return error.NoHeadState;
    return getSingleAttestingIndexPhase0FromEpochCache(cached.epoch_cache, attestation);
}

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

fn convertSingleAttestation(
    node: *BeaconNode,
    single: *const types.electra.SingleAttestation.Type,
) !types.electra.Attestation.Type {
    const cached = node.headState() orelse return error.NoHeadState;
    const committee = try cached.epoch_cache.getBeaconCommittee(single.data.slot, single.committee_index);

    var committee_offset: ?usize = null;
    for (committee, 0..) |validator_index, index_in_committee| {
        if (validator_index == single.attester_index) {
            committee_offset = index_in_committee;
            break;
        }
    }
    const attester_offset = committee_offset orelse return error.AttesterNotInCommittee;

    const AggregationBits = ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT);
    const CommitteeBits = ssz.BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);

    var aggregation_bits = try AggregationBits.Type.fromBitLen(node.allocator, committee.len);
    errdefer aggregation_bits.data.deinit(node.allocator);
    try aggregation_bits.set(node.allocator, attester_offset, true);

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

pub fn importAggregate(ptr: *anyopaque, aggregate: *const AnySignedAggregateAndProof) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const attestation = aggregate.attestation();
    var attesting_indices = try getAttestingIndicesForAnyAttestation(node, attestation);
    defer attesting_indices.deinit();
    try node.chainService().importAggregate(attestation, attesting_indices.items);
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
        std.log.warn("BlobSidecar SSZ decode failed: {}", .{err});
        return err;
    };

    var block_root: [32]u8 = undefined;
    types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root) catch |err| {
        std.log.warn("BlobSidecar block root hash failed: {}", .{err});
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
        std.log.warn("DataColumnSidecar SSZ decode failed: {}", .{err});
        return err;
    };
    defer types.fulu.DataColumnSidecar.deinit(node.allocator, &sidecar);

    var block_root: [32]u8 = undefined;
    types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root) catch |err| {
        std.log.warn("DataColumnSidecar block root hash failed: {}", .{err});
        return err;
    };

    if (try node.ingestDataColumnSidecar(block_root, sidecar.index, sidecar.signed_block_header.message.slot, ssz_bytes)) |ready| {
        _ = try node.completeReadyIngress(ready, null);
    }
}

// ---------------------------------------------------------------------------
// BLS signature verification callbacks
// ---------------------------------------------------------------------------

pub fn verifyBlockSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    const block_slot = readSignedBeaconBlockSlot(ssz_bytes) orelse node.currentHeadSlot();
    const fork_seq = node.config.forkSeq(block_slot);
    const any_signed = fork_types.AnySignedBeaconBlock.deserialize(
        node.allocator,
        .full,
        fork_seq,
        ssz_bytes,
    ) catch return false;
    defer any_signed.deinit(node.allocator);

    const sig_set = state_transition.signature_sets.proposer.getBlockProposerSignatureSet(
        node.allocator,
        node.config,
        cached.epoch_cache,
        any_signed,
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

pub fn verifyAttestationSignature(ptr: *anyopaque, attestation: *const AnyGossipAttestation) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    switch (attestation.*) {
        .phase0 => |att| {
            const validator_index = getSingleAttestingIndexPhase0FromEpochCache(
                cached.epoch_cache,
                &att,
            ) catch return false;
            if (validator_index >= cached.epoch_cache.index_to_pubkey.items.len) return false;

            var signing_root: [32]u8 = undefined;
            state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(
                node.config,
                cached.epoch_cache.epoch,
                &att.data,
                &signing_root,
            ) catch return false;

            const sig_set = state_transition.signature_sets.SingleSignatureSet{
                .pubkey = cached.epoch_cache.index_to_pubkey.items[validator_index],
                .signing_root = signing_root,
                .signature = att.signature,
            };

            return state_transition.signature_sets.verifySingleSignatureSet(&sig_set) catch false;
        },
        .electra_single => |att| {
            if (att.attester_index >= cached.epoch_cache.index_to_pubkey.items.len) return false;

            var signing_root: [32]u8 = undefined;
            state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(
                node.config,
                cached.epoch_cache.epoch,
                &att.data,
                &signing_root,
            ) catch return false;

            const sig_set = state_transition.signature_sets.SingleSignatureSet{
                .pubkey = cached.epoch_cache.index_to_pubkey.items[att.attester_index],
                .signing_root = signing_root,
                .signature = att.signature,
            };

            return state_transition.signature_sets.verifySingleSignatureSet(&sig_set) catch false;
        },
    }
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
    const cached = node.headState() orelse return error.NoHeadState;
    const epoch_cache = cached.epoch_cache;

    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return error.InvalidAggregatorIndex;

    const aggregator_pubkey = epoch_cache.index_to_pubkey.items[aggregator_index];
    const attestation = aggregate.attestation();
    const att_data = attestation.data();
    const att_slot = att_data.slot;
    const committee_index = attestation.committeeIndex();

    const committee = try epoch_cache.getBeaconCommittee(att_slot, committee_index);

    var aggregator_in_committee = false;
    for (committee) |validator_index| {
        if (validator_index == aggregator_index) {
            aggregator_in_committee = true;
            break;
        }
    }
    if (!aggregator_in_committee) return error.AggregatorNotInCommittee;

    if (!state_transition.isAggregatorFromCommitteeLength(committee.len, aggregate.selectionProof())) {
        return error.InvalidSelectionProof;
    }

    const epoch = epoch_cache.epoch;
    const computeSigningRoot = state_transition.computeSigningRoot;
    const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
    const computeSigningRootAlloc = state_transition.computeSigningRootAlloc;

    const selection_domain = try node.config.getDomain(epoch, constants.DOMAIN_SELECTION_PROOF, att_slot);
    var selection_signing_root: [32]u8 = undefined;
    try computeSigningRoot(types.primitive.Slot, &att_slot, selection_domain, &selection_signing_root);

    const target_epoch_start_slot = computeStartSlotAtEpoch(att_data.target.epoch);
    const agg_domain = try node.config.getDomain(epoch, constants.DOMAIN_AGGREGATE_AND_PROOF, target_epoch_start_slot);
    var agg_signing_root: [32]u8 = undefined;
    switch (aggregate.*) {
        .phase0 => |signed_agg| try computeSigningRootAlloc(types.phase0.AggregateAndProof, allocator, &signed_agg.message, agg_domain, &agg_signing_root),
        .electra => |signed_agg| try computeSigningRootAlloc(types.electra.AggregateAndProof, allocator, &signed_agg.message, agg_domain, &agg_signing_root),
    }

    var attesting_indices = try getAttestingIndicesForAnyAttestation(node, attestation);
    defer attesting_indices.deinit();
    if (attesting_indices.items.len == 0) return error.EmptyAggregateAttestation;

    const att_sig_set = try state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
        allocator,
        node.config,
        epoch_cache,
        &att_data,
        attestation.signature(),
        attesting_indices.items,
    );

    out[0] = bls_mod.OwnedSignatureSet.initSingle(
        aggregator_pubkey,
        selection_signing_root,
        aggregate.selectionProof(),
    );
    out[1] = bls_mod.OwnedSignatureSet.initSingle(
        aggregator_pubkey,
        agg_signing_root,
        aggregate.signature(),
    );
    out[2] = bls_mod.OwnedSignatureSet.initOwnedAggregate(
        allocator,
        att_sig_set.pubkeys,
        att_sig_set.signing_root,
        att_sig_set.signature,
    );
}

pub fn verifyAggregateSignature(ptr: *anyopaque, aggregate: *const AnySignedAggregateAndProof) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    return verifyAggregateSignatureTyped(node, cached.epoch_cache, aggregate);
}

fn verifyAggregateSignatureTyped(
    node: *BeaconNode,
    epoch_cache: *const state_transition.EpochCache,
    aggregate: *const AnySignedAggregateAndProof,
) bool {
    const aggregator_index = aggregate.aggregatorIndex();
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return false;

    const aggregator_pubkey = epoch_cache.index_to_pubkey.items[aggregator_index];
    const attestation = aggregate.attestation();
    const att_data = attestation.data();
    const att_slot = att_data.slot;
    const committee_index = attestation.committeeIndex();
    const epoch = epoch_cache.epoch;

    const committee = epoch_cache.getBeaconCommittee(att_slot, committee_index) catch return false;

    var aggregator_in_committee = false;
    for (committee) |validator_index| {
        if (validator_index == aggregator_index) {
            aggregator_in_committee = true;
            break;
        }
    }
    if (!aggregator_in_committee) return false;

    const isAggregatorFromCommitteeLength = @import("state_transition").isAggregatorFromCommitteeLength;
    if (!isAggregatorFromCommitteeLength(committee.len, aggregate.selectionProof())) return false;

    const computeSigningRoot = state_transition.computeSigningRoot;
    const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
    const computeSigningRootAlloc = state_transition.computeSigningRootAlloc;

    const selection_domain = node.config.getDomain(epoch, constants.DOMAIN_SELECTION_PROOF, att_slot) catch return false;
    var selection_signing_root: [32]u8 = undefined;
    computeSigningRoot(types.primitive.Slot, &att_slot, selection_domain, &selection_signing_root) catch return false;

    const selection_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = selection_signing_root,
        .signature = aggregate.selectionProof(),
    };
    const selection_valid = state_transition.signature_sets.verifySingleSignatureSet(&selection_sig_set) catch return false;
    if (!selection_valid) return false;

    const target_epoch_start_slot = computeStartSlotAtEpoch(att_data.target.epoch);
    const agg_domain = node.config.getDomain(epoch, constants.DOMAIN_AGGREGATE_AND_PROOF, target_epoch_start_slot) catch return false;
    var agg_signing_root: [32]u8 = undefined;
    switch (aggregate.*) {
        .phase0 => |signed_agg| computeSigningRootAlloc(types.phase0.AggregateAndProof, node.allocator, &signed_agg.message, agg_domain, &agg_signing_root) catch return false,
        .electra => |signed_agg| computeSigningRootAlloc(types.electra.AggregateAndProof, node.allocator, &signed_agg.message, agg_domain, &agg_signing_root) catch return false,
    }

    const agg_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = agg_signing_root,
        .signature = aggregate.signature(),
    };
    const agg_valid = state_transition.signature_sets.verifySingleSignatureSet(&agg_sig_set) catch return false;
    if (!agg_valid) return false;

    var attesting_indices = getAttestingIndicesForAnyAttestation(node, attestation) catch return false;
    defer attesting_indices.deinit();

    if (attesting_indices.items.len == 0) return false;

    const att_sig_set = state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
        node.allocator,
        node.config,
        epoch_cache,
        &att_data,
        attestation.signature(),
        attesting_indices.items,
    ) catch return false;
    defer node.allocator.free(att_sig_set.pubkeys);

    return state_transition.signature_sets.verifyAggregatedSignatureSet(&att_sig_set) catch false;
}

pub fn verifySyncCommitteeSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const cached = node.headState() orelse return true;

    var msg: types.altair.SyncCommitteeMessage.Type = undefined;
    types.altair.SyncCommitteeMessage.deserializeFromBytes(ssz_bytes, &msg) catch return false;

    if (msg.validator_index >= cached.epoch_cache.index_to_pubkey.items.len) return false;

    const slot = msg.slot;
    const domain = node.config.getDomain(cached.epoch_cache.epoch, constants.DOMAIN_SYNC_COMMITTEE, slot) catch return false;

    var signing_root: [32]u8 = undefined;
    const computeSigningRoot = state_transition.computeSigningRoot;
    computeSigningRoot(types.primitive.Root, &msg.beacon_block_root, domain, &signing_root) catch return false;

    const sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = cached.epoch_cache.index_to_pubkey.items[msg.validator_index],
        .signing_root = signing_root,
        .signature = msg.signature,
    };

    return state_transition.signature_sets.verifySingleSignatureSet(&sig_set) catch false;
}
