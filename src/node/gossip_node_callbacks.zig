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
const types = @import("consensus_types");
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const chain_mod = @import("chain");
const preset = @import("preset").preset;
const constants = @import("constants");

// Import BeaconNode lazily to avoid circular dependency.
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

// ---------------------------------------------------------------------------
// Block import callback
// ---------------------------------------------------------------------------

pub fn importBlockFromGossip(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const fork_seq = node.config.forkSeq(node.head_tracker.head_slot);
    const any_signed = AnySignedBeaconBlock.deserialize(
        node.allocator, .full, fork_seq, block_bytes,
    ) catch |err| {
        std.log.warn("Gossip block import deserialize: {}", .{err});
        return err;
    };
    defer any_signed.deinit(node.allocator);

    const result = node.importBlock(any_signed, .gossip) catch |err| {
        if (err == error.UnknownParentBlock) {
            node.queueOrphanBlock(any_signed, block_bytes);
        } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
            std.log.warn("Gossip block import: {}", .{err});
        }
        return err;
    };
    node.processPendingChildren(result.block_root);
    std.log.info("GOSSIP BLOCK IMPORTED (via handler) slot={d}", .{result.slot});
}

// ---------------------------------------------------------------------------
// "Ptr-free" vtable callbacks — use the node pointer from GossipHandler.node.
// These are now regular ptr-bearing callbacks matching GossipHandler's node field.
// ---------------------------------------------------------------------------

/// Returns the expected block proposer for `slot` from the head state's epoch cache.
pub fn getProposerIndex(ptr: *anyopaque, slot: u64) ?u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return null;
    const proposer = cached.getBeaconProposer(slot) catch return null;
    return @intCast(proposer);
}

/// Returns true if `root` appears in the head tracker's slot→root map or fork choice.
pub fn isKnownBlockRoot(ptr: *anyopaque, root: [32]u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var it = node.head_tracker.slot_roots.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr, &root)) return true;
    }
    if (node.chain.fork_choice) |fc| {
        return fc.hasBlock(root);
    }
    return false;
}

/// Returns the total validator count.
pub fn getValidatorCount(ptr: *anyopaque) u32 {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return 0;
    return @intCast(cached.epoch_cache.index_to_pubkey.items.len);
}

// ---------------------------------------------------------------------------
// Import callbacks
// ---------------------------------------------------------------------------

pub fn importAttestation(
    ptr: *anyopaque,
    attestation_slot: u64,
    committee_index: u64,
    target_root: [32]u8,
    target_epoch: u64,
    validator_index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));

    const att = types.phase0.Attestation.Type{
        .aggregation_bits = .{ .data = std.ArrayListUnmanaged(u8).empty, .bit_len = 0 },
        .data = .{
            .slot = attestation_slot,
            .index = committee_index,
            .beacon_block_root = beacon_block_root,
            .source = .{ .epoch = source_epoch, .root = source_root },
            .target = .{ .epoch = target_epoch, .root = target_root },
        },
        .signature = [_]u8{0} ** 96,
    };

    try node.chain.importAttestation(
        attestation_slot,
        committee_index,
        target_root,
        target_epoch,
        validator_index,
        att,
    );
}

pub fn importVoluntaryExit(ptr: *anyopaque, validator_index: u64, epoch: u64) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const exit = types.phase0.SignedVoluntaryExit.Type{
        .message = .{
            .epoch = epoch,
            .validator_index = validator_index,
        },
        .signature = [_]u8{0} ** 96,
    };
    try node.chain.op_pool.voluntary_exit_pool.add(exit);
}

pub fn importProposerSlashing(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var slashing: types.phase0.ProposerSlashing.Type = undefined;
    types.phase0.ProposerSlashing.deserializeFromBytes(ssz_bytes, &slashing) catch |err| {
        std.log.warn("Proposer slashing SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.proposer_slashing_pool.add(slashing);
}

pub fn importAttesterSlashing(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var slashing: types.phase0.AttesterSlashing.Type = undefined;
    types.phase0.AttesterSlashing.deserializeFromBytes(node.allocator, ssz_bytes, &slashing) catch |err| {
        std.log.warn("Attester slashing SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.attester_slashing_pool.add(slashing);
}

pub fn importBlsChange(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var change: types.capella.SignedBLSToExecutionChange.Type = undefined;
    types.capella.SignedBLSToExecutionChange.deserializeFromBytes(ssz_bytes, &change) catch |err| {
        std.log.warn("BLS change SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.bls_change_pool.add(change);
}

pub fn importSyncContribution(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const pool = node.sync_contribution_pool orelse return;

    var signed_cap: types.altair.SignedContributionAndProof.Type = undefined;
    types.altair.SignedContributionAndProof.deserializeFromBytes(ssz_bytes, &signed_cap) catch |err| {
        std.log.warn("SignedContributionAndProof SSZ decode failed: {}", .{err});
        return err;
    };

    try pool.add(&signed_cap.message.contribution);
}

pub fn importSyncCommitteeMessage(ptr: *anyopaque, ssz_bytes: []const u8, subnet: u64) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const pool = node.sync_committee_message_pool orelse return;

    var msg: types.altair.SyncCommitteeMessage.Type = undefined;
    types.altair.SyncCommitteeMessage.deserializeFromBytes(ssz_bytes, &msg) catch |err| {
        std.log.warn("SyncCommitteeMessage SSZ decode failed: {}", .{err});
        return err;
    };

    const subcommittee_size = preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT;
    const index_in_subcommittee = msg.validator_index % subcommittee_size;

    try pool.add(
        subnet,
        msg.slot,
        msg.beacon_block_root,
        index_in_subcommittee,
        msg.signature,
    );
}

// ---------------------------------------------------------------------------
// BLS signature verification callbacks
// ---------------------------------------------------------------------------

pub fn verifyBlockSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

    const fork_seq = node.config.forkSeq(node.head_tracker.head_slot);
    const any_signed = fork_types.AnySignedBeaconBlock.deserialize(
        node.allocator, .full, fork_seq, ssz_bytes,
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
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

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
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

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

pub fn verifyAttesterSlashingSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

    var slashing: types.phase0.AttesterSlashing.Type = undefined;
    types.phase0.AttesterSlashing.deserializeFromBytes(node.allocator, ssz_bytes, &slashing) catch return false;

    const sig_set1 = state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
        node.allocator,
        node.config,
        cached.epoch_cache,
        &slashing.attestation_1.data,
        slashing.attestation_1.signature,
        slashing.attestation_1.attesting_indices.items,
    ) catch return false;
    defer node.allocator.free(sig_set1.pubkeys);

    const valid1 = state_transition.signature_sets.verifyAggregatedSignatureSet(&sig_set1) catch return false;
    if (!valid1) return false;

    const sig_set2 = state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
        node.allocator,
        node.config,
        cached.epoch_cache,
        &slashing.attestation_2.data,
        slashing.attestation_2.signature,
        slashing.attestation_2.attesting_indices.items,
    ) catch return false;
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

pub fn verifyAttestationSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

    var att: types.electra.SingleAttestation.Type = undefined;
    types.electra.SingleAttestation.deserializeFromBytes(ssz_bytes, &att) catch return false;

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
}

pub fn verifyAggregateSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

    var signed_agg: types.phase0.SignedAggregateAndProof.Type = undefined;
    types.phase0.SignedAggregateAndProof.deserializeFromBytes(node.allocator, ssz_bytes, &signed_agg) catch return false;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(node.allocator);

    const agg = signed_agg.message;
    const att_data = agg.aggregate.data;
    const att_slot = att_data.slot;
    const committee_index = att_data.index;
    const epoch = cached.epoch_cache.epoch;

    if (agg.aggregator_index >= cached.epoch_cache.index_to_pubkey.items.len) return false;
    const aggregator_pubkey = cached.epoch_cache.index_to_pubkey.items[agg.aggregator_index];

    const committee = cached.epoch_cache.getBeaconCommittee(att_slot, committee_index) catch return false;

    var aggregator_in_committee = false;
    for (committee) |vi| {
        if (vi == agg.aggregator_index) {
            aggregator_in_committee = true;
            break;
        }
    }
    if (!aggregator_in_committee) return false;

    const isAggregatorFromCommitteeLength = @import("state_transition").isAggregatorFromCommitteeLength;
    if (!isAggregatorFromCommitteeLength(committee.len, agg.selection_proof)) return false;

    const computeSigningRoot = state_transition.computeSigningRoot;
    const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;

    const selection_domain = node.config.getDomain(epoch, constants.DOMAIN_SELECTION_PROOF, att_slot) catch return false;
    var selection_signing_root: [32]u8 = undefined;
    computeSigningRoot(types.primitive.Slot, &att_slot, selection_domain, &selection_signing_root) catch return false;

    const selection_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = selection_signing_root,
        .signature = agg.selection_proof,
    };
    const selection_valid = state_transition.signature_sets.verifySingleSignatureSet(&selection_sig_set) catch return false;
    if (!selection_valid) return false;

    const computeSigningRootAlloc = state_transition.computeSigningRootAlloc;
    const target_epoch_start_slot = computeStartSlotAtEpoch(att_data.target.epoch);
    const agg_domain = node.config.getDomain(epoch, constants.DOMAIN_AGGREGATE_AND_PROOF, target_epoch_start_slot) catch return false;
    var agg_signing_root: [32]u8 = undefined;
    computeSigningRootAlloc(types.phase0.AggregateAndProof, node.allocator, &agg, agg_domain, &agg_signing_root) catch return false;

    const agg_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = agg_signing_root,
        .signature = signed_agg.signature,
    };
    const agg_valid = state_transition.signature_sets.verifySingleSignatureSet(&agg_sig_set) catch return false;
    if (!agg_valid) return false;

    var attesting_indices = agg.aggregate.aggregation_bits.intersectValues(
        u64,
        node.allocator,
        committee,
    ) catch return false;
    defer attesting_indices.deinit();

    if (attesting_indices.items.len == 0) return false;

    const att_sig_set = state_transition.signature_sets.indexed_attestation.getAttestationWithIndicesSignatureSet(
        node.allocator,
        node.config,
        cached.epoch_cache,
        &att_data,
        agg.aggregate.signature,
        attesting_indices.items,
    ) catch return false;
    defer node.allocator.free(att_sig_set.pubkeys);

    return state_transition.signature_sets.verifyAggregatedSignatureSet(&att_sig_set) catch false;
}

pub fn verifySyncCommitteeSignature(ptr: *anyopaque, ssz_bytes: []const u8) bool {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return true;

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
