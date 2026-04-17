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
const constants = @import("constants");
const ssz = @import("ssz");
const processor_mod = @import("processor");
const AggregateWork = processor_mod.work_item.AggregateWork;
const AttestationWork = processor_mod.work_item.AttestationWork;
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
const gossip_handler_mod = @import("gossip_handler.zig");
const UnknownParentBlock = gossip_handler_mod.UnknownParentBlock;

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
    epoch_cache: *const state_transition.EpochCache,
    attestation: *const AnyGossipAttestation,
    out: *[32]u8,
) !void {
    try state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(
        node.config,
        epoch_cache.epoch,
        &attestation.data(),
        out,
    );
}

fn getAttestationSigningRootFromAnyAttestation(
    node: *const BeaconNode,
    epoch_cache: *const state_transition.EpochCache,
    attestation: *const AnyAttestation,
    out: *[32]u8,
) !void {
    try state_transition.signature_sets.indexed_attestation.getAttestationDataSigningRoot(
        node.config,
        epoch_cache.epoch,
        &attestation.data(),
        out,
    );
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
    const cached_data = try resolveCachedAttestationData(
        node,
        attestation.slot(),
        attestation.committeeIndex(),
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

    const epoch = epoch_cache.epoch;
    const att_slot = attestation.slot();

    const selection_domain = try node.config.getDomain(epoch, constants.DOMAIN_SELECTION_PROOF, att_slot);
    var selection_signing_root: [32]u8 = undefined;
    try state_transition.computeSigningRoot(
        types.primitive.Slot,
        &att_slot,
        selection_domain,
        &selection_signing_root,
    );

    const target_epoch_start_slot = state_transition.computeStartSlotAtEpoch(attestation.data().target.epoch);
    const agg_domain = try node.config.getDomain(epoch, constants.DOMAIN_AGGREGATE_AND_PROOF, target_epoch_start_slot);
    var aggregate_signing_root: [32]u8 = undefined;
    switch (aggregate.*) {
        .phase0 => |signed_agg| try state_transition.computeSigningRootAlloc(
            types.phase0.AggregateAndProof,
            node.allocator,
            &signed_agg.message,
            agg_domain,
            &aggregate_signing_root,
        ),
        .electra => |signed_agg| try state_transition.computeSigningRootAlloc(
            types.electra.AggregateAndProof,
            node.allocator,
            &signed_agg.message,
            agg_domain,
            &aggregate_signing_root,
        ),
    }

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
    if (aggregator_index >= epoch_cache.index_to_pubkey.items.len) return false;

    const aggregator_pubkey = epoch_cache.index_to_pubkey.items[aggregator_index];
    const selection_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = resolved.selection_signing_root,
        .signature = aggregate.selectionProof(),
    };
    const selection_valid = state_transition.signature_sets.verifySingleSignatureSet(&selection_sig_set) catch return false;
    if (!selection_valid) return false;

    const agg_sig_set = state_transition.signature_sets.SingleSignatureSet{
        .pubkey = aggregator_pubkey,
        .signing_root = resolved.aggregate_signing_root,
        .signature = aggregate.signature(),
    };
    const agg_valid = state_transition.signature_sets.verifySingleSignatureSet(&agg_sig_set) catch return false;
    if (!agg_valid) return false;

    var pubkeys = node.allocator.alloc(bls_mod.PublicKey, resolved.attesting_indices.len) catch return false;
    defer node.allocator.free(pubkeys);
    for (resolved.attesting_indices, 0..) |validator_index, i| {
        if (validator_index >= epoch_cache.index_to_pubkey.items.len) return false;
        pubkeys[i] = epoch_cache.index_to_pubkey.items[validator_index];
    }

    return state_transition.signature_sets.verifyAggregatedSignatureSet(&.{
        .pubkeys = pubkeys,
        .signing_root = resolved.attestation_signing_root,
        .signature = aggregate.attestation().signature(),
    }) catch false;
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
