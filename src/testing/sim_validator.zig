//! Simulated validator client for deterministic simulation testing.
//!
//! Holds a range of validator indices and produces blocks/attestations
//! based on duties computed from the sim node's state. Uses stub
//! signatures (designed for verify_signatures: false).
//!
//! Each SimValidator is associated with one SimNodeHarness. The
//! SimController distributes validators across nodes.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const ssz = @import("ssz");

const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;

const BlockGenerator = @import("block_generator.zig").BlockGenerator;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const AttestationData = types.phase0.AttestationData.Type;
const ElectraAttestation = types.electra.Attestation.Type;

const CommitteeBits = ssz.BitVectorType(preset.MAX_COMMITTEES_PER_SLOT);
const AggregationBits = ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT);

pub const DutyResult = struct {
    is_proposer: bool,
    committee_assignments: std.ArrayListUnmanaged(CommitteeAssignment),

    pub fn deinit(self: *DutyResult, allocator: Allocator) void {
        self.committee_assignments.deinit(allocator);
    }
};

pub const CommitteeAssignment = struct {
    committee_index: usize,
    /// Indices within the committee that belong to this validator set.
    validator_positions: std.ArrayListUnmanaged(ValidatorPosition),

    pub fn deinit(self: *CommitteeAssignment, allocator: Allocator) void {
        self.validator_positions.deinit(allocator);
    }
};

pub const ValidatorPosition = struct {
    /// Position within the committee.
    committee_position: usize,
    /// Global validator index.
    validator_index: ValidatorIndex,
};

pub const ProducedBlock = struct {
    signed_block: *types.electra.SignedBeaconBlock.Type,
};

pub const ProducedAttestations = struct {
    attestations: std.ArrayListUnmanaged(ElectraAttestation),

    pub fn deinit(self: *ProducedAttestations, allocator: Allocator) void {
        for (self.attestations.items) |*att| {
            types.electra.Attestation.deinit(allocator, att);
        }
        self.attestations.deinit(allocator);
    }
};

pub const SimValidator = struct {
    allocator: Allocator,

    /// Range of validator indices this sim validator is responsible for.
    validator_start: ValidatorIndex,
    validator_end: ValidatorIndex,

    /// Block generator for producing blocks.
    block_gen: BlockGenerator,

    /// Whether this validator should skip its next proposal (fault injection).
    skip_next_proposal: bool = false,

    /// Whether attestations should be skipped (fault injection).
    skip_attestations: bool = false,

    /// Participation rate for attestations [0.0 - 1.0].
    participation_rate: f64 = 1.0,

    /// Stats.
    blocks_proposed: u64 = 0,
    attestations_produced: u64 = 0,
    proposals_skipped: u64 = 0,

    pub fn init(
        allocator: Allocator,
        validator_start: ValidatorIndex,
        validator_end: ValidatorIndex,
        seed: u64,
    ) SimValidator {
        return .{
            .allocator = allocator,
            .validator_start = validator_start,
            .validator_end = validator_end,
            .block_gen = BlockGenerator.init(allocator, seed),
        };
    }

    /// Check if this validator set includes the given validator index.
    pub fn ownsValidator(self: *const SimValidator, index: ValidatorIndex) bool {
        return index >= self.validator_start and index < self.validator_end;
    }

    /// Number of validators in this set.
    pub fn validatorCount(self: *const SimValidator) u64 {
        return self.validator_end - self.validator_start;
    }

    /// Check if any of our validators is the proposer for the given slot.
    pub fn isProposer(
        self: *const SimValidator,
        cached_state: *CachedBeaconState,
        slot: Slot,
    ) bool {
        const proposer = cached_state.epoch_cache.getBeaconProposer(slot) catch return false;
        return self.ownsValidator(proposer);
    }

    /// Produce a block for the given slot if we are the proposer.
    /// Returns null if we're not the proposer or if skip_next_proposal is set.
    ///
    /// The caller should pass a state that has been advanced to `target_slot`
    /// (i.e., processSlots has already been called).
    pub fn produceBlock(
        self: *SimValidator,
        advanced_state: *CachedBeaconState,
        target_slot: Slot,
    ) !?ProducedBlock {
        const proposer = advanced_state.epoch_cache.getBeaconProposer(target_slot) catch return null;
        if (!self.ownsValidator(proposer)) return null;

        if (self.skip_next_proposal) {
            self.skip_next_proposal = false;
            self.proposals_skipped += 1;
            return null;
        }

        const signed_block = try self.block_gen.generateBlockWithOpts(advanced_state, target_slot, .{
            .participation_rate = self.participation_rate,
        });

        self.blocks_proposed += 1;

        return .{ .signed_block = signed_block };
    }

    /// Produce attestations for the given slot.
    /// Returns attestations for all committees where our validators are assigned.
    ///
    /// The caller should pass a state that is at or past `attestation_slot`.
    pub fn produceAttestations(
        self: *SimValidator,
        allocator: Allocator,
        cached_state: *CachedBeaconState,
        attestation_slot: Slot,
    ) !ProducedAttestations {
        var result = ProducedAttestations{
            .attestations = .empty,
        };
        errdefer result.deinit(allocator);

        if (self.skip_attestations) return result;

        const state = cached_state.state;
        const epoch_cache = cached_state.epoch_cache;

        const att_epoch = computeEpochAtSlot(attestation_slot);
        const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(att_epoch) catch return result;
        if (committees_per_slot == 0) return result;

        // beacon_block_root for attestation data.
        const beacon_block_root = getBlockRootAtSlot(
            .electra,
            state.castToFork(.electra),
            attestation_slot,
        ) catch return result;

        // Target checkpoint.
        const target_epoch_start_slot = computeStartSlotAtEpoch(att_epoch);
        const target_root = if (target_epoch_start_slot < attestation_slot)
            (getBlockRootAtSlot(.electra, state.castToFork(.electra), target_epoch_start_slot) catch return result)
        else
            beacon_block_root;

        // Source checkpoint.
        const current_epoch = epoch_cache.epoch;
        var source_checkpoint: Checkpoint = undefined;
        if (att_epoch == current_epoch) {
            try state.currentJustifiedCheckpoint(&source_checkpoint);
        } else {
            try state.previousJustifiedCheckpoint(&source_checkpoint);
        }

        const att_data = AttestationData{
            .slot = attestation_slot,
            .index = 0,
            .beacon_block_root = beacon_block_root.*,
            .source = source_checkpoint,
            .target = .{
                .epoch = att_epoch,
                .root = target_root.*,
            },
        };

        // Iterate over committees, find ones where our validators participate.
        for (0..committees_per_slot) |committee_idx| {
            const committee = epoch_cache.getBeaconCommittee(attestation_slot, committee_idx) catch continue;
            if (committee.len == 0) continue;

            // Check if any of our validators are in this committee.
            var has_our_validators = false;
            for (committee) |vi| {
                if (self.ownsValidator(vi)) {
                    has_our_validators = true;
                    break;
                }
            }
            if (!has_our_validators) continue;

            // Build committee_bits.
            var committee_bits = CommitteeBits.Type.empty;
            committee_bits.set(committee_idx, true) catch continue;

            // Build aggregation_bits — set bits for our validators.
            var aggregation_bits = AggregationBits.Type.fromBitLen(allocator, committee.len) catch continue;
            errdefer aggregation_bits.deinit(allocator);

            var any_set = false;
            for (committee, 0..) |vi, pos| {
                if (self.ownsValidator(vi)) {
                    // Apply participation rate.
                    if (self.participation_rate >= 1.0) {
                        aggregation_bits.set(allocator, pos, true) catch continue;
                        any_set = true;
                    } else if (self.participation_rate > 0.0) {
                        // Deterministic from slot + validator index.
                        var seed_val: u64 = attestation_slot *% 0x9E3779B97F4A7C15 +% vi *% 0xBF58476D1CE4E5B9;
                        seed_val = seed_val ^ (seed_val >> 30) *% 0xBF58476D1CE4E5B9;
                        const rand_val: f64 = @as(f64, @floatFromInt(seed_val & 0xFFFFFFFF)) /
                            @as(f64, @floatFromInt(std.math.maxInt(u32)));
                        if (rand_val < self.participation_rate) {
                            aggregation_bits.set(allocator, pos, true) catch continue;
                            any_set = true;
                        }
                    }
                }
            }

            if (!any_set) {
                aggregation_bits.deinit(allocator);
                continue;
            }

            try result.attestations.append(allocator, .{
                .aggregation_bits = aggregation_bits,
                .data = att_data,
                .signature = types.primitive.BLSSignature.default_value,
                .committee_bits = committee_bits,
            });

            self.attestations_produced += 1;
        }

        return result;
    }

    /// Compute duties for the given slot: is this validator the proposer?
    /// Which committees are we assigned to?
    pub fn computeDuties(
        self: *const SimValidator,
        allocator: Allocator,
        cached_state: *CachedBeaconState,
        slot: Slot,
    ) !DutyResult {
        const epoch_cache = cached_state.epoch_cache;
        const att_epoch = computeEpochAtSlot(slot);

        const is_proposer = self.isProposer(cached_state, slot);

        var assignments = std.ArrayListUnmanaged(CommitteeAssignment).empty;
        errdefer {
            for (assignments.items) |*a| a.deinit(allocator);
            assignments.deinit(allocator);
        }

        const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(att_epoch) catch
            return .{ .is_proposer = is_proposer, .committee_assignments = assignments };

        for (0..committees_per_slot) |committee_idx| {
            const committee = epoch_cache.getBeaconCommittee(slot, committee_idx) catch continue;
            if (committee.len == 0) continue;

            var positions = std.ArrayListUnmanaged(ValidatorPosition).empty;
            for (committee, 0..) |vi, pos| {
                if (self.ownsValidator(vi)) {
                    try positions.append(allocator, .{
                        .committee_position = pos,
                        .validator_index = vi,
                    });
                }
            }

            if (positions.items.len > 0) {
                try assignments.append(allocator, .{
                    .committee_index = committee_idx,
                    .validator_positions = positions,
                });
            } else {
                positions.deinit(allocator);
            }
        }

        return .{
            .is_proposer = is_proposer,
            .committee_assignments = assignments,
        };
    }
};
