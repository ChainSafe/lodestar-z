//! Attestation service for the Validator Client.
//!
//! Tracks attester duties per epoch and submits attestations + aggregates
//! at the correct time within each slot.
//!
//! TS equivalent: packages/validator/src/services/attestation.ts (AttestationService)
//!               + packages/validator/src/services/attestationDuties.ts (AttestationDutiesService)
//!
//! Timing (Ethereum spec):
//!   - Attestation: produce at ATTESTATION_DUE_BPS (~1/3) or on new head, whichever first.
//!   - Aggregate:   produce at AGGREGATE_DUE_BPS (~2/3) of the slot.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const AttesterDuty = types.AttesterDuty;
const AttesterDutyWithProof = types.AttesterDutyWithProof;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;

const log = std.log.scoped(.attestation_service);

/// Fraction of slot at which attestations are due (1/3 ≈ 4s at 12s slots).
const ATTESTATION_DUE_SLOT_FRACTION_NUM: u64 = 1;
const ATTESTATION_DUE_SLOT_FRACTION_DEN: u64 = 3;

/// Fraction of slot at which aggregation is due (2/3 ≈ 8s at 12s slots).
const AGGREGATE_DUE_SLOT_FRACTION_NUM: u64 = 2;
const AGGREGATE_DUE_SLOT_FRACTION_DEN: u64 = 3;

// ---------------------------------------------------------------------------
// AttestationService
// ---------------------------------------------------------------------------

pub const AttestationService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    seconds_per_slot: u64,

    /// Duties indexed by slot % SLOTS_PER_EPOCH (rolling window across epochs).
    duties: std.ArrayList(AttesterDutyWithProof),
    /// Epoch for which duties are currently cached.
    duties_epoch: ?u64,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        seconds_per_slot: u64,
    ) AttestationService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .seconds_per_slot = seconds_per_slot,
            .duties = std.ArrayList(AttesterDutyWithProof).init(allocator),
            .duties_epoch = null,
        };
    }

    pub fn deinit(self: *AttestationService) void {
        self.duties.deinit();
    }

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to refresh attester duties.
    ///
    /// TS: AttestationDutiesService (runs on each epoch via clock.runEveryEpoch)
    pub fn onEpoch(self: *AttestationService, io: Io, epoch: u64) void {
        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    /// Called at each slot to produce and publish attestations + aggregates.
    ///
    /// TS: AttestationService.runAttestationTasks (runs on each slot via clock.runEverySlot)
    pub fn onSlot(self: *AttestationService, io: Io, slot: u64) void {
        self.runAttestationTasks(io, slot) catch |err| {
            log.err("runAttestationTasks slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    fn refreshDuties(self: *AttestationService, io: Io, epoch: u64) !void {
        // Collect our validator indices.
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("fetching attester duties epoch={d} validators={d}", .{ epoch, indices.len });

        const fetched = try self.api.getAttesterDuties(io, epoch, indices);
        defer self.allocator.free(fetched);

        // Rebuild duties list.
        self.duties.clearRetainingCapacity();
        self.duties_epoch = epoch;

        for (fetched) |duty| {
            try self.duties.append(.{
                .duty = duty,
                .selection_proof = null, // computed lazily
            });
        }

        // Compute selection proofs for aggregator eligibility.
        try self.computeSelectionProofs(epoch);

        log.debug("cached {d} attester duties epoch={d}", .{ fetched.len, epoch });
    }

    fn computeSelectionProofs(self: *AttestationService, epoch: u64) !void {
        _ = epoch;
        // For each duty: sign the slot to produce a selection proof.
        // If modulo(SHA256(selection_proof), committee_length) == 0, we are aggregator.
        // TODO: implement when signing root computation is wired up.
        for (self.duties.items) |*d| {
            // Stub: leave selection_proof null (not aggregating yet).
            _ = d;
        }
    }

    // -----------------------------------------------------------------------
    // Attestation production
    // -----------------------------------------------------------------------

    fn runAttestationTasks(self: *AttestationService, io: Io, slot: u64) !void {
        const duties_at_slot = self.getDutiesAtSlot(slot);
        if (duties_at_slot.len == 0) return;

        // --- Step 1: produce and publish attestations at 1/3 slot ---
        // In full implementation: sleep until 1/3 slot OR head block arrives.
        // Here we call immediately (stub timing).
        try self.produceAndPublishAttestations(io, slot, duties_at_slot);

        // --- Step 2: produce and publish aggregates at 2/3 slot ---
        // In full implementation: sleep until 2/3 slot.
        try self.produceAndPublishAggregates(io, slot, duties_at_slot);
    }

    fn getDutiesAtSlot(self: *const AttestationService, slot: u64) []const AttesterDutyWithProof {
        // Build a temporary slice of duties matching this slot.
        // In the full implementation this returns a view; here we linear-search.
        // For now, return the whole list and filter in the callee (stub).
        _ = slot;
        return self.duties.items;
    }

    fn produceAndPublishAttestations(
        self: *AttestationService,
        io: Io,
        slot: u64,
        duties: []const AttesterDutyWithProof,
    ) !void {
        if (duties.len == 0) return;

        // Fetch attestation data once (committee_index=0; BN ignores index for data).
        const data = try self.api.produceAttestationData(io, slot, 0);

        // Sign for each validator.
        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;

            // TODO: compute signing root from AttestationData + domain.
            const signing_root: [32]u8 = std.mem.zeroes([32]u8); // stub
            const sig = try self.validator_store.signAttestation(
                dp.duty.pubkey,
                signing_root,
                data.source_epoch,
                data.target_epoch,
            );
            _ = sig;

            // TODO: encode SingleAttestation / Attestation and collect for batch submit.
        }

        // TODO: submit batch to api.publishAttestations()
        log.info("published attestations slot={d} count={d}", .{ slot, duties.len });
    }

    fn produceAndPublishAggregates(
        self: *AttestationService,
        io: Io,
        slot: u64,
        duties: []const AttesterDutyWithProof,
    ) !void {
        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;
            // Only act if we have a selection proof and are an aggregator.
            const sel_proof = dp.selection_proof orelse continue;

            // 1. Fetch aggregate attestation.
            const agg_data_root: [32]u8 = std.mem.zeroes([32]u8); // TODO: real root
            const agg = try self.api.getAggregatedAttestation(io, slot, agg_data_root);
            defer self.allocator.free(agg.attestation_ssz);

            // 2. Sign AggregateAndProof.
            const signing_root: [32]u8 = std.mem.zeroes([32]u8); // stub
            const sig = try self.validator_store.signAggregateAndProof(dp.duty.pubkey, signing_root);
            _ = sig;
            _ = sel_proof;

            // 3. Publish.
            try self.api.publishAggregateAndProofs(io, agg.attestation_ssz);
        }
    }
};
