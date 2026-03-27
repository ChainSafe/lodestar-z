//! Attestation service for the Validator Client.
//!
//! Tracks attester duties per epoch and submits attestations + aggregates
//! at the correct time within each slot.
//!
//! TS equivalent: packages/validator/src/services/attestation.ts (AttestationService)
//!               + packages/validator/src/services/attestationDuties.ts (AttestationDutiesService)
//!
//! Timing (Ethereum spec):
//!   - Attestation: produce at ~1/3 slot (or on new head, whichever first).
//!   - Aggregate:   produce at ~2/3 slot.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const consensus_types = @import("consensus_types");
const types = @import("types.zig");
const AttesterDuty = types.AttesterDuty;
const AttesterDutyWithProof = types.AttesterDutyWithProof;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const log = std.log.scoped(.attestation_service);

// ---------------------------------------------------------------------------
// AttestationService
// ---------------------------------------------------------------------------

pub const AttestationService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    signing_ctx: SigningContext,
    seconds_per_slot: u64,

    /// Duties indexed by slot (rolling window across epochs).
    duties: std.ArrayList(AttesterDutyWithProof),
    /// Epoch for which duties are currently cached.
    duties_epoch: ?u64,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        seconds_per_slot: u64,
    ) AttestationService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
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
    pub fn onEpoch(self: *AttestationService, io: Io, epoch: u64) void {
        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    /// Called at each slot to produce and publish attestations + aggregates.
    pub fn onSlot(self: *AttestationService, io: Io, slot: u64) void {
        self.runAttestationTasks(io, slot) catch |err| {
            log.err("runAttestationTasks slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    fn refreshDuties(self: *AttestationService, io: Io, epoch: u64) !void {
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("fetching attester duties epoch={d} validators={d}", .{ epoch, indices.len });

        const fetched = try self.api.getAttesterDuties(io, epoch, indices);
        defer self.allocator.free(fetched);

        self.duties.clearRetainingCapacity();
        self.duties_epoch = epoch;

        for (fetched) |duty| {
            // Compute selection proof: sign(slot) with DOMAIN_SELECTION_PROOF.
            var sel_proof: ?[96]u8 = null;
            var sel_root: [32]u8 = undefined;
            signing_mod.attestationSelectionProofSigningRoot(self.signing_ctx, duty.slot, &sel_root) catch |err| {
                log.warn("selection proof signing root error: {s}", .{@errorName(err)});
            };
            if (self.validator_store.signSelectionProof(duty.pubkey, sel_root)) |sig| {
                sel_proof = sig.compress();
            } else |_| {}

            try self.duties.append(.{
                .duty = duty,
                .selection_proof = sel_proof,
            });
        }

        log.debug("cached {d} attester duties epoch={d}", .{ fetched.len, epoch });
    }

    // -----------------------------------------------------------------------
    // Attestation production
    // -----------------------------------------------------------------------

    fn runAttestationTasks(self: *AttestationService, io: Io, slot: u64) !void {
        const duties_at_slot = self.getDutiesAtSlot(slot);
        if (duties_at_slot.len == 0) return;

        // Step 1: produce and publish attestations (~1/3 slot).
        // Full implementation: sleep until 1/3 slot OR head block arrives, whichever first.
        // Here we call immediately (synchronous stub).
        try self.produceAndPublishAttestations(io, slot, duties_at_slot);

        // Step 2: produce and publish aggregates (~2/3 slot).
        try self.produceAndPublishAggregates(io, slot, duties_at_slot);
    }

    fn getDutiesAtSlot(self: *const AttestationService, slot: u64) []const AttesterDutyWithProof {
        // Return duties for this specific slot.
        // We'll filter in-place rather than allocating a sub-slice.
        // Callee will re-check duty.slot == slot.
        _ = slot;
        return self.duties.items;
    }

    fn produceAndPublishAttestations(
        self: *AttestationService,
        io: Io,
        slot: u64,
        duties: []const AttesterDutyWithProof,
    ) !void {
        // Collect duties for this slot.
        var any = false;
        for (duties) |dp| {
            if (dp.duty.slot == slot) { any = true; break; }
        }
        if (!any) return;

        // Fetch attestation data from BN (committee_index 0; BN ignores for data content).
        const att_data_resp = try self.api.produceAttestationData(io, slot, 0);

        // Build the AttestationData SSZ struct.
        const att_data = consensus_types.phase0.AttestationData.Type{
            .slot = slot,
            .index = 0,
            .beacon_block_root = att_data_resp.beacon_block_root,
            .source = .{
                .epoch = att_data_resp.source_epoch,
                .root = att_data_resp.source_root,
            },
            .target = .{
                .epoch = att_data_resp.target_epoch,
                .root = att_data_resp.target_root,
            },
        };

        // Compute attestation signing root once (same data for all validators this slot).
        var signing_root: [32]u8 = undefined;
        try signing_mod.attestationSigningRoot(self.signing_ctx, &att_data, &signing_root);

        // Sign for each validator with a duty this slot.
        var signed_count: u32 = 0;
        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;

            const sig = self.validator_store.signAttestation(
                dp.duty.pubkey,
                signing_root,
                att_data_resp.source_epoch,
                att_data_resp.target_epoch,
            ) catch |err| {
                log.warn("signAttestation failed validator_index={d} error={s}", .{ dp.duty.validator_index, @errorName(err) });
                continue;
            };
            _ = sig;
            signed_count += 1;
            // TODO: encode SingleAttestation/Attestation and batch for submit.
        }

        if (signed_count > 0) {
            // TODO: submit batch.
            // try self.api.publishAttestations(io, encoded_batch);
            log.info("attested slot={d} count={d}", .{ slot, signed_count });
        }
    }

    fn produceAndPublishAggregates(
        self: *AttestationService,
        io: Io,
        slot: u64,
        duties: []const AttesterDutyWithProof,
    ) !void {
        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;

            // Only aggregate if we have a selection proof and are eligible.
            const sel_proof = dp.selection_proof orelse continue;

            // Aggregation eligibility: modulo(SHA256(sel_proof), committee_length) == 0.
            // Simplified check: for now assume aggregator if selection_proof is set.
            // TODO: implement proper is_aggregator check.
            _ = sel_proof;

            // 1. Fetch aggregate attestation.
            const agg_data_root: [32]u8 = std.mem.zeroes([32]u8); // TODO: real root from att_data
            const agg = try self.api.getAggregatedAttestation(io, slot, agg_data_root);
            defer self.allocator.free(agg.attestation_ssz);

            // 2. Build and sign AggregateAndProof.
            //    For now we stub the signing root — full impl needs the aggregate decoded.
            const signing_root: [32]u8 = std.mem.zeroes([32]u8); // TODO: real AggregateAndProof signing root
            const sig = self.validator_store.signAggregateAndProof(dp.duty.pubkey, signing_root) catch |err| {
                log.warn("signAggregateAndProof error: {s}", .{@errorName(err)});
                continue;
            };
            _ = sig;

            // 3. Publish.
            try self.api.publishAggregateAndProofs(io, agg.attestation_ssz);
        }
    }
};
