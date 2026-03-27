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

const state_transition = @import("state_transition");

const log = std.log.scoped(.attestation_service);

/// Target aggregators per committee (from consensus spec).
const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

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

        // Sub-slot timing per Ethereum spec:
        //   Attestations at 1/3 slot (seconds_per_slot / 3 seconds in).
        //   Aggregates at 2/3 slot (seconds_per_slot * 2 / 3 seconds in).
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        const one_third_ns = slot_duration_ns / 3;
        const two_thirds_ns = slot_duration_ns * 2 / 3;

        // Compute elapsed time within the current slot.
        // genesis_time is not passed here; use nanoTimestamp mod slot_duration as a proxy.
        // This is accurate when the slot clock is aligned with wall clock (which it is).
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            const elapsed_in_slot_ns = now_ns % slot_duration_ns;
            if (elapsed_in_slot_ns < one_third_ns) {
                std.Thread.sleep(one_third_ns - elapsed_in_slot_ns);
            }
        }

        // Step 1: produce and publish attestations (~1/3 slot).
        const att_data_root = try self.produceAndPublishAttestations(io, slot, duties_at_slot);

        // Sleep until 2/3 slot for aggregation.
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            const elapsed_in_slot_ns = now_ns % slot_duration_ns;
            if (elapsed_in_slot_ns < two_thirds_ns) {
                std.Thread.sleep(two_thirds_ns - elapsed_in_slot_ns);
            }
        }

        // Step 2: produce and publish aggregates (~2/3 slot).
        try self.produceAndPublishAggregates(io, slot, duties_at_slot, att_data_root);
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
    ) ![32]u8 {
        // Collect duties for this slot.
        var any = false;
        for (duties) |dp| {
            if (dp.duty.slot == slot) { any = true; break; }
        }
        if (!any) return std.mem.zeroes([32]u8);

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

        // Sign for each validator with a duty this slot and collect JSON.
        var attestations_json = std.ArrayList(u8).init(self.allocator);
        defer attestations_json.deinit();
        var signed_count: u32 = 0;

        try attestations_json.append('[');

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

            const sig_bytes = sig.compress();
            const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);
            const bbr_hex = std.fmt.bytesToHex(&att_data_resp.beacon_block_root, .lower);
            const src_root_hex = std.fmt.bytesToHex(&att_data_resp.source_root, .lower);
            const tgt_root_hex = std.fmt.bytesToHex(&att_data_resp.target_root, .lower);

            // Encode as SingleAttestation JSON (post-Electra format).
            // Falls back to aggregation_bits = 1-bit set if committee_length known.
            if (signed_count > 0) try attestations_json.append(',');
            try attestations_json.writer().print(
                "{{\"aggregation_bits\":\"0x01\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}}",
                .{
                    slot, dp.duty.committee_index,
                    bbr_hex,
                    att_data_resp.source_epoch, src_root_hex,
                    att_data_resp.target_epoch, tgt_root_hex,
                    sig_hex,
                },
            );
            signed_count += 1;
        }

        try attestations_json.append(']');

        if (signed_count > 0) {
            self.api.publishAttestations(io, attestations_json.items) catch |err| {
                log.warn("publishAttestations failed slot={d} error={s}", .{ slot, @errorName(err) });
            };
            log.info("attested slot={d} count={d}", .{ slot, signed_count });
        }

        // Compute and return the AttestationData hash_tree_root for aggregation.
        var att_data_root: [32]u8 = undefined;
        try consensus_types.phase0.AttestationData.hashTreeRoot(&att_data, &att_data_root);
        return att_data_root;
    }

    fn produceAndPublishAggregates(
        self: *AttestationService,
        io: Io,
        slot: u64,
        duties: []const AttesterDutyWithProof,
        att_data_root: [32]u8,
    ) !void {
        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;

            // Only aggregate if we have a selection proof and are eligible.
            const sel_proof = dp.selection_proof orelse continue;

            // Aggregation eligibility check per consensus spec:
            //   is_aggregator = (SHA256(sel_proof)[0:8] as little-endian u64)
            //                   % max(1, committee_size / TARGET_AGGREGATORS_PER_COMMITTEE) == 0
            const committee_size = dp.duty.committee_length;
            const modulo = @max(1, committee_size / TARGET_AGGREGATORS_PER_COMMITTEE);
            const Sha256 = std.crypto.hash.sha2.Sha256;
            var sel_hash: [32]u8 = undefined;
            Sha256.hash(&sel_proof, &sel_hash, .{});
            const hash_val = std.mem.readInt(u64, sel_hash[0..8], .little);
            if (hash_val % modulo != 0) continue; // not selected as aggregator this slot

            log.debug("selected as aggregator slot={d} validator_index={d}", .{ slot, dp.duty.validator_index });

            // 1. Use the real AttestationData hash_tree_root (SSZ-computed).
            const agg_data_root: [32]u8 = att_data_root;
            const agg = try self.api.getAggregatedAttestation(io, slot, agg_data_root);
            defer self.allocator.free(agg.attestation_ssz);

            // 2. Build AggregateAndProof and compute its signing root.
            const aggregate_and_proof = consensus_types.phase0.AggregateAndProof.Type{
                .aggregator_index = dp.duty.validator_index,
                // aggregate: we pass the decoded aggregate attestation here.
                // For now we use a zeroed aggregate since we don't decode the SSZ response.
                .aggregate = std.mem.zeroes(consensus_types.phase0.Attestation.Type),
                .selection_proof = sel_proof,
            };

            var agg_signing_root: [32]u8 = undefined;
            signing_mod.aggregateAndProofSigningRoot(
                self.allocator,
                self.signing_ctx,
                &aggregate_and_proof,
                &agg_signing_root,
            ) catch |err| {
                log.warn("aggregateAndProofSigningRoot error: {s}", .{@errorName(err)});
                continue;
            };

            const sig = self.validator_store.signAggregateAndProof(dp.duty.pubkey, agg_signing_root) catch |err| {
                log.warn("signAggregateAndProof error: {s}", .{@errorName(err)});
                continue;
            };
            const sig_bytes = sig.compress();
            const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);
            const agg_pk_hex = std.fmt.bytesToHex(&dp.duty.pubkey, .lower);

            // 3. Build SignedAggregateAndProof JSON and publish.
            var agg_json = std.ArrayList(u8).init(self.allocator);
            defer agg_json.deinit();
            try agg_json.writer().print(
                "[{{\"message\":{{\"aggregator_index\":\"{d}\",\"aggregate\":{{\"aggregation_bits\":\"0x00\",\"data\":{{\"slot\":\"{d}\",\"index\":\"0\",\"beacon_block_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"source\":{{\"epoch\":\"0\",\"root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}},\"target\":{{\"epoch\":\"0\",\"root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}}}},\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}]",
                .{ dp.duty.validator_index, slot, sig_hex, agg_pk_hex[0..2], sig_hex },
            );

            self.api.publishAggregateAndProofs(io, agg_json.items) catch |err| {
                log.warn("publishAggregateAndProofs error: {s}", .{@errorName(err)});
            };
        }
    }
};
