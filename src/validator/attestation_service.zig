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

const chain_header_tracker = @import("chain_header_tracker.zig");
const ChainHeaderTracker = chain_header_tracker.ChainHeaderTracker;
const HeadInfo = chain_header_tracker.HeadInfo;

const state_transition = @import("state_transition");

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;
const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;

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
    /// Genesis time (Unix seconds) — for correct sub-slot timing (BUG-5 fix).
    genesis_time_unix_secs: u64,

    /// Duties indexed by slot (rolling window across epochs).
    duties: std.ArrayList(AttesterDutyWithProof),
    /// Epoch for which duties are currently cached.
    duties_epoch: ?u64,
    /// Pre-fetched duties for next epoch.
    next_duties: std.ArrayList(AttesterDutyWithProof),
    next_duties_epoch: ?u64,
    /// Optional chain header tracker for reorg detection.
    header_tracker: ?*ChainHeaderTracker,
    /// Last known previous_duty_dependent_root — used to detect reorgs.
    /// When this changes, attester duties for the current epoch must be re-fetched.
    ///
    /// TS: AttestationDutiesService.currentDependentRoot
    last_previous_dependent_root: [32]u8,
    /// Last known current_duty_dependent_root — used to detect reorgs.
    last_current_dependent_root: [32]u8,
    /// Doppelganger service reference (optional).
    doppelganger: ?*DoppelgangerService,
    /// Syncing tracker reference (optional).
    syncing_tracker: ?*SyncingTracker,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        seconds_per_slot: u64,
        genesis_time_unix_secs: u64,
    ) AttestationService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
            .seconds_per_slot = seconds_per_slot,
            .genesis_time_unix_secs = genesis_time_unix_secs,
            .duties = std.ArrayList(AttesterDutyWithProof).init(allocator),
            .duties_epoch = null,
            .next_duties = std.ArrayList(AttesterDutyWithProof).init(allocator),
            .next_duties_epoch = null,
            .header_tracker = null,
            .last_previous_dependent_root = [_]u8{0} ** 32,
            .last_current_dependent_root = [_]u8{0} ** 32,
            .doppelganger = null,
            .syncing_tracker = null,
        };
    }

    /// Wire up safety checkers. Called from validator.zig after init.
    pub fn setSafetyCheckers(
        self: *AttestationService,
        dopple: ?*DoppelgangerService,
        syncing: ?*SyncingTracker,
    ) void {
        self.doppelganger = dopple;
        self.syncing_tracker = syncing;
    }

    /// Returns true if it is safe for this validator to sign attestations.
    fn isSafeToSign(self: *const AttestationService, pubkey: [48]u8) bool {
        if (self.syncing_tracker) |st| {
            if (!st.isSynced()) return false;
        }
        if (self.doppelganger) |d| {
            if (!d.isSigningAllowed(pubkey)) return false;
        }
        return true;
    }

    pub fn deinit(self: *AttestationService) void {
        self.duties.deinit();
        self.next_duties.deinit();
    }

    /// Attach a chain header tracker for reorg detection.
    ///
    /// When set, onHead() will be called via HeadCallback when the chain head
    /// changes. If the dependent_root changes, duties are re-fetched.
    pub fn setHeaderTracker(self: *AttestationService, tracker: *ChainHeaderTracker) void {
        self.header_tracker = tracker;
        tracker.onHead(.{ .ctx = self, .fn_ptr = onHeadChange });
    }

    /// Called when a new head event arrives from ChainHeaderTracker.
    ///
    /// If the duty-dependent root changed, we re-fetch attester duties to avoid
    /// attesting to a stale chain after a reorg.
    ///
    /// TS: AttestationDutiesService.handleClockDutiesReorg
    fn onHeadChange(ctx: *anyopaque, info: HeadInfo) void {
        const self: *AttestationService = @ptrCast(@alignCast(ctx));

        const prev_changed = !std.mem.eql(u8, &self.last_previous_dependent_root, &info.previous_duty_dependent_root);
        const curr_changed = !std.mem.eql(u8, &self.last_current_dependent_root, &info.current_duty_dependent_root);

        if (!prev_changed and !curr_changed) return;

        const epoch = info.slot / 32; // approximate; slots_per_epoch not stored
        log.warn(
            "reorg detected at slot={d}: dependent_root changed — re-fetching attester duties for epoch={d}",
            .{ info.slot, epoch },
        );
        self.last_previous_dependent_root = info.previous_duty_dependent_root;
        self.last_current_dependent_root = info.current_duty_dependent_root;

        // We don't have an io handle here (head callbacks are sync, called from SSE reader).
        // Flag that duties need refresh; they will be re-fetched on the next slot callback.
        // An alternative would be to fire an async task if io is stored; for now we clear
        // cached duties so they get re-fetched at the next onEpoch/onSlot boundary.
        //
        // TS: AttestationDutiesService immediately re-fetches via pollBeaconAttesters.
        self.duties_epoch = null; // invalidate cache → forces refresh on next onEpoch
        log.warn("attester duties cache invalidated due to reorg", .{});
    }

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to refresh attester duties.
    pub fn onEpoch(self: *AttestationService, io: Io, epoch: u64) void {
        // Swap in pre-fetched next epoch duties if available.
        if (self.next_duties_epoch) |ne| {
            if (ne == epoch) {
                // Move next → current.
                self.duties.clearRetainingCapacity();
                for (self.next_duties.items) |d| {
                    self.duties.append(d) catch {};
                }
                self.duties_epoch = ne;
                self.next_duties.clearRetainingCapacity();
                self.next_duties_epoch = null;
                log.debug("swapped pre-fetched attester duties into epoch={d}", .{epoch});
                // Pre-fetch for epoch+1 now.
                self.prefetchNextEpochDuties(io, epoch + 1);
                return;
            }
        }
        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
        // Pre-fetch next epoch duties.
        self.prefetchNextEpochDuties(io, epoch + 1);
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

    /// Pre-fetch attester duties for next epoch to avoid latency at epoch boundaries.
    ///
    /// TS: AttestationDutiesService fetches N+1 at end of epoch N.
    fn prefetchNextEpochDuties(self: *AttestationService, io: Io, next_epoch: u64) void {
        const indices = self.validator_store.allIndices(self.allocator) catch return;
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("pre-fetching attester duties epoch={d}", .{next_epoch});
        const fetched = self.api.getAttesterDuties(io, next_epoch, indices) catch |err| {
            log.warn("prefetch attester duties epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        defer self.allocator.free(fetched);

        self.next_duties.clearRetainingCapacity();
        self.next_duties_epoch = next_epoch;

        for (fetched) |duty| {
            var sel_proof: ?[96]u8 = null;
            var sel_root: [32]u8 = undefined;
            signing_mod.attestationSelectionProofSigningRoot(self.signing_ctx, duty.slot, &sel_root) catch {};
            if (self.validator_store.signSelectionProof(duty.pubkey, sel_root)) |sig| {
                sel_proof = sig.compress();
            } else |_| {}
            self.next_duties.append(.{ .duty = duty, .selection_proof = sel_proof }) catch {};
        }
        log.debug("pre-fetched {d} attester duties epoch={d}", .{ fetched.len, next_epoch });
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

        // Sub-slot timing: compute absolute slot start relative to genesis.
        // slot_start_ns = (genesis_time_unix_secs + slot * seconds_per_slot) * ns_per_s
        //
        // BUG-5 Note: std.time.nanoTimestamp() uses CLOCK_REALTIME on Linux/macOS/Windows
        // (confirmed in zig/lib/std/time.zig — it calls posix.clock_gettime(.REALTIME)).
        // This IS Unix wall-clock time, NOT boot-relative, so comparing against
        // genesis_time_ns is correct. No platform-specific workaround needed.
        const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
        const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            if (now_ns < slot_start_ns + one_third_ns) {
                const wait_ns = slot_start_ns + one_third_ns - now_ns;
                std.Thread.sleep(wait_ns);
            }
        }

        // Step 1: produce and publish attestations (~1/3 slot).
        const att_data_root = try self.produceAndPublishAttestations(io, slot, duties_at_slot);

        // Sleep until 2/3 slot for aggregation.
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            if (now_ns < slot_start_ns + two_thirds_ns) {
                const wait_ns = slot_start_ns + two_thirds_ns - now_ns;
                std.Thread.sleep(wait_ns);
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

            // Safety check before signing.
            if (!self.isSafeToSign(dp.duty.pubkey)) {
                log.warn("skipping attestation slot={d} validator_index={d}: signing not safe", .{ slot, dp.duty.validator_index });
                continue;
            }

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

            // Compute proper SSZ bitlist encoding for aggregation_bits.
            // SSZ bitlist: data bytes with validator bit set + sentinel bit.
            const committee_length = dp.duty.committee_length;
            const validator_committee_index = dp.duty.validator_committee_index;
            // data_byte_count covers bits 0..committee_length-1
            const data_byte_count: usize = (committee_length + 7) / 8;
            // If committee_length is a multiple of 8, sentinel needs an extra byte
            const ssz_byte_count: usize = if (committee_length % 8 == 0) data_byte_count + 1 else data_byte_count;
            var agg_bits_buf = [_]u8{0} ** 257; // max committee_length=2048 -> 256+1 bytes
            const agg_bits = agg_bits_buf[0..ssz_byte_count];
            // Set the validator's bit position within the committee
            agg_bits[validator_committee_index / 8] |= @as(u8, 1) << @intCast(validator_committee_index % 8);
            // Set the SSZ sentinel bit: bit at index committee_length
            agg_bits[committee_length / 8] |= @as(u8, 1) << @intCast(committee_length % 8);
            // Hex-encode agg_bits_buf[0..ssz_byte_count] at runtime.
            var agg_bits_hex_buf = [_]u8{0} ** (257 * 2);
            for (agg_bits[0..ssz_byte_count], 0..) |byte, i| {
                const nibbles = "0123456789abcdef";
                agg_bits_hex_buf[i * 2] = nibbles[(byte >> 4) & 0xF];
                agg_bits_hex_buf[i * 2 + 1] = nibbles[byte & 0xF];
            }
            const agg_bits_hex_slice = agg_bits_hex_buf[0 .. ssz_byte_count * 2];

            if (signed_count > 0) try attestations_json.append(',');
            try attestations_json.writer().print(
                "{{\"aggregation_bits\":\"0x{s}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}}",
                .{
                    agg_bits_hex_slice,
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

            // Safety check before aggregate signing.
            if (!self.isSafeToSign(dp.duty.pubkey)) {
                log.warn("skipping aggregate slot={d} validator_index={d}: signing not safe", .{ slot, dp.duty.validator_index });
                continue;
            }

            // 1. Use the real AttestationData hash_tree_root (SSZ-computed).
            // BUG-2 fix: att_data_root is already computed from the real attestation data
            // in produceAndPublishAttestations() and passed in here (not zeroed).
            const agg = try self.api.getAggregatedAttestation(io, slot, att_data_root);
            defer self.allocator.free(agg.attestation_ssz);

            // 2. Build AggregateAndProof by parsing the aggregate from the BN response.
            // BUG-2 fix: Parse the actual aggregate attestation from the BN JSON response
            // instead of using a zeroed Attestation struct.
            var aggregate_attestation = try self.parseAggregateAttestation(agg.attestation_ssz);
            defer aggregate_attestation.aggregation_bits.data.deinit(self.allocator);

            const aggregate_and_proof = consensus_types.phase0.AggregateAndProof.Type{
                .aggregator_index = dp.duty.validator_index,
                .aggregate = aggregate_attestation,
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
            const sel_hex = std.fmt.bytesToHex(&sel_proof, .lower);

            // 3. Build SignedAggregateAndProof JSON and publish.
            // BUG-2 fix: Use the actual aggregate data from the BN response.
            const agg_data = aggregate_and_proof.aggregate.data;
            const agg_bbr_hex = std.fmt.bytesToHex(&agg_data.beacon_block_root, .lower);
            const agg_src_root_hex = std.fmt.bytesToHex(&agg_data.source.root, .lower);
            const agg_tgt_root_hex = std.fmt.bytesToHex(&agg_data.target.root, .lower);
            const agg_sig_hex = std.fmt.bytesToHex(&aggregate_and_proof.aggregate.signature, .lower);
            var agg_json = std.ArrayList(u8).init(self.allocator);
            defer agg_json.deinit();
            // Serialize actual aggregation_bits from BN aggregate response (SSZ bitlist).
            // data.items contains raw data bytes without sentinel; add sentinel byte.
            var agg_agg_bits_buf: [258]u8 = undefined; // enough for MAX_VALIDATORS_PER_COMMITTEE
            const agg_bits_bl = &aggregate_attestation.aggregation_bits;
            const agg_data_bytes = agg_bits_bl.data.items;
            const agg_bl_bit_len = agg_bits_bl.bit_len;
            const agg_bl_data_byte_count = (agg_bl_bit_len + 7) / 8;
            const agg_bl_ssz_byte_count = if (agg_bl_bit_len % 8 == 0) agg_bl_data_byte_count + 1 else agg_bl_data_byte_count;
            @memset(&agg_agg_bits_buf, 0);
            if (agg_data_bytes.len > 0) {
                const copy_len = @min(agg_data_bytes.len, agg_agg_bits_buf.len);
                @memcpy(agg_agg_bits_buf[0..copy_len], agg_data_bytes[0..copy_len]);
            }
            // Set sentinel bit at position agg_bl_bit_len
            if (agg_bl_ssz_byte_count <= agg_agg_bits_buf.len) {
                agg_agg_bits_buf[agg_bl_bit_len / 8] |= @as(u8, 1) << @intCast(agg_bl_bit_len % 8);
            }
            const agg_agg_bits_ssz = agg_agg_bits_buf[0..agg_bl_ssz_byte_count];
            // Hex-encode at runtime (bytesToHex requires comptime-known size).
            var agg_agg_bits_hex_buf = [_]u8{0} ** (258 * 2);
            for (agg_agg_bits_ssz, 0..) |byte, i| {
                const nibbles = "0123456789abcdef";
                agg_agg_bits_hex_buf[i * 2] = nibbles[(byte >> 4) & 0xF];
                agg_agg_bits_hex_buf[i * 2 + 1] = nibbles[byte & 0xF];
            }
            const agg_agg_bits_hex = agg_agg_bits_hex_buf[0 .. agg_bl_ssz_byte_count * 2];

            try agg_json.writer().print(
                "[{{\"message\":{{\"aggregator_index\":\"{d}\",\"aggregate\":{{\"aggregation_bits\":\"0x{s}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}]",
                .{
                    dp.duty.validator_index,
                    agg_agg_bits_hex,
                    agg_data.slot,
                    agg_data.index,
                    agg_bbr_hex,
                    agg_data.source.epoch, agg_src_root_hex,
                    agg_data.target.epoch, agg_tgt_root_hex,
                    agg_sig_hex,
                    sel_hex,
                    sig_hex,
                },
            );

            self.api.publishAggregateAndProofs(io, agg_json.items) catch |err| {
                log.warn("publishAggregateAndProofs error: {s}", .{@errorName(err)});
            };
        }
    }
    /// Parse an aggregate attestation from the BN JSON response.
    ///
    /// BUG-2 fix: Decode the real aggregate data from the BN response instead of
    /// using zeroed structs. Parses the JSON fields needed for the AggregateAndProof.
    ///
    /// The aggregation_bits field is heap-allocated; caller must deinit via
    /// `aggregate.aggregation_bits.data.deinit(allocator)`.
    fn parseAggregateAttestation(
        self: *AttestationService,
        json_bytes: []const u8,
    ) !consensus_types.phase0.Attestation.Type {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        var result = consensus_types.phase0.Attestation.Type{
            .aggregation_bits = .{ .data = .empty, .bit_len = 0 },
            .data = std.mem.zeroes(consensus_types.phase0.AttestationData.Type),
            .signature = [_]u8{0} ** 96,
        };

        const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), json_bytes, .{}) catch return result;

        // Response may be {"data": {...}} or the attestation directly.
        const att_obj = blk: {
            const root_obj = switch (parsed.value) {
                .object => |o| o,
                else => return result,
            };
            if (root_obj.get("data")) |data_val| {
                break :blk switch (data_val) {
                    .object => |o| o,
                    else => return result,
                };
            }
            break :blk root_obj;
        };

        // Parse aggregation_bits (hex-encoded bitlist).
        if (att_obj.get("aggregation_bits")) |bits_val| {
            const bits_str = switch (bits_val) { .string => |s| s, else => "" };
            const hex = if (std.mem.startsWith(u8, bits_str, "0x")) bits_str[2..] else bits_str;
            const byte_len = hex.len / 2;
            if (byte_len > 0) {
                const bytes = try self.allocator.alloc(u8, byte_len);
                defer self.allocator.free(bytes);
                _ = std.fmt.hexToBytes(bytes, hex) catch {};
                // Last byte has length sentinel: highest set bit marks the end.
                const last_byte = bytes[byte_len - 1];
                if (last_byte != 0) {
                    const sentinel_bit = @as(u3, @intCast(7 - @clz(last_byte)));
                    const bit_len = (byte_len - 1) * 8 + sentinel_bit;
                    result.aggregation_bits = try @TypeOf(result.aggregation_bits).fromBitLen(self.allocator, bit_len);
                    if (byte_len > 1) {
                        @memcpy(result.aggregation_bits.data.items, bytes[0 .. byte_len - 1]);
                    }
                }
            }
        }

        // Parse attestation data fields.
        if (att_obj.get("data")) |data_val| {
            const data_map = switch (data_val) { .object => |o| o, else => return result };

            if (data_map.get("slot")) |v| {
                const s = switch (v) { .string => |s| s, else => "" };
                result.data.slot = std.fmt.parseInt(u64, s, 10) catch result.data.slot;
            }
            if (data_map.get("index")) |v| {
                const s = switch (v) { .string => |s| s, else => "" };
                result.data.index = std.fmt.parseInt(u64, s, 10) catch result.data.index;
            }
            if (data_map.get("beacon_block_root")) |v| {
                const s = switch (v) { .string => |s| s, else => "" };
                const hex = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
                _ = std.fmt.hexToBytes(&result.data.beacon_block_root, hex) catch {};
            }
            if (data_map.get("source")) |src_val| {
                const src_map = switch (src_val) { .object => |o| o, else => return result };
                if (src_map.get("epoch")) |v| {
                    const s = switch (v) { .string => |s| s, else => "" };
                    result.data.source.epoch = std.fmt.parseInt(u64, s, 10) catch result.data.source.epoch;
                }
                if (src_map.get("root")) |v| {
                    const s = switch (v) { .string => |s| s, else => "" };
                    const hex = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
                    _ = std.fmt.hexToBytes(&result.data.source.root, hex) catch {};
                }
            }
            if (data_map.get("target")) |tgt_val| {
                const tgt_map = switch (tgt_val) { .object => |o| o, else => return result };
                if (tgt_map.get("epoch")) |v| {
                    const s = switch (v) { .string => |s| s, else => "" };
                    result.data.target.epoch = std.fmt.parseInt(u64, s, 10) catch result.data.target.epoch;
                }
                if (tgt_map.get("root")) |v| {
                    const s = switch (v) { .string => |s| s, else => "" };
                    const hex = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
                    _ = std.fmt.hexToBytes(&result.data.target.root, hex) catch {};
                }
            }
        }

        // Parse signature.
        if (att_obj.get("signature")) |v| {
            const s = switch (v) { .string => |s| s, else => "" };
            const hex = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
            _ = std.fmt.hexToBytes(&result.signature, hex) catch {};
        }

        return result;
    }
};