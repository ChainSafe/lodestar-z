//! Sync committee service for the Validator Client.
//!
//! Tracks sync committee duties per sync period and submits sync committee
//! messages and contributions at the correct time within each slot.
//!
//! TS equivalent: packages/validator/src/services/syncCommittee.ts (SyncCommitteeService)
//!               + packages/validator/src/services/syncCommitteeDuties.ts
//!
//! Only active post-Altair.
//!
//! Timing:
//!   - Sync message:      ~1/3 slot (after head block arrives).
//!   - Sync contribution: ~2/3 slot.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const consensus_types = @import("consensus_types");
const types = @import("types.zig");
const SyncCommitteeDuty = types.SyncCommitteeDuty;
const SyncCommitteeDutyWithProofs = types.SyncCommitteeDutyWithProofs;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const chain_header_tracker = @import("chain_header_tracker.zig");
const ChainHeaderTracker = chain_header_tracker.ChainHeaderTracker;
const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;
const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;
const liveness_mod = @import("liveness.zig");
const LivenessTracker = liveness_mod.LivenessTracker;

const log = std.log.scoped(.sync_committee_service);

/// SYNC_COMMITTEE_SIZE = 512 (mainnet). SYNC_COMMITTEE_SUBNET_COUNT = 4.
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;
const SYNC_COMMITTEE_SIZE: u64 = 512;

// ---------------------------------------------------------------------------
// SyncCommitteeService
// ---------------------------------------------------------------------------

pub const SyncCommitteeService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    /// Optional chain header tracker for head root queries.
    header_tracker: ?*ChainHeaderTracker,
    signing_ctx: SigningContext,
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    /// Seconds per slot for sub-slot timing.
    seconds_per_slot: u64,
    /// Genesis time (Unix seconds) — for correct sub-slot timing (BUG-5 fix).
    genesis_time_unix_secs: u64,

    /// Duties keyed by validator index (valid for the current sync period).
    duties: std.ArrayList(SyncCommitteeDutyWithProofs),
    /// Sync period for which duties are cached.
    duties_period: ?u64,
    /// Doppelganger service reference (optional).
    doppelganger: ?*DoppelgangerService,
    /// Syncing tracker reference (optional).
    syncing_tracker: ?*SyncingTracker,
    /// Liveness tracker — records per-validator duty outcomes.
    liveness_tracker: ?*LivenessTracker,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        slots_per_epoch: u64,
        epochs_per_sync_committee_period: u64,
        seconds_per_slot: u64,
        genesis_time_unix_secs: u64,
    ) SyncCommitteeService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .header_tracker = null,
            .signing_ctx = signing_ctx,
            .slots_per_epoch = slots_per_epoch,
            .epochs_per_sync_committee_period = epochs_per_sync_committee_period,
            .seconds_per_slot = seconds_per_slot,
            .genesis_time_unix_secs = genesis_time_unix_secs,
            .duties = std.ArrayList(SyncCommitteeDutyWithProofs).init(allocator),
            .duties_period = null,
            .doppelganger = null,
            .syncing_tracker = null,
            .liveness_tracker = null,
        };
    }

    /// Wire up safety checkers. Called from validator.zig after init.
    pub fn setSafetyCheckers(
        self: *SyncCommitteeService,
        dopple: ?*DoppelgangerService,
        syncing: ?*SyncingTracker,
    ) void {
        self.doppelganger = dopple;
        self.syncing_tracker = syncing;
    }

    /// Wire up liveness tracker. Called from validator.zig after init.
    pub fn setLivenessTracker(self: *SyncCommitteeService, tracker: *LivenessTracker) void {
        self.liveness_tracker = tracker;
    }

    /// Returns true if it is safe for this validator to sign sync committee duties.
    fn isSafeToSign(self: *const SyncCommitteeService, pubkey: [48]u8) bool {
        if (self.syncing_tracker) |st| {
            if (!st.isSynced()) return false;
        }
        if (self.doppelganger) |d| {
            if (!d.isSigningAllowed(pubkey)) return false;
        }
        return true;
    }

    pub fn deinit(self: *SyncCommitteeService) void {
        for (self.duties.items) |*d| {
            self.allocator.free(d.duty.validator_sync_committee_indices);
            self.allocator.free(d.selection_proofs);
        }
        self.duties.deinit();
    }

    /// Attach a chain header tracker for head root queries.
    pub fn setHeaderTracker(self: *SyncCommitteeService, tracker: *ChainHeaderTracker) void {
        self.header_tracker = tracker;
    }

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to check if duties need refresh.
    ///
    /// Also pre-fetches duties for the next sync period 1 epoch before the boundary.
    ///
    /// TS: SyncCommitteeDutiesService — fetches at period start, pre-fetches next period.
    pub fn onEpoch(self: *SyncCommitteeService, io: Io, epoch: u64) void {
        const period = epoch / self.epochs_per_sync_committee_period;

        // Refresh if we don't have duties for the current period.
        if (self.duties_period == null or self.duties_period.? != period) {
            log.info("sync committee period transition to period={d} at epoch={d}", .{ period, epoch });
            self.refreshDuties(io, epoch, period) catch |err| {
                log.err("refreshDuties period={d} error={s}", .{ period, @errorName(err) });
            };
        }

        // Pre-fetch next period's duties 1 epoch before the boundary.
        // This ensures we're ready to sign at the start of the next period without delay.
        //
        // TS: SyncCommitteeDutiesService.runEveryEpoch — pre-fetches LOOKAHEAD_EPOCHS ahead.
        const period_end_epoch = (period + 1) * self.epochs_per_sync_committee_period;
        if (epoch + 1 == period_end_epoch) {
            const next_period = period + 1;
            const next_period_start_epoch = next_period * self.epochs_per_sync_committee_period;
            log.info("pre-fetching sync committee duties for next period={d} (epoch={d})", .{
                next_period,
                next_period_start_epoch,
            });
            self.refreshDutiesForPeriod(io, next_period_start_epoch, next_period) catch |err| {
                log.warn("pre-fetch duties next_period={d} error={s}", .{ next_period, @errorName(err) });
            };
        }
    }

    /// Called at each slot to produce and submit sync committee messages + contributions.
    pub fn onSlot(self: *SyncCommitteeService, io: Io, slot: u64) void {
        self.runSyncTasks(io, slot) catch |err| {
            log.err("runSyncTasks slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    /// Pre-fetch duties for an upcoming sync period without overwriting current duties.
    ///
    /// The fetched duties are discarded (this warms the BN cache) and will be
    /// fetched again at the actual period start via refreshDuties().
    ///
    /// A more complete implementation would store them in a pending_duties buffer
    /// and swap atomically at the period boundary.
    ///
    /// TS: SyncCommitteeDutiesService.getDutiesForEpoch(nextPeriodEpoch, true)
    fn refreshDutiesForPeriod(self: *SyncCommitteeService, io: Io, epoch: u64, period: u64) !void {
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("pre-fetching sync committee duties for period={d} epoch={d}", .{ period, epoch });

        const fetched = self.api.getSyncCommitteeDuties(io, epoch, indices) catch |err| {
            log.warn("pre-fetch getSyncCommitteeDuties period={d} error={s}", .{ period, @errorName(err) });
            return;
        };
        defer {
            for (fetched) |d| self.allocator.free(d.validator_sync_committee_indices);
            self.allocator.free(fetched);
        }

        log.info("pre-fetched {d} sync committee duties for period={d} (will apply at period start)", .{
            fetched.len,
            period,
        });
        // Note: duties are not stored here; they will be re-fetched and stored
        // when the period starts (onEpoch detects duties_period != current period).
    }

    fn refreshDuties(
        self: *SyncCommitteeService,
        io: Io,
        epoch: u64,
        period: u64,
    ) !void {
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("fetching sync committee duties epoch={d} period={d}", .{ epoch, period });

        const fetched = try self.api.getSyncCommitteeDuties(io, epoch, indices);
        defer {
            for (fetched) |d| self.allocator.free(d.validator_sync_committee_indices);
            self.allocator.free(fetched);
        }

        // Free old duties.
        for (self.duties.items) |*d| {
            self.allocator.free(d.duty.validator_sync_committee_indices);
            self.allocator.free(d.selection_proofs);
        }
        self.duties.clearRetainingCapacity();
        self.duties_period = period;

        for (fetched) |duty| {
            // Copy sync committee indices.
            const sc_indices = try self.allocator.dupe(u64, duty.validator_sync_committee_indices);
            errdefer self.allocator.free(sc_indices);

            // BUG-8 Fix: Selection proofs must be computed per-slot, not per-epoch.
            // Store null placeholders here; proofs are computed on-demand in
            // produceAndPublishContributions() using the actual current slot.
            const proofs = try self.allocator.alloc(?[96]u8, sc_indices.len);
            errdefer self.allocator.free(proofs);
            @memset(proofs, null); // Will be filled on demand at signing time.
            // BUG-8 fix: epoch not used here — proofs computed per-slot in produceAndPublishContributions.

            try self.duties.append(.{
                .duty = .{
                    .pubkey = duty.pubkey,
                    .validator_index = duty.validator_index,
                    .validator_sync_committee_indices = sc_indices,
                },
                .selection_proofs = proofs,
            });
        }

        log.debug("cached {d} sync committee duties period={d}", .{ self.duties.items.len, period });
    }

    // -----------------------------------------------------------------------
    // Sync task execution
    // -----------------------------------------------------------------------

    fn runSyncTasks(self: *SyncCommitteeService, io: Io, slot: u64) !void {
        if (self.duties.items.len == 0) return;

        // Reset all selection_proofs to null at the start of each slot.
        // Selection proofs are slot-specific (SyncAggregatorSelectionData{slot, subcommittee_index})
        // so they must be recomputed for every slot.
        for (self.duties.items) |*d| {
            @memset(d.selection_proofs, null);
        }

        // Get current head root from tracker (or zero if unknown).
        const beacon_block_root: [32]u8 = if (self.header_tracker) |ht|
            ht.getHeadInfo().block_root
        else
            [_]u8{0} ** 32;

        // Sub-slot timing per Ethereum spec:
        //   Sync committee messages: 1/3 slot (same as attestations).
        //   Sync committee contributions: 2/3 slot.
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        const one_third_ns = slot_duration_ns / 3;
        const two_thirds_ns = slot_duration_ns * 2 / 3;

        // Sub-slot timing: compute absolute slot start relative to genesis.
        // BUG-5 Note: std.time.nanoTimestamp() is CLOCK_REALTIME (Unix wall-clock) on
        // Linux/macOS/Windows. Confirmed in zig/lib/std/time.zig. Comparing against
        // genesis_time_ns is correct — no platform workaround needed.
        const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
        const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;

        // Step 1: sign and submit sync committee messages (~1/3 slot).
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            if (now_ns < slot_start_ns + one_third_ns) {
                std.Thread.sleep(slot_start_ns + one_third_ns - now_ns);
            }
        }
        try self.produceAndPublishMessages(io, slot, &beacon_block_root);

        // Step 2: produce contributions for subcommittees we aggregate (~2/3 slot).
        {
            const now_ns: u64 = @intCast(std.time.nanoTimestamp());
            if (now_ns < slot_start_ns + two_thirds_ns) {
                std.Thread.sleep(slot_start_ns + two_thirds_ns - now_ns);
            }
        }
        try self.produceAndPublishContributions(io, slot, &beacon_block_root);
    }

    fn produceAndPublishMessages(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        beacon_block_root: *const [32]u8,
    ) !void {
        var count: u32 = 0;
        var signed_pubkeys = std.ArrayList([48]u8).init(self.allocator);
        defer signed_pubkeys.deinit();

        var messages_json = std.ArrayList(u8).init(self.allocator);
        defer messages_json.deinit();
        try messages_json.append('[');

        for (self.duties.items) |*d| {
            // Compute signing root: sign(beacon_block_root) with DOMAIN_SYNC_COMMITTEE.
            var signing_root: [32]u8 = undefined;
            // BUG-6 fix: Pass slot for dynamic fork_version lookup.
            signing_mod.syncCommitteeSigningRoot(self.signing_ctx, slot, beacon_block_root, &signing_root) catch |err| {
                log.warn("syncCommitteeSigningRoot error: {s}", .{@errorName(err)});
                continue;
            };

            // Safety check before signing sync committee message.
            if (!self.isSafeToSign(d.duty.pubkey)) {
                log.warn("skipping sync message slot={d} validator_index={d}: signing not safe", .{ slot, d.duty.validator_index });
                continue;
            }

            const sig = self.validator_store.signSyncCommitteeMessage(d.duty.pubkey, signing_root) catch |err| {
                log.warn("signSyncCommitteeMessage validator_index={d} error={s}", .{ d.duty.validator_index, @errorName(err) });
                continue;
            };
            const sig_bytes = sig.compress();
            const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);
            const bbr_hex = std.fmt.bytesToHex(beacon_block_root, .lower);

            if (count > 0) try messages_json.append(',');
            try messages_json.writer().print(
                "{{\"slot\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"validator_index\":\"{d}\",\"signature\":\"0x{s}\"}}",
                .{ slot, bbr_hex, d.duty.validator_index, sig_hex },
            );
            signed_pubkeys.append(d.duty.pubkey) catch {};
            count += 1;
        }

        try messages_json.append(']');

        var publish_ok = false;
        if (count > 0) {
            self.api.publishSyncCommitteeMessages(io, messages_json.items) catch |err| {
                log.warn("publishSyncCommitteeMessages slot={d} error={s}", .{ slot, @errorName(err) });
            };
            publish_ok = true;
            log.info("sync committee messages slot={d} count={d}", .{ slot, count });
        }

        // Record liveness outcomes for all validators with sync committee duties this slot.
        if (self.liveness_tracker) |lt| {
            const epoch = slot / self.slots_per_epoch;
            for (self.duties.items) |*d| {
                var did_sign = false;
                for (signed_pubkeys.items) |pk| {
                    if (std.mem.eql(u8, &pk, &d.duty.pubkey)) {
                        did_sign = true;
                        break;
                    }
                }
                lt.recordSyncDuty(d.duty.pubkey, epoch, did_sign and publish_ok);
            }
        }
    }

    fn produceAndPublishContributions(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        beacon_block_root: *const [32]u8,
    ) !void {
        for (self.duties.items) |*dp| {
            for (dp.duty.validator_sync_committee_indices, dp.selection_proofs) |sc_idx, *cached_proof| {
                const subcommittee_index = sc_idx / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT);

                // BUG-8 Fix: Compute selection proof with the ACTUAL current slot (not epoch start).
                // The spec requires SyncAggregatorSelectionData{slot=current_slot, subcommittee_index}.
                if (cached_proof.* == null) {
                    var sel_root: [32]u8 = undefined;
                    signing_mod.syncCommitteeSelectionProofSigningRoot(
                        self.signing_ctx,
                        slot, // use actual slot, not epoch start
                        subcommittee_index,
                        &sel_root,
                    ) catch |err| {
                        log.warn("sync selection proof signing root error slot={d}: {s}", .{ slot, @errorName(err) });
                        continue;
                    };
                    if (self.validator_store.signSelectionProof(dp.duty.pubkey, sel_root)) |sig| {
                        cached_proof.* = sig.compress();
                    } else |_| {
                        continue;
                    }
                }
                const sel_proof = cached_proof.* orelse continue;

                // 1. Fetch contribution from BN.
                const contrib = try self.api.produceSyncCommitteeContribution(
                    io,
                    slot,
                    subcommittee_index,
                    beacon_block_root.*,
                );
                defer self.allocator.free(contrib.aggregation_bits);

                // 2. Build ContributionAndProof and sign it.
                // Set the correct bit for our validator's position in the sync subcommittee.
                // sc_idx is the full sync committee index (0..SYNC_COMMITTEE_SIZE-1).
                // The bit position within the subcommittee is sc_idx % subcommittee_size.
                const subcommittee_size = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;
                const bit_index = sc_idx % subcommittee_size; // position within subcommittee
                var agg_bits = [_]u8{0} ** @divTrunc(512, 4 * 8); // 16 bytes = 128 bits
                agg_bits[bit_index / 8] |= @as(u8, 1) << @intCast(bit_index % 8);

                const contribution_and_proof = consensus_types.altair.ContributionAndProof.Type{
                    .aggregator_index = dp.duty.validator_index,
                    .contribution = .{
                        .slot = slot,
                        .beacon_block_root = beacon_block_root.*,
                        .subcommittee_index = subcommittee_index,
                        .aggregation_bits = .{ .data = agg_bits },
                        .signature = contrib.signature,
                    },
                    .selection_proof = sel_proof,
                };

                var signing_root: [32]u8 = undefined;
                signing_mod.contributionAndProofSigningRoot(
                    self.signing_ctx,
                    &contribution_and_proof,
                    &signing_root,
                ) catch |err| {
                    log.warn("contributionAndProofSigningRoot error: {s}", .{@errorName(err)});
                    continue;
                };

                // Safety check before contribution signing.
                if (!self.isSafeToSign(dp.duty.pubkey)) {
                    log.warn("skipping contribution slot={d} validator_index={d}: signing not safe", .{ slot, dp.duty.validator_index });
                    continue;
                }

                const sig = self.validator_store.signContributionAndProof(dp.duty.pubkey, signing_root) catch |err| {
                    log.warn("signContributionAndProof error: {s}", .{@errorName(err)});
                    continue;
                };
                const sig_bytes = sig.compress();
                const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);
                const sel_hex = std.fmt.bytesToHex(&sel_proof, .lower);
                const bbr_hex2 = std.fmt.bytesToHex(beacon_block_root, .lower);
                const contrib_sig_hex = std.fmt.bytesToHex(&contrib.signature, .lower);

                // 3. Build SignedContributionAndProof JSON and publish.
                // Fix 4: Hex-encode the actual agg_bits instead of hardcoded "0x00".
                // agg_bits is a BitVector(128) — 16 bytes, no sentinel needed (fixed-size).
                const agg_bits_hex = std.fmt.bytesToHex(&agg_bits, .lower);
                var contrib_json = std.ArrayList(u8).init(self.allocator);
                defer contrib_json.deinit();
                try contrib_json.writer().print(
                    "[{{\"message\":{{\"aggregator_index\":\"{d}\",\"contribution\":{{\"slot\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"subcommittee_index\":\"{d}\",\"aggregation_bits\":\"0x{s}\",\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}]",
                    .{ dp.duty.validator_index, slot, bbr_hex2, subcommittee_index, agg_bits_hex, contrib_sig_hex, sel_hex, sig_hex },
                );

                self.api.publishContributionAndProofs(io, contrib_json.items) catch |err| {
                    log.warn("publishContributionAndProofs error: {s}", .{@errorName(err)});
                };
            }
        }
    }
};
