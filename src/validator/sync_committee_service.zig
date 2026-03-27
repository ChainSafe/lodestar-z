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

    /// Duties keyed by validator index (valid for the current sync period).
    duties: std.ArrayList(SyncCommitteeDutyWithProofs),
    /// Sync period for which duties are cached.
    duties_period: ?u64,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        slots_per_epoch: u64,
        epochs_per_sync_committee_period: u64,
    ) SyncCommitteeService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .header_tracker = null,
            .signing_ctx = signing_ctx,
            .slots_per_epoch = slots_per_epoch,
            .epochs_per_sync_committee_period = epochs_per_sync_committee_period,
            .duties = std.ArrayList(SyncCommitteeDutyWithProofs).init(allocator),
            .duties_period = null,
        };
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
    pub fn onEpoch(self: *SyncCommitteeService, io: Io, epoch: u64) void {
        const period = epoch / self.epochs_per_sync_committee_period;
        if (self.duties_period == null or self.duties_period.? != period) {
            self.refreshDuties(io, epoch, period) catch |err| {
                log.err("refreshDuties period={d} error={s}", .{ period, @errorName(err) });
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

            // Allocate and compute selection proofs for each subcommittee slot.
            const proofs = try self.allocator.alloc(?[96]u8, sc_indices.len);
            errdefer self.allocator.free(proofs);

            for (sc_indices, proofs, 0..) |sc_idx, *proof, _| {
                const subcommittee_index = sc_idx / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT);
                // Selection proof: sign(SyncAggregatorSelectionData{slot, subcommittee_index}).
                // We use epoch start slot as representative; full impl uses the actual slot.
                const slot = epoch * self.slots_per_epoch;
                var sel_root: [32]u8 = undefined;
                signing_mod.syncCommitteeSelectionProofSigningRoot(
                    self.signing_ctx,
                    slot,
                    subcommittee_index,
                    &sel_root,
                ) catch |err| {
                    log.warn("sync selection proof signing root error: {s}", .{@errorName(err)});
                    proof.* = null;
                    continue;
                };

                if (self.validator_store.signSelectionProof(duty.pubkey, sel_root)) |sig| {
                    proof.* = sig.compress();
                } else |_| {
                    proof.* = null;
                }
            }

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

        // Get current head root from tracker (or zero if unknown).
        const beacon_block_root: [32]u8 = if (self.header_tracker) |ht|
            ht.getHeadInfo().block_root
        else
            [_]u8{0} ** 32;

        // Step 1: sign and submit sync committee messages (~1/3 slot).
        try self.produceAndPublishMessages(io, slot, &beacon_block_root);

        // Step 2: produce contributions for subcommittees we aggregate (~2/3 slot).
        try self.produceAndPublishContributions(io, slot, &beacon_block_root);
    }

    fn produceAndPublishMessages(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        beacon_block_root: *const [32]u8,
    ) !void {
        var count: u32 = 0;

        for (self.duties.items) |*d| {
            // Compute signing root: sign(beacon_block_root) with DOMAIN_SYNC_COMMITTEE.
            var signing_root: [32]u8 = undefined;
            signing_mod.syncCommitteeSigningRoot(self.signing_ctx, beacon_block_root, &signing_root) catch |err| {
                log.warn("syncCommitteeSigningRoot error: {s}", .{@errorName(err)});
                continue;
            };

            const sig = self.validator_store.signSyncCommitteeMessage(d.duty.pubkey, signing_root) catch |err| {
                log.warn("signSyncCommitteeMessage validator_index={d} error={s}", .{ d.duty.validator_index, @errorName(err) });
                continue;
            };
            _ = sig;
            count += 1;
            // TODO: build SyncCommitteeMessage JSON and collect for batch submit.
        }

        if (count > 0) {
            // TODO: build JSON array and call api.publishSyncCommitteeMessages().
            log.info("sync committee messages slot={d} count={d}", .{ slot, count });
        }
    }

    fn produceAndPublishContributions(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        beacon_block_root: *const [32]u8,
    ) !void {
        for (self.duties.items) |*dp| {
            for (dp.duty.validator_sync_committee_indices, dp.selection_proofs) |sc_idx, maybe_proof| {
                const sel_proof = maybe_proof orelse continue;
                _ = sel_proof;

                const subcommittee_index = sc_idx / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT);

                // 1. Fetch contribution from BN.
                const contrib = try self.api.produceSyncCommitteeContribution(
                    io,
                    slot,
                    subcommittee_index,
                    beacon_block_root.*,
                );
                defer self.allocator.free(contrib.aggregation_bits);

                // 2. Build ContributionAndProof and sign it.
                const contribution_and_proof = consensus_types.altair.ContributionAndProof.Type{
                    .aggregator_index = dp.duty.validator_index,
                    .contribution = .{
                        .slot = slot,
                        .beacon_block_root = beacon_block_root.*,
                        .subcommittee_index = subcommittee_index,
                        // aggregation_bits: BitVector needs actual bits — stub zeros.
                        .aggregation_bits = .{ .data = [_]u8{0} ** @divTrunc(512, 4 * 8) },
                        .signature = contrib.signature,
                    },
                    .selection_proof = maybe_proof orelse [_]u8{0} ** 96,
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

                const sig = self.validator_store.signContributionAndProof(dp.duty.pubkey, signing_root) catch |err| {
                    log.warn("signContributionAndProof error: {s}", .{@errorName(err)});
                    continue;
                };
                _ = sig;

                // 3. Publish (stub JSON — full impl would SSZ/JSON encode SignedContributionAndProof).
                self.api.publishContributionAndProofs(io, "[]") catch |err| {
                    log.warn("publishContributionAndProofs error: {s}", .{@errorName(err)});
                };
            }
        }
    }
};
