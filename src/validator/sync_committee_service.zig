//! Sync committee service for the Validator Client.
//!
//! Tracks sync committee duties per sync period and submits sync committee
//! messages and contributions at the correct time within each slot.
//!
//! TS equivalent: packages/validator/src/services/syncCommittee.ts (SyncCommitteeService)
//!               + packages/validator/src/services/syncCommitteeDuties.ts
//!
//! Only active post-Altair (bellatrix, capella, deneb, electra, …).
//!
//! Timing:
//!   - Sync message:      at getSyncMessageDueMs (~0 or 1/3 slot, BN-dependent).
//!   - Sync contribution: at ~2/3 slot (SYNC_CONTRIBUTION_DUE_BPS).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const SyncCommitteeDuty = types.SyncCommitteeDuty;
const SyncCommitteeDutyWithProofs = types.SyncCommitteeDutyWithProofs;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;

const log = std.log.scoped(.sync_committee_service);

/// SYNC_COMMITTEE_SIZE = 512 (mainnet). One period spans EPOCHS_PER_SYNC_COMMITTEE_PERIOD epochs.
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

// ---------------------------------------------------------------------------
// SyncCommitteeService
// ---------------------------------------------------------------------------

pub const SyncCommitteeService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
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
        slots_per_epoch: u64,
        epochs_per_sync_committee_period: u64,
    ) SyncCommitteeService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
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

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to check if we need to refresh duties.
    ///
    /// TS: SyncCommitteeDutiesService (runEveryEpoch)
    pub fn onEpoch(self: *SyncCommitteeService, io: Io, epoch: u64) void {
        const period = epoch / self.epochs_per_sync_committee_period;
        if (self.duties_period != period) {
            self.refreshDuties(io, epoch, period) catch |err| {
                log.err("refreshDuties period={d} error={s}", .{ period, @errorName(err) });
            };
        }
    }

    /// Called at each slot to produce and submit sync committee messages + contributions.
    ///
    /// TS: SyncCommitteeService.runSyncCommitteeTasks (clock.runEverySlot)
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
        defer self.allocator.free(fetched);

        // Free old duties.
        for (self.duties.items) |*d| {
            self.allocator.free(d.duty.validator_sync_committee_indices);
            self.allocator.free(d.selection_proofs);
        }
        self.duties.clearRetainingCapacity();
        self.duties_period = period;

        for (fetched) |duty| {
            // Copy sync committee indices.
            const indices_copy = try self.allocator.dupe(u64, duty.validator_sync_committee_indices);
            // Allocate selection proofs (one per subcommittee index the validator sits in).
            const proofs = try self.allocator.alloc(?[96]u8, indices_copy.len);
            @memset(proofs, null);

            try self.duties.append(.{
                .duty = .{
                    .pubkey = duty.pubkey,
                    .validator_index = duty.validator_index,
                    .validator_sync_committee_indices = indices_copy,
                },
                .selection_proofs = proofs,
            });
        }

        // Compute selection proofs for each subcommittee slot.
        try self.computeSelectionProofs();

        log.debug("cached {d} sync committee duties period={d}", .{ fetched.len, period });
    }

    fn computeSelectionProofs(self: *SyncCommitteeService) !void {
        // For each duty/subcommittee index: sign slot to determine if aggregator.
        // TODO: implement when signing root computation is wired up.
        for (self.duties.items) |*d| {
            _ = d;
        }
    }

    // -----------------------------------------------------------------------
    // Sync task execution
    // -----------------------------------------------------------------------

    fn runSyncTasks(self: *SyncCommitteeService, io: Io, slot: u64) !void {
        if (self.duties.items.len == 0) return;

        // --- Step 1: sign and submit sync committee messages (at ~1/3 slot) ---
        try self.produceAndPublishMessages(io, slot);

        // --- Step 2: produce contributions for subcommittees we aggregate (at ~2/3 slot) ---
        try self.produceAndPublishContributions(io, slot);
    }

    fn produceAndPublishMessages(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
    ) !void {
        // The beacon block root to attest to is the current head.
        // TODO: fetch from chain header tracker.
        const beacon_block_root: [32]u8 = std.mem.zeroes([32]u8); // stub

        for (self.duties.items) |*d| {
            // TODO: compute signing root for SyncCommitteeMessage.
            const signing_root: [32]u8 = std.mem.zeroes([32]u8); // stub
            const sig = try self.validator_store.signSyncCommitteeMessage(d.duty.pubkey, signing_root);
            _ = sig;
            _ = beacon_block_root;
            // TODO: encode and collect SyncCommitteeMessage for batch submit.
        }

        // TODO: batch-submit to api.publishSyncCommitteeMessages()
        log.info("published sync committee messages slot={d} count={d}", .{ slot, self.duties.items.len });
    }

    fn produceAndPublishContributions(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
    ) !void {
        // TODO: fetch current head root.
        const beacon_block_root: [32]u8 = std.mem.zeroes([32]u8); // stub

        for (self.duties.items) |*dp| {
            for (dp.duty.validator_sync_committee_indices, dp.selection_proofs) |sc_idx, maybe_proof| {
                const sel_proof = maybe_proof orelse continue;
                const subcommittee_index = sc_idx / (512 / SYNC_COMMITTEE_SUBNET_COUNT); // subnet

                // 1. Fetch contribution.
                const contrib = try self.api.produceSyncCommitteeContribution(
                    io,
                    slot,
                    subcommittee_index,
                    beacon_block_root,
                );

                // 2. Sign ContributionAndProof.
                const signing_root: [32]u8 = std.mem.zeroes([32]u8); // stub
                const sig = try self.validator_store.signContributionAndProof(dp.duty.pubkey, signing_root);
                _ = sig;
                _ = sel_proof;
                _ = contrib;

                // 3. Publish.
                // TODO: encode and submit SignedContributionAndProof.
                try self.api.publishContributionAndProofs(io, ""); // stub
            }
        }
    }
};
