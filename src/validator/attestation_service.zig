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
const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const BeaconCommitteeSubscription = api_client.BeaconCommitteeSubscription;
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
const liveness_mod = @import("liveness.zig");
const LivenessTracker = liveness_mod.LivenessTracker;
const time = @import("time.zig");
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

const log = std.log.scoped(.attestation_service);

/// Target aggregators per committee (from consensus spec).
const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
/// Keep request bodies under typical 1 MiB HTTP limits when pushing beacon
/// committee subscriptions for large validator sets.
const SUBSCRIPTIONS_PER_REQUEST: usize = 8_738;

fn isAttestationAggregator(selection_proof: [96]u8, committee_length: u64) bool {
    const modulo = @max(@as(u64, 1), committee_length / TARGET_AGGREGATORS_PER_COMMITTEE);
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var sel_hash: [32]u8 = undefined;
    Sha256.hash(&selection_proof, &sel_hash, .{});
    const hash_val = std.mem.readInt(u64, sel_hash[0..8], .little);
    return hash_val % modulo == 0;
}

// ---------------------------------------------------------------------------
// AttestationService
// ---------------------------------------------------------------------------

pub const AttestationService = struct {
    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    signing_ctx: SigningContext,
    seconds_per_slot: u64,
    /// Genesis time (Unix seconds) — for correct sub-slot timing (BUG-5 fix).
    genesis_time_unix_secs: u64,
    /// Electra fork epoch — attestation format changes at this epoch (EIP-7549).
    /// Set to maxInt(u64) if Electra is not scheduled.
    electra_fork_epoch: u64,
    /// Gloas fork epoch — attestation and aggregate timing changes at/after this fork.
    gloas_fork_epoch: u64,
    attestation_due_ms: u64,
    attestation_due_ms_gloas: u64,
    aggregate_due_ms: u64,
    aggregate_due_ms_gloas: u64,
    distributed_aggregation_selection: bool,

    /// Protects duty caches and dependent-root invalidation state shared across
    /// the slot clock, epoch clock, and chain-head SSE callback paths.
    cache_mutex: std.Io.Mutex,
    /// Duties indexed by slot (rolling window across epochs).
    duties: std.array_list.Managed(AttesterDutyWithProof),
    /// Epoch for which duties are currently cached.
    duties_epoch: ?u64,
    /// Decision root that keyed the currently cached epoch duties.
    current_duties_dependent_root: ?[32]u8,
    /// Pre-fetched duties for next epoch.
    next_duties: std.array_list.Managed(AttesterDutyWithProof),
    next_duties_epoch: ?u64,
    /// Decision root that keyed the prefetched next-epoch duties.
    next_duties_dependent_root: ?[32]u8,
    /// Reorg-updated decision root for next epoch seen before the boundary.
    pending_next_duties_dependent_root: ?[32]u8,
    /// Optional chain header tracker for reorg detection.
    header_tracker: ?*ChainHeaderTracker,
    /// Last known previous_duty_dependent_root — used to detect reorgs.
    /// When this changes, attester duties for the current epoch must be re-fetched.
    ///
    /// TS: AttestationDutiesService.currentDependentRoot
    last_previous_dependent_root: [32]u8,
    /// Last known current_duty_dependent_root — used to detect reorgs.
    last_current_dependent_root: [32]u8,
    /// Monotonic revision for current-epoch duties. Bumped whenever a head
    /// change invalidates current duties so in-flight refreshes can be dropped.
    current_duties_revision: u64,
    /// Monotonic revision for next-epoch duties. Bumped whenever a head change
    /// invalidates next-epoch duties so stale prefetches do not resurrect them.
    next_duties_revision: u64,
    /// Doppelganger service reference (optional).
    doppelganger: ?*DoppelgangerService,
    /// Syncing tracker reference (optional).
    syncing_tracker: ?*SyncingTracker,
    /// Liveness tracker — records per-validator duty outcomes.
    liveness_tracker: ?*LivenessTracker,
    metrics: *ValidatorMetrics,

    pub fn init(
        io: Io,
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        seconds_per_slot: u64,
        genesis_time_unix_secs: u64,
        electra_fork_epoch: u64,
        gloas_fork_epoch: u64,
        attestation_due_ms: u64,
        attestation_due_ms_gloas: u64,
        aggregate_due_ms: u64,
        aggregate_due_ms_gloas: u64,
        distributed_aggregation_selection: bool,
        metrics: *ValidatorMetrics,
    ) AttestationService {
        return .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
            .seconds_per_slot = seconds_per_slot,
            .genesis_time_unix_secs = genesis_time_unix_secs,
            .electra_fork_epoch = electra_fork_epoch,
            .gloas_fork_epoch = gloas_fork_epoch,
            .attestation_due_ms = attestation_due_ms,
            .attestation_due_ms_gloas = attestation_due_ms_gloas,
            .aggregate_due_ms = aggregate_due_ms,
            .aggregate_due_ms_gloas = aggregate_due_ms_gloas,
            .distributed_aggregation_selection = distributed_aggregation_selection,
            .cache_mutex = .init,
            .duties = std.array_list.Managed(AttesterDutyWithProof).init(allocator),
            .duties_epoch = null,
            .current_duties_dependent_root = null,
            .next_duties = std.array_list.Managed(AttesterDutyWithProof).init(allocator),
            .next_duties_epoch = null,
            .next_duties_dependent_root = null,
            .pending_next_duties_dependent_root = null,
            .header_tracker = null,
            .last_previous_dependent_root = [_]u8{0} ** 32,
            .last_current_dependent_root = [_]u8{0} ** 32,
            .current_duties_revision = 0,
            .next_duties_revision = 0,
            .doppelganger = null,
            .syncing_tracker = null,
            .liveness_tracker = null,
            .metrics = metrics,
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

    /// Wire up liveness tracker. Called from validator.zig after init.
    pub fn setLivenessTracker(self: *AttestationService, tracker: *LivenessTracker) void {
        self.liveness_tracker = tracker;
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
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
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

        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        const prev_changed = !std.mem.eql(u8, &self.last_previous_dependent_root, &info.previous_duty_dependent_root);
        const curr_changed = !std.mem.eql(u8, &self.last_current_dependent_root, &info.current_duty_dependent_root);

        if (!prev_changed and !curr_changed) return;

        const current_epoch = info.slot / self.signing_ctx.slots_per_epoch;
        self.last_previous_dependent_root = info.previous_duty_dependent_root;
        self.last_current_dependent_root = info.current_duty_dependent_root;

        // Head callbacks are synchronous, so do not do HTTP work here. Instead,
        // invalidate whichever epoch cache depends on the changed root so the
        // next slot/epoch boundary refreshes the affected duties before use.
        if (prev_changed and self.currentEpochDutiesNeedRefreshLocked(current_epoch, info.previous_duty_dependent_root)) {
            log.warn(
                "attester duties invalidated for current epoch={d} at slot={d}: previous dependent root changed",
                .{ current_epoch, info.slot },
            );
            self.metrics.incrAttesterDutyReorg();
            self.current_duties_revision +|= 1;
            self.duties_epoch = null;
            self.current_duties_dependent_root = null;
        }

        if (curr_changed) {
            const next_epoch = current_epoch + 1;
            self.next_duties_revision +|= 1;
            if (self.nextEpochDutiesNeedRefreshLocked(next_epoch, info.current_duty_dependent_root)) {
                log.warn(
                    "attester duties marked stale for next epoch={d} at slot={d}: current dependent root changed",
                    .{ next_epoch, info.slot },
                );
                self.metrics.incrAttesterDutyReorg();
                self.pending_next_duties_dependent_root = info.current_duty_dependent_root;
            }
        }

        self.updateDutyMetricsLocked();
    }

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to refresh attester duties.
    pub fn onEpoch(self: *AttestationService, io: Io, epoch: u64) void {
        if (self.activatePrefetchedEpoch(epoch)) |subscriptions| {
            defer self.allocator.free(subscriptions);
            log.debug("swapped pre-fetched attester duties into epoch={d}", .{epoch});
            self.publishBeaconCommitteeSubscriptions(io, subscriptions);
            self.prefetchNextEpochDuties(io, epoch + 1);
            return;
        }

        self.ensureCurrentEpochDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
        // Pre-fetch next epoch duties.
        self.prefetchNextEpochDuties(io, epoch + 1);
    }

    /// Called at each slot to produce and publish attestations + aggregates.
    pub fn onSlot(self: *AttestationService, io: Io, slot: u64) void {
        const epoch = slot / self.signing_ctx.slots_per_epoch;
        if (!self.hasCurrentEpochDuties(epoch)) {
            self.ensureCurrentEpochDuties(io, epoch) catch |err| {
                log.warn("refreshDuties slot={d} epoch={d} error={s}", .{ slot, epoch, @errorName(err) });
                return;
            };
        }

        self.runAttestationTasks(io, slot) catch |err| {
            log.err("runAttestationTasks slot={d} error={s}", .{ slot, @errorName(err) });
        };

        self.maybePrefetchNextEpochDuties(io, slot);
    }

    /// Remove any cached attester duties for the given validator pubkey.
    ///
    /// Lodestar drops duties immediately on validator removal; do the same here so
    /// stale cached duties do not survive until the next epoch refresh.
    pub fn removeDutiesForKey(self: *AttestationService, pubkey: [48]u8) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        var i: usize = 0;
        while (i < self.duties.items.len) {
            if (std.mem.eql(u8, &self.duties.items[i].duty.pubkey, &pubkey)) {
                _ = self.duties.swapRemove(i);
            } else {
                i += 1;
            }
        }

        i = 0;
        while (i < self.next_duties.items.len) {
            if (std.mem.eql(u8, &self.next_duties.items[i].duty.pubkey, &pubkey)) {
                _ = self.next_duties.swapRemove(i);
            } else {
                i += 1;
            }
        }

        self.updateDutyMetricsLocked();
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    fn ensureCurrentEpochDuties(self: *AttestationService, io: Io, epoch: u64) !void {
        if (!self.hasCurrentEpochDuties(epoch)) {
            try self.refreshDuties(io, epoch);
        }
    }

    fn refreshDuties(self: *AttestationService, io: Io, epoch: u64) !void {
        const revision = self.currentDutiesRevision();
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("fetching attester duties epoch={d} validators={d}", .{ epoch, indices.len });

        const fetched = try self.api.getAttesterDuties(io, epoch, indices);
        defer fetched.deinit(self.allocator);

        var fresh_duties = try self.buildDutyList(io, fetched.duties);
        errdefer fresh_duties.deinit();
        try self.resolveDistributedAggregationSelections(io, fresh_duties.items);

        const subscriptions = try self.buildBeaconCommitteeSubscriptions(fresh_duties.items);
        errdefer self.allocator.free(subscriptions);

        if (!self.tryInstallCurrentDuties(epoch, revision, fetched.dependent_root, &fresh_duties)) {
            log.debug("discarded stale attester duty refresh epoch={d} after dependent-root invalidation", .{epoch});
            return;
        }

        defer self.allocator.free(subscriptions);
        self.publishBeaconCommitteeSubscriptions(io, subscriptions);
        log.debug("cached {d} attester duties epoch={d}", .{ fetched.duties.len, epoch });
    }

    /// Pre-fetch attester duties for next epoch to avoid latency at epoch boundaries.
    ///
    /// TS: AttestationDutiesService fetches N+1 at end of epoch N.
    fn prefetchNextEpochDuties(self: *AttestationService, io: Io, next_epoch: u64) void {
        const revision = self.nextDutiesRevision();
        const indices = self.validator_store.allIndices(self.allocator) catch return;
        defer self.allocator.free(indices);
        if (indices.len == 0) return;

        log.debug("pre-fetching attester duties epoch={d}", .{next_epoch});
        const fetched = self.api.getAttesterDuties(io, next_epoch, indices) catch |err| {
            log.warn("prefetch attester duties epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        defer fetched.deinit(self.allocator);

        var fresh_duties = self.buildDutyList(io, fetched.duties) catch |err| {
            log.warn("prefetch duty proof build epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        errdefer fresh_duties.deinit();
        self.resolveDistributedAggregationSelections(io, fresh_duties.items) catch |err| {
            log.warn("prefetch distributed aggregation selection epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };

        const subscriptions = self.buildBeaconCommitteeSubscriptions(fresh_duties.items) catch |err| {
            log.warn("prefetch subscription build epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        errdefer self.allocator.free(subscriptions);

        if (!self.tryInstallNextDuties(next_epoch, revision, fetched.dependent_root, &fresh_duties)) {
            log.debug("discarded stale next-epoch duty prefetch epoch={d} after dependent-root invalidation", .{next_epoch});
            return;
        }

        defer self.allocator.free(subscriptions);
        self.publishBeaconCommitteeSubscriptions(io, subscriptions);
        log.debug("pre-fetched {d} attester duties epoch={d}", .{ fetched.duties.len, next_epoch });
    }

    fn maybePrefetchNextEpochDuties(self: *AttestationService, io: Io, slot: u64) void {
        const epoch = slot / self.signing_ctx.slots_per_epoch;
        const next_epoch = epoch + 1;
        if (!self.nextEpochDutiesNeedRefresh(next_epoch)) return;

        if (self.isLastSlotOfEpoch(slot)) {
            const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
            const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
            const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;
            const refresh_due_ns = slot_start_ns + self.attestationDueMs(slot) * std.time.ns_per_ms;
            const now_ns = time.realNanoseconds(io);
            if (now_ns < refresh_due_ns) {
                io.sleep(.{ .nanoseconds = @intCast(refresh_due_ns - now_ns) }, .real) catch |err| {
                    log.warn("next-epoch attester duty prefetch wait slot={d} error={s}", .{ slot, @errorName(err) });
                    return;
                };
            }
        }

        if (self.nextEpochDutiesNeedRefresh(next_epoch)) {
            self.prefetchNextEpochDuties(io, next_epoch);
        }
    }

    fn publishBeaconCommitteeSubscriptions(
        self: *AttestationService,
        io: Io,
        subscriptions: []const BeaconCommitteeSubscription,
    ) void {
        if (subscriptions.len == 0) return;

        var start: usize = 0;
        while (start < subscriptions.len) {
            const end = @min(start + SUBSCRIPTIONS_PER_REQUEST, subscriptions.len);
            self.api.prepareBeaconCommitteeSubnets(io, subscriptions[start..end]) catch |err| {
                log.warn("prepareBeaconCommitteeSubnets failed batch_start={d} batch_len={d}: {s}", .{
                    start,
                    end - start,
                    @errorName(err),
                });
                return;
            };
            start = end;
        }
    }

    // -----------------------------------------------------------------------
    // Attestation production
    // -----------------------------------------------------------------------

    fn runAttestationTasks(self: *AttestationService, io: Io, slot: u64) !void {
        var duties_at_slot = try self.snapshotCurrentDutiesForSlot(slot);
        defer self.allocator.free(duties_at_slot);
        if (duties_at_slot.len == 0) return;

        // Sub-slot timing: compute absolute slot start relative to genesis.
        // slot_start_ns = (genesis_time_unix_secs + slot * seconds_per_slot) * ns_per_s
        //
        // Ethereum slot timing is based on Unix wall-clock time, so this uses
        // `std.Io.Clock.real` through the shared validator time helper.
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
        const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;
        const attestation_due_ns = slot_start_ns + self.attestationDueMs(slot) * std.time.ns_per_ms;
        if (self.header_tracker) |tracker| {
            tracker.waitForHeadSlotOrDeadline(slot, attestation_due_ns);
        }
        const now_ns = time.realNanoseconds(io);
        if (now_ns < attestation_due_ns) {
            try io.sleep(.{ .nanoseconds = @intCast(attestation_due_ns - now_ns) }, .real);
        }

        const epoch = slot / self.signing_ctx.slots_per_epoch;
        try self.ensureCurrentEpochDuties(io, epoch);
        duties_at_slot = try self.replaceDutySnapshot(duties_at_slot, slot);
        if (duties_at_slot.len == 0) return;
        const duties_revision = self.currentDutiesRevision();

        // Step 1: produce and publish attestations (block arrival or attestation due time, whichever first).
        const att_data_root = try self.produceAndPublishAttestations(io, slot, duties_at_slot);

        // Step 2 runs at the aggregate due time for the active fork.
        const aggregate_due_ns = slot_start_ns + self.aggregateDueMs(slot) * std.time.ns_per_ms;
        const aggregate_now_ns = time.realNanoseconds(io);
        if (aggregate_now_ns < aggregate_due_ns) {
            try io.sleep(.{ .nanoseconds = @intCast(aggregate_due_ns - aggregate_now_ns) }, .real);
        }

        if (self.currentDutiesRevision() != duties_revision or !self.hasCurrentEpochDuties(epoch)) {
            log.warn("skipping aggregate production slot={d}: attester duties changed after attestation publication", .{slot});
            return;
        }

        // Step 2: produce and publish aggregates at the configured aggregate due time.
        try self.produceAndPublishAggregates(io, slot, duties_at_slot, att_data_root);
    }

    fn attestationDueMs(self: *const AttestationService, slot: u64) u64 {
        const epoch = slot / self.signing_ctx.slots_per_epoch;
        return if (epoch >= self.gloas_fork_epoch)
            self.attestation_due_ms_gloas
        else
            self.attestation_due_ms;
    }

    fn aggregateDueMs(self: *const AttestationService, slot: u64) u64 {
        const epoch = slot / self.signing_ctx.slots_per_epoch;
        return if (epoch >= self.gloas_fork_epoch)
            self.aggregate_due_ms_gloas
        else
            self.aggregate_due_ms;
    }

    fn buildDutyList(
        self: *AttestationService,
        io: Io,
        fetched: []const AttesterDuty,
    ) !std.array_list.Managed(AttesterDutyWithProof) {
        var duties = std.array_list.Managed(AttesterDutyWithProof).init(self.allocator);
        errdefer duties.deinit();

        for (fetched) |duty| {
            var sel_proof: ?[96]u8 = null;
            var sel_root: [32]u8 = undefined;
            signing_mod.attestationSelectionProofSigningRoot(self.signing_ctx, duty.slot, &sel_root) catch |err| {
                log.warn("selection proof signing root error: {s}", .{@errorName(err)});
                try duties.append(.{
                    .duty = duty,
                    .selection_proof = null,
                });
                continue;
            };
            if (self.validator_store.signSelectionProof(io, duty.pubkey, sel_root, .AGGREGATION_SLOT)) |sig| {
                const proof = sig.compress();
                if (self.distributed_aggregation_selection) {
                    try duties.append(.{
                        .duty = duty,
                        .selection_proof = null,
                        .partial_selection_proof = proof,
                    });
                    continue;
                }

                if (isAttestationAggregator(proof, duty.committee_length)) {
                    sel_proof = proof;
                }
            } else |_| {}

            try duties.append(.{
                .duty = duty,
                .selection_proof = sel_proof,
                .partial_selection_proof = null,
            });
        }

        return duties;
    }

    fn resolveDistributedAggregationSelections(
        self: *AttestationService,
        io: Io,
        duties: []AttesterDutyWithProof,
    ) !void {
        if (!self.distributed_aggregation_selection or duties.len == 0) return;

        var selections = std.array_list.Managed(api_client.BeaconCommitteeSelection).init(self.allocator);
        defer selections.deinit();

        for (duties) |duty| {
            const partial = duty.partial_selection_proof orelse continue;
            try selections.append(.{
                .validator_index = duty.duty.validator_index,
                .slot = duty.duty.slot,
                .selection_proof = partial,
            });
        }

        if (selections.items.len == 0) return;

        const combined = try self.api.submitBeaconCommitteeSelections(io, selections.items);
        defer self.allocator.free(combined);

        for (duties) |*duty| {
            duty.selection_proof = null;
            if (duty.partial_selection_proof == null) continue;

            for (combined) |selection| {
                if (selection.validator_index != duty.duty.validator_index) continue;
                if (selection.slot != duty.duty.slot) continue;
                if (isAttestationAggregator(selection.selection_proof, duty.duty.committee_length)) {
                    duty.selection_proof = selection.selection_proof;
                }
                break;
            }
        }
    }

    fn buildBeaconCommitteeSubscriptions(
        self: *AttestationService,
        duties: []const AttesterDutyWithProof,
    ) ![]BeaconCommitteeSubscription {
        const subscriptions = try self.allocator.alloc(BeaconCommitteeSubscription, duties.len);
        for (duties, subscriptions) |duty, *subscription| {
            subscription.* = .{
                .validator_index = duty.duty.validator_index,
                .committee_index = duty.duty.committee_index,
                .committees_at_slot = duty.duty.committees_at_slot,
                .slot = duty.duty.slot,
                .is_aggregator = duty.selection_proof != null,
            };
        }
        return subscriptions;
    }

    fn snapshotCurrentDutiesForSlot(self: *AttestationService, slot: u64) ![]AttesterDutyWithProof {
        const epoch = slot / self.signing_ctx.slots_per_epoch;

        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.duties_epoch == null or self.duties_epoch.? != epoch) {
            return self.allocator.alloc(AttesterDutyWithProof, 0);
        }

        var count: usize = 0;
        for (self.duties.items) |duty| {
            if (duty.duty.slot == slot) count += 1;
        }

        const snapshot = try self.allocator.alloc(AttesterDutyWithProof, count);
        var index: usize = 0;
        for (self.duties.items) |duty| {
            if (duty.duty.slot != slot) continue;
            snapshot[index] = duty;
            index += 1;
        }
        return snapshot;
    }

    fn replaceDutySnapshot(
        self: *AttestationService,
        old_snapshot: []AttesterDutyWithProof,
        slot: u64,
    ) ![]AttesterDutyWithProof {
        self.allocator.free(old_snapshot);
        return self.snapshotCurrentDutiesForSlot(slot);
    }

    fn hasCurrentEpochDuties(self: *AttestationService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.duties_epoch != null and self.duties_epoch.? == epoch;
    }

    fn hasNextEpochDuties(self: *AttestationService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.next_duties_epoch != null and self.next_duties_epoch.? == epoch;
    }

    fn isLastSlotOfEpoch(self: *const AttestationService, slot: u64) bool {
        return (slot + 1) % self.signing_ctx.slots_per_epoch == 0;
    }

    fn currentDutiesRevision(self: *AttestationService) u64 {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.current_duties_revision;
    }

    fn nextDutiesRevision(self: *AttestationService) u64 {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.next_duties_revision;
    }

    fn tryInstallCurrentDuties(
        self: *AttestationService,
        epoch: u64,
        revision: u64,
        dependent_root: ?[32]u8,
        duties: *std.array_list.Managed(AttesterDutyWithProof),
    ) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.current_duties_revision != revision) return false;

        const old = self.duties;
        self.duties = duties.*;
        self.duties_epoch = epoch;
        self.current_duties_dependent_root = dependent_root;
        duties.* = std.array_list.Managed(AttesterDutyWithProof).init(self.allocator);
        old.deinit();
        self.updateDutyMetricsLocked();
        return true;
    }

    fn tryInstallNextDuties(
        self: *AttestationService,
        epoch: u64,
        revision: u64,
        dependent_root: ?[32]u8,
        duties: *std.array_list.Managed(AttesterDutyWithProof),
    ) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.next_duties_revision != revision) return false;

        const old = self.next_duties;
        self.next_duties = duties.*;
        self.next_duties_epoch = epoch;
        self.next_duties_dependent_root = dependent_root;
        self.pending_next_duties_dependent_root = null;
        duties.* = std.array_list.Managed(AttesterDutyWithProof).init(self.allocator);
        old.deinit();
        self.updateDutyMetricsLocked();
        return true;
    }

    fn activatePrefetchedEpoch(
        self: *AttestationService,
        epoch: u64,
    ) ?[]BeaconCommitteeSubscription {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.next_duties_epoch == null or self.next_duties_epoch.? != epoch) return null;

        const subscriptions = self.buildBeaconCommitteeSubscriptions(self.next_duties.items) catch |err| {
            log.warn("failed to build beacon committee subscriptions while activating epoch={d}: {s}", .{
                epoch,
                @errorName(err),
            });
            return null;
        };

        const old_current = self.duties;
        self.duties = self.next_duties;
        self.duties_epoch = epoch;
        self.current_duties_dependent_root = self.next_duties_dependent_root;
        self.next_duties = std.array_list.Managed(AttesterDutyWithProof).init(self.allocator);
        self.next_duties_epoch = null;
        self.next_duties_dependent_root = null;
        self.pending_next_duties_dependent_root = null;
        old_current.deinit();
        self.updateDutyMetricsLocked();
        return subscriptions;
    }

    fn nextEpochDutiesNeedRefresh(self: *AttestationService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.nextEpochDutiesNeedRefreshLocked(epoch, null);
    }

    fn currentEpochDutiesNeedRefreshLocked(
        self: *const AttestationService,
        epoch: u64,
        new_dependent_root: [32]u8,
    ) bool {
        if (self.duties_epoch == null or self.duties_epoch.? != epoch) return false;
        const cached = self.current_duties_dependent_root orelse return true;
        return !std.mem.eql(u8, &cached, &new_dependent_root);
    }

    fn nextEpochDutiesNeedRefreshLocked(
        self: *const AttestationService,
        epoch: u64,
        override_pending_root: ?[32]u8,
    ) bool {
        if (self.next_duties_epoch == null or self.next_duties_epoch.? != epoch) return true;

        const pending_root = override_pending_root orelse self.pending_next_duties_dependent_root orelse return false;
        const cached = self.next_duties_dependent_root orelse return true;
        return !std.mem.eql(u8, &cached, &pending_root);
    }

    fn updateDutyMetricsLocked(self: *AttestationService) void {
        var duty_count: usize = 0;
        var epoch_count: usize = 0;
        var next_slot: ?u64 = null;

        if (self.duties_epoch != null) {
            epoch_count += 1;
            duty_count += self.duties.items.len;
            for (self.duties.items) |duty| {
                next_slot = if (next_slot) |current| @min(current, duty.duty.slot) else duty.duty.slot;
            }
        }

        if (self.next_duties_epoch != null) {
            epoch_count += 1;
            duty_count += self.next_duties.items.len;
            for (self.next_duties.items) |duty| {
                next_slot = if (next_slot) |current| @min(current, duty.duty.slot) else duty.duty.slot;
            }
        }

        self.metrics.setAttesterDutyCache(duty_count, epoch_count, next_slot);
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
            if (dp.duty.slot == slot) {
                any = true;
                break;
            }
        }
        if (!any) return std.mem.zeroes([32]u8);

        // Fetch attestation data from BN (committee_index 0; BN ignores for data content).
        const att_data_resp = try self.api.produceAttestationData(io, slot, 0);

        // Build the AttestationData SSZ struct.
        // Note: index is set per-duty below since committee_index is part of the signing root pre-Electra.
        var att_data = consensus_types.phase0.AttestationData.Type{
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

        // Malicious BN protection: validate attestation data bounds before signing.
        // A compromised BN could return maxInt(u64) epochs to permanently burn
        // attestation capability via slashing protection monotonicity.
        // Spec allows at most current_epoch+1 for target (lookahead attestations).
        const current_epoch_for_check = blk: {
            const now_ns = time.realNanoseconds(io);
            const genesis_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
            if (now_ns < genesis_ns) break :blk @as(u64, 0);
            const slot_dur_ns = self.seconds_per_slot * std.time.ns_per_s;
            const current_slot = (now_ns - genesis_ns) / slot_dur_ns;
            break :blk current_slot / self.signing_ctx.slots_per_epoch;
        };
        if (att_data_resp.target_epoch > current_epoch_for_check + 1) {
            log.err("BN returned target_epoch={d} > current_epoch+1={d}: refusing to sign (possible BN compromise)", .{
                att_data_resp.target_epoch, current_epoch_for_check + 1,
            });
            return std.mem.zeroes([32]u8);
        }
        if (att_data_resp.source_epoch >= att_data_resp.target_epoch) {
            log.err("BN returned source_epoch={d} >= target_epoch={d}: refusing to sign (invalid attestation data)", .{
                att_data_resp.source_epoch, att_data_resp.target_epoch,
            });
            return std.mem.zeroes([32]u8);
        }
        if (slot > current_epoch_for_check * self.signing_ctx.slots_per_epoch + self.signing_ctx.slots_per_epoch + 1) {
            log.err("BN returned slot={d} far in the future: refusing to sign (possible BN compromise)", .{slot});
            return std.mem.zeroes([32]u8);
        }

        // Sign for each validator with a duty this slot and collect JSON.
        var attestations_json: std.Io.Writer.Allocating = .init(self.allocator);
        defer attestations_json.deinit();
        var signed_count: u64 = 0;
        var duty_count_at_slot: u64 = 0;
        // Track signed pubkeys for liveness recording.
        var signed_pubkeys = std.array_list.Managed([48]u8).init(self.allocator);
        defer signed_pubkeys.deinit();

        try attestations_json.writer.writeByte('[');

        for (duties) |dp| {
            if (dp.duty.slot != slot) continue;
            duty_count_at_slot += 1;

            // Safety check before signing.
            if (!self.isSafeToSign(dp.duty.pubkey)) {
                log.warn("skipping attestation slot={d} validator_index={d}: signing not safe", .{ slot, dp.duty.validator_index });
                continue;
            }

            // Fork-aware: Pre-Electra uses committee_index in data for signing.
            // Electra: data.index is always 0 (committee encoded in committee_bits).
            {
                const sign_epoch = slot / self.signing_ctx.slots_per_epoch;
                att_data.index = if (sign_epoch >= self.electra_fork_epoch) 0 else dp.duty.committee_index;
            }
            var signing_root: [32]u8 = undefined;
            try signing_mod.attestationSigningRoot(self.signing_ctx, &att_data, &signing_root);

            const sig = self.validator_store.signAttestation(
                io,
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
            // Guard: validator_committee_index must be within the committee.
            if (validator_committee_index >= committee_length) {
                log.warn("validator_committee_index {d} >= committee_length {d}, skipping", .{
                    validator_committee_index, committee_length,
                });
                continue;
            }
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

            if (signed_count > 0) try attestations_json.writer.writeByte(',');

            // Fork-aware JSON format:
            // - Pre-Electra: phase0 Attestation {aggregation_bits, data, signature}
            // - Electra+: SingleAttestation {committee_index, attester_index, data, signature}
            const att_epoch = slot / self.signing_ctx.slots_per_epoch;
            if (att_epoch >= self.electra_fork_epoch) {
                // Electra: SingleAttestation format for v2 endpoint
                try attestations_json.writer.print(
                    "{{\"committee_index\":\"{d}\",\"attester_index\":\"{d}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"0\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}}",
                    .{
                        dp.duty.committee_index,
                        dp.duty.validator_index,
                        slot,
                        bbr_hex,
                        att_data_resp.source_epoch,
                        src_root_hex,
                        att_data_resp.target_epoch,
                        tgt_root_hex,
                        sig_hex,
                    },
                );
            } else {
                // Pre-Electra: phase0 Attestation format
                try attestations_json.writer.print(
                    "{{\"aggregation_bits\":\"0x{s}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}}",
                    .{
                        agg_bits_hex_slice,
                        slot,
                        dp.duty.committee_index,
                        bbr_hex,
                        att_data_resp.source_epoch,
                        src_root_hex,
                        att_data_resp.target_epoch,
                        tgt_root_hex,
                        sig_hex,
                    },
                );
            }
            signed_pubkeys.append(dp.duty.pubkey) catch {};
            signed_count += 1;
        }

        try attestations_json.writer.writeByte(']');

        const publish_ok = blk: {
            if (signed_count == 0) break :blk false;
            self.api.publishAttestations(io, attestations_json.written()) catch |err| {
                log.warn("publishAttestations failed slot={d} error={s}", .{ slot, @errorName(err) });
                break :blk false;
            };
            log.debug("attested slot={d} count={d}", .{ slot, signed_count });
            break :blk true;
        };

        if (publish_ok) {
            self.metrics.recordAttestationPublished(signed_count);
            const delay_seconds = self.slotDelaySeconds(io, slot);
            var observed: u64 = 0;
            while (observed < signed_count) : (observed += 1) {
                self.metrics.observeAttestationDelay(delay_seconds);
            }
        }
        const missed_count = duty_count_at_slot - if (publish_ok) signed_count else 0;
        if (missed_count > 0) {
            self.metrics.attestation_missed_total.incrBy(missed_count);
        }

        // Record liveness outcomes for all validators that had duties this slot.
        if (self.liveness_tracker) |lt| {
            const epoch = slot / self.signing_ctx.slots_per_epoch;
            for (duties) |dp| {
                if (dp.duty.slot != slot) continue;
                // Find if this validator signed successfully.
                var did_sign = false;
                for (signed_pubkeys.items) |pk| {
                    if (std.mem.eql(u8, &pk, &dp.duty.pubkey)) {
                        did_sign = true;
                        break;
                    }
                }
                lt.recordAttestationDuty(dp.duty.pubkey, epoch, did_sign and publish_ok);
            }
        }

        // Compute and return the AttestationData hash_tree_root for aggregation.
        var att_data_root: [32]u8 = undefined;
        try consensus_types.phase0.AttestationData.hashTreeRoot(&att_data, &att_data_root);
        return att_data_root;
    }

    fn slotDelaySeconds(self: *const AttestationService, io: Io, slot: u64) f64 {
        const slot_start_ns = (self.genesis_time_unix_secs * std.time.ns_per_s) + (slot * self.seconds_per_slot * std.time.ns_per_s);
        const now_ns = time.realNanoseconds(io);
        if (now_ns <= slot_start_ns) return 0.0;
        return @as(f64, @floatFromInt(now_ns - slot_start_ns)) / @as(f64, std.time.ns_per_s);
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
            defer self.allocator.free(agg.attestation_json);

            // 2. Build AggregateAndProof by parsing the aggregate from the BN response.
            // BUG-2 fix: Parse the actual aggregate attestation from the BN JSON response
            // instead of using a zeroed Attestation struct.
            var aggregate_attestation = self.parseAggregateAttestation(agg.attestation_json) catch |err| {
                log.warn("parseAggregateAttestation error: {s}", .{@errorName(err)});
                continue;
            };
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

            const sig = self.validator_store.signAggregateAndProof(io, dp.duty.pubkey, agg_signing_root) catch |err| {
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
            var agg_json: std.Io.Writer.Allocating = .init(self.allocator);
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

            try agg_json.writer.print(
                "[{{\"message\":{{\"aggregator_index\":\"{d}\",\"aggregate\":{{\"aggregation_bits\":\"0x{s}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}]",
                .{
                    dp.duty.validator_index,
                    agg_agg_bits_hex,
                    agg_data.slot,
                    agg_data.index,
                    agg_bbr_hex,
                    agg_data.source.epoch,
                    agg_src_root_hex,
                    agg_data.target.epoch,
                    agg_tgt_root_hex,
                    agg_sig_hex,
                    sel_hex,
                    sig_hex,
                },
            );

            self.api.publishAggregateAndProofs(io, agg_json.written()) catch |err| {
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
        var aggregation_bits_initialized = false;
        errdefer if (aggregation_bits_initialized) result.aggregation_bits.data.deinit(self.allocator);

        const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), json_bytes, .{}) catch
            return error.InvalidAggregateAttestation;

        // Response may be {"data": {...}} or the attestation directly.
        const att_obj = blk: {
            const root_obj = switch (parsed.value) {
                .object => |o| o,
                else => return error.InvalidAggregateAttestation,
            };
            if (root_obj.get("data")) |data_val| {
                break :blk switch (data_val) {
                    .object => |o| o,
                    else => return error.InvalidAggregateAttestation,
                };
            }
            break :blk root_obj;
        };

        // Parse aggregation_bits (hex-encoded bitlist).
        const bits_val = att_obj.get("aggregation_bits") orelse return error.InvalidAggregateAttestation;
        const bits_str = switch (bits_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        const bits_hex = if (std.mem.startsWith(u8, bits_str, "0x")) bits_str[2..] else bits_str;
        if (bits_hex.len == 0 or bits_hex.len % 2 != 0) return error.InvalidAggregateAttestation;
        const byte_len = bits_hex.len / 2;
        const bytes = try self.allocator.alloc(u8, byte_len);
        defer self.allocator.free(bytes);
        _ = try std.fmt.hexToBytes(bytes, bits_hex);

        // Last byte has length sentinel: highest set bit marks the end.
        const last_byte = bytes[byte_len - 1];
        if (last_byte == 0) return error.InvalidAggregateAttestation;
        const sentinel_bit = @as(u3, @intCast(7 - @clz(last_byte)));
        const bit_len = (byte_len - 1) * 8 + sentinel_bit;
        result.aggregation_bits = try @TypeOf(result.aggregation_bits).fromBitLen(self.allocator, bit_len);
        aggregation_bits_initialized = true;
        // Copy all data bytes. When byte_len == 1 the single byte holds
        // both validator bits and the sentinel; mask out the sentinel bit
        // so the bitvector only contains the actual committee bits.
        if (byte_len == 1) {
            const data_byte = last_byte & ~(@as(u8, 1) << sentinel_bit);
            if (result.aggregation_bits.data.items.len > 0) {
                result.aggregation_bits.data.items[0] = data_byte;
            }
        } else {
            @memcpy(result.aggregation_bits.data.items, bytes[0 .. byte_len - 1]);
        }

        // Parse attestation data fields.
        const data_val = att_obj.get("data") orelse return error.InvalidAggregateAttestation;
        const data_map = switch (data_val) {
            .object => |o| o,
            else => return error.InvalidAggregateAttestation,
        };

        const slot_val = data_map.get("slot") orelse return error.InvalidAggregateAttestation;
        const slot_str = switch (slot_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        result.data.slot = try std.fmt.parseInt(u64, slot_str, 10);

        const index_val = data_map.get("index") orelse return error.InvalidAggregateAttestation;
        const index_str = switch (index_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        result.data.index = try std.fmt.parseInt(u64, index_str, 10);

        const bbr_val = data_map.get("beacon_block_root") orelse return error.InvalidAggregateAttestation;
        const bbr_str = switch (bbr_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        const bbr_hex = if (std.mem.startsWith(u8, bbr_str, "0x")) bbr_str[2..] else bbr_str;
        _ = try std.fmt.hexToBytes(&result.data.beacon_block_root, bbr_hex);

        const src_val = data_map.get("source") orelse return error.InvalidAggregateAttestation;
        const src_map = switch (src_val) {
            .object => |o| o,
            else => return error.InvalidAggregateAttestation,
        };
        const src_epoch_val = src_map.get("epoch") orelse return error.InvalidAggregateAttestation;
        const src_epoch_str = switch (src_epoch_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        result.data.source.epoch = try std.fmt.parseInt(u64, src_epoch_str, 10);
        const src_root_val = src_map.get("root") orelse return error.InvalidAggregateAttestation;
        const src_root_str = switch (src_root_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        const src_root_hex = if (std.mem.startsWith(u8, src_root_str, "0x")) src_root_str[2..] else src_root_str;
        _ = try std.fmt.hexToBytes(&result.data.source.root, src_root_hex);

        const tgt_val = data_map.get("target") orelse return error.InvalidAggregateAttestation;
        const tgt_map = switch (tgt_val) {
            .object => |o| o,
            else => return error.InvalidAggregateAttestation,
        };
        const tgt_epoch_val = tgt_map.get("epoch") orelse return error.InvalidAggregateAttestation;
        const tgt_epoch_str = switch (tgt_epoch_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        result.data.target.epoch = try std.fmt.parseInt(u64, tgt_epoch_str, 10);
        const tgt_root_val = tgt_map.get("root") orelse return error.InvalidAggregateAttestation;
        const tgt_root_str = switch (tgt_root_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        const tgt_root_hex = if (std.mem.startsWith(u8, tgt_root_str, "0x")) tgt_root_str[2..] else tgt_root_str;
        _ = try std.fmt.hexToBytes(&result.data.target.root, tgt_root_hex);

        // Parse signature.
        const sig_val = att_obj.get("signature") orelse return error.InvalidAggregateAttestation;
        const sig_str = switch (sig_val) {
            .string => |s| s,
            else => return error.InvalidAggregateAttestation,
        };
        const sig_hex = if (std.mem.startsWith(u8, sig_str, "0x")) sig_str[2..] else sig_str;
        _ = try std.fmt.hexToBytes(&result.signature, sig_hex);

        return result;
    }
};

test "isAttestationAggregator matches spec modulus edge case" {
    const proof = [_]u8{0} ** 96;
    try std.testing.expect(isAttestationAggregator(proof, 1));
}

fn testSigningContext() SigningContext {
    return .{
        .genesis_validators_root = [_]u8{0} ** 32,
        .genesis_time_unix_secs = 0,
        .seconds_per_slot = 12,
        .slots_per_epoch = 32,
        .fork_schedule_len = 0,
        .fork_schedule = undefined,
    };
}

fn testMetrics() *ValidatorMetrics {
    const Holder = struct {
        var value = ValidatorMetrics.initNoop();
    };
    return &Holder.value;
}

fn testAttestationService() AttestationService {
    return AttestationService.init(
        std.testing.io,
        std.testing.allocator,
        undefined,
        undefined,
        testSigningContext(),
        12,
        0,
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        4_000,
        3_000,
        8_000,
        6_000,
        false,
        testMetrics(),
    );
}

test "snapshotCurrentDutiesForSlot hides invalidated stale duties" {
    var svc = testAttestationService();
    defer svc.deinit();

    try svc.duties.append(.{
        .duty = .{
            .pubkey = [_]u8{1} ** 48,
            .validator_index = 7,
            .committee_index = 3,
            .committee_length = 16,
            .committees_at_slot = 1,
            .validator_committee_index = 5,
            .slot = 64,
        },
        .selection_proof = null,
    });
    svc.duties_epoch = 2;
    svc.current_duties_dependent_root = [_]u8{1} ** 32;

    var snapshot = try svc.snapshotCurrentDutiesForSlot(64);
    try std.testing.expectEqual(@as(usize, 1), snapshot.len);
    try std.testing.expectEqual(@as(u64, 7), snapshot[0].duty.validator_index);
    std.testing.allocator.free(snapshot);

    AttestationService.onHeadChange(@ptrCast(&svc), .{
        .slot = 64,
        .block_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .previous_duty_dependent_root = [_]u8{9} ** 32,
        .current_duty_dependent_root = [_]u8{0} ** 32,
    });

    snapshot = try svc.snapshotCurrentDutiesForSlot(64);
    defer std.testing.allocator.free(snapshot);
    try std.testing.expectEqual(@as(usize, 0), snapshot.len);
    try std.testing.expect(svc.duties_epoch == null);
}

test "onHeadChange marks prefetched next epoch duties for refresh" {
    var svc = testAttestationService();
    defer svc.deinit();

    try svc.next_duties.append(.{
        .duty = .{
            .pubkey = [_]u8{2} ** 48,
            .validator_index = 9,
            .committee_index = 1,
            .committee_length = 16,
            .committees_at_slot = 1,
            .validator_committee_index = 2,
            .slot = 96,
        },
        .selection_proof = null,
    });
    svc.next_duties_epoch = 3;
    svc.next_duties_dependent_root = [_]u8{2} ** 32;

    const prior_revision = svc.nextDutiesRevision();
    AttestationService.onHeadChange(@ptrCast(&svc), .{
        .slot = 64,
        .block_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .previous_duty_dependent_root = [_]u8{0} ** 32,
        .current_duty_dependent_root = [_]u8{7} ** 32,
    });

    try std.testing.expectEqual(@as(?u64, 3), svc.next_duties_epoch);
    try std.testing.expectEqual(@as(usize, 1), svc.next_duties.items.len);
    try std.testing.expect(svc.nextDutiesRevision() > prior_revision);
    try std.testing.expectEqual(@as(?[32]u8, [_]u8{7} ** 32), svc.pending_next_duties_dependent_root);
    try std.testing.expect(svc.nextEpochDutiesNeedRefresh(3));
}
