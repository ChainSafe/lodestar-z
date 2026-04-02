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
const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const SyncCommitteeSubscription = api_client.SyncCommitteeSubscription;
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
const time = @import("time.zig");
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

const log = std.log.scoped(.sync_committee_service);

/// Maximum subcommittee byte size for stack-allocated agg_bits buffer.
/// = max(SYNC_COMMITTEE_SIZE) / min(SYNC_COMMITTEE_SUBNET_COUNT) / 8
/// Spec max: 2048/4/8 = 64 bytes.
const MAX_SUBCOMMITTEE_BYTES: usize = 64;
/// How many epochs before a sync period begins we ask the BN to subscribe.
const SUBSCRIPTIONS_LOOKAHEAD_EPOCHS: u64 = 2;

fn shouldPublishSyncSubscriptions(
    current_epoch: u64,
    period: u64,
    epochs_per_sync_committee_period: u64,
) bool {
    const from_epoch = period * epochs_per_sync_committee_period;
    return current_epoch + SUBSCRIPTIONS_LOOKAHEAD_EPOCHS >= from_epoch;
}

fn appendUniqueSubnetRepresentative(
    representatives: []u64,
    count: *usize,
    representative: u64,
) void {
    for (representatives[0..count.*]) |existing| {
        if (existing == representative) return;
    }
    representatives[count.*] = representative;
    count.* += 1;
}

// ---------------------------------------------------------------------------
// SyncCommitteeService
// ---------------------------------------------------------------------------

pub const SyncCommitteeService = struct {
    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    /// Optional chain header tracker for head root queries.
    header_tracker: ?*ChainHeaderTracker,
    signing_ctx: SigningContext,
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    /// Sync committee size (preset: mainnet=512, minimal=32).
    sync_committee_size: u64,
    /// Sync committee subnet count (preset: mainnet=4, minimal=4).
    sync_committee_subnet_count: u64,
    /// Seconds per slot for sub-slot timing.
    seconds_per_slot: u64,
    /// Genesis time (Unix seconds) — for correct sub-slot timing (BUG-5 fix).
    genesis_time_unix_secs: u64,
    /// Gloas fork epoch — sync duty timing changes at/after this fork.
    gloas_fork_epoch: u64,
    sync_message_due_ms: u64,
    sync_message_due_ms_gloas: u64,
    sync_contribution_due_ms: u64,
    sync_contribution_due_ms_gloas: u64,

    /// Protects sync-duty caches from concurrent runtime key changes and
    /// period refresh/prefetch swaps.
    cache_mutex: std.Io.Mutex,
    /// Duties keyed by validator index (valid for the current sync period).
    duties: std.array_list.Managed(SyncCommitteeDuty),
    /// Sync period for which duties are cached.
    duties_period: ?u64,
    /// Pre-fetched duties for the next sync committee period.
    next_duties: std.array_list.Managed(SyncCommitteeDuty),
    next_duties_period: ?u64,
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
        slots_per_epoch: u64,
        epochs_per_sync_committee_period: u64,
        sync_committee_size: u64,
        sync_committee_subnet_count: u64,
        seconds_per_slot: u64,
        genesis_time_unix_secs: u64,
        gloas_fork_epoch: u64,
        sync_message_due_ms: u64,
        sync_message_due_ms_gloas: u64,
        sync_contribution_due_ms: u64,
        sync_contribution_due_ms_gloas: u64,
        metrics: *ValidatorMetrics,
    ) SyncCommitteeService {
        return .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .validator_store = validator_store,
            .header_tracker = null,
            .signing_ctx = signing_ctx,
            .slots_per_epoch = slots_per_epoch,
            .epochs_per_sync_committee_period = epochs_per_sync_committee_period,
            .sync_committee_size = sync_committee_size,
            .sync_committee_subnet_count = sync_committee_subnet_count,
            .seconds_per_slot = seconds_per_slot,
            .genesis_time_unix_secs = genesis_time_unix_secs,
            .gloas_fork_epoch = gloas_fork_epoch,
            .sync_message_due_ms = sync_message_due_ms,
            .sync_message_due_ms_gloas = sync_message_due_ms_gloas,
            .sync_contribution_due_ms = sync_contribution_due_ms,
            .sync_contribution_due_ms_gloas = sync_contribution_due_ms_gloas,
            .cache_mutex = .init,
            .duties = std.array_list.Managed(SyncCommitteeDuty).init(allocator),
            .duties_period = null,
            .next_duties = std.array_list.Managed(SyncCommitteeDuty).init(allocator),
            .next_duties_period = null,
            .doppelganger = null,
            .syncing_tracker = null,
            .liveness_tracker = null,
            .metrics = metrics,
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
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        self.clearDutyList(&self.duties);
        self.duties.deinit();
        self.clearDutyList(&self.next_duties);
        self.next_duties.deinit();
    }

    /// Attach a chain header tracker for head root queries.
    pub fn setHeaderTracker(self: *SyncCommitteeService, tracker: *ChainHeaderTracker) void {
        self.header_tracker = tracker;
    }

    // -----------------------------------------------------------------------
    // Clock callbacks
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to refresh current-period duties and keep
    /// the next-period cache warm.
    ///
    /// This mirrors Lodestar's behavior of re-polling sync duties every epoch
    /// so newly discovered validators and newly resolved indices do not wait
    /// until the next sync-period transition to start participating.
    pub fn onEpoch(self: *SyncCommitteeService, io: Io, epoch: u64) void {
        const period = epoch / self.epochs_per_sync_committee_period;

        if (self.activatePrefetchedPeriod(period)) {
            log.info("sync committee period transition to period={d} at epoch={d}", .{ period, epoch });
            log.info("activated pre-fetched sync committee duties for period={d}", .{period});
        }

        self.refreshDuties(io, epoch, period) catch |err| {
            log.err("refreshDuties period={d} error={s}", .{ period, @errorName(err) });
        };
        self.publishSubscriptionsForPeriod(io, period, epoch);

        const next_period = period + 1;
        const next_period_epoch = epoch + self.epochs_per_sync_committee_period;
        self.refreshDutiesForPeriod(io, next_period_epoch, next_period) catch |err| {
            log.warn("pre-fetch duties next_period={d} epoch={d} error={s}", .{
                next_period,
                next_period_epoch,
                @errorName(err),
            });
        };
        self.publishNextPeriodSubscriptions(io, next_period, epoch);
    }

    /// Called at each slot to produce and submit sync committee messages + contributions.
    pub fn onSlot(self: *SyncCommitteeService, io: Io, slot: u64) void {
        self.runSyncTasks(io, slot) catch |err| {
            log.err("runSyncTasks slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    /// Remove any cached sync committee duties for the given validator pubkey.
    ///
    /// This mirrors Lodestar's runtime duty cleanup so validator removals take
    /// effect immediately instead of waiting for the next period refresh.
    pub fn removeDutiesForKey(self: *SyncCommitteeService, pubkey: [48]u8) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        var i: usize = 0;
        while (i < self.duties.items.len) {
            if (std.mem.eql(u8, &self.duties.items[i].pubkey, &pubkey)) {
                self.allocator.free(self.duties.items[i].validator_sync_committee_indices);
                _ = self.duties.swapRemove(i);
            } else {
                i += 1;
            }
        }

        i = 0;
        while (i < self.next_duties.items.len) {
            if (std.mem.eql(u8, &self.next_duties.items[i].pubkey, &pubkey)) {
                self.allocator.free(self.next_duties.items[i].validator_sync_committee_indices);
                _ = self.next_duties.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    /// Pre-fetch duties for an upcoming sync period without overwriting current duties.
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

        var next_duties = std.array_list.Managed(SyncCommitteeDuty).init(self.allocator);
        errdefer {
            self.clearDutyList(&next_duties);
            next_duties.deinit();
        }
        try self.cacheDutyList(&next_duties, fetched);
        self.replaceNextDuties(period, next_duties);
        log.info("pre-fetched {d} sync committee duties for period={d}", .{ fetched.len, period });
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

        var current_duties = std.array_list.Managed(SyncCommitteeDuty).init(self.allocator);
        errdefer {
            self.clearDutyList(&current_duties);
            current_duties.deinit();
        }
        try self.cacheDutyList(&current_duties, fetched);
        self.replaceCurrentDuties(period, current_duties);
        log.debug("cached {d} sync committee duties period={d}", .{ fetched.len, period });
    }

    fn clearDutyList(self: *SyncCommitteeService, duties: *std.array_list.Managed(SyncCommitteeDuty)) void {
        for (duties.items) |*d| {
            self.allocator.free(d.validator_sync_committee_indices);
        }
        duties.clearRetainingCapacity();
    }

    fn cacheDutyList(
        self: *SyncCommitteeService,
        duties: *std.array_list.Managed(SyncCommitteeDuty),
        fetched: []const SyncCommitteeDuty,
    ) !void {
        self.clearDutyList(duties);
        const subcommittee_size = self.sync_committee_size / self.sync_committee_subnet_count;

        for (fetched) |duty| {
            const dedup_buf = try self.allocator.alloc(u64, duty.validator_sync_committee_indices.len);
            defer self.allocator.free(dedup_buf);

            var dedup_len: usize = 0;
            for (duty.validator_sync_committee_indices) |committee_index| {
                const subnet = committee_index / subcommittee_size;
                appendUniqueSubnetRepresentative(dedup_buf, &dedup_len, subnet * subcommittee_size);
            }

            const sc_indices = try self.allocator.alloc(u64, dedup_len);
            errdefer self.allocator.free(sc_indices);
            @memcpy(sc_indices, dedup_buf[0..dedup_len]);

            try duties.append(.{
                .pubkey = duty.pubkey,
                .validator_index = duty.validator_index,
                .validator_sync_committee_indices = sc_indices,
            });
        }
    }

    fn publishSyncCommitteeSubscriptions(
        self: *SyncCommitteeService,
        io: Io,
        duties: []const SyncCommitteeDuty,
        period: u64,
        current_epoch: u64,
    ) void {
        if (duties.len == 0) return;

        if (!shouldPublishSyncSubscriptions(current_epoch, period, self.epochs_per_sync_committee_period)) return;

        const subscriptions = self.allocator.alloc(SyncCommitteeSubscription, duties.len) catch |err| {
            log.warn("alloc sync committee subscriptions failed: {s}", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(subscriptions);

        const until_epoch = (period + 1) * self.epochs_per_sync_committee_period;
        for (duties, subscriptions) |duty, *subscription| {
            subscription.* = .{
                .validator_index = duty.validator_index,
                .sync_committee_indices = duty.validator_sync_committee_indices,
                .until_epoch = until_epoch,
            };
        }

        self.api.prepareSyncCommitteeSubnets(io, subscriptions) catch |err| {
            log.warn("prepareSyncCommitteeSubnets failed: {s}", .{@errorName(err)});
        };
    }

    // -----------------------------------------------------------------------
    // Sync task execution
    // -----------------------------------------------------------------------

    fn runSyncTasks(self: *SyncCommitteeService, io: Io, slot: u64) !void {
        const duties = try self.snapshotDutiesForSlot(slot);
        defer self.freeDutySnapshot(duties);
        if (duties.len == 0) return;

        // Sub-slot timing per Ethereum spec:
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;

        // Ethereum slot timing is based on Unix wall-clock time, so this uses
        // `std.Io.Clock.real` through the shared validator time helper.
        const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
        const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;

        // Step 1: sign and submit sync committee messages once the head block arrives
        // or the sync-message due time elapses, whichever comes first.
        const sync_message_due_ns = slot_start_ns + self.syncMessageDueMs(slot) * std.time.ns_per_ms;
        if (self.header_tracker) |tracker| {
            tracker.waitForHeadSlotOrDeadline(slot, sync_message_due_ns);
        }
        const now_ns = time.realNanoseconds(io);
        if (now_ns < sync_message_due_ns) {
            try io.sleep(.{ .nanoseconds = @intCast(sync_message_due_ns - now_ns) }, .real);
        }

        // Snapshot the head root only after waiting for block arrival or the
        // due instant so sync messages and contributions use the actual slot head.
        const beacon_block_root: [32]u8 = if (self.header_tracker) |ht|
            ht.getHeadInfo().block_root
        else
            [_]u8{0} ** 32;
        try self.produceAndPublishMessages(io, slot, duties, &beacon_block_root);

        // Step 2: produce contributions at the configured contribution due time.
        const contribution_due_ns = slot_start_ns + self.syncContributionDueMs(slot) * std.time.ns_per_ms;
        const contribution_now_ns = time.realNanoseconds(io);
        if (contribution_now_ns < contribution_due_ns) {
            try io.sleep(.{ .nanoseconds = @intCast(contribution_due_ns - contribution_now_ns) }, .real);
        }
        try self.produceAndPublishContributions(io, slot, duties, &beacon_block_root);
    }

    fn syncPeriodForSlot(self: *const SyncCommitteeService, slot: u64) u64 {
        const effective_slot = slot +| 1;
        const epoch = effective_slot / self.slots_per_epoch;
        return epoch / self.epochs_per_sync_committee_period;
    }

    fn periodHasDuties(self: *SyncCommitteeService, period: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.duties_period != null and self.duties_period.? == period) return true;
        if (self.next_duties_period != null and self.next_duties_period.? == period) return true;
        return false;
    }

    fn snapshotDutiesForSlot(self: *SyncCommitteeService, slot: u64) ![]SyncCommitteeDuty {
        const period = self.syncPeriodForSlot(slot);
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        const source = blk: {
            if (self.duties_period != null and self.duties_period.? == period) break :blk self.duties.items;
            if (self.next_duties_period != null and self.next_duties_period.? == period) break :blk self.next_duties.items;
            return self.allocator.alloc(SyncCommitteeDuty, 0);
        };

        const snapshot = try self.allocator.alloc(SyncCommitteeDuty, source.len);
        errdefer self.allocator.free(snapshot);

        for (source, snapshot) |duty, *out| {
            const indices = try self.allocator.dupe(u64, duty.validator_sync_committee_indices);
            out.* = .{
                .pubkey = duty.pubkey,
                .validator_index = duty.validator_index,
                .validator_sync_committee_indices = indices,
            };
        }
        return snapshot;
    }

    fn freeDutySnapshot(self: *SyncCommitteeService, duties: []SyncCommitteeDuty) void {
        for (duties) |duty| {
            self.allocator.free(duty.validator_sync_committee_indices);
        }
        self.allocator.free(duties);
    }

    fn syncMessageDueMs(self: *const SyncCommitteeService, slot: u64) u64 {
        const epoch = slot / self.slots_per_epoch;
        return if (epoch >= self.gloas_fork_epoch)
            self.sync_message_due_ms_gloas
        else
            self.sync_message_due_ms;
    }

    fn syncContributionDueMs(self: *const SyncCommitteeService, slot: u64) u64 {
        const epoch = slot / self.slots_per_epoch;
        return if (epoch >= self.gloas_fork_epoch)
            self.sync_contribution_due_ms_gloas
        else
            self.sync_contribution_due_ms;
    }

    fn produceAndPublishMessages(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        duties: []const SyncCommitteeDuty,
        beacon_block_root: *const [32]u8,
    ) !void {
        var count: u32 = 0;
        var signed_pubkeys = std.array_list.Managed([48]u8).init(self.allocator);
        defer signed_pubkeys.deinit();

        var messages_json: std.Io.Writer.Allocating = .init(self.allocator);
        defer messages_json.deinit();
        try messages_json.writer.writeByte('[');

        for (duties) |d| {
            // Compute signing root: sign(beacon_block_root) with DOMAIN_SYNC_COMMITTEE.
            var signing_root: [32]u8 = undefined;
            // BUG-6 fix: Pass slot for dynamic fork_version lookup.
            signing_mod.syncCommitteeSigningRoot(self.signing_ctx, slot, beacon_block_root, &signing_root) catch |err| {
                log.warn("syncCommitteeSigningRoot error: {s}", .{@errorName(err)});
                continue;
            };

            // Safety check before signing sync committee message.
            if (!self.isSafeToSign(d.pubkey)) {
                log.warn("skipping sync message slot={d} validator_index={d}: signing not safe", .{ slot, d.validator_index });
                continue;
            }

            const sig = self.validator_store.signSyncCommitteeMessage(io, d.pubkey, signing_root) catch |err| {
                log.warn("signSyncCommitteeMessage validator_index={d} error={s}", .{ d.validator_index, @errorName(err) });
                continue;
            };
            const sig_bytes = sig.compress();
            const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);
            const bbr_hex = std.fmt.bytesToHex(beacon_block_root, .lower);

            if (count > 0) try messages_json.writer.writeByte(',');
            try messages_json.writer.print(
                "{{\"slot\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"validator_index\":\"{d}\",\"signature\":\"0x{s}\"}}",
                .{ slot, bbr_hex, d.validator_index, sig_hex },
            );
            signed_pubkeys.append(d.pubkey) catch {};
            count += 1;
        }

        try messages_json.writer.writeByte(']');

        const publish_ok = blk: {
            if (count == 0) break :blk false;
            self.api.publishSyncCommitteeMessages(io, messages_json.written()) catch |err| {
                log.warn("publishSyncCommitteeMessages slot={d} error={s}", .{ slot, @errorName(err) });
                break :blk false;
            };
            log.info("sync committee messages slot={d} count={d}", .{ slot, count });
            break :blk true;
        };
        if (publish_ok) {
            self.metrics.sync_committee_message_total.incrBy(count);
        }

        // Record liveness outcomes for all validators with sync committee duties this slot.
        if (self.liveness_tracker) |lt| {
            const epoch = slot / self.slots_per_epoch;
            for (duties) |d| {
                var did_sign = false;
                for (signed_pubkeys.items) |pk| {
                    if (std.mem.eql(u8, &pk, &d.pubkey)) {
                        did_sign = true;
                        break;
                    }
                }
                lt.recordSyncDuty(d.pubkey, epoch, did_sign and publish_ok);
            }
        }
    }

    fn produceAndPublishContributions(
        self: *SyncCommitteeService,
        io: Io,
        slot: u64,
        duties: []const SyncCommitteeDuty,
        beacon_block_root: *const [32]u8,
    ) !void {
        const slot_duration_ns = self.seconds_per_slot * std.time.ns_per_s;
        const genesis_time_ns = self.genesis_time_unix_secs * std.time.ns_per_s;
        const slot_start_ns = genesis_time_ns + slot * slot_duration_ns;

        for (duties) |dp| {
            for (dp.validator_sync_committee_indices) |sc_idx| {
                const subcommittee_index = sc_idx / (self.sync_committee_size / self.sync_committee_subnet_count);

                // Safety check before any signing.
                if (!self.isSafeToSign(dp.pubkey)) {
                    log.warn("skipping contribution slot={d} validator_index={d}: signing not safe", .{ slot, dp.validator_index });
                    continue;
                }

                // Selection proofs are slot-scoped, so compute them on demand for
                // the current slot rather than storing mutable per-slot state in
                // the long-lived duty cache.
                var sel_root: [32]u8 = undefined;
                signing_mod.syncCommitteeSelectionProofSigningRoot(
                    self.signing_ctx,
                    slot,
                    subcommittee_index,
                    &sel_root,
                ) catch |err| {
                    log.warn("sync selection proof signing root error slot={d}: {s}", .{ slot, @errorName(err) });
                    continue;
                };
                const sel_proof = if (self.validator_store.signSelectionProof(io, dp.pubkey, sel_root, .SYNC_COMMITTEE_SELECTION_PROOF)) |sig|
                    sig.compress()
                else |_|
                    continue;

                // Aggregation eligibility check per consensus spec:
                //   is_sync_committee_aggregator = (SHA256(sel_proof)[0:8] as little-endian u64)
                //       % max(1, SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE) == 0
                // Same pattern as attestation_service.zig's aggregator check.
                const subcommittee_size = self.sync_committee_size / self.sync_committee_subnet_count;
                const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;
                const modulo = @max(1, subcommittee_size / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE);
                const Sha256 = std.crypto.hash.sha2.Sha256;
                var sel_hash: [32]u8 = undefined;
                Sha256.hash(&sel_proof, &sel_hash, .{});
                const hash_val = std.mem.readInt(u64, sel_hash[0..8], .little);
                if (hash_val % modulo != 0) continue; // not selected as aggregator for this subcommittee

                // 1. Fetch contribution from BN.
                const now_ns = time.realNanoseconds(io);
                const slot_end_ns = slot_start_ns + slot_duration_ns;
                const remaining_ns = if (now_ns >= slot_end_ns) @as(u64, 1) else @max(@as(u64, 1), (slot_end_ns - now_ns));
                const timeout_ms: u64 = @max(@as(u64, 1), remaining_ns / std.time.ns_per_ms);

                const contrib = try self.api.produceSyncCommitteeContributionWithTimeout(
                    io,
                    slot,
                    subcommittee_index,
                    beacon_block_root.*,
                    timeout_ms,
                );
                defer self.allocator.free(contrib.aggregation_bits);

                // 2. Build ContributionAndProof and sign the contribution exactly as
                // returned by the BN. The BN response is the source of truth for
                // aggregated sync committee participation at this subnet/slot.
                const AggregationBitsData = @FieldType(
                    @FieldType(consensus_types.altair.SyncCommitteeContribution.Type, "aggregation_bits"),
                    "data",
                );
                var agg_bits: AggregationBitsData = [_]u8{0} ** @typeInfo(AggregationBitsData).array.len;
                const subcommittee_bytes = (subcommittee_size + 7) / 8;
                const agg_bits_slice = agg_bits[0..subcommittee_bytes];
                // Copy BN's aggregated bits directly.
                const copy_len = @min(contrib.aggregation_bits.len, agg_bits_slice.len);
                @memcpy(agg_bits_slice[0..copy_len], contrib.aggregation_bits[0..copy_len]);

                const contribution_and_proof = consensus_types.altair.ContributionAndProof.Type{
                    .aggregator_index = dp.validator_index,
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

                const sig = self.validator_store.signContributionAndProof(io, dp.pubkey, signing_root) catch |err| {
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
                var contrib_json: std.Io.Writer.Allocating = .init(self.allocator);
                defer contrib_json.deinit();
                try contrib_json.writer.print(
                    "[{{\"message\":{{\"aggregator_index\":\"{d}\",\"contribution\":{{\"slot\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"subcommittee_index\":\"{d}\",\"aggregation_bits\":\"0x{x}\",\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}]",
                    .{ dp.validator_index, slot, bbr_hex2, subcommittee_index, agg_bits_slice, contrib_sig_hex, sel_hex, sig_hex },
                );

                self.api.publishContributionAndProofs(io, contrib_json.written()) catch |err| {
                    log.warn("publishContributionAndProofs error: {s}", .{@errorName(err)});
                    continue;
                };
                self.metrics.sync_committee_contribution_total.incr();
            }
        }
    }

    fn replaceCurrentDuties(
        self: *SyncCommitteeService,
        period: u64,
        duties: std.array_list.Managed(SyncCommitteeDuty),
    ) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        var old = self.duties;
        self.duties = duties;
        self.duties_period = period;
        self.clearDutyList(&old);
        old.deinit();
    }

    fn replaceNextDuties(
        self: *SyncCommitteeService,
        period: u64,
        duties: std.array_list.Managed(SyncCommitteeDuty),
    ) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        var old = self.next_duties;
        self.next_duties = duties;
        self.next_duties_period = period;
        self.clearDutyList(&old);
        old.deinit();
    }

    fn activatePrefetchedPeriod(self: *SyncCommitteeService, period: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.next_duties_period == null or self.next_duties_period.? != period) return false;

        var old_current = self.duties;
        self.duties = self.next_duties;
        self.duties_period = period;
        self.next_duties = std.array_list.Managed(SyncCommitteeDuty).init(self.allocator);
        self.next_duties_period = null;
        self.clearDutyList(&old_current);
        old_current.deinit();
        return true;
    }

    fn publishSubscriptionsForPeriod(
        self: *SyncCommitteeService,
        io: Io,
        period: u64,
        current_epoch: u64,
    ) void {
        if (!self.periodHasDuties(period)) return;
        const duties = self.snapshotDutiesForSlot(period * self.epochs_per_sync_committee_period * self.slots_per_epoch) catch |err| {
            log.warn("snapshot current sync duties for period={d} failed: {s}", .{ period, @errorName(err) });
            return;
        };
        defer self.freeDutySnapshot(duties);
        self.publishSyncCommitteeSubscriptions(io, duties, period, current_epoch);
    }

    fn publishNextPeriodSubscriptions(
        self: *SyncCommitteeService,
        io: Io,
        period: u64,
        current_epoch: u64,
    ) void {
        if (!self.periodHasDuties(period)) return;
        const duties = self.snapshotDutiesForSlot(period * self.epochs_per_sync_committee_period * self.slots_per_epoch) catch |err| {
            log.warn("snapshot next sync duties for period={d} failed: {s}", .{ period, @errorName(err) });
            return;
        };
        defer self.freeDutySnapshot(duties);
        self.publishSyncCommitteeSubscriptions(io, duties, period, current_epoch);
    }
};

test "syncPeriodForSlot uses slot plus one offset at period boundary" {
    var service = SyncCommitteeService.init(
        std.testing.io,
        std.testing.allocator,
        undefined,
        undefined,
        undefined,
        32,
        256,
        512,
        4,
        12,
        0,
        std.math.maxInt(u64),
        4_000,
        3_000,
        8_000,
        6_000,
        undefined,
    );
    defer {
        service.duties.deinit();
        service.next_duties.deinit();
    }

    const boundary_slot = 32 * 256;
    try std.testing.expectEqual(@as(u64, 0), service.syncPeriodForSlot(boundary_slot - 2));
    try std.testing.expectEqual(@as(u64, 1), service.syncPeriodForSlot(boundary_slot - 1));
    try std.testing.expectEqual(@as(u64, 1), service.syncPeriodForSlot(boundary_slot));
}

test "shouldPublishSyncSubscriptions only within lookahead window" {
    try std.testing.expect(!shouldPublishSyncSubscriptions(10, 2, 256));
    try std.testing.expect(shouldPublishSyncSubscriptions(510, 2, 256));
    try std.testing.expect(shouldPublishSyncSubscriptions(512, 2, 256));
}

test "cacheDutyList deduplicates multiple committee positions in the same subnet" {
    var service = SyncCommitteeService.init(
        std.testing.io,
        std.testing.allocator,
        undefined,
        undefined,
        undefined,
        32,
        256,
        512,
        4,
        12,
        0,
        std.math.maxInt(u64),
        4_000,
        3_000,
        8_000,
        6_000,
        undefined,
    );
    defer {
        service.clearDutyList(&service.duties);
        service.duties.deinit();
        service.clearDutyList(&service.next_duties);
        service.next_duties.deinit();
    }

    const raw_indices = try std.testing.allocator.dupe(u64, &.{ 5, 9, 129 });
    defer std.testing.allocator.free(raw_indices);

    const fetched = [_]SyncCommitteeDuty{.{
        .pubkey = [_]u8{0} ** 48,
        .validator_index = 1,
        .validator_sync_committee_indices = raw_indices,
    }};

    try service.cacheDutyList(&service.duties, &fetched);
    try std.testing.expectEqual(@as(usize, 1), service.duties.items.len);
    try std.testing.expectEqual(@as(usize, 2), service.duties.items[0].validator_sync_committee_indices.len);
    try std.testing.expectEqualSlices(u64, &.{ 0, 128 }, service.duties.items[0].validator_sync_committee_indices);
}
