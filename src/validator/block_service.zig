//! Block proposal service for the Validator Client.
//!
//! Tracks proposer duties per epoch and submits blocks when our validators
//! are scheduled to propose.
//!
//! TS equivalent: packages/validator/src/services/block.ts (BlockProposingService)
//!               + packages/validator/src/services/blockDuties.ts (BlockDutiesService)
//!
//! Data flow:
//!   1. Cache proposer duties for the current epoch, with optional prefetch for next.
//!   2. At each slot: propose from cache, refresh current-epoch duties, then propose any
//!      newly discovered duties for the same slot.
//!   3. If yes: produceBlock -> sign (RANDAO + block) -> publishBlock.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyBeaconBlockBody = fork_types.AnyBeaconBlockBody;
const ForkSeq = @import("config").ForkSeq;
const BlockType = fork_types.BlockType;
const types = @import("types.zig");
const BuilderSelection = types.BuilderSelection;
const ProposerDuty = types.ProposerDuty;
const BroadcastValidation = types.BroadcastValidation;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;
const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;
const time = @import("time.zig");

const log = std.log.scoped(.block_service);

const CachedProposerDuty = struct {
    duty: ProposerDuty,
    produced: bool,
};

// ---------------------------------------------------------------------------
// BlockService
// ---------------------------------------------------------------------------

pub const BlockService = struct {
    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    /// Signing context (fork_version + genesis_validators_root) for domain computation.
    signing_ctx: SigningContext,
    /// Protects proposer duty caches from concurrent keymanager mutation and
    /// refresh/prefetch swaps.
    cache_mutex: std.Io.Mutex,
    /// Duties for the current epoch.
    duties: std.array_list.Managed(CachedProposerDuty),
    duties_epoch: ?u64,
    /// Pre-fetched duties for the next epoch (swap at epoch boundary).
    next_duties: std.array_list.Managed(CachedProposerDuty),
    next_duties_epoch: ?u64,
    /// Count of missed block proposals this session.
    missed_block_count: u64,
    /// Doppelganger service reference (optional).
    doppelganger: ?*DoppelgangerService,
    /// Syncing tracker reference (optional).
    syncing_tracker: ?*SyncingTracker,
    /// Slots per epoch (from chain config).
    slots_per_epoch: u64,
    /// Seconds per slot for proposal timing metrics.
    seconds_per_slot: u64,
    /// Genesis time (Unix seconds) for proposal timing metrics.
    genesis_time_unix_secs: u64,
    /// Whether to request local block production in blinded form.
    blinded_local: bool,
    /// Validation policy requested when publishing signed blocks.
    broadcast_validation: BroadcastValidation,
    metrics: *ValidatorMetrics,

    pub fn init(
        io: Io,
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        slots_per_epoch: u64,
        seconds_per_slot: u64,
        genesis_time_unix_secs: u64,
        blinded_local: bool,
        broadcast_validation: BroadcastValidation,
        metrics: *ValidatorMetrics,
    ) BlockService {
        return .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
            .cache_mutex = .init,
            .duties = std.array_list.Managed(CachedProposerDuty).init(allocator),
            .duties_epoch = null,
            .next_duties = std.array_list.Managed(CachedProposerDuty).init(allocator),
            .next_duties_epoch = null,
            .missed_block_count = 0,
            .doppelganger = null,
            .syncing_tracker = null,
            .slots_per_epoch = slots_per_epoch,
            .seconds_per_slot = seconds_per_slot,
            .genesis_time_unix_secs = genesis_time_unix_secs,
            .blinded_local = blinded_local,
            .broadcast_validation = broadcast_validation,
            .metrics = metrics,
        };
    }

    /// Wire up safety checkers. Called from validator.zig after init.
    pub fn setSafetyCheckers(
        self: *BlockService,
        dopple: ?*DoppelgangerService,
        syncing: ?*SyncingTracker,
    ) void {
        self.doppelganger = dopple;
        self.syncing_tracker = syncing;
    }

    /// Returns true if it is safe for this validator to sign a block.
    fn isSafeToSign(self: *const BlockService, pubkey: [48]u8) bool {
        if (self.syncing_tracker) |st| {
            if (!st.isSynced()) return false;
        }
        if (self.doppelganger) |d| {
            if (!d.isSigningAllowed(pubkey)) return false;
        }
        return true;
    }

    pub fn deinit(self: *BlockService) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        self.duties.deinit();
        self.next_duties.deinit();
    }

    // -----------------------------------------------------------------------
    // Clock callbacks (registered via SlotClock)
    // -----------------------------------------------------------------------

    /// Called at each epoch boundary to refresh proposer duties.
    ///
    /// TS: BlockDutiesService.pollBeaconProposers (runEveryEpoch)
    pub fn onEpoch(self: *BlockService, io: Io, epoch: u64) void {
        if (self.activatePrefetchedEpoch(epoch)) {
            log.debug("swapped pre-fetched proposer duties into epoch={d}", .{epoch});
            return;
        }

        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    /// Called at each slot to check for a block proposal duty.
    ///
    /// The proposer-duty cache is refreshed at startup, on epoch boundaries, and
    /// on runtime validator-set changes. Slot processing only falls back to an
    /// inline refresh when the cache is stale for the current epoch.
    pub fn onSlot(self: *BlockService, io: Io, slot: u64) void {
        self.maybePropose(io, slot);
    }

    /// Remove any cached proposer duties for the given validator pubkey.
    ///
    /// Used when a validator is removed at runtime so stale proposer duties do not
    /// trigger failed proposal attempts later in the epoch.
    pub fn removeDutiesForKey(self: *BlockService, pubkey: [48]u8) void {
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
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    fn refreshDuties(self: *BlockService, io: Io, epoch: u64) !void {
        log.debug("fetching proposer duties for epoch {d}", .{epoch});

        const fetched = try self.api.getProposerDuties(io, epoch);
        defer self.allocator.free(fetched);

        var refreshed = std.array_list.Managed(CachedProposerDuty).init(self.allocator);
        errdefer refreshed.deinit();

        if (self.duties_epoch) |prev_epoch| {
            if (prev_epoch != epoch and prev_epoch + 1 == epoch) {
                self.checkMissedDuties();
            }
        }

        for (fetched) |duty| {
            if (!self.hasTrackedValidator(duty.pubkey)) continue;

            try refreshed.append(.{
                .duty = duty,
                .produced = self.wasProduced(duty),
            });
        }

        self.replaceCurrentDuties(epoch, refreshed);

        log.debug("cached {d} proposer duties for epoch {d}", .{ refreshed.items.len, epoch });
    }

    /// Pre-fetch proposer duties for the next epoch to reduce latency at epoch boundaries.
    ///
    /// TS: BlockDutiesService fetches N+1 near the end of epoch N.
    fn prefetchNextEpochDuties(self: *BlockService, io: Io, next_epoch: u64) void {
        log.debug("pre-fetching proposer duties for epoch {d}", .{next_epoch});
        const fetched = self.api.getProposerDuties(io, next_epoch) catch |err| {
            log.warn("prefetch proposer duties epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        defer self.allocator.free(fetched);

        var prefetched = std.array_list.Managed(CachedProposerDuty).init(self.allocator);
        errdefer prefetched.deinit();

        for (fetched) |duty| {
            if (!self.hasTrackedValidator(duty.pubkey)) continue;

            prefetched.append(.{
                .duty = duty,
                .produced = false,
            }) catch |err| {
                log.warn("prefetch proposer duties epoch={d} append error={s}", .{ next_epoch, @errorName(err) });
                return;
            };
        }

        self.replaceNextDuties(next_epoch, prefetched);

        log.debug("pre-fetched {d} proposer duties for epoch {d}", .{ prefetched.items.len, next_epoch });
    }

    // -----------------------------------------------------------------------
    // Block proposal
    // -----------------------------------------------------------------------

    fn maybePropose(self: *BlockService, io: Io, slot: u64) void {
        const epoch = slot / self.slots_per_epoch;
        if (!self.hasCurrentEpochDuties(epoch)) {
            self.refreshDuties(io, epoch) catch |err| {
                log.warn("refreshDuties slot={d} epoch={d} error={s}", .{ slot, epoch, @errorName(err) });
                if (self.isLastSlotOfEpoch(slot) and !self.hasNextEpochDuties(epoch + 1)) {
                    self.prefetchNextEpochDuties(io, epoch + 1);
                }
                return;
            };
        }

        self.proposeCachedDutiesAtSlot(io, slot);

        if (self.isLastSlotOfEpoch(slot) and !self.hasNextEpochDuties(epoch + 1)) {
            self.prefetchNextEpochDuties(io, epoch + 1);
        }
    }

    fn proposeCachedDutiesAtSlot(self: *BlockService, io: Io, slot: u64) void {
        const cached_duties = self.snapshotDutiesForSlot(slot) catch |err| {
            log.err("snapshot proposer duties slot={d} error={s}", .{ slot, @errorName(err) });
            return;
        };
        defer self.allocator.free(cached_duties);

        for (cached_duties) |cached| {
            if (cached.produced) continue;

            const produced = self.proposeDuty(io, cached.duty) catch |err| {
                log.err("proposeDuty slot={d} validator_index={d} error={s}", .{
                    slot,
                    cached.duty.validator_index,
                    @errorName(err),
                });
                continue;
            };

            self.markProduced(cached.duty, produced);
        }
    }

    fn ensureBuilderSelectionSatisfied(
        selection: BuilderSelection,
        source: types.ExecutionPayloadSource,
    ) !void {
        switch (selection) {
            .builderonly, .builderalways => {
                if (source != .builder) return error.UnsupportedBuilderSelection;
            },
            .executiononly, .executionalways => {
                if (source != .engine) return error.UnsupportedBuilderSelection;
            },
            .default, .maxprofit => {},
        }
    }

    fn proposeDuty(self: *BlockService, io: Io, duty: ProposerDuty) !bool {
        // Safety checks: syncing status and doppelganger protection.
        if (!self.isSafeToSign(duty.pubkey)) {
            log.warn("skipping block proposal slot={d} validator_index={d}: signing not safe (syncing or doppelganger check pending)", .{ duty.slot, duty.validator_index });
            return false;
        }

        log.info("proposing block slot={d} validator_index={d}", .{ duty.slot, duty.validator_index });
        const builder_selection = self.validator_store.getBuilderSelectionParams(duty.pubkey);

        // 1. Compute RANDAO reveal: sign(epoch) with DOMAIN_RANDAO.
        const epoch = duty.slot / self.slots_per_epoch;
        const randao_reveal = try self.produceRandaoReveal(io, duty.pubkey, epoch);

        // 2. Request unsigned block from BN as SSZ.
        //    The v3 endpoint returns an unsigned BeaconBlock as SSZ.
        //    When builder is enabled, the BN may return a blinded block
        //    (Eth-Execution-Payload-Blinded: true header) if the builder relay
        //    provided a better bid than the local execution payload.
        const block_resp = try self.api.produceBlockSsz(
            io,
            duty.slot,
            randao_reveal,
            self.validator_store.getGraffiti(duty.pubkey),
            .{
                .fee_recipient = self.validator_store.getFeeRecipient(duty.pubkey),
                .builder_selection = builder_selection.selection,
                .builder_boost_factor = builder_selection.boost_factor,
                .strict_fee_recipient_check = self.validator_store.strictFeeRecipientCheck(duty.pubkey),
                .blinded_local = self.blinded_local,
            },
        );
        defer self.allocator.free(block_resp.block_ssz);

        const fork_name = block_resp.forkNameStr();
        const fork_seq = ForkSeq.fromName(fork_name);
        const block_type: BlockType = if (block_resp.blinded) .blinded else .full;

        log.debug("received unsigned block ssz_len={d} fork={s} blinded={}", .{
            block_resp.block_ssz.len, fork_name, block_resp.blinded,
        });
        try ensureBuilderSelectionSatisfied(
            builder_selection.selection,
            block_resp.execution_payload_source,
        );

        // 3. Deserialize the unsigned BeaconBlock from SSZ.
        //    The v3 endpoint returns an unsigned BeaconBlock (not SignedBeaconBlock).
        //    We wrap it as a SignedBeaconBlock with a zero signature for deserialization
        //    using AnySignedBeaconBlock.deserialize, then set the real signature after signing.
        //
        //    SSZ layout of SignedBeaconBlock:
        //      [4-byte offset to message] [signature: 96 bytes] [BeaconBlock SSZ bytes]
        //    The fixed area is 4 + 96 = 100 bytes, so the offset value is always 100.
        const signed_ssz_len = 4 + 96 + block_resp.block_ssz.len;
        const signed_ssz = try self.allocator.alloc(u8, signed_ssz_len);
        defer self.allocator.free(signed_ssz);

        // Build a SignedBeaconBlock with zero signature for deserialization.
        std.mem.writeInt(u32, signed_ssz[0..4], 100, .little);
        @memset(signed_ssz[4..100], 0);
        @memcpy(signed_ssz[100..signed_ssz_len], block_resp.block_ssz);

        const any_signed = AnySignedBeaconBlock.deserialize(
            self.allocator,
            block_type,
            fork_seq,
            signed_ssz,
        ) catch |err| {
            log.err("failed to deserialize block SSZ fork={s}: {s}", .{ fork_name, @errorName(err) });
            return err;
        };
        defer any_signed.deinit(self.allocator);

        const any_block = any_signed.beaconBlock();
        try enforceStrictFeeRecipient(
            any_block.beaconBlockBody(),
            self.validator_store.getFeeRecipient(duty.pubkey),
            self.validator_store.strictFeeRecipientCheck(duty.pubkey),
        );

        // 4. Compute body_root = hashTreeRoot(block.body) and build BeaconBlockHeader.
        var body_root: [32]u8 = undefined;
        try any_block.beaconBlockBody().hashTreeRoot(self.allocator, &body_root);

        var signing_root: [32]u8 = undefined;
        const block_header = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = duty.slot,
            .proposer_index = any_block.proposerIndex(),
            .parent_root = any_block.parentRoot().*,
            .state_root = any_block.stateRoot().*,
            .body_root = body_root,
        };
        try signing_mod.blockHeaderSigningRoot(self.signing_ctx, &block_header, &signing_root);

        // 5. Sign block.
        const block_sig = try self.validator_store.signBlock(io, duty.pubkey, signing_root, duty.slot);
        const sig_bytes = block_sig.compress();

        // 6. Stamp the real signature into the SSZ buffer.
        //    The signature occupies bytes [4..100) in the SignedBeaconBlock SSZ.
        @memcpy(signed_ssz[4..100], &sig_bytes);

        // 7. Publish: blinded blocks go to /eth/v2/beacon/blinded_blocks;
        //    full blocks go to /eth/v2/beacon/blocks.
        if (block_resp.blinded) {
            log.info("publishing blinded block slot={d} validator_index={d} fork={s}", .{
                duty.slot, duty.validator_index, fork_name,
            });
            try self.api.publishBlindedBlockSsz(io, signed_ssz, fork_name, self.broadcast_validation);
        } else {
            try self.api.publishBlockSsz(io, signed_ssz, fork_name, self.broadcast_validation);
        }
        log.info("published block slot={d} validator_index={d} fork={s} blinded={}", .{
            duty.slot, duty.validator_index, fork_name, block_resp.blinded,
        });
        self.metrics.block_proposed_total.incr();
        self.metrics.block_delay_seconds.observe(self.slotDelaySeconds(io, duty.slot));
        return true;
    }

    /// Check for missed block proposals in a completed epoch.
    ///
    /// Called before replacing the current epoch duties with the next epoch's duties.
    fn checkMissedDuties(self: *BlockService) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        for (self.duties.items) |cached| {
            if (!cached.produced) {
                self.missed_block_count += 1;
                self.metrics.block_missed_total.incr();
                log.warn(
                    "missed block proposal slot={d} validator_index={d} (total_missed={d})",
                    .{ cached.duty.slot, cached.duty.validator_index, self.missed_block_count },
                );
            }
        }
    }

    fn slotDelaySeconds(self: *const BlockService, io: Io, slot: u64) f64 {
        const slot_start_ns = (self.genesis_time_unix_secs * std.time.ns_per_s) + (slot * self.seconds_per_slot * std.time.ns_per_s);
        const now_ns = time.realNanoseconds(io);
        if (now_ns <= slot_start_ns) return 0.0;
        return @as(f64, @floatFromInt(now_ns - slot_start_ns)) / @as(f64, std.time.ns_per_s);
    }

    fn hasTrackedValidator(self: *const BlockService, pubkey: [48]u8) bool {
        return self.validator_store.hasPubkey(pubkey);
    }

    fn wasProduced(self: *const BlockService, duty: ProposerDuty) bool {
        const mutex_ptr: *std.Io.Mutex = @constCast(&self.cache_mutex);
        mutex_ptr.lockUncancelable(self.io);
        defer mutex_ptr.unlock(self.io);

        if (self.duties_epoch == null) return false;

        for (self.duties.items) |cached| {
            if (cached.duty.slot == duty.slot and
                cached.duty.validator_index == duty.validator_index and
                std.mem.eql(u8, &cached.duty.pubkey, &duty.pubkey))
            {
                return cached.produced;
            }
        }

        return false;
    }

    fn isLastSlotOfEpoch(self: *const BlockService, slot: u64) bool {
        return (slot + 1) % self.slots_per_epoch == 0;
    }

    fn hasCurrentEpochDuties(self: *BlockService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.duties_epoch != null and self.duties_epoch.? == epoch;
    }

    fn hasNextEpochDuties(self: *BlockService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.next_duties_epoch != null and self.next_duties_epoch.? == epoch;
    }

    fn snapshotDutiesForSlot(self: *BlockService, slot: u64) ![]CachedProposerDuty {
        const epoch = slot / self.slots_per_epoch;

        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.duties_epoch == null or self.duties_epoch.? != epoch) {
            return self.allocator.alloc(CachedProposerDuty, 0);
        }

        var count: usize = 0;
        for (self.duties.items) |cached| {
            if (cached.duty.slot == slot) count += 1;
        }

        const snapshot = try self.allocator.alloc(CachedProposerDuty, count);
        var index: usize = 0;
        for (self.duties.items) |cached| {
            if (cached.duty.slot != slot) continue;
            snapshot[index] = cached;
            index += 1;
        }
        return snapshot;
    }

    fn markProduced(self: *BlockService, duty: ProposerDuty, produced: bool) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        for (self.duties.items) |*cached| {
            if (cached.duty.slot != duty.slot) continue;
            if (cached.duty.validator_index != duty.validator_index) continue;
            if (!std.mem.eql(u8, &cached.duty.pubkey, &duty.pubkey)) continue;
            cached.produced = produced;
            return;
        }
    }

    fn activatePrefetchedEpoch(self: *BlockService, epoch: u64) bool {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.next_duties_epoch == null or self.next_duties_epoch.? != epoch) return false;

        if (self.duties_epoch) |prev_epoch| {
            if (prev_epoch + 1 == epoch) {
                self.checkMissedDutiesLocked();
            }
        }

        const old_current = self.duties;
        self.duties = self.next_duties;
        self.duties_epoch = epoch;
        self.next_duties = std.array_list.Managed(CachedProposerDuty).init(self.allocator);
        self.next_duties_epoch = null;
        old_current.deinit();
        return true;
    }

    fn replaceCurrentDuties(
        self: *BlockService,
        epoch: u64,
        refreshed: std.array_list.Managed(CachedProposerDuty),
    ) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        const old = self.duties;
        self.duties = refreshed;
        self.duties_epoch = epoch;
        old.deinit();
    }

    fn replaceNextDuties(
        self: *BlockService,
        epoch: u64,
        prefetched: std.array_list.Managed(CachedProposerDuty),
    ) void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        const old = self.next_duties;
        self.next_duties = prefetched;
        self.next_duties_epoch = epoch;
        old.deinit();
    }

    fn checkMissedDutiesLocked(self: *BlockService) void {
        for (self.duties.items) |cached| {
            if (!cached.produced) {
                self.missed_block_count += 1;
                self.metrics.block_missed_total.incr();
                log.warn(
                    "missed block proposal slot={d} validator_index={d} (total_missed={d})",
                    .{ cached.duty.slot, cached.duty.validator_index, self.missed_block_count },
                );
            }
        }
    }

    fn produceRandaoReveal(self: *BlockService, io: Io, pubkey: [48]u8, epoch: u64) ![96]u8 {
        var signing_root: [32]u8 = undefined;
        try signing_mod.randaoSigningRoot(self.signing_ctx, epoch, &signing_root);
        const sig = try self.validator_store.signRandao(io, pubkey, signing_root);
        return sig.compress();
    }
};

fn enforceStrictFeeRecipient(
    body: AnyBeaconBlockBody,
    expected_fee_recipient: [20]u8,
    strict_fee_recipient_check: bool,
) !void {
    if (!strict_fee_recipient_check or !body.isExecutionType()) return;

    const actual_fee_recipient = switch (body.blockType()) {
        .full => (try body.executionPayload()).feeRecipient().*,
        .blinded => (try body.executionPayloadHeader()).feeRecipient(),
    };

    ensureExpectedFeeRecipient(
        actual_fee_recipient,
        expected_fee_recipient,
        strict_fee_recipient_check,
    ) catch |err| {
        log.err("produced block fee recipient mismatch expected=0x{s} actual=0x{s}", .{
            std.fmt.bytesToHex(&expected_fee_recipient, .lower),
            std.fmt.bytesToHex(&actual_fee_recipient, .lower),
        });
        return err;
    };
}

const testing = std.testing;

test "enforceStrictFeeRecipient allows mismatch when strict checking is disabled" {
    try testing.expectError(error.FeeRecipientMismatch, ensureExpectedFeeRecipient(
        [_]u8{0x11} ** 20,
        [_]u8{0x22} ** 20,
        true,
    ));
    try ensureExpectedFeeRecipient(
        [_]u8{0x11} ** 20,
        [_]u8{0x22} ** 20,
        false,
    );
}

test "ensureExpectedFeeRecipient accepts matching fee recipients" {
    try ensureExpectedFeeRecipient(
        [_]u8{0x33} ** 20,
        [_]u8{0x33} ** 20,
        true,
    );
}

fn ensureExpectedFeeRecipient(
    actual_fee_recipient: [20]u8,
    expected_fee_recipient: [20]u8,
    strict_fee_recipient_check: bool,
) !void {
    if (!strict_fee_recipient_check or std.mem.eql(u8, &actual_fee_recipient, &expected_fee_recipient)) {
        return;
    }
    return error.FeeRecipientMismatch;
}
