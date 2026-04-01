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
const ForkSeq = @import("config").ForkSeq;
const BlockType = fork_types.BlockType;
const types = @import("types.zig");
const ProposerDuty = types.ProposerDuty;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;
const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;

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
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,
    /// Signing context (fork_version + genesis_validators_root) for domain computation.
    signing_ctx: SigningContext,
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

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
        slots_per_epoch: u64,
    ) BlockService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
            .duties = std.array_list.Managed(CachedProposerDuty).init(allocator),
            .duties_epoch = null,
            .next_duties = std.array_list.Managed(CachedProposerDuty).init(allocator),
            .next_duties_epoch = null,
            .missed_block_count = 0,
            .doppelganger = null,
            .syncing_tracker = null,
            .slots_per_epoch = slots_per_epoch,
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
        // If next epoch duties were pre-fetched, swap them in.
        if (self.next_duties_epoch) |ne| {
            if (ne == epoch) {
                if (self.duties_epoch) |prev_epoch| {
                    if (prev_epoch + 1 == epoch) {
                        self.checkMissedDuties();
                    }
                }

                self.duties.deinit();
                self.duties = self.next_duties;
                self.duties_epoch = ne;
                self.next_duties = std.array_list.Managed(CachedProposerDuty).init(self.allocator);
                self.next_duties_epoch = null;
                log.debug("swapped pre-fetched proposer duties into epoch={d}", .{epoch});
                return;
            }
        }

        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    /// Called at each slot to check for a block proposal duty.
    ///
    /// TS: BlockDutiesService first notifies from cache, then refreshes duties,
    /// then notifies any newly discovered proposers for the same slot.
    pub fn onSlot(self: *BlockService, io: Io, slot: u64) void {
        self.maybePropose(io, slot);
    }

    /// Remove any cached proposer duties for the given validator pubkey.
    ///
    /// Used when a validator is removed at runtime so stale proposer duties do not
    /// trigger failed proposal attempts later in the epoch.
    pub fn removeDutiesForKey(self: *BlockService, pubkey: [48]u8) void {
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

        self.duties.deinit();
        self.duties = refreshed;
        self.duties_epoch = epoch;

        log.debug("cached {d} proposer duties for epoch {d}", .{ self.duties.items.len, epoch });
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

        self.next_duties.deinit();
        self.next_duties = prefetched;
        self.next_duties_epoch = next_epoch;

        log.debug("pre-fetched {d} proposer duties for epoch {d}", .{ self.next_duties.items.len, next_epoch });
    }

    // -----------------------------------------------------------------------
    // Block proposal
    // -----------------------------------------------------------------------

    fn maybePropose(self: *BlockService, io: Io, slot: u64) void {
        // Notify from cached duties first so block production can start immediately.
        self.proposeCachedDutiesAtSlot(io, slot);

        // Then refresh proposer duties for the current epoch and notify again.
        // Produced markers prevent double-proposal of duties that were already handled.
        const epoch = slot / self.slots_per_epoch;
        self.refreshDuties(io, epoch) catch |err| {
            log.warn("refreshDuties slot={d} epoch={d} error={s}", .{ slot, epoch, @errorName(err) });
            if (self.isLastSlotOfEpoch(slot)) {
                self.prefetchNextEpochDuties(io, epoch + 1);
            }
            return;
        };
        self.proposeCachedDutiesAtSlot(io, slot);

        if (self.isLastSlotOfEpoch(slot)) {
            self.prefetchNextEpochDuties(io, epoch + 1);
        }
    }

    fn proposeCachedDutiesAtSlot(self: *BlockService, io: Io, slot: u64) void {
        var i: usize = 0;
        while (i < self.duties.items.len) : (i += 1) {
            const cached = &self.duties.items[i];
            if (cached.produced or cached.duty.slot != slot) continue;

            const produced = self.proposeDuty(io, cached.duty) catch |err| {
                log.err("proposeDuty slot={d} validator_index={d} error={s}", .{
                    slot,
                    cached.duty.validator_index,
                    @errorName(err),
                });
                continue;
            };

            cached.produced = produced;
        }
    }

    fn proposeDuty(self: *BlockService, io: Io, duty: ProposerDuty) !bool {
        // Safety checks: syncing status and doppelganger protection.
        if (!self.isSafeToSign(duty.pubkey)) {
            log.warn("skipping block proposal slot={d} validator_index={d}: signing not safe (syncing or doppelganger check pending)", .{ duty.slot, duty.validator_index });
            return false;
        }

        log.info("proposing block slot={d} validator_index={d}", .{ duty.slot, duty.validator_index });

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
            self.validator_store.getBuilderBoostFactor(duty.pubkey),
        );
        defer self.allocator.free(block_resp.block_ssz);

        const fork_name = block_resp.forkNameStr();
        const fork_seq = ForkSeq.fromName(fork_name);
        const block_type: BlockType = if (block_resp.blinded) .blinded else .full;

        log.debug("received unsigned block ssz_len={d} fork={s} blinded={}", .{
            block_resp.block_ssz.len, fork_name, block_resp.blinded,
        });

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
            try self.api.publishBlindedBlockSsz(io, signed_ssz, fork_name);
        } else {
            try self.api.publishBlockSsz(io, signed_ssz, fork_name);
        }
        log.info("published block slot={d} validator_index={d} fork={s} blinded={}", .{
            duty.slot, duty.validator_index, fork_name, block_resp.blinded,
        });
        return true;
    }

    /// Check for missed block proposals in a completed epoch.
    ///
    /// Called before replacing the current epoch duties with the next epoch's duties.
    fn checkMissedDuties(self: *BlockService) void {
        for (self.duties.items) |cached| {
            if (!cached.produced) {
                self.missed_block_count += 1;
                log.warn(
                    "missed block proposal slot={d} validator_index={d} (total_missed={d})",
                    .{ cached.duty.slot, cached.duty.validator_index, self.missed_block_count },
                );
            }
        }
    }

    fn hasTrackedValidator(self: *const BlockService, pubkey: [48]u8) bool {
        for (self.validator_store.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return true;
        }
        return false;
    }

    fn wasProduced(self: *const BlockService, duty: ProposerDuty) bool {
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

    fn produceRandaoReveal(self: *BlockService, io: Io, pubkey: [48]u8, epoch: u64) ![96]u8 {
        var signing_root: [32]u8 = undefined;
        try signing_mod.randaoSigningRoot(self.signing_ctx, epoch, &signing_root);
        const sig = try self.validator_store.signRandao(io, pubkey, signing_root);
        return sig.compress();
    }
};
