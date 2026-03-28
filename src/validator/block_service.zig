//! Block proposal service for the Validator Client.
//!
//! Tracks proposer duties per epoch and submits blocks when our validators
//! are scheduled to propose.
//!
//! TS equivalent: packages/validator/src/services/block.ts (BlockProposingService)
//!               + packages/validator/src/services/blockDuties.ts (BlockDutiesService)
//!
//! Data flow:
//!   1. Each epoch: fetch proposer duties from BN for current + next epoch.
//!   2. At each slot start: check if we have a duty for this slot.
//!   3. If yes: produceBlock → sign (RANDAO + block) → publishBlock.

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

/// Maximum duties cached per epoch (upper bound; runtime value from slots_per_epoch).
const MAX_DUTIES_PER_EPOCH: usize = 64; // upper bound; actual value from config.slots_per_epoch

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
    duties: [MAX_DUTIES_PER_EPOCH]?ProposerDuty,
    duties_epoch: ?u64,
    /// Pre-fetched duties for the next epoch (swap at epoch boundary).
    next_duties: [MAX_DUTIES_PER_EPOCH]?ProposerDuty,
    next_duties_epoch: ?u64,
    /// Slots for which we had a duty and produced a block (bitmask per epoch).
    produced_slots: [MAX_DUTIES_PER_EPOCH]bool,
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
            .duties = [_]?ProposerDuty{null} ** MAX_DUTIES_PER_EPOCH,
            .duties_epoch = null,
            .next_duties = [_]?ProposerDuty{null} ** MAX_DUTIES_PER_EPOCH,
            .next_duties_epoch = null,
            .produced_slots = [_]bool{false} ** MAX_DUTIES_PER_EPOCH,
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
        _ = self;
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
                self.duties = self.next_duties;
                self.duties_epoch = ne;
                self.next_duties = [_]?ProposerDuty{null} ** MAX_DUTIES_PER_EPOCH;
                self.next_duties_epoch = null;
                for (&self.produced_slots) |*p| p.* = false;
                log.debug("swapped pre-fetched proposer duties into epoch={d}", .{epoch});
                // Still pre-fetch for epoch+1.
                self.prefetchNextEpochDuties(io, epoch + 1);
                return;
            }
        }
        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
        // Pre-fetch next epoch duties immediately.
        self.prefetchNextEpochDuties(io, epoch + 1);
    }

    /// Called at each slot to check for a block proposal duty.
    ///
    /// TS: BlockDutiesService notifyBlockProductionFn → BlockProposingService.createAndPublishBlock
    pub fn onSlot(self: *BlockService, io: Io, slot: u64) void {
        self.maybePropose(io, slot) catch |err| {
            log.err("maybePropose slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Duty management
    // -----------------------------------------------------------------------

    fn refreshDuties(self: *BlockService, io: Io, epoch: u64) !void {
        log.debug("fetching proposer duties for epoch {d}", .{epoch});

        const fetched = try self.api.getProposerDuties(io, epoch);
        defer self.allocator.free(fetched);

        // Before clearing: check if any slot from the previous epoch was missed.
        if (self.duties_epoch) |prev_epoch| {
            if (prev_epoch + 1 == epoch) {
                // We have complete info for prev_epoch — check for misses.
                self.checkMissedSlots(prev_epoch);
            }
        }

        // Clear existing duties.
        for (&self.duties) |*d| d.* = null;
        for (&self.produced_slots) |*p| p.* = false;
        self.duties_epoch = epoch;

        // Index duties by slot (within-epoch offset).
        const epoch_start = epoch * self.slots_per_epoch;
        for (fetched) |duty| {
            if (duty.slot >= epoch_start and duty.slot < epoch_start + self.slots_per_epoch) {
                const offset = duty.slot - epoch_start;
                if (offset < MAX_DUTIES_PER_EPOCH) {
                    self.duties[offset] = duty;
                }
            }
        }

        log.debug("cached {d} proposer duties for epoch {d}", .{ fetched.len, epoch });
    }

    /// Pre-fetch proposer duties for the next epoch to reduce latency at epoch boundaries.
    ///
    /// TS: BlockDutiesService fetches N+1 at end of epoch N.
    fn prefetchNextEpochDuties(self: *BlockService, io: Io, next_epoch: u64) void {
        log.debug("pre-fetching proposer duties for epoch {d}", .{next_epoch});
        const fetched = self.api.getProposerDuties(io, next_epoch) catch |err| {
            log.warn("prefetch proposer duties epoch={d} error={s}", .{ next_epoch, @errorName(err) });
            return;
        };
        defer self.allocator.free(fetched);

        for (&self.next_duties) |*d| d.* = null;
        self.next_duties_epoch = next_epoch;

        const epoch_start = next_epoch * self.slots_per_epoch;
        for (fetched) |duty| {
            if (duty.slot >= epoch_start and duty.slot < epoch_start + self.slots_per_epoch) {
                const offset = duty.slot - epoch_start;
                if (offset < MAX_DUTIES_PER_EPOCH) {
                    self.next_duties[offset] = duty;
                }
            }
        }
        log.debug("pre-fetched {d} proposer duties for epoch {d}", .{ fetched.len, next_epoch });
    }

    // -----------------------------------------------------------------------
    // Block proposal
    // -----------------------------------------------------------------------

    fn maybePropose(self: *BlockService, io: Io, slot: u64) !void {
        const duty = self.getDutyAtSlot(slot) orelse return; // nothing to do

        // Safety checks: syncing status and doppelganger protection.
        if (!self.isSafeToSign(duty.pubkey)) {
            log.warn("skipping block proposal slot={d} validator_index={d}: signing not safe (syncing or doppelganger check pending)", .{ slot, duty.validator_index });
            return;
        }

        log.info("proposing block slot={d} validator_index={d}", .{ slot, duty.validator_index });

        // 1. Compute RANDAO reveal: sign(epoch) with DOMAIN_RANDAO.
        const epoch = slot / self.slots_per_epoch;
        const randao_reveal = try self.produceRandaoReveal(duty.pubkey, epoch);

        // 2. Request unsigned block from BN as SSZ.
        //    Using SSZ avoids JSON body_root computation entirely — we deserialize
        //    the block, compute body_root via hashTreeRoot, and publish as SSZ.
        const graffiti: [32]u8 = std.mem.zeroes([32]u8);
        const block_resp = try self.api.produceBlockSsz(io, slot, randao_reveal, graffiti);
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
        std.mem.writeInt(u32, signed_ssz[0..4], 100, .little); // offset to message
        @memset(signed_ssz[4..100], 0); // zero signature placeholder
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
            .slot = slot,
            .proposer_index = duty.validator_index,
            .parent_root = any_block.parentRoot().*,
            .state_root = any_block.stateRoot().*,
            .body_root = body_root,
        };
        try signing_mod.blockHeaderSigningRoot(self.signing_ctx, &block_header, &signing_root);

        // 5. Sign block.
        const block_sig = try self.validator_store.signBlock(duty.pubkey, signing_root, slot);
        const sig_bytes = block_sig.compress();

        // 6. Stamp the real signature into the SSZ buffer and publish.
        //    The signature occupies bytes [4..100) in the SignedBeaconBlock SSZ.
        @memcpy(signed_ssz[4..100], &sig_bytes);

        // 7. Publish as SSZ.
        try self.api.publishBlockSsz(io, signed_ssz, fork_name);
        log.info("published block slot={d} validator_index={d} fork={s}", .{ slot, duty.validator_index, fork_name });

        // Mark this slot as successfully produced.
        if (self.duties_epoch) |ep| {
            const ep_start = ep * self.slots_per_epoch;
            if (slot >= ep_start and slot < ep_start + self.slots_per_epoch) {
                self.produced_slots[slot - ep_start] = true;
            }
        }
    }

    /// Check for missed block proposals in a completed epoch.
    ///
    /// Called at the start of each new epoch with the previous epoch number.
    ///
    /// TS: BlockDutiesService marks missed blocks via blockDuties tracking.
    fn checkMissedSlots(self: *BlockService, epoch: u64) void {
        const epoch_start = epoch * self.slots_per_epoch;
        for (self.duties, self.produced_slots, 0..) |maybe_duty, produced, i| {
            if (maybe_duty) |duty| {
                if (!produced) {
                    // We had a duty for this slot but did not produce.
                    const missed_slot = epoch_start + i;
                    self.missed_block_count += 1;
                    log.warn(
                        "missed block proposal slot={d} validator_index={d} (total_missed={d})",
                        .{ missed_slot, duty.validator_index, self.missed_block_count },
                    );
                }
            }
        }
    }

    fn getDutyAtSlot(self: *const BlockService, slot: u64) ?ProposerDuty {
        const epoch = self.duties_epoch orelse return null;
        const epoch_start = epoch * self.slots_per_epoch;
        if (slot < epoch_start or slot >= epoch_start + MAX_DUTIES_PER_EPOCH) return null;
        const offset = slot - epoch_start;
        const duty = self.duties[offset] orelse return null;

        // Check if any of our validators are the proposer.
        for (self.validator_store.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &duty.pubkey)) return duty;
        }
        return null;
    }

    fn produceRandaoReveal(self: *BlockService, pubkey: [48]u8, epoch: u64) ![96]u8 {
        var signing_root: [32]u8 = undefined;
        try signing_mod.randaoSigningRoot(self.signing_ctx, epoch, &signing_root);
        const sig = try self.validator_store.signRandao(pubkey, signing_root);
        return sig.compress();
    }
};

