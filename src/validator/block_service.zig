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
const types = @import("types.zig");
const ProposerDuty = types.ProposerDuty;
const BeaconApiClient = @import("api_client.zig").BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const log = std.log.scoped(.block_service);

/// Maximum duties cached per epoch.
const MAX_DUTIES_PER_EPOCH: usize = 32; // SLOTS_PER_EPOCH

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

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        signing_ctx: SigningContext,
    ) BlockService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .signing_ctx = signing_ctx,
            .duties = [_]?ProposerDuty{null} ** MAX_DUTIES_PER_EPOCH,
            .duties_epoch = null,
        };
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
        self.refreshDuties(io, epoch) catch |err| {
            log.err("refreshDuties epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
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

        // Clear existing duties.
        for (&self.duties) |*d| d.* = null;
        self.duties_epoch = epoch;

        // Index duties by slot (within-epoch offset).
        const epoch_start = epoch * MAX_DUTIES_PER_EPOCH;
        for (fetched) |duty| {
            if (duty.slot >= epoch_start and duty.slot < epoch_start + MAX_DUTIES_PER_EPOCH) {
                const offset = duty.slot - epoch_start;
                if (offset < MAX_DUTIES_PER_EPOCH) {
                    self.duties[offset] = duty;
                }
            }
        }

        log.debug("cached {d} proposer duties for epoch {d}", .{ fetched.len, epoch });
    }

    // -----------------------------------------------------------------------
    // Block proposal
    // -----------------------------------------------------------------------

    fn maybePropose(self: *BlockService, io: Io, slot: u64) !void {
        const duty = self.getDutyAtSlot(slot) orelse return; // nothing to do

        log.info("proposing block slot={d} validator_index={d}", .{ slot, duty.validator_index });

        // 1. Compute RANDAO reveal: sign(epoch) with DOMAIN_RANDAO.
        const epoch = slot / MAX_DUTIES_PER_EPOCH;
        const randao_reveal = try self.produceRandaoReveal(duty.pubkey, epoch);

        // 2. Get unsigned block from BN.
        const graffiti: [32]u8 = std.mem.zeroes([32]u8);
        const block_resp = try self.api.produceBlock(io, slot, randao_reveal, graffiti);
        defer self.allocator.free(block_resp.block_ssz);

        // 3. Compute block signing root using DOMAIN_BEACON_PROPOSER.
        //    The BN returns the block as JSON; we sign the BeaconBlockHeader
        //    (slot, proposer_index, parent_root, state_root, body_root).
        //    For now we produce a placeholder header from the duty.
        //    Full implementation would SSZ-decode the block and hash the header.
        var signing_root: [32]u8 = undefined;
        const block_header = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = slot,
            .proposer_index = duty.validator_index,
            .parent_root = [_]u8{0} ** 32, // TODO: extract from block_resp
            .state_root = [_]u8{0} ** 32,  // TODO: filled by BN
            .body_root = [_]u8{0} ** 32,   // TODO: compute from block body
        };
        try signing_mod.blockHeaderSigningRoot(self.signing_ctx, &block_header, &signing_root);

        // 4. Sign block.
        const block_sig = try self.validator_store.signBlock(duty.pubkey, signing_root, slot);
        const sig_bytes = block_sig.compress();
        _ = sig_bytes;

        // 5. Assemble signed block — stub: publish raw block JSON for now.
        //    Full implementation: SSZ-encode SignedBeaconBlock{message, signature}.
        const signed_block_ssz: []const u8 = block_resp.block_ssz;
        try self.api.publishBlock(io, signed_block_ssz);
        log.info("published block slot={d}", .{slot});
    }

    fn getDutyAtSlot(self: *const BlockService, slot: u64) ?ProposerDuty {
        const epoch = self.duties_epoch orelse return null;
        const epoch_start = epoch * MAX_DUTIES_PER_EPOCH;
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
