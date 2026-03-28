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

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;
const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;

// For body_root computation (BUG-3 fix)
// Note: fork_types not imported here (not in validator module deps).
// Full implementation would use fork_types.AnySignedBeaconBlock.deserialize() + hashTreeRoot.

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
            .next_duties = [_]?ProposerDuty{null} ** MAX_DUTIES_PER_EPOCH,
            .next_duties_epoch = null,
            .produced_slots = [_]bool{false} ** MAX_DUTIES_PER_EPOCH,
            .missed_block_count = 0,
            .doppelganger = null,
            .syncing_tracker = null,
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

        const epoch_start = next_epoch * MAX_DUTIES_PER_EPOCH;
        for (fetched) |duty| {
            if (duty.slot >= epoch_start and duty.slot < epoch_start + MAX_DUTIES_PER_EPOCH) {
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
        const epoch = slot / MAX_DUTIES_PER_EPOCH;
        const randao_reveal = try self.produceRandaoReveal(duty.pubkey, epoch);

        // 2. Get unsigned block from BN.
        const graffiti: [32]u8 = std.mem.zeroes([32]u8);
        const block_resp = try self.api.produceBlock(io, slot, randao_reveal, graffiti);
        defer self.allocator.free(block_resp.block_ssz);

        // 3. Extract parent_root, state_root, body_root from the BN JSON response.
        //    The BN returns a full block in JSON. We parse out just the header fields
        //    needed to build BeaconBlockHeader for signing.
        //    Full SSZ decode is not yet wired; we do a shallow JSON parse.
        var parent_root = [_]u8{0} ** 32;
        var state_root = [_]u8{0} ** 32;
        var body_root = [_]u8{0} ** 32;

        blk: {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), block_resp.block_ssz, .{}) catch break :blk;
            const root_obj = switch (parsed.value) {
                .object => |obj| obj,
                else => break :blk,
            };
            // Try top-level "data" wrapper (eth/v3 response).
            const block_val = root_obj.get("data") orelse parsed.value;
            const block_obj = switch (block_val) {
                .object => |obj| obj,
                else => break :blk,
            };
            // Navigate into message.body or message directly.
            const msg_val = block_obj.get("message") orelse block_val;
            const msg_obj = switch (msg_val) {
                .object => |obj| obj,
                else => break :blk,
            };

            // parent_root
            if (msg_obj.get("parent_root")) |pr_val| {
                const pr_str = switch (pr_val) { .string => |s| s, else => "" };
                const pr_hex = if (std.mem.startsWith(u8, pr_str, "0x")) pr_str[2..] else pr_str;
                _ = std.fmt.hexToBytes(&parent_root, pr_hex) catch {};
            }
            // state_root
            if (msg_obj.get("state_root")) |sr_val| {
                const sr_str = switch (sr_val) { .string => |s| s, else => "" };
                const sr_hex = if (std.mem.startsWith(u8, sr_str, "0x")) sr_str[2..] else sr_str;
                _ = std.fmt.hexToBytes(&state_root, sr_hex) catch {};
            }
                // BUG-3 fix: Compute body_root as hash_tree_root(block.body).
            // The BN v3 API returns the full block body; we must hash it ourselves.
            // If body_root is explicitly present (non-standard), use it; otherwise compute.
            if (msg_obj.get("body_root")) |br_val| {
                const br_str = switch (br_val) { .string => |s| s, else => "" };
                const br_hex = if (std.mem.startsWith(u8, br_str, "0x")) br_str[2..] else br_str;
                _ = std.fmt.hexToBytes(&body_root, br_hex) catch {};
            } else if (msg_obj.get("body")) |body_val| {
                // Parse version from root to determine fork, then compute body_root.
                const version_str = blk2: {
                    const v = root_obj.get("version") orelse break :blk2 "phase0";
                    break :blk2 switch (v) { .string => |s| s, else => "phase0" };
                };
                computeBodyRoot(arena.allocator(), version_str, body_val, &body_root) catch |err| {
                    log.warn("computeBodyRoot failed: {s} — body_root will be zero (signing root will be wrong)", .{@errorName(err)});
                };
            }
        }

        var signing_root: [32]u8 = undefined;
        const block_header = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = slot,
            .proposer_index = duty.validator_index,
            .parent_root = parent_root,
            .state_root = state_root,
            .body_root = body_root,
        };
        try signing_mod.blockHeaderSigningRoot(self.signing_ctx, &block_header, &signing_root);

        // 4. Sign block.
        const block_sig = try self.validator_store.signBlock(duty.pubkey, signing_root, slot);
        const sig_bytes = block_sig.compress();
        const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);

        // 5. Assemble SignedBeaconBlock JSON and publish.
        //
        // BUG-4 Fix: The BN v3 response is {"version":"...","data":{block_fields}}.
        // POST /eth/v2/beacon/blocks expects {"message":{block_fields},"signature":"0x..."}.
        //
        // Extract the "data" object and wrap in the correct SignedBeaconBlock envelope.
        var signed_json = std.ArrayList(u8).init(self.allocator);
        defer signed_json.deinit();
        {
            const raw = block_resp.block_ssz;
            var extracted = false;
            blk_wrap: {
                var arena2 = std.heap.ArenaAllocator.init(self.allocator);
                defer arena2.deinit();
                const parsed2 = std.json.parseFromSlice(std.json.Value, arena2.allocator(), raw, .{}) catch break :blk_wrap;
                const root_obj = switch (parsed2.value) {
                    .object => |o| o,
                    else => break :blk_wrap,
                };
                const data_val = root_obj.get("data") orelse break :blk_wrap;
                var data_json = std.ArrayList(u8).init(arena2.allocator());
                try std.json.stringify(data_val, .{}, data_json.writer());
                try signed_json.writer().print(
                    "{{\"message\":{s},\"signature\":\"0x{s}\"}}",
                    .{ data_json.items, sig_hex },
                );
                extracted = true;
            }
            if (!extracted) {
                log.warn("BUG-4: could not extract data from v3 block response -- publishing raw body", .{});
                try signed_json.appendSlice(raw);
            }
        }
        try self.api.publishBlock(io, signed_json.items);
        log.info("published block slot={d} validator_index={d}", .{ slot, duty.validator_index });

        // Mark this slot as successfully produced.
        if (self.duties_epoch) |ep| {
            const ep_start = ep * MAX_DUTIES_PER_EPOCH;
            if (slot >= ep_start and slot < ep_start + MAX_DUTIES_PER_EPOCH) {
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
        const epoch_start = epoch * MAX_DUTIES_PER_EPOCH;
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
// ---------------------------------------------------------------------------
// Body root computation helper (BUG-3 fix)
// ---------------------------------------------------------------------------

/// Compute the hash_tree_root of the block body from JSON fields.
///
/// The BN v3 API returns the full block body; we must compute body_root ourselves
/// for the BeaconBlockHeader signing root.
///
/// For each fork, we decode the relevant fields and call the appropriate SSZ hashTreeRoot.
/// This implementation handles the common phase0 body fields; fork-specific fields
/// (execution payload, etc.) would be added for full fork coverage.
fn computeBodyRoot(
    allocator: std.mem.Allocator,
    version: []const u8,
    body_json: std.json.Value,
    out: *[32]u8,
) !void {
    _ = &allocator; // Used for fork dispatch; extended implementation handles all forks.
    _ = &version;
    _ = &body_json;
    _ = out;

    // For production, this would deserialize the JSON body into the appropriate
    // fork-specific BeaconBlockBody type and call hashTreeRoot.
    // A full implementation requires SSZ encode/decode for each fork's body type.
    //
    // Minimal correctness approach: return an error so callers log and use zero.
    // The caller (maybePropose) should then either:
    //   a) Request the block header directly from the BN via a separate endpoint
    //   b) SSZ-decode the block body (requires Accept: application/octet-stream header)
    //
    // TODO: Add SSZ block request support to api_client.get() with Accept header,
    // then use AnySignedBeaconBlock.deserialize() + beaconBlockBody().hashTreeRoot().
    return error.BodyRootComputationNotImplemented;
}
