//! Deterministic block generator for simulation testing.
//!
//! Generates structurally valid Electra beacon blocks with stub signatures,
//! suitable for state transition testing with `verify_signatures: false`.
//! Block contents are controlled by a deterministic PRNG so that the same
//! seed always produces identical blocks.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const ssz = @import("ssz");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");

const CachedBeaconState = state_transition.CachedBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyBeaconState = fork_types.AnyBeaconState;
const BeaconBlock = fork_types.BeaconBlock;
const BeaconBlockBody = fork_types.BeaconBlockBody;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;
const Slot = types.primitive.Slot.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const BlockOpts = struct {
    /// Use an incorrect proposer index (for rejection testing).
    wrong_proposer: bool = false,
    /// Use an incorrect parent root (for rejection testing).
    wrong_parent: bool = false,
};

pub const BlockGenerator = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,

    pub fn init(allocator: Allocator, seed: u64) BlockGenerator {
        return .{
            .allocator = allocator,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    /// Generate a valid signed beacon block for the given target slot.
    ///
    /// The block is structurally valid (correct proposer, parent root,
    /// execution payload timestamp) but uses zero signatures.  Pass
    /// `verify_signatures: false` to the state transition.
    ///
    /// Caller owns the returned block and must call `deinit` on it.
    pub fn generateBlock(
        self: *BlockGenerator,
        cached_state: *CachedBeaconState,
        target_slot: Slot,
    ) !*types.electra.SignedBeaconBlock.Type {
        return self.generateBlockWithOpts(cached_state, target_slot, .{});
    }

    /// Generate a block with specific characteristics for testing.
    pub fn generateBlockWithOpts(
        self: *BlockGenerator,
        cached_state: *CachedBeaconState,
        target_slot: Slot,
        opts: BlockOpts,
    ) !*types.electra.SignedBeaconBlock.Type {
        const state = cached_state.state;
        const epoch_cache = cached_state.epoch_cache;

        // Determine the correct proposer for the target slot.
        const proposer_index = epoch_cache.getBeaconProposer(target_slot) catch 0;

        // Compute parent root from latest block header.
        var latest_header = try state.latestBlockHeader();
        const parent_root = try latest_header.hashTreeRoot();

        // Compute expected execution payload timestamp.
        const genesis_time = try state.genesisTime();
        const seconds_per_slot = cached_state.config.chain.SECONDS_PER_SLOT;
        const expected_timestamp = genesis_time + target_slot * seconds_per_slot;

        // Build a minimal but valid execution payload.
        var execution_payload = types.electra.ExecutionPayload.default_value;
        execution_payload.timestamp = expected_timestamp;

        // Set the execution payload parent_hash to the latest block hash
        // so processExecutionPayload's isMergeTransitionComplete check passes.
        const latest_block_hash = state.latestExecutionPayloadHeaderBlockHash() catch &([_]u8{0} ** 32);
        execution_payload.parent_hash = latest_block_hash.*;

        // Set prev_randao to the current epoch's randao mix.
        const current_epoch = state_transition.computeEpochAtSlot(target_slot);
        const randao_mix = try state_transition.getRandaoMix(
            .electra,
            state.castToFork(.electra),
            current_epoch,
        );
        execution_payload.prev_randao = randao_mix.*;

        // Build the signed block.
        const signed_block = try self.allocator.create(types.electra.SignedBeaconBlock.Type);
        errdefer self.allocator.destroy(signed_block);

        signed_block.* = .{
            .message = .{
                .slot = target_slot,
                .proposer_index = if (opts.wrong_proposer)
                    proposer_index +% 1
                else
                    proposer_index,
                .parent_root = if (opts.wrong_parent) blk: {
                    var bad_root: [32]u8 = undefined;
                    self.prng.random().bytes(&bad_root);
                    break :blk bad_root;
                } else parent_root.*,
                .state_root = [_]u8{0} ** 32, // Filled by state transition or skipped.
                .body = .{
                    .randao_reveal = [_]u8{0} ** 96,
                    .eth1_data = types.phase0.Eth1Data.default_value,
                    .graffiti = [_]u8{0} ** 32,
                    .proposer_slashings = types.phase0.ProposerSlashings.default_value,
                    .attester_slashings = types.phase0.AttesterSlashings.default_value,
                    .attestations = types.electra.Attestations.default_value,
                    .deposits = types.phase0.Deposits.default_value,
                    .voluntary_exits = types.phase0.VoluntaryExits.default_value,
                    .sync_aggregate = .{
                        .sync_committee_bits = ssz.BitVectorType(preset.SYNC_COMMITTEE_SIZE).default_value,
                        .sync_committee_signature = types.primitive.BLSSignature.default_value,
                    },
                    .execution_payload = execution_payload,
                    .bls_to_execution_changes = types.capella.SignedBLSToExecutionChanges.default_value,
                    .blob_kzg_commitments = types.electra.BlobKzgCommitments.default_value,
                    .execution_requests = types.electra.ExecutionRequests.default_value,
                },
            },
            .signature = types.primitive.BLSSignature.default_value,
        };

        return signed_block;
    }
};
