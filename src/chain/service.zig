//! Chain write/service surface.
//!
//! This is the typed ingress for state-changing operations. Runtime adapters
//! should call into this surface rather than reaching through the chain to
//! mutate pools, caches, and storage directly.

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");

const Chain = @import("chain.zig").Chain;
const chain_types = @import("types.zig");
const chain_effects = @import("effects.zig");
const Query = @import("query.zig").Query;
const produce_block = @import("produce_block.zig");
const ProducedBlockBody = produce_block.ProducedBlockBody;
const ProducedBlock = produce_block.ProducedBlock;
const BlockProductionConfig = produce_block.BlockProductionConfig;
const BlobsBundle = produce_block.BlobsBundle;
const proposer_cache_mod = @import("beacon_proposer_cache.zig");

const CachedBeaconState = state_transition.CachedBeaconState;
const Root = [32]u8;
const Slot = consensus_types.primitive.Slot.Type;
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;
const KZGCommitment = consensus_types.primitive.KZGCommitment.Type;
const SignedVoluntaryExit = consensus_types.phase0.SignedVoluntaryExit.Type;
const ProposerSlashing = consensus_types.phase0.ProposerSlashing.Type;
const AttesterSlashing = consensus_types.phase0.AttesterSlashing.Type;
const SignedBLSToExecutionChange = consensus_types.capella.SignedBLSToExecutionChange.Type;
const SyncCommitteeContribution = consensus_types.altair.SyncCommitteeContribution.Type;
const Eth1Data = consensus_types.phase0.Eth1Data;
const Eth1DataType = Eth1Data.Type;
const ExecutionPayload = consensus_types.electra.ExecutionPayload.Type;
const BLSSignature = consensus_types.primitive.BLSSignature.Type;

pub const Service = struct {
    chain: *Chain,

    pub fn init(chain: *Chain) Service {
        return .{ .chain = chain };
    }

    pub fn query(self: Service) Query {
        return Query.init(self.chain);
    }

    pub fn importBlock(
        self: Service,
        any_signed: fork_types.AnySignedBeaconBlock,
        source: chain_types.BlockSource,
    ) !chain_effects.ImportOutcome {
        const result = try self.chain.importBlock(any_signed, source);
        const snapshot = self.query().currentSnapshot();

        return .{
            .result = result,
            .snapshot = snapshot,
            .effects = .{
                .notify_forkchoice_update_root = snapshot.head.root,
                .archive_state = if (result.epoch_transition)
                    .{
                        .slot = result.slot,
                        .state_root = result.state_root,
                    }
                else
                    null,
                .finalized_checkpoint = if (result.epoch_transition)
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn bootstrapFromGenesis(
        self: Service,
        genesis_state: *CachedBeaconState,
    ) !chain_effects.BootstrapOutcome {
        const bootstrap = try self.chain.bootstrapFromGenesis(genesis_state);
        return .{
            .snapshot = self.query().currentSnapshot(),
            .genesis_time = bootstrap.genesis_time,
            .genesis_validators_root = bootstrap.genesis_validators_root,
        };
    }

    pub fn bootstrapFromCheckpoint(
        self: Service,
        checkpoint_state: *CachedBeaconState,
    ) !chain_effects.BootstrapOutcome {
        const bootstrap = try self.chain.bootstrapFromCheckpoint(checkpoint_state);
        return .{
            .snapshot = self.query().currentSnapshot(),
            .genesis_time = bootstrap.genesis_time,
            .genesis_validators_root = bootstrap.genesis_validators_root,
        };
    }

    pub fn importAttestation(
        self: Service,
        attestation_slot: u64,
        committee_index: u64,
        beacon_block_root: Root,
        target_root: Root,
        target_epoch: u64,
        validator_index: ValidatorIndex,
        attestation: fork_types.AnyAttestation,
    ) !void {
        try self.chain.importAttestation(
            attestation_slot,
            committee_index,
            beacon_block_root,
            target_root,
            target_epoch,
            validator_index,
            attestation,
        );
    }

    pub fn applyAttestationVote(
        self: Service,
        validator_index: ValidatorIndex,
        attestation_slot: Slot,
        beacon_block_root: Root,
        target_epoch: u64,
    ) !void {
        if (self.chain.fork_choice) |fc| {
            try fc.onSingleVote(
                self.chain.allocator,
                @intCast(validator_index),
                attestation_slot,
                beacon_block_root,
                target_epoch,
            );
        }
    }

    pub fn importVoluntaryExit(self: Service, exit: SignedVoluntaryExit) !void {
        try self.chain.op_pool.voluntary_exit_pool.add(exit);
    }

    pub fn importProposerSlashing(self: Service, slashing: ProposerSlashing) !void {
        try self.chain.op_pool.proposer_slashing_pool.add(slashing);
    }

    pub fn importAttesterSlashing(self: Service, slashing: AttesterSlashing) !void {
        try self.chain.op_pool.attester_slashing_pool.add(slashing);
    }

    pub fn importBlsChange(self: Service, change: SignedBLSToExecutionChange) !void {
        try self.chain.op_pool.bls_change_pool.add(change);
    }

    pub fn importSyncContribution(
        self: Service,
        contribution: *const SyncCommitteeContribution,
    ) !void {
        const pool = self.chain.sync_contribution_pool orelse return;
        try pool.add(contribution);
    }

    pub fn importSyncCommitteeMessage(
        self: Service,
        subnet: u64,
        slot: Slot,
        beacon_block_root: Root,
        index_in_subcommittee: u64,
        signature: BLSSignature,
    ) !void {
        const pool = self.chain.sync_committee_message_pool orelse return;
        try pool.add(subnet, slot, beacon_block_root, index_in_subcommittee, signature);
    }

    pub fn importBlobSidecar(self: Service, root: Root, data: []const u8) !void {
        try self.chain.importBlobSidecar(root, data);
    }

    pub fn importDataColumnSidecar(
        self: Service,
        root: Root,
        column_index: u64,
        data: []const u8,
    ) !void {
        try self.chain.db.putDataColumn(root, column_index, data);
    }

    pub fn archiveState(self: Service, slot: Slot, state_root: Root) !void {
        try self.chain.archiveState(slot, state_root);
    }

    pub fn updateBeaconProposerData(
        self: Service,
        epoch: u64,
        preparations: []const proposer_cache_mod.ProposerPreparation,
    ) !void {
        for (preparations) |preparation| {
            try self.setBeaconProposerData(
                epoch,
                preparation.validator_index,
                preparation.fee_recipient,
            );
        }
    }

    pub fn setBeaconProposerData(
        self: Service,
        epoch: u64,
        validator_index: u64,
        fee_recipient: [20]u8,
    ) !void {
        try self.chain.beacon_proposer_cache.add(epoch, validator_index, fee_recipient);
    }

    pub fn produceBlock(self: Service, slot: Slot) !ProducedBlockBody {
        return self.chain.produceBlock(slot);
    }

    pub fn assembleBlock(
        self: Service,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        exec_payload: ExecutionPayload,
        blobs_bundle: ?BlobsBundle,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        eth1_data: Eth1DataType,
        config: BlockProductionConfig,
    ) !ProducedBlock {
        return produce_block.assembleBlock(
            self.chain.allocator,
            slot,
            proposer_index,
            parent_root,
            self.chain.op_pool,
            exec_payload,
            blobs_bundle,
            block_value,
            blob_commitments,
            eth1_data,
            config,
            self.chain.sync_contribution_pool,
        );
    }

    pub fn produceFullBlockWithPayload(
        self: Service,
        slot: Slot,
        exec_payload: ExecutionPayload,
        blobs_bundle: ?BlobsBundle,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        config: BlockProductionConfig,
    ) !ProducedBlock {
        const chain_query = self.query();
        const head = chain_query.head();
        const head_state = chain_query.headState();

        var eth1_data = Eth1Data.default_value;
        if (head_state) |cached| {
            const state_eth1 = cached.state.eth1Data() catch null;
            if (state_eth1) |eth1_view| {
                eth1_data.deposit_root = (eth1_view.getFieldRoot("deposit_root") catch &std.mem.zeroes([32]u8)).*;
                eth1_data.deposit_count = eth1_view.get("deposit_count") catch 0;
                eth1_data.block_hash = (eth1_view.getFieldRoot("block_hash") catch &std.mem.zeroes([32]u8)).*;
            }
        }

        var proposer_index: ValidatorIndex = 0;
        if (head_state) |cached| {
            proposer_index = cached.getBeaconProposer(slot) catch 0;
        }

        return self.assembleBlock(
            slot,
            proposer_index,
            head.root,
            exec_payload,
            blobs_bundle,
            block_value,
            blob_commitments,
            eth1_data,
            config,
        );
    }

    pub fn pruneSyncCommitteePools(self: Service, head_slot: Slot) void {
        if (self.chain.sync_contribution_pool) |pool| pool.prune(head_slot);
        if (self.chain.sync_committee_message_pool) |pool| pool.prune(head_slot);
    }

    pub fn onSlot(self: Service, slot: Slot) void {
        self.chain.onSlot(slot);
    }

    pub fn advanceSlot(self: Service, slot: Slot) !void {
        try self.chain.advanceSlot(slot);
    }
};
