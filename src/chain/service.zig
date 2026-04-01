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

pub const ReadyBlockInput = chain_types.ReadyBlockInput;
pub const RawBlockBytes = chain_types.RawBlockBytes;
pub const BlockIngressReadiness = chain_types.BlockIngressReadiness;
pub const BlockIngressResult = chain_types.BlockIngressResult;

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

    pub fn importRawBlockBytes(
        self: Service,
        block_bytes: []const u8,
        source: chain_types.BlockSource,
    ) !chain_effects.ImportOutcome {
        const slot = try readBlockSlot(block_bytes);
        var any_signed = try deserializeRawBlockBytes(self.chain, slot, block_bytes);
        defer any_signed.deinit(self.chain.allocator);
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        return self.importReadyBlock(readyBlockInput(
            any_signed,
            source,
            block_root,
            self.dataAvailabilityStatusForBlock(block_root, any_signed),
            0,
        ));
    }

    pub fn importReadyBlock(
        self: Service,
        ready: ReadyBlockInput,
    ) !chain_effects.ImportOutcome {
        const result = try self.chain.importReadyBlock(ready);
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

    pub fn processRangeSyncSegment(
        self: Service,
        raw_blocks: []const RawBlockBytes,
    ) !chain_effects.SegmentImportOutcome {
        const before_snapshot = self.query().currentSnapshot();
        if (raw_blocks.len == 0) {
            return .{
                .imported_count = 0,
                .skipped_count = 0,
                .failed_count = 0,
                .snapshot = before_snapshot,
                .effects = .{
                    .notify_forkchoice_update_root = before_snapshot.head.root,
                },
            };
        }

        const allocator = self.chain.allocator;
        const decoded_blocks = try allocator.alloc(fork_types.AnySignedBeaconBlock, raw_blocks.len);
        defer allocator.free(decoded_blocks);
        var decoded_count: usize = 0;
        defer {
            for (decoded_blocks[0..decoded_count]) |*any_signed| {
                any_signed.deinit(allocator);
            }
        }

        const block_inputs = try allocator.alloc(chain_types.BlockInput, raw_blocks.len);
        defer allocator.free(block_inputs);

        for (raw_blocks, 0..) |raw_block, i| {
            const any_signed = try deserializeRawBlockBytes(self.chain, raw_block.slot, raw_block.bytes);
            decoded_blocks[i] = any_signed;
            decoded_count = i + 1;
            const block_root = try hashBlock(allocator, any_signed);
            block_inputs[i] = .{
                .block = any_signed,
                .source = .range_sync,
                .da_status = self.dataAvailabilityStatusForBlock(block_root, any_signed),
            };
        }

        const results = try self.chain.processBlockBatchPipeline(block_inputs, .{
            .from_range_sync = true,
            .skip_execution = true,
            .skip_future_slot = true,
            .skip_signatures = !self.chain.verify_signatures,
        });
        defer allocator.free(results);

        var imported_count: usize = 0;
        var skipped_count: usize = 0;
        var failed_count: usize = 0;
        var archive_states_builder: std.ArrayListUnmanaged(chain_effects.ArchiveStateRequest) = .empty;
        defer archive_states_builder.deinit(allocator);

        for (results) |result| {
            switch (result) {
                .success => |import_result| {
                    imported_count += 1;
                    if (import_result.epoch_transition) {
                        try archive_states_builder.append(allocator, .{
                            .slot = import_result.slot,
                            .state_root = import_result.state_root,
                        });
                    }
                },
                .skipped => skipped_count += 1,
                .failed => failed_count += 1,
            }
        }

        const snapshot = self.query().currentSnapshot();
        const archive_states = if (archive_states_builder.items.len == 0)
            &[_]chain_effects.ArchiveStateRequest{}
        else
            try archive_states_builder.toOwnedSlice(allocator);

        return .{
            .imported_count = imported_count,
            .skipped_count = skipped_count,
            .failed_count = failed_count,
            .snapshot = snapshot,
            .effects = .{
                .notify_forkchoice_update_root = snapshot.head.root,
                .archive_states = archive_states,
                .finalized_checkpoint = if (snapshot.finalized.epoch != before_snapshot.finalized.epoch or
                    !std.mem.eql(u8, &snapshot.finalized.root, &before_snapshot.finalized.root))
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn acceptGossipBlock(
        self: Service,
        any_signed: fork_types.AnySignedBeaconBlock,
        seen_timestamp_sec: u64,
    ) !BlockIngressResult {
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        const da_status = pipelineDaStatus(self.chain, block_root, any_signed);

        if (self.chain.pending_da_blocks) |pending| {
            const ready = try pending.onBlock(
                any_signed,
                block_root,
                any_signed.beaconBlock().slot(),
                .gossip,
                seen_timestamp_sec,
                da_status,
            );
            if (ready) |block| return .{ .ready = block };
            if (self.chain.da_manager) |dam| {
                dam.markPending(block_root, any_signed.beaconBlock().slot()) catch |err| {
                    pending.removePending(block_root);
                    return err;
                };
            }
            return .{ .pending_data = block_root };
        }

        return .{ .ready = readyBlockInput(any_signed, .gossip, block_root, da_status, seen_timestamp_sec) };
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
        validator_index: ValidatorIndex,
        attestation: fork_types.AnyAttestation,
    ) !void {
        try self.chain.importAttestation(
            validator_index,
            attestation,
        );
    }

    pub fn importAggregate(
        self: Service,
        attestation: fork_types.AnyAttestation,
        attesting_indices: []const ValidatorIndex,
    ) !void {
        const data = attestation.data();

        if (self.chain.fork_choice) |fc| {
            for (attesting_indices) |validator_index| {
                fc.onSingleVote(
                    self.chain.allocator,
                    validator_index,
                    data.slot,
                    data.beacon_block_root,
                    data.target.epoch,
                ) catch |err| {
                    std.log.warn("FC onAggregate failed for validator {d} slot {d}: {}", .{
                        validator_index, data.slot, err,
                    });
                };
            }
        }

        _ = try self.chain.op_pool.agg_attestation_pool.addAny(attestation);
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

    pub fn ingestBlobSidecars(
        self: Service,
        root: Root,
        slot: Slot,
        data: []const u8,
        blob_indices: []const u64,
    ) !?ReadyBlockInput {
        try self.chain.importBlobSidecar(root, data);
        const dam = self.chain.da_manager orelse return null;
        const pending = self.chain.pending_da_blocks orelse return null;

        var available = false;
        for (blob_indices) |blob_index| {
            available = dam.onBlobSidecar(root, blob_index, slot) or available;
        }

        if (!available) return null;
        return pending.onDataAvailable(root, .available);
    }

    pub fn ingestBlobSidecar(
        self: Service,
        root: Root,
        blob_index: u64,
        slot: Slot,
        data: []const u8,
    ) !?ReadyBlockInput {
        try self.chain.importBlobSidecar(root, data);
        const dam = self.chain.da_manager orelse return null;
        const pending = self.chain.pending_da_blocks orelse return null;
        if (!dam.onBlobSidecar(root, blob_index, slot)) return null;
        return pending.onDataAvailable(root, .available);
    }

    pub fn importDataColumnSidecar(
        self: Service,
        root: Root,
        column_index: u64,
        data: []const u8,
    ) !void {
        try self.chain.importDataColumnSidecar(root, column_index, data);
    }

    pub fn ingestDataColumnSidecar(
        self: Service,
        root: Root,
        column_index: u64,
        slot: Slot,
        data: []const u8,
    ) !?ReadyBlockInput {
        try self.chain.importDataColumnSidecar(root, column_index, data);
        const dam = self.chain.da_manager orelse return null;
        const pending = self.chain.pending_da_blocks orelse return null;
        if (!dam.onDataColumnSidecar(root, column_index, slot)) return null;
        return pending.onDataAvailable(root, .available);
    }

    pub fn dataAvailabilityStatusForBlock(
        self: Service,
        block_root: Root,
        any_signed: fork_types.AnySignedBeaconBlock,
    ) chain_types.DataAvailabilityStatus {
        return pipelineDaStatus(self.chain, block_root, any_signed);
    }

    pub fn ingressReadinessForBlock(
        self: Service,
        block_root: Root,
        any_signed: fork_types.AnySignedBeaconBlock,
    ) BlockIngressReadiness {
        return pipelineIngressReadiness(self.chain, block_root, any_signed);
    }

    pub fn missingBlobSidecars(
        self: Service,
        allocator: std.mem.Allocator,
        block_root: Root,
    ) ![]u64 {
        const dam = self.chain.da_manager orelse return error.MissingDaManager;
        return dam.getMissingBlobs(allocator, block_root);
    }

    pub fn missingDataColumns(
        self: Service,
        allocator: std.mem.Allocator,
        block_root: Root,
    ) ![]u64 {
        const dam = self.chain.da_manager orelse return error.MissingDaManager;
        return dam.getMissingColumns(allocator, block_root);
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

fn hashBlock(allocator: std.mem.Allocator, any_signed: fork_types.AnySignedBeaconBlock) !Root {
    var block_root: Root = undefined;
    try any_signed.beaconBlock().hashTreeRoot(allocator, &block_root);
    return block_root;
}

fn readBlockSlot(block_bytes: []const u8) !Slot {
    if (block_bytes.len < 4) return error.MalformedBlockBytes;
    const msg_offset = std.mem.readInt(u32, block_bytes[0..4], .little);
    if (block_bytes.len < @as(usize, msg_offset) + 8) return error.MalformedBlockBytes;
    return std.mem.readInt(u64, block_bytes[msg_offset..][0..8], .little);
}

fn deserializeRawBlockBytes(
    chain: *Chain,
    slot: Slot,
    block_bytes: []const u8,
) !fork_types.AnySignedBeaconBlock {
    return fork_types.AnySignedBeaconBlock.deserialize(
        chain.allocator,
        .full,
        chain.config.forkSeq(slot),
        block_bytes,
    );
}

fn readyBlockInput(
    any_signed: fork_types.AnySignedBeaconBlock,
    source: chain_types.BlockSource,
    block_root: Root,
    da_status: chain_types.DataAvailabilityStatus,
    seen_timestamp_sec: u64,
) ReadyBlockInput {
    return .{
        .block = any_signed,
        .source = source,
        .block_root = block_root,
        .slot = any_signed.beaconBlock().slot(),
        .da_status = da_status,
        .seen_timestamp_sec = seen_timestamp_sec,
    };
}

fn pipelineDaStatus(
    chain: *Chain,
    block_root: Root,
    any_signed: fork_types.AnySignedBeaconBlock,
) chain_types.DataAvailabilityStatus {
    return pipelineIngressReadiness(chain, block_root, any_signed).da_status;
}

fn pipelineIngressReadiness(
    chain: *Chain,
    block_root: Root,
    any_signed: fork_types.AnySignedBeaconBlock,
) BlockIngressReadiness {
    const block = any_signed.beaconBlock();
    const slot = block.slot();
    const fork = any_signed.forkSeq();
    const blob_commitments = block.beaconBlockBody().blobKzgCommitments() catch {
        return .{
            .da_status = .not_required,
            .attachment_requirement = .none,
        };
    };
    const blob_count: u32 = @intCast(blob_commitments.items.len);

    if (fork.lt(.deneb)) {
        return .{
            .da_status = .not_required,
            .attachment_requirement = .none,
        };
    }
    if (blob_count == 0) {
        return .{
            .da_status = .available,
            .attachment_requirement = .none,
        };
    }

    const attachment_requirement: chain_types.BlockAttachmentRequirement = if (fork.gte(.fulu))
        .columns
    else
        .blobs;

    if (chain.da_manager) |dam| {
        if (chain.currentWallSlot()) |wall_slot| {
            if (slot < dam.daWindowMinSlot(wall_slot)) {
                return .{
                    .da_status = .out_of_range,
                    .attachment_requirement = .none,
                };
            }
        }

        const da_status: chain_types.DataAvailabilityStatus = switch (dam.checkBlockDataAvailability(block_root, slot, fork, blob_count).status) {
            .available, .reconstruction_possible => .available,
            .not_required => .not_required,
            .missing_blobs, .missing_columns => .pending,
        };
        return .{
            .da_status = da_status,
            .attachment_requirement = if (da_status == .pending) attachment_requirement else .none,
        };
    }

    return .{
        .da_status = .pending,
        .attachment_requirement = attachment_requirement,
    };
}
