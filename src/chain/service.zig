//! Chain write/service surface.
//!
//! This is the typed ingress for state-changing operations. Runtime adapters
//! should call into this surface rather than reaching through the chain to
//! mutate pools, caches, and storage directly.

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const fork_choice_mod = @import("fork_choice");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const StateGraphGate = @import("regen/root.zig").StateGraphGate;

const Chain = @import("chain.zig").Chain;
const chain_types = @import("types.zig");
const chain_effects = @import("effects.zig");
const ports = @import("ports/root.zig");
const blocks = @import("blocks/root.zig");
const Query = @import("query.zig").Query;
const produce_block = @import("produce_block.zig");
const blob_kzg_verification = @import("blob_kzg_verification.zig");
const payload_envelope_ingress_mod = @import("payload_envelope_ingress.zig");
const ProducedBlockBody = produce_block.ProducedBlockBody;
const ProposalSnapshot = produce_block.ProposalSnapshot;
const PreparedProposalTemplate = produce_block.PreparedProposalTemplate;
const ProducedBlock = produce_block.ProducedBlock;
const ProducedBlindedBlock = produce_block.ProducedBlindedBlock;
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
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const SignedBLSToExecutionChange = consensus_types.capella.SignedBLSToExecutionChange.Type;
const SyncCommitteeContribution = consensus_types.altair.SyncCommitteeContribution.Type;
const Eth1Data = consensus_types.phase0.Eth1Data;
const Eth1DataType = Eth1Data.Type;
const ExecutionPayload = consensus_types.electra.ExecutionPayload.Type;
const ExecutionPayloadHeader = consensus_types.deneb.ExecutionPayloadHeader.Type;
const ExecutionRequests = consensus_types.electra.ExecutionRequests.Type;
const BLSSignature = consensus_types.primitive.BLSSignature.Type;
const BlobVerifyInput = blob_kzg_verification.BlobVerifyInput;
const BYTES_PER_CELL = blob_kzg_verification.BYTES_PER_CELL;
const HeadResult = fork_choice_mod.HeadResult;
const LVHExecResponse = fork_choice_mod.LVHExecResponse;
pub const PlannedBlockImport = @import("blocks/root.zig").PlannedBlockImport;
pub const CompletedBlockImport = @import("state_work_service.zig").CompletedBlockImport;
pub const CompletedBlockImportWaitResult = @import("state_work_service.zig").StateWorkService.WaitResult;
pub const PreparedBlockImport = @import("blocks/root.zig").PreparedBlockImport;
pub const ExecutionStatus = blocks.ExecutionStatus;

fn eth1DataFromHeadState(cached: *CachedBeaconState) Eth1DataType {
    var eth1_data = Eth1Data.default_value;
    const state_eth1 = cached.state.eth1Data() catch return eth1_data;
    eth1_data.deposit_root = (state_eth1.getFieldRoot("deposit_root") catch &std.mem.zeroes([32]u8)).*;
    eth1_data.deposit_count = state_eth1.get("deposit_count") catch 0;
    eth1_data.block_hash = (state_eth1.getFieldRoot("block_hash") catch &std.mem.zeroes([32]u8)).*;
    return eth1_data;
}

fn proposerPubkeyForSlot(
    allocator: std.mem.Allocator,
    cached: *CachedBeaconState,
    proposer_index: ValidatorIndex,
) ![48]u8 {
    var validators = try cached.state.validators();
    var validator: consensus_types.phase0.Validator.Type = undefined;
    try validators.getValue(allocator, proposer_index, &validator);
    return validator.pubkey;
}

fn prevRandaoForSlot(cached: *CachedBeaconState, slot: Slot) ![32]u8 {
    const epoch = slot / preset.SLOTS_PER_EPOCH;
    const randao_index = epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR;
    var mixes = try cached.state.randaoMixes();
    const mix_ptr = try mixes.getFieldRoot(randao_index);
    return mix_ptr.*;
}

pub const ReadyBlockInput = chain_types.ReadyBlockInput;
pub const RawBlockBytes = chain_types.RawBlockBytes;
pub const PlannedBlockIngress = chain_types.PlannedBlockIngress;
pub const BlockIngressReadiness = chain_types.BlockIngressReadiness;
pub const BlockDataFetchPlan = chain_types.BlockDataFetchPlan;
pub const BlockIngressResult = chain_types.BlockIngressResult;
pub const PayloadEnvelopeFetchPlan = payload_envelope_ingress_mod.PayloadEnvelopeFetchPlan;

pub const Service = struct {
    chain: *Chain,

    pub fn init(chain: *Chain) Service {
        return .{ .chain = chain };
    }

    pub fn query(self: Service) Query {
        return Query.init(self.chain);
    }

    pub fn acquireStateGraphLease(self: Service) StateGraphGate.Lease {
        return self.chain.acquireStateGraphLease();
    }

    fn forkchoiceUpdateForHead(self: Service, head_root: Root) ?chain_effects.ExecutionForkchoiceUpdate {
        const state = self.query().executionForkchoiceState(head_root) orelse return null;
        return .{
            .beacon_block_root = head_root,
            .state = state,
        };
    }
    pub fn prepareBlockInput(
        self: Service,
        any_signed: fork_types.AnySignedBeaconBlock,
        source: blocks.BlockSource,
    ) !ReadyBlockInput {
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        return readyBlockInput(
            any_signed,
            source,
            block_root,
            self.dataAvailabilityStatusForBlock(block_root, any_signed),
            0,
            .none,
        );
    }

    pub fn prepareRawBlockInput(
        self: Service,
        block_bytes: []const u8,
        source: blocks.BlockSource,
    ) !ReadyBlockInput {
        const slot = try readBlockSlot(block_bytes);
        const any_signed = try deserializeRawBlockBytes(self.chain, slot, block_bytes);
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        return readyBlockInput(
            any_signed,
            source,
            block_root,
            self.dataAvailabilityStatusForBlock(block_root, any_signed),
            0,
            .none,
        );
    }
    /// Consumes `ready`. On success, ownership transfers into the returned plan.
    /// On error, `ready` still owns its resources.
    pub fn planReadyBlockImport(
        self: Service,
        ready: *ReadyBlockInput,
    ) !PlannedBlockImport {
        return self.chain.planReadyBlockImport(ready);
    }

    /// Consumes `planned` on both success and failure.
    /// Returns `true` when queued for background STFN, `false` when the caller
    /// still owns `planned` and should fall back to synchronous execution.
    pub fn tryQueuePlannedReadyBlockImport(
        self: Service,
        planned: PlannedBlockImport,
    ) !bool {
        return self.chain.tryQueuePlannedReadyBlockImport(planned);
    }

    /// Consumes `planned`.
    pub fn executePlannedReadyBlockImportSync(
        self: Service,
        planned: PlannedBlockImport,
    ) CompletedBlockImport {
        return self.chain.executePlannedReadyBlockImportSync(planned);
    }

    /// Consumes `completed`.
    pub fn finishCompletedReadyBlockImport(
        self: Service,
        completed: CompletedBlockImport,
    ) !chain_effects.ImportOutcome {
        const result = try self.chain.finishCompletedReadyBlockImport(completed);
        const snapshot = self.query().currentSnapshot();

        return .{
            .result = result,
            .snapshot = snapshot,
            .effects = .{
                .forkchoice_update = self.forkchoiceUpdateForHead(snapshot.head.root),
                .finalized_checkpoint = if (result.epoch_transition)
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn finishPreparedReadyBlockImport(
        self: Service,
        prepared: *PreparedBlockImport,
        exec_status: ExecutionStatus,
    ) !chain_effects.ImportOutcome {
        const result = try self.chain.finishPreparedReadyBlockImport(prepared, exec_status);
        const snapshot = self.query().currentSnapshot();

        return .{
            .result = result,
            .snapshot = snapshot,
            .effects = .{
                .forkchoice_update = self.forkchoiceUpdateForHead(snapshot.head.root),
                .finalized_checkpoint = if (result.epoch_transition)
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn popCompletedReadyBlockImport(self: Service) ?CompletedBlockImport {
        return self.chain.popCompletedReadyBlockImport();
    }

    pub fn waitForCompletedReadyBlockImport(self: Service) CompletedBlockImportWaitResult {
        return self.chain.waitForCompletedReadyBlockImport();
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
                    .forkchoice_update = self.forkchoiceUpdateForHead(before_snapshot.head.root),
                },
            };
        }

        const allocator = self.chain.allocator;
        const block_inputs = try allocator.alloc(blocks.BlockInput, raw_blocks.len);
        defer allocator.free(block_inputs);

        var decoded_count: usize = 0;
        var handed_off_to_pipeline = false;
        defer if (!handed_off_to_pipeline) {
            for (block_inputs[0..decoded_count]) |*block_input| {
                block_input.block.deinit(allocator);
            }
        };

        for (raw_blocks, 0..) |raw_block, i| {
            const any_signed = try deserializeRawBlockBytes(self.chain, raw_block.slot, raw_block.bytes);
            const block_root = try hashBlock(allocator, any_signed);
            block_inputs[i] = .{
                .block = any_signed,
                .source = .range_sync,
                .da_status = self.dataAvailabilityStatusForBlock(block_root, any_signed),
            };
            decoded_count = i + 1;
        }

        const results = try self.chain.processBlockBatchPipeline(block_inputs, .{
            .from_range_sync = true,
            .skip_future_slot = true,
            .skip_signatures = !self.chain.verify_signatures,
        });
        handed_off_to_pipeline = true;
        defer allocator.free(results);

        var imported_count: usize = 0;
        var skipped_count: usize = 0;
        var failed_count: usize = 0;
        var optimistic_imported_count: usize = 0;
        var epoch_transition_count: usize = 0;
        var error_counts: chain_effects.BlockImportErrorCounts = .{};
        for (results) |result| {
            switch (result) {
                .success => |import_result| {
                    imported_count += 1;
                    if (import_result.execution_optimistic) optimistic_imported_count += 1;
                    if (import_result.epoch_transition) epoch_transition_count += 1;
                },
                .skipped => |reason| {
                    skipped_count += 1;
                    error_counts.incr(reason);
                },
                .failed => |err| {
                    failed_count += 1;
                    error_counts.incr(err);
                },
            }
        }

        const snapshot = self.query().currentSnapshot();

        return .{
            .imported_count = imported_count,
            .skipped_count = skipped_count,
            .failed_count = failed_count,
            .optimistic_imported_count = optimistic_imported_count,
            .epoch_transition_count = epoch_transition_count,
            .error_counts = error_counts,
            .snapshot = snapshot,
            .effects = .{
                .forkchoice_update = self.forkchoiceUpdateForHead(snapshot.head.root),
                .finalized_checkpoint = if (snapshot.finalized.epoch != before_snapshot.finalized.epoch or
                    !std.mem.eql(u8, &snapshot.finalized.root, &before_snapshot.finalized.root))
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn buildDeferredRangeSyncSegmentOutcome(
        self: Service,
        before_snapshot: chain_effects.ChainSnapshot,
        imported_count: usize,
        skipped_count: usize,
        failed_count: usize,
        optimistic_imported_count: usize,
        epoch_transition_count: usize,
        error_counts: chain_effects.BlockImportErrorCounts,
    ) chain_effects.SegmentImportOutcome {
        const snapshot = self.query().currentSnapshot();
        return .{
            .imported_count = imported_count,
            .skipped_count = skipped_count,
            .failed_count = failed_count,
            .optimistic_imported_count = optimistic_imported_count,
            .epoch_transition_count = epoch_transition_count,
            .error_counts = error_counts,
            .snapshot = snapshot,
            .effects = .{
                .forkchoice_update = self.forkchoiceUpdateForHead(snapshot.head.root),
                .finalized_checkpoint = if (snapshot.finalized.epoch != before_snapshot.finalized.epoch or
                    !std.mem.eql(u8, &snapshot.finalized.root, &before_snapshot.finalized.root))
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn planRawBlockIngress(
        self: Service,
        block_bytes: []const u8,
        slot_hint: ?Slot,
    ) !PlannedBlockIngress {
        const slot = slot_hint orelse try readBlockSlot(block_bytes);
        var any_signed = try deserializeRawBlockBytes(self.chain, slot, block_bytes);
        errdefer any_signed.deinit(self.chain.allocator);
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        return .{
            .any_signed = any_signed,
            .block_root = block_root,
            .slot = slot,
            .block_data_plan = try self.blockDataFetchPlan(self.chain.allocator, block_root, any_signed),
        };
    }

    pub fn acceptGossipBlock(
        self: Service,
        any_signed: fork_types.AnySignedBeaconBlock,
        seen_timestamp_sec: u64,
    ) !BlockIngressResult {
        const block_root = try hashBlock(self.chain.allocator, any_signed);
        const readiness = self.ingressReadinessForBlock(block_root, any_signed);
        const block_data_plan = try self.blockDataFetchPlan(self.chain.allocator, block_root, any_signed);

        if (self.chain.pending_block_ingress) |pending| {
            const ready = try pending.acceptBlock(
                any_signed,
                block_root,
                any_signed.beaconBlock().slot(),
                .gossip,
                block_data_plan,
                seen_timestamp_sec,
                readiness.da_status,
            );
            if (ready) |block| return .{ .ready = block };
            if (self.chain.da_manager) |dam| {
                dam.markPending(block_root, any_signed.beaconBlock().slot()) catch |err| {
                    pending.removePending(block_root);
                    return err;
                };
            }
            return .{ .pending_block_data = block_root };
        }

        return .{ .ready = readyBlockInput(any_signed, .gossip, block_root, readiness.da_status, seen_timestamp_sec, block_data_plan) };
    }

    pub fn bootstrapFromGenesis(
        self: Service,
        genesis_state: *CachedBeaconState,
    ) !chain_effects.BootstrapOutcome {
        const bootstrap = try self.chain.bootstrapFromGenesis(genesis_state);
        try self.chain.installForkChoice(bootstrap.fork_choice);
        return .{
            .snapshot = self.query().currentSnapshot(),
            .genesis_time = bootstrap.genesis_time,
            .genesis_validators_root = bootstrap.genesis_validators_root,
            .earliest_available_slot = bootstrap.earliest_available_slot,
        };
    }

    pub fn bootstrapFromCheckpoint(
        self: Service,
        checkpoint_state: *CachedBeaconState,
    ) !chain_effects.BootstrapOutcome {
        const bootstrap = try self.chain.bootstrapFromCheckpoint(checkpoint_state);
        try self.chain.installForkChoice(bootstrap.fork_choice);
        return .{
            .snapshot = self.query().currentSnapshot(),
            .genesis_time = bootstrap.genesis_time,
            .genesis_validators_root = bootstrap.genesis_validators_root,
            .earliest_available_slot = bootstrap.earliest_available_slot,
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

        for (attesting_indices) |validator_index| {
            _ = self.chain.onSingleVote(
                @intCast(validator_index),
                data.slot,
                data.beacon_block_root,
                data.target.epoch,
            ) catch |err| {
                std.log.debug("fork choice aggregate vote update failed for validator {d} at slot {d}: {}", .{
                    validator_index, data.slot, err,
                });
            };
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
        _ = try self.chain.onSingleVote(
            @intCast(validator_index),
            attestation_slot,
            beacon_block_root,
            target_epoch,
        );
    }

    pub fn importVoluntaryExit(self: Service, exit: SignedVoluntaryExit) !void {
        try self.chain.op_pool.voluntary_exit_pool.add(exit);
    }

    pub fn importProposerSlashing(self: Service, slashing: ProposerSlashing) !void {
        try self.chain.op_pool.proposer_slashing_pool.add(slashing);
    }

    pub fn importAttesterSlashing(self: Service, slashing: *const AnyAttesterSlashing) !void {
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
        const pending = self.chain.pending_block_ingress orelse return null;

        var available = false;
        for (blob_indices) |blob_index| {
            available = dam.onBlobSidecar(root, blob_index, slot) or available;
        }

        if (!available) return null;
        return pending.resolveAttachments(root, .available);
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
        const pending = self.chain.pending_block_ingress orelse return null;
        if (!dam.onBlobSidecar(root, blob_index, slot)) return null;
        return pending.resolveAttachments(root, .available);
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
        const pending = self.chain.pending_block_ingress orelse return null;
        if (!dam.onDataColumnSidecar(root, column_index, slot)) return null;
        return pending.resolveAttachments(root, .available);
    }

    pub fn trackPayloadEnvelope(
        self: Service,
        block_root: Root,
        slot: Slot,
        fetch_plan: PayloadEnvelopeFetchPlan,
    ) !void {
        const ingress = self.chain.payload_envelope_ingress orelse return error.MissingPayloadEnvelopeIngress;
        try ingress.putOrReplace(block_root, slot, fetch_plan);
    }

    pub fn clearPayloadEnvelope(self: Service, block_root: Root) void {
        const ingress = self.chain.payload_envelope_ingress orelse return;
        ingress.remove(block_root);
    }

    pub fn dataAvailabilityStatusForBlock(
        self: Service,
        block_root: Root,
        any_signed: fork_types.AnySignedBeaconBlock,
    ) blocks.DataAvailabilityStatus {
        return pipelineDaStatus(self.chain, block_root, any_signed);
    }

    pub fn ingressReadinessForBlock(
        self: Service,
        block_root: Root,
        any_signed: fork_types.AnySignedBeaconBlock,
    ) BlockIngressReadiness {
        return pipelineIngressReadiness(self.chain, block_root, any_signed);
    }

    pub fn blockDataFetchPlan(
        self: Service,
        allocator: std.mem.Allocator,
        block_root: Root,
        any_signed: fork_types.AnySignedBeaconBlock,
    ) !BlockDataFetchPlan {
        return switch (self.ingressReadinessForBlock(block_root, any_signed).data_requirement) {
            .none => .none,
            .blobs => blk: {
                const missing = try self.missingBlobSidecars(allocator, block_root);
                if (missing.len == 0) {
                    allocator.free(missing);
                    break :blk .{ .blobs = &[_]u64{} };
                }
                break :blk .{ .blobs = missing };
            },
            .columns => blk: {
                const missing = try self.missingDataColumns(allocator, block_root);
                if (missing.len == 0) {
                    allocator.free(missing);
                    break :blk .{ .columns = &[_]u64{} };
                }
                break :blk .{ .columns = missing };
            },
        };
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

    pub fn verifyBlobSidecar(self: Service, input: BlobVerifyInput) !void {
        const kzg = self.chain.kzg orelse return error.MissingKzgContext;
        try blob_kzg_verification.verifyBlobSidecar(kzg.*, input);
    }

    pub fn verifyDataColumnSidecar(
        self: Service,
        allocator: std.mem.Allocator,
        column_index: u64,
        commitments: []const [48]u8,
        cells: []const [BYTES_PER_CELL]u8,
        proofs: []const [48]u8,
    ) !void {
        const kzg = self.chain.kzg orelse return error.MissingKzgContext;
        try blob_kzg_verification.verifyDataColumnSidecar(
            allocator,
            kzg.*,
            column_index,
            commitments,
            cells,
            proofs,
        );
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
        execution_requests: ExecutionRequests,
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
            execution_requests,
            eth1_data,
            config,
            self.chain.sync_contribution_pool,
        );
    }

    pub fn assembleBlindedBlock(
        self: Service,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        exec_payload_header: ExecutionPayloadHeader,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        execution_requests: ExecutionRequests,
        eth1_data: Eth1DataType,
        config: BlockProductionConfig,
    ) !ProducedBlindedBlock {
        return produce_block.assembleBlindedBlock(
            self.chain.allocator,
            slot,
            proposer_index,
            parent_root,
            self.chain.op_pool,
            exec_payload_header,
            block_value,
            blob_commitments,
            execution_requests,
            eth1_data,
            config,
            self.chain.sync_contribution_pool,
        );
    }

    pub fn prepareProposalSnapshot(
        self: Service,
        slot: Slot,
    ) !ProposalSnapshot {
        const chain_query = self.query();
        const head = chain_query.head();
        const head_state = chain_query.headState() orelse return error.NoHeadState;
        const proposer_index = try head_state.getBeaconProposer(slot);
        const proposer_pubkey = try proposerPubkeyForSlot(self.chain.allocator, head_state, proposer_index);
        const execution_forkchoice = chain_query.executionForkchoiceState(head.root) orelse return error.NoExecutionHeadHash;

        return produce_block.prepareProposalSnapshot(
            slot,
            proposer_index,
            proposer_pubkey,
            head.root,
            execution_forkchoice.head_block_hash,
            try prevRandaoForSlot(head_state, slot),
            eth1DataFromHeadState(head_state),
        );
    }

    pub fn buildProposalTemplate(
        self: Service,
        snapshot: ProposalSnapshot,
        config: BlockProductionConfig,
    ) !PreparedProposalTemplate {
        return produce_block.buildProposalTemplate(
            self.chain.allocator,
            snapshot,
            self.chain.op_pool,
            config,
            self.chain.sync_contribution_pool,
        );
    }

    pub fn assemblePreparedBlock(
        self: Service,
        template: PreparedProposalTemplate,
        exec_payload: ExecutionPayload,
        blobs_bundle: ?BlobsBundle,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        execution_requests: ExecutionRequests,
    ) !ProducedBlock {
        return produce_block.assembleBlockFromTemplate(
            self.chain.allocator,
            template,
            exec_payload,
            blobs_bundle,
            block_value,
            blob_commitments,
            execution_requests,
        );
    }

    pub fn assemblePreparedBlindedBlock(
        self: Service,
        template: PreparedProposalTemplate,
        exec_payload_header: ExecutionPayloadHeader,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        execution_requests: ExecutionRequests,
    ) !ProducedBlindedBlock {
        return produce_block.assembleBlindedBlockFromTemplate(
            self.chain.allocator,
            template,
            exec_payload_header,
            block_value,
            blob_commitments,
            execution_requests,
        );
    }

    pub fn produceFullBlockWithPayload(
        self: Service,
        slot: Slot,
        exec_payload: ExecutionPayload,
        blobs_bundle: ?BlobsBundle,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        execution_requests: ExecutionRequests,
        config: BlockProductionConfig,
    ) !ProducedBlock {
        const snapshot = try self.prepareProposalSnapshot(slot);
        return self.assemblePreparedBlock(
            try self.buildProposalTemplate(snapshot, config),
            exec_payload,
            blobs_bundle,
            block_value,
            blob_commitments,
            execution_requests,
        );
    }

    pub fn produceBlindedBlockWithHeader(
        self: Service,
        slot: Slot,
        exec_payload_header: ExecutionPayloadHeader,
        block_value: u256,
        blob_commitments: std.ArrayListUnmanaged(KZGCommitment),
        execution_requests: ExecutionRequests,
        config: BlockProductionConfig,
    ) !ProducedBlindedBlock {
        const snapshot = try self.prepareProposalSnapshot(slot);
        return self.assemblePreparedBlindedBlock(
            try self.buildProposalTemplate(snapshot, config),
            exec_payload_header,
            block_value,
            blob_commitments,
            execution_requests,
        );
    }

    pub fn pruneSyncCommitteePools(self: Service, head_slot: Slot) void {
        if (self.chain.sync_contribution_pool) |pool| pool.prune(head_slot);
        if (self.chain.sync_committee_message_pool) |pool| pool.prune(head_slot);
    }

    pub fn onSlot(self: Service, slot: Slot) void {
        self.chain.onSlot(slot);
    }

    pub fn prepareCurrentOptimisticHeadRevalidation(self: Service) !?chain_effects.PreparedExecutionRevalidation {
        if (!self.chain.currentHeadExecutionOptimistic()) return null;

        const head_root = self.query().head().root;
        const block_bytes = (try self.query().blockBytesByRoot(head_root)) orelse return error.HeadBlockNotAvailable;
        defer self.chain.allocator.free(block_bytes);

        const slot = try readBlockSlot(block_bytes);
        var any_signed = try deserializeRawBlockBytes(self.chain, slot, block_bytes);
        defer any_signed.deinit(self.chain.allocator);

        const request = try ports.execution.makeNewPayloadRequest(self.chain.allocator, any_signed) orelse return null;
        return .{
            .pending = .{
                .target_head_root = head_root,
                .invalidate_from_parent_block_root = any_signed.beaconBlock().parentRoot().*,
            },
            .request = request,
        };
    }

    pub fn finishCurrentOptimisticHeadRevalidation(
        self: Service,
        pending: chain_effects.PendingExecutionRevalidation,
        result: ports.execution.NewPayloadResult,
    ) !?chain_effects.ExecutionRevalidationOutcome {
        if (!self.chain.currentHeadExecutionOptimistic()) return null;

        const old_head = self.query().head();
        if (!std.mem.eql(u8, &old_head.root, &pending.target_head_root)) return null;

        const fc = self.chain.forkChoice();
        const response: LVHExecResponse = switch (result) {
            .valid => |valid| .{ .valid = .{
                .latest_valid_exec_hash = valid.latest_valid_hash,
            } },
            .invalid => |invalid| .{ .invalid = .{
                .latest_valid_exec_hash = invalid.latest_valid_hash,
                .invalidate_from_parent_block_root = pending.invalidate_from_parent_block_root,
            } },
            .invalid_block_hash => |invalid| .{ .invalid = .{
                .latest_valid_exec_hash = invalid.latest_valid_hash,
                .invalidate_from_parent_block_root = pending.invalidate_from_parent_block_root,
            } },
            .syncing, .accepted, .unavailable => return null,
        };

        fc.validateLatestHash(self.chain.allocator, response, fc.getTime());

        const uagh_result = try fc.updateAndGetHead(self.chain.allocator, .get_canonical_head);
        const head_node = fc.getBlockDefaultStatus(uagh_result.head.block_root);
        const new_head = HeadResult{
            .block_root = uagh_result.head.block_root,
            .slot = uagh_result.head.slot,
            .state_root = uagh_result.head.state_root,
            .execution_optimistic = if (head_node) |node|
                switch (node.extra_meta.executionStatus()) {
                    .syncing, .payload_separated => true,
                    else => false,
                }
            else
                false,
            .payload_status = if (head_node) |node| node.payload_status else .full,
        };
        self.chain.setTrackedHead(new_head.block_root, new_head.slot, new_head.state_root);

        const snapshot = self.query().currentSnapshot();
        const head_changed = !std.mem.eql(u8, &snapshot.head.root, &pending.target_head_root);
        return .{
            .snapshot = snapshot,
            .head_changed = head_changed,
            .forkchoice_update = if (head_changed) self.forkchoiceUpdateForHead(snapshot.head.root) else null,
        };
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
    source: blocks.BlockSource,
    block_root: Root,
    da_status: blocks.DataAvailabilityStatus,
    seen_timestamp_sec: u64,
    block_data_plan: chain_types.BlockDataFetchPlan,
) ReadyBlockInput {
    return .{
        .block = any_signed,
        .source = source,
        .block_root = block_root,
        .slot = any_signed.beaconBlock().slot(),
        .da_status = da_status,
        .block_data_plan = block_data_plan,
        .seen_timestamp_sec = seen_timestamp_sec,
    };
}

fn pipelineDaStatus(
    chain: *Chain,
    block_root: Root,
    any_signed: fork_types.AnySignedBeaconBlock,
) blocks.DataAvailabilityStatus {
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
            .data_requirement = .none,
        };
    };
    const blob_count: u32 = @intCast(blob_commitments.items.len);

    if (fork.lt(.deneb)) {
        return .{
            .da_status = .not_required,
            .data_requirement = .none,
        };
    }
    if (blob_count == 0) {
        return .{
            .da_status = .available,
            .data_requirement = .none,
        };
    }

    // This is intentionally the pre-import beacon-block data path only.
    // When Gloas lands, separated execution payload envelopes belong in the
    // payload-envelope ingress subsystem, not as another block attachment here.
    const data_requirement: chain_types.BlockDataRequirement = if (fork.gte(.fulu))
        .columns
    else
        .blobs;

    if (chain.da_manager) |dam| {
        if (chain.currentWallSlot()) |wall_slot| {
            if (slot < dam.daWindowMinSlot(wall_slot)) {
                return .{
                    .da_status = .out_of_range,
                    .data_requirement = .none,
                };
            }
        }

        const da_status: blocks.DataAvailabilityStatus = switch (dam.checkBlockDataAvailability(block_root, slot, fork, blob_count).status) {
            .available, .reconstruction_possible => .available,
            .not_required => .not_required,
            .missing_blobs, .missing_columns => .pending,
        };
        return .{
            .da_status = da_status,
            .data_requirement = if (da_status == .pending) data_requirement else .none,
        };
    }

    return .{
        .da_status = .pending,
        .data_requirement = data_requirement,
    };
}
