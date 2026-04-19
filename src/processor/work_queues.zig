//! WorkQueues — the collection of per-type priority queues for the BeaconProcessor.
//!
//! Contains ~35 typed queues, one per work type that requires queueing.
//! Queue sizes are computed from active validator count via `QueueConfig`.
//! Provides `routeToQueue()` for ingestion and `popHighestPriority()` for
//! strict-priority draining.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const work_item_mod = @import("work_item.zig");
const WorkItem = work_item_mod.WorkItem;
const WorkType = work_item_mod.WorkType;
const GossipSource = work_item_mod.GossipSource;
const MessageId = work_item_mod.MessageId;
const OpaqueHandle = work_item_mod.OpaqueHandle;
const PeerIdHandle = work_item_mod.PeerIdHandle;
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const GossipBlockWork = work_item_mod.GossipBlockWork;
const GossipWork = work_item_mod.GossipWork;
const GossipBlobWork = work_item_mod.GossipBlobWork;
const GossipColumnWork = work_item_mod.GossipColumnWork;
const GossipPayloadWork = work_item_mod.GossipPayloadWork;
const DelayedBlockWork = work_item_mod.DelayedBlockWork;
const ColumnReconstructionWork = work_item_mod.ColumnReconstructionWork;
const AttestationWork = work_item_mod.AttestationWork;
const AttestationBatchWork = work_item_mod.AttestationBatchWork;
const AggregateWork = work_item_mod.AggregateWork;
const AggregateBatchWork = work_item_mod.AggregateBatchWork;
const SyncMessageWork = work_item_mod.SyncMessageWork;
const SyncContributionWork = work_item_mod.SyncContributionWork;
const VoluntaryExitWork = work_item_mod.VoluntaryExitWork;
const ProposerSlashingWork = work_item_mod.ProposerSlashingWork;
const AttesterSlashingWork = work_item_mod.AttesterSlashingWork;
const BlsToExecutionChangeWork = work_item_mod.BlsToExecutionChangeWork;
const GloasWork = work_item_mod.GloasWork;
const RpcBlockWork = work_item_mod.RpcBlockWork;
const RpcBlobWork = work_item_mod.RpcBlobWork;
const RpcColumnWork = work_item_mod.RpcColumnWork;
const ChainSegmentWork = work_item_mod.ChainSegmentWork;
const BackfillWork = work_item_mod.BackfillWork;
const ReqRespWork = work_item_mod.ReqRespWork;
const ApiWork = work_item_mod.ApiWork;
const SlotTickWork = work_item_mod.SlotTickWork;
const ReprocessMessage = work_item_mod.ReprocessMessage;
const LightClientWork = work_item_mod.LightClientWork;

const queues_mod = @import("queues.zig");
const FifoQueue = queues_mod.FifoQueue;
const LifoQueue = queues_mod.LifoQueue;

const attestation_batch_target_size: u32 = 8;
const aggregate_batch_target_size: u32 = 4;
const sync_message_batch_target_size: u32 = 16;
const gossip_batch_holdback_ns: i64 = 2 * std.time.ns_per_ms;

// ---------------------------------------------------------------------------
// QueueConfig — sizes for each queue, derived from validator count.
// ---------------------------------------------------------------------------

/// Configuration for all queue capacities.
/// Computed once at startup from the active validator count.
pub const QueueConfig = struct {
    chain_segment: u32,
    rpc_block: u32,
    rpc_blob: u32,
    rpc_custody_column: u32,
    gossip_block_ingress: u32,
    gossip_blob_ingress: u32,
    gossip_data_column_ingress: u32,
    gossip_attestation_ingress: u32,
    gossip_aggregate_ingress: u32,
    gossip_sync_contribution_ingress: u32,
    gossip_sync_message_ingress: u32,
    gossip_voluntary_exit_ingress: u32,
    gossip_proposer_slashing_ingress: u32,
    gossip_attester_slashing_ingress: u32,
    gossip_bls_to_exec_ingress: u32,
    delayed_block: u32,
    gossip_block: u32,
    gossip_execution_payload: u32,
    gossip_blob: u32,
    gossip_data_column: u32,
    column_reconstruction: u32,
    api_request_p0: u32,
    aggregate: u32,
    attestation: u32,
    gossip_payload_attestation: u32,
    sync_contribution: u32,
    sync_message: u32,
    gossip_execution_payload_bid: u32,
    gossip_proposer_preferences: u32,
    status: u32,
    blocks_by_range: u32,
    blocks_by_root: u32,
    blobs_by_range: u32,
    blobs_by_root: u32,
    columns_by_range: u32,
    columns_by_root: u32,
    gossip_attester_slashing: u32,
    gossip_proposer_slashing: u32,
    gossip_voluntary_exit: u32,
    gossip_bls_to_exec: u32,
    api_request_p1: u32,
    backfill_segment: u32,
    lc_bootstrap: u32,
    lc_finality_update: u32,
    lc_optimistic_update: u32,
    lc_updates_by_range: u32,

    /// Default config matching the design doc defaults.
    pub const default: QueueConfig = fromValidatorCount(500_000);

    /// Compute queue sizes from active validator count.
    /// Applies 110% overprovision to attestation-related queues.
    pub fn fromValidatorCount(active_validators: u32) QueueConfig {
        const slots_per_epoch: u32 = 32;

        // Attestation queue: one attestation per validator per epoch,
        // distributed across slots. 110% overprovision.
        const raw_att = active_validators / slots_per_epoch;
        const att_queue = @max(raw_att + raw_att / 10, 128);

        return .{
            .chain_segment = 64,
            .rpc_block = 1024,
            .rpc_blob = 1024,
            .rpc_custody_column = 64,
            .gossip_block_ingress = 1024,
            .gossip_blob_ingress = 4096,
            .gossip_data_column_ingress = 4096,
            .gossip_attestation_ingress = att_queue,
            .gossip_aggregate_ingress = 4096,
            .gossip_sync_contribution_ingress = 1024,
            .gossip_sync_message_ingress = 2048,
            .gossip_voluntary_exit_ingress = 4096,
            .gossip_proposer_slashing_ingress = 4096,
            .gossip_attester_slashing_ingress = 4096,
            .gossip_bls_to_exec_ingress = 16384,
            .delayed_block = 1024,
            .gossip_block = 1024,
            .gossip_execution_payload = 1024,
            .gossip_blob = 4096,
            .gossip_data_column = 4096,
            .column_reconstruction = 1,
            .api_request_p0 = 1024,
            .aggregate = 4096,
            .attestation = att_queue,
            .gossip_payload_attestation = 1536,
            .sync_contribution = 1024,
            .sync_message = 2048,
            .gossip_execution_payload_bid = 1024,
            .gossip_proposer_preferences = 1024,
            .status = 1024,
            .blocks_by_range = 1024,
            .blocks_by_root = 1024,
            .blobs_by_range = 1024,
            .blobs_by_root = 1024,
            .columns_by_range = 1024,
            .columns_by_root = 1024,
            .gossip_attester_slashing = 4096,
            .gossip_proposer_slashing = 4096,
            .gossip_voluntary_exit = 4096,
            .gossip_bls_to_exec = 16384,
            .api_request_p1 = 1024,
            .backfill_segment = 64,
            .lc_bootstrap = 1024,
            .lc_finality_update = 1024,
            .lc_optimistic_update = 1024,
            .lc_updates_by_range = 1024,
        };
    }

    /// Total buffer elements needed across all queues.
    pub fn totalCapacity(self: *const QueueConfig) u64 {
        var total: u64 = 0;
        inline for (std.meta.fields(QueueConfig)) |field| {
            if (field.type == u32) {
                total += @field(self, field.name);
            }
        }
        return total;
    }
};

// ---------------------------------------------------------------------------
// SyncState — used for sync-aware dropping.
// ---------------------------------------------------------------------------

/// Simplified sync state for drop decisions.
pub const SyncState = enum(u8) {
    /// Fully synced or close to head.
    synced,
    /// Initial sync — far behind head.
    syncing,
};

// ---------------------------------------------------------------------------
// WorkQueues — the per-type queue collection.
// ---------------------------------------------------------------------------

/// Collection of all per-type priority queues.
///
/// Backed by a single contiguous allocation sliced into per-queue regions.
/// The manager fiber is the sole accessor — no locking required.
pub const WorkQueues = struct {
    allocator: Allocator,

    // ── FIFO queues ──
    chain_segment: FifoQueue(ChainSegmentWork),
    rpc_block: FifoQueue(RpcBlockWork),
    rpc_blob: FifoQueue(RpcBlobWork),
    rpc_custody_column: FifoQueue(RpcColumnWork),
    gossip_block_ingress: FifoQueue(GossipWork),
    gossip_blob_ingress: FifoQueue(GossipWork),
    gossip_data_column_ingress: FifoQueue(GossipWork),
    delayed_block: FifoQueue(DelayedBlockWork),
    gossip_block: FifoQueue(GossipBlockWork),
    gossip_execution_payload: FifoQueue(GossipPayloadWork),
    gossip_blob: FifoQueue(GossipBlobWork),
    gossip_data_column: FifoQueue(GossipColumnWork),
    api_request_p0: FifoQueue(ApiWork),
    gossip_payload_attestation: FifoQueue(GloasWork),
    gossip_execution_payload_bid: FifoQueue(GloasWork),
    gossip_proposer_preferences: FifoQueue(GloasWork),
    status: FifoQueue(ReqRespWork),
    blocks_by_range: FifoQueue(ReqRespWork),
    blocks_by_root: FifoQueue(ReqRespWork),
    blobs_by_range: FifoQueue(ReqRespWork),
    blobs_by_root: FifoQueue(ReqRespWork),
    columns_by_range: FifoQueue(ReqRespWork),
    columns_by_root: FifoQueue(ReqRespWork),
    gossip_attester_slashing: FifoQueue(AttesterSlashingWork),
    gossip_proposer_slashing: FifoQueue(ProposerSlashingWork),
    gossip_voluntary_exit: FifoQueue(VoluntaryExitWork),
    gossip_bls_to_exec: FifoQueue(BlsToExecutionChangeWork),
    api_request_p1: FifoQueue(ApiWork),
    backfill_segment: FifoQueue(BackfillWork),
    lc_bootstrap: FifoQueue(LightClientWork),
    lc_finality_update: FifoQueue(LightClientWork),
    lc_optimistic_update: FifoQueue(LightClientWork),
    lc_updates_by_range: FifoQueue(LightClientWork),
    gossip_voluntary_exit_ingress: FifoQueue(GossipWork),
    gossip_proposer_slashing_ingress: FifoQueue(GossipWork),
    gossip_attester_slashing_ingress: FifoQueue(GossipWork),
    gossip_bls_to_exec_ingress: FifoQueue(GossipWork),

    // ── LIFO queues ──
    gossip_attestation_ingress: LifoQueue(GossipWork),
    gossip_aggregate_ingress: LifoQueue(GossipWork),
    gossip_sync_contribution_ingress: LifoQueue(GossipWork),
    gossip_sync_message_ingress: LifoQueue(GossipWork),
    aggregate: LifoQueue(AggregateWork),
    attestation: LifoQueue(AttestationWork),
    attestation_group_counts: std.AutoHashMap([32]u8, u32),
    sync_contribution: LifoQueue(SyncContributionWork),
    sync_message: LifoQueue(SyncMessageWork),
    column_reconstruction: LifoQueue(ColumnReconstructionWork),

    // ── State ──
    sync_state: SyncState,
    attestation_dispatch_enabled: bool = true,
    aggregate_dispatch_enabled: bool = true,
    sync_message_dispatch_enabled: bool = true,

    // ── Metrics counters (plain u64, no Prometheus yet) ──
    items_routed: u64,
    items_dropped_full: u64,
    items_dropped_sync: u64,

    // ── Batch scratch buffers (owned by allocator) ──
    attestation_batch_buf: []AttestationWork,
    aggregate_batch_buf: []AggregateWork,
    sync_message_batch_buf: []SyncMessageWork,

    /// Initialise all queues from individually allocated per-type slices.
    /// Each queue gets its own slice from the allocator.
    pub fn init(
        allocator: std.mem.Allocator,
        config: QueueConfig,
    ) !WorkQueues {
        var attestation_group_counts = std.AutoHashMap([32]u8, u32).init(allocator);
        errdefer attestation_group_counts.deinit();
        try attestation_group_counts.ensureTotalCapacity(config.attestation);

        return .{
            .allocator = allocator,
            .chain_segment = FifoQueue(ChainSegmentWork).init(
                try allocator.alloc(ChainSegmentWork, config.chain_segment),
            ),
            .rpc_block = FifoQueue(RpcBlockWork).init(
                try allocator.alloc(RpcBlockWork, config.rpc_block),
            ),
            .rpc_blob = FifoQueue(RpcBlobWork).init(
                try allocator.alloc(RpcBlobWork, config.rpc_blob),
            ),
            .rpc_custody_column = FifoQueue(RpcColumnWork).init(
                try allocator.alloc(RpcColumnWork, config.rpc_custody_column),
            ),
            .gossip_block_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_block_ingress),
            ),
            .gossip_blob_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_blob_ingress),
            ),
            .gossip_data_column_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_data_column_ingress),
            ),
            .delayed_block = FifoQueue(DelayedBlockWork).init(
                try allocator.alloc(DelayedBlockWork, config.delayed_block),
            ),
            .gossip_block = FifoQueue(GossipBlockWork).init(
                try allocator.alloc(GossipBlockWork, config.gossip_block),
            ),
            .gossip_execution_payload = FifoQueue(GossipPayloadWork).init(
                try allocator.alloc(GossipPayloadWork, config.gossip_execution_payload),
            ),
            .gossip_blob = FifoQueue(GossipBlobWork).init(
                try allocator.alloc(GossipBlobWork, config.gossip_blob),
            ),
            .gossip_data_column = FifoQueue(GossipColumnWork).init(
                try allocator.alloc(GossipColumnWork, config.gossip_data_column),
            ),
            .api_request_p0 = FifoQueue(ApiWork).init(
                try allocator.alloc(ApiWork, config.api_request_p0),
            ),
            .gossip_payload_attestation = FifoQueue(GloasWork).init(
                try allocator.alloc(GloasWork, config.gossip_payload_attestation),
            ),
            .gossip_execution_payload_bid = FifoQueue(GloasWork).init(
                try allocator.alloc(GloasWork, config.gossip_execution_payload_bid),
            ),
            .gossip_proposer_preferences = FifoQueue(GloasWork).init(
                try allocator.alloc(GloasWork, config.gossip_proposer_preferences),
            ),
            .status = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.status),
            ),
            .blocks_by_range = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.blocks_by_range),
            ),
            .blocks_by_root = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.blocks_by_root),
            ),
            .blobs_by_range = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.blobs_by_range),
            ),
            .blobs_by_root = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.blobs_by_root),
            ),
            .columns_by_range = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.columns_by_range),
            ),
            .columns_by_root = FifoQueue(ReqRespWork).init(
                try allocator.alloc(ReqRespWork, config.columns_by_root),
            ),
            .gossip_attester_slashing = FifoQueue(AttesterSlashingWork).init(
                try allocator.alloc(AttesterSlashingWork, config.gossip_attester_slashing),
            ),
            .gossip_proposer_slashing = FifoQueue(ProposerSlashingWork).init(
                try allocator.alloc(ProposerSlashingWork, config.gossip_proposer_slashing),
            ),
            .gossip_voluntary_exit = FifoQueue(VoluntaryExitWork).init(
                try allocator.alloc(VoluntaryExitWork, config.gossip_voluntary_exit),
            ),
            .gossip_bls_to_exec = FifoQueue(BlsToExecutionChangeWork).init(
                try allocator.alloc(BlsToExecutionChangeWork, config.gossip_bls_to_exec),
            ),
            .api_request_p1 = FifoQueue(ApiWork).init(
                try allocator.alloc(ApiWork, config.api_request_p1),
            ),
            .backfill_segment = FifoQueue(BackfillWork).init(
                try allocator.alloc(BackfillWork, config.backfill_segment),
            ),
            .lc_bootstrap = FifoQueue(LightClientWork).init(
                try allocator.alloc(LightClientWork, config.lc_bootstrap),
            ),
            .lc_finality_update = FifoQueue(LightClientWork).init(
                try allocator.alloc(LightClientWork, config.lc_finality_update),
            ),
            .lc_optimistic_update = FifoQueue(LightClientWork).init(
                try allocator.alloc(LightClientWork, config.lc_optimistic_update),
            ),
            .lc_updates_by_range = FifoQueue(LightClientWork).init(
                try allocator.alloc(LightClientWork, config.lc_updates_by_range),
            ),
            .gossip_voluntary_exit_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_voluntary_exit_ingress),
            ),
            .gossip_proposer_slashing_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_proposer_slashing_ingress),
            ),
            .gossip_attester_slashing_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_attester_slashing_ingress),
            ),
            .gossip_bls_to_exec_ingress = FifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_bls_to_exec_ingress),
            ),

            // LIFO queues.
            .gossip_attestation_ingress = LifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_attestation_ingress),
            ),
            .gossip_aggregate_ingress = LifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_aggregate_ingress),
            ),
            .gossip_sync_contribution_ingress = LifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_sync_contribution_ingress),
            ),
            .gossip_sync_message_ingress = LifoQueue(GossipWork).init(
                try allocator.alloc(GossipWork, config.gossip_sync_message_ingress),
            ),
            .aggregate = LifoQueue(AggregateWork).init(
                try allocator.alloc(AggregateWork, config.aggregate),
            ),
            .attestation = LifoQueue(AttestationWork).init(
                try allocator.alloc(AttestationWork, config.attestation),
            ),
            .attestation_group_counts = attestation_group_counts,
            .sync_contribution = LifoQueue(SyncContributionWork).init(
                try allocator.alloc(SyncContributionWork, config.sync_contribution),
            ),
            .sync_message = LifoQueue(SyncMessageWork).init(
                try allocator.alloc(SyncMessageWork, config.sync_message),
            ),
            .column_reconstruction = LifoQueue(ColumnReconstructionWork).init(
                try allocator.alloc(ColumnReconstructionWork, config.column_reconstruction),
            ),

            .sync_state = .synced,
            .items_routed = 0,
            .items_dropped_full = 0,
            .items_dropped_sync = 0,

            // Batch scratch buffers.
            .attestation_batch_buf = try allocator.alloc(
                AttestationWork,
                work_item_mod.max_attestation_batch_size,
            ),
            .aggregate_batch_buf = try allocator.alloc(
                AggregateWork,
                work_item_mod.max_aggregate_batch_size,
            ),
            .sync_message_batch_buf = try allocator.alloc(
                SyncMessageWork,
                work_item_mod.max_sync_message_batch_size,
            ),
        };
    }

    pub fn deinit(self: *WorkQueues) void {
        self.cleanupQueuedItems();
        self.attestation_group_counts.deinit();
        self.freeQueueBuffers();
        self.allocator.free(self.attestation_batch_buf);
        self.allocator.free(self.aggregate_batch_buf);
        self.allocator.free(self.sync_message_batch_buf);
    }

    fn cleanupItem(self: *WorkQueues, item: WorkItem) void {
        item.deinit(self.allocator);
    }

    fn cleanupQueue(self: *WorkQueues, comptime tag: WorkType, queue: anytype) void {
        while (queue.pop()) |item| {
            self.cleanupItem(@unionInit(WorkItem, @tagName(tag), item));
        }
    }

    fn cleanupQueuedItems(self: *WorkQueues) void {
        self.cleanupQueue(.chain_segment, &self.chain_segment);
        self.cleanupQueue(.rpc_block, &self.rpc_block);
        self.cleanupQueue(.rpc_blob, &self.rpc_blob);
        self.cleanupQueue(.rpc_custody_column, &self.rpc_custody_column);
        self.cleanupQueue(.gossip_block_ingress, &self.gossip_block_ingress);
        self.cleanupQueue(.gossip_blob_ingress, &self.gossip_blob_ingress);
        self.cleanupQueue(.gossip_data_column_ingress, &self.gossip_data_column_ingress);
        self.cleanupQueue(.delayed_block, &self.delayed_block);
        self.cleanupQueue(.gossip_block, &self.gossip_block);
        self.cleanupQueue(.gossip_execution_payload, &self.gossip_execution_payload);
        self.cleanupQueue(.gossip_blob, &self.gossip_blob);
        self.cleanupQueue(.gossip_data_column, &self.gossip_data_column);
        self.cleanupQueue(.column_reconstruction, &self.column_reconstruction);
        self.cleanupQueue(.api_request_p0, &self.api_request_p0);
        self.cleanupQueue(.aggregate, &self.aggregate);
        self.cleanupQueue(.attestation, &self.attestation);
        self.cleanupQueue(.gossip_payload_attestation, &self.gossip_payload_attestation);
        self.cleanupQueue(.sync_contribution, &self.sync_contribution);
        self.cleanupQueue(.sync_message, &self.sync_message);
        self.cleanupQueue(.gossip_execution_payload_bid, &self.gossip_execution_payload_bid);
        self.cleanupQueue(.gossip_proposer_preferences, &self.gossip_proposer_preferences);
        self.cleanupQueue(.status, &self.status);
        self.cleanupQueue(.blocks_by_range, &self.blocks_by_range);
        self.cleanupQueue(.blocks_by_root, &self.blocks_by_root);
        self.cleanupQueue(.blobs_by_range, &self.blobs_by_range);
        self.cleanupQueue(.blobs_by_root, &self.blobs_by_root);
        self.cleanupQueue(.columns_by_range, &self.columns_by_range);
        self.cleanupQueue(.columns_by_root, &self.columns_by_root);
        self.cleanupQueue(.gossip_attester_slashing, &self.gossip_attester_slashing);
        self.cleanupQueue(.gossip_proposer_slashing, &self.gossip_proposer_slashing);
        self.cleanupQueue(.gossip_voluntary_exit, &self.gossip_voluntary_exit);
        self.cleanupQueue(.gossip_bls_to_exec, &self.gossip_bls_to_exec);
        self.cleanupQueue(.api_request_p1, &self.api_request_p1);
        self.cleanupQueue(.backfill_segment, &self.backfill_segment);
        self.cleanupQueue(.lc_bootstrap, &self.lc_bootstrap);
        self.cleanupQueue(.lc_finality_update, &self.lc_finality_update);
        self.cleanupQueue(.lc_optimistic_update, &self.lc_optimistic_update);
        self.cleanupQueue(.lc_updates_by_range, &self.lc_updates_by_range);
        self.cleanupQueue(.gossip_voluntary_exit_ingress, &self.gossip_voluntary_exit_ingress);
        self.cleanupQueue(.gossip_proposer_slashing_ingress, &self.gossip_proposer_slashing_ingress);
        self.cleanupQueue(.gossip_attester_slashing_ingress, &self.gossip_attester_slashing_ingress);
        self.cleanupQueue(.gossip_bls_to_exec_ingress, &self.gossip_bls_to_exec_ingress);
        self.cleanupQueue(.gossip_attestation_ingress, &self.gossip_attestation_ingress);
        self.cleanupQueue(.gossip_aggregate_ingress, &self.gossip_aggregate_ingress);
        self.cleanupQueue(.gossip_sync_contribution_ingress, &self.gossip_sync_contribution_ingress);
        self.cleanupQueue(.gossip_sync_message_ingress, &self.gossip_sync_message_ingress);
    }

    fn freeQueueBuffers(self: *WorkQueues) void {
        self.allocator.free(self.chain_segment.buffer);
        self.allocator.free(self.rpc_block.buffer);
        self.allocator.free(self.rpc_blob.buffer);
        self.allocator.free(self.rpc_custody_column.buffer);
        self.allocator.free(self.gossip_block_ingress.buffer);
        self.allocator.free(self.gossip_blob_ingress.buffer);
        self.allocator.free(self.gossip_data_column_ingress.buffer);
        self.allocator.free(self.delayed_block.buffer);
        self.allocator.free(self.gossip_block.buffer);
        self.allocator.free(self.gossip_execution_payload.buffer);
        self.allocator.free(self.gossip_blob.buffer);
        self.allocator.free(self.gossip_data_column.buffer);
        self.allocator.free(self.api_request_p0.buffer);
        self.allocator.free(self.gossip_payload_attestation.buffer);
        self.allocator.free(self.gossip_execution_payload_bid.buffer);
        self.allocator.free(self.gossip_proposer_preferences.buffer);
        self.allocator.free(self.status.buffer);
        self.allocator.free(self.blocks_by_range.buffer);
        self.allocator.free(self.blocks_by_root.buffer);
        self.allocator.free(self.blobs_by_range.buffer);
        self.allocator.free(self.blobs_by_root.buffer);
        self.allocator.free(self.columns_by_range.buffer);
        self.allocator.free(self.columns_by_root.buffer);
        self.allocator.free(self.gossip_attester_slashing.buffer);
        self.allocator.free(self.gossip_proposer_slashing.buffer);
        self.allocator.free(self.gossip_voluntary_exit.buffer);
        self.allocator.free(self.gossip_bls_to_exec.buffer);
        self.allocator.free(self.api_request_p1.buffer);
        self.allocator.free(self.backfill_segment.buffer);
        self.allocator.free(self.lc_bootstrap.buffer);
        self.allocator.free(self.lc_finality_update.buffer);
        self.allocator.free(self.lc_optimistic_update.buffer);
        self.allocator.free(self.lc_updates_by_range.buffer);
        self.allocator.free(self.gossip_voluntary_exit_ingress.buffer);
        self.allocator.free(self.gossip_proposer_slashing_ingress.buffer);
        self.allocator.free(self.gossip_attester_slashing_ingress.buffer);
        self.allocator.free(self.gossip_bls_to_exec_ingress.buffer);
        self.allocator.free(self.gossip_attestation_ingress.buffer);
        self.allocator.free(self.gossip_aggregate_ingress.buffer);
        self.allocator.free(self.gossip_sync_contribution_ingress.buffer);
        self.allocator.free(self.gossip_sync_message_ingress.buffer);
        self.allocator.free(self.aggregate.buffer);
        self.allocator.free(self.attestation.buffer);
        self.allocator.free(self.sync_contribution.buffer);
        self.allocator.free(self.sync_message.buffer);
        self.allocator.free(self.column_reconstruction.buffer);
    }

    /// Route a work item to the appropriate typed queue.
    /// Handles sync-aware dropping and queue-full metrics.
    ///
    /// Dispatches via explicit switch — each arm is one line: push to the
    /// matching named field. FIFO queues check for full; LIFO queues evict.
    pub fn routeToQueue(self: *WorkQueues, item: WorkItem) void {
        const wtype = item.workType();

        // Drop during initial sync if applicable.
        if (self.sync_state == .syncing and wtype.dropDuringSync()) {
            self.items_dropped_sync += 1;
            self.cleanupItem(item);
            return;
        }

        self.items_routed += 1;

        // Helper: push to a FIFO queue, count drops on overflow.
        const pushFifo = struct {
            fn call(queues: *WorkQueues, queue: anytype, w: anytype, wrapped: WorkItem) void {
                if (!queue.push(w)) {
                    queues.items_dropped_full += 1;
                    queues.cleanupItem(wrapped);
                }
            }
        }.call;

        switch (item) {
            // ── FIFO queues ──
            inline .chain_segment, .rpc_block, .rpc_blob, .rpc_custody_column, .gossip_block_ingress, .gossip_blob_ingress, .gossip_data_column_ingress, .delayed_block, .gossip_block, .gossip_execution_payload, .gossip_blob, .gossip_data_column, .api_request_p0, .gossip_payload_attestation, .gossip_execution_payload_bid, .gossip_proposer_preferences, .status, .blocks_by_range, .blocks_by_root, .blobs_by_range, .blobs_by_root, .columns_by_range, .columns_by_root, .gossip_attester_slashing, .gossip_proposer_slashing, .gossip_voluntary_exit, .gossip_bls_to_exec, .api_request_p1, .backfill_segment, .lc_bootstrap, .lc_finality_update, .lc_optimistic_update, .lc_updates_by_range, .gossip_voluntary_exit_ingress, .gossip_proposer_slashing_ingress, .gossip_attester_slashing_ingress, .gossip_bls_to_exec_ingress => |w, tag| {
                pushFifo(self, &@field(self, @tagName(tag)), w, @unionInit(WorkItem, @tagName(tag), w));
            },

            // ── LIFO queues: always accept, drop oldest on overflow ──
            .attestation => |w| {
                self.pushAttestationWork(w);
            },

            inline .gossip_attestation_ingress, .gossip_aggregate_ingress, .gossip_sync_contribution_ingress, .gossip_sync_message_ingress, .aggregate, .sync_contribution, .sync_message, .column_reconstruction => |w, tag| {
                if (@field(self, @tagName(tag)).push(w)) |dropped| {
                    self.items_dropped_full += 1;
                    self.cleanupItem(@unionInit(WorkItem, @tagName(tag), dropped));
                }
            },

            // ── Batch items are produced internally, not routed from inbound ──
            .attestation_batch, .aggregate_batch, .sync_message_batch => unreachable,

            // ── Internal items: handled directly by the processor loop ──
            .slot_tick, .reprocess => {},
        }
    }

    /// Pop the highest-priority work item across all queues.
    ///
    /// Follows the strict priority order from the design doc.
    /// For attestation/aggregate queues, forms batches when multiple items
    /// are available (batch BLS verification is significantly faster).
    ///
    /// Returns null when all queues are empty.
    pub fn popHighestPriority(self: *WorkQueues) ?WorkItem {
        return self.popHighestPriorityAt(std.math.maxInt(i64));
    }

    /// Pop the highest-priority work item across all queues using `now_ns`
    /// to decide whether attestation and aggregate queues should be held a
    /// little longer to form a more worthwhile BLS batch.
    pub fn popHighestPriorityAt(self: *WorkQueues, now_ns: i64) ?WorkItem {
        // Priority 1-4: Sync.
        if (self.chain_segment.pop()) |w| return .{ .chain_segment = w };
        if (self.rpc_block.pop()) |w| return .{ .rpc_block = w };
        if (self.rpc_blob.pop()) |w| return .{ .rpc_blob = w };
        if (self.rpc_custody_column.pop()) |w| return .{ .rpc_custody_column = w };

        // Priority 5-7: typed fast-lane gossip ingress.
        if (self.gossip_block_ingress.pop()) |w| return .{ .gossip_block_ingress = w };
        if (self.gossip_blob_ingress.pop()) |w| return .{ .gossip_blob_ingress = w };
        if (self.gossip_data_column_ingress.pop()) |w| return .{ .gossip_data_column_ingress = w };

        // Priority 8-12: Prepared fast-lane gossip.
        if (self.delayed_block.pop()) |w| return .{ .delayed_block = w };
        if (self.gossip_block.pop()) |w| return .{ .gossip_block = w };
        if (self.gossip_execution_payload.pop()) |w| return .{ .gossip_execution_payload = w };
        if (self.gossip_blob.pop()) |w| return .{ .gossip_blob = w };
        if (self.gossip_data_column.pop()) |w| return .{ .gossip_data_column = w };

        // Priority 13: Column reconstruction.
        if (self.column_reconstruction.pop()) |w| return .{ .column_reconstruction = w };

        // Priority 14: High-priority API.
        if (self.api_request_p0.pop()) |w| return .{ .api_request_p0 = w };

        // Priority 15-21: typed control gossip ingress.
        if (self.gossip_aggregate_ingress.pop()) |w| return .{ .gossip_aggregate_ingress = w };
        if (self.gossip_sync_contribution_ingress.pop()) |w| return .{ .gossip_sync_contribution_ingress = w };
        if (self.gossip_sync_message_ingress.pop()) |w| return .{ .gossip_sync_message_ingress = w };
        if (self.gossip_voluntary_exit_ingress.pop()) |w| return .{ .gossip_voluntary_exit_ingress = w };
        if (self.gossip_proposer_slashing_ingress.pop()) |w| return .{ .gossip_proposer_slashing_ingress = w };
        if (self.gossip_attester_slashing_ingress.pop()) |w| return .{ .gossip_attester_slashing_ingress = w };
        if (self.gossip_bls_to_exec_ingress.pop()) |w| return .{ .gossip_bls_to_exec_ingress = w };

        // Priority 22-25: Attestations — ingress overload then prepared batches.
        if (self.gossip_attestation_ingress.pop()) |w| return .{ .gossip_attestation_ingress = w };
        if (self.aggregate_dispatch_enabled and self.aggregate.len > 0 and self.aggregateBatchReady(now_ns)) {
            return self.formAggregateBatch();
        }
        if (self.attestation_dispatch_enabled and self.attestation.len > 0 and self.attestationBatchReady(now_ns)) {
            return self.formAttestationBatch();
        }

        // Priority 26: Payload attestation (Gloas).
        if (self.gossip_payload_attestation.pop()) |w| return .{ .gossip_payload_attestation = w };

        // Priority 27-29: Sync committee.
        if (self.sync_contribution.pop()) |w| return .{ .sync_contribution = w };
        if (self.sync_message_dispatch_enabled and self.sync_message.len > 0) {
            if (self.syncMessageBatchReady(now_ns)) {
                return self.formSyncMessageBatch();
            }
        } else if (self.sync_message.pop()) |w| {
            return .{ .sync_message = w };
        }

        // Priority 30-31: Gloas.
        if (self.gossip_execution_payload_bid.pop()) |w| return .{ .gossip_execution_payload_bid = w };
        if (self.gossip_proposer_preferences.pop()) |w| return .{ .gossip_proposer_preferences = w };

        // Priority 32-38: Peer serving.
        if (self.status.pop()) |w| return .{ .status = w };
        if (self.blocks_by_range.pop()) |w| return .{ .blocks_by_range = w };
        if (self.blocks_by_root.pop()) |w| return .{ .blocks_by_root = w };
        if (self.blobs_by_range.pop()) |w| return .{ .blobs_by_range = w };
        if (self.blobs_by_root.pop()) |w| return .{ .blobs_by_root = w };
        if (self.columns_by_range.pop()) |w| return .{ .columns_by_range = w };
        if (self.columns_by_root.pop()) |w| return .{ .columns_by_root = w };

        // Priority 39-42: Pool objects.
        if (self.gossip_attester_slashing.pop()) |w| return .{ .gossip_attester_slashing = w };
        if (self.gossip_proposer_slashing.pop()) |w| return .{ .gossip_proposer_slashing = w };
        if (self.gossip_voluntary_exit.pop()) |w| return .{ .gossip_voluntary_exit = w };
        if (self.gossip_bls_to_exec.pop()) |w| return .{ .gossip_bls_to_exec = w };

        // Priority 43: Low-priority API.
        if (self.api_request_p1.pop()) |w| return .{ .api_request_p1 = w };

        // Priority 44: Backfill (dead last).
        if (self.backfill_segment.pop()) |w| return .{ .backfill_segment = w };

        // Priority 45-48: Light client.
        if (self.lc_bootstrap.pop()) |w| return .{ .lc_bootstrap = w };
        if (self.lc_finality_update.pop()) |w| return .{ .lc_finality_update = w };
        if (self.lc_optimistic_update.pop()) |w| return .{ .lc_optimistic_update = w };
        if (self.lc_updates_by_range.pop()) |w| return .{ .lc_updates_by_range = w };

        return null;
    }

    pub fn setGossipBlsBatchDispatchEnabled(self: *WorkQueues, enabled: bool) void {
        self.attestation_dispatch_enabled = enabled;
        self.aggregate_dispatch_enabled = enabled;
        self.sync_message_dispatch_enabled = enabled;
    }

    /// Returns true if every queue is empty.
    pub fn allQueuesEmpty(self: *const WorkQueues) bool {
        return self.totalQueued() == 0;
    }

    /// Total number of items across all queues.
    pub fn totalQueued(self: *const WorkQueues) u64 {
        var total: u64 = 0;

        // FIFO queues.
        total += self.chain_segment.len;
        total += self.rpc_block.len;
        total += self.rpc_blob.len;
        total += self.rpc_custody_column.len;
        total += self.gossip_block_ingress.len;
        total += self.gossip_blob_ingress.len;
        total += self.gossip_data_column_ingress.len;
        total += self.delayed_block.len;
        total += self.gossip_block.len;
        total += self.gossip_execution_payload.len;
        total += self.gossip_blob.len;
        total += self.gossip_data_column.len;
        total += self.api_request_p0.len;
        total += self.gossip_payload_attestation.len;
        total += self.gossip_execution_payload_bid.len;
        total += self.gossip_proposer_preferences.len;
        total += self.status.len;
        total += self.blocks_by_range.len;
        total += self.blocks_by_root.len;
        total += self.blobs_by_range.len;
        total += self.blobs_by_root.len;
        total += self.columns_by_range.len;
        total += self.columns_by_root.len;
        total += self.gossip_attester_slashing.len;
        total += self.gossip_proposer_slashing.len;
        total += self.gossip_voluntary_exit.len;
        total += self.gossip_bls_to_exec.len;
        total += self.api_request_p1.len;
        total += self.backfill_segment.len;
        total += self.lc_bootstrap.len;
        total += self.lc_finality_update.len;
        total += self.lc_optimistic_update.len;
        total += self.lc_updates_by_range.len;
        total += self.gossip_voluntary_exit_ingress.len;
        total += self.gossip_proposer_slashing_ingress.len;
        total += self.gossip_attester_slashing_ingress.len;
        total += self.gossip_bls_to_exec_ingress.len;

        // LIFO queues.
        total += self.gossip_attestation_ingress.len;
        total += self.gossip_aggregate_ingress.len;
        total += self.gossip_sync_contribution_ingress.len;
        total += self.gossip_sync_message_ingress.len;
        total += self.aggregate.len;
        total += self.attestation.len;
        total += self.sync_contribution.len;
        total += self.sync_message.len;
        total += self.column_reconstruction.len;

        return total;
    }

    // ── Batch formation ──

    fn aggregateBatchReady(self: *const WorkQueues, now_ns: i64) bool {
        return batchReady(
            AggregateWork,
            self.aggregate.len,
            self.aggregate.peekOldest(),
            now_ns,
            aggregate_batch_target_size,
        );
    }

    fn attestationBatchReady(self: *const WorkQueues, now_ns: i64) bool {
        return batchReady(
            AttestationWork,
            self.attestation.len,
            self.attestation.peekOldest(),
            now_ns,
            attestation_batch_target_size,
        );
    }

    fn syncMessageBatchReady(self: *const WorkQueues, now_ns: i64) bool {
        return batchReady(
            SyncMessageWork,
            self.sync_message.len,
            self.sync_message.peekOldest(),
            now_ns,
            sync_message_batch_target_size,
        );
    }

    /// Form a batch from the aggregate LIFO queue.
    /// If only 1 item, returns a single aggregate work item.
    /// If 2+, pops up to max_aggregate_batch_size into a batch.
    fn formAggregateBatch(self: *WorkQueues) WorkItem {
        assert(self.aggregate.len > 0);
        if (self.aggregate.len < 2) {
            return .{ .aggregate = self.aggregate.pop().? };
        }
        const batch_size = @min(
            self.aggregate.len,
            work_item_mod.max_aggregate_batch_size,
        );
        const count = self.aggregate.popBatch(
            self.aggregate_batch_buf[0..batch_size],
        );
        assert(count > 0);
        return .{ .aggregate_batch = .{
            .items = self.aggregate_batch_buf.ptr,
            .count = count,
        } };
    }

    /// Form a batch from the attestation LIFO queue.
    /// If only 1 item, returns a single attestation work item.
    /// If 2+, pops up to max_attestation_batch_size into a batch.
    fn formAttestationBatch(self: *WorkQueues) WorkItem {
        assert(self.attestation.len > 0);
        if (self.attestation.len < 2) {
            return .{ .attestation = self.popAttestation().? };
        }

        if (self.bestAttestationGroupRoot()) |root| {
            var matching_offsets: [work_item_mod.max_attestation_batch_size]u32 = undefined;
            var match_count: u32 = 0;
            var offset: u32 = 0;
            while (offset < self.attestation.len and match_count < work_item_mod.max_attestation_batch_size) : (offset += 1) {
                const item = self.attestation.peekAt(offset).?;
                if (std.mem.eql(u8, &item.attestation_data_root, &root)) {
                    matching_offsets[match_count] = offset;
                    match_count += 1;
                }
            }

            assert(match_count >= 2);
            var remaining = match_count;
            while (remaining > 0) {
                remaining -= 1;
                const batch_index = remaining;
                self.attestation_batch_buf[batch_index] = self.removeAttestationAt(
                    matching_offsets[remaining],
                ).?;
            }

            return .{ .attestation_batch = .{
                .items = self.attestation_batch_buf.ptr,
                .count = match_count,
            } };
        }

        const batch_size = @min(
            self.attestation.len,
            work_item_mod.max_attestation_batch_size,
        );
        var count: u32 = 0;
        while (count < batch_size) : (count += 1) {
            self.attestation_batch_buf[count] = self.popAttestation().?;
        }
        assert(count > 0);
        return .{ .attestation_batch = .{
            .items = self.attestation_batch_buf.ptr,
            .count = count,
        } };
    }

    fn formSyncMessageBatch(self: *WorkQueues) WorkItem {
        assert(self.sync_message.len > 0);
        if (self.sync_message.len < 2) {
            return .{ .sync_message = self.sync_message.pop().? };
        }

        const batch_size = @min(
            self.sync_message.len,
            work_item_mod.max_sync_message_batch_size,
        );
        const count = self.sync_message.popBatch(
            self.sync_message_batch_buf[0..batch_size],
        );
        assert(count > 0);
        return .{ .sync_message_batch = .{
            .items = self.sync_message_batch_buf.ptr,
            .count = count,
        } };
    }

    fn pushAttestationWork(self: *WorkQueues, work: AttestationWork) void {
        self.incrementAttestationGroupCount(work.attestation_data_root);
        if (self.attestation.push(work)) |dropped| {
            self.items_dropped_full += 1;
            self.decrementAttestationGroupCount(dropped.attestation_data_root);
            self.cleanupItem(.{ .attestation = dropped });
        }
    }

    fn popAttestation(self: *WorkQueues) ?AttestationWork {
        const work = self.attestation.pop() orelse return null;
        self.decrementAttestationGroupCount(work.attestation_data_root);
        return work;
    }

    fn removeAttestationAt(self: *WorkQueues, offset: u32) ?AttestationWork {
        const work = self.attestation.removeAt(offset) orelse return null;
        self.decrementAttestationGroupCount(work.attestation_data_root);
        return work;
    }

    fn incrementAttestationGroupCount(self: *WorkQueues, root: [32]u8) void {
        const gop = self.attestation_group_counts.getOrPutAssumeCapacity(root);
        if (gop.found_existing) {
            gop.value_ptr.* += 1;
        } else {
            gop.value_ptr.* = 1;
        }
    }

    fn decrementAttestationGroupCount(self: *WorkQueues, root: [32]u8) void {
        const count_ptr = self.attestation_group_counts.getPtr(root) orelse unreachable;
        if (count_ptr.* == 1) {
            _ = self.attestation_group_counts.fetchRemove(root);
        } else {
            count_ptr.* -= 1;
        }
    }

    fn bestAttestationGroupRoot(self: *const WorkQueues) ?[32]u8 {
        var max_count: u32 = 0;
        var it = self.attestation_group_counts.iterator();
        while (it.next()) |entry| {
            max_count = @max(max_count, entry.value_ptr.*);
        }
        if (max_count < 2) return null;

        var offset: u32 = 0;
        while (offset < self.attestation.len) : (offset += 1) {
            const item = self.attestation.peekAt(offset).?;
            if (self.attestation_group_counts.get(item.attestation_data_root)) |count| {
                if (count == max_count) return item.attestation_data_root;
            }
        }

        return null;
    }
};

fn sameAttestationMessage(a: *const AttestationWork, b: *const AttestationWork) bool {
    return std.mem.eql(u8, &a.attestation_data_root, &b.attestation_data_root);
}

fn batchReady(
    comptime T: type,
    queue_len: u32,
    oldest: ?*const T,
    now_ns: i64,
    target_size: u32,
) bool {
    if (queue_len == 0) return false;
    if (queue_len >= target_size) return true;

    const oldest_item = oldest orelse return true;
    if (oldest_item.seen_timestamp_ns <= 0) return true;
    if (now_ns <= oldest_item.seen_timestamp_ns) return false;

    return now_ns - oldest_item.seen_timestamp_ns >= gossip_batch_holdback_ns;
}

// ===========================================================================
// Tests
// ===========================================================================

test "QueueConfig: fromValidatorCount default" {
    const config = QueueConfig.fromValidatorCount(500_000);
    // 500000 / 32 = 15625; 15625 * 1.1 = 17187.
    try testing.expectEqual(@as(u32, 17187), config.attestation);
    try testing.expectEqual(@as(u32, 4096), config.aggregate);
    try testing.expectEqual(@as(u32, 64), config.chain_segment);
}

test "QueueConfig: small validator count floors at 128" {
    const config = QueueConfig.fromValidatorCount(100);
    // 100 / 32 = 3; 3 * 1.1 = 3; max(3, 128) = 128.
    try testing.expectEqual(@as(u32, 128), config.attestation);
}

test "QueueConfig: totalCapacity" {
    const config = QueueConfig.fromValidatorCount(500_000);
    const total = config.totalCapacity();
    // Sanity: should be at least the sum of fixed-size queues.
    try testing.expect(total > 50_000);
}

test "WorkQueues: route and pop priority order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);

    // Route a low-priority item first, then a high-priority one.
    wq.routeToQueue(.{ .api_request_p1 = .{
        .response = testOpaqueHandle(1),
        .seen_timestamp_ns = 100,
    } });
    wq.routeToQueue(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(2),
        .seen_timestamp_ns = 200,
    } });

    // Pop should return status (priority 22) before api_request_p1 (33).
    const first = wq.popHighestPriority().?;
    try testing.expectEqual(WorkType.status, first.workType());

    const second = wq.popHighestPriority().?;
    try testing.expectEqual(WorkType.api_request_p1, second.workType());

    // Should be empty now.
    try testing.expect(wq.popHighestPriority() == null);
    try testing.expect(wq.allQueuesEmpty());
}

test "WorkQueues: attestation batching holds briefly for a fuller batch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);

    wq.routeToQueue(.{ .attestation = testAttestationWork(1, 0, 1_000) });
    wq.routeToQueue(.{ .attestation = testAttestationWork(2, 1, 1_500) });

    try testing.expect(wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns - 1) == null);

    const ready = wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns + 1).?;
    try testing.expectEqual(WorkType.attestation_batch, ready.workType());
}

test "WorkQueues: attestation batching dispatches immediately at target size" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = testQueueConfig();
    config.attestation = attestation_batch_target_size;
    var wq = try WorkQueues.init(allocator, config);

    var i: u32 = 0;
    while (i < attestation_batch_target_size) : (i += 1) {
        wq.routeToQueue(.{ .attestation = testAttestationWork(
            i + 1,
            @intCast(i % 4),
            10_000 + i,
        ) });
    }

    const ready = wq.popHighestPriorityAt(10_000).?;
    try testing.expectEqual(WorkType.attestation_batch, ready.workType());
}

test "WorkQueues: attestation batching prefers same attestation data" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);

    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(1, 900, 0, 1_000) });
    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(2, 901, 1, 1_001) });
    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(3, 900, 0, 1_002) });

    const ready = wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns + 1).?;
    try testing.expectEqual(WorkType.attestation_batch, ready.workType());

    const batch = ready.attestation_batch;
    try testing.expectEqual(@as(u32, 2), batch.count);
    try testing.expectEqual(@as(u64, 900), batch.items[0].attestation.slot());
    try testing.expectEqual(@as(u64, 900), batch.items[1].attestation.slot());

    const next = wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns + 1).?;
    defer next.deinit(allocator);
    try testing.expectEqual(WorkType.attestation, next.workType());
    try testing.expectEqual(@as(u64, 901), next.attestation.attestation.slot());
}

test "WorkQueues: attestation batching scans the full queue for matching data" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = testQueueConfig();
    config.attestation = 96;
    var wq = try WorkQueues.init(allocator, config);

    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(1, 777, 0, 1_000) });

    var i: u32 = 0;
    while (i < 70) : (i += 1) {
        wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(
            10 + i,
            900 + i,
            @intCast(i % 4),
            1_001 + i,
        ) });
    }

    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(500, 777, 0, 2_000) });

    const ready = wq.popHighestPriorityAt(2_000 + gossip_batch_holdback_ns + 1).?;
    try testing.expectEqual(WorkType.attestation_batch, ready.workType());
    try testing.expectEqual(@as(u32, 2), ready.attestation_batch.count);
    try testing.expectEqual(@as(u64, 777), ready.attestation_batch.items[0].attestation.slot());
    try testing.expectEqual(@as(u64, 777), ready.attestation_batch.items[1].attestation.slot());
}

test "WorkQueues: attestation batching picks the largest duplicate group" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = testQueueConfig();
    config.attestation = 8;
    var wq = try WorkQueues.init(allocator, config);

    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(1, 700, 0, 1_000) });
    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(2, 700, 0, 1_001) });
    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(3, 700, 0, 1_002) });

    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(4, 800, 1, 2_000) });
    wq.routeToQueue(.{ .attestation = testAttestationWorkWithSlot(5, 800, 1, 2_001) });

    const ready = wq.popHighestPriorityAt(2_001 + gossip_batch_holdback_ns + 1).?;
    try testing.expectEqual(WorkType.attestation_batch, ready.workType());
    try testing.expectEqual(@as(u32, 3), ready.attestation_batch.count);
    try testing.expectEqual(@as(u64, 700), ready.attestation_batch.items[0].attestation.slot());
    try testing.expectEqual(@as(u64, 700), ready.attestation_batch.items[1].attestation.slot());
    try testing.expectEqual(@as(u64, 700), ready.attestation_batch.items[2].attestation.slot());
}

test "WorkQueues: gossip bls dispatch gate defers attestation and aggregate work" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);

    wq.setGossipBlsBatchDispatchEnabled(false);
    wq.routeToQueue(.{ .attestation = testAttestationWork(1, 0, 1_000) });
    wq.routeToQueue(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(2),
        .seen_timestamp_ns = 2_000,
    } });

    const first = wq.popHighestPriorityAt(10_000).?;
    try testing.expectEqual(WorkType.status, first.workType());
    try testing.expect(wq.popHighestPriorityAt(10_000) == null);
    try testing.expectEqual(@as(u32, 1), wq.attestation.len);
}

test "WorkQueues: sync message batching holds briefly for a fuller batch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);

    wq.routeToQueue(.{ .sync_message = testSyncMessageWork(1, 500, 1_000) });
    wq.routeToQueue(.{ .sync_message = testSyncMessageWork(2, 500, 1_500) });

    try testing.expect(wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns - 1) == null);

    const ready = wq.popHighestPriorityAt(1_000 + gossip_batch_holdback_ns + 1).?;
    try testing.expectEqual(WorkType.sync_message_batch, ready.workType());
    try testing.expectEqual(@as(u32, 2), ready.sync_message_batch.count);
}

test "WorkQueues: sync-aware dropping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);
    wq.sync_state = .syncing;

    // Attestation should be dropped during sync.
    wq.routeToQueue(.{ .attestation = testAttestationWork(1, 0, 100) });

    try testing.expectEqual(@as(u64, 1), wq.items_dropped_sync);
    try testing.expect(wq.attestation.isEmpty());

    // Status should NOT be dropped during sync.
    wq.routeToQueue(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(2),
        .seen_timestamp_ns = 200,
    } });

    try testing.expectEqual(@as(u32, 1), wq.status.len);
}

test "WorkQueues: sync drop deinitializes owned gossip data" {
    const allocator = testing.allocator;
    var config = testQueueConfig();
    config.attestation = 1;

    var wq = try WorkQueues.init(allocator, config);
    defer wq.deinit();
    wq.sync_state = .syncing;

    wq.routeToQueue(.{ .attestation = try testOwnedAttestationWork(allocator, 1, 0, 100) });

    try testing.expect(wq.attestation.isEmpty());
}

test "WorkQueues: LIFO overflow deinitializes dropped owned gossip data" {
    const allocator = testing.allocator;
    var config = testQueueConfig();
    config.attestation = 1;

    var wq = try WorkQueues.init(allocator, config);
    defer wq.deinit();

    wq.routeToQueue(.{ .attestation = try testOwnedAttestationWork(allocator, 1, 0, 100) });
    wq.routeToQueue(.{ .attestation = try testOwnedAttestationWork(allocator, 2, 1, 200) });

    const queued = wq.popHighestPriority().?;
    defer queued.deinit(allocator);
    try testing.expectEqual(WorkType.attestation, queued.workType());
}

test "WorkQueues: FIFO overflow deinitializes rejected owned API handles" {
    const allocator = testing.allocator;
    var config = testQueueConfig();
    config.api_request_p1 = 1;

    var wq = try WorkQueues.init(allocator, config);
    defer wq.deinit();

    var dropped_existing: u32 = 0;
    var dropped_rejected: u32 = 0;
    wq.routeToQueue(.{ .api_request_p1 = .{
        .response = try makeOwnedHandle(allocator, &dropped_existing),
        .seen_timestamp_ns = 100,
    } });
    wq.routeToQueue(.{ .api_request_p1 = .{
        .response = try makeOwnedHandle(allocator, &dropped_rejected),
        .seen_timestamp_ns = 200,
    } });

    try testing.expectEqual(@as(u32, 0), dropped_existing);
    try testing.expectEqual(@as(u32, 1), dropped_rejected);

    const queued = wq.popHighestPriority().?;
    defer queued.deinit(allocator);
    try testing.expectEqual(WorkType.api_request_p1, queued.workType());
}

/// Test helper: tiny queue config with capacity 4 for all queues.
fn testQueueConfig() QueueConfig {
    return .{
        .chain_segment = 4,
        .rpc_block = 4,
        .rpc_blob = 4,
        .rpc_custody_column = 4,
        .gossip_block_ingress = 4,
        .gossip_blob_ingress = 4,
        .gossip_data_column_ingress = 4,
        .gossip_attestation_ingress = 4,
        .gossip_aggregate_ingress = 4,
        .gossip_sync_contribution_ingress = 4,
        .gossip_sync_message_ingress = 4,
        .gossip_voluntary_exit_ingress = 4,
        .gossip_proposer_slashing_ingress = 4,
        .gossip_attester_slashing_ingress = 4,
        .gossip_bls_to_exec_ingress = 4,
        .delayed_block = 4,
        .gossip_block = 4,
        .gossip_execution_payload = 4,
        .gossip_blob = 4,
        .gossip_data_column = 4,
        .column_reconstruction = 4,
        .api_request_p0 = 4,
        .aggregate = 4,
        .attestation = 4,
        .gossip_payload_attestation = 4,
        .sync_contribution = 4,
        .sync_message = 4,
        .gossip_execution_payload_bid = 4,
        .gossip_proposer_preferences = 4,
        .status = 4,
        .blocks_by_range = 4,
        .blocks_by_root = 4,
        .blobs_by_range = 4,
        .blobs_by_root = 4,
        .columns_by_range = 4,
        .columns_by_root = 4,
        .gossip_attester_slashing = 4,
        .gossip_proposer_slashing = 4,
        .gossip_voluntary_exit = 4,
        .gossip_bls_to_exec = 4,
        .api_request_p1 = 4,
        .backfill_segment = 4,
        .lc_bootstrap = 4,
        .lc_finality_update = 4,
        .lc_optimistic_update = 4,
        .lc_updates_by_range = 4,
    };
}

fn testOpaqueHandle(tag: usize) OpaqueHandle {
    return OpaqueHandle.initBorrowed(@ptrFromInt(0x2000 + tag));
}

fn testPeerId(tag: u8) PeerIdHandle {
    return switch (tag) {
        1 => PeerIdHandle.initBorrowed("peer-1"),
        2 => PeerIdHandle.initBorrowed("peer-2"),
        else => PeerIdHandle.initBorrowed("peer-x"),
    };
}

fn testSource(tag: u64) GossipSource {
    return .{ .key = tag };
}

fn testMessageId(tag: u8) MessageId {
    var out = std.mem.zeroes(MessageId);
    out[0] = tag;
    return out;
}

const DropCounterHandle = struct {
    allocator: Allocator,
    counter: *u32,

    pub fn deinit(self: *DropCounterHandle) void {
        self.counter.* += 1;
        self.allocator.destroy(self);
    }
};

fn makeOwnedHandle(allocator: Allocator, counter: *u32) !OpaqueHandle {
    const handle = try allocator.create(DropCounterHandle);
    handle.* = .{
        .allocator = allocator,
        .counter = counter,
    };
    return OpaqueHandle.initOwned(DropCounterHandle, handle);
}

fn testGossipAttestation(tag: u64) fork_types.AnyGossipAttestation {
    return testGossipAttestationWithSlot(tag, 100 + tag);
}

fn testGossipAttestationWithSlot(tag: u64, slot: u64) fork_types.AnyGossipAttestation {
    var attestation = consensus_types.electra.SingleAttestation.default_value;
    attestation.committee_index = @intCast(tag % 8);
    attestation.attester_index = tag;
    attestation.data.slot = slot;
    attestation.data.target.epoch = 4;
    return .{ .electra_single = attestation };
}

fn testGossipAttestationDataRoot(attestation: *const fork_types.AnyGossipAttestation) [32]u8 {
    var root: [32]u8 = undefined;
    consensus_types.phase0.AttestationData.hashTreeRoot(&attestation.data(), &root) catch unreachable;
    return root;
}

fn testAttestationWork(tag: u64, subnet_id: u8, seen_timestamp_ns: i64) AttestationWork {
    return testAttestationWorkWithSlot(tag, 100 + tag, subnet_id, seen_timestamp_ns);
}

fn testAttestationWorkWithSlot(tag: u64, slot: u64, subnet_id: u8, seen_timestamp_ns: i64) AttestationWork {
    const attestation = testGossipAttestationWithSlot(tag, slot);
    return .{
        .source = testSource(tag),
        .message_id = testMessageId(@intCast(tag & 0xff)),
        .attestation = attestation,
        .attestation_data_root = testGossipAttestationDataRoot(&attestation),
        .resolved = .{
            .validator_index = tag,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{@intCast(tag % 251)} ** 32,
            .expected_subnet = subnet_id,
        },
        .subnet_id = subnet_id,
        .seen_timestamp_ns = seen_timestamp_ns,
    };
}

fn testSyncMessageWork(tag: u64, slot: u64, seen_timestamp_ns: i64) SyncMessageWork {
    var message = consensus_types.altair.SyncCommitteeMessage.default_value;
    message.slot = slot;
    message.validator_index = tag;
    message.beacon_block_root = [_]u8{@intCast(tag % 251)} ** 32;
    return .{
        .source = testSource(tag),
        .message_id = testMessageId(@intCast(tag & 0xff)),
        .message = message,
        .subnet_id = @intCast(tag % 4),
        .seen_timestamp_ns = seen_timestamp_ns,
    };
}

fn testOwnedAttestationWork(
    allocator: Allocator,
    tag: u64,
    subnet_id: u8,
    seen_timestamp_ns: i64,
) !AttestationWork {
    const attestation = try testOwnedPhase0GossipAttestation(allocator, tag);
    return .{
        .source = testSource(tag),
        .message_id = testMessageId(@intCast(tag & 0xff)),
        .attestation = attestation,
        .attestation_data_root = testGossipAttestationDataRoot(&attestation),
        .resolved = .{
            .validator_index = tag,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{@intCast(tag % 251)} ** 32,
            .expected_subnet = subnet_id,
        },
        .subnet_id = subnet_id,
        .seen_timestamp_ns = seen_timestamp_ns,
    };
}

fn testOwnedPhase0GossipAttestation(
    allocator: Allocator,
    tag: u64,
) !fork_types.AnyGossipAttestation {
    var aggregation_bits = std.ArrayListUnmanaged(u8).empty;
    try aggregation_bits.append(allocator, 0x01);

    return .{
        .phase0 = .{
            .aggregation_bits = .{
                .data = aggregation_bits,
                .bit_len = 1,
            },
            .data = .{
                .slot = 100 + tag,
                .index = @intCast(tag % 8),
                .beacon_block_root = [_]u8{@intCast(tag)} ** 32,
                .source = .{ .epoch = 3, .root = [_]u8{0x11} ** 32 },
                .target = .{ .epoch = 4, .root = [_]u8{0x22} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        },
    };
}
