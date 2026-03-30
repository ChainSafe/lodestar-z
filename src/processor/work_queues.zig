//! WorkQueues — the collection of per-type priority queues for the BeaconProcessor.
//!
//! Contains ~35 typed queues, one per work type that requires queueing.
//! Queue sizes are computed from active validator count via `QueueConfig`.
//! Provides `routeToQueue()` for ingestion and `popHighestPriority()` for
//! strict-priority draining.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const work_item_mod = @import("work_item.zig");
const WorkItem = work_item_mod.WorkItem;
const WorkType = work_item_mod.WorkType;
const MessageId = work_item_mod.MessageId;
const GossipBlockWork = work_item_mod.GossipBlockWork;
const GossipBlobWork = work_item_mod.GossipBlobWork;
const GossipColumnWork = work_item_mod.GossipColumnWork;
const GossipPayloadWork = work_item_mod.GossipPayloadWork;
const DelayedBlockWork = work_item_mod.DelayedBlockWork;
const ColumnReconstructionWork = work_item_mod.ColumnReconstructionWork;
const AttestationWork = work_item_mod.AttestationWork;
const AttestationBatchWork = work_item_mod.AttestationBatchWork;
const AggregateWork = work_item_mod.AggregateWork;
const AggregateBatchWork = work_item_mod.AggregateBatchWork;
const ReprocessWork = work_item_mod.ReprocessWork;
const SyncMessageWork = work_item_mod.SyncMessageWork;
const SyncContributionWork = work_item_mod.SyncContributionWork;
const PoolObjectWork = work_item_mod.PoolObjectWork;
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
    unknown_block_aggregate: u32,
    unknown_block_attestation: u32,
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

        // Unknown block queues match attestation sizing.
        const unknown_att_queue = att_queue;

        return .{
            .chain_segment = 64,
            .rpc_block = 1024,
            .rpc_blob = 1024,
            .rpc_custody_column = 64,
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
            .unknown_block_aggregate = 1024,
            .unknown_block_attestation = unknown_att_queue,
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
    // ── FIFO queues ──
    chain_segment: FifoQueue(ChainSegmentWork),
    rpc_block: FifoQueue(RpcBlockWork),
    rpc_blob: FifoQueue(RpcBlobWork),
    rpc_custody_column: FifoQueue(RpcColumnWork),
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
    gossip_attester_slashing: FifoQueue(PoolObjectWork),
    gossip_proposer_slashing: FifoQueue(PoolObjectWork),
    gossip_voluntary_exit: FifoQueue(PoolObjectWork),
    gossip_bls_to_exec: FifoQueue(PoolObjectWork),
    api_request_p1: FifoQueue(ApiWork),
    backfill_segment: FifoQueue(BackfillWork),
    lc_bootstrap: FifoQueue(LightClientWork),
    lc_finality_update: FifoQueue(LightClientWork),
    lc_optimistic_update: FifoQueue(LightClientWork),
    lc_updates_by_range: FifoQueue(LightClientWork),

    // ── LIFO queues ──
    aggregate: LifoQueue(AggregateWork),
    attestation: LifoQueue(AttestationWork),
    unknown_block_aggregate: LifoQueue(ReprocessWork),
    unknown_block_attestation: LifoQueue(ReprocessWork),
    sync_contribution: LifoQueue(SyncContributionWork),
    sync_message: LifoQueue(SyncMessageWork),
    column_reconstruction: LifoQueue(ColumnReconstructionWork),

    // ── State ──
    sync_state: SyncState,

    // ── Metrics counters (plain u64, no Prometheus yet) ──
    items_routed: u64,
    items_dropped_full: u64,
    items_dropped_sync: u64,

    // ── Batch scratch buffers (owned by allocator) ──
    attestation_batch_buf: []AttestationWork,
    aggregate_batch_buf: []AggregateWork,

    /// Initialise all queues from individually allocated per-type slices.
    /// Each queue gets its own slice from the allocator.
    pub fn init(
        allocator: std.mem.Allocator,
        config: QueueConfig,
    ) !WorkQueues {
        return .{
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
            .gossip_attester_slashing = FifoQueue(PoolObjectWork).init(
                try allocator.alloc(PoolObjectWork, config.gossip_attester_slashing),
            ),
            .gossip_proposer_slashing = FifoQueue(PoolObjectWork).init(
                try allocator.alloc(PoolObjectWork, config.gossip_proposer_slashing),
            ),
            .gossip_voluntary_exit = FifoQueue(PoolObjectWork).init(
                try allocator.alloc(PoolObjectWork, config.gossip_voluntary_exit),
            ),
            .gossip_bls_to_exec = FifoQueue(PoolObjectWork).init(
                try allocator.alloc(PoolObjectWork, config.gossip_bls_to_exec),
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

            // LIFO queues.
            .aggregate = LifoQueue(AggregateWork).init(
                try allocator.alloc(AggregateWork, config.aggregate),
            ),
            .attestation = LifoQueue(AttestationWork).init(
                try allocator.alloc(AttestationWork, config.attestation),
            ),
            .unknown_block_aggregate = LifoQueue(ReprocessWork).init(
                try allocator.alloc(ReprocessWork, config.unknown_block_aggregate),
            ),
            .unknown_block_attestation = LifoQueue(ReprocessWork).init(
                try allocator.alloc(ReprocessWork, config.unknown_block_attestation),
            ),
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
        };
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
            return;
        }

        self.items_routed += 1;

        // Helper: push to a FIFO queue, count drops on overflow.
        const pushFifo = struct {
            fn call(dropped: *u64, queue: anytype, w: anytype) void {
                if (!queue.push(w)) dropped.* += 1;
            }
        }.call;

        switch (item) {
            // ── FIFO queues ──
            inline .chain_segment, .rpc_block, .rpc_blob, .rpc_custody_column,
            .delayed_block, .gossip_block, .gossip_execution_payload, .gossip_blob,
            .gossip_data_column, .api_request_p0, .gossip_payload_attestation,
            .gossip_execution_payload_bid, .gossip_proposer_preferences,
            .status, .blocks_by_range, .blocks_by_root, .blobs_by_range, .blobs_by_root,
            .columns_by_range, .columns_by_root, .gossip_attester_slashing,
            .gossip_proposer_slashing, .gossip_voluntary_exit, .gossip_bls_to_exec,
            .api_request_p1, .backfill_segment, .lc_bootstrap, .lc_finality_update,
            .lc_optimistic_update, .lc_updates_by_range => |w, tag| {
                pushFifo(&self.items_dropped_full, &@field(self, @tagName(tag)), w);
            },

            // ── LIFO queues: always accept, drop oldest on overflow ──
            inline .aggregate, .attestation, .unknown_block_aggregate,
            .unknown_block_attestation, .sync_contribution, .sync_message,
            .column_reconstruction => |w, tag| {
                @field(self, @tagName(tag)).push(w);
            },

            // ── Batch items are produced internally, not routed from inbound ──
            .attestation_batch, .aggregate_batch => unreachable,

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
        // Priority 1-4: Sync.
        if (self.chain_segment.pop()) |w| return .{ .chain_segment = w };
        if (self.rpc_block.pop()) |w| return .{ .rpc_block = w };
        if (self.rpc_blob.pop()) |w| return .{ .rpc_blob = w };
        if (self.rpc_custody_column.pop()) |w| return .{ .rpc_custody_column = w };

        // Priority 5-9: Gossip blocks + DA.
        if (self.delayed_block.pop()) |w| return .{ .delayed_block = w };
        if (self.gossip_block.pop()) |w| return .{ .gossip_block = w };
        if (self.gossip_execution_payload.pop()) |w| return .{ .gossip_execution_payload = w };
        if (self.gossip_blob.pop()) |w| return .{ .gossip_blob = w };
        if (self.gossip_data_column.pop()) |w| return .{ .gossip_data_column = w };

        // Priority 10: Column reconstruction.
        if (self.column_reconstruction.pop()) |w| return .{ .column_reconstruction = w };

        // Priority 11: High-priority API.
        if (self.api_request_p0.pop()) |w| return .{ .api_request_p0 = w };

        // Priority 12-13: Attestations — form batches for BLS batch verify.
        if (self.aggregate.len > 0) {
            return self.formAggregateBatch();
        }
        if (self.attestation.len > 0) {
            return self.formAttestationBatch();
        }

        // Priority 14: Payload attestation (Gloas).
        if (self.gossip_payload_attestation.pop()) |w| return .{ .gossip_payload_attestation = w };

        // Priority 15-16: Sync committee.
        if (self.sync_contribution.pop()) |w| return .{ .sync_contribution = w };
        if (self.sync_message.pop()) |w| return .{ .sync_message = w };

        // Priority 17-18: Unknown block reprocessing.
        if (self.unknown_block_aggregate.pop()) |w| return .{ .unknown_block_aggregate = w };
        if (self.unknown_block_attestation.pop()) |w| return .{ .unknown_block_attestation = w };

        // Priority 19-20: Gloas.
        if (self.gossip_execution_payload_bid.pop()) |w| return .{ .gossip_execution_payload_bid = w };
        if (self.gossip_proposer_preferences.pop()) |w| return .{ .gossip_proposer_preferences = w };

        // Priority 21-27: Peer serving.
        if (self.status.pop()) |w| return .{ .status = w };
        if (self.blocks_by_range.pop()) |w| return .{ .blocks_by_range = w };
        if (self.blocks_by_root.pop()) |w| return .{ .blocks_by_root = w };
        if (self.blobs_by_range.pop()) |w| return .{ .blobs_by_range = w };
        if (self.blobs_by_root.pop()) |w| return .{ .blobs_by_root = w };
        if (self.columns_by_range.pop()) |w| return .{ .columns_by_range = w };
        if (self.columns_by_root.pop()) |w| return .{ .columns_by_root = w };

        // Priority 28-31: Pool objects.
        if (self.gossip_attester_slashing.pop()) |w| return .{ .gossip_attester_slashing = w };
        if (self.gossip_proposer_slashing.pop()) |w| return .{ .gossip_proposer_slashing = w };
        if (self.gossip_voluntary_exit.pop()) |w| return .{ .gossip_voluntary_exit = w };
        if (self.gossip_bls_to_exec.pop()) |w| return .{ .gossip_bls_to_exec = w };

        // Priority 32: Low-priority API.
        if (self.api_request_p1.pop()) |w| return .{ .api_request_p1 = w };

        // Priority 33: Backfill (dead last).
        if (self.backfill_segment.pop()) |w| return .{ .backfill_segment = w };

        // Priority 34-37: Light client.
        if (self.lc_bootstrap.pop()) |w| return .{ .lc_bootstrap = w };
        if (self.lc_finality_update.pop()) |w| return .{ .lc_finality_update = w };
        if (self.lc_optimistic_update.pop()) |w| return .{ .lc_optimistic_update = w };
        if (self.lc_updates_by_range.pop()) |w| return .{ .lc_updates_by_range = w };

        return null;
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

        // LIFO queues.
        total += self.aggregate.len;
        total += self.attestation.len;
        total += self.unknown_block_aggregate.len;
        total += self.unknown_block_attestation.len;
        total += self.sync_contribution.len;
        total += self.sync_message.len;
        total += self.column_reconstruction.len;

        return total;
    }

    // ── Batch formation ──

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
            return .{ .attestation = self.attestation.pop().? };
        }
        const batch_size = @min(
            self.attestation.len,
            work_item_mod.max_attestation_batch_size,
        );
        const count = self.attestation.popBatch(
            self.attestation_batch_buf[0..batch_size],
        );
        assert(count > 0);
        return .{ .attestation_batch = .{
            .items = self.attestation_batch_buf.ptr,
            .count = count,
        } };
    }
};

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
        .response_handle = 1,
        .seen_timestamp_ns = 100,
    } });
    wq.routeToQueue(.{ .status = .{
        .peer_id = 1,
        .request_context = 2,
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

test "WorkQueues: sync-aware dropping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = testQueueConfig();
    var wq = try WorkQueues.init(allocator, config);
    wq.sync_state = .syncing;

    // Attestation should be dropped during sync.
    const dummy_handle: *anyopaque = @ptrFromInt(0xDEAD);
    wq.routeToQueue(.{ .attestation = .{
        .peer_id = 1,
        .message_id = testMessageId(1),
        .data = dummy_handle,
        .subnet_id = 0,
        .seen_timestamp_ns = 100,
    } });

    try testing.expectEqual(@as(u64, 1), wq.items_dropped_sync);
    try testing.expect(wq.attestation.isEmpty());

    // Status should NOT be dropped during sync.
    wq.routeToQueue(.{ .status = .{
        .peer_id = 1,
        .request_context = 2,
        .seen_timestamp_ns = 200,
    } });

    try testing.expectEqual(@as(u32, 1), wq.status.len);
}

/// Test helper: tiny queue config with capacity 4 for all queues.
fn testQueueConfig() QueueConfig {
    return .{
        .chain_segment = 4,
        .rpc_block = 4,
        .rpc_blob = 4,
        .rpc_custody_column = 4,
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
        .unknown_block_aggregate = 4,
        .unknown_block_attestation = 4,
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

fn testMessageId(tag: u8) MessageId {
    var out = std.mem.zeroes(MessageId);
    out[0] = tag;
    return out;
}
