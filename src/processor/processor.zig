//! BeaconProcessor — the central scheduling loop.
//!
//! The active boundary here is gossip. Typed gossip ingress, unknown-parent
//! parking, deferred validation completion, and async gossip verification all
//! live under this processor now. Handlers still execute inline on the main
//! owner thread.
//!
//! Architecture:
//! ```
//!   Inbound Channel ──▶ routeToQueue() ──▶ popHighestPriority() ──▶ handler()
//! ```
//!
//! The processor is designed to run as a single fiber in the std.Io event
//! loop. It never does CPU-heavy work itself — just routes and dispatches.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const work_item_mod = @import("work_item.zig");
const WorkItem = work_item_mod.WorkItem;
const WorkType = work_item_mod.WorkType;
const GossipSource = work_item_mod.GossipSource;
const GossipTopicType = work_item_mod.GossipTopicType;
const AttestationWork = work_item_mod.AttestationWork;
const AggregateWork = work_item_mod.AggregateWork;
const MessageId = work_item_mod.MessageId;
const OpaqueHandle = work_item_mod.OpaqueHandle;
const PeerIdHandle = work_item_mod.PeerIdHandle;
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const Root = consensus_types.primitive.Root.Type;
const Slot = consensus_types.primitive.Slot.Type;

const work_queues_mod = @import("work_queues.zig");
const WorkQueues = work_queues_mod.WorkQueues;
const QueueConfig = work_queues_mod.QueueConfig;
const SyncState = work_queues_mod.SyncState;
const pending_unknown_block_gossip_mod = @import("pending_unknown_block_gossip.zig");
const PendingUnknownBlockGossipQueue = pending_unknown_block_gossip_mod.Queue;
const PendingUnknownBlockGossipCallbacks = pending_unknown_block_gossip_mod.Callbacks;
const PendingUnknownBlockGossipItem = pending_unknown_block_gossip_mod.PendingItem;
const ReleasedPendingUnknownBlockItems = pending_unknown_block_gossip_mod.ReleasedItems;

// ---------------------------------------------------------------------------
// Handler function type.
// ---------------------------------------------------------------------------

/// Handler callback: processes a single work item.
/// Called inline by the processor loop (no worker pool yet).
pub const HandlerFn = *const fn (item: WorkItem, context: *anyopaque) void;

// ---------------------------------------------------------------------------
// Metrics — plain u64 counters, no Prometheus yet.
// ---------------------------------------------------------------------------

/// Per-type and aggregate metrics for the processor.
pub const ProcessorMetrics = struct {
    /// Total items processed, per work type.
    items_processed: [WorkType.count]u64,
    /// Total processing time in nanoseconds, per work type.
    processing_time_ns: [WorkType.count]u64,
    /// Number of times the processor loop iterated.
    loop_iterations: u64,
    /// Number of times we popped from queues (items dispatched).
    items_dispatched: u64,
    /// Number of inbound items received from the channel.
    items_received: u64,

    pub fn init() ProcessorMetrics {
        return .{
            .items_processed = [_]u64{0} ** WorkType.count,
            .processing_time_ns = [_]u64{0} ** WorkType.count,
            .loop_iterations = 0,
            .items_dispatched = 0,
            .items_received = 0,
        };
    }

    /// Record that a work item of the given type was processed.
    pub fn recordProcessed(
        self: *ProcessorMetrics,
        wtype: WorkType,
        elapsed_ns: u64,
    ) void {
        const idx = @intFromEnum(wtype);
        self.items_processed[idx] +|= 1;
        self.processing_time_ns[idx] +|= elapsed_ns;
    }
};

pub const MetricsSnapshot = struct {
    items_processed: [WorkType.count]u64,
    processing_time_ns: [WorkType.count]u64,
    loop_iterations: u64,
    items_dispatched: u64,
    items_received: u64,
    items_dropped_full: u64,
    items_dropped_sync: u64,
    queue_depths: BeaconProcessor.QueueDepths,
};

pub const GossipRejectReason = enum {
    decode_failed,
    invalid_signature,
    wrong_subnet,
    invalid_block,
    invalid_attestation,
    invalid_aggregate,
    invalid_voluntary_exit,
    invalid_proposer_slashing,
    invalid_attester_slashing,
    invalid_bls_to_execution_change,
    invalid_sync_contribution,
    invalid_sync_committee_message,
    invalid_blob_sidecar,
    invalid_data_column_sidecar,
};

pub const GossipValidationContext = struct {
    peer_id: PeerIdHandle = .none,
    fork_digest: [4]u8,
    topic_type: GossipTopicType,
    subnet_id: ?u8 = null,

    pub fn deinit(self: *GossipValidationContext) void {
        self.peer_id.deinit();
        self.* = undefined;
    }
};

pub const GossipValidationOutcome = union(enum) {
    accept,
    ignore,
    reject: GossipRejectReason,
};

pub const CompletedGossipValidation = struct {
    msg_id: MessageId,
    context: GossipValidationContext,
    outcome: GossipValidationOutcome,

    pub fn deinit(self: *CompletedGossipValidation) void {
        self.context.deinit();
        self.* = undefined;
    }
};

pub const PendingGossipBatchKind = enum {
    attestation,
    aggregate,
    sync_message,
};

pub const PendingGossipBatchPriority = enum(u8) {
    high,
    normal,
};

pub const GossipBlsPendingSnapshot = struct {
    attestation_batches: u64 = 0,
    attestation_items: u64 = 0,
    aggregate_batches: u64 = 0,
    aggregate_items: u64 = 0,
    sync_message_batches: u64 = 0,
    sync_message_items: u64 = 0,
};

pub const PendingGossipBatchHandle = struct {
    ptr: *anyopaque,
    kind: PendingGossipBatchKind,
    item_count: u32,
    priority: PendingGossipBatchPriority = .normal,
    is_started_fn: *const fn (ptr: *anyopaque) bool,
    is_ready_fn: *const fn (ptr: *anyopaque) bool,
    mark_started_fn: *const fn (ptr: *anyopaque, now_ns: i64) void,
    drain_fn: *const fn (ptr: *anyopaque, context: *anyopaque, finished_at_ns: i64) void,

    fn isStarted(self: PendingGossipBatchHandle) bool {
        return self.is_started_fn(self.ptr);
    }

    fn isReady(self: PendingGossipBatchHandle) bool {
        return self.is_ready_fn(self.ptr);
    }

    fn markStarted(self: PendingGossipBatchHandle, now_ns: i64) void {
        self.mark_started_fn(self.ptr, now_ns);
    }

    fn drain(self: PendingGossipBatchHandle, context: *anyopaque, finished_at_ns: i64) void {
        self.drain_fn(self.ptr, context, finished_at_ns);
    }
};

// ---------------------------------------------------------------------------
// BeaconProcessor
// ---------------------------------------------------------------------------

/// The central scheduling processor.
///
/// For Phase 1 (inline execution), the run loop is:
/// 1. Try to receive a work item from the inbound slice.
/// 2. Route it to the appropriate per-type queue.
/// 3. Pop the highest-priority item and execute it inline.
/// 4. Record metrics.
///
/// This struct is designed to be driven externally (call `processOne` or
/// `drainInbound` + `dispatchOne` in a loop) rather than owning the event
/// loop, so it composes cleanly with std.Io fibers.
pub const BeaconProcessor = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    queues: WorkQueues,
    handler: HandlerFn,
    handler_context: *anyopaque,
    metrics: ProcessorMetrics,
    pending_gossip_validations: std.AutoHashMap(MessageId, GossipValidationContext),
    completed_gossip_validations: std.ArrayListUnmanaged(CompletedGossipValidation) = .empty,
    pending_gossip_batches: std.ArrayListUnmanaged(PendingGossipBatchHandle) = .empty,
    pending_unknown_block_gossip: PendingUnknownBlockGossipQueue,

    /// Initialise the processor.
    ///
    /// `allocator`: used for queue backing buffers (allocated once at startup).
    /// `config`: queue capacity configuration.
    /// `handler`: callback invoked for each dispatched work item.
    /// `handler_context`: opaque pointer passed to the handler.
    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        config: QueueConfig,
        handler: HandlerFn,
        handler_context: *anyopaque,
    ) !BeaconProcessor {
        return .{
            .allocator = allocator,
            .io = io,
            .queues = try WorkQueues.init(allocator, config),
            .handler = handler,
            .handler_context = handler_context,
            .metrics = ProcessorMetrics.init(),
            .pending_gossip_validations = std.AutoHashMap(MessageId, GossipValidationContext).init(allocator),
            .pending_unknown_block_gossip = PendingUnknownBlockGossipQueue.init(allocator),
        };
    }

    pub fn deinit(self: *BeaconProcessor) void {
        self.flushPendingGossipBatches();
        self.pending_gossip_batches.deinit(self.allocator);
        self.pending_unknown_block_gossip.deinit();

        var pending_iter = self.pending_gossip_validations.valueIterator();
        while (pending_iter.next()) |context| {
            context.deinit();
        }
        self.pending_gossip_validations.deinit();

        for (self.completed_gossip_validations.items) |*completion| {
            completion.deinit();
        }
        self.completed_gossip_validations.deinit(self.allocator);
        self.queues.deinit();
    }

    /// Ingest a single work item into the appropriate queue.
    pub fn ingest(self: *BeaconProcessor, item: WorkItem) void {
        self.metrics.items_received += 1;
        self.queues.routeToQueue(item);
    }

    /// Ingest a topic-specific gossip work item into the processor.
    ///
    /// The work item must already be one of the typed gossip ingress variants.
    pub fn ingestGossipWork(self: *BeaconProcessor, item: WorkItem) void {
        assert(item.workType().gossipIngressTopicType() != null);
        self.ingest(item);
    }

    /// Dispatch the highest-priority queued item to the handler.
    /// Returns true if an item was dispatched, false if all queues empty.
    pub fn dispatchOne(self: *BeaconProcessor) bool {
        const now_ns = std.Io.Timestamp.now(self.io, .real).toNanoseconds();
        const item = self.queues.popHighestPriorityAt(if (now_ns > std.math.maxInt(i64))
            std.math.maxInt(i64)
        else
            @intCast(now_ns)) orelse return false;

        self.dispatchItem(item);
        return true;
    }

    fn dispatchItem(self: *BeaconProcessor, item: WorkItem) void {
        const wtype = item.workType();

        const t0 = std.Io.Timestamp.now(self.io, .real).toNanoseconds();
        self.handler(item, self.handler_context);
        const t1 = std.Io.Timestamp.now(self.io, .real).toNanoseconds();
        const elapsed: u64 = if (t1 > t0) @intCast(t1 - t0) else 0;
        self.metrics.recordProcessed(wtype, elapsed);
        self.metrics.items_dispatched += 1;
    }

    /// Process one iteration: ingest an item, then dispatch highest priority.
    /// Combines ingest + dispatch for the simple inline-execution model.
    pub fn processOne(self: *BeaconProcessor, item: WorkItem) void {
        self.ingest(item);
        _ = self.dispatchOne();
    }

    /// Drain all queues by repeatedly dispatching until empty.
    /// Useful for testing and shutdown.
    pub fn drainAll(self: *BeaconProcessor) u64 {
        var count: u64 = 0;
        while (self.dispatchOne()) {
            count += 1;
        }
        return count;
    }

    /// Process up to `max_items` work items in priority order.
    ///
    /// Returns the number of items dispatched. Designed for cooperative
    /// scheduling: call once per main-loop tick to process queued work
    /// without monopolizing the event loop.
    ///
    /// Recommended: max_items = 128 (matches TS Lodestar's MAX_JOBS_SUBMITTED_PER_TICK).
    pub fn tick(self: *BeaconProcessor, max_items: u32) u64 {
        var count: u64 = 0;
        while (count < max_items) {
            if (!self.dispatchOne()) break;
            count += 1;
        }
        self.metrics.loop_iterations += 1;
        return count;
    }

    pub fn trackDeferredGossipValidation(
        self: *BeaconProcessor,
        msg_id: MessageId,
        context: GossipValidationContext,
    ) !void {
        const entry = try self.pending_gossip_validations.getOrPut(msg_id);
        if (entry.found_existing) {
            entry.value_ptr.deinit();
        }
        entry.value_ptr.* = context;
    }

    pub fn finishDeferredGossipValidation(
        self: *BeaconProcessor,
        msg_id: MessageId,
        outcome: GossipValidationOutcome,
    ) void {
        const removed = self.pending_gossip_validations.fetchRemove(msg_id) orelse return;
        self.queueGossipValidationResult(removed.key, removed.value, outcome);
    }

    pub fn queueGossipValidationResult(
        self: *BeaconProcessor,
        msg_id: MessageId,
        context: GossipValidationContext,
        outcome: GossipValidationOutcome,
    ) void {
        self.completed_gossip_validations.append(self.allocator, .{
            .msg_id = msg_id,
            .context = context,
            .outcome = outcome,
        }) catch |err| {
            var dropped_context = context;
            dropped_context.deinit();
            std.log.warn("failed to queue completed gossip validation result: {}", .{err});
        };
    }

    pub fn popGossipValidationResult(self: *BeaconProcessor) ?CompletedGossipValidation {
        if (self.completed_gossip_validations.items.len == 0) return null;
        return self.completed_gossip_validations.orderedRemove(0);
    }

    pub fn queueUnknownBlockAttestation(
        self: *BeaconProcessor,
        block_root: Root,
        work: AttestationWork,
        peer_id: ?[]const u8,
    ) !bool {
        const added = try self.pending_unknown_block_gossip.addAttestation(block_root, peer_id, work);
        self.drainDroppedPendingUnknownBlockGossip();
        return added;
    }

    pub fn queueUnknownBlockAggregate(
        self: *BeaconProcessor,
        block_root: Root,
        work: AggregateWork,
        peer_id: ?[]const u8,
    ) !bool {
        const added = try self.pending_unknown_block_gossip.addAggregate(block_root, peer_id, work);
        self.drainDroppedPendingUnknownBlockGossip();
        return added;
    }

    pub fn onPendingUnknownBlockFetchAccepted(self: *BeaconProcessor, block_root: Root) void {
        self.pending_unknown_block_gossip.onFetchAccepted(block_root);
    }

    pub fn onPendingUnknownBlockFetchFailed(
        self: *BeaconProcessor,
        block_root: Root,
        peer_id: ?[]const u8,
    ) void {
        self.pending_unknown_block_gossip.onFetchFailed(block_root, peer_id);
        self.drainDroppedPendingUnknownBlockGossip();
    }

    pub fn dropPendingUnknownBlock(self: *BeaconProcessor, block_root: Root) void {
        self.pending_unknown_block_gossip.dropRoot(block_root);
        self.drainDroppedPendingUnknownBlockGossip();
    }

    pub fn onPendingUnknownBlockSlot(self: *BeaconProcessor, current_slot: Slot) void {
        self.pending_unknown_block_gossip.onSlot(current_slot);
        self.drainDroppedPendingUnknownBlockGossip();
    }

    pub fn drivePendingUnknownBlockGossip(
        self: *BeaconProcessor,
        callbacks: PendingUnknownBlockGossipCallbacks,
    ) void {
        self.pending_unknown_block_gossip.tick(callbacks);
        self.drainDroppedPendingUnknownBlockGossip();
    }

    pub fn releasePendingUnknownBlockGossip(self: *BeaconProcessor, block_root: Root) void {
        var released: ReleasedPendingUnknownBlockItems = .empty;
        defer {
            for (released.items) |*item| item.deinit(self.allocator);
            released.deinit(self.allocator);
        }

        self.pending_unknown_block_gossip.releaseImported(block_root, &released) catch return;
        for (released.items) |item| {
            self.requeuePendingUnknownBlockGossipItem(item);
        }
        released.items.len = 0;
    }

    pub fn pendingUnknownBlockGossipCount(self: *const BeaconProcessor) usize {
        return self.pending_unknown_block_gossip.pendingCount();
    }

    pub fn ensurePendingGossipBatchCapacity(self: *BeaconProcessor, additional: usize) !void {
        try self.pending_gossip_batches.ensureUnusedCapacity(self.allocator, additional);
    }

    pub fn enqueuePendingGossipBatch(
        self: *BeaconProcessor,
        pending: PendingGossipBatchHandle,
    ) void {
        const items = self.pending_gossip_batches.items;
        var insert_at = items.len;
        if (pending.priority == .high) {
            insert_at = 0;
            while (insert_at < items.len) : (insert_at += 1) {
                if (items[insert_at].priority != .high) break;
            }
        }
        self.pending_gossip_batches.insertAssumeCapacity(insert_at, pending);
    }

    pub fn processPendingGossipBatches(self: *BeaconProcessor) bool {
        const now_ns = wallNowNs(self.io);
        for (self.pending_gossip_batches.items) |pending| {
            pending.markStarted(now_ns);
        }

        var did_work = false;
        while (findReadyPendingGossipBatch(self)) |ready_index| {
            const finished_at_ns = wallNowNs(self.io);
            const ready = self.pending_gossip_batches.orderedRemove(ready_index);
            ready.markStarted(finished_at_ns);
            ready.drain(self.handler_context, finished_at_ns);
            did_work = true;
        }

        return did_work or self.pending_gossip_batches.items.len > 0;
    }

    pub fn flushPendingGossipBatches(self: *BeaconProcessor) void {
        while (self.pending_gossip_batches.items.len > 0) {
            const active_index = findStartedPendingGossipBatch(self) orelse 0;
            const finished_at_ns = wallNowNs(self.io);
            const pending = self.pending_gossip_batches.orderedRemove(active_index);
            pending.markStarted(finished_at_ns);
            pending.drain(self.handler_context, finished_at_ns);
        }
    }

    pub fn gossipBlsPendingSnapshot(self: *const BeaconProcessor) GossipBlsPendingSnapshot {
        var snapshot: GossipBlsPendingSnapshot = .{};
        for (self.pending_gossip_batches.items) |pending| {
            switch (pending.kind) {
                .attestation => {
                    snapshot.attestation_batches += 1;
                    snapshot.attestation_items += pending.item_count;
                },
                .aggregate => {
                    snapshot.aggregate_batches += 1;
                    snapshot.aggregate_items += pending.item_count;
                },
                .sync_message => {
                    snapshot.sync_message_batches += 1;
                    snapshot.sync_message_items += pending.item_count;
                },
            }
        }
        return snapshot;
    }

    /// Update the sync state (affects sync-aware dropping).
    pub fn setSyncState(self: *BeaconProcessor, state: SyncState) void {
        self.queues.sync_state = state;
    }

    pub fn setGossipBlsBatchDispatchEnabled(self: *BeaconProcessor, enabled: bool) void {
        self.queues.setGossipBlsBatchDispatchEnabled(enabled);
    }

    /// Returns total items currently queued.
    pub fn totalQueued(self: *const BeaconProcessor) u64 {
        return self.queues.totalQueued();
    }

    /// Returns true if all queues are empty.
    pub fn allQueuesEmpty(self: *const BeaconProcessor) bool {
        return self.queues.allQueuesEmpty();
    }

    /// Returns the number of items dropped due to full queues.
    pub fn itemsDroppedFull(self: *const BeaconProcessor) u64 {
        return self.queues.items_dropped_full;
    }

    /// Returns the number of items dropped during initial sync.
    pub fn itemsDroppedSync(self: *const BeaconProcessor) u64 {
        return self.queues.items_dropped_sync;
    }

    /// Returns a summary of queue depths for monitoring.
    pub const QueueDepths = struct {
        total: u64,
        gossip_block_ingress: u32,
        gossip_blob_ingress: u32,
        gossip_data_column_ingress: u32,
        gossip_attestation_ingress: u32,
        gossip_aggregate_ingress: u32,
        gossip_sync_message_ingress: u32,
        gossip_sync_contribution_ingress: u32,
        gossip_voluntary_exit_ingress: u32,
        gossip_proposer_slashing_ingress: u32,
        gossip_attester_slashing_ingress: u32,
        gossip_bls_to_exec_ingress: u32,
        gossip_blocks: u32,
        blob_sidecars: u32,
        data_column_sidecars: u32,
        attestations: u32,
        aggregates: u32,
        sync_messages: u32,
        sync_contributions: u32,
        voluntary_exits: u32,
        proposer_slashings: u32,
        attester_slashings: u32,
        bls_to_execution_changes: u32,
        pool_objects: u64,
    };

    pub fn getQueueDepths(self: *const BeaconProcessor) QueueDepths {
        return .{
            .total = self.queues.totalQueued(),
            .gossip_block_ingress = self.queues.gossip_block_ingress.len,
            .gossip_blob_ingress = self.queues.gossip_blob_ingress.len,
            .gossip_data_column_ingress = self.queues.gossip_data_column_ingress.len,
            .gossip_attestation_ingress = self.queues.gossip_attestation_ingress.len,
            .gossip_aggregate_ingress = self.queues.gossip_aggregate_ingress.len,
            .gossip_sync_message_ingress = self.queues.gossip_sync_message_ingress.len,
            .gossip_sync_contribution_ingress = self.queues.gossip_sync_contribution_ingress.len,
            .gossip_voluntary_exit_ingress = self.queues.gossip_voluntary_exit_ingress.len,
            .gossip_proposer_slashing_ingress = self.queues.gossip_proposer_slashing_ingress.len,
            .gossip_attester_slashing_ingress = self.queues.gossip_attester_slashing_ingress.len,
            .gossip_bls_to_exec_ingress = self.queues.gossip_bls_to_exec_ingress.len,
            .gossip_blocks = self.queues.gossip_block_ingress.len +
                self.queues.delayed_block.len +
                self.queues.gossip_block.len,
            .blob_sidecars = self.queues.gossip_blob_ingress.len +
                self.queues.gossip_blob.len,
            .data_column_sidecars = self.queues.gossip_data_column_ingress.len +
                self.queues.gossip_data_column.len +
                self.queues.column_reconstruction.len,
            .attestations = self.queues.gossip_attestation_ingress.len +
                self.queues.attestation.len,
            .aggregates = self.queues.gossip_aggregate_ingress.len +
                self.queues.aggregate.len,
            .sync_messages = self.queues.gossip_sync_message_ingress.len +
                self.queues.sync_message.len,
            .sync_contributions = self.queues.gossip_sync_contribution_ingress.len +
                self.queues.sync_contribution.len,
            .voluntary_exits = self.queues.gossip_voluntary_exit_ingress.len +
                self.queues.gossip_voluntary_exit.len,
            .proposer_slashings = self.queues.gossip_proposer_slashing_ingress.len +
                self.queues.gossip_proposer_slashing.len,
            .attester_slashings = self.queues.gossip_attester_slashing_ingress.len +
                self.queues.gossip_attester_slashing.len,
            .bls_to_execution_changes = self.queues.gossip_bls_to_exec_ingress.len +
                self.queues.gossip_bls_to_exec.len,
            .pool_objects = self.queues.gossip_voluntary_exit_ingress.len +
                self.queues.gossip_proposer_slashing_ingress.len +
                self.queues.gossip_attester_slashing_ingress.len +
                self.queues.gossip_bls_to_exec_ingress.len +
                self.queues.gossip_voluntary_exit.len +
                self.queues.gossip_proposer_slashing.len +
                self.queues.gossip_attester_slashing.len +
                self.queues.gossip_bls_to_exec.len,
        };
    }

    pub fn metricsSnapshot(self: *const BeaconProcessor) MetricsSnapshot {
        return .{
            .items_processed = self.metrics.items_processed,
            .processing_time_ns = self.metrics.processing_time_ns,
            .loop_iterations = self.metrics.loop_iterations,
            .items_dispatched = self.metrics.items_dispatched,
            .items_received = self.metrics.items_received,
            .items_dropped_full = self.queues.items_dropped_full,
            .items_dropped_sync = self.queues.items_dropped_sync,
            .queue_depths = self.getQueueDepths(),
        };
    }

    fn requeuePendingUnknownBlockGossipItem(self: *BeaconProcessor, item: PendingUnknownBlockGossipItem) void {
        switch (item) {
            .attestation => |work| self.ingest(.{ .attestation = work }),
            .aggregate => |work| self.ingest(.{ .aggregate = work }),
        }
    }

    fn drainDroppedPendingUnknownBlockGossip(self: *BeaconProcessor) void {
        var dropped: ReleasedPendingUnknownBlockItems = .empty;
        defer {
            for (dropped.items) |*item| item.deinit(self.allocator);
            dropped.deinit(self.allocator);
        }

        self.pending_unknown_block_gossip.takeDropped(&dropped) catch |err| {
            std.log.warn("failed to drain dropped pending unknown-block gossip: {}", .{err});
            return;
        };

        for (dropped.items) |item| {
            self.finishDeferredGossipValidation(item.messageId(), .ignore);
        }
    }
};

fn findReadyPendingGossipBatch(self: *const BeaconProcessor) ?usize {
    for (self.pending_gossip_batches.items, 0..) |pending, i| {
        if (pending.isReady()) return i;
    }
    return null;
}

fn findStartedPendingGossipBatch(self: *const BeaconProcessor) ?usize {
    for (self.pending_gossip_batches.items, 0..) |pending, i| {
        if (pending.isStarted()) return i;
    }
    return null;
}

fn wallNowNs(io: std.Io) i64 {
    const now_ns = std.Io.Timestamp.now(io, .real).toNanoseconds();
    return std.math.cast(i64, now_ns) orelse if (now_ns < 0)
        std.math.minInt(i64)
    else
        std.math.maxInt(i64);
}

// ===========================================================================
// Tests
// ===========================================================================

/// Test handler context: tracks what was processed.
const TestContext = struct {
    processed_types: [64]WorkType,
    count: u32,

    fn init() TestContext {
        return .{
            .processed_types = undefined,
            .count = 0,
        };
    }

    fn handler(item: WorkItem, context: *anyopaque) void {
        const ctx: *TestContext = @ptrCast(@alignCast(context));
        assert(ctx.count < 64);
        ctx.processed_types[ctx.count] = item.workType();
        ctx.count += 1;
    }
};

fn testOpaqueHandle(tag: usize) OpaqueHandle {
    return OpaqueHandle.initBorrowed(@ptrFromInt(0x1000 + tag));
}

fn testPeerId(tag: u8) PeerIdHandle {
    return switch (tag) {
        1 => PeerIdHandle.initBorrowed("peer-1"),
        2 => PeerIdHandle.initBorrowed("peer-2"),
        3 => PeerIdHandle.initBorrowed("peer-3"),
        else => PeerIdHandle.initBorrowed("peer-x"),
    };
}

fn testSource(tag: u64) GossipSource {
    return .{ .key = tag };
}

fn testSignedVoluntaryExit(validator_index: u64, epoch: u64) consensus_types.phase0.SignedVoluntaryExit.Type {
    return .{
        .message = .{
            .epoch = epoch,
            .validator_index = validator_index,
        },
        .signature = [_]u8{0} ** 96,
    };
}

fn testGossipAttestation(tag: u64) fork_types.AnyGossipAttestation {
    var attestation = consensus_types.electra.SingleAttestation.default_value;
    attestation.committee_index = @intCast(tag % 8);
    attestation.attester_index = tag;
    attestation.data.slot = 100 + tag;
    attestation.data.target.epoch = 4;
    return .{ .electra_single = attestation };
}

fn testGossipAttestationDataRoot(attestation: *const fork_types.AnyGossipAttestation) [32]u8 {
    var root: [32]u8 = undefined;
    consensus_types.phase0.AttestationData.hashTreeRoot(&attestation.data(), &root) catch unreachable;
    return root;
}

fn testAttestationWork(tag: u64, subnet_id: u8, seen_timestamp_ns: i64) work_item_mod.AttestationWork {
    const attestation = testGossipAttestation(tag);
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

test "BeaconProcessor: ingest and dispatch priority order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest items in reverse priority order.
    proc.ingest(.{ .api_request_p1 = .{
        .response = testOpaqueHandle(1),
        .seen_timestamp_ns = 100,
    } });
    proc.ingest(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(2),
        .seen_timestamp_ns = 200,
    } });

    // Dispatch both — should come out in priority order.
    try testing.expect(proc.dispatchOne());
    try testing.expect(proc.dispatchOne());
    try testing.expect(!proc.dispatchOne());

    try testing.expectEqual(@as(u32, 2), ctx.count);
    // Status (priority 22) before api_request_p1 (priority 33).
    try testing.expectEqual(WorkType.status, ctx.processed_types[0]);
    try testing.expectEqual(WorkType.api_request_p1, ctx.processed_types[1]);
}

test "BeaconProcessor: drainAll" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest 3 items.
    proc.ingest(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(1),
        .seen_timestamp_ns = 100,
    } });
    proc.ingest(.{ .status = .{
        .peer_id = testPeerId(2),
        .request = testOpaqueHandle(2),
        .seen_timestamp_ns = 200,
    } });
    proc.ingest(.{ .api_request_p1 = .{
        .response = testOpaqueHandle(3),
        .seen_timestamp_ns = 300,
    } });

    const drained = proc.drainAll();
    try testing.expectEqual(@as(u64, 3), drained);
    try testing.expect(proc.allQueuesEmpty());
    try testing.expectEqual(@as(u32, 3), ctx.count);
}

test "BeaconProcessor: metrics tracking" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    proc.processOne(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(1),
        .seen_timestamp_ns = 100,
    } });

    try testing.expectEqual(@as(u64, 1), proc.metrics.items_received);
    try testing.expectEqual(@as(u64, 1), proc.metrics.items_dispatched);
    const idx = @intFromEnum(WorkType.status);
    try testing.expectEqual(@as(u64, 1), proc.metrics.items_processed[idx]);
}

test "BeaconProcessor: sync state affects dropping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    proc.setSyncState(.syncing);

    // Attestation should be dropped during sync.
    proc.ingest(.{ .attestation = testAttestationWork(1, 0, 100) });

    // Nothing to dispatch — it was dropped.
    try testing.expect(!proc.dispatchOne());
    try testing.expectEqual(@as(u32, 0), ctx.count);

    // Switch to synced — attestation should be accepted.
    proc.setSyncState(.synced);
    proc.ingest(.{ .attestation = testAttestationWork(2, 1, 200) });

    try testing.expect(proc.dispatchOne());
    try testing.expectEqual(@as(u32, 1), ctx.count);
    try testing.expectEqual(WorkType.attestation, ctx.processed_types[0]);
}

/// Test helper: tiny queue config with capacity 4 for all queues.
fn testConfig() QueueConfig {
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

test "BeaconProcessor: deferred gossip validation is tracked and completed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        testConfig(),
        &TestContext.handler,
        @ptrCast(&ctx),
    );
    defer proc.deinit();

    const msg_id = testMessageId(9);
    try proc.trackDeferredGossipValidation(msg_id, .{
        .peer_id = testPeerId(1),
        .fork_digest = .{ 0xde, 0xad, 0xbe, 0xef },
        .topic_type = .beacon_attestation,
        .subnet_id = 3,
    });

    proc.finishDeferredGossipValidation(msg_id, .{ .reject = .invalid_signature });

    var completion = proc.popGossipValidationResult().?;
    defer completion.deinit();

    try testing.expectEqual(msg_id, completion.msg_id);
    try testing.expectEqualStrings("peer-1", completion.context.peer_id.bytes().?);
    try testing.expectEqual(work_item_mod.GossipTopicType.beacon_attestation, completion.context.topic_type);
    try testing.expectEqual(@as(?u8, 3), completion.context.subnet_id);
    try testing.expectEqual(@as(u8, 0xde), completion.context.fork_digest[0]);
    try testing.expectEqual(@as(GossipValidationOutcome, .{ .reject = .invalid_signature }), completion.outcome);
    try testing.expect(proc.popGossipValidationResult() == null);
}

test "BeaconProcessor: tick processes limited items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest 4 items (testConfig capacity is 4 per queue).
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        proc.ingest(.{ .api_request_p1 = .{
            .response = testOpaqueHandle(i),
            .seen_timestamp_ns = @as(i64, i) * 100,
        } });
    }

    try testing.expectEqual(@as(u64, 4), proc.totalQueued());

    // tick(2) should process exactly 2 items.
    const dispatched = proc.tick(2);
    try testing.expectEqual(@as(u64, 2), dispatched);
    try testing.expectEqual(@as(u64, 2), proc.totalQueued());
    try testing.expectEqual(@as(u32, 2), ctx.count);
    try testing.expectEqual(@as(u64, 1), proc.metrics.loop_iterations);

    // tick(10) should process remaining 2 items (not 10).
    const dispatched2 = proc.tick(10);
    try testing.expectEqual(@as(u64, 2), dispatched2);
    try testing.expect(proc.allQueuesEmpty());
    try testing.expectEqual(@as(u32, 4), ctx.count);
}

test "BeaconProcessor: getQueueDepths" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest different types.
    proc.ingest(.{ .status = .{
        .peer_id = testPeerId(1),
        .request = testOpaqueHandle(1),
        .seen_timestamp_ns = 100,
    } });

    proc.ingest(.{ .attestation = testAttestationWork(1, 0, 100) });

    proc.ingest(.{ .gossip_voluntary_exit = .{
        .source = testSource(1),
        .message_id = testMessageId(1),
        .exit = testSignedVoluntaryExit(12, 34),
        .seen_timestamp_ns = 100,
    } });

    const depths = proc.getQueueDepths();
    try testing.expectEqual(@as(u64, 3), depths.total);
    try testing.expectEqual(@as(u32, 1), depths.attestations);
    try testing.expectEqual(@as(u64, 1), depths.pool_objects);
}

test "BeaconProcessor: attestation batching" {
    // Verify that multiple attestations are formed into a batch by the
    // priority queue system, and that the batch is dispatched as a single
    // attestation_batch work item.

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest 3 attestations. The LIFO queue should batch them when popped.
    proc.ingest(.{ .attestation = testAttestationWork(1, 0, 100) });
    proc.ingest(.{ .attestation = testAttestationWork(2, 1, 200) });
    proc.ingest(.{ .attestation = testAttestationWork(3, 2, 300) });

    try testing.expectEqual(@as(u64, 3), proc.totalQueued());

    // Dispatch once — should get a batch, not individual items.
    try testing.expect(proc.dispatchOne());
    try testing.expectEqual(@as(u32, 1), ctx.count);

    // The dispatched item should be attestation_batch (3 items batched).
    try testing.expectEqual(WorkType.attestation_batch, ctx.processed_types[0]);

    // Queue should be empty after batch dispatch.
    try testing.expect(proc.allQueuesEmpty());
}

test "BeaconProcessor: single attestation not batched" {
    // A single attestation should come out as a plain attestation,
    // not a batch.

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    proc.ingest(.{ .attestation = testAttestationWork(1, 0, 100) });

    try testing.expect(proc.dispatchOne());
    try testing.expectEqual(@as(u32, 1), ctx.count);

    // Single attestation — NOT batched.
    try testing.expectEqual(WorkType.attestation, ctx.processed_types[0]);
    try testing.expect(proc.allQueuesEmpty());
}

test "BeaconProcessor: blocks dispatched before attestations" {
    // Verify strict priority: gossip_block (priority 5) should be
    // dispatched before attestation (priority 12), even if attestations
    // were enqueued first.

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        std.testing.io,
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Enqueue attestation first, then block.
    proc.ingest(.{ .attestation = testAttestationWork(1, 0, 100) });

    proc.ingest(.{ .gossip_block = .{
        .source = testSource(2),
        .message_id = testMessageId(2),
        .block = fork_types.AnySignedBeaconBlock{ .phase0 = undefined },
        .seen_timestamp_ns = 200,
    } });

    // First dispatch: should be the block (higher priority).
    try testing.expect(proc.dispatchOne());
    try testing.expectEqual(WorkType.gossip_block, ctx.processed_types[0]);

    // Second dispatch: attestation.
    try testing.expect(proc.dispatchOne());
    try testing.expectEqual(WorkType.attestation, ctx.processed_types[1]);

    try testing.expect(proc.allQueuesEmpty());
}

fn testMessageId(tag: u8) MessageId {
    var out = std.mem.zeroes(MessageId);
    out[0] = tag;
    return out;
}
