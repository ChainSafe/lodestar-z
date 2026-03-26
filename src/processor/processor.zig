//! BeaconProcessor — the central scheduling loop.
//!
//! Receives all inbound work via a channel, routes to per-type priority
//! queues, and dispatches the highest-priority item to a handler. Worker
//! pool integration comes later — for now handlers execute inline.
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

const work_queues_mod = @import("work_queues.zig");
const WorkQueues = work_queues_mod.WorkQueues;
const QueueConfig = work_queues_mod.QueueConfig;
const SyncState = work_queues_mod.SyncState;

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
        self.items_processed[idx] += 1;
        self.processing_time_ns[idx] += elapsed_ns;
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
    queues: WorkQueues,
    handler: HandlerFn,
    handler_context: *anyopaque,
    metrics: ProcessorMetrics,

    /// Initialise the processor.
    ///
    /// `allocator`: used for queue backing buffers (allocated once at startup).
    /// `config`: queue capacity configuration.
    /// `handler`: callback invoked for each dispatched work item.
    /// `handler_context`: opaque pointer passed to the handler.
    pub fn init(
        allocator: std.mem.Allocator,
        config: QueueConfig,
        handler: HandlerFn,
        handler_context: *anyopaque,
    ) !BeaconProcessor {
        return .{
            .queues = try WorkQueues.init(allocator, config),
            .handler = handler,
            .handler_context = handler_context,
            .metrics = ProcessorMetrics.init(),
        };
    }

    /// Ingest a single work item into the appropriate queue.
    pub fn ingest(self: *BeaconProcessor, item: WorkItem) void {
        self.metrics.items_received += 1;
        self.queues.routeToQueue(item);
    }

    /// Dispatch the highest-priority queued item to the handler.
    /// Returns true if an item was dispatched, false if all queues empty.
    pub fn dispatchOne(self: *BeaconProcessor) bool {
        const item = self.queues.popHighestPriority() orelse return false;

        const wtype = item.workType();

        self.handler(item, self.handler_context);

        // TODO: Add timing when std.Io clock is available.
        const elapsed: u64 = 0;
        self.metrics.recordProcessed(wtype, elapsed);
        self.metrics.items_dispatched += 1;

        return true;
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

    /// Update the sync state (affects sync-aware dropping).
    pub fn setSyncState(self: *BeaconProcessor, state: SyncState) void {
        self.queues.sync_state = state;
    }

    /// Returns total items currently queued.
    pub fn totalQueued(self: *const BeaconProcessor) u64 {
        return self.queues.totalQueued();
    }

    /// Returns true if all queues are empty.
    pub fn allQueuesEmpty(self: *const BeaconProcessor) bool {
        return self.queues.allQueuesEmpty();
    }
};

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

test "BeaconProcessor: ingest and dispatch priority order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ctx = TestContext.init();
    const config = testConfig();

    var proc = try BeaconProcessor.init(
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest items in reverse priority order.
    proc.ingest(.{ .api_request_p1 = .{
        .response_handle = 1,
        .seen_timestamp_ns = 100,
    } });
    proc.ingest(.{ .status = .{
        .peer_id = 1,
        .request_context = 2,
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
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    // Ingest 3 items.
    proc.ingest(.{ .status = .{
        .peer_id = 1,
        .request_context = 1,
        .seen_timestamp_ns = 100,
    } });
    proc.ingest(.{ .status = .{
        .peer_id = 2,
        .request_context = 2,
        .seen_timestamp_ns = 200,
    } });
    proc.ingest(.{ .api_request_p1 = .{
        .response_handle = 1,
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
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    proc.processOne(.{ .status = .{
        .peer_id = 1,
        .request_context = 1,
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
        allocator,
        config,
        &TestContext.handler,
        @ptrCast(&ctx),
    );

    proc.setSyncState(.syncing);

    // Attestation should be dropped during sync.
    const dummy_handle: *anyopaque = @ptrFromInt(0xDEAD);
    proc.ingest(.{ .attestation = .{
        .peer_id = 1,
        .message_id = 1,
        .data = dummy_handle,
        .subnet_id = 0,
        .seen_timestamp_ns = 100,
    } });

    // Nothing to dispatch — it was dropped.
    try testing.expect(!proc.dispatchOne());
    try testing.expectEqual(@as(u32, 0), ctx.count);

    // Switch to synced — attestation should be accepted.
    proc.setSyncState(.synced);
    proc.ingest(.{ .attestation = .{
        .peer_id = 2,
        .message_id = 2,
        .data = dummy_handle,
        .subnet_id = 1,
        .seen_timestamp_ns = 200,
    } });

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
