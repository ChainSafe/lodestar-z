//! Node ↔ API bridge callbacks.
//!
//! This module owns the type-erased callback contexts that wire `ApiContext`
//! to `BeaconNode` internals and keeps that adapter layer out of
//! `beacon_node.zig`.

const std = @import("std");

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const chain_mod = @import("chain");
const ChainQuery = chain_mod.Query;
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const ApiHeadTracker = api_mod.context.HeadTracker;
const ApiSyncStatus = api_mod.context.SyncStatus;
const ValidatorMonitor = chain_mod.ValidatorMonitor;

pub const ApiBindings = struct {
    block_import_ctx: *BlockImportCallbackCtx,
    chain_view_ctx: *ChainViewCallbackCtx,
    agg_att_cb_ctx: *AggregateAttestationCallbackCtx,
    op_pool_cb_ctx: *OpPoolCallbackCtx,
    event_callback_ctx: *EventCallbackCtx,
    produce_block_ctx: *ProduceBlockCallbackCtx,
    attestation_data_ctx: *AttestationDataCallbackCtx,
    pool_submit_ctx: *PoolSubmitCallbackCtx,
    validator_monitor_cb_ctx: ?*ValidatorMonitorCallbackCtx = null,
    builder_cb_ctx: ?*BuilderCallbackCtx = null,

    pub fn init(allocator: std.mem.Allocator, node: *BeaconNode, beacon_config: *const BeaconConfig) !*ApiBindings {
        const bindings = try allocator.create(ApiBindings);
        errdefer allocator.destroy(bindings);
        bindings.* = .{
            .block_import_ctx = undefined,
            .chain_view_ctx = undefined,
            .agg_att_cb_ctx = undefined,
            .op_pool_cb_ctx = undefined,
            .event_callback_ctx = undefined,
            .produce_block_ctx = undefined,
            .attestation_data_ctx = undefined,
            .pool_submit_ctx = undefined,
            .validator_monitor_cb_ctx = null,
            .builder_cb_ctx = null,
        };

        bindings.block_import_ctx = try allocator.create(BlockImportCallbackCtx);
        errdefer allocator.destroy(bindings.block_import_ctx);
        bindings.block_import_ctx.* = .{
            .node = node,
            .beacon_config = beacon_config,
        };

        bindings.chain_view_ctx = try allocator.create(ChainViewCallbackCtx);
        errdefer allocator.destroy(bindings.chain_view_ctx);
        bindings.chain_view_ctx.* = .{ .chain = node.chain };

        bindings.agg_att_cb_ctx = try allocator.create(AggregateAttestationCallbackCtx);
        errdefer allocator.destroy(bindings.agg_att_cb_ctx);
        bindings.agg_att_cb_ctx.* = .{ .chain = node.chain };

        bindings.op_pool_cb_ctx = try allocator.create(OpPoolCallbackCtx);
        errdefer allocator.destroy(bindings.op_pool_cb_ctx);
        bindings.op_pool_cb_ctx.* = .{ .chain = node.chain };

        bindings.event_callback_ctx = try allocator.create(EventCallbackCtx);
        errdefer allocator.destroy(bindings.event_callback_ctx);
        bindings.event_callback_ctx.* = .{ .event_bus = node.event_bus };

        bindings.produce_block_ctx = try allocator.create(ProduceBlockCallbackCtx);
        errdefer allocator.destroy(bindings.produce_block_ctx);
        bindings.produce_block_ctx.* = .{ .node = node };

        bindings.attestation_data_ctx = try allocator.create(AttestationDataCallbackCtx);
        errdefer allocator.destroy(bindings.attestation_data_ctx);
        bindings.attestation_data_ctx.* = .{ .chain = node.chain };

        bindings.pool_submit_ctx = try allocator.create(PoolSubmitCallbackCtx);
        errdefer allocator.destroy(bindings.pool_submit_ctx);
        bindings.pool_submit_ctx.* = .{ .node = node };

        if (node.validator_monitor) |vm| {
            bindings.validator_monitor_cb_ctx = try allocator.create(ValidatorMonitorCallbackCtx);
            bindings.validator_monitor_cb_ctx.?.* = .{ .monitor = vm };
        }

        if (node.builder_api != null) {
            bindings.builder_cb_ctx = try allocator.create(BuilderCallbackCtx);
            bindings.builder_cb_ctx.?.* = .{ .node = node };
        }

        wireApiContext(bindings, node.api_context);
        node.chain.event_callback = .{
            .ptr = @ptrCast(bindings.event_callback_ctx),
            .emitFn = &eventCallbackFn,
        };
        return bindings;
    }

    pub fn deinit(self: *ApiBindings, allocator: std.mem.Allocator) void {
        if (self.builder_cb_ctx) |ctx| allocator.destroy(ctx);
        if (self.validator_monitor_cb_ctx) |ctx| allocator.destroy(ctx);
        allocator.destroy(self.pool_submit_ctx);
        allocator.destroy(self.attestation_data_ctx);
        allocator.destroy(self.produce_block_ctx);
        allocator.destroy(self.event_callback_ctx);
        allocator.destroy(self.op_pool_cb_ctx);
        allocator.destroy(self.agg_att_cb_ctx);
        allocator.destroy(self.chain_view_ctx);
        allocator.destroy(self.block_import_ctx);
    }

    fn wireApiContext(self: *ApiBindings, api_ctx: *ApiContext) void {
        api_ctx.block_import = .{
            .ptr = @ptrCast(self.block_import_ctx),
            .importFn = &importBlockCallback,
        };
        api_ctx.chain_view = .{
            .ptr = @ptrCast(self.chain_view_ctx),
            .getHeadTrackerFn = &getChainHeadTrackerCallback,
            .getSyncStatusFn = &getChainSyncStatusCallback,
        };
        api_ctx.chain_query = .{
            .ptr = @ptrCast(self.chain_view_ctx),
            .getBlockRootBySlotFn = &getChainBlockRootBySlotCallback,
            .getBlockBytesByRootFn = &getChainBlockBytesByRootCallback,
            .getStateRootBySlotFn = &getChainStateRootBySlotCallback,
            .getStateRootByBlockRootFn = &getChainStateRootByBlockRootCallback,
            .getStateBytesBySlotFn = &getChainStateBytesBySlotCallback,
            .getStateBytesByRootFn = &getChainStateBytesByRootCallback,
            .getStateArchiveAtSlotFn = &getChainStateArchiveAtSlotCallback,
            .getStateArchiveByRootFn = &getChainStateArchiveByRootCallback,
        };
        api_ctx.state_query = .{
            .ptr = @ptrCast(self.chain_view_ctx),
            .getHeadStateFn = &getChainHeadStateCallback,
            .getStateByRootFn = &getChainStateByRootCallback,
            .getStateBySlotFn = &getChainStateBySlotCallback,
        };
        api_ctx.aggregate_attestation = .{
            .ptr = @ptrCast(self.agg_att_cb_ctx),
            .getAggregateAttestationFn = &getAggregateAttestationCallback,
        };
        api_ctx.op_pool = .{
            .ptr = @ptrCast(self.op_pool_cb_ctx),
            .getPoolCountsFn = &opPoolGetCountsCallback,
            .getAttestationsFn = &opPoolGetAttestationsCallback,
            .getVoluntaryExitsFn = &opPoolGetVoluntaryExitsCallback,
            .getProposerSlashingsFn = &opPoolGetProposerSlashingsCallback,
            .getAttesterSlashingsFn = &opPoolGetAttesterSlashingsCallback,
            .getBlsToExecutionChangesFn = &opPoolGetBlsToExecutionChangesCallback,
        };
        api_ctx.produce_block = .{
            .ptr = @ptrCast(self.produce_block_ctx),
            .produceBlockFn = &produceBlockCallback,
        };
        api_ctx.attestation_data = .{
            .ptr = @ptrCast(self.attestation_data_ctx),
            .getAttestationDataFn = &getAttestationDataCallback,
        };
        api_ctx.pool_submit = .{
            .ptr = @ptrCast(self.pool_submit_ctx),
            .submitAttestationFn = &submitAttestationCallback,
            .submitAggregateAndProofFn = &submitAggregateAndProofCallback,
            .submitVoluntaryExitFn = &submitVoluntaryExitCallback,
            .submitContributionAndProofFn = &submitContributionAndProofCallback,
        };
        if (self.validator_monitor_cb_ctx) |ctx| {
            api_ctx.validator_monitor = .{
                .ptr = @ptrCast(ctx),
                .getMonitorStatusFn = &getValidatorMonitorCallback,
            };
        }
        if (self.builder_cb_ctx) |ctx| {
            api_ctx.builder = .{
                .ptr = @ptrCast(ctx),
                .registerValidatorsFn = &builderRegisterValidatorsCallback,
            };
        }
    }
};

pub const BlockImportCallbackCtx = struct {
    node: *BeaconNode,
    beacon_config: *const BeaconConfig,
};

pub const ChainViewCallbackCtx = struct {
    chain: *chain_mod.Chain,
};

pub const AggregateAttestationCallbackCtx = struct {
    chain: *chain_mod.Chain,
};

pub const ValidatorMonitorCallbackCtx = struct {
    monitor: *ValidatorMonitor,
};

pub const EventCallbackCtx = struct {
    event_bus: *api_mod.EventBus,
};

pub const ProduceBlockCallbackCtx = struct {
    node: *BeaconNode,
};

pub const AttestationDataCallbackCtx = struct {
    chain: *chain_mod.Chain,
};

pub const PoolSubmitCallbackCtx = struct {
    node: *BeaconNode,
};

pub const BuilderCallbackCtx = struct {
    node: *BeaconNode,
};

pub const OpPoolCallbackCtx = struct {
    chain: *chain_mod.Chain,
};

fn getChainHeadTrackerCallback(ptr: *anyopaque) ApiHeadTracker {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    const snapshot = ChainQuery.init(ctx.chain).currentSnapshot();
    return .{
        .head_slot = snapshot.head.slot,
        .head_root = snapshot.head.root,
        .head_state_root = snapshot.head.state_root,
        .finalized_slot = snapshot.finalized.slot,
        .finalized_root = snapshot.finalized.root,
        .justified_slot = snapshot.justified.slot,
        .justified_root = snapshot.justified.root,
    };
}

fn getChainSyncStatusCallback(ptr: *anyopaque) ApiSyncStatus {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    const status = ChainQuery.init(ctx.chain).syncStatus();
    return .{
        .head_slot = status.head_slot,
        .sync_distance = status.sync_distance,
        .is_syncing = status.is_syncing,
        .is_optimistic = status.is_optimistic,
        .el_offline = status.el_offline,
    };
}

fn getChainBlockRootBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).canonicalBlockRootAtSlot(slot);
}

fn getChainBlockBytesByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).blockBytesByRoot(root);
}

fn getChainStateRootBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateRootBySlot(slot);
}

fn getChainStateRootByBlockRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[32]u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateRootByBlockRoot(root);
}

fn getChainStateBytesBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateBytesBySlot(slot);
}

fn getChainStateBytesByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateBytesByRoot(root);
}

fn getChainStateArchiveAtSlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateArchiveAtSlot(slot);
}

fn getChainStateArchiveByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateArchiveByRoot(root);
}

fn getChainHeadStateCallback(ptr: *anyopaque) ?*CachedBeaconState {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).headState();
}

fn getChainStateByRootCallback(ptr: *anyopaque, state_root: [32]u8) anyerror!?*CachedBeaconState {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateByRoot(state_root);
}

fn getChainStateBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?*CachedBeaconState {
    const ctx: *ChainViewCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).stateBySlot(slot);
}

fn getAggregateAttestationCallback(
    ptr: *anyopaque,
    alloc: std.mem.Allocator,
    slot: u64,
    attestation_data_root: [32]u8,
) anyerror![]const u8 {
    const ctx: *AggregateAttestationCallbackCtx = @ptrCast(@alignCast(ptr));
    const best = ChainQuery.init(ctx.chain).aggregateAttestation(@intCast(slot), attestation_data_root) orelse
        return error.NotFound;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.writeAll("{");
    try writer.print("\"aggregation_bits\":\"0x", .{});
    for (best.aggregation_bits.data.items) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
    try writer.writeAll("\",");
    try writer.print("\"data\":{{\"slot\":{d},\"index\":{d},", .{
        best.data.slot,
        best.data.index,
    });
    try writer.writeAll("\"beacon_block_root\":\"0x");
    for (best.data.beacon_block_root) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeAll("\",");
    try writer.print("\"source\":{{\"epoch\":{d},\"root\":\"0x", .{best.data.source.epoch});
    for (best.data.source.root) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeAll("\"}},");
    try writer.print("\"target\":{{\"epoch\":{d},\"root\":\"0x", .{best.data.target.epoch});
    for (best.data.target.root) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeAll("\"}}},");
    try writer.writeAll("\"signature\":\"0x");
    for (best.signature) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeAll("\"");
    try writer.writeAll("}");

    return out.toOwnedSlice();
}

fn importBlockCallback(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
    const cb_ctx: *BlockImportCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = cb_ctx.node;

    // SignedBeaconBlock SSZ layout starts with a 4-byte offset to `message`,
    // followed by the fixed 96-byte signature. The BeaconBlock `slot` is the
    // first field in the message fixed section.
    const block_slot: u64 = if (block_bytes.len >= 108)
        std.mem.readInt(u64, block_bytes[100..108], .little)
    else
        node.head_tracker.head_slot;
    const fork_seq = cb_ctx.beacon_config.forkSeq(block_slot);

    const any_signed = try AnySignedBeaconBlock.deserialize(node.allocator, .full, fork_seq, block_bytes);
    defer any_signed.deinit(node.allocator);

    _ = try node.importBlock(any_signed, .api);
}

fn getValidatorMonitorCallback(
    ptr: *anyopaque,
    alloc: std.mem.Allocator,
) anyerror![]const u8 {
    const ctx: *ValidatorMonitorCallbackCtx = @ptrCast(@alignCast(ptr));
    const monitor = ctx.monitor;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.writeAll("{\"data\":{\"validators\":[");

    var first = true;
    const indices = try monitor.getMonitoredIndices(alloc);
    defer alloc.free(indices);

    for (indices) |idx| {
        if (monitor.getValidatorSummary(idx)) |summary| {
            if (!first) try writer.writeAll(",");
            first = false;

            try writer.print(
                "{{\"index\":{d},\"balance_gwei\":{d},\"effective_balance_gwei\":{d}," ++
                    "\"balance_delta_gwei\":{d},\"effectiveness_score\":{d:.1}," ++
                    "\"attestation_included\":{},\"attestation_delay\":",
                .{
                    summary.index,
                    summary.balance_gwei,
                    summary.effective_balance_gwei,
                    summary.balance_delta_gwei,
                    summary.effectiveness_score,
                    summary.attestation_included,
                },
            );

            if (summary.attestation_delay) |delay| {
                try writer.print("{d}", .{delay});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(
                ",\"head_correct\":{},\"source_correct\":{},\"target_correct\":{}," ++
                    "\"block_proposed\":{},\"sync_participated\":{}," ++
                    "\"cumulative_reward_gwei\":{d}," ++
                    "\"total_attestations_included\":{d},\"total_attestations_expected\":{d}," ++
                    "\"inclusion_delay_histogram\":[{d},{d},{d},{d}]}}",
                .{
                    summary.head_correct,
                    summary.source_correct,
                    summary.target_correct,
                    summary.block_proposed,
                    summary.sync_participated,
                    summary.cumulative_reward_gwei,
                    summary.total_attestations_included,
                    summary.total_attestations_expected,
                    summary.inclusion_delay_histogram[0],
                    summary.inclusion_delay_histogram[1],
                    summary.inclusion_delay_histogram[2],
                    summary.inclusion_delay_histogram[3],
                },
            );
        }
    }

    try writer.writeAll("],\"epoch_summaries\":[");

    const summaries = monitor.getAllEpochSummaries();
    for (summaries, 0..) |summary, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print(
            "{{\"epoch\":{d},\"validators_monitored\":{d}," ++
                "\"attestation_hit_rate\":{d:.4},\"head_accuracy_rate\":{d:.4}," ++
                "\"source_accuracy_rate\":{d:.4},\"target_accuracy_rate\":{d:.4}," ++
                "\"avg_inclusion_delay\":{d:.2},\"blocks_proposed\":{d}," ++
                "\"blocks_expected\":{d},\"sync_participation_rate\":{d:.4}," ++
                "\"total_balance_delta_gwei\":{d}}}",
            .{
                summary.epoch,
                summary.validators_monitored,
                summary.attestation_hit_rate,
                summary.head_accuracy_rate,
                summary.source_accuracy_rate,
                summary.target_accuracy_rate,
                summary.avg_inclusion_delay,
                summary.blocks_proposed,
                summary.blocks_expected,
                summary.sync_participation_rate,
                summary.total_balance_delta_gwei,
            },
        );
    }

    try writer.writeAll("]}}");
    return out.toOwnedSlice();
}

fn eventCallbackFn(ptr: *anyopaque, event: chain_mod.SseEvent) void {
    const ctx: *EventCallbackCtx = @ptrCast(@alignCast(ptr));
    const bus = ctx.event_bus;
    const api_event: api_mod.Event = switch (event) {
        .head => |e| .{ .head = .{
            .slot = e.slot,
            .block_root = e.block_root,
            .state_root = e.state_root,
            .epoch_transition = e.epoch_transition,
        } },
        .block => |e| .{ .block = .{
            .slot = e.slot,
            .block_root = e.block_root,
        } },
        .finalized_checkpoint => |e| .{ .finalized_checkpoint = .{
            .epoch = e.epoch,
            .root = e.root,
            .state_root = e.state_root,
        } },
        .chain_reorg => |e| .{ .chain_reorg = .{
            .slot = e.slot,
            .depth = e.depth,
            .old_head_root = e.old_head_root,
            .new_head_root = e.new_head_root,
            .old_state_root = e.old_state_root,
            .new_state_root = e.new_state_root,
            .epoch = e.epoch,
        } },
        .attestation => |e| .{ .attestation = .{
            .aggregation_bits = e.aggregation_bits,
            .slot = e.slot,
            .committee_index = e.committee_index,
            .beacon_block_root = e.beacon_block_root,
            .source_epoch = e.source_epoch,
            .source_root = e.source_root,
            .target_epoch = e.target_epoch,
            .target_root = e.target_root,
            .signature = e.signature,
        } },
        .voluntary_exit => |e| .{ .voluntary_exit = .{
            .epoch = e.epoch,
            .validator_index = e.validator_index,
            .signature = e.signature,
        } },
        .contribution_and_proof => |e| .{ .contribution_and_proof = .{
            .aggregator_index = e.aggregator_index,
            .slot = e.slot,
            .beacon_block_root = e.beacon_block_root,
            .subcommittee_index = e.subcommittee_index,
            .aggregation_bits = e.aggregation_bits,
            .contribution_signature = e.contribution_signature,
            .selection_proof = e.selection_proof,
        } },
        .payload_attributes => |e| .{ .payload_attributes = .{
            .proposer_index = e.proposer_index,
            .proposal_slot = e.proposal_slot,
            .parent_block_number = e.parent_block_number,
            .parent_block_root = e.parent_block_root,
            .parent_block_hash = e.parent_block_hash,
            .timestamp = e.timestamp,
            .prev_randao = e.prev_randao,
            .suggested_fee_recipient = e.suggested_fee_recipient,
        } },
        .blob_sidecar => |e| .{ .blob_sidecar = .{
            .block_root = e.block_root,
            .index = e.index,
            .slot = e.slot,
            .kzg_commitment = e.kzg_commitment,
            .versioned_hash = e.versioned_hash,
        } },
    };
    bus.emit(api_event);
}

fn produceBlockCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    params: api_mod.context.ProduceBlockParams,
) anyerror!api_mod.context.ProducedBlockData {
    const ctx: *ProduceBlockCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    var prod_config = chain_mod.BlockProductionConfig{};
    if (params.graffiti) |graffiti| prod_config.graffiti = graffiti;
    _ = params.randao_reveal;

    var produced = try node.produceFullBlock(params.slot, prod_config);
    defer produced.deinit(allocator);

    return error.NotImplemented;
}

fn getAttestationDataCallback(
    ptr: *anyopaque,
    slot: u64,
    committee_index: u64,
) anyerror!api_mod.context.AttestationDataResult {
    const ctx: *AttestationDataCallbackCtx = @ptrCast(@alignCast(ptr));
    const query = ChainQuery.init(ctx.chain);
    const snapshot = query.currentSnapshot();
    const head_root = snapshot.head.root;

    const source_epoch = snapshot.justified.epoch;
    const source_root = snapshot.justified.root;

    const target_epoch = computeEpochAtSlot(slot);
    const target_slot = computeStartSlotAtEpoch(target_epoch);

    const target_root = blk: {
        if (target_slot == slot) break :blk head_root;

        if (query.headState()) |head_state| {
            if (head_state.state.blockRoots()) |block_roots_view| {
                const idx = target_slot % preset.SLOTS_PER_HISTORICAL_ROOT;
                if (block_roots_view.getFieldRoot(idx) catch null) |root_ptr| {
                    break :blk root_ptr.*;
                }
            } else |_| {}
        }
        break :blk head_root;
    };

    return .{
        .slot = slot,
        .index = committee_index,
        .beacon_block_root = head_root,
        .source_epoch = source_epoch,
        .source_root = source_root,
        .target_epoch = target_epoch,
        .target_root = target_root,
    };
}

fn submitAttestationCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    if (node.p2p_service) |*p2p| {
        p2p.publishGossip(
            networking.gossip_topics.GossipTopicType.beacon_attestation,
            null,
            json_bytes,
        ) catch |err| {
            std.log.warn("pool_submit: gossip publish attestation failed: {}", .{err});
        };
    }
}

fn submitAggregateAndProofCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    if (node.p2p_service) |*p2p| {
        p2p.publishGossip(
            networking.gossip_topics.GossipTopicType.beacon_aggregate_and_proof,
            null,
            json_bytes,
        ) catch |err| {
            std.log.warn("pool_submit: gossip publish aggregate failed: {}", .{err});
        };
    }
}

fn submitVoluntaryExitCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    _ = json_bytes;

    node.event_bus.emit(.{ .voluntary_exit = .{
        .epoch = 0,
        .validator_index = 0,
        .signature = [_]u8{0} ** 96,
    } });
}

fn submitContributionAndProofCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    _ = json_bytes;

    node.event_bus.emit(.{ .contribution_and_proof = .{
        .aggregator_index = 0,
        .slot = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .subcommittee_index = 0,
        .aggregation_bits = [_]u8{0} ** 16,
        .contribution_signature = [_]u8{0} ** 96,
        .selection_proof = [_]u8{0} ** 96,
    } });
}

fn builderRegisterValidatorsCallback(ptr: *anyopaque, registrations_json: []const u8) anyerror!void {
    const ctx: *BuilderCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    const builder = node.builder_api orelse return;
    _ = builder;
    _ = registrations_json;
    std.log.info("builder: received validator registration request (forwarding not yet implemented, VC uses direct relay path)", .{});
}

fn opPoolGetCountsCallback(ptr: *anyopaque) [5]usize {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).opPoolCounts();
}

fn opPoolGetAttestationsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) anyerror![]types.phase0.Attestation.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).attestations(allocator, slot_filter, committee_index_filter);
}

fn opPoolGetVoluntaryExitsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.phase0.SignedVoluntaryExit.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).voluntaryExits(allocator);
}

fn opPoolGetProposerSlashingsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.phase0.ProposerSlashing.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).proposerSlashings(allocator);
}

fn opPoolGetAttesterSlashingsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.phase0.AttesterSlashing.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).attesterSlashings(allocator);
}

fn opPoolGetBlsToExecutionChangesCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.capella.SignedBLSToExecutionChange.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ChainQuery.init(ctx.chain).blsToExecutionChanges(allocator);
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
