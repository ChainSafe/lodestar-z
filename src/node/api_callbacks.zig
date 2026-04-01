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
const isFixedType = @import("ssz").isFixedType;
const chain_mod = @import("chain");
const ChainQuery = chain_mod.Query;
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const SubnetService = networking.SubnetService;
const fork_types = @import("fork_types");
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const ApiHeadTracker = api_mod.context.HeadTracker;
const ApiSyncStatus = api_mod.context.SyncStatus;
const ValidatorMonitor = chain_mod.ValidatorMonitor;
const block_production_mod = @import("block_production.zig");
const execution_mod = @import("execution");

pub const ApiBindings = struct {
    block_import_ctx: *BlockImportCallbackCtx,
    chain_ctx: *ChainCallbackCtx,
    sync_status_ctx: *SyncStatusCallbackCtx,
    agg_att_cb_ctx: *AggregateAttestationCallbackCtx,
    op_pool_cb_ctx: *OpPoolCallbackCtx,
    notification_sink_ctx: *ChainNotificationSinkCtx,
    produce_block_ctx: *ProduceBlockCallbackCtx,
    prepare_beacon_proposer_ctx: *PrepareBeaconProposerCallbackCtx,
    attestation_data_ctx: *AttestationDataCallbackCtx,
    pool_submit_ctx: *PoolSubmitCallbackCtx,
    subnet_subscription_cb_ctx: *SubnetSubscriptionCallbackCtx,
    validator_monitor_cb_ctx: ?*ValidatorMonitorCallbackCtx = null,
    builder_cb_ctx: ?*BuilderCallbackCtx = null,

    pub fn init(allocator: std.mem.Allocator, node: *BeaconNode, beacon_config: *const BeaconConfig) !*ApiBindings {
        const bindings = try allocator.create(ApiBindings);
        errdefer allocator.destroy(bindings);
        bindings.* = .{
            .block_import_ctx = undefined,
            .chain_ctx = undefined,
            .sync_status_ctx = undefined,
            .agg_att_cb_ctx = undefined,
            .op_pool_cb_ctx = undefined,
            .notification_sink_ctx = undefined,
            .produce_block_ctx = undefined,
            .prepare_beacon_proposer_ctx = undefined,
            .attestation_data_ctx = undefined,
            .pool_submit_ctx = undefined,
            .subnet_subscription_cb_ctx = undefined,
            .validator_monitor_cb_ctx = null,
            .builder_cb_ctx = null,
        };

        bindings.block_import_ctx = try allocator.create(BlockImportCallbackCtx);
        errdefer allocator.destroy(bindings.block_import_ctx);
        bindings.block_import_ctx.* = .{
            .node = node,
            .beacon_config = beacon_config,
        };

        bindings.chain_ctx = try allocator.create(ChainCallbackCtx);
        errdefer allocator.destroy(bindings.chain_ctx);
        bindings.chain_ctx.* = .{ .query = node.chainQuery() };

        bindings.sync_status_ctx = try allocator.create(SyncStatusCallbackCtx);
        errdefer allocator.destroy(bindings.sync_status_ctx);
        bindings.sync_status_ctx.* = .{ .node = node };

        bindings.agg_att_cb_ctx = try allocator.create(AggregateAttestationCallbackCtx);
        errdefer allocator.destroy(bindings.agg_att_cb_ctx);
        bindings.agg_att_cb_ctx.* = .{ .query = node.chainQuery() };

        bindings.op_pool_cb_ctx = try allocator.create(OpPoolCallbackCtx);
        errdefer allocator.destroy(bindings.op_pool_cb_ctx);
        bindings.op_pool_cb_ctx.* = .{ .query = node.chainQuery() };

        bindings.notification_sink_ctx = try allocator.create(ChainNotificationSinkCtx);
        errdefer allocator.destroy(bindings.notification_sink_ctx);
        bindings.notification_sink_ctx.* = .{ .event_bus = node.event_bus };

        bindings.produce_block_ctx = try allocator.create(ProduceBlockCallbackCtx);
        errdefer allocator.destroy(bindings.produce_block_ctx);
        bindings.produce_block_ctx.* = .{ .node = node };

        bindings.prepare_beacon_proposer_ctx = try allocator.create(PrepareBeaconProposerCallbackCtx);
        errdefer allocator.destroy(bindings.prepare_beacon_proposer_ctx);
        bindings.prepare_beacon_proposer_ctx.* = .{ .node = node };

        bindings.attestation_data_ctx = try allocator.create(AttestationDataCallbackCtx);
        errdefer allocator.destroy(bindings.attestation_data_ctx);
        bindings.attestation_data_ctx.* = .{ .query = node.chainQuery() };

        bindings.pool_submit_ctx = try allocator.create(PoolSubmitCallbackCtx);
        errdefer allocator.destroy(bindings.pool_submit_ctx);
        bindings.pool_submit_ctx.* = .{ .node = node };

        bindings.subnet_subscription_cb_ctx = try allocator.create(SubnetSubscriptionCallbackCtx);
        errdefer allocator.destroy(bindings.subnet_subscription_cb_ctx);
        bindings.subnet_subscription_cb_ctx.* = .{ .node = node };

        if (node.validator_monitor) |vm| {
            bindings.validator_monitor_cb_ctx = try allocator.create(ValidatorMonitorCallbackCtx);
            bindings.validator_monitor_cb_ctx.?.* = .{ .monitor = vm };
        }

        if (node.builder_api != null) {
            bindings.builder_cb_ctx = try allocator.create(BuilderCallbackCtx);
            bindings.builder_cb_ctx.?.* = .{ .node = node };
        }

        wireApiContext(bindings, node.api_context);
        node.chain.notification_sink = .{
            .ptr = @ptrCast(bindings.notification_sink_ctx),
            .publishFn = &publishChainNotificationFn,
        };
        return bindings;
    }

    pub fn deinit(self: *ApiBindings, allocator: std.mem.Allocator) void {
        if (self.builder_cb_ctx) |ctx| allocator.destroy(ctx);
        if (self.validator_monitor_cb_ctx) |ctx| allocator.destroy(ctx);
        allocator.destroy(self.subnet_subscription_cb_ctx);
        allocator.destroy(self.pool_submit_ctx);
        allocator.destroy(self.attestation_data_ctx);
        allocator.destroy(self.prepare_beacon_proposer_ctx);
        allocator.destroy(self.produce_block_ctx);
        allocator.destroy(self.notification_sink_ctx);
        allocator.destroy(self.op_pool_cb_ctx);
        allocator.destroy(self.agg_att_cb_ctx);
        allocator.destroy(self.sync_status_ctx);
        allocator.destroy(self.chain_ctx);
        allocator.destroy(self.block_import_ctx);
    }

    fn wireApiContext(self: *ApiBindings, api_ctx: *ApiContext) void {
        api_ctx.block_import = .{
            .ptr = @ptrCast(self.block_import_ctx),
            .importFn = &importBlockCallback,
        };
        api_ctx.chain = .{
            .ptr = @ptrCast(self.chain_ctx),
            .getHeadTrackerFn = &getChainHeadTrackerCallback,
            .getBlockRootBySlotFn = &getChainBlockRootBySlotCallback,
            .getBlockBytesByRootFn = &getChainBlockBytesByRootCallback,
            .getStateRootBySlotFn = &getChainStateRootBySlotCallback,
            .getStateRootByBlockRootFn = &getChainStateRootByBlockRootCallback,
            .getStateBytesBySlotFn = &getChainStateBytesBySlotCallback,
            .getStateBytesByRootFn = &getChainStateBytesByRootCallback,
            .getStateArchiveAtSlotFn = &getChainStateArchiveAtSlotCallback,
            .getStateArchiveByRootFn = &getChainStateArchiveByRootCallback,
            .getHeadStateFn = &getChainHeadStateCallback,
            .getStateByRootFn = &getChainStateByRootCallback,
            .getStateBySlotFn = &getChainStateBySlotCallback,
        };
        api_ctx.sync_status_view = .{
            .ptr = @ptrCast(self.sync_status_ctx),
            .getSyncStatusFn = &getNodeSyncStatusCallback,
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
        api_ctx.prepare_beacon_proposer = .{
            .ptr = @ptrCast(self.prepare_beacon_proposer_ctx),
            .prepareBeaconProposerFn = &prepareBeaconProposerCallback,
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
            .submitProposerSlashingFn = &submitProposerSlashingCallback,
            .submitAttesterSlashingFn = &submitAttesterSlashingCallback,
            .submitBlsChangeFn = &submitBlsChangeCallback,
            .submitSyncCommitteeMessageFn = &submitSyncCommitteeMessageCallback,
            .submitContributionAndProofFn = &submitContributionAndProofCallback,
        };
        api_ctx.subnet_subscriptions = .{
            .ptr = @ptrCast(self.subnet_subscription_cb_ctx),
            .prepareBeaconCommitteeSubnetsFn = &prepareBeaconCommitteeSubnetsCallback,
            .prepareSyncCommitteeSubnetsFn = &prepareSyncCommitteeSubnetsCallback,
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

pub const ChainCallbackCtx = struct {
    query: ChainQuery,
};

pub const AggregateAttestationCallbackCtx = struct {
    query: ChainQuery,
};

pub const SyncStatusCallbackCtx = struct {
    node: *BeaconNode,
};

pub const ValidatorMonitorCallbackCtx = struct {
    monitor: *ValidatorMonitor,
};

pub const ChainNotificationSinkCtx = struct {
    event_bus: *api_mod.EventBus,
};

pub const ProduceBlockCallbackCtx = struct {
    node: *BeaconNode,
};

pub const PrepareBeaconProposerCallbackCtx = struct {
    node: *BeaconNode,
};

pub const AttestationDataCallbackCtx = struct {
    query: ChainQuery,
};

pub const PoolSubmitCallbackCtx = struct {
    node: *BeaconNode,
};

pub const SubnetSubscriptionCallbackCtx = struct {
    node: *BeaconNode,
};

pub const BuilderCallbackCtx = struct {
    node: *BeaconNode,
};

pub const OpPoolCallbackCtx = struct {
    query: ChainQuery,
};

fn computeAttestationSubnet(slot: u64, committees_at_slot: u64, committee_index: u64) u8 {
    const committees_since_epoch_start = committees_at_slot * (slot % preset.SLOTS_PER_EPOCH);
    return @intCast((committees_since_epoch_start + committee_index) % networking.peer_info.ATTESTATION_SUBNET_COUNT);
}

fn parseJsonValue(comptime SszType: type, allocator: std.mem.Allocator, json_bytes: []const u8) !SszType.Type {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json_bytes);
    defer scanner.deinit();

    var value = SszType.default_value;
    errdefer if (!comptime isFixedType(SszType)) SszType.deinit(allocator, &value);

    if (comptime isFixedType(SszType)) {
        SszType.deserializeFromJson(&scanner, &value) catch return error.InvalidRequest;
    } else {
        SszType.deserializeFromJson(allocator, &scanner, &value) catch return error.InvalidRequest;
    }

    switch (scanner.next() catch return error.InvalidRequest) {
        .end_of_document => {},
        else => return error.InvalidRequest,
    }

    return value;
}

fn parseJsonArray(comptime SszType: type, allocator: std.mem.Allocator, json_bytes: []const u8) !std.ArrayListUnmanaged(SszType.Type) {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json_bytes);
    defer scanner.deinit();

    var items = std.ArrayListUnmanaged(SszType.Type).empty;
    errdefer deinitParsedArray(SszType, allocator, &items);

    switch (scanner.next() catch return error.InvalidRequest) {
        .array_begin => {},
        else => return error.InvalidRequest,
    }

    while (true) {
        switch (scanner.peekNextTokenType() catch return error.InvalidRequest) {
            .array_end => {
                _ = scanner.next() catch return error.InvalidRequest;
                break;
            },
            else => {},
        }

        const idx = items.items.len;
        try items.append(allocator, SszType.default_value);
        errdefer if (!comptime isFixedType(SszType)) SszType.deinit(allocator, &items.items[idx]);

        if (comptime isFixedType(SszType)) {
            SszType.deserializeFromJson(&scanner, &items.items[idx]) catch return error.InvalidRequest;
        } else {
            SszType.deserializeFromJson(allocator, &scanner, &items.items[idx]) catch return error.InvalidRequest;
        }
    }

    switch (scanner.next() catch return error.InvalidRequest) {
        .end_of_document => {},
        else => return error.InvalidRequest,
    }

    return items;
}

fn deinitParsedArray(comptime SszType: type, allocator: std.mem.Allocator, items: *std.ArrayListUnmanaged(SszType.Type)) void {
    if (!comptime isFixedType(SszType)) {
        for (items.items) |*item| SszType.deinit(allocator, item);
    }
    items.deinit(allocator);
}

fn serializeSszValue(comptime SszType: type, allocator: std.mem.Allocator, value: *const SszType.Type) ![]u8 {
    const size = if (comptime isFixedType(SszType)) SszType.fixed_size else SszType.serializedSize(value);
    const bytes = try allocator.alloc(u8, size);
    _ = SszType.serializeIntoBytes(value, bytes);
    return bytes;
}

fn publishSsz(
    node: *BeaconNode,
    topic_type: networking.gossip_topics.GossipTopicType,
    subnet_id: ?u8,
    ssz_bytes: []const u8,
) !void {
    if (node.p2p_service) |*p2p| {
        try p2p.publishGossip(topic_type, subnet_id, ssz_bytes);
    }
}

fn importAttestationFromApi(node: *BeaconNode, attestation: *const AnyGossipAttestation) !void {
    const gh = node.gossip_handler orelse return error.NotImplemented;
    const import_fn = gh.importAttestationFn orelse return error.NotImplemented;
    try import_fn(gh.node, attestation);
}

fn importAggregateFromApi(node: *BeaconNode, aggregate: *const AnySignedAggregateAndProof) !void {
    const gh = node.gossip_handler orelse return error.NotImplemented;
    const import_fn = gh.importAggregateFn orelse return error.NotImplemented;
    try import_fn(gh.node, aggregate);
}

fn syncCommitteePositionsForValidator(
    node: *BeaconNode,
    slot: u64,
    validator_index: u64,
) ![]const u32 {
    const cached = node.headState() orelse return error.StateNotAvailable;
    const indexed = try cached.epoch_cache.getIndexedSyncCommittee(slot);
    const positions = indexed.getValidatorIndexMap().get(validator_index) orelse return error.ValidatorNotFound;
    return positions.items;
}

fn prepareBeaconCommitteeSubnetsCallback(ptr: *anyopaque, subscriptions: []const api_mod.types.BeaconCommitteeSubscription) anyerror!void {
    const ctx: *SubnetSubscriptionCallbackCtx = @ptrCast(@alignCast(ptr));
    const subnet_service = ctx.node.subnet_service orelse return error.NotImplemented;

    for (subscriptions) |subscription| {
        try subnet_service.subscribeToAttestationSubnet(
            computeAttestationSubnet(subscription.slot, subscription.committees_at_slot, subscription.committee_index),
            subscription.slot,
            subscription.is_aggregator,
        );
    }
}

fn prepareBeaconProposerCallback(
    ptr: *anyopaque,
    preparations: []const api_mod.types.ProposerPreparation,
) anyerror!void {
    const ctx: *PrepareBeaconProposerCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    const epoch = if (node.clock) |clock|
        (clock.currentSlot(node.io) orelse node.currentHeadSlot()) / preset.SLOTS_PER_EPOCH
    else
        node.currentHeadSlot() / preset.SLOTS_PER_EPOCH;

    for (preparations) |preparation| {
        try node.chainService().setBeaconProposerData(
            epoch,
            preparation.validator_index,
            preparation.fee_recipient,
        );
    }
}

fn prepareSyncCommitteeSubnetsCallback(ptr: *anyopaque, subscriptions: []const api_mod.types.SyncCommitteeSubscription) anyerror!void {
    const ctx: *SubnetSubscriptionCallbackCtx = @ptrCast(@alignCast(ptr));
    const subnet_service = ctx.node.subnet_service orelse return error.NotImplemented;
    const sync_subcommittee_size = @divFloor(preset.SYNC_COMMITTEE_SIZE, networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT);

    for (subscriptions) |subscription| {
        var seen = std.StaticBitSet(networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT).initEmpty();
        for (subscription.sync_committee_indices) |committee_index| {
            const subnet: u8 = @intCast(@divFloor(committee_index, sync_subcommittee_size));
            if (seen.isSet(subnet)) continue;
            seen.set(subnet);
            try subnet_service.subscribeToSyncSubnet(
                subnet,
                (subscription.until_epoch + 1) * preset.SLOTS_PER_EPOCH,
                true,
            );
        }
    }
}

fn getChainHeadTrackerCallback(ptr: *anyopaque) ApiHeadTracker {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    const snapshot = ctx.query.currentSnapshot();
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

fn getNodeSyncStatusCallback(ptr: *anyopaque) ApiSyncStatus {
    const ctx: *SyncStatusCallbackCtx = @ptrCast(@alignCast(ptr));
    const status = ctx.node.getSyncStatus();
    return .{
        .head_slot = status.head_slot,
        .sync_distance = status.sync_distance,
        .is_syncing = status.is_syncing,
        .is_optimistic = status.is_optimistic,
        .el_offline = status.el_offline,
    };
}

fn getChainBlockRootBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.canonicalBlockRootAtSlot(slot);
}

fn getChainBlockBytesByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.blockBytesByRoot(root);
}

fn getChainStateRootBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[32]u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateRootBySlot(slot);
}

fn getChainStateRootByBlockRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[32]u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateRootByBlockRoot(root);
}

fn getChainStateBytesBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateBytesBySlot(slot);
}

fn getChainStateBytesByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateBytesByRoot(root);
}

fn getChainStateArchiveAtSlotCallback(ptr: *anyopaque, slot: u64) anyerror!?[]const u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateArchiveAtSlot(slot);
}

fn getChainStateArchiveByRootCallback(ptr: *anyopaque, root: [32]u8) anyerror!?[]const u8 {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateArchiveByRoot(root);
}

fn getChainHeadStateCallback(ptr: *anyopaque) ?*CachedBeaconState {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.headState();
}

fn getChainStateByRootCallback(ptr: *anyopaque, state_root: [32]u8) anyerror!?*CachedBeaconState {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateByRoot(state_root);
}

fn getChainStateBySlotCallback(ptr: *anyopaque, slot: u64) anyerror!?*CachedBeaconState {
    const ctx: *ChainCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.stateBySlot(slot);
}

fn getAggregateAttestationCallback(
    ptr: *anyopaque,
    alloc: std.mem.Allocator,
    slot: u64,
    attestation_data_root: [32]u8,
) anyerror![]const u8 {
    const ctx: *AggregateAttestationCallbackCtx = @ptrCast(@alignCast(ptr));
    const best = ctx.query.aggregateAttestation(@intCast(slot), attestation_data_root) orelse
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

fn readSignedBlockSlot(block_bytes: []const u8) ?u64 {
    if (block_bytes.len < 4) return null;
    const msg_offset = std.mem.readInt(u32, block_bytes[0..4], .little);
    if (block_bytes.len < @as(usize, msg_offset) + 8) return null;
    return std.mem.readInt(u64, block_bytes[msg_offset..][0..8], .little);
}

fn applyPublishValidation(
    node: *BeaconNode,
    any_signed: AnySignedBeaconBlock,
    validation: api_mod.types.BroadcastValidation,
) anyerror!void {
    switch (validation) {
        .gossip => {
            var block_root: [32]u8 = undefined;
            try any_signed.beaconBlock().hashTreeRoot(node.allocator, &block_root);
            const beacon_block = any_signed.beaconBlock();
            const gossip_state = node.chain.makeGossipState();
            const action = chain_mod.validateGossipBlock(
                beacon_block.slot(),
                beacon_block.proposerIndex(),
                beacon_block.parentRoot().*,
                block_root,
                &gossip_state,
            );
            if (action == .reject) return error.InvalidRequest;
        },
        .consensus => {},
        .consensus_and_equivocation => {
            std.log.warn(
                "broadcastValidation=consensus_and_equivocation currently aliases consensus validation; equivocation checks are not implemented yet",
                .{},
            );
        },
        .none => {},
    }
}

fn importBlockCallback(
    ptr: *anyopaque,
    params: api_mod.context.PublishedBlockParams,
) anyerror!void {
    const cb_ctx: *BlockImportCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = cb_ctx.node;

    // SignedBeaconBlock SSZ layout starts with a 4-byte offset to `message`,
    // followed by the fixed 96-byte signature. The BeaconBlock `slot` is the
    // first field in the message fixed section.
    const block_slot: u64 = if (readSignedBlockSlot(params.block_bytes)) |slot|
        slot
    else
        node.currentHeadSlot();
    const fork_seq = cb_ctx.beacon_config.forkSeq(block_slot);

    const any_signed = try AnySignedBeaconBlock.deserialize(
        node.allocator,
        params.block_type,
        fork_seq,
        params.block_bytes,
    );

    const imported = switch (params.block_type) {
        .full => any_signed,
        .blinded => blk: {
            errdefer any_signed.deinit(node.allocator);
            break :blk try block_production_mod.unblindPublishedBlock(node, any_signed);
        },
    };

    try applyPublishValidation(node, imported, params.broadcast_validation);
    _ = try node.importBlock(imported, .api);
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

fn publishChainNotificationFn(ptr: *anyopaque, notification: chain_mod.ChainNotification) void {
    const ctx: *ChainNotificationSinkCtx = @ptrCast(@alignCast(ptr));
    const bus = ctx.event_bus;
    const api_event: api_mod.Event = switch (notification) {
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
    if (params.fee_recipient) |fee_recipient| prod_config.fee_recipient = fee_recipient;
    const selection = params.builder_selection orelse .executiononly;
    prod_config.builder_boost_factor = switch (selection) {
        .executionalways, .executiononly => 0,
        .default => 90,
        .maxprofit => params.builder_boost_factor,
        .builderalways, .builderonly => params.builder_boost_factor,
    };
    prod_config.randao_reveal = params.randao_reveal;

    switch (selection) {
        .executiononly, .executionalways => {
            var produced = try node.produceFullBlock(params.slot, prod_config);
            defer produced.deinit(allocator);

            if (params.strict_fee_recipient_check) {
                const expected_fee_recipient = params.fee_recipient orelse node.chainQuery().proposerFeeRecipientForSlot(
                    params.slot,
                    node.node_options.suggested_fee_recipient,
                ) orelse return error.MissingProposerFeeRecipient;
                try block_production_mod.ensureProducedFeeRecipient(&produced, expected_fee_recipient, true);
            }

            const serialized = try block_production_mod.serializeUnsignedBlock(
                node,
                allocator,
                params.slot,
                &produced,
                if (params.blinded_local) .blinded else .full,
            );
            return .{
                .ssz_bytes = serialized.ssz_bytes,
                .fork = serialized.fork_name,
                .blinded = serialized.block_type == .blinded,
                .execution_payload_source = .engine,
            };
        },
        .@"default", .maxprofit => {
            if (try block_production_mod.produceBuilderBlindedBlock(
                node,
                params.slot,
                prod_config,
                block_production_mod.builderBidThresholdForConfig(node, prod_config),
                false,
            )) |produced_blinded_value| {
                var produced_blinded = produced_blinded_value;
                defer produced_blinded.deinit(allocator);

                if (params.strict_fee_recipient_check) {
                    const expected_fee_recipient = params.fee_recipient orelse node.chainQuery().proposerFeeRecipientForSlot(
                        params.slot,
                        node.node_options.suggested_fee_recipient,
                    ) orelse return error.MissingProposerFeeRecipient;
                    try block_production_mod.ensureProducedBlindedFeeRecipient(&produced_blinded, expected_fee_recipient, true);
                }

                const serialized = try block_production_mod.serializeUnsignedProducedBlindedBlock(
                    node,
                    allocator,
                    params.slot,
                    &produced_blinded,
                );
                return .{
                    .ssz_bytes = serialized.ssz_bytes,
                    .fork = serialized.fork_name,
                    .blinded = true,
                    .execution_payload_source = .builder,
                };
            }

            var produced = try node.produceFullBlock(params.slot, prod_config);
            defer produced.deinit(allocator);

            if (params.strict_fee_recipient_check) {
                const expected_fee_recipient = params.fee_recipient orelse node.chainQuery().proposerFeeRecipientForSlot(
                    params.slot,
                    node.node_options.suggested_fee_recipient,
                ) orelse return error.MissingProposerFeeRecipient;
                try block_production_mod.ensureProducedFeeRecipient(&produced, expected_fee_recipient, true);
            }

            const serialized = try block_production_mod.serializeUnsignedBlock(
                node,
                allocator,
                params.slot,
                &produced,
                if (params.blinded_local) .blinded else .full,
            );
            return .{
                .ssz_bytes = serialized.ssz_bytes,
                .fork = serialized.fork_name,
                .blinded = serialized.block_type == .blinded,
                .execution_payload_source = .engine,
            };
        },
        .builderalways, .builderonly => {
            var produced = (try block_production_mod.produceBuilderBlindedBlock(
                node,
                params.slot,
                prod_config,
                null,
                true,
            )) orelse return error.BuilderBidUnavailable;
            defer produced.deinit(allocator);

            if (params.strict_fee_recipient_check) {
                const expected_fee_recipient = params.fee_recipient orelse node.chainQuery().proposerFeeRecipientForSlot(
                    params.slot,
                    node.node_options.suggested_fee_recipient,
                ) orelse return error.MissingProposerFeeRecipient;
                try block_production_mod.ensureProducedBlindedFeeRecipient(&produced, expected_fee_recipient, true);
            }

            const serialized = try block_production_mod.serializeUnsignedProducedBlindedBlock(
                node,
                allocator,
                params.slot,
                &produced,
            );
            return .{
                .ssz_bytes = serialized.ssz_bytes,
                .fork = serialized.fork_name,
                .blinded = true,
                .execution_payload_source = .builder,
            };
        },
    }
}

fn getAttestationDataCallback(
    ptr: *anyopaque,
    slot: u64,
    committee_index: u64,
) anyerror!api_mod.context.AttestationDataResult {
    const ctx: *AttestationDataCallbackCtx = @ptrCast(@alignCast(ptr));
    const query = ctx.query;
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
    const cached = node.headState() orelse return error.StateNotAvailable;

    if (parseJsonArray(types.electra.SingleAttestation, node.allocator, json_bytes)) |single_attestations| {
        var parsed_single_attestations = single_attestations;
        defer deinitParsedArray(types.electra.SingleAttestation, node.allocator, &parsed_single_attestations);

        for (parsed_single_attestations.items) |*single| {
            const committees_at_slot = try cached.epoch_cache.getCommitteeCountPerSlot(computeEpochAtSlot(single.data.slot));
            const subnet = computeAttestationSubnet(single.data.slot, committees_at_slot, single.committee_index);
            const gossip_attestation = AnyGossipAttestation{ .electra_single = single.* };
            try importAttestationFromApi(node, &gossip_attestation);

            const ssz_bytes = try serializeSszValue(types.electra.SingleAttestation, node.allocator, single);
            defer node.allocator.free(ssz_bytes);
            try publishSsz(node, .beacon_attestation, subnet, ssz_bytes);
        }
        return;
    } else |_| {}

    var attestations = try parseJsonArray(types.phase0.Attestation, node.allocator, json_bytes);
    defer deinitParsedArray(types.phase0.Attestation, node.allocator, &attestations);

    for (attestations.items) |*attestation| {
        const committees_at_slot = try cached.epoch_cache.getCommitteeCountPerSlot(computeEpochAtSlot(attestation.data.slot));
        const subnet = computeAttestationSubnet(attestation.data.slot, committees_at_slot, attestation.data.index);
        const gossip_attestation = AnyGossipAttestation{ .phase0 = attestation.* };
        try importAttestationFromApi(node, &gossip_attestation);

        const ssz_bytes = try serializeSszValue(types.phase0.Attestation, node.allocator, attestation);
        defer node.allocator.free(ssz_bytes);
        try publishSsz(node, .beacon_attestation, subnet, ssz_bytes);
    }
}

fn submitAggregateAndProofCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    if (parseJsonArray(types.electra.SignedAggregateAndProof, node.allocator, json_bytes)) |aggregates| {
        var parsed_aggregates = aggregates;
        defer deinitParsedArray(types.electra.SignedAggregateAndProof, node.allocator, &parsed_aggregates);

        for (parsed_aggregates.items) |*aggregate| {
            const any_aggregate = AnySignedAggregateAndProof{ .electra = aggregate.* };
            try importAggregateFromApi(node, &any_aggregate);

            const ssz_bytes = try serializeSszValue(types.electra.SignedAggregateAndProof, node.allocator, aggregate);
            defer node.allocator.free(ssz_bytes);
            try publishSsz(node, .beacon_aggregate_and_proof, null, ssz_bytes);
        }
        return;
    } else |_| {}

    var aggregates = try parseJsonArray(types.phase0.SignedAggregateAndProof, node.allocator, json_bytes);
    defer deinitParsedArray(types.phase0.SignedAggregateAndProof, node.allocator, &aggregates);

    for (aggregates.items) |*aggregate| {
        const any_aggregate = AnySignedAggregateAndProof{ .phase0 = aggregate.* };
        try importAggregateFromApi(node, &any_aggregate);

        const ssz_bytes = try serializeSszValue(types.phase0.SignedAggregateAndProof, node.allocator, aggregate);
        defer node.allocator.free(ssz_bytes);
        try publishSsz(node, .beacon_aggregate_and_proof, null, ssz_bytes);
    }
}

fn submitVoluntaryExitCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    const exit = try parseJsonValue(types.phase0.SignedVoluntaryExit, node.allocator, json_bytes);
    try node.chainService().importVoluntaryExit(exit);

    const ssz_bytes = try serializeSszValue(types.phase0.SignedVoluntaryExit, node.allocator, &exit);
    defer node.allocator.free(ssz_bytes);
    try publishSsz(node, .voluntary_exit, null, ssz_bytes);
}

fn submitProposerSlashingCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    const slashing = try parseJsonValue(types.phase0.ProposerSlashing, node.allocator, json_bytes);
    try node.chainService().importProposerSlashing(slashing);

    const ssz_bytes = try serializeSszValue(types.phase0.ProposerSlashing, node.allocator, &slashing);
    defer node.allocator.free(ssz_bytes);
    try publishSsz(node, .proposer_slashing, null, ssz_bytes);
}

fn submitAttesterSlashingCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    if (parseJsonValue(types.electra.AttesterSlashing, node.allocator, json_bytes)) |electra_slashing| {
        var parsed_electra_slashing = electra_slashing;
        defer types.electra.AttesterSlashing.deinit(node.allocator, &parsed_electra_slashing);
        const any_slashing = AnyAttesterSlashing{ .electra = parsed_electra_slashing };
        try node.chainService().importAttesterSlashing(&any_slashing);

        const ssz_bytes = try serializeSszValue(types.electra.AttesterSlashing, node.allocator, &parsed_electra_slashing);
        defer node.allocator.free(ssz_bytes);
        try publishSsz(node, .attester_slashing, null, ssz_bytes);
        return;
    } else |_| {}

    var phase0_slashing = try parseJsonValue(types.phase0.AttesterSlashing, node.allocator, json_bytes);
    defer types.phase0.AttesterSlashing.deinit(node.allocator, &phase0_slashing);

    const any_slashing = AnyAttesterSlashing{ .phase0 = phase0_slashing };
    try node.chainService().importAttesterSlashing(&any_slashing);

    const ssz_bytes = try serializeSszValue(types.phase0.AttesterSlashing, node.allocator, &phase0_slashing);
    defer node.allocator.free(ssz_bytes);
    try publishSsz(node, .attester_slashing, null, ssz_bytes);
}

fn submitBlsChangeCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    var changes = try parseJsonArray(types.capella.SignedBLSToExecutionChange, node.allocator, json_bytes);
    defer deinitParsedArray(types.capella.SignedBLSToExecutionChange, node.allocator, &changes);

    for (changes.items) |*change| {
        try node.chainService().importBlsChange(change.*);
        const ssz_bytes = try serializeSszValue(types.capella.SignedBLSToExecutionChange, node.allocator, change);
        defer node.allocator.free(ssz_bytes);
        try publishSsz(node, .bls_to_execution_change, null, ssz_bytes);
    }
}

fn submitSyncCommitteeMessageCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    var messages = try parseJsonArray(types.altair.SyncCommitteeMessage, node.allocator, json_bytes);
    defer deinitParsedArray(types.altair.SyncCommitteeMessage, node.allocator, &messages);

    const subcommittee_size = @divFloor(preset.SYNC_COMMITTEE_SIZE, networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT);
    for (messages.items) |*msg| {
        const ssz_bytes = try serializeSszValue(types.altair.SyncCommitteeMessage, node.allocator, msg);
        defer node.allocator.free(ssz_bytes);

        const positions = try syncCommitteePositionsForValidator(node, msg.slot, msg.validator_index);
        for (positions) |position| {
            const subnet: u64 = @divFloor(position, subcommittee_size);
            const index_in_subcommittee: u64 = position % subcommittee_size;
            try node.chainService().importSyncCommitteeMessage(
                subnet,
                msg.slot,
                msg.beacon_block_root,
                index_in_subcommittee,
                msg.signature,
            );
            try publishSsz(node, .sync_committee, @intCast(subnet), ssz_bytes);
        }
    }
}

fn submitContributionAndProofCallback(ptr: *anyopaque, json_bytes: []const u8) anyerror!void {
    const ctx: *PoolSubmitCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    var contributions = try parseJsonArray(types.altair.SignedContributionAndProof, node.allocator, json_bytes);
    defer deinitParsedArray(types.altair.SignedContributionAndProof, node.allocator, &contributions);

    for (contributions.items) |*contribution| {
        try node.chainService().importSyncContribution(&contribution.message.contribution);
        const ssz_bytes = try serializeSszValue(types.altair.SignedContributionAndProof, node.allocator, contribution);
        defer node.allocator.free(ssz_bytes);
        try publishSsz(node, .sync_committee_contribution_and_proof, null, ssz_bytes);
    }
}

fn builderRegisterValidatorsCallback(
    ptr: *anyopaque,
    registrations: []const api_mod.types.SignedValidatorRegistrationV1,
) anyerror!void {
    const ctx: *BuilderCallbackCtx = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    _ = node.builder_api orelse return;

    const relay_registrations = try node.allocator.alloc(
        execution_mod.builder.SignedValidatorRegistration,
        registrations.len,
    );
    defer node.allocator.free(relay_registrations);

    for (registrations, 0..) |registration, i| {
        relay_registrations[i] = .{
            .message = .{
                .fee_recipient = registration.message.fee_recipient,
                .gas_limit = registration.message.gas_limit,
                .timestamp = registration.message.timestamp,
                .pubkey = registration.message.pubkey,
            },
            .signature = registration.signature,
        };
    }

    node.registerValidatorsWithBuilder(relay_registrations);
}

fn opPoolGetCountsCallback(ptr: *anyopaque) [5]usize {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.opPoolCounts();
}

fn opPoolGetAttestationsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    slot_filter: ?u64,
    committee_index_filter: ?u64,
) anyerror![]types.phase0.Attestation.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.attestations(allocator, slot_filter, committee_index_filter);
}

fn opPoolGetVoluntaryExitsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.phase0.SignedVoluntaryExit.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.voluntaryExits(allocator);
}

fn opPoolGetProposerSlashingsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.phase0.ProposerSlashing.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.proposerSlashings(allocator);
}

fn opPoolGetAttesterSlashingsCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]fork_types.AnyAttesterSlashing {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.attesterSlashings(allocator);
}

fn opPoolGetBlsToExecutionChangesCallback(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]types.capella.SignedBLSToExecutionChange.Type {
    const ctx: *OpPoolCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.query.blsToExecutionChanges(allocator);
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
