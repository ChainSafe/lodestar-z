const std = @import("std");

const ct = @import("consensus_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const preset = @import("preset").preset;
const preset_root = @import("preset");
const active_preset = @import("preset").active_preset;
const state_transition = @import("state_transition");
const chain_mod = @import("chain");
const db_mod = @import("db");
const networking = @import("networking");
const fork_choice_mod = @import("fork_choice");

const node_pkg = @import("root.zig");
const BeaconNode = node_pkg.BeaconNode;
const NodeOptions = node_pkg.NodeOptions;
const block_production_mod = node_pkg.block_production_mod;
const identity_mod = node_pkg.identity;
const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");

const StatusMessage = networking.messages.StatusMessage;
const freeResponseChunks = networking.freeResponseChunks;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;
const ProtoBlock = fork_choice_mod.ProtoBlock;

const generateElectraState = state_transition.test_utils.generateElectraState;
const SharedStateGraph = chain_mod.SharedStateGraph;
const BatchOp = db_mod.BatchOp;

const active_chain_config = if (active_preset == .mainnet)
    config_mod.mainnet.chain_config
else
    config_mod.minimal.chain_config;
const test_validator_count = 16;

fn makeTestConfig(allocator: std.mem.Allocator) !*BeaconConfig {
    var temp_pool = try @import("persistent_merkle_tree").Node.Pool.init(allocator, 256 * 5);
    defer temp_pool.deinit();

    const temp_state = try generateElectraState(allocator, &temp_pool, active_chain_config, test_validator_count);
    defer {
        temp_state.deinit();
        allocator.destroy(temp_state);
    }

    const config = try allocator.create(BeaconConfig);
    errdefer allocator.destroy(config);
    config.* = BeaconConfig.init(active_chain_config, (try temp_state.genesisValidatorsRoot()).*);
    return config;
}

fn createPublishedState(
    allocator: std.mem.Allocator,
    shared_state_graph: *SharedStateGraph,
) !*state_transition.CachedBeaconState {
    const raw_state = try generateElectraState(
        allocator,
        shared_state_graph.pool,
        active_chain_config,
        test_validator_count,
    );

    const validators = try raw_state.validatorsSlice(allocator);
    defer allocator.free(validators);
    try shared_state_graph.validator_pubkeys.syncFromValidators(validators);

    return state_transition.CachedBeaconState.createCachedBeaconState(
        allocator,
        raw_state,
        state_transition.metrics.noop(),
        shared_state_graph.validator_pubkeys.immutableData(shared_state_graph.config),
        .{
            .skip_sync_committee_cache = raw_state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
}

fn onReqRespVersioned(
    node: *BeaconNode,
    method: networking.Method,
    version: u8,
    request_bytes: []const u8,
) ![]const networking.ResponseChunk {
    var req_ctx = reqresp_callbacks_mod.RequestContext{
        .node = @ptrCast(node),
    };
    const ctx = reqresp_callbacks_mod.makeReqRespContext(&req_ctx);
    return networking.req_resp_handler.handleRequestVersioned(std.testing.allocator, method, version, request_bytes, &ctx);
}

fn installCanonicalTestBlock(
    node: *BeaconNode,
    block_root: [32]u8,
    parent_root: [32]u8,
    slot: u64,
    state_root: [32]u8,
) !void {
    const fc = node.chain.forkChoice();
    const justified = fc.getJustifiedCheckpoint();
    const finalized = fc.getFinalizedCheckpoint();
    const block = ProtoBlock{
        .slot = slot,
        .block_root = block_root,
        .parent_root = parent_root,
        .state_root = state_root,
        .target_root = block_root,
        .justified_epoch = justified.epoch,
        .justified_root = justified.root,
        .finalized_epoch = finalized.epoch,
        .finalized_root = finalized.root,
        .unrealized_justified_epoch = justified.epoch,
        .unrealized_justified_root = justified.root,
        .unrealized_finalized_epoch = finalized.epoch,
        .unrealized_finalized_root = finalized.root,
        .extra_meta = .pre_merge,
        .timeliness = true,
    };
    try fork_choice_mod.onBlockFromProto(fc, std.testing.allocator, block, slot);
    const updated = try fc.updateAndGetHead(std.testing.allocator, .get_canonical_head);
    try node.chain.onTrackedBlock(block_root, slot, state_root);
    node.chain.setTrackedHead(updated.head.block_root, updated.head.slot, updated.head.state_root);
}

fn queueForkchoiceUpdateForHead(node: *BeaconNode, head_root: [32]u8) !void {
    const fc_state = node.chainQuery().executionForkchoiceState(head_root) orelse return;
    try node.execution_runtime.submitForkchoiceUpdateAsync(.{
        .beacon_block_root = head_root,
        .state = fc_state,
    });

    var spins: usize = 0;
    while (spins < 1_000) : (spins += 1) {
        if (node.processPendingExecutionForkchoiceUpdates()) return;
        switch (node.execution_runtime.waitForAsyncCompletion()) {
            .completed => continue,
            .shutdown => return error.TestShutdown,
            .idle => break,
        }
    }

    return error.TestTimeout;
}

const TestContext = struct {
    config: *BeaconConfig,
    node: *BeaconNode,

    fn initUnbootstrapped(opts: NodeOptions) !TestContext {
        const allocator = std.testing.allocator;
        const config = try makeTestConfig(allocator);
        errdefer allocator.destroy(config);

        const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, opts);
        const node = try BeaconNode.initUnbootstrapped(allocator, std.testing.io, config, .{
            .options = opts,
            .node_identity = node_identity,
        });
        errdefer node.deinit();

        return .{
            .config = config,
            .node = node,
        };
    }

    fn init(opts: NodeOptions) !TestContext {
        const allocator = std.testing.allocator;
        const config = try makeTestConfig(allocator);
        errdefer allocator.destroy(config);

        const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, opts);
        var builder = try BeaconNode.Builder.init(allocator, std.testing.io, config, .{
            .options = opts,
            .node_identity = node_identity,
        });
        errdefer builder.deinit();

        const genesis_state = try createPublishedState(allocator, builder.sharedStateGraph());
        try genesis_state.state.setSlot(0);
        const node = try builder.finishGenesis(genesis_state);

        return .{
            .config = config,
            .node = node,
        };
    }

    fn makePublishedState(self: *TestContext) !*state_transition.CachedBeaconState {
        return createPublishedState(std.testing.allocator, self.node.chain_runtime.shared_state_graph);
    }

    fn deinit(self: *TestContext) void {
        self.node.deinit();
        std.testing.allocator.destroy(self.config);
    }
};

test "BeaconNode: init and deinit" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const head = ctx.node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
    try std.testing.expectEqual(@as(usize, 0), ctx.node.chainQuery().opPoolCounts()[0]);
}

test "BeaconNode: initFromGenesis sets head at slot 0" {
    var ctx = try TestContext.initUnbootstrapped(.{});
    defer ctx.deinit();

    const genesis_state = try ctx.makePublishedState();
    try genesis_state.state.setSlot(0);

    try ctx.node.initFromGenesis(genesis_state);

    const head = ctx.node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    _ = head.finalized_epoch;
    _ = head.justified_epoch;
    try std.testing.expect(ctx.node.clock != null);
}

test "BeaconNode: getHead returns initial state" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const head = ctx.node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
}

test "BeaconNode: getSyncStatus" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const sync = ctx.node.getSyncStatus();
    try std.testing.expectEqual(@as(u64, 0), sync.head_slot);
    try std.testing.expect(!sync.is_syncing);
    try std.testing.expect(!sync.el_offline);
}

test "BeaconNode: getStatus returns current chain state" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const status = ctx.node.getStatus();
    try std.testing.expectEqual(@as(u64, 0), status.head_slot);
    try std.testing.expectEqual(@as(u64, 0), status.finalized_epoch);
}

test "BeaconNode: produceBlock from empty pool" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    var body = try ctx.node.produceBlock(1);
    defer body.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), body.attestations.len);
    try std.testing.expectEqual(@as(usize, 0), body.voluntary_exits.len);
    try std.testing.expectEqual(@as(usize, 0), body.proposer_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.attester_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.bls_to_execution_changes.len);
}

test "BeaconNode: op pool integration" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const exit = chain_mod.op_pool.makeTestExit(42, 10);
    try ctx.node.chainService().importVoluntaryExit(exit);

    var body = try ctx.node.produceBlock(1);
    defer body.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), body.voluntary_exits.len);
}

test "BeaconNode: seen cache dedup" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const root = [_]u8{0xAB} ** 32;
    try std.testing.expect(!ctx.node.chain_runtime.seen_cache.hasSeenBlock(root));

    try ctx.node.chain_runtime.seen_cache.markBlockSeen(root, 5);
    try std.testing.expect(ctx.node.chain_runtime.seen_cache.hasSeenBlock(root));
}

test "BeaconNode: onReqResp Status" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const status_msg = StatusMessage.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
    };
    var buf: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&status_msg, &buf);

    const chunks = try ctx.node.onReqResp(.status, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
}

test "BeaconNode: onReqResp Status returns real head slot and root" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const expected_root = [_]u8{0xAB} ** 32;
    const finalized_slot = ctx.node.chain.forkChoice().getFinalizedCheckpoint().epoch * preset.SLOTS_PER_EPOCH;
    const expected_slot: u64 = finalized_slot + 10;
    const state_root = [_]u8{0x11} ** 32;
    try installCanonicalTestBlock(ctx.node, expected_root, ctx.node.getHead().root, expected_slot, state_root);

    const peer_status = StatusMessage.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
    };
    var buf: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&peer_status, &buf);

    const chunks = try ctx.node.onReqResp(.status, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    var resp: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &resp);
    try std.testing.expectEqual(expected_slot, resp.head_slot);
    try std.testing.expectEqualSlices(u8, &expected_root, &resp.head_root);
}

test "BeaconNode: onReqResp StatusV2 returns earliest available slot" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const expected_root = [_]u8{0xBC} ** 32;
    const finalized_slot = ctx.node.chain.forkChoice().getFinalizedCheckpoint().epoch * preset.SLOTS_PER_EPOCH;
    const expected_slot: u64 = finalized_slot + 10;
    const expected_earliest_slot: u64 = expected_slot - 16;
    const state_root = [_]u8{0x22} ** 32;
    try installCanonicalTestBlock(ctx.node, expected_root, ctx.node.getHead().root, expected_slot, state_root);
    ctx.node.earliest_available_slot = expected_earliest_slot;

    const peer_status = networking.messages.StatusMessageV2.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
        .earliest_available_slot = 0,
    };
    var buf: [networking.messages.StatusMessageV2.fixed_size]u8 = undefined;
    _ = networking.messages.StatusMessageV2.serializeIntoBytes(&peer_status, &buf);

    const chunks = try onReqRespVersioned(ctx.node, .status, 2, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    var resp: networking.messages.StatusMessageV2.Type = undefined;
    try networking.messages.StatusMessageV2.deserializeFromBytes(chunks[0].ssz_payload, &resp);
    try std.testing.expectEqual(expected_slot, resp.head_slot);
    try std.testing.expectEqualSlices(u8, &expected_root, &resp.head_root);
    try std.testing.expectEqual(expected_earliest_slot, resp.earliest_available_slot);
}

test "BeaconNode: onReqResp MetadataV3 returns live custody group count" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    ctx.node.api_node_identity.metadata.seq_number = 17;
    ctx.node.api_node_identity.metadata.attnets[0] = 0b0000_0101;
    ctx.node.api_node_identity.metadata.syncnets[0] = 0b0000_0010;

    const chunks = try onReqRespVersioned(ctx.node, .metadata, 3, &.{});
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    var resp: networking.messages.MetadataV3.Type = undefined;
    try networking.messages.MetadataV3.deserializeFromBytes(chunks[0].ssz_payload, &resp);
    try std.testing.expectEqual(@as(u64, 17), resp.seq_number);
    try std.testing.expectEqual(ctx.node.api_node_identity.metadata.attnets, resp.attnets.data);
    try std.testing.expectEqual(ctx.node.api_node_identity.metadata.syncnets, resp.syncnets.data);
    try std.testing.expectEqual(ctx.node.config.chain.CUSTODY_REQUIREMENT, resp.custody_group_count);
}

test "BeaconNode: onReqResp BeaconBlocksByRoot returns stored block" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const known_root = [_]u8{0xCC} ** 32;
    const fake_block_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 } ** 8;
    try ctx.node.chain_runtime.db.putBlock(known_root, &fake_block_bytes);

    const known_root_2 = [_]u8{0xDD} ** 32;
    const fake_block_bytes_2 = [_]u8{ 0x05, 0x06 } ** 16;
    try ctx.node.chain_runtime.db.putBlock(known_root_2, &fake_block_bytes_2);

    const unknown_root = [_]u8{0xFF} ** 32;
    var request_bytes: [32 * 3]u8 = undefined;
    @memcpy(request_bytes[0..32], &known_root);
    @memcpy(request_bytes[32..64], &unknown_root);
    @memcpy(request_bytes[64..96], &known_root_2);

    const chunks = try ctx.node.onReqResp(.beacon_blocks_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[1].result);
    try std.testing.expectEqualSlices(u8, &fake_block_bytes, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &fake_block_bytes_2, chunks[1].ssz_payload);
}

test "BeaconNode: onReqResp Ping returns sequence 0" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const peer_seq: networking.messages.Ping.Type = 7;
    var buf: [networking.messages.Ping.fixed_size]u8 = undefined;
    _ = networking.messages.Ping.serializeIntoBytes(&peer_seq, &buf);

    const chunks = try ctx.node.onReqResp(.ping, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    var resp_seq: networking.messages.Ping.Type = undefined;
    try networking.messages.Ping.deserializeFromBytes(chunks[0].ssz_payload, &resp_seq);
    try std.testing.expectEqual(@as(u64, 0), resp_seq);
}

test "BeaconNode: onReqResp BeaconBlocksByRange returns blocks for known slots" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const root_10 = [_]u8{0x10} ** 32;
    const root_11 = [_]u8{0x11} ** 32;
    const block_10 = [_]u8{0xAA} ** 20;
    const block_11 = [_]u8{0xBB} ** 20;
    const genesis_root = ctx.node.getHead().root;
    const finalized_slot = ctx.node.chain.forkChoice().getFinalizedCheckpoint().epoch * preset.SLOTS_PER_EPOCH;
    const start_slot = finalized_slot + 10;

    try installCanonicalTestBlock(ctx.node, root_10, genesis_root, start_slot, [_]u8{0} ** 32);
    try installCanonicalTestBlock(ctx.node, root_11, root_10, start_slot + 1, [_]u8{0} ** 32);
    ctx.node.earliest_available_slot = start_slot;
    try ctx.node.chain_runtime.db.putBlock(root_10, &block_10);
    try ctx.node.chain_runtime.db.putBlock(root_11, &block_11);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = start_slot,
        .count = 3,
    };
    var buf: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &buf);

    const chunks = try ctx.node.onReqResp(.beacon_blocks_by_range, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqualSlices(u8, &block_10, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &block_11, chunks[1].ssz_payload);
}

test "BeaconNode: onReqResp BeaconBlocksByRange skips missing slots and preserves order" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const root_a = [_]u8{0x21} ** 32;
    const root_c = [_]u8{0x23} ** 32;
    const block_a = [_]u8{0xCA} ** 24;
    const block_c = [_]u8{0xCC} ** 24;
    const genesis_root = ctx.node.getHead().root;
    const finalized_slot = ctx.node.chain.forkChoice().getFinalizedCheckpoint().epoch * preset.SLOTS_PER_EPOCH;
    const start_slot = finalized_slot + 20;

    try installCanonicalTestBlock(ctx.node, root_a, genesis_root, start_slot, [_]u8{0xA1} ** 32);
    try installCanonicalTestBlock(ctx.node, root_c, root_a, start_slot + 2, [_]u8{0xC3} ** 32);
    ctx.node.earliest_available_slot = start_slot;
    try ctx.node.chain_runtime.db.putBlock(root_a, &block_a);
    try ctx.node.chain_runtime.db.putBlock(root_c, &block_c);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = start_slot,
        .count = 3,
    };
    var buf: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &buf);

    const chunks = try ctx.node.onReqResp(.beacon_blocks_by_range, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[1].result);
    try std.testing.expectEqualSlices(u8, &block_a, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &block_c, chunks[1].ssz_payload);
}

test "BeaconNode: importBlobSidecar and onReqResp BlobSidecarsByRoot returns stored blob" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const blob_root = [_]u8{0xBB} ** 32;
    const fake_blob_bytes = try allocator.alloc(u8, sidecar_size * 2);
    defer allocator.free(fake_blob_bytes);
    @memset(fake_blob_bytes[0..sidecar_size], 0xAA);
    @memset(fake_blob_bytes[sidecar_size..], 0xBB);
    try ctx.node.importBlobSidecar(blob_root, fake_blob_bytes);

    var request_bytes: [32 + 8]u8 = undefined;
    @memcpy(request_bytes[0..32], &blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], 0, .little);

    const chunks0 = try ctx.node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks0);

    try std.testing.expectEqual(@as(usize, 1), chunks0.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks0[0].result);
    try std.testing.expectEqual(@as(usize, sidecar_size), chunks0[0].ssz_payload.len);
    try std.testing.expectEqual(@as(u8, 0xAA), chunks0[0].ssz_payload[0]);

    std.mem.writeInt(u64, request_bytes[32..40], 1, .little);

    const chunks1 = try ctx.node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks1);

    try std.testing.expectEqual(@as(usize, 1), chunks1.len);
    try std.testing.expectEqual(@as(usize, sidecar_size), chunks1[0].ssz_payload.len);
    try std.testing.expectEqual(@as(u8, 0xBB), chunks1[0].ssz_payload[0]);
}

test "BeaconNode: importBlobSidecar out-of-bounds index returns empty" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const blob_root = [_]u8{0xCC} ** 32;
    const fake_blob_bytes = try allocator.alloc(u8, sidecar_size);
    defer allocator.free(fake_blob_bytes);
    @memset(fake_blob_bytes, 0x01);
    try ctx.node.importBlobSidecar(blob_root, fake_blob_bytes);

    var request_bytes: [32 + 8]u8 = undefined;
    @memcpy(request_bytes[0..32], &blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], 1, .little);

    const chunks = try ctx.node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 0), chunks.len);
}

test "BeaconNode: onReqResp BlobSidecarsByRange returns stored blobs" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const root_5 = [_]u8{0x05} ** 32;
    const root_6 = [_]u8{0x06} ** 32;
    try ctx.node.chain.onTrackedBlock(root_5, 5, [_]u8{0} ** 32);
    try ctx.node.chain.onTrackedBlock(root_6, 6, [_]u8{0} ** 32);

    const blob_5 = try allocator.alloc(u8, sidecar_size * 2);
    defer allocator.free(blob_5);
    @memset(blob_5[0..sidecar_size], 0xA5);
    @memset(blob_5[sidecar_size..], 0xA6);

    const blob_6 = try allocator.alloc(u8, sidecar_size);
    defer allocator.free(blob_6);
    @memset(blob_6, 0xB6);

    try ctx.node.importBlobSidecar(root_5, blob_5);
    try ctx.node.importBlobSidecar(root_6, blob_6);

    const request = networking.messages.BlobSidecarsByRangeRequest.Type{
        .start_slot = 5,
        .count = 3,
    };
    var buf: [networking.messages.BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &buf);

    const chunks = try ctx.node.onReqResp(.blob_sidecars_by_range, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 3), chunks.len);
    try std.testing.expectEqual(@as(usize, sidecar_size), chunks[0].ssz_payload.len);
    try std.testing.expectEqual(@as(u8, 0xA5), chunks[0].ssz_payload[0]);
    try std.testing.expectEqual(@as(u8, 0xA6), chunks[1].ssz_payload[0]);
    try std.testing.expectEqual(@as(u8, 0xB6), chunks[2].ssz_payload[0]);
}

test "BeaconNode: onReqResp BlobSidecarsByRoot falls back to archived blobs" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const sidecar_size = preset_root.BLOBSIDECAR_FIXED_SIZE;
    const blob_root = [_]u8{0xD1} ** 32;
    const slot: u64 = 24;
    const archived_blobs = try allocator.alloc(u8, sidecar_size * 2);
    defer allocator.free(archived_blobs);
    @memset(archived_blobs[0..sidecar_size], 0x31);
    @memset(archived_blobs[sidecar_size..], 0x32);

    try ctx.node.chain_runtime.db.putBlockArchive(slot, blob_root, "archived-block");
    try ctx.node.chain_runtime.db.putBlobSidecarsArchive(slot, archived_blobs);

    var request_bytes: [32 + 8]u8 = undefined;
    @memcpy(request_bytes[0..32], &blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], 1, .little);

    const chunks = try ctx.node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqual(@as(usize, sidecar_size), chunks[0].ssz_payload.len);
    try std.testing.expectEqual(@as(u8, 0x32), chunks[0].ssz_payload[0]);
}

test "BeaconNode: onReqResp DataColumnSidecarsByRange falls back to archived columns" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const root = [_]u8{0xE2} ** 32;
    const slot: u64 = 48;
    const column_index: u64 = 7;
    try ctx.node.chain_runtime.db.putBlockArchive(slot, root, "archived-block");
    try ctx.node.chain_runtime.db.putDataColumnArchive(slot, column_index, "archived-column-7");

    var request: networking.messages.DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = slot,
        .count = 1,
        .columns = .empty,
    };
    defer networking.messages.DataColumnSidecarsByRangeRequest.deinit(allocator, &request);
    try request.columns.append(allocator, column_index);

    const request_bytes = try allocator.alloc(
        u8,
        networking.messages.DataColumnSidecarsByRangeRequest.serializedSize(&request),
    );
    defer allocator.free(request_bytes);
    _ = networking.messages.DataColumnSidecarsByRangeRequest.serializeIntoBytes(&request, request_bytes);

    const chunks = try ctx.node.onReqResp(.data_column_sidecars_by_range, request_bytes);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqualSlices(u8, "archived-column-7", chunks[0].ssz_payload);
}

test "BeaconNode: forkchoiceUpdated called after block import for post-merge head" {
    var ctx = try TestContext.initUnbootstrapped(.{ .engine_mock = true });
    defer ctx.deinit();

    const allocator = std.testing.allocator;
    const genesis_state = try ctx.makePublishedState();
    try genesis_state.state.setSlot(0);
    try ctx.node.initFromGenesis(genesis_state);

    const mock = ctx.node.execution_runtime.mock_engine orelse return error.TestFailed;
    const genesis_root = ctx.node.getHead().root;
    const fake_exec_hash = [_]u8{0xab} ** 32;
    const post_merge_root = [_]u8{0xcd} ** 32;
    const fc = ctx.node.chain.forkChoice();
    const finalized_cp = fc.getFinalizedCheckpoint();
    const post_merge_slot = finalized_cp.epoch * preset.SLOTS_PER_EPOCH + 10;

    const post_merge_block = ProtoBlock{
        .slot = post_merge_slot,
        .block_root = post_merge_root,
        .parent_root = genesis_root,
        .state_root = [_]u8{0xef} ** 32,
        .target_root = post_merge_root,
        .justified_epoch = finalized_cp.epoch,
        .justified_root = finalized_cp.root,
        .finalized_epoch = finalized_cp.epoch,
        .finalized_root = finalized_cp.root,
        .unrealized_justified_epoch = finalized_cp.epoch,
        .unrealized_justified_root = finalized_cp.root,
        .unrealized_finalized_epoch = finalized_cp.epoch,
        .unrealized_finalized_root = finalized_cp.root,
        .extra_meta = .{
            .post_merge = BlockExtraMeta.PostMergeMeta.init(fake_exec_hash, 1, .valid, .available),
        },
        .timeliness = true,
    };

    try fork_choice_mod.onBlockFromProto(fc, allocator, post_merge_block, post_merge_slot);
    try std.testing.expect(mock.last_forkchoice_state == null);

    try queueForkchoiceUpdateForHead(ctx.node, post_merge_root);

    try std.testing.expect(mock.last_forkchoice_state != null);
    const fcu_state = mock.last_forkchoice_state.?;
    try std.testing.expectEqual(fake_exec_hash, fcu_state.head_block_hash);
}

test "BeaconNode: forkchoiceUpdated not called for pre-merge head" {
    var ctx = try TestContext.initUnbootstrapped(.{ .engine_mock = true });
    defer ctx.deinit();

    const genesis_state = try ctx.makePublishedState();
    try genesis_state.state.setSlot(0);
    try ctx.node.initFromGenesis(genesis_state);

    const mock = ctx.node.execution_runtime.mock_engine orelse return error.TestFailed;
    const genesis_root = ctx.node.getHead().root;

    try queueForkchoiceUpdateForHead(ctx.node, genesis_root);

    try std.testing.expect(mock.last_forkchoice_state == null);
}

test "BeaconNode.Builder: finishCheckpoint repairs archive lag during bootstrap" {
    const allocator = std.testing.allocator;
    const config = try makeTestConfig(allocator);
    defer allocator.destroy(config);

    const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
    var builder = try BeaconNode.Builder.init(allocator, std.testing.io, config, .{
        .options = .{},
        .node_identity = node_identity,
    });
    defer builder.deinit();

    const checkpoint_state = try createPublishedState(allocator, builder.sharedStateGraph());

    const anchor_epoch: u64 = 1024;
    const anchor_slot: u64 = anchor_epoch * preset.SLOTS_PER_EPOCH;
    const parent_root = [_]u8{0x41} ** 32;
    const state_root_hint = [_]u8{0x52} ** 32;
    const body_root = [_]u8{0x63} ** 32;
    const checkpoint_header = ct.phase0.BeaconBlockHeader.Type{
        .slot = anchor_slot,
        .proposer_index = 0,
        .parent_root = parent_root,
        .state_root = state_root_hint,
        .body_root = body_root,
    };

    try checkpoint_state.state.setSlot(anchor_slot);
    try checkpoint_state.state.setLatestBlockHeader(&checkpoint_header);

    var anchor_block_root: [32]u8 = undefined;
    try ct.phase0.BeaconBlockHeader.hashTreeRoot(&checkpoint_header, &anchor_block_root);

    const finalized_checkpoint = ct.phase0.Checkpoint.Type{
        .epoch = anchor_epoch,
        .root = anchor_block_root,
    };
    try checkpoint_state.state.setCurrentJustifiedCheckpoint(&finalized_checkpoint);
    try checkpoint_state.state.setFinalizedCheckpoint(&finalized_checkpoint);
    try checkpoint_state.state.commit();

    try builder.runtime_builder.graph.db.putBlock(anchor_block_root, "lagging-finalized-block");

    const finalized_slot_key = db_mod.slotKey(anchor_slot);
    const finalized_slot_value = db_mod.slotKey(anchor_slot);
    const finalized_index_ops = [_]BatchOp{
        .{ .put = .{ .db = .idx_main_chain, .key = &finalized_slot_key, .value = &anchor_block_root } },
        .{ .put = .{ .db = .idx_block_root, .key = &anchor_block_root, .value = &finalized_slot_value } },
        .{ .put = .{ .db = .idx_block_parent_root, .key = &parent_root, .value = &finalized_slot_value } },
        .{ .put = .{ .db = .chain_info, .key = db_mod.BeaconDB.chainInfoKeyBytes(.finalized_slot), .value = &finalized_slot_value } },
        .{ .put = .{ .db = .chain_info, .key = db_mod.BeaconDB.chainInfoKeyBytes(.finalized_root), .value = &anchor_block_root } },
    };
    try builder.runtime_builder.graph.db.writeBatch(&finalized_index_ops);

    const node = try builder.finishCheckpoint(checkpoint_state);
    defer node.deinit();

    const archived_block = try node.chain_runtime.db.getBlockArchive(anchor_slot);
    try std.testing.expect(archived_block != null);
    defer if (archived_block) |bytes| allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "lagging-finalized-block", archived_block.?);

    const archived_state = try node.chain_runtime.db.getStateArchive(anchor_slot);
    try std.testing.expect(archived_state != null);
    defer if (archived_state) |bytes| allocator.free(bytes);

    try std.testing.expectEqual(@as(?u64, anchor_slot), try node.chain_runtime.db.getChainInfoU64(.archive_finalized_slot));
    try std.testing.expectEqual(@as(?u64, anchor_epoch), try node.chain_runtime.db.getChainInfoU64(.archive_state_epoch));
    try std.testing.expectEqual(@as(?u64, anchor_slot), try node.chain_runtime.db.getLatestStateArchiveSlot());

    const hot = try node.chain_runtime.db.getBlock(anchor_block_root);
    defer if (hot) |bytes| allocator.free(bytes);
    try std.testing.expect(hot == null);
}
