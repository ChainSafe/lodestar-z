const std = @import("std");

const preset = @import("preset").preset;
const preset_root = @import("preset");
const state_transition = @import("state_transition");
const chain_mod = @import("chain");
const networking = @import("networking");
const fork_choice_mod = @import("fork_choice");

const node_pkg = @import("root.zig");
const BeaconNode = node_pkg.BeaconNode;
const NodeOptions = node_pkg.NodeOptions;
const block_production_mod = node_pkg.block_production_mod;
const identity_mod = node_pkg.identity;

const StatusMessage = networking.messages.StatusMessage;
const freeResponseChunks = networking.freeResponseChunks;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;
const ProtoBlock = fork_choice_mod.ProtoBlock;

const TreeNode = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

const TestContext = struct {
    pool: TreeNode.Pool,
    test_state: TestCachedBeaconState,
    node: *BeaconNode,

    fn init(opts: NodeOptions) !TestContext {
        const allocator = std.testing.allocator;
        var pool = try TreeNode.Pool.init(allocator, 256 * 5);
        errdefer pool.deinit();

        const test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
        errdefer {
            var owned_state = test_state;
            owned_state.deinit();
        }

        const node_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, opts);
        const node = try BeaconNode.init(allocator, std.testing.io, test_state.cached_state.config, .{
            .options = opts,
            .node_identity = node_identity,
        });
        errdefer node.deinit();

        return .{
            .pool = pool,
            .test_state = test_state,
            .node = node,
        };
    }

    fn deinit(self: *TestContext) void {
        self.node.deinit();
        self.test_state.deinit();
        self.pool.deinit();
    }
};

test "BeaconNode: init and deinit" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const head = ctx.node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
    try std.testing.expectEqual(@as(usize, 0), ctx.node.op_pool.attestation_pool.groupCount());
}

test "BeaconNode: initFromGenesis sets head at slot 0" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const genesis_state = try ctx.test_state.cached_state.clone(allocator, .{});
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
    try ctx.node.op_pool.voluntary_exit_pool.add(exit);

    var body = try ctx.node.produceBlock(1);
    defer body.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), body.voluntary_exits.len);
}

test "BeaconNode: seen cache dedup" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const root = [_]u8{0xAB} ** 32;
    try std.testing.expect(!ctx.node.seen_cache.hasSeenBlock(root));

    try ctx.node.seen_cache.markBlockSeen(root, 5);
    try std.testing.expect(ctx.node.seen_cache.hasSeenBlock(root));
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
    const expected_slot: u64 = 42;
    const state_root = [_]u8{0x11} ** 32;
    try ctx.node.head_tracker.onBlock(expected_root, expected_slot, state_root);

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

test "BeaconNode: onReqResp BeaconBlocksByRoot returns stored block" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const known_root = [_]u8{0xCC} ** 32;
    const fake_block_bytes = [_]u8{0x01, 0x02, 0x03, 0x04} ** 8;
    try ctx.node.db.putBlock(known_root, &fake_block_bytes);

    const known_root_2 = [_]u8{0xDD} ** 32;
    const fake_block_bytes_2 = [_]u8{0x05, 0x06} ** 16;
    try ctx.node.db.putBlock(known_root_2, &fake_block_bytes_2);

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

    try ctx.node.head_tracker.onBlock(root_10, 10, [_]u8{0} ** 32);
    try ctx.node.head_tracker.onBlock(root_11, 11, [_]u8{0} ** 32);
    try ctx.node.db.putBlock(root_10, &block_10);
    try ctx.node.db.putBlock(root_11, &block_11);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = 10,
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
    try ctx.node.head_tracker.onBlock(root_5, 5, [_]u8{0} ** 32);
    try ctx.node.head_tracker.onBlock(root_6, 6, [_]u8{0} ** 32);

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

test "BeaconNode: archiveState stores state bytes in DB and retrieves them" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const state = try ctx.test_state.cached_state.clone(allocator, .{});
    const state_root = try ctx.node.queued_regen.onNewBlock(state, true);
    const slot: u64 = 32;

    try ctx.node.archiveState(slot, state_root);

    const retrieved = try ctx.node.db.getStateArchive(slot);
    try std.testing.expect(retrieved != null);
    if (retrieved) |bytes| allocator.free(bytes);
}

test "BeaconNode: archiveState is no-op for unknown state root" {
    var ctx = try TestContext.init(.{});
    defer ctx.deinit();

    const missing_root = [_]u8{0xff} ** 32;
    try ctx.node.archiveState(64, missing_root);

    const retrieved = try ctx.node.db.getStateArchive(64);
    try std.testing.expectEqual(@as(?[]const u8, null), retrieved);
}

test "BeaconNode: forkchoiceUpdated called after block import for post-merge head" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{ .engine_mock = true });
    defer ctx.deinit();

    const genesis_state = try ctx.test_state.cached_state.clone(allocator, .{});
    try genesis_state.state.setSlot(0);
    try ctx.node.initFromGenesis(genesis_state);

    const mock = ctx.node.mock_engine orelse return error.TestFailed;
    const genesis_root = ctx.node.head_tracker.head_root;
    const fake_exec_hash = [_]u8{0xab} ** 32;
    const post_merge_root = [_]u8{0xcd} ** 32;
    const fc = ctx.node.fork_choice.?;
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

    try block_production_mod.notifyForkchoiceUpdate(ctx.node, post_merge_root);

    try std.testing.expect(mock.last_forkchoice_state != null);
    const fcu_state = mock.last_forkchoice_state.?;
    try std.testing.expectEqual(fake_exec_hash, fcu_state.head_block_hash);
}

test "BeaconNode: forkchoiceUpdated not called for pre-merge head" {
    const allocator = std.testing.allocator;
    var ctx = try TestContext.init(.{ .engine_mock = true });
    defer ctx.deinit();

    const genesis_state = try ctx.test_state.cached_state.clone(allocator, .{});
    try genesis_state.state.setSlot(0);
    try ctx.node.initFromGenesis(genesis_state);

    const mock = ctx.node.mock_engine orelse return error.TestFailed;
    const genesis_root = ctx.node.head_tracker.head_root;

    try block_production_mod.notifyForkchoiceUpdate(ctx.node, genesis_root);

    try std.testing.expect(mock.last_forkchoice_state == null);
}
